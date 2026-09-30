"""
HYPERION SOLANA GUARD: PRE-TRADE FIREWALL & ED25519 CO-SIGNER
=============================================================
Enforces pre-trade safety controls on Solana transactions before broadcast:
  1. Kill Switch Enforcement (instantly blocks compromised or runaway agents)
  2. Target Program Allowlisting (blocks unauthorized smart contracts & drainers)
  3. Notional Ceiling (enforces max order size)
  4. Maximum Slippage Collar (prevents MEV sandwich attacks on Jupiter/DEXs)
  5. Daily Cumulative Spend Limits & Frequency Throttles

If approved, produces a valid 64-byte Ed25519 signature over the transaction message,
allowing multi-sig or co-signed execution on Solana.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from .base58 import b58encode
from .decoder import (
    ALLOWLISTED_PROGRAMS,
    decode_solana_transaction,
)


@dataclass
class SolanaAgentPolicy:
    agent_id: str
    owner_solana_pubkey: str
    guardian_solana_pubkey: str = ""
    max_order_notional_usd: float = 5_000.0
    daily_notional_cap_usd: float = 50_000.0
    max_slippage_bps: int = 150 # 1.5% max allowable slippage
    max_orders_per_minute: int = 30
    is_killed: bool = False
    policy_version: int = 1
    require_guard_signer: bool = True # Forces Guard to be a required signer in tx
    allowed_programs: list[str] = field(default_factory=lambda: list(ALLOWLISTED_PROGRAMS.keys()))

@dataclass
class SolanaVerdict:
    approved: bool
    status: str # "APPROVED", "REJECTED_KILL_SWITCH", "REJECTED_ORDER_CAP", "REJECTED_SLIPPAGE", etc.
    agent_id: str
    recent_blockhash: str
    evaluated_at_ns: int
    cosigner_pubkey: str
    cosigner_signature_b58: str | None
    decoded_operations: list[str]
    violation_details: str | None = None

class SolanaGuardEngine:
    def __init__(self, cosigner_private_key_bytes: bytes | None = None):
        """Initializes the Guard engine with an Ed25519 co-signer keypair."""
        if cosigner_private_key_bytes:
            self._key = ECC.import_key(cosigner_private_key_bytes)
        else:
            self._key = ECC.generate(curve="ed25519")

        # Extract 32-byte raw public key
        raw_pub = self._key.public_key().export_key(format="raw")
        self.cosigner_pubkey_b58 = b58encode(raw_pub)
        self._signer = eddsa.new(self._key, "rfc8032")

        # Policies and tracking state
        self.policies: dict[str, SolanaAgentPolicy] = {}
        self.daily_spend_tracker: dict[str, list[tuple[float, float]]] = {} # agent_id -> [(time_sec, usd)]
        self.order_timestamps: dict[str, list[float]] = {}                  # agent_id -> [time_sec]

    @property
    def pubkey_b58(self) -> str:
        return self.cosigner_pubkey_b58

    def get_policy(self, agent_id: str) -> SolanaAgentPolicy | None:
        """Retrieves policy for an agent if registered."""
        return self.policies.get(agent_id)

    def set_policy(self, policy: SolanaAgentPolicy):
        """Registers or updates policy for an agent."""
        self.policies[policy.agent_id] = policy

    def kill_agent(self, agent_id: str, reason: str = "") -> bool:
        """Emergency circuit breaker: trips kill switch."""
        if agent_id not in self.policies:
            # Register a default killed policy if agent was not yet registered
            self.policies[agent_id] = SolanaAgentPolicy(agent_id=agent_id, owner_solana_pubkey="", is_killed=True)
            return True
        self.policies[agent_id].is_killed = True
        return True

    def revive_agent(self, agent_id: str) -> bool:
        """Owner revival: restores execution."""
        if agent_id in self.policies:
            self.policies[agent_id].is_killed = False
            return True
        return False

    def evaluate_transaction(
        self,
        agent_id: str,
        raw_tx_bytes: bytes,
        sol_price_usd: float = 150.0,
    ) -> SolanaVerdict:
        """
        Inspects serialized Solana transaction against policy rules.
        If compliant, co-signs the transaction message.
        """
        now_ns = time.time_ns()
        now_sec = time.time()
        policy = self.policies.get(agent_id)

        if not policy:
            return SolanaVerdict(
                approved=False,
                status="AGENT_POLICY_NOT_FOUND",
                agent_id=agent_id,
                recent_blockhash="",
                evaluated_at_ns=now_ns,
                cosigner_pubkey=self.cosigner_pubkey_b58,
                cosigner_signature_b58=None,
                decoded_operations=[],
                violation_details=f"Agent '{agent_id}' is not registered with Solana Guard"
            )

        # 1. Kill Switch Check
        if policy.is_killed:
            return SolanaVerdict(
                approved=False,
                status="REJECTED_KILL_SWITCH",
                agent_id=agent_id,
                recent_blockhash="",
                evaluated_at_ns=now_ns,
                cosigner_pubkey=self.cosigner_pubkey_b58,
                cosigner_signature_b58=None,
                decoded_operations=[],
                violation_details="Agent kill switch is active. All execution is blocked."
            )

        # 2. Decode serialized transaction
        try:
            decoded = decode_solana_transaction(raw_tx_bytes)
        except (ValueError, struct.error, KeyError, IndexError, TypeError) as e:
            return SolanaVerdict(
                approved=False,
                status="MALFORMED_TRANSACTION",
                agent_id=agent_id,
                recent_blockhash="",
                evaluated_at_ns=now_ns,
                cosigner_pubkey=self.cosigner_pubkey_b58,
                cosigner_signature_b58=None,
                decoded_operations=[],
                violation_details=f"Failed to decode Solana wire transaction: {e!s}"
            )

        # 3. Guard Signer Requirement (Forces Guard co-signature to matter!)
        if policy.require_guard_signer:
            guard_idx = None
            try:
                guard_idx = decoded.account_keys.index(self.cosigner_pubkey_b58)
            except ValueError:
                pass

            if guard_idx is None or guard_idx >= decoded.num_required_signatures:
                return SolanaVerdict(
                    approved=False,
                    status="REJECTED_MISSING_GUARD_SIGNER",
                    agent_id=agent_id,
                    recent_blockhash=decoded.recent_blockhash,
                    evaluated_at_ns=now_ns,
                    cosigner_pubkey=self.cosigner_pubkey_b58,
                    cosigner_signature_b58=None,
                    decoded_operations=[],
                    violation_details=(
                        f"Transaction does not configure Hyperion Guard ({self.cosigner_pubkey_b58}) "
                        f"as a required signer. Found index: {guard_idx}, "
                        f"required signers count: {decoded.num_required_signatures}."
                    ),
                )

        # 4. Frequency Rate Limiting
        recent_orders = [t for t in self.order_timestamps.get(agent_id, []) if now_sec - t <= 60.0]
        if len(recent_orders) >= policy.max_orders_per_minute:
            return SolanaVerdict(
                approved=False,
                status="REJECTED_THROTTLE_LIMIT",
                agent_id=agent_id,
                recent_blockhash=decoded.recent_blockhash,
                evaluated_at_ns=now_ns,
                cosigner_pubkey=self.cosigner_pubkey_b58,
                cosigner_signature_b58=None,
                decoded_operations=[],
                violation_details=f"Exceeded frequency limit: {len(recent_orders)} orders in last 60s"
            )

        # 4. Deep Inspection of Instructions
        total_estimated_usd = 0.0
        operations = []

        for inst in decoded.instructions:
            operations.append(f"{inst.program_label}::{inst.operation}")

            # Check A: Program Allowlist
            if inst.program_id not in policy.allowed_programs:
                return SolanaVerdict(
                    approved=False,
                    status="REJECTED_UNAUTHORIZED_PROGRAM",
                    agent_id=agent_id,
                    recent_blockhash=decoded.recent_blockhash,
                    evaluated_at_ns=now_ns,
                    cosigner_pubkey=self.cosigner_pubkey_b58,
                    cosigner_signature_b58=None,
                    decoded_operations=operations,
                    violation_details=f"Target program '{inst.program_id}' ({inst.program_label}) is not in policy allowlist"
                )

            # Check A.1: Fail-Closed on Unparsed or Malformed Instructions
            if inst.details.get("error") or inst.operation.startswith("UNKNOWN_"):
                err_msg = inst.details.get("error") or f"unrecognized operation '{inst.operation}'"
                return SolanaVerdict(
                    approved=False,
                    status="REJECTED_MALFORMED_INSTRUCTION",
                    agent_id=agent_id,
                    recent_blockhash=decoded.recent_blockhash,
                    evaluated_at_ns=now_ns,
                    cosigner_pubkey=self.cosigner_pubkey_b58,
                    cosigner_signature_b58=None,
                    decoded_operations=operations,
                    violation_details=(
                        f"Instruction targeting '{inst.program_label}' ({inst.program_id}) "
                        f"could not be safely decoded: {err_msg}"
                    ),
                )

            # Check B: Maximum Slippage Collar (MEV defense)
            if inst.slippage_bps is not None and inst.slippage_bps > policy.max_slippage_bps:
                return SolanaVerdict(
                    approved=False,
                    status="REJECTED_EXCESSIVE_SLIPPAGE",
                    agent_id=agent_id,
                    recent_blockhash=decoded.recent_blockhash,
                    evaluated_at_ns=now_ns,
                    cosigner_pubkey=self.cosigner_pubkey_b58,
                    cosigner_signature_b58=None,
                    decoded_operations=operations,
                    violation_details=f"Slippage tolerance {inst.slippage_bps} bps exceeds max limit of {policy.max_slippage_bps} bps"
                )

            # Check C: Notional Size Estimation
            if inst.operation in ("JUPITER_SWAP", "PHOENIX_SWAP", "TOKEN_TRANSFER", "TOKEN_TRANSFER_CHECKED") and inst.input_amount is not None:
                # Assume 6 decimals (standard for USDC on Solana)
                est_usd = float(inst.input_amount) / 1e6
                total_estimated_usd += est_usd
            elif inst.operation == "SOL_TRANSFER" and inst.input_amount is not None:
                # Lamports (9 decimals) * sol_price_usd
                est_usd = (float(inst.input_amount) / 1e9) * sol_price_usd
                total_estimated_usd += est_usd

        # Check D: Order Notional Cap
        if total_estimated_usd > policy.max_order_notional_usd:
            return SolanaVerdict(
                approved=False,
                status="REJECTED_ORDER_CAP",
                agent_id=agent_id,
                recent_blockhash=decoded.recent_blockhash,
                evaluated_at_ns=now_ns,
                cosigner_pubkey=self.cosigner_pubkey_b58,
                cosigner_signature_b58=None,
                decoded_operations=operations,
                violation_details=f"Order notional ${total_estimated_usd:,.2f} exceeds cap of ${policy.max_order_notional_usd:,.2f}"
            )

        # Check E: Daily Spend Cap (Rolling 24h)
        rolling_24h_spends = [
            (t, usd) for t, usd in self.daily_spend_tracker.get(agent_id, [])
            if now_sec - t <= 86_400.0
        ]
        cum_daily_usd = sum(usd for _, usd in rolling_24h_spends) + total_estimated_usd

        if cum_daily_usd > policy.daily_notional_cap_usd:
            return SolanaVerdict(
                approved=False,
                status="REJECTED_DAILY_CAP",
                agent_id=agent_id,
                recent_blockhash=decoded.recent_blockhash,
                evaluated_at_ns=now_ns,
                cosigner_pubkey=self.cosigner_pubkey_b58,
                cosigner_signature_b58=None,
                decoded_operations=operations,
                violation_details=f"Cumulative 24h spend ${cum_daily_usd:,.2f} exceeds daily cap ${policy.daily_notional_cap_usd:,.2f}"
            )

        # --- All Checks Passed: Issue Co-Signature ---
        sig_bytes = self._signer.sign(decoded.message_bytes)
        sig_b58 = b58encode(sig_bytes)

        # Update state trackers
        recent_orders.append(now_sec)
        self.order_timestamps[agent_id] = recent_orders

        rolling_24h_spends.append((now_sec, total_estimated_usd))
        self.daily_spend_tracker[agent_id] = rolling_24h_spends

        return SolanaVerdict(
            approved=True,
            status="APPROVED",
            agent_id=agent_id,
            recent_blockhash=decoded.recent_blockhash,
            evaluated_at_ns=now_ns,
            cosigner_pubkey=self.cosigner_pubkey_b58,
            cosigner_signature_b58=sig_b58,
            decoded_operations=operations,
            violation_details=None
        )
