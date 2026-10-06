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

import hashlib
import struct
import threading
import time
from dataclasses import asdict, dataclass, field, replace

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from .base58 import b58decode, b58encode
from .decoder import (
    ALLOWLISTED_PROGRAMS,
    MAX_COMPUTE_UNITS,
    USDC_MINT,
    USDT_MINT,
    WSOL_MINT,
    LookupTables,
    TokenAccounts,
    decode_solana_transaction,
)
from .prices import TokenPrices
from .store import MemoryStore, StateStore

# What the Guard will co-sign: instructions it can size, a few that move and
# grant nothing, and calls into programs the owner listed that it can't decode.
CO_SIGNABLE = frozenset({
    "JUPITER_SWAP", "RAYDIUM_SWAP", "TOKEN_TRANSFER", "TOKEN_TRANSFER_CHECKED", "SOL_TRANSFER", "VAULT_TRANSFER_SOL",
    "TOKEN_HARMLESS", "EXTERNAL_CALL", "COMPUTE_BUDGET", "ATA_CREATE", "SOL_WRAP",
})


@dataclass
class SolanaAgentPolicy:
    agent_id: str
    owner_solana_pubkey: str
    guardian_solana_pubkey: str = ""
    # The agent's own key. When set, the Guard judges only transactions this key has
    # signed. The API requires it; leaving it empty skips the check (for callers that
    # authenticate the agent some other way).
    agent_solana_pubkey: str = ""
    max_order_notional_usd: float = 5_000.0
    daily_notional_cap_usd: float = 50_000.0
    max_slippage_bps: int = 150 # 1.5% max allowable slippage
    max_orders_per_minute: int = 30
    is_killed: bool = False
    policy_version: int = 1
    require_guard_signer: bool = True # Forces Guard to be a required signer in tx
    vault_address: str = ""           # if set, vault instructions must use this vault
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

def _signed_by(decoded, signer: str) -> bool:
    """Whether `signer` is a required signer of the transaction and its slot
    holds a valid Ed25519 signature over the message."""
    try:
        slot = decoded.account_keys.index(signer)
        if slot >= decoded.num_required_signatures or slot >= len(decoded.signatures):
            return False
        key = eddsa.import_public_key(b58decode(signer))
        eddsa.new(key, "rfc8032").verify(decoded.message_bytes, b58decode(decoded.signatures[slot]))
        return True
    except (ValueError, TypeError):
        return False


class SolanaGuardEngine:
    def __init__(self, cosigner_private_key_bytes: bytes | None = None, lookup_tables: LookupTables | None = None,
                 prices: TokenPrices | None = None, token_accounts: TokenAccounts | None = None,
                 store: StateStore | None = None):
        """Initializes the Guard engine with an Ed25519 co-signer keypair.

        `lookup_tables` resolves the address lookup tables v0 transactions use
        (see lookup.RpcLookupTables). Without it, accounts named through a
        table stay unknown, and a swap whose input token can't be told from
        the rest of the transaction is refused.

        `prices` gives the dollar price of SOL and of other tokens (see
        prices.JupiterTokenPrices). USDC and USDT are always $1. Without it,
        only those two can be sized, unless the caller passes a SOL price."""
        self.lookup_tables = lookup_tables
        self.prices = prices
        # Says which mint a token account holds, for instructions that spend one without
        # naming its mint (see lookup.RpcTokenAccounts).
        self.token_accounts = token_accounts
        if cosigner_private_key_bytes and len(cosigner_private_key_bytes) == 32:
            self._key = eddsa.import_private_key(cosigner_private_key_bytes)      # a raw Ed25519 seed
        elif cosigner_private_key_bytes:
            self._key = ECC.import_key(cosigner_private_key_bytes)
        else:
            # A key made up at start-up is gone at the next one, and every vault that named
            # it as its Guard with it. Fine for tests and demos; a host passes its own.
            self._key = ECC.generate(curve="ed25519")

        # Extract 32-byte raw public key
        raw_pub = self._key.public_key().export_key(format="raw")
        self.cosigner_pubkey_b58 = b58encode(raw_pub)
        self._signer = eddsa.new(self._key, "rfc8032")

        # One request at a time: the checks read the throttle and the caps and then
        # write them, and two requests interleaved could both fit under a cap that
        # only has room for one.
        self._lock = threading.RLock()

        # State. Every change is written through to `store` (see store.py) and read back
        # here, so a restart forgets nothing. The default store is memory, which does.
        self.store: StateStore = store if store is not None else MemoryStore()
        self.policies: dict[str, SolanaAgentPolicy] = {}
        self.daily_spend_tracker: dict[str, list[tuple[float, float]]] = {} # agent_id -> [(time_sec, usd)]
        self.order_timestamps: dict[str, list[float]] = {}                  # agent_id -> [time_sec]
        # Highest control-message nonce accepted per agent (policy, kill and revive share
        # one sequence), so a signed message can never be replayed.
        self.last_nonce: dict[str, int] = {}
        # Messages already approved, per agent: sha256(message) -> the signature given.
        # Asking again about the same transaction gets the same answer and isn't counted
        # again. A broadcast transaction is public, so without this anyone could resubmit
        # it to use up the agent's rate limit and daily cap. It only grows with
        # transactions the agent itself signed. Read from the store as they're asked about.
        self.approved_messages: dict[str, dict[bytes, str]] = {}
        self._load()

    def _load(self) -> None:
        for agent_id, saved in self.store.items("policy"):
            self.policies[agent_id] = SolanaAgentPolicy(**saved)
        for agent_id, saved in self.store.items("nonce"):
            self.last_nonce[agent_id] = int(saved["nonce"])
        for agent_id, saved in self.store.items("usage"):
            self.order_timestamps[agent_id] = [float(t) for t in saved["orders"]]
            self.daily_spend_tracker[agent_id] = [(float(t), float(usd)) for t, usd in saved["spends"]]

    @staticmethod
    def _policy_record(policy: SolanaAgentPolicy) -> tuple[str, str, dict]:
        saved = asdict(policy)
        saved["allowed_programs"] = sorted(saved["allowed_programs"])       # a set isn't JSON
        return "policy", policy.agent_id, saved

    def _approved(self, agent_id: str, message_hash: bytes) -> str | None:
        """The signature already given for this message, from memory or the store."""
        known = self.approved_messages.setdefault(agent_id, {})
        if message_hash not in known:
            saved = self.store.get("approved", f"{agent_id}:{message_hash.hex()}")
            if saved is None:
                return None
            known[message_hash] = saved["signature"]
        return known[message_hash]

    @property
    def pubkey_b58(self) -> str:
        return self.cosigner_pubkey_b58

    def get_policy(self, agent_id: str) -> SolanaAgentPolicy | None:
        """Retrieves policy for an agent if registered."""
        return self.policies.get(agent_id)

    def set_policy(self, policy: SolanaAgentPolicy, nonce: int | None = None) -> bool:
        """Registers or updates policy for an agent. With `nonce`, the nonce is
        consumed and the policy saved together, or neither is: returns False,
        changing nothing, if the nonce isn't above the last one accepted."""
        with self._lock:
            records = [self._policy_record(policy)]
            if nonce is not None:
                if nonce <= self.last_nonce.get(policy.agent_id, 0):
                    return False
                records.append(("nonce", policy.agent_id, {"nonce": nonce}))
            self.store.put_many(records)                    # saved first: if this fails, nothing changed
            if nonce is not None:
                self.last_nonce[policy.agent_id] = nonce
            self.policies[policy.agent_id] = policy
            return True

    def consume_nonce(self, agent_id: str, nonce: int) -> bool:
        """Accept `nonce` for `agent_id` only if it's above every nonce accepted
        before. Call after the signature checks out, before applying the action."""
        with self._lock:
            if nonce <= self.last_nonce.get(agent_id, 0):
                return False
            self.store.put_many([("nonce", agent_id, {"nonce": nonce})])
            self.last_nonce[agent_id] = nonce
            return True

    def _set_killed(self, agent_id: str, killed: bool, nonce: int | None) -> bool:
        with self._lock:
            policy = self.policies.get(agent_id)
            if policy is None:
                if not killed:
                    return False
                # Register a default killed policy if agent was not yet registered
                policy = SolanaAgentPolicy(agent_id=agent_id, owner_solana_pubkey="")
            if nonce is not None and nonce <= self.last_nonce.get(agent_id, 0):
                return False
            changed = replace(policy, is_killed=killed)
            records = [self._policy_record(changed)]
            if nonce is not None:
                records.append(("nonce", agent_id, {"nonce": nonce}))
            self.store.put_many(records)
            if nonce is not None:
                self.last_nonce[agent_id] = nonce
            policy.is_killed = killed
            self.policies[agent_id] = policy
            return True

    def kill_agent(self, agent_id: str, reason: str = "", nonce: int | None = None) -> bool:
        """Emergency circuit breaker: trips kill switch. With `nonce`, the nonce
        is consumed and the kill saved together (False if the nonce is stale)."""
        return self._set_killed(agent_id, True, nonce)

    def revive_agent(self, agent_id: str, nonce: int | None = None) -> bool:
        """Owner revival: restores execution."""
        return self._set_killed(agent_id, False, nonce)

    def evaluate_transaction(
        self,
        agent_id: str,
        raw_tx_bytes: bytes,
        sol_price_usd: float | None = None,
    ) -> SolanaVerdict:
        """Judge a transaction, one at a time (see _lock)."""
        with self._lock:
            return self._evaluate(agent_id, raw_tx_bytes, sol_price_usd)

    def _evaluate(
        self,
        agent_id: str,
        raw_tx_bytes: bytes,
        sol_price_usd: float | None = None,
    ) -> SolanaVerdict:
        """
        Inspects serialized Solana transaction against policy rules.
        If compliant, co-signs the transaction message.

        `sol_price_usd` overrides the price source's SOL price (for tests and
        demos that want repeatable dollar figures).
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
            decoded = decode_solana_transaction(raw_tx_bytes, self.lookup_tables)
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

        # 2.1 The agent must have signed it. Checked before anything is counted, so a
        # stranger's transaction can't touch the agent's throttle or caps.
        if policy.agent_solana_pubkey and not _signed_by(decoded, policy.agent_solana_pubkey):
            return SolanaVerdict(
                approved=False,
                status="REJECTED_NOT_SIGNED_BY_AGENT",
                agent_id=agent_id,
                recent_blockhash=decoded.recent_blockhash,
                evaluated_at_ns=now_ns,
                cosigner_pubkey=self.cosigner_pubkey_b58,
                cosigner_signature_b58=None,
                decoded_operations=[],
                violation_details=(f"The transaction doesn't carry a valid signature from this agent's key "
                                   f"({policy.agent_solana_pubkey})"),
            )

        # 2.2 Already approved: the same answer, not counted a second time.
        message_hash = hashlib.sha256(decoded.message_bytes).digest()
        earlier = self._approved(agent_id, message_hash)
        if earlier is not None:
            return SolanaVerdict(
                approved=True,
                status="APPROVED",
                agent_id=agent_id,
                recent_blockhash=decoded.recent_blockhash,
                evaluated_at_ns=now_ns,
                cosigner_pubkey=self.cosigner_pubkey_b58,
                cosigner_signature_b58=earlier,
                decoded_operations=[f"{inst.program_label}::{inst.operation}" for inst in decoded.instructions],
                violation_details=None,
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
        unit_price_micro_lamports = 0
        # Token accounts this transaction itself sets up. What one of them holds can't be
        # read off the chain beforehand: it may be opened for a different mint than it has now.
        opened_here = {
            accounts[0]
            for inst in decoded.instructions
            for det, accounts in [(inst.details.get("inner", {}), inst.accounts[4:]) if inst.operation == "VAULT_EXECUTE"
                                  else (inst.details, inst.accounts)]
            if str(det.get("type", "")).startswith("InitializeAccount") and accounts
        }
        sol_lamports = 0.0
        unit_limit: int | None = None

        for inst in decoded.instructions:
            operations.append(f"{inst.program_label}::{inst.operation}")

            # Check A0: vault instructions. Only the agent's own actions are co-signable,
            # only from the agent's vault, and the call inside Execute is held to the
            # same allow-list as a direct call.
            reject = None
            if inst.operation.startswith("VAULT_ADMIN_"):
                reject = ("REJECTED_VAULT_ADMIN_OPERATION",
                          (f"{inst.details.get('vault_instruction')} is for the vault's owner or guardian, "
                           "not something the Guard co-signs for an agent"))
            elif inst.operation.startswith("VAULT_") and policy.vault_address \
                    and inst.details.get("vault") != policy.vault_address:
                reject = ("REJECTED_WRONG_VAULT",
                          f"vault {inst.details.get('vault')} isn't this agent's vault {policy.vault_address}")
            elif inst.operation == "VAULT_EXECUTE" and inst.details.get("inner_program") not in policy.allowed_programs:
                reject = ("REJECTED_UNAUTHORIZED_PROGRAM",
                          f"vault call targets '{inst.details.get('inner_program')}', which is not in the policy allowlist")
            if reject:
                return SolanaVerdict(
                    approved=False,
                    status=reject[0],
                    agent_id=agent_id,
                    recent_blockhash=decoded.recent_blockhash,
                    evaluated_at_ns=now_ns,
                    cosigner_pubkey=self.cosigner_pubkey_b58,
                    cosigner_signature_b58=None,
                    decoded_operations=operations,
                    violation_details=reject[1],
                )

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

            # Check A.2: fail closed on anything the Guard can't put a size on. A decoded
            # instruction is co-signable only if it's one of these kinds; a call into a
            # program the owner listed that the Guard has no decoder for (EXTERNAL_CALL)
            # is the owner's decision and passes.
            kind = inst.details.get("inner_operation") if inst.operation == "VAULT_EXECUTE" else inst.operation
            if kind not in CO_SIGNABLE or (kind == "COMPUTE_BUDGET" and inst.operation == "VAULT_EXECUTE"):
                what = inst.details.get("inner", inst.details) if inst.operation == "VAULT_EXECUTE" else inst.details
                name = what.get("instruction_name") or what.get("type") or kind
                return SolanaVerdict(
                    approved=False,
                    status="REJECTED_UNSUPPORTED_INSTRUCTION",
                    agent_id=agent_id,
                    recent_blockhash=decoded.recent_blockhash,
                    evaluated_at_ns=now_ns,
                    cosigner_pubkey=self.cosigner_pubkey_b58,
                    cosigner_signature_b58=None,
                    decoded_operations=operations,
                    violation_details=(f"{inst.program_label}: {name} ({kind}) is not something the Guard can "
                                       "size or check, so it won't co-sign it"),
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

            # Check B.1: a swap with no limit on the other side has unlimited slippage.
            # Raydium carries a minimum-out (or maximum-in) instead of a bps figure.
            inner = inst.details.get("inner") if inst.operation == "VAULT_EXECUTE" else inst.details
            if isinstance(inner, dict) and inner.get("unbounded"):
                return SolanaVerdict(
                    approved=False,
                    status="REJECTED_EXCESSIVE_SLIPPAGE",
                    agent_id=agent_id,
                    recent_blockhash=decoded.recent_blockhash,
                    evaluated_at_ns=now_ns,
                    cosigner_pubkey=self.cosigner_pubkey_b58,
                    cosigner_signature_b58=None,
                    decoded_operations=operations,
                    violation_details=(f"{inner.get('instruction_name')} sets no limit on the other side of the swap "
                                       "(minimum out of 0, or no maximum in): unlimited slippage"),
                )

            # Check C: Notional Size Estimation (a vault Execute counts as its inner call).
            # SOL is totalled in lamports and priced once, below.
            if kind == "VAULT_TRANSFER_SOL":
                kind = "SOL_TRANSFER"
            what = inst.details.get("inner", {}) if inst.operation == "VAULT_EXECUTE" else inst.details
            if kind == "COMPUTE_BUDGET":
                unit_price_micro_lamports = max(unit_price_micro_lamports, what.get("micro_lamports_per_unit", 0))
                if "units" in what:
                    unit_limit = max(unit_limit or 0, what["units"])
            elif kind in ("SOL_TRANSFER", "ATA_CREATE") and inst.input_amount is not None:
                sol_lamports += inst.input_amount
            elif kind in ("JUPITER_SWAP", "RAYDIUM_SWAP", "TOKEN_TRANSFER", "TOKEN_TRANSFER_CHECKED") and inst.input_amount is not None:
                # A token amount is only a dollar figure if the Guard knows the token and its price.
                mint = what.get("source_mint")
                token_account = what.get("source_token_account")
                if not mint and token_account and self.token_accounts and token_account not in opened_here:
                    try:
                        mint = self.token_accounts(token_account)
                    except (OSError, ValueError, LookupError):      # can't be read: unknown, as before
                        mint = None
                if mint in (USDC_MINT, USDT_MINT):
                    total_estimated_usd += float(inst.input_amount) / 1e6
                elif mint == WSOL_MINT:
                    sol_lamports += inst.input_amount
                else:
                    token_price = self.prices.price(mint) if mint and self.prices else None
                    if token_price is not None:
                        total_estimated_usd += token_price.value(inst.input_amount)
                        continue
                    if not mint:
                        why = "the token it spends couldn't be identified"
                        if decoded.unresolved_accounts:
                            why += (f" ({decoded.unresolved_accounts} of the transaction's accounts are in lookup "
                                    "tables the Guard couldn't read)")
                    elif self.prices is None:
                        why = f"it spends token {mint}, and the Guard has no price source for tokens"
                    else:
                        why = (f"it spends token {mint}, which the Guard has no price for "
                               "(none available, or too little liquidity behind it to trust)")
                    return SolanaVerdict(
                        approved=False,
                        status="REJECTED_UNPRICED_TOKEN",
                        agent_id=agent_id,
                        recent_blockhash=decoded.recent_blockhash,
                        evaluated_at_ns=now_ns,
                        cosigner_pubkey=self.cosigner_pubkey_b58,
                        cosigner_signature_b58=None,
                        decoded_operations=operations,
                        violation_details=f"{inst.program_label}: can't size this against the dollar caps, because {why}",
                    )

        # Check C.1: the priority fee is SOL the agent spends too. With no limit set,
        # assume the most a transaction can use.
        if unit_price_micro_lamports:
            sol_lamports += unit_price_micro_lamports * min(unit_limit or MAX_COMPUTE_UNITS, MAX_COMPUTE_UNITS) / 1e6

        # Check C.2: price the SOL. The caller's figure if it gave one, else the price
        # source's. There is no built-in figure: without a price, SOL can't be sized.
        if sol_lamports:
            if sol_price_usd is None and self.prices is not None:
                sol = self.prices.price(WSOL_MINT)
                sol_price_usd = sol.usd if sol else None
            if sol_price_usd is None or not sol_price_usd > 0:
                return SolanaVerdict(
                    approved=False,
                    status="REJECTED_UNPRICED_TOKEN",
                    agent_id=agent_id,
                    recent_blockhash=decoded.recent_blockhash,
                    evaluated_at_ns=now_ns,
                    cosigner_pubkey=self.cosigner_pubkey_b58,
                    cosigner_signature_b58=None,
                    decoded_operations=operations,
                    violation_details=(f"can't size the {sol_lamports / 1e9:.9f} SOL this transaction spends against "
                                       "the dollar caps: no SOL price is available"),
                )
            total_estimated_usd += (sol_lamports / 1e9) * sol_price_usd

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

        # Record it, then answer. The record is saved before the signature leaves: if
        # the save fails, this raises and nothing was approved.
        recent_orders.append(now_sec)
        rolling_24h_spends.append((now_sec, total_estimated_usd))
        self.store.put_many([
            ("usage", agent_id, {"orders": recent_orders, "spends": rolling_24h_spends}),
            ("approved", f"{agent_id}:{message_hash.hex()}", {"signature": sig_b58, "at": now_sec,
                                                               "usd": total_estimated_usd}),
        ])
        self.order_timestamps[agent_id] = recent_orders
        self.daily_spend_tracker[agent_id] = rolling_24h_spends
        self.approved_messages.setdefault(agent_id, {})[message_hash] = sig_b58

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
