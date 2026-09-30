"""
HYPERION GUARD: HTTP API
========================
    GET  /v1/health                  signer, contract, chain
    POST /v1/check                   one order → one signed verdict (paid, via the proxy)
    GET  /v1/agents/{address}        the agent's policy and kill state, read from Arc
    GET  /v1/verdicts?agent=0x…      recent verdicts
    GET  /v1/verdicts/{seq}          one verdict, with its Merkle proof once anchored

Payment is not handled here. In production this app listens on localhost
only and the x402 payment proxy (guard/paywall) sits in front of it:
`/v1/check` costs a fraction of a cent per call in USDC via Circle Gateway,
and everything else passes through free, so anyone can audit a verdict.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Annotated

from eth_account import Account
from fastapi import Body, FastAPI, HTTPException

from .engine import ExecutorCall, Guard, GuardUnavailable, parse_order
from .solana import SolanaAgentPolicy, SolanaGuardEngine, b58decode

ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX = re.compile(r"^0x([0-9a-fA-F]{2})*$")


def _address(value: str, name: str) -> str:
    if not isinstance(value, str) or not ADDRESS.match(value):
        raise HTTPException(422, f"{name} must be a 0x-prefixed 20-byte address")
    return value


def create_app(guard: Guard | None = None, solana_guard: SolanaGuardEngine | None = None) -> FastAPI:
    app = FastAPI(title="Hyperion Guard", version="1",
                  description="Pre-trade risk checks for autonomous trading agents, with multi-chain protection (Arc EVM + Solana).")
    signer = Account.from_key(guard.signer_key).address if guard else None
    if solana_guard is None:
        solana_guard = SolanaGuardEngine()

    @app.get("/v1/health")
    def health():
        res = {"ok": True, "solana_cosigner": solana_guard.pubkey_b58}
        if guard:
            res.update({
                "signer": signer,
                "contract": guard.domain.contract,
                "chain_id": guard.domain.chain_id,
                "verdict_ttl_s": guard.ttl,
            })
        return res

    @app.post("/v1/check")
    def check(body: Annotated[dict, Body()]):
        if guard is None:
            raise HTTPException(503, "EVM guard service is not enabled")
        agent = _address(body.get("agent"), "agent")
        try:
            order = parse_order(body.get("order") or {})
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        executor = None
        if body.get("executor") is not None:
            e = body["executor"]
            if not isinstance(e, dict) or not HEX.match(str(e.get("data", ""))) or not isinstance(e.get("nonce"), int) \
                    or e["nonce"] < 0:
                raise HTTPException(422, "executor needs address, target, data (0x-hex) and a non-negative nonce")
            executor = ExecutorCall(executor=_address(e.get("address"), "executor.address"),
                                    target=_address(e.get("target"), "executor.target"),
                                    data=e["data"], nonce=e["nonce"])
        client_order_id = str(body.get("client_order_id", ""))[:128]
        try:
            return guard.check(agent, order, executor=executor, client_order_id=client_order_id)
        except GuardUnavailable as exc:
            raise HTTPException(503, str(exc)) from None

    @app.get("/v1/agents/{address}")
    def agent(address: str):
        _address(address, "address")
        try:
            state = guard.chain.agent(address)
        except Exception as exc:  # noqa: BLE001 — any RPC failure is "can't tell right now"
            raise HTTPException(503, f"can't read Arc: {exc}") from None
        if state is None:
            raise HTTPException(404, "agent isn't registered")
        p = state.policy
        return {"agent": address, "owner": state.owner, "guardian": state.guardian, "killed": state.killed,
                "policy_version": state.policy_version,
                "policy": {"max_order_notional": p.max_order_notional, "max_daily_notional": p.max_daily_notional,
                           "collar_bps": p.collar_bps, "max_orders_per_minute": p.max_orders_per_minute}}

    @app.get("/v1/verdicts")
    def verdicts(agent: str | None = None, limit: int = 50):
        if agent:
            _address(agent, "agent")
        return {"data": guard.ledger.recent(agent, max(1, min(limit, 500)))}

    @app.get("/v1/verdicts/{seq}")
    def verdict(seq: int):
        row = guard.ledger.get(seq)
        if row is None:
            raise HTTPException(404, "no such verdict")
        return {"verdict": row, "anchor": guard.ledger.proof_for(seq)}

    # =========================================================================
    # Solana Endpoints
    # =========================================================================

    from Crypto.Signature import eddsa

    def _verify_ed25519_sig(pubkey_b58: str, message: bytes, signature_b58: str) -> bool:
        try:
            raw_pub = b58decode(pubkey_b58)
            raw_sig = b58decode(signature_b58)
            key = eddsa.import_public_key(raw_pub)
            verifier = eddsa.new(key, "rfc8032")
            verifier.verify(message, raw_sig)
            return True
        except (ValueError, TypeError):
            return False

    @app.get("/v1/solana/health")
    def solana_health():
        return {"ok": True, "cosigner_pubkey": solana_guard.pubkey_b58}

    @app.post("/v1/solana/policy")
    def set_solana_policy(body: Annotated[dict, Body()]):
        agent_id = body.get("agent_id")
        if not agent_id or not isinstance(agent_id, str):
            raise HTTPException(422, "agent_id must be a non-empty string")
        owner_pubkey = str(body.get("owner_solana_pubkey", ""))
        if not owner_pubkey:
            raise HTTPException(422, "owner_solana_pubkey is required")

        guardian_pubkey = str(body.get("guardian_solana_pubkey", ""))
        max_notional = float(body.get("max_order_notional_usd", 5_000.0))
        max_slippage = int(body.get("max_slippage_bps", 100))
        policy_version = int(body.get("policy_version", 1))
        nonce = int(body.get("nonce", 0))
        require_guard = bool(body.get("require_guard_signer", True))
        allowed = body.get("allowed_programs")

        # Owner Ed25519 Signature Verification
        owner_sig = body.get("signature_b58")
        if not owner_sig:
            raise HTTPException(401, "Missing owner Ed25519 signature (signature_b58)")

        msg = f"hyperion-guard/solana/policy/v1:{agent_id}:{owner_pubkey}:{max_notional:.2f}:{max_slippage}:{nonce}:{policy_version}".encode()
        if not _verify_ed25519_sig(owner_pubkey, msg, owner_sig):
            raise HTTPException(401, "Invalid owner signature for policy update")

        # Check existing policy ownership & monotonic version bump
        existing = solana_guard.get_policy(agent_id)
        if existing is not None and existing.owner_solana_pubkey:
            if existing.owner_solana_pubkey != owner_pubkey:
                raise HTTPException(403, "Forbidden: Only the registered owner can modify an existing policy")
            if policy_version <= existing.policy_version:
                raise HTTPException(409, f"policy_version {policy_version} must be strictly greater than current version {existing.policy_version}")

        policy = SolanaAgentPolicy(
            agent_id=agent_id,
            owner_solana_pubkey=owner_pubkey,
            guardian_solana_pubkey=guardian_pubkey,
            max_order_notional_usd=max_notional,
            max_slippage_bps=max_slippage,
            policy_version=policy_version,
            require_guard_signer=require_guard,
            allowed_programs=set(allowed) if allowed else None,
        )
        solana_guard.set_policy(policy)
        return {
            "ok": True,
            "agent_id": agent_id,
            "policy": {
                "owner_solana_pubkey": policy.owner_solana_pubkey,
                "guardian_solana_pubkey": policy.guardian_solana_pubkey,
                "max_order_notional_usd": policy.max_order_notional_usd,
                "max_slippage_bps": policy.max_slippage_bps,
                "policy_version": policy.policy_version,
                "require_guard_signer": policy.require_guard_signer,
                "allowed_programs": sorted(policy.allowed_programs),
            },
        }

    @app.get("/v1/solana/policy/{agent_id}")
    def get_solana_policy(agent_id: str):
        policy = solana_guard.get_policy(agent_id)
        if policy is None:
            raise HTTPException(404, f"No policy configured for Solana agent '{agent_id}'")
        return {
            "agent_id": agent_id,
            "owner_solana_pubkey": policy.owner_solana_pubkey,
            "guardian_solana_pubkey": policy.guardian_solana_pubkey,
            "max_order_notional_usd": policy.max_order_notional_usd,
            "max_slippage_bps": policy.max_slippage_bps,
            "policy_version": policy.policy_version,
            "require_guard_signer": policy.require_guard_signer,
            "allowed_programs": sorted(policy.allowed_programs),
            "killed": policy.is_killed,
        }

    @app.post("/v1/solana/kill")
    def kill_solana_agent(body: Annotated[dict, Body()]):
        agent_id = body.get("agent_id")
        if not agent_id or not isinstance(agent_id, str):
            raise HTTPException(422, "agent_id must be a non-empty string")

        policy = solana_guard.get_policy(agent_id)
        if policy is None:
            raise HTTPException(404, f"No policy configured for Solana agent '{agent_id}'")

        caller_pubkey = str(body.get("caller_pubkey", ""))
        nonce = int(body.get("nonce", 0))
        sig_b58 = body.get("signature_b58")
        if not caller_pubkey or not sig_b58:
            raise HTTPException(401, "caller_pubkey and signature_b58 are required to trip kill switch")

        msg = f"hyperion-guard/solana/kill/v1:{agent_id}:{nonce}".encode()
        if not _verify_ed25519_sig(caller_pubkey, msg, sig_b58):
            raise HTTPException(401, "Invalid signature for kill switch invocation")

        authorized_callers = {policy.owner_solana_pubkey}
        if policy.guardian_solana_pubkey:
            authorized_callers.add(policy.guardian_solana_pubkey)

        if caller_pubkey not in authorized_callers:
            raise HTTPException(403, "Forbidden: Caller is neither owner nor guardian")

        reason = str(body.get("reason", "Emergency kill switch triggered"))
        solana_guard.kill_agent(agent_id, reason=reason)
        return {"ok": True, "agent_id": agent_id, "killed": True, "reason": reason}

    @app.post("/v1/solana/revive")
    def revive_solana_agent(body: Annotated[dict, Body()]):
        agent_id = body.get("agent_id")
        if not agent_id or not isinstance(agent_id, str):
            raise HTTPException(422, "agent_id must be a non-empty string")

        policy = solana_guard.get_policy(agent_id)
        if policy is None:
            raise HTTPException(404, f"No policy configured for Solana agent '{agent_id}'")

        caller_pubkey = str(body.get("caller_pubkey", ""))
        nonce = int(body.get("nonce", 0))
        sig_b58 = body.get("signature_b58")
        if not caller_pubkey or not sig_b58:
            raise HTTPException(401, "caller_pubkey and signature_b58 are required to revive agent")

        msg = f"hyperion-guard/solana/revive/v1:{agent_id}:{nonce}".encode()
        if not _verify_ed25519_sig(caller_pubkey, msg, sig_b58):
            raise HTTPException(401, "Invalid signature for agent revival")

        # ONLY the owner can revive! (Guardian or agent CANNOT revive)
        if caller_pubkey != policy.owner_solana_pubkey:
            raise HTTPException(403, "Forbidden: Guardian cannot revive, only the registered owner can revive an agent")

        solana_guard.revive_agent(agent_id)
        return {"ok": True, "agent_id": agent_id, "killed": False}

    @app.post("/v1/solana/check")
    def solana_check(body: Annotated[dict, Body()]):
        agent_id = body.get("agent_id")
        if not agent_id or not isinstance(agent_id, str):
            raise HTTPException(422, "agent_id must be a non-empty string")
        tx_raw = body.get("tx_bytes")
        if not tx_raw or not isinstance(tx_raw, str):
            raise HTTPException(422, "tx_bytes must be a non-empty string")

        encoding = body.get("encoding", "").lower()
        try:
            if encoding == "base58":
                raw_bytes = b58decode(tx_raw)
            elif encoding == "hex" or tx_raw.startswith("0x"):
                hex_str = tx_raw.removeprefix("0x")
                raw_bytes = bytes.fromhex(hex_str)
            elif encoding == "base64":
                raw_bytes = base64.b64decode(tx_raw)
            else:
                if tx_raw.startswith("0x"):
                    raw_bytes = bytes.fromhex(tx_raw[2:])
                else:
                    try:
                        raw_bytes = base64.b64decode(tx_raw)
                    except (ValueError, binascii.Error):
                        raw_bytes = b58decode(tx_raw)
        except (ValueError, binascii.Error, TypeError) as exc:
            raise HTTPException(422, f"Failed to decode transaction bytes: {exc}") from None

        verdict = solana_guard.evaluate_transaction(agent_id, raw_bytes)
        return {
            "approved": verdict.approved,
            "status": verdict.status,
            "violation_details": verdict.violation_details,
            "agent_id": verdict.agent_id,
            "recent_blockhash": verdict.recent_blockhash,
            "evaluated_at_ns": verdict.evaluated_at_ns,
            "instructions_count": len(verdict.decoded_operations),
            "decoded_operations": verdict.decoded_operations,
            "cosigner_pubkey": verdict.cosigner_pubkey,
            "cosigner_signature_b58": verdict.cosigner_signature_b58,
        }

    return app
