"""
HYPERION GUARD: HTTP API
========================
    GET  /v1/health                  signer, contract, chain
    POST /v1/check                   one order → one signed verdict (paid, via the proxy)
    /v1/solana/*                     the co-signer for a Solana Guarded Vault
    /v1/hyperliquid/*                the co-signer for a Hyperliquid multi-sig account
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
import math
import os
import re
from typing import Annotated

from eth_account import Account
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .engine import ExecutorCall, Guard, GuardUnavailable, parse_order
from .hyperliquid import control as hl_control
from .hyperliquid.guard import HyperliquidGuardEngine, HyperliquidPolicy, Refused
from .hyperliquid.market import HyperliquidMarket, MarketUnavailable
from .ratelimit import Limits
from .solana import SolanaAgentPolicy, SolanaGuardEngine, b58decode
from .solana.control import action_message, policy_message
from .solana.decoder import ALLOWLISTED_PROGRAMS
from .solana.lookup import RpcLookupTables, RpcTokenAccounts
from .solana.prices import JupiterTokenPrices
from .solana.store import store_from_env
from .solana.vault import register_vault_program

ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX = re.compile(r"^0x([0-9a-fA-F]{2})*$")


def _address(value: str, name: str) -> str:
    if not isinstance(value, str) or not ADDRESS.match(value):
        raise HTTPException(422, f"{name} must be a 0x-prefixed 20-byte address")
    return value


def create_app(guard: Guard | None = None, solana_guard: SolanaGuardEngine | None = None,
               limits: Limits | None = None, hyperliquid_guard: HyperliquidGuardEngine | None = None) -> FastAPI:
    app = FastAPI(title="Hyperion Guard", version="1",
                  description="Pre-trade risk checks for autonomous trading agents, with multi-chain protection (Arc EVM + Solana).")

    # How often anyone may ask: see ratelimit.py. Off unless set in the environment.
    limits = limits if limits is not None else Limits.from_env()
    app.state.limits = limits
    if limits.enabled:
        @app.middleware("http")
        async def rate_limit(request: Request, call_next):
            refused = limits.check(request.method, request.url.path, request.client.host if request.client else None,
                                   request.headers.get("x-forwarded-for"))
            if refused is not None:
                what, wait = refused
                return JSONResponse({"detail": f"Too many {what}. Try again in {math.ceil(wait)} s."}, status_code=429,
                                    headers={"Retry-After": str(math.ceil(wait))})
            return await call_next(request)
    signer = Account.from_key(guard.signer_key).address if guard else None
    if solana_guard is None:
        # With an RPC node the Guard reads the address lookup tables v0 transactions use, and
        # the token accounts they spend, so it can tell which token a swap spends. Without one, a swap whose token can't
        # be told from the transaction alone is refused.
        rpc_url = os.environ.get("HYPERION_SOLANA_RPC_URL")
        # With a price source it can size SOL and other tokens; without one, only USDC and USDT.
        # "jupiter" is Jupiter's public price API; anything else is the URL of a compatible one.
        price_url = os.environ.get("HYPERION_SOLANA_PRICES")
        prices = None
        if price_url:
            prices = JupiterTokenPrices() if price_url == "jupiter" else JupiterTokenPrices(price_url)
        # The co-signing key: a 32-byte Ed25519 seed in hex. Without it a key is made up at
        # start-up and is gone at the next one, with every vault that named it.
        seed = os.environ.get("HYPERION_SOLANA_COSIGNER_KEY", "").strip()
        solana_guard = SolanaGuardEngine(
            cosigner_private_key_bytes=bytes.fromhex(seed.removeprefix("0x")) if seed else None,
            lookup_tables=RpcLookupTables(rpc_url) if rpc_url else None, prices=prices,
            token_accounts=RpcTokenAccounts(rpc_url) if rpc_url else None,
            # Where policies, nonces, usage and approvals are kept: see solana/store.py.
            store=store_from_env(os.environ.get("HYPERION_SOLANA_STATE")))
        for program_id in filter(None, os.environ.get("HYPERION_VAULT_PROGRAM_ID", "").split(",")):
            register_vault_program(program_id)
    # A public Guard shouldn't let strangers fill its store with policies.
    max_agents = int(os.environ.get("HYPERION_SOLANA_MAX_AGENTS", "1000"))
    app.state.solana_guard = solana_guard
    if hyperliquid_guard is None:
        # The co-signing key: a secp256k1 private key in hex. Without it a key is made up at
        # start-up, and every account that named the old one can't trade until its owner changes signers.
        key = os.environ.get("HYPERION_HYPERLIQUID_COSIGNER_KEY", "").strip()
        hyperliquid_guard = HyperliquidGuardEngine(HyperliquidMarket(), cosigner_key=key or None, store=solana_guard.store)
    app.state.hyperliquid_guard = hyperliquid_guard

    @app.get("/v1/health")
    def health():
        res = {"ok": True, "solana_cosigner": solana_guard.pubkey_b58, "hyperliquid_cosigner": hyperliquid_guard.address}
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

        # The agent's own key: /v1/solana/check only judges transactions it has signed.
        agent_pubkey = str(body.get("agent_solana_pubkey", ""))
        try:
            if len(b58decode(agent_pubkey)) != 32:
                raise ValueError
        except ValueError:
            raise HTTPException(422, "agent_solana_pubkey is required: the agent's 32-byte key, base58") from None

        guardian_pubkey = str(body.get("guardian_solana_pubkey", ""))
        max_notional = float(body.get("max_order_notional_usd", 5_000.0))
        max_slippage = int(body.get("max_slippage_bps", 100))
        policy_version = int(body.get("policy_version", 1))
        nonce = int(body.get("nonce", 0))
        require_guard = bool(body.get("require_guard_signer", True))
        allowed = body.get("allowed_programs")
        vault_address = str(body.get("vault_address", ""))

        # Owner Ed25519 Signature Verification
        owner_sig = body.get("signature_b58")
        if not owner_sig:
            raise HTTPException(401, "Missing owner Ed25519 signature (signature_b58)")

        # The signature covers every field, so nothing can be changed in transit.
        msg = policy_message(agent_id=agent_id, agent=agent_pubkey, owner=owner_pubkey, guardian=guardian_pubkey,
                             max_order_notional_usd=max_notional, max_slippage_bps=max_slippage,
                             policy_version=policy_version, nonce=nonce, require_guard_signer=require_guard,
                             allowed_programs=allowed, vault_address=vault_address)
        if not _verify_ed25519_sig(owner_pubkey, msg, owner_sig):
            raise HTTPException(401, "Invalid owner signature for policy update")

        # Check existing policy ownership & monotonic version bump
        existing = solana_guard.get_policy(agent_id)
        if existing is not None and existing.owner_solana_pubkey:
            if existing.owner_solana_pubkey != owner_pubkey:
                raise HTTPException(403, "Forbidden: Only the registered owner can modify an existing policy")
            if policy_version <= existing.policy_version:
                raise HTTPException(409, f"policy_version {policy_version} must be strictly greater than current version {existing.policy_version}")
        if existing is None and len(solana_guard.policies) >= max_agents:
            raise HTTPException(507, f"this Guard holds its limit of {max_agents} agents")

        policy = SolanaAgentPolicy(
            agent_id=agent_id,
            owner_solana_pubkey=owner_pubkey,
            guardian_solana_pubkey=guardian_pubkey,
            agent_solana_pubkey=agent_pubkey,
            max_order_notional_usd=max_notional,
            max_slippage_bps=max_slippage,
            policy_version=policy_version,
            require_guard_signer=require_guard,
            allowed_programs=set(allowed) if allowed else set(ALLOWLISTED_PROGRAMS),  # never None
            vault_address=vault_address,
        )
        # the nonce is used up and the policy saved together, or neither is
        if not solana_guard.set_policy(policy, nonce=nonce):
            raise HTTPException(409, "nonce already used: sign a new message with a higher nonce")
        return {
            "ok": True,
            "agent_id": agent_id,
            "policy": {
                "agent_solana_pubkey": policy.agent_solana_pubkey,
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
            "agent_solana_pubkey": policy.agent_solana_pubkey,
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

        msg = action_message("kill", agent_id, nonce)
        if not _verify_ed25519_sig(caller_pubkey, msg, sig_b58):
            raise HTTPException(401, "Invalid signature for kill switch invocation")

        authorized_callers = {policy.owner_solana_pubkey}
        if policy.guardian_solana_pubkey:
            authorized_callers.add(policy.guardian_solana_pubkey)

        if caller_pubkey not in authorized_callers:
            raise HTTPException(403, "Forbidden: Caller is neither owner nor guardian")
        if not solana_guard.kill_agent(agent_id, reason=str(body.get("reason", "")), nonce=nonce):
            raise HTTPException(409, "nonce already used: sign a new message with a higher nonce")

        reason = str(body.get("reason", "Emergency kill switch triggered"))
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

        msg = action_message("revive", agent_id, nonce)
        if not _verify_ed25519_sig(caller_pubkey, msg, sig_b58):
            raise HTTPException(401, "Invalid signature for agent revival")

        # ONLY the owner can revive! (Guardian or agent CANNOT revive)
        if caller_pubkey != policy.owner_solana_pubkey:
            raise HTTPException(403, "Forbidden: Guardian cannot revive, only the registered owner can revive an agent")
        if not solana_guard.revive_agent(agent_id, nonce=nonce):
            raise HTTPException(409, "nonce already used: an old revive can't undo a newer kill")

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

    # =========================================================================
    # Hyperliquid Endpoints
    # =========================================================================
    hl = hyperliquid_guard

    def _hl_policy_json(p: HyperliquidPolicy) -> dict:
        return {"account": p.account, "network": p.network, "agent": p.agent, "owner": p.owner, "guardian": p.guardian,
                "max_order_notional_usd": p.max_order_notional_usd, "daily_notional_cap_usd": p.daily_notional_cap_usd,
                "max_slippage_bps": p.max_slippage_bps, "max_leverage": p.max_leverage, "allowed_coins": p.allowed_coins,
                "policy_version": p.policy_version, "killed": p.is_killed}

    def _int(body: dict, name: str, default: int | None = None) -> int:
        value = body.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool):
            raise HTTPException(422, f"{name} must be an integer")
        return value

    @app.get("/v1/hyperliquid/health")
    def hyperliquid_health():
        return {"ok": True, "cosigner_address": hl.address, "max_expiry_ms": 120_000}

    @app.post("/v1/hyperliquid/policy")
    def set_hyperliquid_policy(body: Annotated[dict, Body()]):
        network = body.get("network")
        if network not in ("mainnet", "testnet"):
            raise HTTPException(422, 'network must be "mainnet" or "testnet"')
        account = _address(body.get("account"), "account").lower()
        agent = _address(body.get("agent"), "agent").lower()
        owner = _address(body.get("owner"), "owner").lower()
        guardian = body.get("guardian") or ""
        if guardian:
            guardian = _address(guardian, "guardian").lower()
        coins = body.get("allowed_coins")
        if coins is not None and (not isinstance(coins, list) or not all(isinstance(c, str) and c for c in coins)):
            raise HTTPException(422, "allowed_coins must be a list of coin names, or omitted for any listed perp")
        try:
            cap = float(body.get("max_order_notional_usd", 1_000.0))
            daily = float(body.get("daily_notional_cap_usd", 10_000.0))
        except (TypeError, ValueError):
            raise HTTPException(422, "the caps must be numbers") from None
        if not (math.isfinite(cap) and math.isfinite(daily) and cap > 0 and daily >= cap):
            raise HTTPException(422, "max_order_notional_usd must be above zero, and the daily cap at least that")
        slippage, leverage = _int(body, "max_slippage_bps", 100), _int(body, "max_leverage", 3)
        version, nonce = _int(body, "policy_version", 1), _int(body, "nonce", 0)
        if not 1 <= slippage <= 1_000 or not 1 <= leverage <= 50:
            raise HTTPException(422, "max_slippage_bps must be 1–1000 and max_leverage 1–50")

        message = hl_control.policy_message(
            network=network, account=account, agent=agent, owner=owner, guardian=guardian, max_order_notional_usd=cap,
            daily_notional_cap_usd=daily, max_slippage_bps=slippage, max_leverage=leverage, allowed_coins=coins,
            policy_version=version, nonce=nonce)
        if hl_control.signer_of(message, str(body.get("signature", ""))) != owner:
            raise HTTPException(401, "signature must be the owner's over the policy message")

        existing = hl.get_policy(account)
        if existing is not None:
            if existing.owner != owner:
                raise HTTPException(403, "only the account's registered owner can change its policy")
            if version <= existing.policy_version:
                raise HTTPException(409, f"policy_version must be above {existing.policy_version}")
        elif len(hl.policies) >= max_agents:
            raise HTTPException(507, f"this Guard holds its limit of {max_agents} accounts")
        policy = HyperliquidPolicy(account=account, network=network, agent=agent, owner=owner, guardian=guardian,
                                   max_order_notional_usd=cap, daily_notional_cap_usd=daily, max_slippage_bps=slippage,
                                   max_leverage=leverage, allowed_coins=sorted(coins) if coins else None,
                                   policy_version=version, is_killed=existing.is_killed if existing else False)
        try:
            hl.check_account(policy)
        except Refused as r:
            raise HTTPException(422, r.details) from None
        except MarketUnavailable as exc:
            raise HTTPException(503, str(exc)) from None
        if not hl.set_policy(policy, nonce):
            raise HTTPException(409, "nonce already used: sign a new message with a higher nonce")
        return {"ok": True, "policy": _hl_policy_json(policy)}

    @app.get("/v1/hyperliquid/policy/{account}")
    def get_hyperliquid_policy(account: str):
        policy = hl.get_policy(_address(account, "account"))
        if policy is None:
            raise HTTPException(404, f"no policy for {account}")
        return _hl_policy_json(policy)

    def _hl_control(action: str, body: dict) -> HyperliquidPolicy:
        account = _address(body.get("account"), "account").lower()
        policy = hl.get_policy(account)
        if policy is None:
            raise HTTPException(404, f"no policy for {account}")
        nonce = _int(body, "nonce")
        caller = hl_control.signer_of(hl_control.action_message(action, account, nonce), str(body.get("signature", "")))
        allowed = {policy.owner} | ({policy.guardian} if policy.guardian and action == "kill" else set())
        if caller not in allowed:
            raise HTTPException(403, f"{action} must be signed by the owner{' or the guardian' if action == 'kill' else ''}")
        if not hl.set_killed(account, action == "kill", nonce):
            raise HTTPException(409, "nonce already used: an old message can't be replayed")
        return policy

    @app.post("/v1/hyperliquid/kill")
    def kill_hyperliquid(body: Annotated[dict, Body()]):
        policy = _hl_control("kill", body)
        return {"ok": True, "account": policy.account, "killed": True}

    @app.post("/v1/hyperliquid/revive")
    def revive_hyperliquid(body: Annotated[dict, Body()]):
        policy = _hl_control("revive", body)
        return {"ok": True, "account": policy.account, "killed": False}

    @app.post("/v1/hyperliquid/check")
    def hyperliquid_check(body: Annotated[dict, Body()]):
        account = _address(body.get("account"), "account")
        signer = _address(body.get("signer"), "signer")
        signature = body.get("signature")
        if not isinstance(signature, dict) or not {"r", "s", "v"} <= set(signature):
            raise HTTPException(422, "signature must be {r, s, v}: the signer's own over the same multi-sig envelope")
        v = hl.evaluate(account, body.get("action"), body.get("nonce"), body.get("expires_after"), signer, signature)
        return {"approved": v.approved, "status": v.status, "violation_details": v.violation_details,
                "account": v.account, "operations": v.operations, "cosigner_address": v.cosigner_address,
                "cosigner_signature": v.cosigner_signature}

    return app
