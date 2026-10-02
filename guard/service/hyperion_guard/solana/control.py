"""
HYPERION SOLANA GUARD: WHAT AN OWNER OR GUARDIAN SIGNS
======================================================
Every control action (set a policy, kill, revive) is an Ed25519 signature
over one of these byte strings. They're defined once, here, so the API and
anything that builds requests sign exactly the same bytes.

The policy message covers *every* field of the policy. An earlier version
signed only the size and slippage limits, so whoever relayed a validly
signed update could change the allowed programs, the guardian or the
co-signer requirement without breaking the signature.

Each message carries a nonce. The Guard keeps the highest nonce it has
accepted per agent and refuses anything not above it, so a signed message
can't be replayed: an old "revive" can't bring back an agent killed since.
"""

from __future__ import annotations

import json

POLICY_DOMAIN = b"hyperion-guard/solana/policy/v2:"


def policy_message(*, agent_id: str, owner: str, guardian: str, max_order_notional_usd: float,
                   max_slippage_bps: int, policy_version: int, nonce: int, require_guard_signer: bool,
                   allowed_programs: list[str] | set[str] | None) -> bytes:
    body = {
        "agent_id": agent_id,
        "owner": owner,
        "guardian": guardian,
        "max_order_notional_usd": f"{float(max_order_notional_usd):.2f}",
        "max_slippage_bps": int(max_slippage_bps),
        "policy_version": int(policy_version),
        "nonce": int(nonce),
        "require_guard_signer": bool(require_guard_signer),
        "allowed_programs": sorted(allowed_programs) if allowed_programs else None,
    }
    return POLICY_DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def action_message(action: str, agent_id: str, nonce: int) -> bytes:
    """For "kill" and "revive"."""
    if action not in ("kill", "revive"):
        raise ValueError(f"unknown action {action!r}")
    return f"hyperion-guard/solana/{action}/v1:{agent_id}:{int(nonce)}".encode()
