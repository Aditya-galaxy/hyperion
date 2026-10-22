"""
HYPERION HYPERLIQUID GUARD: WHAT AN OWNER OR GUARDIAN SIGNS
===========================================================
Control messages (set a policy, kill, revive) are EIP-191 personal-sign
messages from the owner's or guardian's Ethereum key, the same key type
Hyperliquid uses. Defined once, here, so the API and anything building
requests sign the same bytes.

The policy message covers every field, and each message carries a nonce the
Guard keeps the highest of per account, so nothing can be altered in transit
or replayed: an old "revive" can't undo a newer kill.
"""

from __future__ import annotations

import json

from eth_account import Account
from eth_account.messages import encode_defunct

POLICY_DOMAIN = "hyperion-guard/hyperliquid/policy/v1:"


def policy_message(*, network: str, account: str, agent: str, owner: str, guardian: str, max_order_notional_usd: float,
                   daily_notional_cap_usd: float, max_slippage_bps: int, max_leverage: int,
                   allowed_coins: list[str] | None, policy_version: int, nonce: int) -> str:
    body = {
        "network": network,
        "account": account.lower(),
        "agent": agent.lower(),
        "owner": owner.lower(),
        "guardian": guardian.lower(),
        "max_order_notional_usd": f"{float(max_order_notional_usd):.2f}",
        "daily_notional_cap_usd": f"{float(daily_notional_cap_usd):.2f}",
        "max_slippage_bps": int(max_slippage_bps),
        "max_leverage": int(max_leverage),
        "allowed_coins": sorted(allowed_coins) if allowed_coins else None,
        "policy_version": int(policy_version),
        "nonce": int(nonce),
    }
    return POLICY_DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":"))


def action_message(action: str, account: str, nonce: int) -> str:
    """For "kill" and "revive"."""
    if action not in ("kill", "revive"):
        raise ValueError(f"unknown action {action!r}")
    return f"hyperion-guard/hyperliquid/{action}/v1:{account.lower()}:{int(nonce)}"


def sign_message(key: str | bytes, message: str) -> str:
    return "0x" + Account.sign_message(encode_defunct(text=message), key).signature.hex().removeprefix("0x")


def signer_of(message: str, signature: str) -> str | None:
    """The address that signed `message`, lower-case, or None if the signature is malformed."""
    try:
        return Account.recover_message(encode_defunct(text=message), signature=signature).lower()
    except Exception:  # noqa: BLE001 — any malformed signature is simply not a signature
        return None
