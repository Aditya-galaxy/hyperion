"""
HYPERION PAYMENTS GUARD: WHAT GETS SIGNED
=========================================
Three kinds of message, each defined once here so the API and every client
sign the same bytes:

  policy, kill, revive   EIP-191 messages from the owner's (or guardian's)
                         Ethereum key; each carries a nonce, kept the highest
                         of per agent, so none can be replayed
  a payout request       EIP-191, from the agent's key: the Guard judges only
                         requests the agent signed
  an approval            EIP-712 from the Guard's key, over exactly one payout.
                         A payer verifies it before sending money (viem's
                         verifyTypedData, or any EIP-712 library)
"""

from __future__ import annotations

import json
from decimal import Decimal

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

from ..hyperliquid.control import sign_message, signer_of  # noqa: F401 — the same EIP-191 helpers

POLICY_DOMAIN = "hyperion-guard/payments/policy/v1:"
REQUEST_DOMAIN = "hyperion-guard/payments/request/v1:"

APPROVAL_DOMAIN = {"name": "Hyperion Guard Payments", "version": "1"}
APPROVAL_TYPES = {
    "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"}],
    "PaymentApproval": [
        {"name": "agent", "type": "address"},
        {"name": "payer", "type": "address"},
        {"name": "recipient", "type": "address"},
        {"name": "token", "type": "address"},
        {"name": "chain", "type": "string"},
        {"name": "amount", "type": "uint256"},      # in the token's base units (USDC: 6 decimals)
        {"name": "intentId", "type": "string"},
        {"name": "policyVersion", "type": "uint32"},
        {"name": "expiresAt", "type": "uint64"},     # unix seconds
    ],
}


def _json(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def usd(value: float | Decimal | str) -> str:
    return f"{Decimal(str(value)):.2f}"


def policy_message(*, agent: str, owner: str, guardian: str, payers: list[str], chains: list[str], tokens: list[str],
                   max_per_payment_usdc: float, daily_cap_usdc: float, max_per_recipient_daily_usdc: float,
                   policy_version: int, nonce: int) -> str:
    return POLICY_DOMAIN + _json({
        "agent": agent.lower(), "owner": owner.lower(), "guardian": guardian.lower(),
        "payers": sorted(p.lower() for p in payers), "chains": sorted(chains), "tokens": sorted(t.lower() for t in tokens),
        "max_per_payment_usdc": usd(max_per_payment_usdc), "daily_cap_usdc": usd(daily_cap_usdc),
        "max_per_recipient_daily_usdc": usd(max_per_recipient_daily_usdc),
        "policy_version": int(policy_version), "nonce": int(nonce),
    })


def action_message(action: str, agent: str, nonce: int) -> str:
    """For "kill" and "revive"."""
    if action not in ("kill", "revive"):
        raise ValueError(f"unknown action {action!r}")
    return f"hyperion-guard/payments/{action}/v1:{agent.lower()}:{int(nonce)}"


def request_message(*, agent: str, payer: str, recipient: str, token: str, chain: str, amount: str, intent_id: str,
                    expires_at: int, simulate: bool) -> str:
    return REQUEST_DOMAIN + _json({
        "agent": agent.lower(), "payer": payer.lower(), "recipient": recipient.lower(), "token": token.lower(),
        "chain": chain, "amount": amount, "intent_id": intent_id, "expires_at": int(expires_at), "simulate": bool(simulate),
    })


def approval_typed_data(*, agent: str, payer: str, recipient: str, token: str, chain: str, amount_units: int,
                        intent_id: str, policy_version: int, expires_at: int) -> dict:
    return {
        "domain": APPROVAL_DOMAIN, "types": APPROVAL_TYPES, "primaryType": "PaymentApproval",
        "message": {"agent": to_checksum_address(agent), "payer": to_checksum_address(payer),
                    "recipient": to_checksum_address(recipient), "token": to_checksum_address(token), "chain": chain,
                    "amount": int(amount_units), "intentId": intent_id, "policyVersion": int(policy_version),
                    "expiresAt": int(expires_at)},
    }


def sign_approval(key: str | bytes, typed: dict) -> str:
    return "0x" + Account.sign_message(encode_typed_data(full_message=typed), key).signature.hex().removeprefix("0x")


def approval_signer(typed: dict, signature: str) -> str:
    return Account.recover_message(encode_typed_data(full_message=typed), signature=signature)
