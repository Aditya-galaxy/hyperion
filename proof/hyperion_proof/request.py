"""
HYPERION PROOF: THE SIGNED REQUEST
==================================
An attestation is only worth something if the account belongs to the agent.
The request is an EIP-712 message signed by the trading account's own key,
naming the ERC-8004 agent it's for. The validator checks the signature
before looking at any data, and the signed request goes into the evidence
file, so anyone can check the binding too.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
    ],
    "TrackRecordRequest": [
        {"name": "agentRegistry", "type": "string"},   # e.g. eip155:5042:0x8004A169…
        {"name": "agentId", "type": "uint256"},
        {"name": "venue", "type": "string"},           # "hyperliquid"
        {"name": "account", "type": "address"},        # the trading account being scored
        {"name": "window", "type": "string"},          # "month", "allTime", …
        {"name": "issuedAt", "type": "uint64"},        # unix seconds
    ],
}
DOMAIN = {"name": "HyperionProof", "version": "1"}
WINDOWS = ("day", "week", "month", "allTime", "perpDay", "perpWeek", "perpMonth", "perpAllTime")
MAX_AGE_S = 7 * 24 * 3600


@dataclass(frozen=True)
class Request:
    agentRegistry: str
    agentId: int
    venue: str
    account: str
    window: str
    issuedAt: int

    def message(self) -> dict:
        d = asdict(self)
        d["account"] = to_checksum_address(self.account)
        return d


def _typed(r: Request):
    return encode_typed_data(full_message={"types": TYPES, "primaryType": "TrackRecordRequest",
                                           "domain": DOMAIN, "message": r.message()})


def sign(r: Request, private_key: str) -> str:
    return "0x" + Account.sign_message(_typed(r), private_key=private_key).signature.hex().removeprefix("0x")


def check(r: Request, signature: str, now: int) -> str | None:
    """None if the request is valid, otherwise why not."""
    if r.venue != "hyperliquid":
        return f"unsupported venue {r.venue!r}"
    if r.window not in WINDOWS:
        return f"window must be one of {', '.join(WINDOWS)}"
    parts = r.agentRegistry.split(":")
    if len(parts) != 3 or parts[0] != "eip155" or not parts[1].isdigit():
        return "agentRegistry must look like eip155:<chainId>:<address>"
    if not (now - MAX_AGE_S <= r.issuedAt <= now + 300):
        return "request is stale or from the future"
    try:
        signer = Account.recover_message(_typed(r), signature=signature)
    except Exception:  # noqa: BLE001 — malformed signature bytes
        return "signature doesn't parse"
    if signer.lower() != r.account.lower():
        return "signature isn't from the account being scored"
    return None
