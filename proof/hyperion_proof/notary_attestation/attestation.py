"""
HYPERION PROOF: NOTARY-SIGNED ATTESTATION (PROTOTYPE)
=====================================================
Defines cryptographic data structures and signing protocols for notary-signed
HTTP response attestations over exchange data (Hyperliquid).

This prototype implements a trusted notary / oracle signing model over canonical
JSON payloads from public exchange APIs as a development precursor to production
MPC-TLS (e.g. TLSNotary / Reclaim Protocol) zero-knowledge attestation.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from decimal import Decimal
from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

from ..metrics import TradeFill

SCHEMA_NOTARY_ATTESTATION = "hyperion-proof/notary-attestation/v1"


@dataclass
class NotaryAttestation:
    """A notary-signed HTTP session attestation (prototype)."""
    session_id: str                      # Unique 32-byte session identifier (0x-hex)
    venue: str                           # "hyperliquid"
    server_name: str                     # "api.hyperliquid.xyz"
    endpoint: str                        # "/info", etc.
    notary_pubkey: str                   # Notary address (0x-prefixed)
    notary_signature: str                # Notary signature over canonical claims
    transcript_commitment: str           # Keccak-256 hash of payload/response
    redacted_headers: dict[str, str]     # Headers with sensitive keys masked
    revealed_payload: Any                # Plaintext JSON response (trades, balances, fills)
    timestamp_ms: int                    # Handshake epoch timestamp in milliseconds

    def canonical_bytes(self) -> bytes:
        """Deterministic UTF-8 JSON serialization of attested claims (excluding notary signature)."""
        claims = {
            "session_id": self.session_id,
            "venue": self.venue,
            "server_name": self.server_name,
            "endpoint": self.endpoint,
            "notary_pubkey": self.notary_pubkey.lower(),
            "transcript_commitment": self.transcript_commitment,
            "redacted_headers": self.redacted_headers,
            "revealed_payload": self.revealed_payload,
            "timestamp_ms": self.timestamp_ms,
        }
        return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    def claims_digest(self) -> str:
        """Keccak-256 hash of canonical attested claims."""
        return "0x" + keccak(self.canonical_bytes()).hex()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["schema"] = SCHEMA_NOTARY_ATTESTATION
        return d

    @classmethod
    def from_dict(cls, data: dict) -> NotaryAttestation:
        return cls(
            session_id=data["session_id"],
            venue=data["venue"],
            server_name=data["server_name"],
            endpoint=data["endpoint"],
            notary_pubkey=data["notary_pubkey"],
            notary_signature=data["notary_signature"],
            transcript_commitment=data["transcript_commitment"],
            redacted_headers=dict(data.get("redacted_headers", {})),
            revealed_payload=data["revealed_payload"],
            timestamp_ms=int(data["timestamp_ms"]),
        )


def sign_notary_attestation(
    attestation: NotaryAttestation,
    notary_private_key: str,
) -> NotaryAttestation:
    """Signs the notary attestation using the notary's private key."""
    attestation.notary_pubkey = Account.from_key(notary_private_key).address
    digest = attestation.claims_digest()
    msg = encode_defunct(hexstr=digest)
    signed = Account.sign_message(msg, private_key=notary_private_key)
    attestation.notary_signature = "0x" + signed.signature.hex().removeprefix("0x")
    return attestation


def normalize_hyperliquid_fills(raw_fills: list[dict[str, Any]]) -> list[TradeFill]:
    """
    Normalizes Hyperliquid public userFills response into standard TradeFill objects.
    Each raw fill from /info {"type": "userFills"} has:
        coin, px, sz, side ('B' or 'A'), time, closedPnl, fee, tid, oid, hash
    """
    fills: list[TradeFill] = []
    for f in sorted(raw_fills, key=lambda x: int(x.get("time", 0))):
        coin = str(f.get("coin", "UNKNOWN"))
        px = Decimal(str(f["px"]))
        sz = Decimal(str(f["sz"]))
        side = str(f.get("side", "B")).upper()
        closed_pnl = Decimal(str(f.get("closedPnl", "0")))
        fee = Decimal(str(f.get("fee", "0")))
        t_ms = int(f.get("time", 0))

        fills.append(
            TradeFill(
                t_ms=t_ms,
                coin=coin,
                px=px,
                sz=sz,
                side=side,
                closed_pnl=closed_pnl,
                fee=fee,
            )
        )
    return fills


def create_hyperliquid_notary_attestation(
    payload: Any,
    notary_private_key: str,
    endpoint: str = "/info",
    session_id: str | None = None,
    timestamp_ms: int | None = None,
    custom_headers: dict[str, str] | None = None,
) -> NotaryAttestation:
    """
    Constructs and signs a NotaryAttestation prototype for Hyperliquid response data.
    """
    t_ms = timestamp_ms or int(time.time() * 1000)
    s_id = session_id or ("0x" + hashlib.sha256(f"hyperliquid-session:{t_ms}".encode()).hexdigest())

    payload_canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    transcript_commitment = "0x" + keccak(payload_canonical).hex()

    headers = {
        "Host": "api.hyperliquid.xyz",
        "Content-Type": "application/json",
        "User-Agent": "Hyperion-Notary-Client/1.0",
    }
    if custom_headers:
        headers.update(custom_headers)

    attestation = NotaryAttestation(
        session_id=s_id,
        venue="hyperliquid",
        server_name="api.hyperliquid.xyz",
        endpoint=endpoint,
        notary_pubkey="",
        notary_signature="",
        transcript_commitment=transcript_commitment,
        redacted_headers=headers,
        revealed_payload=payload,
        timestamp_ms=t_ms,
    )
    return sign_notary_attestation(attestation, notary_private_key)
