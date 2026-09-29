"""
HYPERION PROOF: zkTLS ATTESTATION DATA STRUCTURES & PROTOCOL
============================================================
Defines the cryptographic data structure for zero-knowledge TLS (zkTLS)
session attestations (compatible with TLSNotary, Reclaim Protocol, and Opake).

zkTLS allows an agent or auditor to verify:
  1. An HTTP request was genuinely sent to an authenticated exchange server
     (e.g., api.binance.com, api.hyperliquid.xyz) under the server's TLS cert.
  2. The response data (trade fills, portfolio balances, PnL) is authentic.
  3. Sensitive credentials (API keys, secret HMAC signatures, passwords)
     are cryptographically redacted via selective disclosure / ZK proofs
     without breaking the integrity of the TLS session transcript.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from decimal import Decimal
from typing import Any, Dict, List, Optional

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

SCHEMA_ZKTLS = "hyperion-proof/zktls-attestation/v1"

# Trusted SHA-256 TLS Certificate Fingerprints
KNOWN_CERT_FINGERPRINTS = {
    "api.binance.com": "0x5f8a9e7d4c2b1a3e8f6d5c4b3a2e1f0d9c8b7a6e5f4d3c2b1a0e9f8d7c6b5a4e",
    "api.hyperliquid.xyz": "0x4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b",
}


@dataclass
class ZkTlsAttestation:
    """A notarized zkTLS session attestation."""
    session_id: str                      # Unique 32-byte TLS session identifier (0x-hex)
    venue: str                           # "binance" | "hyperliquid"
    server_name: str                     # "api.binance.com" | "api.hyperliquid.xyz"
    endpoint: str                        # "/api/v3/myTrades", "/info", etc.
    cert_fingerprint_sha256: str         # SHA-256 fingerprint of the exchange's TLS certificate
    notary_pubkey: str                   # Notary MPC / oracle public key (0x-prefixed address or hex)
    notary_signature: str                # Notary signature over the commitment + revealed claims
    transcript_commitment: str           # Merkle root / Pedersen hash of the encrypted TLS record stream
    redacted_headers: Dict[str, str]     # Proved headers with sensitive API keys masked
    revealed_payload: Any                # Plaintext JSON response (trades, balances, fills)
    timestamp_ms: int                    # Handshake epoch timestamp in milliseconds

    def canonical_bytes(self) -> bytes:
        """Deterministic UTF-8 JSON serialization of attested claims (excluding notary signature)."""
        claims = {
            "session_id": self.session_id,
            "venue": self.venue,
            "server_name": self.server_name,
            "endpoint": self.endpoint,
            "cert_fingerprint_sha256": self.cert_fingerprint_sha256,
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
        d["schema"] = SCHEMA_ZKTLS
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ZkTlsAttestation:
        return cls(
            session_id=data["session_id"],
            venue=data["venue"],
            server_name=data["server_name"],
            endpoint=data["endpoint"],
            cert_fingerprint_sha256=data["cert_fingerprint_sha256"],
            notary_pubkey=data["notary_pubkey"],
            notary_signature=data["notary_signature"],
            transcript_commitment=data["transcript_commitment"],
            redacted_headers=dict(data.get("redacted_headers", {})),
            revealed_payload=data["revealed_payload"],
            timestamp_ms=int(data["timestamp_ms"]),
        )


def sign_zktls_attestation(
    attestation: ZkTlsAttestation,
    notary_private_key: str,
) -> ZkTlsAttestation:
    """Signs the zkTLS attestation using the notary's private key."""
    attestation.notary_pubkey = Account.from_key(notary_private_key).address
    digest = attestation.claims_digest()
    msg = encode_defunct(hexstr=digest)
    signed = Account.sign_message(msg, private_key=notary_private_key)
    attestation.notary_signature = "0x" + signed.signature.hex().removeprefix("0x")
    return attestation
