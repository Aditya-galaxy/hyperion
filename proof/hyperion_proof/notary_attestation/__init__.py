"""
HYPERION PROOF: Notary-Signed Attestation Package (Prototype)
============================================================
Cryptographic data structures, signing, and verification engines for
notary-signed HTTP responses from exchange APIs (Hyperliquid).
"""

from .attestation import (
    NotaryAttestation,
    SCHEMA_NOTARY_ATTESTATION,
    create_hyperliquid_notary_attestation,
    normalize_hyperliquid_fills,
    sign_notary_attestation,
)
from .verifier import (
    NotaryAttestationVerifier,
    NotaryVerificationError,
)

__all__ = [
    "NotaryAttestation",
    "NotaryAttestationVerifier",
    "NotaryVerificationError",
    "SCHEMA_NOTARY_ATTESTATION",
    "create_hyperliquid_notary_attestation",
    "normalize_hyperliquid_fills",
    "sign_notary_attestation",
]
