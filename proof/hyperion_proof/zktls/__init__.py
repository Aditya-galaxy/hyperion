"""
HYPERION PROOF: zkTLS Attestation Package
=========================================
"""

from .attestation import (
    KNOWN_CERT_FINGERPRINTS,
    SCHEMA_ZKTLS,
    ZkTlsAttestation,
    sign_zktls_attestation,
)
from .binance import (
    create_binance_zktls_attestation,
    normalize_binance_trades,
)
from .verifier import (
    ZkTlsVerificationError,
    ZkTlsVerifier,
)

__all__ = [
    "KNOWN_CERT_FINGERPRINTS",
    "SCHEMA_ZKTLS",
    "ZkTlsAttestation",
    "sign_zktls_attestation",
    "create_binance_zktls_attestation",
    "normalize_binance_trades",
    "ZkTlsVerificationError",
    "ZkTlsVerifier",
]
