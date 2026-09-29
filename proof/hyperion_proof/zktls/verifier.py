"""
HYPERION PROOF: zkTLS VERIFICATION ENGINE
=========================================
Validates zkTLS notarized session attestations before metrics computation
or ERC-8004 Reputation Registry anchoring.
"""

from __future__ import annotations

import time
from typing import Optional, Set

from eth_account import Account
from eth_account.messages import encode_defunct

from .attestation import KNOWN_CERT_FINGERPRINTS, ZkTlsAttestation


class ZkTlsVerificationError(Exception):
    """Raised when a zkTLS attestation fails cryptographic or policy checks."""


class ZkTlsVerifier:
    def __init__(
        self,
        trusted_notaries: Optional[Set[str]] = None,
        max_timestamp_skew_seconds: int = 3600 * 24 * 7, # 7 days max age
    ):
        """
        Args:
            trusted_notaries: Set of approved 0x-prefixed notary addresses / keys.
            max_timestamp_skew_seconds: Allowed age of the TLS attestation in seconds.
        """
        self.trusted_notaries = {n.lower() for n in trusted_notaries} if trusted_notaries else set()
        self.max_age_s = max_timestamp_skew_seconds

    def verify(self, attestation: ZkTlsAttestation, current_time_s: Optional[float] = None) -> bool:
        """
        Verifies notary cryptographic signature, certificate fingerprint,
        credential redaction integrity, and timestamp freshness.
        """
        now_s = current_time_s or time.time()

        # 1. Verify Server Name and SSL/TLS Certificate Fingerprint
        expected_cert = KNOWN_CERT_FINGERPRINTS.get(attestation.server_name)
        if not expected_cert:
            raise ZkTlsVerificationError(f"Untrusted exchange server name: {attestation.server_name}")
        if attestation.cert_fingerprint_sha256.lower() != expected_cert.lower():
            raise ZkTlsVerificationError(
                f"TLS certificate mismatch for {attestation.server_name}: "
                f"expected {expected_cert}, got {attestation.cert_fingerprint_sha256}"
            )

        # 2. Check Credential Redaction (Ensure private API keys/secrets are never leaked)
        for header, val in attestation.redacted_headers.items():
            h_lower = header.lower()
            if any(k in h_lower for k in ("key", "secret", "auth", "token", "signature")):
                if not (val.startswith("[REDACTED") or val == "***"):
                    raise ZkTlsVerificationError(
                        f"Unredacted sensitive credential detected in header '{header}'"
                    )

        # 3. Verify Timestamp Freshness
        attestation_time_s = attestation.timestamp_ms / 1000.0
        if attestation_time_s > now_s + 300: # 5 min future tolerance
            raise ZkTlsVerificationError(f"Attestation timestamp is in the future: {attestation.timestamp_ms}")
        if (now_s - attestation_time_s) > self.max_age_s:
            raise ZkTlsVerificationError(f"Attestation has expired: age {now_s - attestation_time_s:.0f}s > {self.max_age_s}s")

        # 4. Cryptographic Signature Verification
        digest = attestation.claims_digest()
        msg = encode_defunct(hexstr=digest)
        try:
            recovered_signer = Account.recover_message(msg, signature=attestation.notary_signature).lower()
        except Exception as exc:
            raise ZkTlsVerificationError(f"Failed to recover notary signature: {exc}") from None

        if recovered_signer != attestation.notary_pubkey.lower():
            raise ZkTlsVerificationError(
                f"Notary signature mismatch: declared {attestation.notary_pubkey}, recovered {recovered_signer}"
            )

        if self.trusted_notaries and recovered_signer not in self.trusted_notaries:
            raise ZkTlsVerificationError(f"Notary {recovered_signer} is not in the trusted notary committee")

        return True
