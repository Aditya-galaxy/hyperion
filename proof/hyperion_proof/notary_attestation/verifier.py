"""
HYPERION PROOF: NOTARY ATTESTATION VERIFIER
===========================================
Validates notary-signed session attestations before metrics computation
or ERC-8004 Reputation Registry anchoring.
"""

from __future__ import annotations

import time
from typing import Optional, Set

from eth_account import Account
from eth_account.messages import encode_defunct

from .attestation import NotaryAttestation


class NotaryVerificationError(Exception):
    """Raised when a notary attestation fails cryptographic or policy checks."""


class NotaryAttestationVerifier:
    def __init__(
        self,
        trusted_notaries: Optional[Set[str]] = None,
        allowed_servers: Optional[Set[str]] = None,
        max_timestamp_skew_seconds: int = 3600 * 24 * 7,  # 7 days max age
    ):
        """
        Args:
            trusted_notaries: Set of approved 0x-prefixed notary addresses.
            allowed_servers: Set of recognized exchange API server hostnames.
            max_timestamp_skew_seconds: Allowed age of the attestation in seconds.
        """
        self.trusted_notaries = {n.lower() for n in trusted_notaries} if trusted_notaries else set()
        self.allowed_servers = {s.lower() for s in allowed_servers} if allowed_servers else {"api.hyperliquid.xyz"}
        self.max_age_s = max_timestamp_skew_seconds

    def verify(self, attestation: NotaryAttestation, current_time_s: Optional[float] = None) -> bool:
        """
        Verifies notary cryptographic signature, server hostname allowlist,
        credential redaction integrity, and timestamp freshness.
        """
        now_s = current_time_s or time.time()

        # 1. Verify Server Hostname
        if attestation.server_name.lower() not in self.allowed_servers:
            raise NotaryVerificationError(
                f"Untrusted exchange server name '{attestation.server_name}'. "
                f"Allowed servers: {sorted(list(self.allowed_servers))}"
            )

        # 2. Check Credential Redaction (Ensure sensitive credentials are never leaked in plain text)
        for header, val in attestation.redacted_headers.items():
            h_lower = header.lower()
            if any(k in h_lower for k in ("key", "secret", "auth", "token", "signature")):
                if not (val.startswith("[REDACTED") or val == "***"):
                    raise NotaryVerificationError(
                        f"Unredacted sensitive credential detected in header '{header}'"
                    )

        # 3. Verify Timestamp Freshness
        attestation_time_s = attestation.timestamp_ms / 1000.0
        if attestation_time_s > now_s + 300:  # 5 min future tolerance
            raise NotaryVerificationError(f"Attestation timestamp is in the future: {attestation.timestamp_ms}")
        if (now_s - attestation_time_s) > self.max_age_s:
            raise NotaryVerificationError(
                f"Attestation has expired: age {now_s - attestation_time_s:.0f}s > {self.max_age_s}s"
            )

        # 4. Cryptographic Signature Verification
        digest = attestation.claims_digest()
        msg = encode_defunct(hexstr=digest)
        try:
            recovered_signer = Account.recover_message(msg, signature=attestation.notary_signature).lower()
        except Exception as exc:
            raise NotaryVerificationError(f"Failed to recover notary signature: {exc}") from None

        if recovered_signer != attestation.notary_pubkey.lower():
            raise NotaryVerificationError(
                f"Notary signature mismatch: declared {attestation.notary_pubkey}, recovered {recovered_signer}"
            )

        if self.trusted_notaries and recovered_signer not in self.trusted_notaries:
            raise NotaryVerificationError(f"Notary {recovered_signer} is not in the trusted notary committee")

        return True
