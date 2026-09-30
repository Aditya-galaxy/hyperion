"""
TEST SUITE: HYPERION PROOF NOTARY ATTESTATION MODULE
====================================================
Tests notary-signed session attestation generation, cryptographic notary signing,
canonical evidence hashing, credential redaction, tampering detection, and
Hyperliquid public userFills normalization for Modified Dietz analysis.
"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest
from eth_account import Account
from hyperion_proof.metrics import compute_modified_dietz
from hyperion_proof.notary_attestation import (
    SCHEMA_NOTARY_ATTESTATION,
    NotaryAttestationVerifier,
    NotaryVerificationError,
    create_hyperliquid_notary_attestation,
    normalize_hyperliquid_fills,
    sign_notary_attestation,
)

NOTARY_KEY = "0x" + "77" * 32
NOTARY_ADDR = Account.from_key(NOTARY_KEY).address


def mock_hyperliquid_fills():
    return [
        {
            "coin": "SOL",
            "px": "150.00",
            "sz": "10.0",
            "side": "B",
            "time": 1727000000000,
            "closedPnl": "0.0",
            "fee": "0.15",
            "tid": 1001,
            "oid": 5001,
            "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        },
        {
            "coin": "SOL",
            "px": "155.00",
            "sz": "10.0",
            "side": "A",
            "time": 1727003600000,
            "closedPnl": "50.00",  # Realized gain: 10 * (155 - 150) = +50 USDC
            "fee": "0.155",
            "tid": 1002,
            "oid": 5002,
            "hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
        },
    ]


def test_notary_attestation_signing_and_verification():
    fills_data = mock_hyperliquid_fills()
    attestation = create_hyperliquid_notary_attestation(
        payload=fills_data,
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1727000000000,
    )
    assert attestation.notary_pubkey == NOTARY_ADDR
    assert attestation.notary_signature.startswith("0x")
    assert attestation.server_name == "api.hyperliquid.xyz"
    assert attestation.to_dict()["schema"] == SCHEMA_NOTARY_ATTESTATION

    # Verify with trusted notary
    verifier = NotaryAttestationVerifier(
        trusted_notaries={NOTARY_ADDR},
        max_timestamp_skew_seconds=3600 * 24 * 365,
    )
    assert verifier.verify(attestation, current_time_s=1727000000.0)


def test_notary_tampering_payload_breaks_signature():
    fills_data = mock_hyperliquid_fills()
    attestation = create_hyperliquid_notary_attestation(
        payload=fills_data,
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1727000000000,
    )

    # 1. Tampering payload without updating commitment triggers Transcript commitment mismatch
    tampered_payload = json.loads(json.dumps(fills_data))
    tampered_payload[1]["closedPnl"] = "5000.00"
    attestation.revealed_payload = tampered_payload

    verifier = NotaryAttestationVerifier(trusted_notaries={NOTARY_ADDR}, max_timestamp_skew_seconds=3600 * 24 * 365)
    with pytest.raises(NotaryVerificationError, match="Transcript commitment mismatch"):
        verifier.verify(attestation, current_time_s=1727000000.0)

    # 2. Tampering payload AND updating transcript commitment triggers Notary signature mismatch
    from eth_utils import keccak
    payload_bytes = json.dumps(tampered_payload, sort_keys=True, separators=(",", ":")).encode()
    attestation.transcript_commitment = "0x" + keccak(payload_bytes).hex()
    with pytest.raises(NotaryVerificationError, match="Notary signature mismatch"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_notary_unauthorized_server_name_rejected():
    fills_data = mock_hyperliquid_fills()
    attestation = create_hyperliquid_notary_attestation(
        payload=fills_data,
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1727000000000,
    )
    # Impersonate server hostname
    attestation.server_name = "api.attacker-exchange.com"
    sign_notary_attestation(attestation, NOTARY_KEY)

    verifier = NotaryAttestationVerifier(trusted_notaries={NOTARY_ADDR}, max_timestamp_skew_seconds=3600 * 24 * 365)
    with pytest.raises(NotaryVerificationError, match="Untrusted exchange server name"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_notary_rejects_unredacted_credentials():
    fills_data = mock_hyperliquid_fills()
    attestation = create_hyperliquid_notary_attestation(
        payload=fills_data,
        custom_headers={"X-Auth-Token": "RAW_UNMASKED_SECRET_API_TOKEN_999"},
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1727000000000,
    )

    verifier = NotaryAttestationVerifier(trusted_notaries={NOTARY_ADDR}, max_timestamp_skew_seconds=3600 * 24 * 365)
    with pytest.raises(NotaryVerificationError, match="Unredacted sensitive credential detected"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_notary_untrusted_notary_rejected():
    fills_data = mock_hyperliquid_fills()
    unauthorized_key = "0x" + "99" * 32
    attestation = create_hyperliquid_notary_attestation(
        payload=fills_data,
        notary_private_key=unauthorized_key,
        timestamp_ms=1727000000000,
    )

    verifier = NotaryAttestationVerifier(trusted_notaries={NOTARY_ADDR}, max_timestamp_skew_seconds=3600 * 24 * 365)
    with pytest.raises(NotaryVerificationError, match="is not in the trusted notary committee"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_notary_expired_attestation_rejected():
    fills_data = mock_hyperliquid_fills()
    attestation = create_hyperliquid_notary_attestation(
        payload=fills_data,
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1700000000000,  # Old timestamp
    )

    verifier = NotaryAttestationVerifier(
        trusted_notaries={NOTARY_ADDR},
        max_timestamp_skew_seconds=3600,  # 1 hour max age
    )
    with pytest.raises(NotaryVerificationError, match="Attestation has expired"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_hyperliquid_trade_normalization_to_modified_dietz():
    raw_fills = mock_hyperliquid_fills()
    fills = normalize_hyperliquid_fills(raw_fills)

    assert len(fills) == 2
    assert fills[0].coin == "SOL"
    assert fills[0].side == "B"
    assert fills[1].side == "A"
    assert fills[1].closed_pnl == Decimal("50.00")
    assert fills[0].fee == Decimal("0.15")
    assert fills[1].fee == Decimal("0.155")

    # Feed normalized Hyperliquid fills into Modified Dietz
    out = compute_modified_dietz(
        v_start=Decimal("1500.00"),
        v_end=Decimal("1549.695"),  # 1500 + 50 - 0.305
        t_start_ms=1727000000000,
        t_end_ms=1727086400000,  # 1 day
        cash_flows=[],
        fills=fills,
    )

    assert out["method"] == "modified-dietz/v1"
    assert out["tradesCount"] == 2
    assert Decimal(out["realizedPnlUsd"]) == Decimal("50.00")
    assert Decimal(out["totalFeesUsd"]) == Decimal("0.305")
    assert Decimal(out["winRate"]) == Decimal("0.5")
    assert Decimal(out["tradeSharpeRatio"]) > Decimal(0)
