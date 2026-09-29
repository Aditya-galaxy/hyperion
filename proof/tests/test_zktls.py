"""
TEST SUITE: HYPERION PROOF zkTLS MODULE
=======================================
Tests zkTLS attestation generation, cryptographic notary signing,
evidence hashing, credential redaction, tampering detection, and
Binance trade normalization for Modified Dietz.
"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest
from eth_account import Account

from hyperion_proof.metrics import compute_modified_dietz
from hyperion_proof.zktls import (
    KNOWN_CERT_FINGERPRINTS,
    ZkTlsAttestation,
    ZkTlsVerificationError,
    ZkTlsVerifier,
    create_binance_zktls_attestation,
    normalize_binance_trades,
    sign_zktls_attestation,
)

NOTARY_KEY = "0x" + "77" * 32
NOTARY_ADDR = Account.from_key(NOTARY_KEY).address


def mock_binance_trades():
    return [
        {
            "id": 1001,
            "symbol": "BTCUSDT",
            "price": "60000.00",
            "qty": "0.1",
            "quoteQty": "6000.00",
            "commission": "6.00",
            "commissionAsset": "USDT",
            "time": 1727000000000,
            "isBuyer": True,
        },
        {
            "id": 1002,
            "symbol": "BTCUSDT",
            "price": "63000.00",
            "qty": "0.1",
            "quoteQty": "6300.00",
            "commission": "6.30",
            "commissionAsset": "USDT",
            "time": 1727003600000,
            "isBuyer": False, # Sells for profit: 0.1 * (63000 - 60000) = +300 PnL
        },
    ]


def test_zktls_attestation_signing_and_verification():
    trades = mock_binance_trades()
    attestation = create_binance_zktls_attestation(
        raw_trades_or_balances=trades,
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1727000000000,
    )
    assert attestation.notary_pubkey == NOTARY_ADDR
    assert attestation.notary_signature.startswith("0x")

    # Verify with trusted notary
    verifier = ZkTlsVerifier(
        trusted_notaries={NOTARY_ADDR},
        max_timestamp_skew_seconds=3600 * 24 * 365, # 1 yr
    )
    assert verifier.verify(attestation, current_time_s=1727000000.0)


def test_zktls_tampering_payload_breaks_signature():
    trades = mock_binance_trades()
    attestation = create_binance_zktls_attestation(
        raw_trades_or_balances=trades,
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1727000000000,
    )

    # Malicious actor changes trade price from 63000 to 99000
    tampered_payload = json.loads(json.dumps(trades))
    tampered_payload[1]["price"] = "99000.00"
    attestation.revealed_payload = tampered_payload

    verifier = ZkTlsVerifier(trusted_notaries={NOTARY_ADDR}, max_timestamp_skew_seconds=3600 * 24 * 365)
    with pytest.raises(ZkTlsVerificationError, match="Notary signature mismatch"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_zktls_tampering_cert_fingerprint_rejected():
    trades = mock_binance_trades()
    attestation = create_binance_zktls_attestation(
        raw_trades_or_balances=trades,
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1727000000000,
    )
    # Impersonate server with rogue certificate
    attestation.cert_fingerprint_sha256 = "0x" + "00" * 32
    # Even if notary signs the bad cert, verifier rejects untrusted fingerprint
    sign_zktls_attestation(attestation, NOTARY_KEY)

    verifier = ZkTlsVerifier(trusted_notaries={NOTARY_ADDR}, max_timestamp_skew_seconds=3600 * 24 * 365)
    with pytest.raises(ZkTlsVerificationError, match="TLS certificate mismatch"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_zktls_rejects_unredacted_credentials():
    trades = mock_binance_trades()
    attestation = create_binance_zktls_attestation(
        raw_trades_or_balances=trades,
        api_key_masked="RAW_UNMASKED_SECRET_API_KEY_12345", # Leak!
        notary_private_key=NOTARY_KEY,
        timestamp_ms=1727000000000,
    )

    verifier = ZkTlsVerifier(trusted_notaries={NOTARY_ADDR}, max_timestamp_skew_seconds=3600 * 24 * 365)
    with pytest.raises(ZkTlsVerificationError, match="Unredacted sensitive credential detected"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_zktls_untrusted_notary_rejected():
    trades = mock_binance_trades()
    unauthorized_key = "0x" + "99" * 32
    attestation = create_binance_zktls_attestation(
        raw_trades_or_balances=trades,
        notary_private_key=unauthorized_key,
        timestamp_ms=1727000000000,
    )

    verifier = ZkTlsVerifier(trusted_notaries={NOTARY_ADDR}, max_timestamp_skew_seconds=3600 * 24 * 365)
    with pytest.raises(ZkTlsVerificationError, match="is not in the trusted notary committee"):
        verifier.verify(attestation, current_time_s=1727000000.0)


def test_binance_trade_normalization_to_modified_dietz():
    trades = mock_binance_trades()
    fills = normalize_binance_trades(trades)

    assert len(fills) == 2
    assert fills[0].side == "B"
    assert fills[1].side == "A"
    # Fill 1 realized PnL = 0.1 * (63000 - 60000) = +300
    assert fills[1].closed_pnl == Decimal("300")
    assert fills[0].fee == Decimal("6.00")
    assert fills[1].fee == Decimal("6.30")

    # Compute Modified Dietz using normalized Binance fills
    out = compute_modified_dietz(
        v_start=Decimal("10000"),
        v_end=Decimal("10287.70"), # 10000 + 300 - 12.30
        t_start_ms=1727000000000,
        t_end_ms=1727086400000, # 1 day
        cash_flows=[],
        fills=fills,
    )
    assert out["tradesCount"] == 2
    assert Decimal(out["realizedPnlUsd"]) == Decimal("300")
    assert Decimal(out["totalFeesUsd"]) == Decimal("12.30")
    assert Decimal(out["netTradePnlUsd"]) == Decimal("287.70")
    assert Decimal(out["winRate"]) == Decimal("0.5") # 1 trade had closed_pnl=0, 1 had closed_pnl=300
