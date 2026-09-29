"""
TEST SUITE: HYPERION SOLANA GUARD
==================================
Tests Base58 encoding, Solana transaction decoding, DEX instruction extraction,
and pre-trade firewall policy enforcement (kill switch, notional cap, slippage collar,
program allowlisting, Ed25519 co-signing).
"""

from __future__ import annotations

import struct
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from hyperion_guard.solana import (
    b58encode,
    b58decode,
    decode_solana_transaction,
    JUPITER_V6_PROGRAM_ID,
    PHOENIX_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
    SolanaAgentPolicy,
    SolanaGuardEngine,
)

def build_mock_solana_tx(
    program_id_b58: str,
    instruction_data: bytes,
    agent_pubkey_b58: str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    num_signatures: int = 1,
) -> bytes:
    """Helper to synthesize a valid wire-format Solana transaction payload."""
    agent_pubkey = b58decode(agent_pubkey_b58)
    prog_pubkey = b58decode(program_id_b58)
    blockhash = b"B" * 32

    # 1. Signatures
    # compact-u16 len = 1
    raw = bytearray([num_signatures])
    for _ in range(num_signatures):
        raw.extend(b"\x00" * 64) # dummy 64-byte signature slot

    # 2. Message Header (3 bytes: 1 required sig, 0 readonly signed, 1 readonly unsigned)
    msg = bytearray([1, 0, 1])

    # 3. Account keys: [agent_pubkey, prog_pubkey]
    msg.append(2) # 2 accounts
    msg.extend(agent_pubkey)
    msg.extend(prog_pubkey)

    # 4. Recent blockhash
    msg.extend(blockhash)

    # 5. Instructions (1 instruction calling prog_pubkey with instruction_data)
    msg.append(1) # 1 instruction
    msg.append(1) # program_id is index 1

    # Accounts passed to instruction: [index 0 (agent)]
    msg.append(1) # 1 account
    msg.append(0) # account index 0

    # Data
    data_len = len(instruction_data)
    msg.append(data_len)
    msg.extend(instruction_data)

    # Combine signatures + message
    raw.extend(msg)
    return bytes(raw)

# ── 1. Base58 Encoding Tests ──────────────────────────────────────────────────

def test_base58_roundtrip():
    data = b"Solana Agent Safety by Hyperion"
    encoded = b58encode(data)
    assert b58decode(encoded) == data

def test_base58_leading_zeros():
    data = b"\x00\x00\x00\x01\x02\x03"
    encoded = b58encode(data)
    assert encoded.startswith("111")
    assert b58decode(encoded) == data

# ── 2. Solana Transaction & DEX Decoding Tests ────────────────────────────────

def test_decode_jupiter_v6_swap():
    # Construct Jupiter V6 route instruction:
    # 8-byte discriminator + in_amount (u64) + quoted_out (u64) + slippage_bps (u16)
    disc = bytes.fromhex("e517cb977ae3ad2a")
    in_amt = 1_000_000_000 # 1,000 USDC (6 decimals)
    quoted_out = 998_000_000
    slippage_bps = 50 # 50 bps = 0.5%
    data = disc + struct.pack("<QQH", in_amt, quoted_out, slippage_bps)

    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data)
    decoded = decode_solana_transaction(tx_bytes)

    assert len(decoded.instructions) == 1
    inst = decoded.instructions[0]
    assert inst.program_id == JUPITER_V6_PROGRAM_ID
    assert inst.operation == "JUPITER_SWAP"
    assert inst.input_amount == in_amt
    assert inst.slippage_bps == 50

def test_decode_phoenix_limit_order():
    # Phoenix NewOrder tag = 1, side = 0 (BID), price_ticks = 1000, lots = 500
    data = bytes([1, 0]) + struct.pack("<QQ", 1000, 500)
    tx_bytes = build_mock_solana_tx(PHOENIX_PROGRAM_ID, data)
    decoded = decode_solana_transaction(tx_bytes)

    assert len(decoded.instructions) == 1
    inst = decoded.instructions[0]
    assert inst.program_id == PHOENIX_PROGRAM_ID
    assert inst.operation == "PHOENIX_LIMIT_ORDER"
    assert inst.details["side"] == "BID"

# ── 3. Solana Guard Policy & Firewall Enforcement Tests ───────────────────────

def test_guard_approves_safe_jupiter_swap():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        max_order_notional_usd=2_000.0,
        max_slippage_bps=100,
    )
    engine.set_policy(policy)

    # Safe swap: 500 USDC ($500 < $2,000 cap), 50 bps slippage (< 100 bps)
    disc = bytes.fromhex("e517cb977ae3ad2a")
    data = disc + struct.pack("<QQH", 500_000_000, 498_000_000, 50)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert verdict.approved
    assert verdict.status == "APPROVED"
    assert verdict.cosigner_signature_b58 is not None

    # Verify Ed25519 co-signature authenticity
    raw_sig = b58decode(verdict.cosigner_signature_b58)
    raw_pub = b58decode(verdict.cosigner_pubkey)
    pub_key = eddsa.import_public_key(raw_pub)
    verifier = eddsa.new(pub_key, "rfc8032")
    # Message bytes from tx
    decoded_tx = decode_solana_transaction(tx_bytes)
    verifier.verify(decoded_tx.message_bytes, raw_sig)

def test_guard_rejects_oversized_order_cap():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        max_order_notional_usd=1_000.0,
    )
    engine.set_policy(policy)

    # Oversized swap: 5,000 USDC ($5,000 > $1,000 cap)
    disc = bytes.fromhex("e517cb977ae3ad2a")
    data = disc + struct.pack("<QQH", 5_000_000_000, 4_900_000_000, 50)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_ORDER_CAP"
    assert verdict.cosigner_signature_b58 is None
    assert "exceeds cap" in verdict.violation_details

def test_guard_rejects_excessive_slippage_mev_risk():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        max_slippage_bps=100, # 1% max
    )
    engine.set_policy(policy)

    # Excessive slippage: 400 bps (4.0% slippage exposes agent to sandwich attack)
    disc = bytes.fromhex("e517cb977ae3ad2a")
    data = disc + struct.pack("<QQH", 500_000_000, 480_000_000, 400)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_EXCESSIVE_SLIPPAGE"
    assert "Slippage tolerance 400 bps exceeds max limit" in verdict.violation_details

def test_guard_rejects_unauthorized_target_program():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    )
    engine.set_policy(policy)

    # Malicious or unknown contract address (valid 32-byte pubkey)
    malicious_program = b58encode(b"D" * 32)
    tx_bytes = build_mock_solana_tx(malicious_program, b"drain_all")

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_UNAUTHORIZED_PROGRAM"
    assert "is not in policy allowlist" in verdict.violation_details

def test_guard_kill_switch_blocks_execution_and_revival():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    )
    engine.set_policy(policy)

    # Trip emergency kill switch
    assert engine.kill_agent("sol-agent-1")

    disc = bytes.fromhex("e517cb977ae3ad2a")
    data = disc + struct.pack("<QQH", 100_000_000, 99_000_000, 50)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_KILL_SWITCH"

    # Revive agent
    assert engine.revive_agent("sol-agent-1")
    verdict_after = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert verdict_after.approved
    assert verdict_after.status == "APPROVED"


def test_solana_api_lifecycle():
    import base64
    from fastapi.testclient import TestClient
    from hyperion_guard.api import create_app

    engine = SolanaGuardEngine()
    app = create_app(guard=None, solana_guard=engine)
    client = TestClient(app)

    # 1. Health check
    res_health = client.get("/v1/solana/health")
    assert res_health.status_code == 200
    assert res_health.json()["ok"] is True
    assert res_health.json()["cosigner_pubkey"] == engine.pubkey_b58

    # 2. Configure policy
    policy_payload = {
        "agent_id": "test-agent-solana",
        "owner_solana_pubkey": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        "max_order_notional_usd": 1500.0,
        "max_slippage_bps": 50,
        "allowed_programs": [JUPITER_V6_PROGRAM_ID],
    }
    res_set = client.post("/v1/solana/policy", json=policy_payload)
    assert res_set.status_code == 200
    assert res_set.json()["ok"] is True

    # 3. Read policy back
    res_get = client.get("/v1/solana/policy/test-agent-solana")
    assert res_get.status_code == 200
    assert res_get.json()["max_order_notional_usd"] == 1500.0
    assert res_get.json()["killed"] is False

    # 4. Check safe transaction (Base64 encoding)
    disc = bytes.fromhex("e517cb977ae3ad2a")
    data = disc + struct.pack("<QQH", 500_000_000, 498_000_000, 30)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data)
    tx_b64 = base64.b64encode(tx_bytes).decode("ascii")

    res_check = client.post("/v1/solana/check", json={
        "agent_id": "test-agent-solana",
        "tx_bytes": tx_b64,
        "encoding": "base64",
    })
    assert res_check.status_code == 200
    body = res_check.json()
    assert body["approved"] is True
    assert body["status"] == "APPROVED"
    assert body["cosigner_signature_b58"] is not None

    # 5. Check violating transaction (Excessive slippage: 80 bps > 50 bps)
    bad_data = disc + struct.pack("<QQH", 500_000_000, 498_000_000, 80)
    bad_tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, bad_data)
    bad_tx_b58 = b58encode(bad_tx_bytes)

    res_bad = client.post("/v1/solana/check", json={
        "agent_id": "test-agent-solana",
        "tx_bytes": bad_tx_b58,
        "encoding": "base58",
    })
    assert res_bad.status_code == 200
    assert res_bad.json()["approved"] is False
    assert res_bad.json()["status"] == "REJECTED_EXCESSIVE_SLIPPAGE"

    # 6. Kill switch endpoint
    res_kill = client.post("/v1/solana/kill", json={
        "agent_id": "test-agent-solana",
        "reason": "Risk officer halted trading",
    })
    assert res_kill.status_code == 200
    assert res_kill.json()["killed"] is True

    # 7. Check that previously safe tx is now rejected by kill switch
    res_blocked = client.post("/v1/solana/check", json={
        "agent_id": "test-agent-solana",
        "tx_bytes": tx_b64,
    })
    assert res_blocked.status_code == 200
    assert res_blocked.json()["approved"] is False
    assert res_blocked.json()["status"] == "REJECTED_KILL_SWITCH"

