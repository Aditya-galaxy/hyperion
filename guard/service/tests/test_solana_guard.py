"""
TEST SUITE: HYPERION SOLANA GUARD
==================================
Tests Base58 encoding, Solana transaction decoding, DEX instruction extraction,
and pre-trade firewall policy enforcement (kill switch, notional cap, slippage collar,
program allowlisting, Ed25519 co-signing, required-signer enforcement, and authenticated API lifecycle).
"""

from __future__ import annotations

import base64
import struct

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from fastapi.testclient import TestClient
from hyperion_guard.api import create_app
from hyperion_guard.solana import (
    JUPITER_V6_PROGRAM_ID,
    PHOENIX_PROGRAM_ID,
    SolanaAgentPolicy,
    SolanaGuardEngine,
    b58decode,
    b58encode,
    decode_jupiter_instruction,
    decode_solana_transaction,
)
from hyperion_guard.solana.control import policy_message


def build_jupiter_ix_data(
    in_amt: int,
    quoted_out: int,
    slippage_bps: int,
    disc_hex: str = "e517cb977ae3ad2a",
    platform_fee_bps: int = 0,
) -> bytes:
    """Builds synthetic Jupiter instruction data with variable routePlan and 19-byte suffix."""
    disc = bytes.fromhex(disc_hex)
    mock_route_plan = b"\x01\x00\x00\x00\x01\x02\x03\x04"
    return disc + mock_route_plan + struct.pack("<QQHB", in_amt, quoted_out, slippage_bps, platform_fee_bps)


def build_mock_solana_tx(
    program_id_b58: str,
    instruction_data: bytes,
    agent_pubkey_b58: str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    guard_pubkey_b58: str | None = None,
    num_signatures: int | None = None,
    guard_as_signer: bool = True,
) -> bytes:
    """Helper to synthesize a valid wire-format Solana transaction payload."""
    agent_pubkey = b58decode(agent_pubkey_b58)
    prog_pubkey = b58decode(program_id_b58)
    blockhash = b"B" * 32

    if guard_pubkey_b58:
        guard_pubkey = b58decode(guard_pubkey_b58)
        if guard_as_signer:
            sig_count = num_signatures if num_signatures is not None else 2
            raw = bytearray([sig_count])
            for _ in range(sig_count):
                raw.extend(b"\x00" * 64)

            # Message Header (2 required signers, 0 readonly signed, 1 readonly unsigned)
            msg = bytearray([2, 0, 1])
            # Account keys: [agent_pubkey, guard_pubkey, prog_pubkey]
            msg.append(3)
            msg.extend(agent_pubkey)
            msg.extend(guard_pubkey)
            msg.extend(prog_pubkey)

            msg.extend(blockhash)

            # 1 instruction calling prog_pubkey (account index 2)
            msg.append(1)  # 1 instruction
            msg.append(2)  # program_id index 2
            msg.append(1)  # 1 account
            msg.append(0)  # account index 0 (agent)
        else:
            # Guard included but NOT marked as required signer (only 1 signer)
            sig_count = num_signatures if num_signatures is not None else 1
            raw = bytearray([sig_count])
            for _ in range(sig_count):
                raw.extend(b"\x00" * 64)

            # Message Header: only 1 required signer!
            msg = bytearray([1, 0, 2])
            # Account keys: [agent_pubkey, prog_pubkey, guard_pubkey]
            msg.append(3)
            msg.extend(agent_pubkey)
            msg.extend(prog_pubkey)
            msg.extend(guard_pubkey)

            msg.extend(blockhash)
            msg.append(1)
            msg.append(1)  # program_id index 1
            msg.append(1)
            msg.append(0)
    else:
        sig_count = num_signatures if num_signatures is not None else 1
        raw = bytearray([sig_count])
        for _ in range(sig_count):
            raw.extend(b"\x00" * 64)

        # Message Header (1 required signer)
        msg = bytearray([1, 0, 1])
        # Account keys: [agent_pubkey, prog_pubkey]
        msg.append(2)
        msg.extend(agent_pubkey)
        msg.extend(prog_pubkey)

        msg.extend(blockhash)

        msg.append(1)
        msg.append(1)  # program_id index 1
        msg.append(1)
        msg.append(0)

    # Compact-u16 length of instruction data
    data_len = len(instruction_data)
    if data_len < 128:
        msg.append(data_len)
    else:
        msg.extend([(data_len & 0x7F) | 0x80, (data_len >> 7) & 0x7F])
    msg.extend(instruction_data)

    raw.extend(msg)
    return bytes(raw)


def sign_policy_payload(
    key: ECC.EccKey,
    agent_id: str,
    owner_pubkey: str,
    max_notional: float,
    max_slippage: int,
    nonce: int,
    policy_version: int,
    guardian: str = "",
    allowed_programs: list[str] | None = None,
    require_guard_signer: bool = True,
) -> str:
    msg = policy_message(agent_id=agent_id, owner=owner_pubkey, guardian=guardian,
                         max_order_notional_usd=max_notional, max_slippage_bps=max_slippage,
                         policy_version=policy_version, nonce=nonce, require_guard_signer=require_guard_signer,
                         allowed_programs=allowed_programs)
    signer = eddsa.new(key, "rfc8032")
    return b58encode(signer.sign(msg))


def sign_kill_payload(key: ECC.EccKey, agent_id: str, nonce: int) -> str:
    msg = f"hyperion-guard/solana/kill/v1:{agent_id}:{nonce}".encode()
    signer = eddsa.new(key, "rfc8032")
    return b58encode(signer.sign(msg))


def sign_revive_payload(key: ECC.EccKey, agent_id: str, nonce: int) -> str:
    msg = f"hyperion-guard/solana/revive/v1:{agent_id}:{nonce}".encode()
    signer = eddsa.new(key, "rfc8032")
    return b58encode(signer.sign(msg))


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

def test_decode_real_mainnet_jupiter_swap():
    """
    Tests decoding against real Jupiter V6 instruction data from mainnet transaction
    7zoC74aDKgHFJSsybBhUBUfyEYPsLMs9tEywS7jCY5Bqd7K8sfdQkRvKvrNRrf9bLdWY8YWuQMn8zLVJVKwqziX.
    Instruction data: PrpFmsY4d26dKbdKP4k8r2Gce9GTJ53gRUqSXvA7BqcdAHQ3 (route, one route-plan step),
    checked against the transaction via getTransaction on mainnet-beta.
    """
    raw_ix_data = b58decode("PrpFmsY4d26dKbdKP4k8r2Gce9GTJ53gRUqSXvA7BqcdAHQ3")
    op_type, in_amt, quoted_out, slippage_bps, details = decode_jupiter_instruction(raw_ix_data, [])

    assert op_type == "JUPITER_SWAP"
    assert in_amt == 144082
    assert quoted_out == 135842588
    assert slippage_bps == 10000
    assert details["instruction_name"] == "route"
    assert details["platform_fee_bps"] == 0
    assert details["discriminator"] == "e517cb977ae3ad2a"


def test_decode_jupiter_v6_swap():
    in_amt = 1_000_000_000  # 1,000 USDC (6 decimals)
    quoted_out = 998_000_000
    slippage_bps = 50  # 50 bps = 0.5%
    data = build_jupiter_ix_data(in_amt, quoted_out, slippage_bps)

    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data)
    decoded = decode_solana_transaction(tx_bytes)

    assert len(decoded.instructions) == 1
    inst = decoded.instructions[0]
    assert inst.program_id == JUPITER_V6_PROGRAM_ID
    assert inst.operation == "JUPITER_SWAP"
    assert inst.input_amount == in_amt
    assert inst.slippage_bps == 50


def test_decode_jupiter_exact_out_route():
    # exact_out_route, from Jupiter's on-chain IDL
    disc = bytes.fromhex("d033ef977b2bed5c")
    route_plan = b"\x01" * 15 # mock route plan steps
    out_amount = 50_000_000 # 50 SOL (desired out)
    quoted_in = 7_500_000_000 # 7,500 USDC (quoted in)
    slippage_bps = 25
    fee_bps = 0
    fixed_tail = struct.pack("<QQHB", out_amount, quoted_in, slippage_bps, fee_bps)
    ix_data = disc + route_plan + fixed_tail

    op_type, in_amt, quoted_out, slip, details = decode_jupiter_instruction(ix_data, [])
    assert op_type == "JUPITER_SWAP"
    assert in_amt == 7_518_750_000 # the most it can spend: the quote plus 25 bps
    assert details["quoted_in_raw"] == quoted_in
    assert quoted_out == out_amount # output desired
    assert slip == 25
    assert details["instruction_name"] == "exactOutRoute"


def test_decode_phoenix_limit_order():
    # PlaceLimitOrder (2), OrderPacket::Limit (1), bid (0), price 1000 ticks, 500 base lots
    data = bytes([2, 1, 0]) + struct.pack("<QQ", 1000, 500) + bytes(40)
    tx_bytes = build_mock_solana_tx(PHOENIX_PROGRAM_ID, data)
    decoded = decode_solana_transaction(tx_bytes)

    assert len(decoded.instructions) == 1
    inst = decoded.instructions[0]
    assert inst.program_id == PHOENIX_PROGRAM_ID
    assert inst.operation == "PHOENIX_ORDER"
    assert inst.input_amount is None                     # lots aren't dollars
    assert (inst.details["instruction_name"], inst.details["order_type"], inst.details["side"]) == (
        "PlaceLimitOrder", "Limit", "BID")
    assert (inst.details["price_in_ticks"], inst.details["num_base_lots"]) == (1000, 500)


# ── 3. Solana Guard Policy & Firewall Enforcement Tests ───────────────────────

def test_guard_rejects_missing_guard_signer():
    """Forces Guard co-signature to matter: Reject if Guard key is not a required signer."""
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        require_guard_signer=True,
    )
    engine.set_policy(policy)

    # Transaction without Guard's pubkey
    data = build_jupiter_ix_data(500_000_000, 498_000_000, 50)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data, guard_pubkey_b58=None)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_MISSING_GUARD_SIGNER"
    assert "does not configure Hyperion Guard" in verdict.violation_details


def test_guard_rejects_guard_not_marked_as_required_signer():
    """Reject if Guard key is in account keys but NOT at index < num_required_signatures."""
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        require_guard_signer=True,
    )
    engine.set_policy(policy)

    # Guard pubkey present in accounts, but guard_as_signer=False (num_required_signatures = 1)
    data = build_jupiter_ix_data(500_000_000, 498_000_000, 50)
    tx_bytes = build_mock_solana_tx(
        JUPITER_V6_PROGRAM_ID, data, guard_pubkey_b58=engine.pubkey_b58, guard_as_signer=False
    )

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_MISSING_GUARD_SIGNER"


def test_guard_approves_safe_jupiter_swap():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        max_order_notional_usd=2_000.0,
        max_slippage_bps=100,
        require_guard_signer=True,
    )
    engine.set_policy(policy)

    # Safe swap: 500 USDC ($500 < $2,000 cap), 50 bps slippage (< 100 bps)
    data = build_jupiter_ix_data(500_000_000, 498_000_000, 50)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data, guard_pubkey_b58=engine.pubkey_b58)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert verdict.approved
    assert verdict.status == "APPROVED"
    assert verdict.cosigner_signature_b58 is not None

    # Verify Ed25519 co-signature authenticity
    raw_sig = b58decode(verdict.cosigner_signature_b58)
    raw_pub = b58decode(verdict.cosigner_pubkey)
    pub_key = eddsa.import_public_key(raw_pub)
    verifier = eddsa.new(pub_key, "rfc8032")
    decoded_tx = decode_solana_transaction(tx_bytes)
    verifier.verify(decoded_tx.message_bytes, raw_sig)


def test_guard_rejects_oversized_order_cap():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        max_order_notional_usd=1_000.0,
        require_guard_signer=True,
    )
    engine.set_policy(policy)

    # Oversized swap: 5,000 USDC ($5,000 > $1,000 cap)
    data = build_jupiter_ix_data(5_000_000_000, 4_900_000_000, 50)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data, guard_pubkey_b58=engine.pubkey_b58)

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
        max_slippage_bps=100,  # 1% max
        require_guard_signer=True,
    )
    engine.set_policy(policy)

    # Excessive slippage: 400 bps (4.0% slippage exposes agent to sandwich attack)
    data = build_jupiter_ix_data(500_000_000, 480_000_000, 400)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data, guard_pubkey_b58=engine.pubkey_b58)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_EXCESSIVE_SLIPPAGE"
    assert "Slippage tolerance 400 bps exceeds max limit" in verdict.violation_details


def test_guard_rejects_unauthorized_target_program():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        require_guard_signer=True,
    )
    engine.set_policy(policy)

    # Malicious or unknown contract address (valid 32-byte pubkey)
    malicious_program = b58encode(b"D" * 32)
    tx_bytes = build_mock_solana_tx(malicious_program, b"drain_all", guard_pubkey_b58=engine.pubkey_b58)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_UNAUTHORIZED_PROGRAM"
    assert "is not in policy allowlist" in verdict.violation_details


def test_guard_kill_switch_blocks_execution_and_revival():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        require_guard_signer=True,
    )
    engine.set_policy(policy)

    # Trip emergency kill switch
    assert engine.kill_agent("sol-agent-1")

    data = build_jupiter_ix_data(100_000_000, 99_000_000, 50)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, data, guard_pubkey_b58=engine.pubkey_b58)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_KILL_SWITCH"

    # Revive agent
    assert engine.revive_agent("sol-agent-1")
    verdict_after = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert verdict_after.approved
    assert verdict_after.status == "APPROVED"


def test_guard_rejects_malformed_or_unparsed_instruction():
    """Firewall Fail-Closed: Unknown/malformed instruction on allowlisted program is rejected."""
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="sol-agent-1",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        require_guard_signer=True,
    )
    engine.set_policy(policy)

    # Corrupt or unrecognized instruction data targeting Jupiter (e.g. unknown discriminator 0xdeadbeefdeadbeef)
    bogus_ix_data = bytes.fromhex("deadbeefdeadbeef") + b"\x00" * 30
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, bogus_ix_data, guard_pubkey_b58=engine.pubkey_b58)

    verdict = engine.evaluate_transaction("sol-agent-1", tx_bytes)
    assert not verdict.approved
    assert verdict.status == "REJECTED_MALFORMED_INSTRUCTION"
    assert "could not be safely decoded" in verdict.violation_details
    assert verdict.cosigner_signature_b58 is None


# ── 4. Authenticated Solana Policy & Kill API Tests ───────────────────────────

def test_solana_api_lifecycle():
    engine = SolanaGuardEngine()
    app = create_app(guard=None, solana_guard=engine)
    client = TestClient(app)

    # Setup Ed25519 keypairs for Owner and Guardian
    owner_key = ECC.generate(curve="ed25519")
    owner_pubkey_bytes = owner_key.public_key().export_key(format="raw")
    owner_pubkey_b58 = b58encode(owner_pubkey_bytes)

    guardian_key = ECC.generate(curve="ed25519")
    guardian_pubkey_bytes = guardian_key.public_key().export_key(format="raw")
    guardian_pubkey_b58 = b58encode(guardian_pubkey_bytes)

    imposter_key = ECC.generate(curve="ed25519")
    imposter_pubkey_bytes = imposter_key.public_key().export_key(format="raw")
    imposter_pubkey_b58 = b58encode(imposter_pubkey_bytes)

    # 1. Health check
    res_health = client.get("/v1/solana/health")
    assert res_health.status_code == 200
    assert res_health.json()["ok"] is True
    assert res_health.json()["cosigner_pubkey"] == engine.pubkey_b58

    # 2. Reject unauthenticated policy setup
    res_unauth = client.post("/v1/solana/policy", json={
        "agent_id": "test-agent-solana",
        "owner_solana_pubkey": owner_pubkey_b58,
        "max_order_notional_usd": 1500.0,
        "max_slippage_bps": 50,
    })
    assert res_unauth.status_code == 401

    # 3. Configure initial policy (version 1) signed by owner
    sig_v1 = sign_policy_payload(
        owner_key, "test-agent-solana", owner_pubkey_b58, 1500.0, 50, nonce=1, policy_version=1,
        guardian=guardian_pubkey_b58, allowed_programs=[JUPITER_V6_PROGRAM_ID],
    )
    res_set = client.post("/v1/solana/policy", json={
        "agent_id": "test-agent-solana",
        "owner_solana_pubkey": owner_pubkey_b58,
        "guardian_solana_pubkey": guardian_pubkey_b58,
        "max_order_notional_usd": 1500.0,
        "max_slippage_bps": 50,
        "policy_version": 1,
        "nonce": 1,
        "signature_b58": sig_v1,
        "allowed_programs": [JUPITER_V6_PROGRAM_ID],
        "require_guard_signer": True,
    })
    assert res_set.status_code == 200
    assert res_set.json()["ok"] is True

    # 4. Reject policy replay / non-monotonic version bump (policy_version <= 1)
    sig_replay = sign_policy_payload(
        owner_key, "test-agent-solana", owner_pubkey_b58, 2000.0, 50, nonce=2, policy_version=1
    )
    res_replay = client.post("/v1/solana/policy", json={
        "agent_id": "test-agent-solana",
        "owner_solana_pubkey": owner_pubkey_b58,
        "max_order_notional_usd": 2000.0,
        "max_slippage_bps": 50,
        "policy_version": 1,
        "nonce": 2,
        "signature_b58": sig_replay,
    })
    assert res_replay.status_code == 409

    # 5. Reject unauthorized caller trying to modify registered agent policy
    sig_imposter = sign_policy_payload(
        imposter_key, "test-agent-solana", imposter_pubkey_b58, 50000.0, 500, nonce=3, policy_version=2
    )
    res_imposter = client.post("/v1/solana/policy", json={
        "agent_id": "test-agent-solana",
        "owner_solana_pubkey": imposter_pubkey_b58,
        "max_order_notional_usd": 50000.0,
        "max_slippage_bps": 500,
        "policy_version": 2,
        "nonce": 3,
        "signature_b58": sig_imposter,
    })
    assert res_imposter.status_code == 403

    # 6. Read policy back
    res_get = client.get("/v1/solana/policy/test-agent-solana")
    assert res_get.status_code == 200
    assert res_get.json()["max_order_notional_usd"] == 1500.0
    assert res_get.json()["killed"] is False

    # 7. Check safe transaction (Base64 encoding) with Guard co-signer
    safe_data = build_jupiter_ix_data(500_000_000, 498_000_000, 30)
    tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, safe_data, guard_pubkey_b58=engine.pubkey_b58)
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

    # 8. Check violating transaction (Excessive slippage: 80 bps > 50 bps)
    bad_data = build_jupiter_ix_data(500_000_000, 498_000_000, 80)
    bad_tx_bytes = build_mock_solana_tx(JUPITER_V6_PROGRAM_ID, bad_data, guard_pubkey_b58=engine.pubkey_b58)
    bad_tx_b58 = b58encode(bad_tx_bytes)

    res_bad = client.post("/v1/solana/check", json={
        "agent_id": "test-agent-solana",
        "tx_bytes": bad_tx_b58,
        "encoding": "base58",
    })
    assert res_bad.status_code == 200
    assert res_bad.json()["approved"] is False
    assert res_bad.json()["status"] == "REJECTED_EXCESSIVE_SLIPPAGE"

    # 9. Guardian triggers emergency kill switch
    kill_sig = sign_kill_payload(guardian_key, "test-agent-solana", nonce=10)
    res_kill = client.post("/v1/solana/kill", json={
        "agent_id": "test-agent-solana",
        "caller_pubkey": guardian_pubkey_b58,
        "nonce": 10,
        "signature_b58": kill_sig,
        "reason": "Risk officer halted trading",
    })
    assert res_kill.status_code == 200
    assert res_kill.json()["killed"] is True

    # 10. Check that previously safe tx is now rejected by kill switch
    res_blocked = client.post("/v1/solana/check", json={
        "agent_id": "test-agent-solana",
        "tx_bytes": tx_b64,
    })
    assert res_blocked.status_code == 200
    assert res_blocked.json()["approved"] is False
    assert res_blocked.json()["status"] == "REJECTED_KILL_SWITCH"

    # 11. Guardian attempts to revive agent -> FORBIDDEN (403)! Only owner can revive.
    guardian_revive_sig = sign_revive_payload(guardian_key, "test-agent-solana", nonce=11)
    res_guardian_revive = client.post("/v1/solana/revive", json={
        "agent_id": "test-agent-solana",
        "caller_pubkey": guardian_pubkey_b58,
        "nonce": 11,
        "signature_b58": guardian_revive_sig,
    })
    assert res_guardian_revive.status_code == 403
    assert "Guardian cannot revive" in res_guardian_revive.json()["detail"]

    # 12. Owner revives agent -> SUCCESS (200)
    owner_revive_sig = sign_revive_payload(owner_key, "test-agent-solana", nonce=12)
    res_owner_revive = client.post("/v1/solana/revive", json={
        "agent_id": "test-agent-solana",
        "caller_pubkey": owner_pubkey_b58,
        "nonce": 12,
        "signature_b58": owner_revive_sig,
    })
    assert res_owner_revive.status_code == 200
    assert res_owner_revive.json()["killed"] is False

    # 13. Safe trade passes again after owner revival
    res_restored = client.post("/v1/solana/check", json={
        "agent_id": "test-agent-solana",
        "tx_bytes": tx_b64,
    })
    assert res_restored.status_code == 200
    assert res_restored.json()["approved"] is True

    # 14. A validly signed update can't be altered in transit: every field is signed.
    sig_v2 = sign_policy_payload(
        owner_key, "test-agent-solana", owner_pubkey_b58, 1500.0, 50, nonce=13, policy_version=2,
        guardian=guardian_pubkey_b58, allowed_programs=[JUPITER_V6_PROGRAM_ID],
    )
    signed_v2 = {
        "agent_id": "test-agent-solana", "owner_solana_pubkey": owner_pubkey_b58,
        "guardian_solana_pubkey": guardian_pubkey_b58, "max_order_notional_usd": 1500.0,
        "max_slippage_bps": 50, "policy_version": 2, "nonce": 13, "signature_b58": sig_v2,
        "allowed_programs": [JUPITER_V6_PROGRAM_ID], "require_guard_signer": True,
    }
    drainer = "Drain1111111111111111111111111111111111111111"
    for tampered in ({**signed_v2, "allowed_programs": [JUPITER_V6_PROGRAM_ID, drainer]},
                     {**signed_v2, "require_guard_signer": False},
                     {**signed_v2, "guardian_solana_pubkey": imposter_pubkey_b58}):
        assert client.post("/v1/solana/policy", json=tampered).status_code == 401
    assert client.post("/v1/solana/policy", json=signed_v2).status_code == 200
    assert client.post("/v1/solana/policy", json=signed_v2).status_code == 409    # and it can't be replayed

    # 15. An old revive can't undo a newer kill.
    kill2 = sign_kill_payload(guardian_key, "test-agent-solana", nonce=14)
    assert client.post("/v1/solana/kill", json={
        "agent_id": "test-agent-solana", "caller_pubkey": guardian_pubkey_b58,
        "nonce": 14, "signature_b58": kill2}).status_code == 200
    replayed = client.post("/v1/solana/revive", json={
        "agent_id": "test-agent-solana", "caller_pubkey": owner_pubkey_b58,
        "nonce": 12, "signature_b58": owner_revive_sig})
    assert replayed.status_code == 409
    assert client.get("/v1/solana/policy/test-agent-solana").json()["killed"] is True
