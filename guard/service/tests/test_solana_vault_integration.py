"""
The Guard and the Guarded Vault program together: transactions built with the
Python vault client, decoded and judged by the Guard, the way an agent would
send them. The program's own on-chain checks are tested in
guard/contracts_solana (LiteSVM); this is the off-chain half.
"""

from __future__ import annotations

import os

import pytest
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58decode, b58encode
from hyperion_guard.solana.decoder import (
    JUPITER_V6_PROGRAM_ID,
    decode_solana_transaction,
)
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.tx import (
    add_signature,
    compile_message,
    pubkey,
    serialize,
    sign,
)

VAULT_PID = b58encode(bytes([7] * 32))
MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
SOL = 1_000_000_000
REAL_JUPITER_ROUTE = "PrpFmsY4d26dKbdKP4k8r2Gce9GTJ53gRUqSXvA7BqcdAHQ3"   # mainnet; slippage 10,000 bps


def test_pda_matches_the_rust_program():
    """The same vector guard/contracts_solana/tests/vault.rs pins."""
    pda, bump = v.vault_address(VAULT_PID, b58encode(bytes([1] * 32)), b58encode(bytes([3] * 32)))
    assert (pda, bump) == ("7nBk9JTMcododJyarAbXMD5p5MHNr6xPJd1sWdTCeKcq", 250)


@pytest.fixture
def world():
    v.register_vault_program(VAULT_PID)
    keys = {name: ECC.generate(curve="ed25519") for name in ("owner", "agent", "guardian")}
    guard = SolanaGuardEngine()
    agent, owner = pubkey(keys["agent"]), pubkey(keys["owner"])
    vault, _ = v.vault_address(VAULT_PID, owner, agent)
    guard.set_policy(SolanaAgentPolicy(
        agent_id="agent-1", owner_solana_pubkey=owner, max_order_notional_usd=500.0,
        max_slippage_bps=100, allowed_programs=[VAULT_PID, JUPITER_V6_PROGRAM_ID],
        vault_address=vault))
    return {"keys": keys, "guard": guard, "agent": agent, "owner": owner, "vault": vault,
            "blockhash": b58encode(os.urandom(32))}


def agent_tx(w, ix: v.Ix) -> bytes:
    """Signed by the agent, with an empty slot for the Guard."""
    msg, keys, n = compile_message([ix], w["agent"], w["blockhash"])
    return serialize(msg, keys, n, {w["agent"]: sign(msg, w["keys"]["agent"])})


def transfer(w, lamports: int, vault: str | None = None) -> bytes:
    return agent_tx(w, v.transfer_sol(VAULT_PID, vault or w["vault"], w["agent"], w["guard"].pubkey_b58,
                                      b58encode(os.urandom(32)), lamports))


def test_the_builder_round_trips_through_the_decoder(world):
    raw = transfer(world, SOL)
    d = decode_solana_transaction(raw)
    assert d.num_required_signatures == 2                         # agent (fee payer) + Guard
    assert d.account_keys[:2] == [world["agent"], world["guard"].pubkey_b58]
    (ix,) = d.instructions
    assert (ix.operation, ix.input_amount, ix.details["vault"]) == ("VAULT_TRANSFER_SOL", SOL, world["vault"])
    assert ix.program_label == "Hyperion Guarded Vault"


def test_a_capped_transfer_is_co_signed_and_the_signature_completes_the_tx(world):
    raw = transfer(world, 2 * SOL)                                # $300 at $150/SOL, under the $500 cap
    verdict = world["guard"].evaluate_transaction("agent-1", raw, sol_price_usd=150.0)
    assert verdict.approved, verdict.violation_details
    sig = b58decode(verdict.cosigner_signature_b58)
    full = add_signature(raw, world["guard"].pubkey_b58, sig)
    d = decode_solana_transaction(full)
    key = eddsa.import_public_key(b58decode(world["guard"].pubkey_b58))
    eddsa.new(key, "rfc8032").verify(d.message_bytes, sig)       # the Guard signed exactly this message
    assert d.signatures[1] == verdict.cosigner_signature_b58


def test_over_the_dollar_cap_is_refused(world):
    v_ = world["guard"].evaluate_transaction("agent-1", transfer(world, 4 * SOL), sol_price_usd=150.0)
    assert (v_.approved, v_.status) == (False, "REJECTED_ORDER_CAP")    # $600 > $500


def test_execute_is_judged_by_its_inner_call(world):
    jup = v.Ix(JUPITER_V6_PROGRAM_ID, [v.AccountMeta(world["vault"], True, True)], b58decode(REAL_JUPITER_ROUTE))
    raw = agent_tx(world, v.execute(VAULT_PID, world["vault"], world["agent"], world["guard"].pubkey_b58, jup))
    (ix,) = decode_solana_transaction(raw).instructions
    assert ix.operation == "VAULT_EXECUTE" and ix.details["inner_operation"] == "JUPITER_SWAP"
    assert ix.slippage_bps == 10_000
    verdict = world["guard"].evaluate_transaction("agent-1", raw)
    assert (verdict.approved, verdict.status) == (False, "REJECTED_EXCESSIVE_SLIPPAGE")


def test_execute_into_a_program_off_the_list_is_refused(world):
    memo = v.Ix(MEMO, [v.AccountMeta(world["vault"], True, False)], b"hi")
    raw = agent_tx(world, v.execute(VAULT_PID, world["vault"], world["agent"], world["guard"].pubkey_b58, memo))
    verdict = world["guard"].evaluate_transaction("agent-1", raw)
    assert (verdict.approved, verdict.status) == (False, "REJECTED_UNAUTHORIZED_PROGRAM")


def test_owner_and_guardian_instructions_are_never_co_signed(world):
    # Worst case: the transaction lists the Guard as a signer, hoping it co-signs.
    base = v.simple(VAULT_PID, 3, world["agent"], world["vault"])
    kill = v.Ix(base.program_id, [*base.accounts, v.AccountMeta(world["guard"].pubkey_b58, True, False)], base.data)
    verdict = world["guard"].evaluate_transaction("agent-1", agent_tx(world, kill))
    assert (verdict.approved, verdict.status) == (False, "REJECTED_VAULT_ADMIN_OPERATION")


def test_another_vault_is_refused(world):
    other, _ = v.vault_address(VAULT_PID, world["owner"], b58encode(os.urandom(32)))
    verdict = world["guard"].evaluate_transaction("agent-1", transfer(world, SOL, vault=other))
    assert (verdict.approved, verdict.status) == (False, "REJECTED_WRONG_VAULT")


def test_the_vault_program_must_itself_be_allowed(world):
    p = world["guard"].get_policy("agent-1")
    p.allowed_programs = [JUPITER_V6_PROGRAM_ID]
    verdict = world["guard"].evaluate_transaction("agent-1", transfer(world, SOL))
    assert (verdict.approved, verdict.status) == (False, "REJECTED_UNAUTHORIZED_PROGRAM")


def test_add_signature_refuses_a_non_signer(world):
    with pytest.raises(ValueError):
        add_signature(transfer(world, SOL), world["vault"], bytes(64))
