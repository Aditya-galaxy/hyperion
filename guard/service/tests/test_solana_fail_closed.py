"""
The Guard co-signs only what it can size or knows to be harmless. Being on the
allow-list gets a program looked at, not waved through: Approve on the token
program, a durable nonce, a Phoenix order it can't price are all refused,
directly and inside a vault Execute.
"""

from __future__ import annotations

import os
import struct

import pytest
from Crypto.PublicKey import ECC
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58encode
from hyperion_guard.solana.decoder import (
    PHOENIX_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
    decode_phoenix_instruction,
)
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.tx import compile_message, pubkey, serialize, sign

VAULT_PID = b58encode(bytes([7] * 32))
MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
SOL = 1_000_000_000
REFUSED = "REJECTED_UNSUPPORTED_INSTRUCTION"


def token(tag: int, amount: int | None = None) -> bytes:
    return bytes([tag]) + (struct.pack("<Q", amount) if amount is not None else b"")


def system(tag: int, lamports: int | None = None) -> bytes:
    return struct.pack("<I", tag) + (struct.pack("<Q", lamports) if lamports is not None else b"") + bytes(40)


@pytest.fixture
def judge():
    v.register_vault_program(VAULT_PID)
    agent_key = ECC.generate(curve="ed25519")
    guard = SolanaGuardEngine()
    agent, owner = pubkey(agent_key), b58encode(os.urandom(32))
    vault, _ = v.vault_address(VAULT_PID, owner, agent)
    guard.set_policy(SolanaAgentPolicy(
        agent_id="a", owner_solana_pubkey=owner, max_order_notional_usd=1_000.0, vault_address=vault,
        allowed_programs=[VAULT_PID, SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, PHOENIX_PROGRAM_ID, MEMO]))

    def run(*calls: tuple[str, bytes], through_vault: bool = False):
        ixs = []
        for program, data in calls:
            if through_vault:
                inner = v.Ix(program, [v.AccountMeta(vault, True, True)], data)
                ixs.append(v.execute(VAULT_PID, vault, agent, guard.pubkey_b58, inner))
            else:
                ixs.append(v.Ix(program, [v.AccountMeta(agent, True, True),
                                          v.AccountMeta(guard.pubkey_b58, True, False)], data))
        msg, keys, n = compile_message(ixs, agent, b58encode(os.urandom(32)))
        return guard.evaluate_transaction("a", serialize(msg, keys, n, {agent: sign(msg, agent_key)}),
                                          sol_price_usd=150.0)
    return run


BOTH = pytest.mark.parametrize("through_vault", [False, True])


@BOTH
@pytest.mark.parametrize(("tag", "name"), [(4, "Approve"), (13, "ApproveChecked"), (6, "SetAuthority"),
                                           (9, "CloseAccount"), (8, "Burn"), (7, "MintTo"), (99, "instruction 99")])
def test_token_instructions_that_grant_or_destroy_are_refused(judge, through_vault, tag, name):
    verdict = judge((SPL_TOKEN_PROGRAM_ID, token(tag, 2**64 - 1)), through_vault=through_vault)
    assert (verdict.approved, verdict.status, verdict.cosigner_signature_b58) == (False, REFUSED, None)
    assert name in verdict.violation_details


@BOTH
@pytest.mark.parametrize("tag", [1, 16, 18, 17, 5])      # InitializeAccount x3, SyncNative, Revoke
def test_token_instructions_that_move_nothing_pass(judge, through_vault, tag):
    assert judge((SPL_TOKEN_PROGRAM_ID, token(tag)), through_vault=through_vault).approved


@BOTH
def test_token_transfers_are_still_sized(judge, through_vault):
    assert judge((SPL_TOKEN_PROGRAM_ID, token(3, 500_000_000)), through_vault=through_vault).approved
    over = judge((SPL_TOKEN_PROGRAM_ID, token(3, 1_500_000_000)), through_vault=through_vault)
    assert over.status == "REJECTED_ORDER_CAP"


@BOTH
@pytest.mark.parametrize(("tag", "name"), [(1, "Assign"), (4, "AdvanceNonceAccount"), (5, "WithdrawNonceAccount"),
                                           (11, "TransferWithSeed"), (3, "CreateAccountWithSeed"), (8, "Allocate")])
def test_system_instructions_other_than_plain_payments_are_refused(judge, through_vault, tag, name):
    verdict = judge((SYSTEM_PROGRAM_ID, system(tag, SOL)), through_vault=through_vault)
    assert (verdict.approved, verdict.status) == (False, REFUSED)
    assert name in verdict.violation_details


@BOTH
@pytest.mark.parametrize("tag", [0, 2])                   # CreateAccount, Transfer: both spend the payer's lamports
def test_sol_leaving_the_payer_is_sized(judge, through_vault, tag):
    assert judge((SYSTEM_PROGRAM_ID, system(tag, 2 * SOL)), through_vault=through_vault).approved     # $300
    over = judge((SYSTEM_PROGRAM_ID, system(tag, 10 * SOL)), through_vault=through_vault)             # $1,500
    assert over.status == "REJECTED_ORDER_CAP"


def ioc(side: int, price: int | None, base: int, quote: int) -> bytes:
    """Swap with OrderPacket::ImmediateOrCancel."""
    opt = b"\x01" + struct.pack("<Q", price) if price is not None else b"\x00"
    return bytes([0, 2, side]) + opt + struct.pack("<QQQQ", base, quote, 0, 0) + bytes(30)


def test_phoenix_orders_are_read_as_the_program_lays_them_out():
    op, amount, _, _, d = decode_phoenix_instruction(ioc(1, 2_500, 40, 0), [])
    assert (op, amount) == ("PHOENIX_ORDER", None)
    assert (d["instruction_name"], d["order_type"], d["side"]) == ("Swap", "ImmediateOrCancel", "ASK")
    assert (d["price_in_ticks"], d["num_base_lots"], d["num_quote_lots"]) == (2_500, 40, 0)

    op, *_, d = decode_phoenix_instruction(ioc(0, None, 0, 9_000), [])      # market buy by quote size
    assert (op, d["price_in_ticks"], d["num_quote_lots"]) == ("PHOENIX_ORDER", None, 9_000)

    assert decode_phoenix_instruction(bytes([12]), [])[0] == "PHOENIX_OPERATION"       # WithdrawFunds
    assert decode_phoenix_instruction(bytes([2, 7, 0]) + bytes(32), [])[0] == "UNKNOWN_PHOENIX"   # no such packet
    assert decode_phoenix_instruction(bytes([0, 2, 1, 1]), [])[0] == "UNKNOWN_PHOENIX"            # cut short
    assert decode_phoenix_instruction(bytes([55]), [])[0] == "UNKNOWN_PHOENIX"


@BOTH
@pytest.mark.parametrize("data", [ioc(0, 2_500, 40, 0), bytes([2, 1, 0]) + struct.pack("<QQ", 1000, 500) + bytes(40),
                                  bytes([12]), bytes([6])])
def test_phoenix_is_refused_until_it_can_be_sized(judge, through_vault, data):
    """Lots and ticks need the market's parameters to become dollars, and the Guard doesn't have them."""
    verdict = judge((PHOENIX_PROGRAM_ID, data), through_vault=through_vault)
    assert (verdict.approved, verdict.status) == (False, REFUSED)


@BOTH
def test_one_refused_instruction_refuses_the_whole_transaction(judge, through_vault):
    verdict = judge((SPL_TOKEN_PROGRAM_ID, token(3, 1_000_000)), (SPL_TOKEN_PROGRAM_ID, token(4, 2**64 - 1)),
                    through_vault=through_vault)
    assert (verdict.approved, verdict.status) == (False, REFUSED)


@BOTH
def test_a_program_the_owner_listed_without_a_decoder_still_passes(judge, through_vault):
    """The owner's call: the Guard can't see inside it, and says so in the README."""
    assert judge((MEMO, b"gm"), through_vault=through_vault).approved
