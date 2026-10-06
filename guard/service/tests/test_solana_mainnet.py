"""
Real Jupiter transactions from Solana mainnet (tests/fixtures/mainnet_jupiter.json),
judged whole: the compute budget, the token-account setup, the wrap and unwrap
of SOL around the swap, and the swap itself. Then each piece on its own.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
from pathlib import Path

import pytest
from Crypto.PublicKey import ECC
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58encode
from hyperion_guard.solana.decoder import (
    ASSOCIATED_TOKEN_PROGRAM_ID,
    COMPUTE_BUDGET_PROGRAM_ID,
    JUPITER_ROUTES,
    JUPITER_V6_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
    UNRESOLVED_ACCOUNT,
    WSOL_MINT,
    decode_jupiter_instruction,
    decode_solana_transaction,
)
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.tx import compile_message, pubkey, serialize, sign

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "mainnet_jupiter.json").read_text())
REAL = {t["signature"][:8]: base64.b64decode(t["transaction_base64"]) for t in FIXTURES["transactions"]}
VAULT_PID = b58encode(bytes([7] * 32))
SOL = 1_000_000_000


def judge_real(raw: bytes, **policy):
    """The fixtures weren't built for a Guard, so it isn't one of their signers."""
    guard = SolanaGuardEngine()
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey="owner", require_guard_signer=False,
                                       **{"max_order_notional_usd": 1e12, "daily_notional_cap_usd": 1e13,
                                          "max_slippage_bps": 10_000, **policy}))
    return guard.evaluate_transaction("a", raw)


def jupiter(raw: bytes):
    return [i for i in decode_solana_transaction(raw).instructions if i.program_id == JUPITER_V6_PROGRAM_ID]


def test_discriminators_are_the_anchor_hash_of_the_instruction_name():
    for disc, (name, *_) in JUPITER_ROUTES.items():
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
        assert hashlib.sha256(f"global:{snake}".encode()).digest()[:8].hex() == disc, name


@pytest.mark.parametrize(("sig", "name", "amount", "slippage"), [
    ("XpERyrRh", "sharedAccountsRouteV2", 300_000_000, 100),
    ("2wisuJyL", "routeV2", 88_593_387_179, 1_000),
    ("3fhAEwFp", "route", 154_775_577, 100),
    ("3gXMDJBu", "route", 1_182_020_282_387, 10_000),
])
def test_real_swaps_decode_and_are_judged_on_their_merits(sig, name, amount, slippage):
    (ix,) = jupiter(REAL[sig])
    assert (ix.operation, ix.details["instruction_name"], ix.input_amount, ix.slippage_bps) == (
        "JUPITER_SWAP", name, amount, slippage)

    assert judge_real(REAL[sig]).approved                                  # nothing in it is refused outright
    tight = judge_real(REAL[sig], max_slippage_bps=slippage - 1)
    assert (tight.approved, tight.status) == (False, "REJECTED_EXCESSIVE_SLIPPAGE")
    small = judge_real(REAL[sig], max_order_notional_usd=amount / 1e6 - 1)
    assert (small.approved, small.status) == (False, "REJECTED_ORDER_CAP")


def test_a_real_legacy_transaction_with_two_swaps_and_a_readable_source_mint():
    first, second = jupiter(REAL["2bf8G4ur"])
    assert (first.details["instruction_name"], first.details["source_mint"]) == ("routeV2", WSOL_MINT)
    assert (first.input_amount, second.input_amount) == (3_482_636_000, 11_257_065_530_000)
    assert judge_real(REAL["2bf8G4ur"]).approved


def test_a_real_swap_that_closes_a_token_account_to_someone_else_is_refused():
    verdict = judge_real(REAL["5RCa41rE"])
    assert (verdict.approved, verdict.status) == (False, "REJECTED_UNSUPPORTED_INSTRUCTION")
    assert "CloseAccount" in verdict.violation_details


def test_real_transactions_keep_lookup_table_accounts_in_place():
    """v0 transactions load most accounts from lookup tables. They must stay as
    placeholders, at their positions, not vanish and shift the rest."""
    decoded = decode_solana_transaction(REAL["2wisuJyL"])
    assert decoded.is_versioned
    (ix,) = jupiter(REAL["2wisuJyL"])
    assert (len(ix.accounts), ix.accounts.count(UNRESOLVED_ACCOUNT)) == (39, 26)
    assert "source_mint" not in ix.details                                 # it's in a lookup table: unknown, not guessed


# ── the pieces, on built transactions ─────────────────────────────────────────

@pytest.fixture
def judge():
    v.register_vault_program(VAULT_PID)
    agent_key = ECC.generate(curve="ed25519")
    guard = SolanaGuardEngine()
    agent, owner = pubkey(agent_key), b58encode(os.urandom(32))
    vault, _ = v.vault_address(VAULT_PID, owner, agent)
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey=owner, max_order_notional_usd=100.0,
                                       vault_address=vault))
    guard.get_policy("a").allowed_programs.append(VAULT_PID)

    def run(*calls: tuple[str, bytes, list[str]], patch=None):
        ixs = [v.Ix(program, [v.AccountMeta(agent, True, True), v.AccountMeta(guard.pubkey_b58, True, False),
                              *(v.AccountMeta(a, False, False) for a in extra)], data)
               for program, data, extra in calls]
        msg, keys, n = compile_message(ixs, agent, b58encode(os.urandom(32)))
        if patch:
            msg = patch(msg)
        return guard.evaluate_transaction("a", serialize(msg, keys, n, {agent: sign(msg, agent_key)}),
                                          sol_price_usd=150.0)
    run.agent, run.guard, run.vault = agent, guard, vault
    return run


def price(micro_lamports: int):
    return (COMPUTE_BUDGET_PROGRAM_ID, bytes([3]) + struct.pack("<Q", micro_lamports), [])


def limit(units: int):
    return (COMPUTE_BUDGET_PROGRAM_ID, bytes([2]) + struct.pack("<I", units), [])


def test_the_priority_fee_counts_as_money_spent(judge):
    assert judge(limit(200_000), price(1_000_000_000)).approved            # 0.2 SOL = $30 of a $100 cap
    burn = judge(limit(1_400_000), price(1_000_000_000))                   # 1.4 SOL = $210
    assert (burn.approved, burn.status) == (False, "REJECTED_ORDER_CAP")
    no_limit = judge(price(1_000_000_000))                                 # no limit set: assume the maximum
    assert no_limit.status == "REJECTED_ORDER_CAP"
    assert judge((COMPUTE_BUDGET_PROGRAM_ID, bytes([0]) + bytes(8), [])).status == "REJECTED_MALFORMED_INSTRUCTION"


def test_opening_token_accounts_costs_rent_and_recover_nested_is_refused(judge):
    assert judge((ASSOCIATED_TOKEN_PROGRAM_ID, b"\x01", [])).approved
    assert judge((ASSOCIATED_TOKEN_PROGRAM_ID, b"", [])).approved
    many = judge(*[(ASSOCIATED_TOKEN_PROGRAM_ID, b"\x01", [])] * 400)      # 400 x 0.00204 SOL = $122
    assert many.status == "REJECTED_ORDER_CAP"
    assert judge((ASSOCIATED_TOKEN_PROGRAM_ID, b"\x02", [])).status == "REJECTED_UNSUPPORTED_INSTRUCTION"


def test_close_account_passes_only_back_to_its_own_authority(judge):
    token_account, thief = b58encode(os.urandom(32)), b58encode(os.urandom(32))

    def close_to(dest: str):
        # CloseAccount [account, destination, authority]
        ix = v.Ix(SPL_TOKEN_PROGRAM_ID, [v.AccountMeta(token_account, False, True), v.AccountMeta(dest, False, True),
                                         v.AccountMeta(judge.agent, True, False),
                                         v.AccountMeta(judge.guard.pubkey_b58, True, False)], bytes([9]))
        msg, keys, n = compile_message([ix], judge.agent, b58encode(os.urandom(32)))
        return judge.guard.evaluate_transaction("a", serialize(msg, keys, n, {}), sol_price_usd=150.0)

    assert close_to(judge.agent).approved
    assert close_to(thief).status == "REJECTED_UNSUPPORTED_INSTRUCTION"


def route_v2(in_amount: int, slippage_bps: int = 50) -> bytes:
    return bytes.fromhex("bb64facc31c4af14") + struct.pack("<QQHHHI", in_amount, 1, slippage_bps, 0, 0, 0)


def test_a_swap_from_wrapped_sol_is_sized_in_sol(judge):
    filler = [b58encode(os.urandom(32))]                                   # accounts[2]; source_mint is accounts[3]
    ok = judge((JUPITER_V6_PROGRAM_ID, route_v2(SOL // 2), [*filler, WSOL_MINT]))            # 0.5 SOL = $75
    assert ok.approved, ok.violation_details
    over = judge((JUPITER_V6_PROGRAM_ID, route_v2(SOL), [*filler, WSOL_MINT]))               # 1 SOL = $150
    assert over.status == "REJECTED_ORDER_CAP"
    # an unknown mint falls back to the 6-decimal assumption: 0.5e9 raw reads as $500
    assert judge((JUPITER_V6_PROGRAM_ID, route_v2(SOL // 2), [*filler, filler[0]])).status == "REJECTED_ORDER_CAP"


def test_exact_out_is_sized_at_the_most_it_can_spend():
    data = bytes.fromhex("9d8ab85215f4f324") + struct.pack("<QQHHHI", 7, 1_000_000, 300, 0, 0, 0)
    op, amount, out, slippage, d = decode_jupiter_instruction(data, [])
    assert (op, amount, out, slippage, d["instruction_name"]) == ("JUPITER_SWAP", 1_030_000, 7, 300, "exactOutRouteV2")


def test_token_ledger_routes_carry_no_input_amount_and_are_refused(judge):
    data = bytes.fromhex("96564774a75d0e68") + bytes(8) + struct.pack("<QHB", 1_000, 50, 0)
    assert decode_jupiter_instruction(data, [])[:2] == ("JUPITER_LEDGER_SWAP", None)
    assert judge((JUPITER_V6_PROGRAM_ID, data, [])).status == "REJECTED_UNSUPPORTED_INSTRUCTION"


def test_a_vault_named_through_a_lookup_table_is_not_mistaken_for_the_next_account(judge):
    """Dropping the unresolved account would slide `to` into the vault's position."""
    ix = v.transfer_sol(VAULT_PID, judge.vault, judge.agent, judge.guard.pubkey_b58, judge.vault, SOL // 100)
    msg, keys, n = compile_message([ix], judge.agent, b58encode(os.urandom(32)))
    at = msg.rindex(bytes([keys.index(judge.vault)]) * 2)                  # the instruction's vault and `to` indexes
    patched = msg[:at] + bytes([200]) + msg[at + 1:]                       # the vault now comes from a lookup table
    verdict = judge.guard.evaluate_transaction("a", serialize(patched, keys, n, {}), sol_price_usd=150.0)
    assert (verdict.approved, verdict.status) == (False, "REJECTED_WRONG_VAULT")
