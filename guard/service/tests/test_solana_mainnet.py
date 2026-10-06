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
    SYSTEM_PROGRAM_ID,
    UNRESOLVED_ACCOUNT,
    USDC_MINT,
    WSOL_MINT,
    associated_token_address,
    decode_jupiter_instruction,
    decode_solana_transaction,
)
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.lookup import (
    LOOKUP_TABLE_META_SIZE,
    RpcLookupTables,
    parse_lookup_table,
)
from hyperion_guard.solana.tx import compile_message, pubkey, serialize, sign

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "mainnet_jupiter.json").read_text())
REAL = {t["signature"][:8]: base64.b64decode(t["transaction_base64"]) for t in FIXTURES["transactions"]}
VAULT_PID = b58encode(bytes([7] * 32))
SOL = 1_000_000_000


class RecordedTable:
    """A lookup table as recorded in the fixtures: only the indexes the transactions use."""

    def __init__(self, entries: dict[str, str]):
        self.entries = entries

    def __len__(self) -> int:
        return max(map(int, self.entries)) + 1

    def __getitem__(self, i: int) -> str:
        return self.entries.get(str(i), UNRESOLVED_ACCOUNT)


def recorded_tables(table: str, highest_index: int):
    entries = FIXTURES["lookup_tables"].get(table)
    return RecordedTable(entries) if entries else None


def judge_real(raw: bytes, tables=recorded_tables, **policy):
    """The fixtures weren't built for a Guard, so it isn't one of their signers."""
    guard = SolanaGuardEngine(lookup_tables=tables)
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey="owner", require_guard_signer=False,
                                       **{"max_order_notional_usd": 1e12, "daily_notional_cap_usd": 1e13,
                                          "max_slippage_bps": 10_000, **policy}))
    return guard.evaluate_transaction("a", raw, sol_price_usd=150.0)


def jupiter(raw: bytes, tables=recorded_tables):
    return [i for i in decode_solana_transaction(raw, tables).instructions if i.program_id == JUPITER_V6_PROGRAM_ID]


def test_discriminators_are_the_anchor_hash_of_the_instruction_name():
    for disc, (name, *_) in JUPITER_ROUTES.items():
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
        assert hashlib.sha256(f"global:{snake}".encode()).digest()[:8].hex() == disc, name


@pytest.mark.parametrize(("sig", "name", "amount", "slippage", "mint", "usd"), [
    ("XpERyrRh", "sharedAccountsRouteV2", 300_000_000, 100, USDC_MINT, 300.02),     # 300 USDC and a priority fee
    ("3LxXkHXS", "routeV2", 47_000_000, 100, USDC_MINT, 47.36),                     # 47 USDC, a new token account
    ("2hYARrmD", "routeV2", 120_540_278, 4_500, USDC_MINT, 122.72),                 # and two USDC fee transfers
    ("4VfVbP9n", "routeV2", 50_000_000, 2_000, WSOL_MINT, 7.81),                    # 0.05 SOL, wrapped first
    ("3fhAEwFp", "route", 154_775_577, 100, WSOL_MINT, 23.53),                      # 0.155 SOL, wrapped first
])
def test_real_swaps_are_sized_in_the_token_they_spend(sig, name, amount, slippage, mint, usd):
    (ix,) = jupiter(REAL[sig])
    assert (ix.operation, ix.details["instruction_name"], ix.input_amount, ix.slippage_bps, ix.details["source_mint"]) == (
        "JUPITER_SWAP", name, amount, slippage, mint)
    assert decode_solana_transaction(REAL[sig], recorded_tables).unresolved_accounts == 0

    assert judge_real(REAL[sig], max_order_notional_usd=usd + 0.01).approved
    under = judge_real(REAL[sig], max_order_notional_usd=usd - 0.01)
    assert (under.approved, under.status) == (False, "REJECTED_ORDER_CAP")
    tight = judge_real(REAL[sig], max_slippage_bps=slippage - 1)
    assert (tight.approved, tight.status) == (False, "REJECTED_EXCESSIVE_SLIPPAGE")


@pytest.mark.parametrize(("sig", "token"), [
    ("2wisuJyL", "9ANVLB4L"),      # read as an $88,593 dollar swap before the Guard resolved lookup tables
    ("5RCa41rE", "HAPPYwgF"),
    ("2bf8G4ur", "AsrX7Lug"),      # two swaps: the first spends SOL, the second this
])
def test_real_swaps_of_a_token_with_no_price_are_refused(sig, token):
    verdict = judge_real(REAL[sig])
    assert (verdict.approved, verdict.status, verdict.cosigner_signature_b58) == (False, "REJECTED_UNPRICED_TOKEN", None)
    assert f"spends token {token}" in verdict.violation_details


def test_a_real_swap_whose_token_cant_be_identified_is_refused():
    """`route` doesn't name its source mint, and the account it spends isn't the
    wallet's USDC, USDT or wrapped-SOL account."""
    (ix,) = jupiter(REAL["3gXMDJBu"])
    assert "source_mint" not in ix.details
    verdict = judge_real(REAL["3gXMDJBu"])
    assert (verdict.status, "couldn't be identified" in verdict.violation_details) == ("REJECTED_UNPRICED_TOKEN", True)


def test_without_lookup_tables_accounts_stay_in_place_and_unknown():
    """v0 transactions load most accounts from lookup tables. Unread, they are
    placeholders at their positions, not gaps that shift the rest."""
    decoded = decode_solana_transaction(REAL["2hYARrmD"])
    assert (decoded.is_versioned, len(decoded.lookup_tables), decoded.unresolved_accounts) == (True, 5, 46)
    (ix,) = jupiter(REAL["2hYARrmD"], tables=None)
    assert (len(ix.accounts), ix.accounts.count(UNRESOLVED_ACCOUNT)) == (82, 49)
    assert "source_mint" not in ix.details                                 # unknown, not guessed

    verdict = judge_real(REAL["2hYARrmD"], tables=None)                    # approved once the tables are read
    assert verdict.status == "REJECTED_UNPRICED_TOKEN"
    assert "46 of the transaction's accounts are in lookup tables" in verdict.violation_details


def test_the_wallets_own_token_account_identifies_the_token_without_any_lookup():
    """`route` on a v0 transaction, no tables read: the account it spends is the
    signer's wrapped-SOL account, which can be worked out from the two addresses."""
    (ix,) = jupiter(REAL["3fhAEwFp"], tables=None)
    assert ix.details["source_mint"] == WSOL_MINT
    assert judge_real(REAL["3fhAEwFp"], tables=None, max_order_notional_usd=24.0).approved


def test_a_table_that_cant_be_read_leaves_its_accounts_unknown():
    def broken(table: str, highest_index: int):
        raise TimeoutError("rpc down")
    assert decode_solana_transaction(REAL["2hYARrmD"], broken).unresolved_accounts == 46
    short = decode_solana_transaction(REAL["2hYARrmD"], lambda table, hi: [])     # a table shorter than the index used
    assert short.unresolved_accounts == 46


def test_rpc_lookup_tables_parse_cache_and_refetch_when_a_table_has_grown(monkeypatch):
    addresses = [b58encode(bytes([i]) * 32) for i in range(1, 4)]
    data = bytes(LOOKUP_TABLE_META_SIZE) + b"".join(bytes([i]) * 32 for i in range(1, 4))
    assert parse_lookup_table(data) == addresses
    with pytest.raises(ValueError):
        parse_lookup_table(data[:-1])

    calls = []
    rpc = RpcLookupTables("http://unused")
    monkeypatch.setattr(rpc, "fetch", lambda table: calls.append(table) or addresses[:2 + len(calls) - 1])
    assert rpc("T", 1) == addresses[:2]
    assert rpc("T", 0) == addresses[:2] and len(calls) == 1               # cached
    assert rpc("T", 2) == addresses and len(calls) == 2                   # index past the cache: fetched again
    monkeypatch.setattr(rpc, "fetch", lambda table: None)
    assert rpc("T", 9) == addresses                                       # not a table any more: keep what was known
    assert rpc("other", 0) is None


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
    # a token the Guard has no price for isn't guessed at
    assert judge((JUPITER_V6_PROGRAM_ID, route_v2(5), [*filler, filler[0]])).status == "REJECTED_UNPRICED_TOKEN"


def test_wrapping_sol_isnt_counted_as_spending_it(judge):
    wsol_account = associated_token_address(judge.agent, WSOL_MINT)
    wrap = struct.pack("<IQ", 2, 100 * SOL)
    def sent_to(dest: str):
        ix = v.Ix(SYSTEM_PROGRAM_ID, [v.AccountMeta(judge.agent, True, True), v.AccountMeta(dest, False, True),
                                      v.AccountMeta(judge.guard.pubkey_b58, True, False)], wrap)
        msg, keys, n = compile_message([ix], judge.agent, b58encode(os.urandom(32)))
        return judge.guard.evaluate_transaction("a", serialize(msg, keys, n, {}), sol_price_usd=150.0)
    assert sent_to(wsol_account).approved                                  # still the agent's: $15,000 moved, $0 spent
    assert sent_to(b58encode(os.urandom(32))).status == "REJECTED_ORDER_CAP"
    someone_elses = associated_token_address(b58encode(os.urandom(32)), WSOL_MINT)
    assert sent_to(someone_elses).status == "REJECTED_ORDER_CAP"


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
