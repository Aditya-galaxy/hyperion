"""
Instructions that spend a token account without naming its mint (Jupiter's
`route`, Raydium's swaps, a plain token Transfer): the Guard reads the account
to learn the token, then prices it like any other.
"""

from __future__ import annotations

import os
import struct

import pytest
from Crypto.PublicKey import ECC
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58decode, b58encode
from hyperion_guard.solana.decoder import (
    RAYDIUM_V4_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
    USDC_MINT,
    WSOL_MINT,
    associated_token_address,
    decode_solana_transaction,
)
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.lookup import RpcTokenAccounts, parse_token_account
from hyperion_guard.solana.prices import FixedTokenPrices
from hyperion_guard.solana.tx import compile_message, pubkey, serialize, sign
from test_solana_mainnet import FIXTURES, REAL, recorded_tables

VAULT_PID = b58encode(bytes([7] * 32))
BONK = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
PRICES = FixedTokenPrices({BONK: (0.00001, 5), WSOL_MINT: (120.0, 9)})
REAL_ROUTE = "3gXMDJBu"                      # a mainnet `route` swap; its token account is in the fixtures
REAL_ACCOUNT, REAL_MINT = next(iter(FIXTURES["token_accounts"].items()))


def recorded_token_accounts(address: str) -> str | None:
    return FIXTURES["token_accounts"].get(address)


def judge_real(token_accounts, prices, **policy):
    guard = SolanaGuardEngine(lookup_tables=recorded_tables, prices=prices, token_accounts=token_accounts)
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey="owner", require_guard_signer=False,
                                       **{"max_order_notional_usd": 1e12, "daily_notional_cap_usd": 1e13,
                                          "max_slippage_bps": 10_000, **policy}))
    return guard.evaluate_transaction("a", REAL[REAL_ROUTE])


def test_a_real_route_swap_names_the_account_it_spends_not_the_token():
    (ix,) = [i for i in decode_solana_transaction(REAL[REAL_ROUTE], recorded_tables).instructions
             if i.operation == "JUPITER_SWAP"]
    assert "source_mint" not in ix.details
    assert ix.details["source_token_account"] == REAL_ACCOUNT


def test_a_real_route_swap_is_sized_once_its_token_account_is_read():
    # 1,182,020.282387 tokens (6 decimals) at $0.0001 = $118.20, plus a token account's rent in SOL
    prices = FixedTokenPrices({REAL_MINT: (0.0001, 6), WSOL_MINT: (120.0, 9)})
    assert judge_real(recorded_token_accounts, prices, max_order_notional_usd=118.46).approved
    over = judge_real(recorded_token_accounts, prices, max_order_notional_usd=118.19)
    assert (over.approved, over.status) == (False, "REJECTED_ORDER_CAP")


def test_reading_the_account_is_not_enough_without_a_price():
    verdict = judge_real(recorded_token_accounts, FixedTokenPrices({WSOL_MINT: (120.0, 9)}))
    assert verdict.status == "REJECTED_UNPRICED_TOKEN" and f"spends token {REAL_MINT}" in verdict.violation_details


def test_without_a_way_to_read_the_account_the_token_stays_unknown():
    prices = FixedTokenPrices({REAL_MINT: (0.0001, 6), WSOL_MINT: (120.0, 9)})
    for token_accounts in (None, lambda address: None):
        verdict = judge_real(token_accounts, prices)
        assert verdict.status == "REJECTED_UNPRICED_TOKEN" and "couldn't be identified" in verdict.violation_details

    def down(address: str):
        raise TimeoutError("rpc down")
    assert judge_real(down, prices).status == "REJECTED_UNPRICED_TOKEN"


# ── built transactions ────────────────────────────────────────────────────────

@pytest.fixture
def world():
    v.register_vault_program(VAULT_PID)
    agent_key = ECC.generate(curve="ed25519")
    agent, owner = pubkey(agent_key), b58encode(os.urandom(32))
    vault, _ = v.vault_address(VAULT_PID, owner, agent)
    holds: dict[str, str] = {}                                  # what the chain says each token account holds
    guard = SolanaGuardEngine(prices=PRICES, token_accounts=holds.get)
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey=owner, max_order_notional_usd=100.0,
                                       vault_address=vault))
    guard.get_policy("a").allowed_programs.append(VAULT_PID)

    def judge(*ixs_for, through_vault: bool = False):
        payer = vault if through_vault else agent
        ixs = []
        for make in ixs_for:
            program, metas, data = make(payer)
            if through_vault:
                ixs.append(v.execute(VAULT_PID, vault, agent, guard.pubkey_b58, v.Ix(program, metas, data)))
            else:
                # the Guard co-signs, so it's among the accounts: after a Transfer's own three,
                # before a Raydium swap's, whose last three are fixed
                cosigners = [v.AccountMeta(agent, True, True), v.AccountMeta(guard.pubkey_b58, True, False)]
                order = [*cosigners, *metas] if program == RAYDIUM_V4_PROGRAM_ID else [*metas, *cosigners]
                ixs.append(v.Ix(program, order, data))
        msg, keys, n = compile_message(ixs, agent, b58encode(os.urandom(32)))
        return guard.evaluate_transaction("a", serialize(msg, keys, n, {agent: sign(msg, agent_key)}))
    judge.holds = holds
    return judge


def transfer_from(token_account: str, amount: int):
    """A plain Transfer [source, destination, authority]: no mint anywhere in it."""
    return lambda payer: (SPL_TOKEN_PROGRAM_ID,
                          [v.AccountMeta(token_account, False, True), v.AccountMeta(b58encode(os.urandom(32)), False, True),
                           v.AccountMeta(payer, True, False)], bytes([3]) + struct.pack("<Q", amount))


def raydium_swap_from(token_account: str, amount: int):
    """Ends [user source token account, user destination, user owner], as every Raydium swap does."""
    return lambda payer: (RAYDIUM_V4_PROGRAM_ID,
                          [*(v.AccountMeta(b58encode(os.urandom(32)), False, True) for _ in range(5)),
                           v.AccountMeta(token_account, False, True), v.AccountMeta(b58encode(os.urandom(32)), False, True),
                           v.AccountMeta(payer, True, False)], bytes([9]) + struct.pack("<QQ", amount, 1))


BOTH = pytest.mark.parametrize("through_vault", [False, True])
BOTH_KINDS = pytest.mark.parametrize("spend", [transfer_from, raydium_swap_from])


@BOTH
@BOTH_KINDS
def test_a_token_account_that_isnt_the_wallets_own_is_read_and_priced(world, through_vault, spend):
    account = b58encode(os.urandom(32))                         # not an associated token account of anything
    world.holds[account] = BONK
    assert world(spend(account, 500_000_000_000), through_vault=through_vault).approved          # 5M BONK = $50
    over = world(spend(account, 1_500_000_000_000), through_vault=through_vault)                 # 15M BONK = $150
    assert (over.approved, over.status) == (False, "REJECTED_ORDER_CAP")

    world.holds[account] = USDC_MINT                            # the same amount of a different token
    assert world(spend(account, 50_000_000), through_vault=through_vault).approved               # $50
    assert world(spend(account, 500_000_000_000), through_vault=through_vault).status == "REJECTED_ORDER_CAP"


@BOTH
@BOTH_KINDS
def test_an_account_the_chain_doesnt_know_is_refused(world, through_vault, spend):
    verdict = world(spend(b58encode(os.urandom(32)), 5), through_vault=through_vault)
    assert (verdict.approved, verdict.status) == (False, "REJECTED_UNPRICED_TOKEN")


@BOTH
@pytest.mark.parametrize("init_tag", [1, 16, 18])
def test_an_account_opened_in_the_same_transaction_isnt_trusted_to_be_what_it_was(world, through_vault, init_tag):
    """It holds USDC now, but this transaction opens it again, possibly for another
    mint, before spending from it. What the chain says today doesn't settle that."""
    account = b58encode(os.urandom(32))
    world.holds[account] = USDC_MINT
    def reopen(payer):
        return SPL_TOKEN_PROGRAM_ID, [v.AccountMeta(account, False, True)], bytes([init_tag]) + bytes(32)
    assert world(transfer_from(account, 5), through_vault=through_vault).approved
    verdict = world(reopen, transfer_from(account, 5), through_vault=through_vault)
    assert (verdict.approved, verdict.status) == (False, "REJECTED_UNPRICED_TOKEN")
    assert world(transfer_from(account, 5), reopen, through_vault=through_vault).status == "REJECTED_UNPRICED_TOKEN"


def token_account_data(mint: str, owner: str, state: int = 1) -> bytes:
    return b58decode(mint) + b58decode(owner) + bytes(44) + bytes([state]) + bytes(56)


def test_parse_token_account():
    owner = b58encode(os.urandom(32))
    assert parse_token_account(token_account_data(BONK, owner)) == (BONK, owner)
    assert parse_token_account(token_account_data(BONK, owner, state=2)) == (BONK, owner)       # frozen
    assert parse_token_account(token_account_data(BONK, owner, state=0)) is None                # not initialized
    assert parse_token_account(token_account_data(BONK, owner)[:100]) is None
    assert parse_token_account(token_account_data(BONK, owner) + bytes(40)) == (BONK, owner)    # Token-2022, with extensions


def test_only_an_associated_token_account_is_remembered(monkeypatch):
    owner = b58encode(os.urandom(32))
    ata, loose = associated_token_address(owner, BONK), b58encode(os.urandom(32))
    rpc, calls = RpcTokenAccounts("http://unused"), []
    monkeypatch.setattr(rpc, "fetch", lambda address: calls.append(address) or (BONK, owner))
    assert (rpc(ata), rpc(ata), calls) == (BONK, BONK, [ata])                # its address fixes its mint: read once
    assert (rpc(loose), rpc(loose)) == (BONK, BONK) and calls.count(loose) == 2      # could be reopened: read every time
    monkeypatch.setattr(rpc, "fetch", lambda address: None)
    assert (rpc(loose), rpc(ata)) == (None, BONK)
