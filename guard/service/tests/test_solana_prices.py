"""
Token prices: SOL and other tokens sized at a price source's figure, and
everything the source can't vouch for refused. Real mainnet swaps that sell a
token other than USDC or SOL are judged here with fixed prices.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from hyperion_guard.api import create_app
from hyperion_guard.solana.decoder import WSOL_MINT, decode_solana_transaction
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.prices import (
    FixedTokenPrices,
    JupiterTokenPrices,
    TokenPrice,
)
from test_solana_mainnet import REAL, recorded_tables

TOKEN_9ANV_PREFIX, TOKEN_HAPPY_PREFIX, TOKEN_ASRX_PREFIX = "9ANVLB4L", "HAPPYwgF", "AsrX7Lug"


def judge(raw: bytes, prices=None, sol_price_usd=None, **policy):
    guard = SolanaGuardEngine(lookup_tables=recorded_tables, prices=prices)
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey="owner", require_guard_signer=False,
                                       **{"max_order_notional_usd": 1e12, "daily_notional_cap_usd": 1e13,
                                          "max_slippage_bps": 10_000, **policy}))
    return guard.evaluate_transaction("a", raw, sol_price_usd=sol_price_usd)


def full_mint(prefix: str) -> str:
    """A token's full address, from the transaction or lookup table that names it."""
    for raw in REAL.values():
        for ix in decode_solana_transaction(raw, recorded_tables).instructions:
            if ix.details.get("source_mint", "").startswith(prefix):
                return ix.details["source_mint"]
    raise KeyError(prefix)


def test_token_price_values_a_raw_amount():
    assert TokenPrice(usd=0.5, decimals=6).value(3_000_000) == 1.5
    assert TokenPrice(usd=120.0, decimals=9).value(250_000_000) == 30.0


def test_a_real_sale_of_another_token_is_sized_at_its_price():
    # 88,593.387179 tokens (6 decimals) at $0.002 = $177.19, plus a priority fee and a token account's rent in SOL
    prices = FixedTokenPrices({full_mint(TOKEN_9ANV_PREFIX): (0.002, 6), WSOL_MINT: (120.0, 9)})
    assert judge(REAL["2wisuJyL"], prices, max_order_notional_usd=177.45).approved
    over = judge(REAL["2wisuJyL"], prices, max_order_notional_usd=177.18)
    assert (over.approved, over.status) == (False, "REJECTED_ORDER_CAP")

    doubled = FixedTokenPrices({full_mint(TOKEN_9ANV_PREFIX): (0.004, 6), WSOL_MINT: (120.0, 9)})
    assert judge(REAL["2wisuJyL"], doubled, max_order_notional_usd=177.45).status == "REJECTED_ORDER_CAP"


def test_without_a_price_for_the_token_the_sale_is_refused():
    no_source = judge(REAL["2wisuJyL"], prices=None, sol_price_usd=120.0)
    assert no_source.status == "REJECTED_UNPRICED_TOKEN" and "no price source" in no_source.violation_details
    not_listed = judge(REAL["2wisuJyL"], FixedTokenPrices({WSOL_MINT: (120.0, 9)}))
    assert not_listed.status == "REJECTED_UNPRICED_TOKEN" and "too little liquidity" in not_listed.violation_details


def test_a_real_transaction_spending_sol_and_another_token_adds_both():
    # a 3.482636 SOL swap and a further SOL transfer at $120, and 11,257,065.53 tokens
    # (6 decimals) at $0.00001 = $112.57, plus rent: $978.42 in all
    prices = FixedTokenPrices({full_mint(TOKEN_ASRX_PREFIX): (0.00001, 6), WSOL_MINT: (120.0, 9)})
    assert judge(REAL["2bf8G4ur"], prices, max_order_notional_usd=978.43).approved
    assert judge(REAL["2bf8G4ur"], prices, max_order_notional_usd=978.41).status == "REJECTED_ORDER_CAP"


def test_a_priced_token_doesnt_excuse_the_rest_of_the_transaction():
    """Once its token has a price, this real swap gets as far as the instruction
    that closes a token account to another wallet."""
    prices = FixedTokenPrices({full_mint(TOKEN_HAPPY_PREFIX): (0.000001, 6), WSOL_MINT: (120.0, 9)})
    verdict = judge(REAL["5RCa41rE"], prices)
    assert (verdict.status, "CloseAccount" in verdict.violation_details) == ("REJECTED_UNSUPPORTED_INSTRUCTION", True)


def test_sol_is_priced_by_the_source_and_there_is_no_built_in_figure():
    swap_of_sol = REAL["4VfVbP9n"]                                          # 0.05 SOL and a token account's rent
    at_120 = FixedTokenPrices({WSOL_MINT: (120.0, 9)})
    assert judge(swap_of_sol, at_120, max_order_notional_usd=6.26).approved           # 0.05204 SOL x $120 = $6.25
    assert judge(swap_of_sol, at_120, max_order_notional_usd=6.24).status == "REJECTED_ORDER_CAP"
    assert judge(swap_of_sol, at_120, sol_price_usd=300.0, max_order_notional_usd=6.26).status == "REJECTED_ORDER_CAP"

    nothing = judge(swap_of_sol)                                            # no source, no figure from the caller
    assert (nothing.approved, nothing.status) == (False, "REJECTED_UNPRICED_TOKEN")
    assert "no SOL price is available" in nothing.violation_details
    assert judge(REAL["XpERyrRh"], FixedTokenPrices({})).status == "REJECTED_UNPRICED_TOKEN"    # a USDC swap, but its fee is SOL


def entry(usd=2.0, decimals=6, liquidity=5_000_000.0):
    return {"usdPrice": usd, "decimals": decimals, "liquidity": liquidity, "blockId": 1}


def test_jupiter_prices_cache_for_a_while_then_ask_again(monkeypatch):
    now, calls = [0.0], []
    feed = JupiterTokenPrices(ttl=10.0, clock=lambda: now[0])
    monkeypatch.setattr(feed, "fetch", lambda mint: calls.append(mint) or entry(usd=2.0 + len(calls)))
    assert feed.price("M") == TokenPrice(3.0, 6)
    now[0] = 9.9
    assert feed.price("M") == TokenPrice(3.0, 6) and len(calls) == 1
    now[0] = 10.0
    assert feed.price("M") == TokenPrice(4.0, 6) and len(calls) == 2


def test_jupiter_prices_have_no_price_for_a_thin_market(monkeypatch):
    feed = JupiterTokenPrices(min_liquidity_usd=100_000.0)
    monkeypatch.setattr(feed, "fetch", lambda mint: entry(liquidity=99_999.0))
    assert feed.price("M") is None
    monkeypatch.setattr(feed, "fetch", lambda mint: {"usdPrice": 2.0, "decimals": 6})          # liquidity not stated
    assert feed.price("N") is None
    monkeypatch.setattr(feed, "fetch", lambda mint: entry(liquidity=100_000.0))
    assert feed.price("O") == TokenPrice(2.0, 6)


@pytest.mark.parametrize("bad", [None, {}, entry(usd=0), entry(usd=-1), entry(usd=float("nan")), entry(usd=float("inf")),
                                 entry(decimals=40), entry(decimals="6"), {"usdPrice": "abc", "decimals": 6}])
def test_jupiter_prices_refuse_an_answer_they_cant_use(monkeypatch, bad):
    feed = JupiterTokenPrices()
    monkeypatch.setattr(feed, "fetch", lambda mint: bad)
    assert feed.price("M") is None


def test_a_failed_request_is_no_price_not_the_last_one(monkeypatch):
    now = [0.0]
    feed = JupiterTokenPrices(ttl=10.0, clock=lambda: now[0])
    monkeypatch.setattr(feed, "fetch", lambda mint: entry())
    assert feed.price("M") == TokenPrice(2.0, 6)

    def down(mint):
        raise TimeoutError("price api down")
    monkeypatch.setattr(feed, "fetch", down)
    now[0] = 11.0
    assert feed.price("M") is None                                          # expired and unreachable: nothing stale


def test_the_api_takes_its_price_source_from_the_environment(monkeypatch):
    monkeypatch.delenv("HYPERION_SOLANA_PRICES", raising=False)
    assert create_app().state.solana_guard.prices is None
    monkeypatch.setenv("HYPERION_SOLANA_PRICES", "jupiter")
    assert create_app().state.solana_guard.prices.url == JupiterTokenPrices.URL
    monkeypatch.setenv("HYPERION_SOLANA_PRICES", "https://prices.example/v3")
    assert create_app().state.solana_guard.prices.url == "https://prices.example/v3"
    assert TestClient(create_app()).get("/v1/health").status_code == 200
