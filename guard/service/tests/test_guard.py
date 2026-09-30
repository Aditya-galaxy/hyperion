"""
Tests for the Guard service: the checks, signing, the ledger's Merkle
trees, and the engine end to end against a fake chain. No network.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from eth_account import Account
from hyperion_guard import verdict as vd
from hyperion_guard.chain import RpcError
from hyperion_guard.engine import ExecutorCall, Guard, GuardUnavailable, parse_order
from hyperion_guard.ledger import Ledger, leaf, merkle_proof, merkle_root, verify
from hyperion_guard.policy import (
    AgentState,
    Order,
    Policy,
    Reason,
    RiskBook,
    outside_collar,
)
from hyperion_guard.prices import FixedPrices

SIGNER = Account.from_key("0x" + "11" * 32)
AGENT = "0x" + "a1" * 20
OWNER = "0x" + "0b" * 20
GUARD_ADDR = "0x" + "9d" * 20
NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC).timestamp()

POLICY = Policy(max_order_notional=1_000_000_000, max_daily_notional=2_500_000_000,
                collar_bps=200, max_orders_per_minute=3)


def state(killed=False, version=1, policy=POLICY):
    return AgentState(owner=OWNER, guardian="0x" + "00" * 20, killed=killed, policy_version=version, policy=policy)


def order(qty="0.01", price="65000", side="buy", symbol="BTC-USD"):
    return Order(symbol=symbol, side=side, qty=Decimal(qty), price=Decimal(price))


# ── the checks ───────────────────────────────────────────────────────────────

def test_notional_rounds_up_so_limits_cant_be_shaved():
    assert order("0.0000001", "1").notional == 1          # 0.1 micro-USDC → 1
    assert order("0.01", "65000").notional == 650_000_000


def test_checks_in_order():
    book = RiskBook()
    ref = Decimal(65000)
    assert book.check(AGENT, None, order(), ref, NOW) is Reason.UNKNOWN_AGENT
    assert book.check(AGENT, state(), order(qty="-1"), ref, NOW) is Reason.BAD_ORDER
    assert book.check(AGENT, state(killed=True), order(qty="100"), ref, NOW) is Reason.KILLED   # kill beats size
    assert book.check(AGENT, state(), order(qty="0.02"), ref, NOW) is Reason.ORDER_NOTIONAL    # $1,300
    assert book.check(AGENT, state(), order(), None, NOW) is Reason.NO_REFERENCE_PRICE
    assert book.check(AGENT, state(), order(price="66400"), ref, NOW) is Reason.PRICE_COLLAR   # +2.15%
    assert book.check(AGENT, state(), order(price="66300"), ref, NOW) is Reason.APPROVED       # +2.0%


def test_collar_bounds_only_the_harmful_side():
    ref = Decimal(100)
    assert outside_collar(order(price="102.01"), ref, 200)
    assert not outside_collar(order(price="50"), ref, 200)                 # a cheap buy just won't fill
    assert outside_collar(order(side="sell", price="97.99"), ref, 200)
    assert not outside_collar(order(side="sell", price="150"), ref, 200)


def test_daily_cap_resets_at_utc_midnight():
    book = RiskBook()
    ref = Decimal(65000)
    lax = Policy(1_000_000_000, 1_300_000_000, 200, 100)
    assert book.check(AGENT, state(policy=lax), order(), ref, NOW) is Reason.APPROVED           # $650
    assert book.check(AGENT, state(policy=lax), order(), ref, NOW + 1) is Reason.APPROVED       # $1,300
    assert book.check(AGENT, state(policy=lax), order(), ref, NOW + 2) is Reason.DAILY_NOTIONAL
    tomorrow = NOW + 12 * 3600 + 1
    assert book.check(AGENT, state(policy=lax), order(), ref, tomorrow) is Reason.APPROVED


def test_throttle_counts_only_approvals_and_slides():
    book = RiskBook()
    ref = Decimal(65000)
    small = order(qty="0.001")
    for i in range(3):
        assert book.check(AGENT, state(), small, ref, NOW + i) is Reason.APPROVED
    for i in range(5):                                        # rejections don't use up the window
        assert book.check(AGENT, state(), order(price="99999"), ref, NOW + 3) is Reason.PRICE_COLLAR
    assert book.check(AGENT, state(), small, ref, NOW + 10) is Reason.RATE_LIMIT
    assert book.check(AGENT, state(), small, ref, NOW + 60.5) is Reason.APPROVED   # first one aged out


def test_agents_have_separate_budgets():
    book = RiskBook()
    ref = Decimal(65000)
    for i in range(3):
        book.check(AGENT, state(), order(qty="0.001"), ref, NOW + i)
    assert book.check("0x" + "a2" * 20, state(), order(qty="0.001"), ref, NOW + 3) is Reason.APPROVED


# ── signing ──────────────────────────────────────────────────────────────────

def test_sign_and_recover():
    d = vd.Domain(5042002, GUARD_ADDR)
    v = vd.Verdict(AGENT, "0x" + "ab" * 32, True, 0, 1, 7, 1_790_000_060)
    sig, _digest = vd.sign(d, v, SIGNER.key.hex())
    assert vd.recover(d, v, sig) == SIGNER.address
    other = vd.Verdict(AGENT, "0x" + "ab" * 32, True, 0, 2, 7, 1_790_000_060)     # one field differs
    assert vd.recover(d, other, sig) != SIGNER.address
    assert vd.recover(vd.Domain(1, GUARD_ADDR), v, sig) != SIGNER.address       # another chain


def test_offchain_order_hash_is_canonical_and_unique():
    h = lambda q, p, cid="c1": vd.offchain_order_hash(1, AGENT, "btc-usd", "buy", Decimal(q), Decimal(p), cid)
    assert h("1.50", "65000.0") == h("1.5", "65000")
    assert h("1.5", "65000") != h("1.5", "65000", "c2")
    assert h("1.5", "65000") != h("1.51", "65000")


# ── ledger & Merkle ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 13])
def test_every_leaf_proves_against_the_root(n):
    leaves = [leaf("0x" + f"{i:064x}") for i in range(n)]
    root = merkle_root(leaves)
    for i, lf in enumerate(leaves):
        assert verify(merkle_proof(leaves, i), root, lf)
    assert not verify(merkle_proof(leaves, 0), root, leaf("0x" + "ff" * 32))


def test_unanchored_stops_at_an_unsigned_gap():
    led = Ledger(":memory:")
    fields = {"issued_at": NOW, "agent": AGENT, "order_hash": "0x", "approved": 1, "reason": 0,
              "policy_version": 1, "expires_at": 0}
    s1, _s2, s3 = (led.reserve(**fields) for _ in range(3))
    led.finish(s1, "0x" + "01" * 32, "0x")
    led.finish(s3, "0x" + "03" * 32, "0x")                   # s2 still being signed
    assert [s for s, _ in led.unanchored(0)] == [s1]


# ── the engine end to end ────────────────────────────────────────────────────

class FakeChain:
    def __init__(self):
        self.chain_id, self.guard = 5042002, GUARD_ADDR
        self.agents = {AGENT.lower(): state()}
        self.anchored, self.sent, self.down = 0, [], False

    def agent(self, address):
        if self.down:
            raise RpcError("rpc down")
        return self.agents.get(address.lower())

    def last_anchored_seq(self):
        return self.anchored

    def send_anchor(self, key, first, last, root):
        self.sent.append((first, last, root))
        self.anchored = last
        return "0xtx"


@pytest.fixture
def guard():
    clock = [NOW]
    g = Guard(FakeChain(), FixedPrices({"BTC-USD": "65000"}), Ledger(":memory:"), SIGNER.key.hex(),
              clock=lambda: clock[0])
    g._clock = clock
    return g


def test_engine_signs_approvals_and_rejections(guard):
    ok = guard.check(AGENT, order(), client_order_id="a")
    bad = guard.check(AGENT, order(qty="1"), client_order_id="b")
    assert ok["approved"] and ok["reason"] == "approved"
    assert not bad["approved"] and bad["reason"] == "order_notional"
    for r in (ok, bad):
        v = vd.Verdict(**r["verdict"])
        assert vd.recover(guard.domain, v, r["signature"]) == SIGNER.address
        assert v.expires_at == int(NOW) + 60
    assert [ok["verdict"]["seq"], bad["verdict"]["seq"]] == [1, 2]


def test_engine_hashes_executor_orders_like_the_contract(guard):
    call = ExecutorCall(executor="0x" + "e0" * 20, target="0x" + "d0" * 20, data="0xdeadbeef", nonce=4)
    r = guard.check(AGENT, order(), executor=call)
    assert r["verdict"]["order_hash"] == vd.executor_order_hash(5042002, call.executor, call.target,
                                                                call.data, 650_000_000, 4)


def test_kill_on_chain_stops_the_very_next_order(guard):
    assert guard.check(AGENT, order())["approved"]
    guard.chain.agents[AGENT.lower()] = state(killed=True)
    assert guard.check(AGENT, order())["reason"] == "killed"


def test_no_verdict_when_arc_cant_be_read(guard):
    guard.chain.down = True
    with pytest.raises(GuardUnavailable):
        guard.check(AGENT, order())
    assert guard.ledger.recent() == []                        # nothing signed, nothing logged


def test_restart_restores_todays_usage(guard):
    lax = Policy(1_000_000_000, 1_300_000_000, 200, 100)
    guard.chain.agents[AGENT.lower()] = state(policy=lax)
    guard.check(AGENT, order())
    guard.check(AGENT, order())
    fresh = Guard(guard.chain, guard.prices, guard.ledger, SIGNER.key.hex(), clock=lambda: NOW + 5)
    assert fresh.check(AGENT, order())["reason"] == "daily_notional"


def test_anchor_covers_everything_since_the_last_anchor(guard):
    for _ in range(5):
        guard.check(AGENT, order(qty="0.001"))
    out = guard.anchor()
    assert (out["first_seq"], out["last_seq"]) == (1, 5)
    assert guard.anchor() is None                             # nothing new
    p = guard.ledger.proof_for(3)
    assert verify([bytes.fromhex(x[2:]) for x in p["proof"]], bytes.fromhex(p["root"][2:]),
                  bytes.fromhex(p["leaf"][2:]))


def test_parse_order_rejects_garbage():
    with pytest.raises(ValueError):
        parse_order({"symbol": "BTC-USD", "side": "buy", "qty": "abc", "price": "1"})
    with pytest.raises(ValueError):
        parse_order({"symbol": "BTC-USD"})
    assert not parse_order({"symbol": "x", "side": "buy", "qty": "NaN", "price": "1"}).validate()


# ── the HTTP API ─────────────────────────────────────────────────────────────

@pytest.fixture
def client(guard):
    from fastapi.testclient import TestClient
    from hyperion_guard.api import create_app
    return TestClient(create_app(guard))


def test_api_check_returns_a_verifiable_verdict(client, guard):
    r = client.post("/v1/check", json={"agent": AGENT, "client_order_id": "x1",
                                       "order": {"symbol": "btc-usd", "side": "BUY", "qty": "0.01", "price": "65000"}})
    assert r.status_code == 200
    body = r.json()
    assert body["approved"] and body["notional"] == 650_000_000 and body["reference_price"] == "65000"
    assert vd.recover(guard.domain, vd.Verdict(**body["verdict"]), body["signature"]) == SIGNER.address


def test_api_rejects_bad_input_without_signing(client, guard):
    assert client.post("/v1/check", json={"agent": "nope", "order": {}}).status_code == 422
    assert client.post("/v1/check", json={"agent": AGENT, "order": {"symbol": "BTC-USD"}}).status_code == 422
    bad_exec = {"agent": AGENT, "order": {"symbol": "BTC-USD", "side": "buy", "qty": "0.01", "price": "65000"},
                "executor": {"address": AGENT, "target": AGENT, "data": "0xZZ", "nonce": 0}}
    assert client.post("/v1/check", json=bad_exec).status_code == 422
    assert guard.ledger.recent() == []


def test_api_503_when_arc_is_unreachable(client, guard):
    guard.chain.down = True
    r = client.post("/v1/check", json={"agent": AGENT,
                                       "order": {"symbol": "BTC-USD", "side": "buy", "qty": "0.01", "price": "65000"}})
    assert r.status_code == 503


def test_api_agent_and_verdict_lookup(client, guard):
    assert client.get(f"/v1/agents/{AGENT}").json()["policy"]["collar_bps"] == 200
    assert client.get("/v1/agents/0x" + "77" * 20).status_code == 404
    client.post("/v1/check", json={"agent": AGENT,
                                   "order": {"symbol": "BTC-USD", "side": "buy", "qty": "0.01", "price": "65000"}})
    assert client.get("/v1/verdicts/1").json()["anchor"] is None
    guard.anchor()
    assert client.get("/v1/verdicts/1").json()["anchor"]["first_seq"] == 1
    assert client.get("/v1/health").json()["signer"] == SIGNER.address


# ── vectors shared with the Solidity tests (guard/contracts/test) ────────────

def test_verdict_digest_matches_the_contract():
    """HyperionGuard.hashVerdict gives this digest for this verdict at the
    Foundry test deployment (chain 31337, first CREATE address)."""
    d = vd.Domain(31337, "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f")
    v = vd.Verdict("0x" + "a1" * 20, "0x" + "ab" * 32, True, 0, 1, 7, 1_790_000_060)
    _sig, digest = vd.sign(d, v, SIGNER.key.hex())            # the digest doesn't depend on the key
    assert digest == "0x1aa970729120b515155762c75c9a2c80cd6ee2063c364f6d5b2994decb50ba07"


def test_executor_order_hash_matches_the_contract_encoding():
    assert vd.executor_order_hash(31337, "0x" + "e0" * 20, "0x" + "d0" * 20, "0xdeadbeef", 650_000_000, 4) == \
        "0x97e53d86177a34484050182064ab45b43938f14d1e9cea6af687f174b317dee0"
