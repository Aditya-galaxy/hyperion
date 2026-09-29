"""
Tests for Hyperion Proof: metrics on series worked out by hand, the signed
request, the evidence file and its hash, and the ERC-8004 encoding. The one
real-data fixture is a Hyperliquid `portfolio` response recorded once; no
test touches the network.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest
from eth_abi import decode
from eth_account import Account
from hyperion_proof import erc8004, evidence, metrics
from hyperion_proof.cli import data_uri, load_evidence
from hyperion_proof.request import Request, check, sign

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "portfolio_hlp.json").read_text())
KEY = "0x" + "22" * 32
ACCOUNT = Account.from_key(KEY).address
NOW = 1_790_500_000
REGISTRY = f"eip155:5042002:{erc8004.REGISTRIES[5042002]['identity']}"


def series(values, pnls, t0=1_000):
    return ([[t0 + i, str(v)] for i, v in enumerate(values)], [[t0 + i, str(p)] for i, p in enumerate(pnls)])


# ── metrics ──────────────────────────────────────────────────────────────────

def test_deposits_are_not_performance():
    # 100 → 110 on +10 PnL (+10%), then a 100 deposit and +10 PnL on 110 (+9.09%)
    m = metrics.compute(metrics.points(*series([100, 110, 220], [0, 10, 20])))
    assert Decimal(m["timeWeightedReturn"]) == pytest.approx(Decimal("0.2"))
    assert Decimal(m["netDeposits"]) == 100
    assert Decimal(m["pnl"]) == 20


def test_drawdown_of_the_return_index():
    # +10%, then −10% of 110: index 1.1 → 0.99, a 10% drawdown from the peak
    m = metrics.compute(metrics.points(*series([100, 110, 99], [0, 10, -1])))
    assert Decimal(m["maxDrawdown"]) == pytest.approx(Decimal("0.1"))
    assert Decimal(m["timeWeightedReturn"]) == pytest.approx(Decimal("-0.01"))


def test_empty_account_intervals_are_skipped_and_counted():
    m = metrics.compute(metrics.points(*series([0, 100, 110], [0, 0, 10])))
    assert (m["intervals"], m["intervalsSkipped"]) == (1, 1)
    assert Decimal(m["timeWeightedReturn"]) == pytest.approx(Decimal("0.1"))


def test_unmatched_timestamps_are_dropped_and_two_points_needed():
    pts = metrics.points([[1, "100"], [2, "110"], [3, "120"]], [[1, "0"], [3, "20"]])
    assert [p.t_ms for p in pts] == [1, 3]
    with pytest.raises(ValueError):
        metrics.compute(pts[:1])


def test_real_hyperliquid_history_is_internally_consistent():
    w = dict(FIXTURE)["month"]
    m = metrics.compute(metrics.points(w["accountValueHistory"], w["pnlHistory"]))
    change = Decimal(m["endValue"]) - Decimal(m["startValue"])
    assert Decimal(m["pnl"]) + Decimal(m["netDeposits"]) == pytest.approx(change)
    assert (Decimal(m["timeWeightedReturn"]) > 0) == (Decimal(m["pnl"]) > 0)
    assert m["intervals"] == len(w["accountValueHistory"]) - 1


def test_deflated_sharpe_ratio_and_moments():
    w = dict(FIXTURE)["month"]
    pts = metrics.points(w["accountValueHistory"], w["pnlHistory"])
    m_10 = metrics.compute(pts, num_trials=10)
    m_1000 = metrics.compute(pts, num_trials=1000)

    # 1. Moments must be populated and finite
    assert "sharpeRatio" in m_10
    assert "probabilisticSharpeRatio" in m_10
    assert "deflatedSharpeRatio" in m_10
    assert "skewness" in m_10
    assert "kurtosis" in m_10

    # 2. Deflated Sharpe under 1000 trials must be strictly lower or equal to 10 trials (Bailey & López de Prado)
    dsr_10 = Decimal(m_10["deflatedSharpeRatio"])
    dsr_1000 = Decimal(m_1000["deflatedSharpeRatio"])
    assert dsr_1000 <= dsr_10, "More trials must deflate the Sharpe ratio confidence"
    assert 0 <= dsr_10 <= 1
    assert 0 <= dsr_1000 <= 1



# ── the signed request ───────────────────────────────────────────────────────

def request(**kw) -> Request:
    base = {"agentRegistry": REGISTRY, "agentId": 7, "venue": "hyperliquid", "account": ACCOUNT,
            "window": "month", "issuedAt": NOW}
    return Request(**{**base, **kw})


def test_request_signed_by_the_account_passes():
    r = request()
    assert check(r, sign(r, KEY), NOW) is None


@pytest.mark.parametrize("kw, sig_key, why", [
    ({}, "0x" + "33" * 32, "isn't from the account"),         # someone else signed
    ({"window": "forever"}, KEY, "window"),
    ({"venue": "binance"}, KEY, "venue"),
    ({"agentRegistry": "nope"}, KEY, "agentRegistry"),
    ({"issuedAt": NOW - 8 * 86400}, KEY, "stale"),
])
def test_bad_requests_are_refused(kw, sig_key, why):
    r = request(**kw)
    assert why in check(r, sign(r, sig_key), NOW)


def test_signature_covers_the_agent_id():
    sig = sign(request(), KEY)
    assert "isn't from the account" in check(request(agentId=8), sig, NOW)


# ── evidence ─────────────────────────────────────────────────────────────────

def doc():
    r = request()
    return evidence.build(r, sign(r, KEY), dict(FIXTURE)["month"], "fixture", "2026-09-27T00:00:00+00:00",
                          "0x" + "ab" * 20)


def test_evidence_recomputes_and_hash_is_order_independent():
    d = doc()
    assert evidence.recompute(d) == d["metrics"]
    shuffled = json.loads(json.dumps(d, sort_keys=False))
    assert evidence.digest(dict(reversed(list(shuffled.items())))) == evidence.digest(d)


def test_tampering_is_caught():
    d = doc()
    h = evidence.digest(d)
    faked = json.loads(json.dumps(d))
    faked["metrics"]["timeWeightedReturn"] = "0.5"
    assert evidence.recompute(faked) != faked["metrics"]          # the numbers don't follow from the inputs
    assert evidence.digest(faked) != h                            # and the on-chain hash no longer matches
    edited = json.loads(json.dumps(d))
    edited["inputs"]["pnlHistory"][-1][1] = "999999999"
    assert evidence.digest(edited) != h


def test_data_uri_round_trip():
    d = doc()
    assert load_evidence(data_uri(d)) == json.loads(evidence.canonical(d))


# ── ERC-8004 encoding ────────────────────────────────────────────────────────

def test_percent_values():
    assert erc8004.percent_value("0.0123456") == 12346          # 1.2346%
    assert erc8004.percent_value("-0.1") == -100000              # −10.0000%


def test_feedback_entries_and_calldata():
    d = doc()
    entries = erc8004.feedback_entries(d)
    assert [e[:2] for e in entries] == [("tradingYield", "hyperliquid:month"), ("maxDrawdown", "hyperliquid:month")]
    h = evidence.digest(d)
    data = erc8004.give_feedback_calldata(7, entries[0][2], *entries[0][:2], "data:x", h)
    assert data[:4] == erc8004.GIVE_FEEDBACK
    agent, value, dec, t1, t2, endpoint, uri, fh = decode(
        ["uint256", "int128", "uint8", "string", "string", "string", "string", "bytes32"], data[4:])
    assert (agent, value, dec, t1, t2, endpoint, uri) == (7, entries[0][2], 4, "tradingYield",
                                                          "hyperliquid:month", "", "data:x")
    assert "0x" + fh.hex() == h
