"""
HYPERION PROOF: TRACK-RECORD METRICS
====================================
Method `twr-pnl/v1`. Given an account's value history and its cumulative PnL
history over the same timestamps (as Hyperliquid's `portfolio` endpoint
returns them), compute:

  * time-weighted return: each interval's PnL over the account value at its
    start, compounded. Deposits and withdrawals move the account value but
    not the PnL, so they don't count as performance;
  * max drawdown of that return index;
  * PnL, net deposits (the part of the value change that wasn't PnL), and
    the number and span of intervals.

Everything is Decimal arithmetic on the input strings, rounded only when
reported, so the same inputs give the same numbers on any machine. That is
what lets anyone check an attestation by recomputing it.

Known approximation: a deposit inside an interval isn't in that interval's
starting value, so the interval's return is slightly overstated. Intervals
whose starting value is zero or negative are skipped and counted.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, getcontext
from itertools import pairwise

getcontext().prec = 50
METHOD = "twr-pnl/v1"
PLACES = Decimal("1e-10")


@dataclass(frozen=True)
class Point:
    t_ms: int
    value: Decimal
    pnl: Decimal


def points(value_history: list, pnl_history: list) -> list[Point]:
    """Pair the two histories by timestamp. Hyperliquid returns them on the
    same grid; a timestamp missing from either is dropped."""
    pnl = {int(t): Decimal(str(v)) for t, v in pnl_history}
    out = [Point(int(t), Decimal(str(v)), pnl[int(t)]) for t, v in value_history if int(t) in pnl]
    return sorted(out, key=lambda p: p.t_ms)


def _q(x: Decimal) -> str:
    return str(x.quantize(PLACES, rounding=ROUND_HALF_EVEN))


def compute(pts: list[Point]) -> dict:
    if len(pts) < 2:
        raise ValueError("need at least two points")
    index, peak, max_dd = Decimal(1), Decimal(1), Decimal(0)
    used = skipped = 0
    for a, b in pairwise(pts):
        if a.value <= 0:
            skipped += 1
            continue
        index *= 1 + (b.pnl - a.pnl) / a.value
        used += 1
        peak = max(peak, index)
        max_dd = max(max_dd, (peak - index) / peak)
    first, last = pts[0], pts[-1]
    pnl = last.pnl - first.pnl
    return {
        "method": METHOD,
        "periodStart": first.t_ms,
        "periodEnd": last.t_ms,
        "intervals": used,
        "intervalsSkipped": skipped,
        "timeWeightedReturn": _q(index - 1),
        "maxDrawdown": _q(max_dd),
        "pnl": _q(pnl),
        "netDeposits": _q((last.value - first.value) - pnl),
        "startValue": _q(first.value),
        "endValue": _q(last.value),
    }
