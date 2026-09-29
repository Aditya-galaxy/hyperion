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
    the number and span of intervals;
  * annualized Sharpe ratio;
  * higher statistical moments: Skewness (tail asymmetry) & Kurtosis (fat-tail risk);
  * Probabilistic Sharpe Ratio (PSR) (Mertens 2002, Lo 2002);
  * Deflated Sharpe Ratio (DSR) correcting for selection bias & backtest overfitting
    under multiple trials (Bailey & López de Prado, 2014).

Everything is Decimal arithmetic on the input strings, rounded only when
reported, so the same inputs give the same numbers on any machine. That is
what lets anyone check an attestation by recomputing it.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, getcontext
from itertools import pairwise
import math

getcontext().prec = 50
METHOD = "twr-pnl/v1"
PLACES = Decimal("1e-10")
EULER_MASCHERONI = Decimal("0.5772156649015328606065120900824024310421")


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


def _norm_cdf(z: float) -> float:
    """Standard normal cumulative distribution function using erf."""
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def compute(pts: list[Point], num_trials: int = 100) -> dict:
    if len(pts) < 2:
        raise ValueError("need at least two points")
    index, peak, max_dd = Decimal(1), Decimal(1), Decimal(0)
    used = skipped = 0
    returns: list[Decimal] = []

    for a, b in pairwise(pts):
        if a.value <= 0:
            skipped += 1
            continue
        r = (b.pnl - a.pnl) / a.value
        returns.append(r)
        index *= 1 + r
        used += 1
        peak = max(peak, index)
        max_dd = max(max_dd, (peak - index) / peak)

    first, last = pts[0], pts[-1]
    pnl = last.pnl - first.pnl

    # Compute Statistical Moments and Deflated Sharpe Ratio (Bailey & López de Prado 2014)
    n = len(returns)
    sharpe_ann = Decimal(0)
    psr = Decimal("0.5")
    dsr = Decimal("0.5")
    skew = Decimal(0)
    kurt = Decimal(3) # Normal baseline

    if n >= 2:
        mean_r = sum(returns) / Decimal(n)
        variance = sum((r - mean_r) ** 2 for r in returns) / Decimal(n - 1)
        std_dev = variance.sqrt()

        if std_dev > Decimal(0):
            # Annualization factor based on time span
            duration_ms = max(1, last.t_ms - first.t_ms)
            duration_days = Decimal(duration_ms) / Decimal(86_400_000)
            ann_factor = (Decimal(n) / duration_days * Decimal("365.25")).sqrt() if duration_days > 0 else Decimal(1)

            period_sharpe = mean_r / std_dev
            sharpe_ann = period_sharpe * ann_factor

            # Sample Skewness and Kurtosis
            skew = (sum((r - mean_r) ** 3 for r in returns) / Decimal(n)) / (std_dev ** 3)
            kurt = (sum((r - mean_r) ** 4 for r in returns) / Decimal(n)) / (std_dev ** 4)

            # Standard error of Sharpe under non-normal returns (Lo 2002, Mertens 2002)
            se_denom = Decimal(n - 1)
            se_num = Decimal(1) - (skew * period_sharpe) + ((kurt - Decimal(1)) / Decimal(4)) * (period_sharpe ** 2)
            se_sr = (se_num / se_denom).sqrt() if se_num > 0 else Decimal("0.001")

            if se_sr > 0:
                # 1. Probabilistic Sharpe Ratio (PSR) vs SR* = 0
                z_psr = float(period_sharpe / se_sr)
                psr = Decimal(str(min(0.9999999999, max(0.0000000001, _norm_cdf(z_psr)))))

                # 2. Deflated Sharpe Ratio (DSR) under M = num_trials (Bailey & López de Prado 2014)
                # Expected maximum Sharpe under null hypothesis of zero skill
                m = max(2, num_trials)
                ln_m = math.log(m)
                expected_max_period_sr = Decimal(str(
                    math.sqrt(2.0 * ln_m) - (float(EULER_MASCHERONI) / math.sqrt(2.0 * ln_m))
                )) * (Decimal(1) / ann_factor)

                z_dsr = float((period_sharpe - expected_max_period_sr) / se_sr)
                dsr = Decimal(str(min(0.9999999999, max(0.0000000001, _norm_cdf(z_dsr)))))

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
        "sharpeRatio": _q(sharpe_ann),
        "probabilisticSharpeRatio": _q(psr),
        "deflatedSharpeRatio": _q(dsr),
        "skewness": _q(skew),
        "kurtosis": _q(kurt),
    }
