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


# =============================================================================
# Trade-By-Trade Modified Dietz (GIPS / CFA Institute Standard)
# =============================================================================

DIETZ_METHOD = "modified-dietz/v1"


@dataclass(frozen=True)
class CashFlow:
    t_ms: int
    amount: Decimal  # Positive for deposit, negative for withdrawal


@dataclass(frozen=True)
class TradeFill:
    t_ms: int
    coin: str
    px: Decimal
    sz: Decimal
    side: str  # "B" or "A"
    closed_pnl: Decimal
    fee: Decimal


def compute_modified_dietz(
    v_start: Decimal,
    v_end: Decimal,
    t_start_ms: int,
    t_end_ms: int,
    cash_flows: list[CashFlow] | None = None,
    fills: list[TradeFill] | None = None,
    num_trials: int = 100,
) -> dict:
    """
    Computes time-weighted return using the Modified Dietz method:
        R_dietz = (V_end - V_start - F) / (V_start + sum(W_i * F_i))
    where W_i = (T_end - t_i) / (T_end - T_start).

    Also computes granular trade-by-trade metrics (win rate, profit factor,
    volume, realized fees, and per-trade DSR/PSR moments) if fills are supplied.
    """
    if t_end_ms <= t_start_ms:
        raise ValueError("t_end_ms must be strictly greater than t_start_ms")

    flows = cash_flows or []
    trade_fills = fills or []
    duration_ms = Decimal(t_end_ms - t_start_ms)

    # 1. Calculate Net External Cash Flows & Weighted Cash Flows
    net_flows = sum((cf.amount for cf in flows), Decimal(0))
    weighted_flows = Decimal(0)
    for cf in flows:
        # Weight based on remaining time in period
        clamped_t = max(t_start_ms, min(t_end_ms, cf.t_ms))
        w = Decimal(t_end_ms - clamped_t) / duration_ms
        weighted_flows += w * cf.amount

    # 2. Investment Gain and Average Capital
    gain = v_end - v_start - net_flows
    avg_capital = v_start + weighted_flows

    if avg_capital <= Decimal(0):
        # Fallback if initial capital and flows sum to zero or negative
        dietz_return = Decimal(0)
    else:
        dietz_return = gain / avg_capital

    # 3. Annualization
    duration_days = duration_ms / Decimal(86_400_000)
    ann_factor = Decimal(1)
    dietz_ann = dietz_return
    if duration_days > Decimal(0):
        ann_mult = Decimal("365.25") / duration_days
        # Linear annualization for stability under extreme values
        dietz_ann = dietz_return * ann_mult

    # 4. Trade-by-Trade Performance & Statistical Moments
    n_trades = len(trade_fills)
    total_volume = sum((f.px * f.sz for f in trade_fills), Decimal(0))
    total_fees = sum((f.fee for f in trade_fills), Decimal(0))
    realized_pnl = sum((f.closed_pnl for f in trade_fills), Decimal(0))
    net_trade_pnl = realized_pnl - total_fees

    wins = sum(1 for f in trade_fills if (f.closed_pnl - f.fee) > Decimal(0))
    losses = sum(1 for f in trade_fills if (f.closed_pnl - f.fee) < Decimal(0))
    win_rate = Decimal(wins) / Decimal(n_trades) if n_trades > 0 else Decimal(0)

    gross_gains = sum((f.closed_pnl - f.fee for f in trade_fills if (f.closed_pnl - f.fee) > Decimal(0)), Decimal(0))
    gross_losses = sum((abs(f.closed_pnl - f.fee) for f in trade_fills if (f.closed_pnl - f.fee) < Decimal(0)), Decimal(0))
    profit_factor = (gross_gains / gross_losses) if gross_losses > Decimal(0) else (Decimal("100.0") if gross_gains > Decimal(0) else Decimal("1.0"))

    # Per-trade returns normalized by average capital
    trade_returns: list[Decimal] = []
    base_cap = max(Decimal(1), avg_capital if avg_capital > Decimal(0) else v_start)
    for f in trade_fills:
        trade_returns.append((f.closed_pnl - f.fee) / base_cap)

    trade_sharpe = Decimal(0)
    trade_psr = Decimal("0.5")
    trade_dsr = Decimal("0.5")
    trade_skew = Decimal(0)
    trade_kurt = Decimal(3)

    if len(trade_returns) >= 2:
        n_r = len(trade_returns)
        mean_tr = sum(trade_returns) / Decimal(n_r)
        var_tr = sum((r - mean_tr) ** 2 for r in trade_returns) / Decimal(n_r - 1)
        std_tr = var_tr.sqrt()

        if std_tr > Decimal(0):
            period_sr = mean_tr / std_tr
            # Annualized based on trade frequency
            trades_per_day = Decimal(n_r) / duration_days if duration_days > Decimal(0) else Decimal(1)
            trade_ann_factor = (trades_per_day * Decimal("365.25")).sqrt()
            trade_sharpe = period_sr * trade_ann_factor

            trade_skew = (sum((r - mean_tr) ** 3 for r in trade_returns) / Decimal(n_r)) / (std_tr ** 3)
            trade_kurt = (sum((r - mean_tr) ** 4 for r in trade_returns) / Decimal(n_r)) / (std_tr ** 4)

            se_denom = Decimal(n_r - 1)
            se_num = Decimal(1) - (trade_skew * period_sr) + ((trade_kurt - Decimal(1)) / Decimal(4)) * (period_sr ** 2)
            se_sr = (se_num / se_denom).sqrt() if se_num > Decimal(0) else Decimal("0.001")

            if se_sr > Decimal(0):
                z_psr = float(period_sr / se_sr)
                trade_psr = Decimal(str(min(0.9999999999, max(0.0000000001, _norm_cdf(z_psr)))))

                m = max(2, num_trials)
                ln_m = math.log(m)
                exp_max_sr = Decimal(str(
                    math.sqrt(2.0 * ln_m) - (float(EULER_MASCHERONI) / math.sqrt(2.0 * ln_m))
                )) * (Decimal(1) / trade_ann_factor) if trade_ann_factor > Decimal(0) else Decimal(0)

                z_dsr = float((period_sr - exp_max_sr) / se_sr)
                trade_dsr = Decimal(str(min(0.9999999999, max(0.0000000001, _norm_cdf(z_dsr)))))

    return {
        "method": DIETZ_METHOD,
        "periodStart": t_start_ms,
        "periodEnd": t_end_ms,
        "durationDays": _q(duration_days),
        "startValue": _q(v_start),
        "endValue": _q(v_end),
        "netExternalFlows": _q(net_flows),
        "weightedCashFlows": _q(weighted_flows),
        "averageCapital": _q(avg_capital),
        "investmentGain": _q(gain),
        "modifiedDietzReturn": _q(dietz_return),
        "annualizedReturn": _q(dietz_ann),
        "tradesCount": n_trades,
        "totalVolumeUsd": _q(total_volume),
        "totalFeesUsd": _q(total_fees),
        "realizedPnlUsd": _q(realized_pnl),
        "netTradePnlUsd": _q(net_trade_pnl),
        "winRate": _q(win_rate),
        "profitFactor": _q(profit_factor),
        "tradeSharpeRatio": _q(trade_sharpe),
        "tradeProbabilisticSharpeRatio": _q(trade_psr),
        "tradeDeflatedSharpeRatio": _q(trade_dsr),
        "tradeSkewness": _q(trade_skew),
        "tradeKurtosis": _q(trade_kurt),
    }

