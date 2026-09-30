use crate::core::types::Price;

/// Configuration for Funding Rate Cash-and-Carry Basis Arbitrage
#[derive(Debug, Clone, Copy)]
pub struct BasisArbConfig {
    /// Minimum annualized funding rate hurdle to open delta-neutral basis trade (e.g. 0.12 = 12% APR)
    pub min_apr_hurdle: f64,
    /// Minimum basis premium (perp price - spot price) / spot price (e.g. 0.0005 = 5 bps)
    pub min_basis_bps: f64,
    /// Funding payment period in hours (standard crypto perp is 8.0 hours)
    pub funding_period_hours: f64,
    /// Annualized borrowing/financing cost of capital (e.g. 0.04 = 4% APR)
    pub financing_cost_apr: f64,
}

impl Default for BasisArbConfig {
    fn default() -> Self {
        Self {
            min_apr_hurdle: 0.10, // 10% APR threshold
            min_basis_bps: 0.0005, // 5 bps premium
            funding_period_hours: 8.0,
            financing_cost_apr: 0.03, // 3% cost of funding
        }
    }
}

/// Trading signal for Basis Arbitrage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasisSignal {
    NoOpportunity,
    /// Long Spot, Short Perpetual Future (Captures positive funding rate)
    OpenLongBasis,
    /// Short Spot, Long Perpetual Future (Captures deeply negative funding rate)
    OpenReverseBasis,
    /// Unwind basis trade (yield dropped below financing cost or inverted)
    UnwindBasis,
}

/// Real-time basis and yield summary
#[derive(Debug, Clone, Copy)]
pub struct YieldSummary {
    pub spot_price: f64,
    pub perp_price: f64,
    pub basis_absolute: f64,
    pub basis_percent: f64,
    pub funding_rate_per_period: f64,
    pub annualized_funding_apr: f64,
    pub net_carry_yield_apr: f64,
}

/// Zero-risk delta-neutral cash-and-carry basis arbitrage engine.
#[derive(Debug)]
pub struct BasisArbEngine {
    config: BasisArbConfig,
}

impl BasisArbEngine {
    pub fn new(config: BasisArbConfig) -> Self {
        Self { config }
    }

    /// Evaluate current market spot, perp, and 8-hour funding rate
    pub fn evaluate(
        &self,
        spot_price: Price,
        perp_price: Price,
        funding_rate: f64,
    ) -> (BasisSignal, YieldSummary) {
        let spot = spot_price.to_f64();
        let perp = perp_price.to_f64();

        let basis_abs = perp - spot;
        let basis_pct = if spot > 0.0 { basis_abs / spot } else { 0.0 };

        // Crypto perps pay funding every 8 hours -> 3 payments per day -> 1095 payments/year
        let payments_per_year = (24.0 / self.config.funding_period_hours) * 365.0;
        let annualized_funding = funding_rate * payments_per_year;

        // In long basis (Long Spot + Short Perp), trader receives annualized_funding and pays financing_cost_apr.
        // In reverse basis (Short Spot + Long Perp), trader receives (-annualized_funding) and pays short borrow cost.
        let (signal, net_carry_apr) = if annualized_funding >= 0.0 {
            let long_net_carry = annualized_funding - self.config.financing_cost_apr;
            let sig = if long_net_carry >= self.config.min_apr_hurdle
                && basis_pct >= self.config.min_basis_bps
            {
                BasisSignal::OpenLongBasis
            } else if long_net_carry.abs() < 0.01 {
                BasisSignal::UnwindBasis
            } else {
                BasisSignal::NoOpportunity
            };
            (sig, long_net_carry)
        } else {
            let reverse_net_carry = -annualized_funding - self.config.financing_cost_apr;
            let sig = if reverse_net_carry >= self.config.min_apr_hurdle
                && basis_pct <= -self.config.min_basis_bps
            {
                BasisSignal::OpenReverseBasis
            } else if reverse_net_carry.abs() < 0.01 {
                BasisSignal::UnwindBasis
            } else {
                BasisSignal::NoOpportunity
            };
            (sig, reverse_net_carry)
        };

        let summary = YieldSummary {
            spot_price: spot,
            perp_price: perp,
            basis_absolute: basis_abs,
            basis_percent: basis_pct,
            funding_rate_per_period: funding_rate,
            annualized_funding_apr: annualized_funding,
            net_carry_yield_apr: net_carry_apr,
        };

        (signal, summary)
    }

    pub fn config(&self) -> &BasisArbConfig {
        &self.config
    }
}
