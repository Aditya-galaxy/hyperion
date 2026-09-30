use hyperion_quant::core::types::Price;
use hyperion_quant::quant::basis_arb::{BasisArbConfig, BasisArbEngine, BasisSignal};

#[test]
fn test_basis_arbitrage_yield_and_signals() {
    let config = BasisArbConfig {
        min_apr_hurdle: 0.12, // 12% APR
        min_basis_bps: 0.0005,
        funding_period_hours: 8.0,
        financing_cost_apr: 0.03, // 3%
    };

    let engine = BasisArbEngine::new(config);

    // Scenario 1: High positive funding (e.g. 0.05% per 8hr -> 0.0005 * 1095 = 54.75% APR)
    // Spot = $60,000, Perp = $60,060 (10 bps premium)
    let spot = Price::from_f64(60_000.0);
    let perp = Price::from_f64(60_060.0);
    let funding_rate = 0.0005;

    let (sig, summary) = engine.evaluate(spot, perp, funding_rate);
    assert_eq!(sig, BasisSignal::OpenLongBasis);
    assert!(summary.annualized_funding_apr > 0.50);
    assert!(summary.net_carry_yield_apr > 0.45);
    assert!(summary.basis_percent > 0.0009);

    // Scenario 2: Flat funding rate (e.g. 0.00001 -> negligible yield below hurdle)
    let (sig_flat, summary_flat) = engine.evaluate(spot, Price::from_f64(60_005.0), 0.00001);
    assert_eq!(sig_flat, BasisSignal::NoOpportunity);
    assert!(summary_flat.net_carry_yield_apr < 0.10);

    // Scenario 3: Negative funding (Perp trading at deep discount, shorts pay longs)
    let perp_discount = Price::from_f64(59_900.0);
    let negative_funding = -0.0008; // -87.6% APR
    let (sig_rev, summary_rev) = engine.evaluate(spot, perp_discount, negative_funding);
    assert_eq!(sig_rev, BasisSignal::OpenReverseBasis);
    assert!(summary_rev.net_carry_yield_apr > 0.50, "Reverse basis must yield positive net carry from negative funding");
}
