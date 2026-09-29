use hyperion_quant::core::types::{Price, Qty};
use hyperion_quant::strategy::avellaneda_stoikov::{AsModelParams, AvellanedaStoikov};

#[test]
fn test_avellaneda_stoikov_inventory_skewing() {
    let params = AsModelParams {
        gamma: 0.5,
        sigma: 0.2, // 20% vol so inventory penalty is well above 1 tick
        kappa: 1.5,
        time_horizon: 1.0,
        tick_size: Price::from_f64(0.01),
    };
    let strategy = AvellanedaStoikov::new(params, Qty::from_f64(1.0));
    let mid = Price::from_f64(100.0);

    // 1. Neutral inventory (q = 0)
    let q_neutral = strategy.compute_quotes(mid, 0.0, 0.0);
    assert_eq!(q_neutral.reservation_price, mid);

    // 2. Heavy Long inventory (q = +10.0) -> Must lower reservation price to encourage selling
    let q_long = strategy.compute_quotes(mid, 10.0, 0.0);
    assert!(q_long.reservation_price < mid, "Long inventory must lower reservation price");
    assert!(q_long.bid_price < q_neutral.bid_price, "Bid must be lower to discourage buying");
    assert!(q_long.ask_price < q_neutral.ask_price, "Ask must be lower to attract sellers/fills");

    // 3. Heavy Short inventory (q = -10.0) -> Must raise reservation price to encourage buying
    let q_short = strategy.compute_quotes(mid, -10.0, 0.0);
    assert!(q_short.reservation_price > mid, "Short inventory must raise reservation price");
    assert!(q_short.bid_price > q_neutral.bid_price, "Bid must be higher to attract fills");
    assert!(q_short.ask_price > q_neutral.ask_price, "Ask must be higher to discourage selling");
}

#[test]
fn test_ofi_kyle_lambda_and_square_root_impact() {
    use hyperion_quant::strategy::ofi_alpha::OfiAlpha;

    let mut ofi = OfiAlpha::with_kyle_adaptive(
        0.005, // initial lambda
        10.0,  // ref_volume = 10 units
        0.50,  // max skew = $0.50
        0.50,  // decay = 0.50
        0.05,  // adaptive learning rate
    );

    // 1. Initial zero state
    assert_eq!(ofi.current_skew(), 0.0);

    // 2. Positive OFI flow (buyers aggressive) -> positive skew (raises reservation price)
    let skew_10 = ofi.update_with_price(10.0, 100.0);
    assert!(skew_10 > 0.0, "Positive OFI must create positive price skew");

    // 3. Verify sublinear concave scaling (Square-Root Law):
    // Compare fresh 10 units vs 40 units (ratio must be sqrt(40/10) = 2.0, well below linear 4.0)
    let mut ofi_40 = OfiAlpha::with_kyle_adaptive(0.005, 10.0, 0.50, 0.50, 0.0);
    let mut ofi_10 = OfiAlpha::with_kyle_adaptive(0.005, 10.0, 0.50, 0.50, 0.0);
    let s_10 = ofi_10.update_with_price(10.0, 100.0);
    let s_40 = ofi_40.update_with_price(40.0, 100.0);
    let ratio = s_40 / s_10;
    assert!((ratio - 2.0).abs() < 0.05, "Square-root impact law must yield ratio of 2.0 for 4x volume, got {}", ratio);

    // 4. Kyle's lambda dynamic calibration:
    // Repeated positive OFI with rising price should adapt positive lambda
    for _ in 0..10 {
        ofi.update_with_price(15.0, 100.10);
    }
    assert!(ofi.lambda > 0.0);
}
