use crate::orderbook::lob::LimitOrderBook;

/// Order Flow Imbalance (OFI) Alpha Model.
///
/// Grounded in:
/// - Kyle's Lambda (Kyle, 1985; Hasbrouck, 1991): dP / d(OFI) price impact coefficient.
/// - Concave Square-Root Law of Market Impact (Cont, Kukanov & Stoikov, 2014; Bouchaud et al., 2018):
///   Replaces naive linear extrapolation to prevent extreme over-skewing on large block sweeps.
#[derive(Debug, Clone)]
pub struct OfiAlpha {
    /// Price impact coefficient (Kyle's Lambda)
    pub lambda: f64,
    /// Reference volume normalizer (typical queue size or ADV unit)
    pub ref_volume: f64,
    /// Maximum allowed quote skew in price units (safety boundary)
    pub max_skew_price: f64,
    /// Exponential decay factor for OFI accumulator (e.g. 0.90)
    pub decay_factor: f64,
    /// Smoothed OFI state
    pub smoothed_ofi: f64,
    /// Online recursive covariance tracker between delta_mid and OFI
    rolling_cov: f64,
    /// Online recursive variance tracker of OFI
    rolling_var: f64,
    /// Previous mid price for dynamic Kyle's lambda calibration
    prev_mid: Option<f64>,
    /// Adaptivity learning rate for Kyle's lambda recursive updates (0.0 = static lambda)
    pub kyle_learning_rate: f64,
}

impl OfiAlpha {
    /// Standard constructor (backward-compatible)
    pub fn new(alpha_multiplier: f64, max_skew_price: f64, decay_factor: f64) -> Self {
        Self {
            lambda: alpha_multiplier,
            ref_volume: 1.0,
            max_skew_price,
            decay_factor,
            smoothed_ofi: 0.0,
            rolling_cov: alpha_multiplier * 100.0,
            rolling_var: 100.0,
            prev_mid: None,
            kyle_learning_rate: 0.0, // Static by default
        }
    }

    /// Full research-backed constructor with dynamic Kyle's Lambda calibration
    /// and Square-Root market impact scaling.
    pub fn with_kyle_adaptive(
        initial_lambda: f64,
        ref_volume: f64,
        max_skew_price: f64,
        decay_factor: f64,
        kyle_learning_rate: f64,
    ) -> Self {
        let ref_vol = ref_volume.max(0.001);
        Self {
            lambda: initial_lambda,
            ref_volume: ref_vol,
            max_skew_price,
            decay_factor,
            smoothed_ofi: 0.0,
            rolling_cov: initial_lambda * 100.0,
            rolling_var: 100.0,
            prev_mid: None,
            kyle_learning_rate: kyle_learning_rate.clamp(0.0, 0.20),
        }
    }

    /// Compute concave square-root market impact:
    /// For |OFI| <= delta: linear core to prevent infinite derivative at origin.
    /// For |OFI| > delta: sign(OFI) * lambda * sqrt(|OFI| / V_ref).
    #[inline(always)]
    fn compute_impact(&self, ofi: f64) -> f64 {
        let delta = 0.1 * self.ref_volume;
        let abs_ofi = ofi.abs();

        let raw_impact = if abs_ofi <= delta {
            // Linear tangent near zero
            ofi * (self.lambda / (delta * self.ref_volume).sqrt())
        } else {
            // Empirical square-root law (Bouchaud et al. 2018)
            ofi.signum() * self.lambda * (abs_ofi / self.ref_volume).sqrt()
        };

        raw_impact.clamp(-self.max_skew_price, self.max_skew_price)
    }

    /// Update alpha state with latest book metrics and return price skew in dollars.
    #[inline(always)]
    pub fn update(&mut self, book: &LimitOrderBook) -> f64 {
        let raw_ofi = book.ofi_accumulator as f64;
        self.smoothed_ofi = self.decay_factor * self.smoothed_ofi + (1.0 - self.decay_factor) * raw_ofi;

        // If adaptive Kyle learning is enabled and mid is available, update lambda online
        if self.kyle_learning_rate > 0.0 {
            if let Some(current_mid) = book.mid_price() {
                let mid_f64 = current_mid.to_f64();
                if let Some(prev_mid) = self.prev_mid {
                    let delta_p = mid_f64 - prev_mid;
                    let lr = self.kyle_learning_rate;

                    self.rolling_cov = (1.0 - lr) * self.rolling_cov + lr * (delta_p * raw_ofi);
                    self.rolling_var = (1.0 - lr) * self.rolling_var + lr * (raw_ofi * raw_ofi);

                    if self.rolling_var > 1e-6 {
                        let empirical_lambda = self.rolling_cov / self.rolling_var;
                        // Bound lambda to positive, realistic market range [0.1x to 5.0x of baseline]
                        let min_l = self.lambda * 0.1;
                        let max_l = self.lambda * 5.0;
                        self.lambda = empirical_lambda.clamp(min_l, max_l);
                    }
                }
                self.prev_mid = Some(mid_f64);
            }
        }

        self.compute_impact(self.smoothed_ofi)
    }

    /// Update with explicit mid price to allow calibrating Kyle's lambda in backtests
    #[inline(always)]
    pub fn update_with_price(&mut self, raw_ofi: f64, current_mid: f64) -> f64 {
        self.smoothed_ofi = self.decay_factor * self.smoothed_ofi + (1.0 - self.decay_factor) * raw_ofi;

        if self.kyle_learning_rate > 0.0 {
            if let Some(prev_mid) = self.prev_mid {
                let delta_p = current_mid - prev_mid;
                let lr = self.kyle_learning_rate;

                self.rolling_cov = (1.0 - lr) * self.rolling_cov + lr * (delta_p * raw_ofi);
                self.rolling_var = (1.0 - lr) * self.rolling_var + lr * (raw_ofi * raw_ofi);

                if self.rolling_var > 1e-6 {
                    let empirical_lambda = self.rolling_cov / self.rolling_var;
                    let min_l = 1e-6;
                    let max_l = 1.0;
                    self.lambda = empirical_lambda.clamp(min_l, max_l);
                }
            }
            self.prev_mid = Some(current_mid);
        }

        self.compute_impact(self.smoothed_ofi)
    }

    #[inline(always)]
    pub fn current_skew(&self) -> f64 {
        self.compute_impact(self.smoothed_ofi)
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        self.smoothed_ofi = 0.0;
        self.prev_mid = None;
    }
}
