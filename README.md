# Hyperion

[![Hosted Guard](https://img.shields.io/badge/live-Hyperion%20Guard%20API-1f8a4c.svg)](https://hyperion-guard-dijsyl2kwq-uc.a.run.app/docs)
[![Solana devnet](https://img.shields.io/badge/solana%20devnet-Guarded%20Vault-9945ff.svg)](https://explorer.solana.com/address/9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq?cluster=devnet)
[![Live site](https://img.shields.io/badge/live-Hyperion%20Events-2a78d6.svg)](https://storage.googleapis.com/hyperion-events-site-kronagent/index.html)
[![Build Status](https://github.com/Aditya-galaxy/hyperion/actions/workflows/ci.yml/badge.svg)](https://github.com/Aditya-galaxy/hyperion/actions)
[![Code: MIT](https://img.shields.io/badge/code-MIT-yellow.svg)](LICENSE)
[![Data: CC BY-NC-SA 4.0](https://img.shields.io/badge/data-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

Hyperion is three pieces of trading research in one repository:

- **[Hyperion Guard](#️-hyperion-guard-a-firewall-for-trading-agents):** a
  pre-trade firewall and co-signer for autonomous trading agents. Live on
  Solana devnet, with a hosted API.
- **[Hyperion Events](#-hyperion-events-exchange-notices-vs-real-prices):** an
  open event study of exchange notices against real prices, with a live site.
- **[A low-latency engine in Rust](#️-the-rust-engine-research-code):**
  research code, run on simulated data.

**What exchange notices do to crypto prices, second by second, and how fast
you'd have had to be to trade them.** Hyperion Events matches every Upbit trade notice
(listings, delistings, caution designations) against Binance's one-second price
archive, and measures how much of each move was still there for an order filled
0–10 seconds late, after fees.

What the data says so far (433 events, 217 measurable on Binance):

- **Listings (140):** a median move of **+13.6% within 10 seconds**. The median
  trade only paid if it was filled **in the same second** as the notice.
  Filled one second late, it returned **−1.1%** after fees. That race is run
  by machines.
- **Delistings (14):** shorting still paid when filled 10 seconds late. It's a
  lead, not a result: 14 events is too few, and many of these coins can't be
  shorted.

**[See the charts and every event →](https://storage.googleapis.com/hyperion-events-site-kronagent/index.html)**

The repo also holds a low-latency trading engine in Rust (see *The Rust
engine* below). It's research and learning code:
fast, tested, but run only on simulated data and not connected to any exchange.

---

## 🛡️ Hyperion Guard: a firewall for trading agents

An AI agent that trades holds a key. Hyperion Guard stands between the agent's
decision and the chain: it decodes the transaction, checks it against limits
the agent's owner set, and only then co-signs.

- **On Solana**, the agent's funds sit in a Guarded Vault program that pays
  only with the Guard's signature. The Guard decodes Jupiter and Raydium swaps
  and token and SOL transfers, sizes them in dollars at a live price, and
  refuses what it can't size. The vault is live on **devnet**:
  [`9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq`](https://explorer.solana.com/address/9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq?cluster=devnet).
  See [guard/contracts_solana](guard/contracts_solana/README.md), and run the
  six-scene demo with `python guard/demo/solana_devnet.py`. There are Python
  and [TypeScript](guard/client-ts/README.md) clients. A hosted Guard
  for devnet runs at [https://hyperion-guard-dijsyl2kwq-uc.a.run.app](https://hyperion-guard-dijsyl2kwq-uc.a.run.app/docs).
- **On Arc** (live on **Arc mainnet**: [`0x9683…6890`](https://explorer.arc.io/address/0x9683450F53B767AFfa080b6B3C91A1fA8F966890)),
  limits and the kill switch live in a contract, and a
  `GuardedExecutor` wallet only executes a call that carries a live approval.
  See [guard/README.md](guard/README.md); `bash guard/demo/local.sh` runs it
  on a local chain.

It's a prototype: on Solana devnet and Arc mainnet, and not audited. Don't put money behind it.

## 📰 Hyperion Events: exchange notices vs. real prices

**Live site: [Hyperion Events](https://storage.googleapis.com/hyperion-events-site-kronagent/index.html)**:
findings, charts and every event, with the data as CSV/JSON (CC BY-NC-SA 4.0).

For each event it records how far the price moved (against BTC, so a market-wide
move isn't credited to the notice), the second-by-second price path, and the
net result of the implied trade by fill delay and hold time.

```bash
pip install ./python
hyperion-events ingest                    # fetch new notices, measure what's ready
hyperion-events report --kinds listing    # reaction + "how fast would I have to be?"
hyperion-events export --format csv > events.csv
hyperion-events site --out site           # public static site: findings, charts, event feed
```

**Data licence.** The code is MIT. The *data* is not: prices come from Binance
Vision, whose archive is licensed CC BY-NC-SA 4.0 (Binance Vision Dataset Terms
v1.0, 26 Aug 2026), and that covers anything calculated from it. So everything
this publishes (the site, the API, public exports) is **non-commercial, credits
Binance Vision, and carries the same licence**. Upbit's notice text is theirs:
published output links to each notice instead of copying its title. See
[`terms.py`](python/event_study/terms.py).

**HTTP API** (`pip install "./python[api]"`):

```bash
hyperion-events keys create you@lab.edu                  # free research key, printed once
hyperion-events serve --port 8000                        # interactive docs at /docs
curl -H "X-API-Key: hk_..." "localhost:8000/v1/stats?kind=listing&hold=300"
```

| Endpoint | Returns |
|---|---|
| `GET /v1/events` | Newest first; filter by `kind`, `symbol`, `since`, `until`, `status`; cursor paging; `format=csv` |
| `GET /v1/events/{id}` | One event with its full tradability grid |
| `GET /v1/stats?kind=` | Price reaction by horizon, net trade return by fill delay, and the slowest fill that still paid |
| `GET /v1/meta` | Kinds, horizons, fill delays, fees; your plan and data cutoff |

Keys are free: the `research` plan allows 60 requests a minute, `collaborator`
600. Every response carries the data licence in an `X-Data-License` header.

Everything is stored in `data/hyperion.db` (SQLite). Re-running `ingest` only
fetches what's new; events from the last couple of days stay *pending* until
Binance publishes their price files. Read only: no keys, no accounts, no orders.

---

## ⚙️ The Rust engine (research code)

The components of an exchange-grade trading stack, built to learn how they work
and how fast they can be. **Read these numbers as engineering, not trading
results.** Speeds are measured inside one process, with no network: a real
order's trip to an exchange takes milliseconds, thousands of times longer. The
strategies have been run only on simulated data. Nothing here signs or sends an
order to an exchange.

| Component | What it is | What's been shown |
|---|---|---|
| Order book & matching (`src/orderbook/`, `src/matching/`) | L3 limit order book with O(1) price-level queues; FIFO price-time matching (limit, IOC, FOK) | Tests; median 83 ns add+cancel, 208 ns limit-order ingest |
| Core (`src/core/`) | Slab arena and a lock-free SPSC ring buffer; no heap allocation on the hot path | Tests |
| Pre-trade risk (`src/risk/`) | Fat-finger limits, price collars, throttles, kill switch | Tests; median 83 ns per check |
| Simulated market (`src/main.rs`) | Quotes, risk, matching and order management in one loop against a simulated flow | Median **1.1 µs** tick-to-trade |
| Backtester (`src/backtest/`) | Event-driven, with fees, slippage and delay | About **25M bars/s**; fed by a synthetic data generator |
| Pairs trading (`src/quant/stat_arb.rs`) | Rolling z-score of a hedged spread (Welford, no allocations) | Simulated cointegrated pair only (see below) |
| Basis trade (`src/quant/basis_arb.rs`) | Spot vs. perpetual funding carry, annualised | Hand-written scenarios |
| Market making (`src/strategy/`) | Avellaneda–Stoikov inventory skew; order-flow-imbalance signal | Tests |
| Adverse-selection rule (`src/quant/ml_model.rs`) | Three hand-set decision stumps over 8 order-book features; about 49 ns an evaluation | Agreement with a simulator's label; [model card](hf_publish/README.md) |
| Feed parser (`src/feed/binance_feed.rs`) | Zero-copy parser for Binance `@bookTicker` and depth messages | Tests on sample messages |

Timings are from `cargo run --release --bin benchmark`, `run_ml_alpha`,
`run_stat_arb` and `hyperion-quant` on an Apple M1 laptop. They vary by machine
and run; measure on yours.

### About the pairs-trading backtest

`cargo run --release --bin run_stat_arb` trades a **synthetic** pair that is
generated to mean-revert: 10,000 one-minute bars, hedge ratio 18.5, 4 bps fees,
2 bps slippage. It reports a Sharpe ratio of about 28 and a 0.38% maximum
drawdown. That shows the engine and the metrics work. It is **not** evidence
the strategy makes money: the data was built so that it would. Real pairs drift
apart, and no real-data backtest has been run.

---

## 🚀 Quickstart & Usage

### Prerequisites
* Rust 1.80+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

### Clone & Build
```bash
git clone https://github.com/Aditya-galaxy/hyperion.git
cd hyperion
cargo build --release
```

### 1. Run Quantitative Backtest Simulation (Statistical Arbitrage)
```bash
cargo run --release --bin run_stat_arb
```

### 2. Run Cash-and-Carry Basis Arbitrage Engine
```bash
cargo run --release --bin run_basis_arb
```

### 3. Run the adverse-selection rule
```bash
cargo run --release --bin run_ml_alpha
```

### 4. Run Microsecond Execution Benchmark
```bash
cargo run --release --bin benchmark
```

### 5. Run the simulated market (no exchange connection)
```bash
cargo run --release --bin hyperion-quant
```

### 6. Run the Rust test suite (15 tests)
```bash
cargo test
```

---

## ☁️ Google Cloud

**The public site.** [`deploy_site.sh`](deploy_site.sh) rebuilds the site from
`data/hyperion.db` and uploads it to its own public bucket
(`hyperion-events-site-<project>`). Refresh it with:

```bash
hyperion-events ingest && bash deploy_site.sh
```

Ingest runs by hand for now, not on a schedule: Upbit's terms bar automated
access without their permission, and that's been asked for.

**The retraining job (paused).** [`deploy_cloud_trainer.sh`](deploy_cloud_trainer.sh)
sets up a Cloud Run job, `hyperion-model-retrainer`, that runs
`python/train_purged_cv.py`. The script re-scores the three hand-set decision
stumps on freshly **simulated** data; nothing is trained on market data (see
the [model card](hf_publish/README.md)). Its nightly trigger,
`hyperion-nightly-retrain`, is **paused** because re-running it produced nothing
new. To run it once, or switch the schedule back on:

```bash
gcloud run jobs execute hyperion-model-retrainer --region us-central1
```

```bash
gcloud scheduler jobs resume hyperion-nightly-retrain --location=us-central1
```

---

## 📄 License

The **code** is [MIT](LICENSE). The **data** Hyperion Events publishes is
derived from Binance Vision's archive and is licensed
[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/):
non-commercial use, credit Binance Vision, share alike. Not affiliated with or
endorsed by Binance or Upbit. Research, not financial advice.
