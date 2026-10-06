# Hyperion Guard

**A pre-trade firewall for autonomous trading agents, with its kill switch on Arc.**

AI agents are being handed wallets and trading keys, and they fail in ways
people don't. They get prompt-injected, fat-finger a price, or loop on an
order. Nothing stands between the model's decision and the market. Hyperion
Guard does:

- **Every order is checked before it goes out:**
  - order size;
  - the day's total;
  - a price collar against an independent reference;
  - a rate throttle;
  - the kill switch.
- **The agent's limits and its kill switch live on Arc**, set by the agent's
  human owner. The agent's own key can't loosen them. A guardian, such as a
  monitoring bot, can stop the agent in one transaction that finalises in
  under a second. Only the owner can bring it back.
- **Every decision is a signed verdict,** approved or not. A
  `GuardedExecutor` wallet on Arc will only execute a call that carries a
  live approval for exactly that call. So a rejected, replayed, altered or
  pre-kill approval fails on-chain, not just in the Guard's opinion.
- **The Guard's record is anchored on Arc** as Merkle roots over contiguous
  ranges, so anyone holding a verdict can prove it's in the record, and gaps
  can't be hidden.
- **Agents pay per check** in USDC through Circle Gateway Nanopayments
  (x402): $0.001 a check.

The checks are modelled on Hyperion's Rust pre-trade risk controller
([`src/risk/controller.rs`](../src/risk/controller.rs)): kill switch first,
then size, collar and throttle, with a daily notional cap in place of its
position limit, since the Guard sees orders, not fills.

## Also on Solana

The same idea runs on Solana, where the enforcement is a native program
instead of an EVM wallet:

- **The Guarded Vault** ([contracts_solana](contracts_solana/README.md)) holds
  the agent's funds and pays only when the agent and the Guard both signed.
  A guardian can kill it; only the owner can revive it or withdraw. It is
  deployed on devnet: [`9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq`](https://explorer.solana.com/address/9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq?cluster=devnet).
- **The Solana Guard** ([service/hyperion_guard/solana](service/hyperion_guard/solana/))
  decodes the agent's transaction (Jupiter and Raydium swaps, token and SOL
  transfers, vault instructions), sizes it in dollars and co-signs with
  Ed25519, or refuses. It co-signs only what it can size:
  - USDC and USDT at $1; SOL and other tokens at a live price
    (`HYPERION_SOLANA_PRICES=jupiter`);
  - with `HYPERION_SOLANA_RPC_URL` it reads the address lookup tables and
    token accounts a transaction uses, to know which token is being spent;
  - anything it can't identify or price is refused.
- **Live demo:** `python guard/demo/solana_devnet.py` runs six scenes on
  devnet and prints an explorer link for each.

A policy names the agent's own key, and `/v1/solana/check` judges only
transactions that key has signed, so nobody else can use up an agent's rate
limit or daily cap. Asking twice about the same transaction returns the same
signature and counts once.

**A restart forgets nothing.** Policies and kill switches, control-message
nonces, the throttle and the day's spend, and the transactions already
approved are written through to a store
([`solana/store.py`](service/hyperion_guard/solana/store.py)) before a
verdict leaves, and read back at start. If the store can't be written, nothing
is approved.

| Setting | What it does |
|---|---|
| `HYPERION_SOLANA_STATE` | Where state lives: unset for memory, a path for a SQLite file, or `firestore` |
| `HYPERION_SOLANA_COSIGNER_KEY` | The co-signing key, a 32-byte Ed25519 seed in hex. Unset, a key is made up at start and lost at the next |
| `HYPERION_SOLANA_RPC_URL` | Lets the Guard read lookup tables and token accounts |
| `HYPERION_SOLANA_PRICES` | `jupiter` for live prices of SOL and other tokens |
| `HYPERION_VAULT_PROGRAM_ID` | The vault program(s) to recognise |
| `HYPERION_SOLANA_MAX_AGENTS` | How many agents a Guard will hold (default 1000) |

**A hosted Guard** runs at [https://hyperion-guard-dijsyl2kwq-uc.a.run.app](https://hyperion-guard-dijsyl2kwq-uc.a.run.app/docs), pointed at devnet. It is a
demo: don't put money behind it. [`deploy_guard.sh`](../deploy_guard.sh) hosts
your own on Cloud Run, with its state in Firestore and its key in Secret
Manager. Run the devnet demo against either:

```bash
HYPERION_GUARD_URL=https://hyperion-guard-dijsyl2kwq-uc.a.run.app python guard/demo/solana_devnet.py
```

The Solana Guard is written for one running instance: it keeps a copy of its
state in memory, and two instances sharing a store would let more through
than the caps allow. It answers one request at a time.

## Try it in one command

With [Foundry](https://getfoundry.sh) and Python 3.11+:

```bash
git clone --recursive https://github.com/Aditya-galaxy/hyperion.git && cd hyperion
python3 -m venv guard/service/.venv && guard/service/.venv/bin/pip install -e guard/service
bash guard/demo/local.sh
```

It starts a local chain, deploys the contracts, and runs six scenes:

| Scene | The Guard says | On-chain |
|---|---|---|
| A normal order | approved | executed |
| A prompt-injected $39,000 order | rejected: `order_notional` | forced through anyway, `VerdictRejected(NotApproved)` |
| A price 7% over the market | rejected: `price_collar` | nothing sent |
| A burst of orders | rejected: `rate_limit` after 5 a minute | nothing sent |
| The guardian kills the agent | rejected: `killed` | an approval issued *before* the kill reverts, `VerdictRejected(Killed)` |
| Anchor the record | root of verdicts 1–11 | `VerdictsAnchored` event |

Only the normal order reaches the venue.

## How it fits together

```
 agent ──order──► paywall (x402, $0.001) ──► Guard service ──reads──► HyperionGuard on Arc
   │                                              │                   (policy, kill switch,
   │                                              ▼                    signer, anchors)
   │                                     signed verdict ◄── ledger ──anchor──►┘
   │
   └──execute(call, verdict)──► GuardedExecutor on Arc ──check(verdict)──► HyperionGuard
                                        │
                                        └──only if Valid──► venue
```

| Part | Where | What it does |
|---|---|---|
| `HyperionGuard` | [`contracts/src/HyperionGuard.sol`](contracts/src/HyperionGuard.sol) | Agent registry: owner, guardian, policy, kill switch. EIP-712 verdict checks. Contiguous Merkle anchors. |
| `GuardedExecutor` | [`contracts/src/GuardedExecutor.sol`](contracts/src/GuardedExecutor.sol) | An agent's trading wallet. Runs a call only with a live approval bound to the chain, the wallet, the target, the calldata, the notional and the nonce. The owner can always withdraw. |
| Guard service | [`service/hyperion_guard`](service/hyperion_guard) | Reads the agent's record from Arc **on every check**, runs the checks, signs the verdict, logs it. Fails closed if Arc can't be read or there's no fresh reference price. |
| Paywall | [`paywall/server.ts`](paywall/server.ts) | Circle Gateway Nanopayments middleware in front of the service. `/v1/check` is paid. Health, agent lookups and verdict proofs are free. |
| Demo | [`demo`](demo) | The six scenes above, on a local chain or Arc testnet. |

### The policy

Set by the owner and stored on-chain. Amounts are in USDC's 6-decimal units.

| Field | Meaning |
|---|---|
| `maxOrderNotional` | largest single order |
| `maxDailyNotional` | total approved per UTC day |
| `collarBps` | how far a buy may pay above, or a sell take below, the reference price |
| `maxOrdersPerMinute` | throttle on approved orders |

A policy change or a revive bumps `policyVersion`. That kills every
outstanding verdict: nothing approved under the old rules survives.

### Rejection codes

These are carried in the signed verdict's `reason`:

| Code | Meaning |
|---|---|
| 0 | approved |
| 1 | killed |
| 2 | over the per-order limit |
| 3 | over the daily limit |
| 4 | outside the price collar |
| 5 | rate limited |
| 6 | no fresh reference price |
| 7 | unknown agent |
| 8 | malformed order |

## API

`POST /v1/check` (paid):

```json
{
  "agent": "0x…",
  "order": {"symbol": "BTC-USD", "side": "buy", "qty": "0.005", "price": "65100"},
  "client_order_id": "abc-1",
  "executor": {"address": "0x…", "target": "0x…", "data": "0x…", "nonce": 0}
}
```

- **With `executor`**, the verdict's `orderHash` is exactly
  `GuardedExecutor.orderHash(target, data, notional, nonce)`, ready to pass
  to `execute`.
- **Without it**, the order hash covers the order's canonical fields and
  `client_order_id`. That's for venues that aren't on-chain.

The response contains:

- the `verdict` struct;
- its EIP-712 `signature` and `digest`;
- `approved`, `reason` and a plain-English `explanation`;
- the computed `notional` and the `reference_price`.

Free endpoints:

- `GET /v1/health`
- `GET /v1/agents/{address}`
- `GET /v1/verdicts?agent=`
- `GET /v1/verdicts/{seq}`, which includes the Merkle proof once the verdict is anchored

## Deploying on Arc

Use an encrypted keystore (`cast wallet import guard-owner --interactive`),
never a private key on the command line.

```bash
cd guard/contracts
GUARD_SIGNER=0x<signer address> forge script script/Deploy.s.sol:Deploy \
  --rpc-url arc_testnet --account guard-owner --broadcast
GUARD=0x<guard> AGENT=0x<agent> GUARDIAN=0x<guardian> forge script script/Deploy.s.sol:DemoSetup \
  --rpc-url arc_testnet --account guard-owner --broadcast
```

For mainnet, use `--rpc-url arc_mainnet` (chain 5042). Gas is paid in USDC,
and a full deployment costs cents.

To run the service, see `hyperion-guard --help` for the environment variables:

```bash
hyperion-guard serve
```

To anchor new verdicts:

```bash
hyperion-guard anchor
```

To run the paywall, from `guard/paywall`:

```bash
SELLER_ADDRESS=0x… npm start
```

## What it doesn't do (yet)

- **The notional is declared, and decoded only for calls the executor knows.**
  `GuardedExecutor` reads the size out of a few known calls (the demo venue's
  `placeOrder`, Uniswap V3 `exactInputSingle` and USDC transfers) and reverts
  if the agent declared less. For any other calldata the Guard checks the
  declared figure, and the owner's target allow-list bounds what a lie could
  reach.
- **One signer.** The Guard's signing key is a hot key on the service. The
  contract lets the admin rotate it, and rotating kills every outstanding
  verdict. A threshold of signers is future work.
- **Usage is in memory.** The daily total and throttle are rebuilt from the
  ledger on restart, but aren't shared between replicas. Run one instance, or
  put a shared store behind it.
- **Reference prices.** Pyth Hermes (it needs an API key since 2026-08-26) or
  fixed prices for demos. On-chain oracles on Arc (Chainlink, Pyth, RedStone)
  are the next source to add.
- **Not audited.** Research code: tested (27 contract tests including a fuzz
  test, 29 service tests for Arc and over 100 for Solana, cross-language
  signature vectors), but not
  reviewed by a third party. Don't trust it with money you can't lose.

## License

MIT, like the rest of the repository.
