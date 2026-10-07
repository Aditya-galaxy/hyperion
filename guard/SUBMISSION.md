# Arc Microgrants submission: Hyperion Guard

For the DoraHacks form (https://dorahacks.io/hackathon/arc-microgrants/detail).
The form asks for four things: a live deployment on Arc mainnet, a public
repo, a short description of what the project does and what it uses Arc for,
and a public builder profile. The deployment below was made on 2026-10-07
with `bash guard/demo/arc.sh mainnet`; addresses are in
`guard/deployments/mainnet.json`.

---

## Name

Hyperion Guard

## One-liner

A pre-trade firewall for autonomous trading agents, with the kill switch on Arc.

## Links

- **Live deployment (Arc mainnet):**
  - HyperionGuard: [`0x9683450F53B767AFfa080b6B3C91A1fA8F966890`](https://explorer.arc.io/address/0x9683450F53B767AFfa080b6B3C91A1fA8F966890)
  - GuardedExecutor: [`0xAf816b1E338584abAA2c2dcFba01B345cb6978AA`](https://explorer.arc.io/address/0xAf816b1E338584abAA2c2dcFba01B345cb6978AA)
  - DemoVenue: [`0x22F78ff7a8220E5E516d2c45aa540452cf49B77A`](https://explorer.arc.io/address/0x22F78ff7a8220E5E516d2c45aa540452cf49B77A)
  - Transactions: [deployment](https://explorer.arc.io/tx/0x7ca08fc7d7a5e3eddca51b71ac8ee5515015494a27a5db669c799592e8f668c3), [an order executed through the executor](https://explorer.arc.io/tx/0xcda2bb3b3fa0e4aa005bce86a75bcb9b1deaa3f443c5eeb4bd2c26801b1b06b2), [the guardian's kill](https://explorer.arc.io/tx/0xf0ce2f7215bbe8c618d5afb9215e0deb1db8bc5c87837f0702514c74a3d93e8c), [the verdict root anchored](https://explorer.arc.io/tx/0x224ee712477e76795b4796d8df1adc184309c9291277528e51775060e0736891)
- **Also on Arc testnet:** HyperionGuard [`0xA8Fc10f47BA1a486B1899e65204eEac099c59C93`](https://testnet.arcscan.app/address/0xA8Fc10f47BA1a486B1899e65204eEac099c59C93)
- **Repo:** https://github.com/Aditya-galaxy/hyperion/tree/main/guard
- **Builder profile:** https://github.com/Aditya-galaxy

## Description

AI agents are being given wallets and trading keys, and they fail in ways
people don't. They get prompt-injected, fat-finger a price, or loop on an
order, and nothing stands between the model's decision and the market.

Hyperion Guard checks every order an agent proposes before it goes out:

- the per-order size;
- the day's total;
- a price collar against an independent reference;
- a rate throttle;
- the kill switch.

Every decision comes back as an EIP-712 signed verdict, approved or not.
The checks come from a Rust pre-trade risk engine built for low-latency
trading.

## What it uses Arc for

1. **The control plane.** The agent's human owner registers its limits in
   `HyperionGuard`. The agent's own key can't loosen them.
2. **The kill switch.** An owner or a guardian (for example a monitoring bot)
   stops an agent in one transaction. Arc's sub-second deterministic finality
   means the next order is refused everywhere at once. Only the owner can
   revive the agent, and reviving bumps the policy version so pre-kill
   approvals stay dead.
3. **Enforcement, not advice.** `GuardedExecutor` is an agent wallet that only
   executes a call carrying a live approval for exactly that call: it's bound
   to the chain, the wallet, the target, the calldata, the notional and the
   nonce. Rejected, replayed, altered and pre-kill approvals revert on-chain.
4. **An audit trail.** The Guard anchors Merkle roots of every verdict on Arc
   in contiguous ranges, so a verdict can be proven and gaps can't be hidden.
5. **USDC-native payments.** Agents pay per check in USDC through Circle
   Gateway Nanopayments (x402), $0.001 a check. Gas on Arc is USDC too.

## Demo

`bash guard/demo/arc.sh mainnet` deploys and runs six scenes against the live
contracts. `guard/demo/local.sh` runs the same on a local chain with no keys.

| Scene | Guard | On-chain |
|---|---|---|
| A normal order | approved | executed |
| A prompt-injected $39,000 order | rejected (`order_notional`) | forced through anyway: `VerdictRejected(NotApproved)` |
| A price 7% above the market | rejected (`price_collar`) | nothing sent |
| A burst of orders | rejected (`rate_limit`) | nothing sent |
| Guardian kills the agent | rejected (`killed`) | an approval issued before the kill: `VerdictRejected(Killed)` |
| Anchor the record | Merkle root of all verdicts | `VerdictsAnchored` |

The mainnet run, 2026-10-07 (agent `0x9433FE30CB95eD895851B62FeD9F13459Fb13A9a`, chain 5042):

```
  normal order             approved         executed
  prompt-injected order    order_notional   reverted
  fat-finger price         price_collar     —
  order burst              rate_limit       —
  after the kill           killed           pre-kill approval reverted
  venue fills during the demo: 1 (only the normal order)
```

- Scene 1, the order executed: https://explorer.arc.io/tx/0xcda2bb3b3fa0e4aa005bce86a75bcb9b1deaa3f443c5eeb4bd2c26801b1b06b2
- Scene 5, the kill (mined in 2.0 s): https://explorer.arc.io/tx/0xf0ce2f7215bbe8c618d5afb9215e0deb1db8bc5c87837f0702514c74a3d93e8c
- Scene 6, verdicts 1–11 anchored: https://explorer.arc.io/tx/0x224ee712477e76795b4796d8df1adc184309c9291277528e51775060e0736891

The prompt-injected order and the pre-kill approval revert in the executor
(`VerdictRejected(NotApproved)`, `VerdictRejected(Killed)`), so they leave no
transaction. The whole deployment and demo cost about $0.07 in USDC gas.

## Quality

- **Contracts:** 27 Foundry tests, including a 512-run fuzz test that only
  the exact approved call executes. They cover replay, altered calls,
  reentrancy, kill and revive, and signer and policy rotation.
- **Service:** 29 tests.
- **Cross-language signing:** Python and Solidity produce identical EIP-712
  digests and order hashes, checked on both sides.
- **Fails closed:** if Arc can't be read or no fresh reference price exists,
  no approval is issued.
- **CI** runs `forge fmt --check`, `forge test` and the service tests on every
  pull request.
- **Limits are documented:** the notional is decoded only for calls the
  executor knows and otherwise declared, the Guard uses a single hot signing
  key, and the code isn't audited. See `guard/README.md`.

## Worth taking further

1. **Verified track records.** Every order and fill passes through the Guard,
   so it can publish attested performance records to the ERC-8004
   reputation registry. Agent reputation would then rest on executed trades
   rather than unverifiable reviews.
2. **Venue decoders**, so the executor reads the notional from calldata instead
   of trusting the declared figure.
3. **Threshold signing** for the Guard's key.
4. **Adapters** for agent-wallet providers and for broker-side deployments.
