# Hyperion Proof

**Verified track records for trading agents, recorded in ERC-8004 on Arc.**

Agent reputation today is mostly assertion. In an empirical study of
ERC-8004 activity ([arXiv 2606.26028](https://arxiv.org/html/2606.26028)):

- 98.7–100% of reputation feedback carried no evidence of any interaction;
- 59–91% of reviewers were sybils.

A trading agent's record shouldn't be a review. It should be a number anyone
can recompute from public data.

Hyperion Proof produces that number:

1. **The account proves it belongs to the agent.** The trading account signs
   an EIP-712 request naming the agent's ERC-8004 identity. A record can't be
   borrowed from someone else's account.
2. **A validator computes the record from public data.** It reads the
   account's history from Hyperliquid's public API: account value and
   cumulative PnL. From that it computes a time-weighted return, which
   deposits and withdrawals don't inflate, and a max drawdown. It uses exact
   decimal arithmetic, so every machine gets the same answer.
3. **Everything goes into one evidence file:** the signed request, the raw
   inputs as fetched, and the metrics. Its keccak256 is the commitment.
4. **The record is posted to the ERC-8004 Reputation Registry on Arc** as two
   feedback entries from the validator:
   - `tradingYield`: the return, in percent, to 4 decimals;
   - `maxDrawdown`: also in percent, to 4 decimals.

   Both use tag2 `hyperliquid:<window>` and carry the evidence URI and hash.
   By default the evidence travels inline as a `data:` URI, so the chain
   itself holds it. The registry refuses feedback from an agent's owner or
   operators, so an agent can't grade itself.
5. **Anyone can verify.** Verification recomputes the metrics from the file's
   own inputs, checks the request's signature, and confirms that the on-chain
   entries commit to exactly this file.

## Try it (no funds, real contracts)

```bash
python3 -m venv .venv && .venv/bin/pip install -e proof
PYTHON=.venv/bin/python bash proof/demo/fork.sh
```

This forks Arc testnet locally and runs the flow against the deployed
ERC-8004 v2.0.0 registries:

1. register an agent;
2. sign a request;
3. attest and post;
4. verify;
5. read the registry's own `getSummary`;
6. watch the owner get refused when it tries to rate its own agent.

## Use it

```bash
# the trading account signs (its key in PROOF_ACCOUNT_KEY)
hyperion-proof request --agent-id 12 --chain 5042 --window month > req.json

# the validator attests (PROOF_VALIDATOR_KEY; PROOF_RPC_URL optional)
hyperion-proof attest req.json --post

# anyone checks
hyperion-proof verify data/proofs/<hash>.json --chain 5042 --tx <the two posting transactions>
```

**Registries used** (ERC-8004 v2.0.0; code checked on-chain):

| Network | Identity | Reputation |
|---|---|---|
| Arc mainnet (5042) | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` |
| Arc testnet (5042002) | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | `0x8004B663056A597Dffe9eCcC1965A193B7388713` |

**Windows:** `day`, `week`, `month`, `allTime`, and the same four for perps only
(`perpDay`, `perpWeek`, `perpMonth`, `perpAllTime`), as Hyperliquid defines them.

## The method (`twr-pnl/v1`)

For consecutive history points *i−1* and *i*, the interval return is the
change in cumulative PnL divided by the account value at *i−1*.

- **Time-weighted return:** the product of (1 + interval return), minus one.
- **Max drawdown:** the largest fall of that index from its running peak.
- **Net deposits:** the part of the value change that wasn't PnL.

Intervals that start at a zero or negative value are skipped and counted.
Numbers are computed with 50-digit Decimals and reported to 10 places.

## What it doesn't prove (yet)

- **The inputs are what the API returned, as the validator saw them.** The
  file records what was fetched and when. Anyone can spot-check the
  historical points against Hyperliquid's API while they're still in its
  window. Proving the response itself with MPC-TLS (e.g. TLSNotary / Reclaim) or
  TEEs is on the roadmap; the codebase provides a notary-signed attestation
  prototype in `hyperion_proof.notary_attestation` in the interim.
- **Deposits inside an interval.** A deposit mid-interval isn't in that
  interval's starting value, which slightly overstates its return.
  Hyperliquid's own ledger of deposits and withdrawals would allow a
  Modified Dietz method.
- **One validator per attestation.** ERC-8004 lets readers choose which
  validators they trust, and several validators can attest the same account
  and window.
- **Only accounts with their own key.** Vaults and sub-accounts need their
  leader or master to sign, which isn't supported yet.
- **Reputation, not Validation.** ERC-8004's Validation Registry, the natural
  home for this, isn't deployed on any network yet. When it is, a request
  will go on-chain and the response will point to the same evidence.
- **Not audited.** Research code, tested but not independently reviewed.

## License

MIT, like the rest of the repository. The Hyperliquid data in the evidence
files is public account history, used under Hyperliquid's terms of use.
