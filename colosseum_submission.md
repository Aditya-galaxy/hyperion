# 🏛️ Colosseum Hackathon Submission Dossier

**Submission URL:** [https://colosseum.com/arena/hackathon](https://colosseum.com/arena/hackathon)  
**Hackathon:** Colosseum Arena (Fall 2026 Global Hackathon)  
**Project Name:** **Hyperion Guard (Solana Agent Firewall)**  
**Track:** AI Agents / Infrastructure & Developer Tooling / DeFi  
**Repository:** [https://github.com/Aditya-galaxy/hyperion](https://github.com/Aditya-galaxy/hyperion)  

---

## 1. Executive Summary & Tagline

> **Tagline:** The sub-millisecond pre-trade firewall & Ed25519 cryptographic co-signing risk engine protecting autonomous AI trading agents on Solana.

Autonomous trading agents on Solana are rapidly executing across Jupiter, Phoenix LOB, and Raydium. However, autonomous agents suffer from failure modes: model hallucinations, prompt injection attacks, stale pricing, and toxic sandwich MEV exploitation by searchers. Because Solana processes blocks in ~400ms, **post-trade monitoring is a post-mortem**. 

**Hyperion Guard** is an institutional pre-trade risk gateway and cryptographic co-signer designed for the Solana agentic economy (prototype). Before any raw Solana transaction payload reaches validators, Hyperion Guard intercepts the wire bytes, decodes the compiled instructions (Jupiter V6 and Raydium AMM V4 swaps, SPL Token and SOL transfers, and the Guarded Vault), checks strict risk firewalls, and co-signs compliant transactions with an authorized Ed25519 key. If an agent hallucinates an excessive swap size, accepts toxic slippage, or is targeted by an unapproved program, the Guard rejects the transaction before a single lamport is risked.

---

## 2. The Problem: The Agent Safety Trilemma on Solana

1. **Autonomous Execution Without Guardrails:** LLM and RL-driven trading agents hold private keys and sign arbitrary transaction payloads. A hallucinated decimal or inverted spread can vaporize capital in a single slot.
2. **MEV Sandwiches in High-Speed Slots:** Excessive slippage settings accepted by careless agents become lucrative bait for MEV searchers running sandwich bundles. 
3. **No Reactive Safety:** With ~400ms block times and sub-second finality, off-chain circuit breakers and post-trade alerts trigger too late. The primary defense is **deterministic pre-trade enforcement**.

---

## 3. The Solution: Hyperion Solana Guard

Hyperion Guard acts as an institutional pre-trade co-signing firewall:

```
┌─────────────────────────┐
│ Autonomous AI Agent     │
│ (Python / TypeScript)   │
└────────────┬────────────┘
             │ 1. Builds a transaction that spends from its vault
             │    (a payment, or a Jupiter / Raydium swap)
             ▼
┌────────────────────────────────────────────────────────┐
│               HYPERION SOLANA GUARD                   │
│                                                        │
│  [1. Wire Decoder]     Legacy & V0 transaction parser  │
│  [2. Instruction DPI]  Extracts Jupiter / Raydium data │
│  [3. Policy Firewall]                                  │
│     ├─ Max Notional Cap  ($ USD limit per order)       │
│     ├─ Slippage Collar   (≤ max allowed bps)           │
│     ├─ Program Allowlist (Only trusted DEX IDs)        │
│     └─ Kill Switch       (Instant slot-level circuit)  │
│  [4. Ed25519 Engine]   Signs compliant tx message      │
└────────────┬───────────────────────────────────────────┘
             │ 2. Co-Signed Transaction (Agent Sig + Guard Sig)
             ▼
┌────────────────────────────────────────────────────────┐
│          GUARDED VAULT (Solana program, devnet)        │
│                                                        │
│  Holds the agent's funds. Pays only if:                │
│     ├─ the agent AND the Guard both signed             │
│     ├─ the vault isn't killed                          │
│     └─ the amount is under the on-chain cap, or the    │
│        target program is on the vault's allow-list     │
│  Guardian can kill. Only the owner can revive,         │
│  change the policy, or withdraw.                       │
└────────────────────────────────────────────────────────┘
```

The Guard alone protects an agent that chooses to ask it. The vault is what makes asking mandatory: without the Guard's signature, the program refuses the transaction on-chain.

### Core Firewalls
- **Deterministic Program Allowlisting:** Dissects compiled transaction account keys. Rejects any transaction interacting with unauthorized programs or drainers.
- **Deep DEX Instruction Decoding:** Native unpacking of Anchor 8-byte discriminators and variable-length route plans with 19-byte parameter suffixes for Jupiter V6 (`sharedAccountsRoute`, `route`) and Raydium AMM V4 swaps (`swapBaseIn`, `swapBaseOut` and their V2 forms). Raydium's instruction has no slippage figure, so the Guard requires a real limit instead (a non-zero minimum out, or a maximum in) and refuses Raydium's non-swap instructions.
- **Fail-Closed on Everything Else:** An allow-listed program is inspected, not waved through. The Guard co-signs only instructions it can size (swaps, token and SOL transfers) or knows move nothing (opening a token account, `SyncNative`, `Revoke`). It refuses token `Approve`, `SetAuthority`, `CloseAccount` and `Burn`; System `Assign` and durable-nonce instructions (a transaction on a durable nonce never expires, so a co-signature on one would outlive a kill); and every Phoenix instruction. Phoenix orders are decoded (type, side, ticks, lots), but lots only become dollars with a market's parameters, which the Guard doesn't have yet. One exception: a program the owner adds that the Guard has no decoder for is passed on the owner's word.
- **Anti-MEV Slippage Collar:** Directly inspects `slippage_bps` encoded in DEX swaps, bounding maximum acceptable slippage to eliminate sandwich vulnerability.
- **Notional Size Caps:** Binds maximum USD exposure per order and throttles runaway trading loops. Swaps and transfers are sized in the token they actually spend, at a live price; a token the Guard can't price is refused, not guessed.
- **Cryptographic Kill Switch:** Owner/Guardian Ed25519-signed endpoint immediately revokes an agent's trading authority without requiring on-chain transaction delays. Guardians may trip the kill switch, but only the registered owner can revive trading.
- **Dual-Signature Multisig Enforcement:** Reference dual-signer execution vault specification and state machine (`guard/contracts_solana/`) enforcing both Agent signature and Guard Ed25519 co-signature for non-custodial agent risk isolation.

---

## 4. Architecture & Technical Implementation

Hyperion Guard is built as a zero-overhead, sub-millisecond service within the Hyperion repository (`guard/service/hyperion_guard/solana/`):

| Component | File Path | Implementation Details |
| :--- | :--- | :--- |
| **Pure Base58 Engine** | [`guard/service/hyperion_guard/solana/base58.py`](guard/service/hyperion_guard/solana/base58.py) | Zero-dependency, memory-safe Base58 encoder/decoder with full leading-zero preservation. |
| **Wire Transaction Decoder** | [`guard/service/hyperion_guard/solana/decoder.py`](guard/service/hyperion_guard/solana/decoder.py) | Compact-u16 parser, legacy & V0 transaction header decoding, compiled instruction resolution, and Anchor DEX discriminator + suffix unpacking. |
| **Pre-Trade Risk Engine** | [`guard/service/hyperion_guard/solana/guard.py`](guard/service/hyperion_guard/solana/guard.py) | Real-time policy evaluation, rate limiting, kill switch state machine, co-signer presence verification, and RFC 8032 Ed25519 message signing. |
| **REST API Gateway** | [`guard/service/hyperion_guard/api.py`](guard/service/hyperion_guard/api.py) | High-throughput FastAPI endpoints (`/v1/solana/check`, `/v1/solana/policy`, `/v1/solana/kill`, `/v1/solana/revive`, `/v1/solana/health`). |
| **Guarded Vault (Solana program)** | [`guard/contracts_solana/`](guard/contracts_solana/) | Native Solana program, compiled with `cargo build-sbf`. Every agent action (TransferSol, Execute) needs the agent's and the Guard's signatures, a vault that isn't killed, a cap or an allow-listed target; the vault signs inner calls as a PDA. Guardian can kill, only the owner can revive, set policy or withdraw (even when killed). Tests run the compiled program in LiteSVM, including transactions built in Python and co-signed by the Guard. **Deployed on devnet:** [`9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq`](https://explorer.solana.com/address/9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq?cluster=devnet). |

### Supported Solana Protocols
- **Jupiter V6 Aggregator:** `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`. All ten swap instructions in the program's on-chain IDL, including the `v2` routes most live swaps use. The two token-ledger routes carry no input amount and are refused.
- **Phoenix Limit Order Book (decoded, not co-signed yet):** `PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY`
- **Raydium AMM V4 (swaps):** `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`
- **SPL Token Program:** `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
- **Solana System Program:** `11111111111111111111111111111111`
- **Compute Budget:** `ComputeBudget111111111111111111111111111111`. The priority fee (unit price times unit limit) counts toward the order cap.
- **Associated Token Account:** `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`. Opening a token account is allowed and its rent counted; `RecoverNested` is refused.

**Checked against real mainnet transactions.** Nine Jupiter transactions fetched from mainnet, with the lookup-table entries and token account they use, are kept as test fixtures ([`tests/fixtures/mainnet_jupiter.json`](guard/service/tests/fixtures/mainnet_jupiter.json)) and judged whole: compute budget, token-account setup, the wrap and unwrap of SOL, and the swap. Five spend USDC or SOL and are sized to the cent. Four sell another token: with a price for it they are sized the same way, and without one they are refused.

**How a swap is sized.** A token amount is only a dollar figure if the Guard knows the token, so it finds out which token an instruction spends:

1. **From the instruction's accounts**, where it names its source mint. A v0 transaction loads most accounts from address lookup tables; given an RPC node (`HYPERION_SOLANA_RPC_URL`) the Guard reads those tables and caches them.
2. **From the wallet's own token account.** If the account being spent is the signer's associated token account for USDC, USDT or wrapped SOL, that settles it with no network call.
3. **From the token account itself.** Jupiter's older `route`, Raydium's swaps and a plain token `Transfer` spend a token account without naming its mint. The Guard reads the account over RPC to learn it. An associated token account's mint is fixed by its address and is remembered; any other account could be reopened for a different mint, so it's read every time.

USDC and USDT are taken at $1. SOL and every other token are priced by a price source: Jupiter's price API when `HYPERION_SOLANA_PRICES=jupiter` is set. Wrapping SOL into the wallet's own account isn't counted as spending it; the swap that follows is. **Anything the Guard can't price is refused** (`REJECTED_UNPRICED_TOKEN`): a token that couldn't be identified, one the source has no price for, or SOL when there is no source. The Guard doesn't guess, and it has no built-in SOL price.

**Keeping a bad price from becoming an approval.** A price is used for 10 seconds, then asked for again. A failed request is no price, never the last one. A token with under $100,000 of liquidity behind its price has no price: a thin market is cheap to push down, and a price pushed down would let a large sale through under the cap.

**What that leaves out.** A token too thinly traded to have a trusted price can't be sold through the Guard. A token account opened in the same transaction that spends it can't be read beforehand, so it's identified only if it's the wallet's own USDC, USDT or wrapped-SOL account. And the Guard believes its RPC node about lookup tables and token accounts, and its price source about prices.

---

## 5. Developer Integration (Python / TypeScript)

Autonomous agents integrate Hyperion Guard with minimal overhead:

```python
import base64
import requests

# 1. Autonomous agent generates a swap transaction via Jupiter API
swap_tx_bytes = jupiter_client.get_swap_transaction(quote)

# 2. Submit transaction bytes to local or self-hosted Hyperion Guard for pre-trade clearance
response = requests.post("http://localhost:8080/v1/solana/check", json={
    "agent_id": "ai-alpha-agent-sol-1",
    "tx_bytes": base64.b64encode(swap_tx_bytes).decode("ascii"),
    "encoding": "base64"
})
verdict = response.json()

if verdict["approved"]:
    # 3. Attach Guard's Ed25519 co-signature and broadcast to Solana RPC / Jito
    signed_tx = attach_cosigner_signature(swap_tx_bytes, verdict["cosigner_signature_b58"])
    solana_client.send_raw_transaction(signed_tx)
else:
    print(f"Trade blocked by Hyperion Guard: {verdict['status']} - {verdict['violation_details']}")
```

---

## 6. Verification & Test Suite

Hyperion Solana Guard is backed by an automated test suite verifying edge cases, malformed payloads, and adversarial scenarios:

```bash
cd guard/service
./.venv/bin/pytest tests/test_solana_guard.py -v
```

**Key Test Coverage:**
- `test_base58_roundtrip`: Cryptographic round-trip fidelity.
- `test_base58_leading_zeros`: Solana pubkey alignment preservation.
- `test_decode_real_mainnet_jupiter_swap`: Tests against real mainnet Jupiter route instruction (`7zoC74aDKgHF...`).
- `test_decode_jupiter_v6_swap`: Correct extraction of in-amount, min-out, and slippage BPS.
- `test_decode_jupiter_exact_out_route`: Verified parameter unpacking on exactOutRoute Jupiter swaps.
- `test_decode_phoenix_limit_order`: Reads a Phoenix order packet (type, side, ticks, lots) as phoenix-v1 lays it out.
- `test_solana_fail_closed.py`: Token approvals, durable nonces, Phoenix orders and other unsized instructions are refused, directly and inside a vault call.
- `test_guard_rejects_missing_guard_signer`: Rejects transactions that do not configure Guard as a required signer.
- `test_guard_rejects_malformed_or_unparsed_instruction`: Fail-closed firewall guarantees on unparsed instructions.
- `test_guard_approves_safe_jupiter_swap`: Co-signs safe trades with verified Ed25519 signatures.
- `test_guard_rejects_oversized_order_cap`: Intercepts orders exceeding notional limits.
- `test_guard_rejects_excessive_slippage_mev_risk`: Enforces anti-sandwich slippage collars.
- `test_guard_rejects_unauthorized_target_program`: Halts interactions with untrusted programs.
- `test_guard_kill_switch_blocks_execution_and_revival`: Tests emergency circuit breaker and recovery.
- `test_solana_api_lifecycle`: Full end-to-end authenticated HTTP API lifecycle testing with Ed25519 signatures.

**Total Project Tests Passing:**
- 15 Rust High-Performance Quant Engine Tests (`cargo test`)
- 15 Solana vault tests: 5 unit, 10 integration against the compiled program in LiteSVM (`cd guard/contracts_solana && cargo build-sbf && cargo test`)
- 27 EVM Guard & Calldata Decoder Tests (`forge test`)
- 220 Python Guard, vault client, MEV Harness & Attestation Tests (`pytest guard/service/tests proof/tests`), 4 of which send Guard-co-signed transactions to the compiled vault program
- **Total: 277 automated tests, all passing**

### Jito MEV & Sandwich Attack Simulation Benchmarks

To evaluate anti-sandwich protection dynamics, we built a standalone mathematical simulation harness ([`scripts/jito_mev_harness.py`](scripts/jito_mev_harness.py)). The harness models a constant-product AMM pool (Raydium CPMM $k = x \cdot y$) and simulates searcher front-run/back-run bundle economics offline without making live network calls:

| Metric / Scenario | Unprotected Agent (200 bps) | Hyperion Protected Agent (40 bps collar) |
| :--- | :--- | :--- |
| **Simulation Model** | Searcher computes optimal front-run | Intercepted pre-trade, before signing |
| **Searcher Front-run** | Injects $76,366 USDC pushing spot to $153.07 | **Blocked** (Zero victim tx to bundle) |
| **Searcher Gross Profit** | +$121.63 USDC (75% to Jito Validator) | $0.00 USDC (Searcher drops bundle) |
| **Agent Capital Loss** | **-$497.10 USDC (-2.0% loss)** | **$0.00 USDC (100% Protected)** |
| **Ed25519 Co-Signature** | N/A | **WITHHELD** (`REJECTED_EXCESSIVE_SLIPPAGE`) |
| **Median Guard Latency**| N/A | **32 µs** to refuse; **0.36 ms** to approve and sign |

> [!NOTE]
> Measured on a laptop, in Python: a refusal takes a median of **32 µs**; an approval takes **0.36 ms**, nearly all of it the Ed25519 signature. Both are under 0.1% of Solana's 400 ms slot. Two things cost more, once each: the first transaction from a wallet (about 0.3 to 0.8 ms to work out its token accounts), and the first use of a lookup table, a token account or a token's price (prices again every 10 seconds), each a network call of roughly 0.2 to 0.3 s to a public endpoint.

---

## 7. 2.5-Minute Video Pitch & Demo Script

The demo below is the pitch: six scenes, each a real devnet transaction.

### Live on devnet: the six scenes to record

`python guard/demo/solana_devnet.py` runs these against the deployed program and prints an explorer link for each. One recorded run (2026-10-06):

| Scene | What happened | Transaction |
|---|---|---|
| 1 | Owner opens the vault and funds it | [51Q1D1…](https://explorer.solana.com/tx/51Q1D13asYWch5q5DKWMJwaNtsdiVeVmnL1xEfADQXZ1FspAaAqGtGBCpYkE7fSot8nkLe9h2BnryctgmYVJQrKd?cluster=devnet) |
| 2 | Guard co-signs a $3 payment; the vault pays | [2F3edF…](https://explorer.solana.com/tx/2F3edF9ocehyenzUvrp9tDgDZXcHqQhZFPAmMb2pcCd3NT3s9sCvknjCMkhLQWCkHsoz6eqD3epBwdKRPEdieXD7?cluster=devnet) |
| 3 | Agent skips the Guard; the program fails it with `Custom(3)` MissingGuardCoSignature | [yTo6an…](https://explorer.solana.com/tx/yTo6an7jYUouBWWMZzMzVzYTfNgpFwpkKevGiaeo7cqJLxG5ZLpiBbWG96wV7umiP21KvV1wXUJr9ZipxwXfGEh?cluster=devnet) |
| 4 | A $6 order against a $5 cap; the Guard won't sign | none: nothing to send |
| 5 | Guardian kills the vault | [5dEKRQ…](https://explorer.solana.com/tx/5dEKRQGU4DtniJ1mNr9qumunZEzDz79SGo12PZ1DgPCR1T4ifucrKFJNMKhjzcyeqsZ138tqLds17LaLbHw6LRMU?cluster=devnet) |
| 5 | A transfer the Guard approved before the kill fails with `Custom(4)` VaultKilled | [62diUw…](https://explorer.solana.com/tx/62diUwm9B769pnPa2d8mVttaFPbrCSBe9cmXfkPT2y74q4GoQwomd3bQwgTtgKCbGvBf3nuPVkUQ6U3uGTfY7BzV?cluster=devnet) |
| 6 | Owner withdraws from the killed vault | [2WesDi…](https://explorer.solana.com/tx/2WesDiZqG7xbyNWeb9Xw8WXtrh4xmaaqvwBcHA9Sw3mupUKqYeH4Z2mtynMxqZVNp5xDzGLPiMVdJMpBoHKfSMMa?cluster=devnet) |

Each run makes a fresh agent, guardian and Guard key and so a fresh vault; the links above are from one run.

### The script (2:30, about 360 spoken words)

One terminal and one browser tab. No slides except the opening and closing cards. Everything on screen is the real demo running on devnet.

#### 0:00 – 0:20 · The problem
- **On screen:** Title card: "An AI agent holds the keys. What stops it?"
- **Voiceover:** "AI agents now trade and pay on Solana on their own. To do that, they hold a private key. One hallucinated number, one prompt injection, and the money is gone in a single slot, about four hundred milliseconds. An alert afterwards only tells you what you lost."

#### 0:20 – 0:40 · What Hyperion Guard is
- **On screen:** The architecture diagram from section 3: agent, Guard, vault.
- **Voiceover:** "Hyperion Guard has two halves. The agent's money sits in a vault, a Solana program. The vault only pays when a second signature is present: the Guard's. And the Guard only signs after it has decoded the transaction and checked it against the owner's policy. Let me show you, live on devnet."

#### 0:40 – 0:55 · Scene 1 and 2: open a vault, make a normal payment
- **On screen:** Run `python guard/demo/solana_devnet.py`. Let scenes 1 and 2 print. Click the scene 2 link; show both signatures in the explorer.
- **Voiceover:** "The owner opens a vault for the agent and funds it. The agent pays a merchant three dollars. The policy allows five, so the Guard co-signs, and the vault pays. Two signatures: the agent's and the Guard's."

#### 0:55 – 1:15 · Scene 3: the agent goes around the Guard
- **On screen:** Scene 3 output. Click the link; show the failed transaction and `custom program error: 0x3`.
- **Voiceover:** "Now the agent is compromised and sends the same payment without asking the Guard. The program itself refuses it, on-chain: missing Guard co-signature. The merchant's balance hasn't moved. This is the point of the vault. The agent can't opt out."

#### 1:15 – 1:30 · Scene 4: over the limit
- **On screen:** Scene 4 output: `REJECTED_ORDER_CAP`, "Order notional $6.00 exceeds cap of $5.00".
- **Voiceover:** "Next, a six-dollar order against a five-dollar cap. The Guard decodes the amount, refuses, and returns no signature. There's no transaction to send."

#### 1:30 – 1:55 · Scene 5 and 6: the kill switch, and the owner's exit
- **On screen:** Scene 5 output: the kill link, then the failed transfer with `0x4`. Then scene 6.
- **Voiceover:** "Something looks wrong, so a guardian, a monitoring bot, kills the vault with one transaction. Here's a transfer the Guard had already approved a moment earlier. It fails too: vault killed. The guardian can stop the agent, but it can't take the money. Only the owner can, and here the owner withdraws everything from the killed vault."

#### 1:55 – 2:15 · What's real, and what isn't yet
- **On screen:** The repository: `guard/contracts_solana/`, then the green CI run.
- **Voiceover:** "What you saw is a native Solana program, deployed on devnet, and a Guard that decodes Jupiter and Raydium swaps and token transfers, and refuses what it can't size. The tests run the compiled program, and Python and Rust agree byte for byte. It's a prototype: devnet only, not audited, and token amounts are checked by the Guard, not yet capped on-chain."

#### 2:15 – 2:30 · Close
- **On screen:** Closing card: repository URL and the program id.
- **Voiceover:** "Agents will hold money. Hyperion Guard is how an owner sets the rules and knows they hold. It's open source. The program id and every transaction from this demo are in the repository."

### Recording checklist

1. Check the wallet has at least 0.2 SOL on devnet: `solana balance --url devnet`.
2. Do one practice run first. Each run opens a new vault, so the links change every time; record the explorer tabs from the same run you narrate.
3. Terminal at 16–18 pt, dark theme, window about 110 columns wide so the links don't wrap.
4. The run takes about 30 seconds. Record it once at real speed, then cut to the explorer between scenes in the edit instead of waiting on screen.
5. In the explorer, keep `?cluster=devnet` visible in the address bar, so nobody mistakes this for mainnet.
6. Failed transactions show `custom program error: 0x3` and `0x4`. Zoom in on that line.
7. Record the voiceover separately and lay it over the picture. It's easier to hit 2:30.

---

## 8. Links & Deliverables

- **GitHub Repository:** [https://github.com/Aditya-galaxy/hyperion](https://github.com/Aditya-galaxy/hyperion)
- **Solana Guard Module:** [`guard/service/hyperion_guard/solana/`](guard/service/hyperion_guard/solana/)
- **Solana Guarded Vault program, on devnet:** [`9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq`](https://explorer.solana.com/address/9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq?cluster=devnet); source in [`guard/contracts_solana/`](guard/contracts_solana/)
- **Live devnet demo:** [`guard/demo/solana_devnet.py`](guard/demo/solana_devnet.py), six scenes, each a real transaction (links in section 7)
- **Jito MEV Simulation Harness:** [`scripts/jito_mev_harness.py`](scripts/jito_mev_harness.py)
- **Test Suite:** [`guard/service/tests/test_solana_guard.py`](guard/service/tests/test_solana_guard.py)
