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

**Hyperion Guard** is an institutional pre-trade risk gateway and cryptographic co-signer designed for the Solana agentic economy (prototype). Before any raw Solana transaction payload reaches validators, Hyperion Guard intercepts the wire bytes, decodes the compiled instructions (Jupiter V6, Phoenix, SPL Token, System and the Guarded Vault; Raydium can be allow-listed but its instructions aren't decoded yet), checks strict risk firewalls, and co-signs compliant transactions with an authorized Ed25519 key. If an agent hallucinates an excessive swap size, accepts toxic slippage, or is targeted by an unapproved program, the Guard rejects the transaction before a single lamport is risked.

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
             │ 1. Assembles Solana Transaction (Jupiter / Phoenix / Raydium)
             ▼
┌────────────────────────────────────────────────────────┐
│               HYPERION SOLANA GUARD                   │
│                                                        │
│  [1. Wire Decoder]     Legacy & V0 transaction parser  │
│  [2. Instruction DPI]  Extracts Jupiter / Phoenix data │
│  [3. Policy Firewall]                                  │
│     ├─ Max Notional Cap  ($ USD limit per order)       │
│     ├─ Slippage Collar   (≤ max allowed bps)           │
│     ├─ Program Allowlist (Only trusted DEX IDs)        │
│     └─ Kill Switch       (Instant slot-level circuit)  │
│  [4. Ed25519 Engine]   Signs compliant tx message      │
└────────────┬───────────────────────────────────────────┘
             │ 2. Co-Signed Transaction (Agent Sig + Guard Sig)
             ▼
┌─────────────────────────┐
│ Solana Validator / Jito │
│ (RPC / Shredstream)     │
└─────────────────────────┘
```

### Core Firewalls
- **Deterministic Program Allowlisting:** Dissects compiled transaction account keys. Rejects any transaction interacting with unauthorized programs or drainers.
- **Deep DEX Instruction Decoding:** Native unpacking of Anchor 8-byte discriminators and variable-length route plans with 19-byte parameter suffixes for Jupiter V6 (`sharedAccountsRoute`, `route`), and Phoenix LOB (`newOrder`, `swap`). Raydium is not decoded yet.
- **Anti-MEV Slippage Collar:** Directly inspects `slippage_bps` encoded in DEX swaps, bounding maximum acceptable slippage to eliminate sandwich vulnerability.
- **Notional Size Caps:** Binds maximum USD exposure per order and throttles runaway trading loops.
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
- **Jupiter V6 Aggregator:** `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`
- **Phoenix Limit Order Book:** `PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY`
- **Raydium AMM V4 (allow-listed, not decoded):** `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`
- **SPL Token Program:** `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
- **Solana System Program:** `11111111111111111111111111111111`

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
- `test_decode_phoenix_limit_order`: Accurate price/quantity unpacking from Phoenix byte stream.
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
- 14 Solana vault tests: 5 unit, 9 integration against the compiled program in LiteSVM (`cd guard/contracts_solana && cargo build-sbf && cargo test`)
- 26 EVM Guard & Calldata Decoder Tests (`forge test`)
- 74 Python Guard, MEV Harness & Attestation Tests (`pytest guard/service/tests proof/tests`)
- **Total: 120 Automated Tests (100% Pass Rate)**

### Jito MEV & Sandwich Attack Simulation Benchmarks

To evaluate anti-sandwich protection dynamics, we built a standalone mathematical simulation harness ([`scripts/jito_mev_harness.py`](scripts/jito_mev_harness.py)). The harness models a constant-product AMM pool (Raydium CPMM $k = x \cdot y$) and simulates searcher front-run/back-run bundle economics offline without making live network calls:

| Metric / Scenario | Unprotected Agent (200 bps) | Hyperion Protected Agent (40 bps collar) |
| :--- | :--- | :--- |
| **Simulation Model** | Searcher computes optimal front-run | Intercepted pre-trade in **~45 µs** |
| **Searcher Front-run** | Injects $76,366 USDC pushing spot to $153.07 | **Blocked** (Zero victim tx to bundle) |
| **Searcher Gross Profit** | +$121.63 USDC (75% to Jito Validator) | $0.00 USDC (Searcher drops bundle) |
| **Agent Capital Loss** | **-$497.10 USDC (-2.0% loss)** | **$0.00 USDC (100% Protected)** |
| **Ed25519 Co-Signature** | N/A | **WITHHELD** (`REJECTED_EXCESSIVE_SLIPPAGE`) |
| **Median Guard Latency**| N/A | **25.7 µs (0.026 ms)** |

> [!NOTE]
> Hyperion Guard's median evaluation latency of **~26 µs** consumes less than **0.01%** of Solana's 400 ms slot time.

---

## 7. 2.5-Minute Video Pitch & Demo Script

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

### Scene 1: The Problem (0:00 - 0:35)
- **Visual:** High-speed terminal showing Solana AI trading agents firing automated trades. Screen cuts to an alert showing an agent losing funds to a 500 bps slippage sandwich attack on Jupiter.
- **Voiceover:** "Autonomous AI agents are executing DeFi trades on Solana. They analyze orderbooks, spot arbitrage, and execute swaps in milliseconds. But autonomous trading without guardrails can be catastrophic. Hallucinations, bad quotes, and aggressive MEV searchers can drain an agent's treasury in a single block. Because Solana finalizes blocks in 400 milliseconds, reactive alerts only tell you what you’ve already lost."

### Scene 2: Introducing Hyperion Guard (0:35 - 1:15)
- **Visual:** Architectural graphic showing an AI agent sending raw transactions to Hyperion Guard, which validates the instructions in microseconds and co-signs them.
- **Voiceover:** "Meet Hyperion Guard: an institutional pre-trade risk firewall for autonomous Solana agents. Hyperion Guard inspects compiled wire transactions *before* they touch the network. It parses the actual Anchor byte stream of Jupiter V6 swaps, and Phoenix LOB orders, enforcing mathematical risk collars before signing."

### Scene 3: Live Demo — Safe Trade vs. MEV Exploit (1:15 - 1:55)
- **Visual:** Split-screen terminal.
  - Left: Agent submits a safe trade with 25 bps slippage. Guard approves in <1ms and attaches an Ed25519 co-signature.
  - Right: Agent submits a trade with 200 bps slippage (sandwich target). Guard immediately flags `REJECTED_EXCESSIVE_SLIPPAGE`, refusing to co-sign.
- **Voiceover:** "Watch it in action. On the left, our agent submits a standard USDC to SOL swap on Jupiter. Guard decodes the instruction data, verifies the slippage collar and size cap, attaches an authorized Ed25519 co-signature, and authorizes broadcast. On the right, the agent experiences slippage drift. Guard instantly detects excessive slippage, rejects the transaction, and prevents the sandwich attack."

### Scene 4: Emergency Circuit Breaker & Co-Signing (1:55 - 2:15)
- **Visual:** Admin triggers `/v1/solana/kill`. Agent immediately attempts another trade; Guard blocks it with `REJECTED_KILL_SWITCH`.
- **Voiceover:** "If an agent enters an infinite retry loop or exhibits anomalous behavior, the risk officer triggers the cryptographic kill switch. All subsequent transactions are denied co-signing immediately, freezing execution within the current slot."

### Scene 5: Conclusion & Future Roadmap (2:15 - 2:30)
- **Visual:** Links to GitHub repository, Colosseum submission portal, and documentation.
- **Voiceover:** "Hyperion Guard is an open-source, fully tested pre-trade risk engine for Jupiter and Phoenix, with a Guarded Vault program live on devnet. Inspect our open-source implementation on GitHub. Built for the Colosseum Arena Hackathon."

---

## 8. Links & Deliverables

- **GitHub Repository:** [https://github.com/Aditya-galaxy/hyperion](https://github.com/Aditya-galaxy/hyperion)
- **Solana Guard Module:** [`guard/service/hyperion_guard/solana/`](guard/service/hyperion_guard/solana/)
- **Solana Guarded Vault program, on devnet:** [`9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq`](https://explorer.solana.com/address/9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq?cluster=devnet); source in [`guard/contracts_solana/`](guard/contracts_solana/)
- **Live devnet demo:** [`guard/demo/solana_devnet.py`](guard/demo/solana_devnet.py), six scenes, each a real transaction (links in section 7)
- **Jito MEV Simulation Harness:** [`scripts/jito_mev_harness.py`](scripts/jito_mev_harness.py)
- **Test Suite:** [`guard/service/tests/test_solana_guard.py`](guard/service/tests/test_solana_guard.py)
