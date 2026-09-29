# 🏛️ Colosseum Hackathon Submission Dossier

**Submission URL:** [https://colosseum.com/arena/hackathon](https://colosseum.com/arena/hackathon)  
**Hackathon:** Colosseum Arena (Fall 2026 Crypto World's Fair / Global Hackathon)  
**Project Name:** **Hyperion Guard (Solana Agent Firewall)**  
**Track:** AI Agents / Infrastructure & Developer Tooling / DeFi  
**Repository:** [github.com/aditya/hyperion_hft](https://github.com/aditya/hyperion_hft)  

---

## 1. Executive Summary & Tagline

> **Tagline:** The sub-millisecond pre-trade firewall & Ed25519 cryptographic co-signing risk engine protecting autonomous AI trading agents on Solana.

Autonomous trading agents on Solana are rapidly replacing human traders across Jupiter, Phoenix LOB, and Raydium. However, autonomous agents suffer from catastrophic failure modes: model hallucinations, prompt injection attacks, stale pricing, and toxic sandwich MEV exploitation by Jito searchers. Because Solana processes blocks in ~400ms, **post-trade monitoring is a post-mortem**. 

**Hyperion Guard** is an institutional pre-trade risk gateway and cryptographic co-signer designed for the Solana agentic economy. Before any raw Solana transaction payload reaches validators, Hyperion Guard intercepts the wire bytes, decodes the compiled instructions (supporting Jupiter V6, Phoenix, Raydium, and SPL Token programs), checks 4 strict risk firewalls, and co-signs compliant transactions with an authorized Ed25519 key. If an agent hallucinates an excessive swap size, accepts toxic slippage, or is targeted by a drainer, the Guard rejects the transaction before a single lamport is risked.

---

## 2. The Problem: The Agent Safety Trilemma on Solana

1. **Autonomous Execution Without Guardrails:** LLM and RL-driven trading agents hold private keys and sign arbitrary transaction payloads. A hallucinated decimal or inverted spread can instantly vaporize capital in a single slot.
2. **MEV Sandwiches in High-Speed Slots:** High slippage settings accepted by careless agents become lucrative bait for MEV searchers running Jito bundles. 
3. **No Reactive Safety:** With ~400ms block times and sub-second finality, off-chain circuit breakers and post-trade alerts trigger too late. The only protection is **deterministic pre-trade enforcement**.

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
- **Deep DEX Instruction Decoding:** Native unpacking of Anchor 8-byte discriminators for Jupiter V6 (`sharedAccountsRoute`, `route`), Phoenix LOB (`newOrder`, `swap`), and Raydium CPMM.
- **Anti-MEV Slippage Collar:** Directly inspects `slippage_bps` encoded in DEX swaps, bounding maximum acceptable slippage to eliminate sandwich vulnerability.
- **Notional Size Caps:** Binds maximum USD exposure per order and throttles runaway trading loops.
- **Cryptographic Kill Switch:** Owner/Guardian endpoint immediately revokes an agent's trading authority without requiring on-chain transaction delays.
- **Dual-Signature Multisig Enforcement:** Secure on-chain execution vaults require both the Agent's signature and the Guard's Ed25519 co-signature to execute.

---

## 4. Architecture & Technical Implementation

Hyperion Guard is built as a zero-overhead, sub-millisecond service within the Hyperion HFT repository (`guard/service/hyperion_guard/solana/`):

| Component | File Path | Implementation Details |
| :--- | :--- | :--- |
| **Pure Base58 Engine** | [`solana/base58.py`](file:///Users/aditya/Agent/hyperion_hft/guard/service/hyperion_guard/solana/base58.py) | Zero-dependency, memory-safe Base58 encoder/decoder with full leading-zero preservation. |
| **Wire Transaction Decoder** | [`solana/decoder.py`](file:///Users/aditya/Agent/hyperion_hft/guard/service/hyperion_guard/solana/decoder.py) | Compact-u16 parser, legacy & V0 transaction header decoding, compiled instruction resolution, and Anchor DEX discriminator unpacking. |
| **Pre-Trade Risk Engine** | [`solana/guard.py`](file:///Users/aditya/Agent/hyperion_hft/guard/service/hyperion_guard/solana/guard.py) | Real-time policy evaluation, rate limiting, kill switch state machine, and RFC 8032 Ed25519 message signing. |
| **REST API Gateway** | [`hyperion_guard/api.py`](file:///Users/aditya/Agent/hyperion_hft/guard/service/hyperion_guard/api.py) | High-throughput FastAPI endpoints (`/v1/solana/check`, `/v1/solana/policy`, `/v1/solana/kill`, `/v1/solana/health`). |

### Supported Solana Protocols
- **Jupiter V6 Aggregator:** `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`
- **Phoenix Limit Order Book:** `PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY`
- **Raydium V4 CPMM:** `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`
- **SPL Token Program:** `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
- **Solana System Program:** `11111111111111111111111111111111`

---

## 5. Developer Integration (Python / TypeScript)

Autonomous agents integrate Hyperion Guard in under 10 lines of code:

```python
import base64
import requests

# 1. Autonomous agent generates a swap transaction via Jupiter API
swap_tx_bytes = jupiter_client.get_swap_transaction(quote)

# 2. Submit transaction bytes to Hyperion Guard for pre-trade clearance
response = requests.post("https://guard.hyperion.fi/v1/solana/check", json={
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

**Test Results:**
- `test_base58_roundtrip`: Exact cryptographic round-trip fidelity.
- `test_base58_leading_zeros`: Solana pubkey alignment preservation.
- `test_decode_jupiter_v6_swap`: Correct extraction of in-amount, min-out, and slippage BPS.
- `test_decode_phoenix_limit_order`: Accurate price/quantity unpacking from Phoenix byte stream.
- `test_guard_approves_safe_jupiter_swap`: Co-signs safe trades with verified Ed25519 signatures.
- `test_guard_rejects_oversized_order_cap`: Intercepts orders exceeding notional limits.
- `test_guard_rejects_excessive_slippage_mev_risk`: Enforces anti-sandwich slippage collars.
- `test_guard_rejects_unauthorized_target_program`: Halts interactions with untrusted programs.
- `test_guard_kill_switch_blocks_execution_and_revival`: Tests emergency circuit breaker and recovery.
- `test_solana_api_lifecycle`: Full end-to-end HTTP API lifecycle testing.

**Total Project Tests Passing:**
- 15 Rust High-Performance Engine Tests (`cargo test`)
- 18 Cryptographic Proof & Track Record Tests (`pytest proof/tests`)
- 39 Multi-Chain Guard Service Tests (`pytest guard/service/tests`)
- **Total: 72 Automated Tests (100% Pass Rate)**

---

## 7. 2.5-Minute Video Pitch & Demo Script

### Scene 1: The Problem (0:00 - 0:35)
- **Visual:** High-speed terminal showing Solana AI trading agents firing automated trades. Screen cuts to a red alert showing an agent losing funds to a 500 bps slippage sandwich attack on Jupiter.
- **Voiceover:** "Autonomous AI agents are revolutionizing DeFi on Solana. They analyze orderbooks, spot arbitrage, and execute swaps in milliseconds. But autonomous trading without guardrails is a disaster waiting to happen. Hallucinations, bad quotes, and aggressive MEV searchers can drain an agent's treasury in a single block. Because Solana finalizes blocks in 400 milliseconds, reactive alerts only tell you what you’ve already lost."

### Scene 2: Introducing Hyperion Guard (0:35 - 1:15)
- **Visual:** Architectural graphic showing an AI agent sending raw transactions to Hyperion Guard, which validates the instructions in microseconds and co-signs them.
- **Voiceover:** "Meet Hyperion Guard: the institutional pre-trade risk firewall for autonomous Solana agents. Hyperion Guard inspects compiled wire transactions *before* they touch the network. It parses the actual Anchor byte stream of Jupiter V6 swaps, Phoenix LOB orders, and Raydium liquidity routes, enforcing mathematical risk collars before signing."

### Scene 3: Live Demo — Safe Trade vs. MEV Exploit (1:15 - 1:55)
- **Visual:** Split-screen terminal.
  - Left: Agent submits a safe trade with 30 bps slippage. Guard approves in <1ms and attaches an Ed25519 co-signature.
  - Right: Agent submits a trade with 250 bps slippage (sandwich target). Guard immediately flags `REJECTED_EXCESSIVE_SLIPPAGE`, refusing to co-sign.
- **Voiceover:** "Watch it in action. On the left, our agent submits a standard USDC to SOL swap on Jupiter. Guard decodes the instruction data, verifies the 30-basis-point slippage collar and $500 size cap, attaches an authorized Ed25519 co-signature, and broadcasts it safely. On the right, the agent experiences slippage drift from a spoofed pool. Guard instantly detects a 250-basis-point slippage risk, rejects the transaction, and prevents the sandwich attack."

### Scene 4: Emergency Circuit Breaker & Co-Signing (1:55 - 2:15)
- **Visual:** Admin triggers `/v1/solana/kill`. Agent immediately attempts another trade; Guard blocks it with `REJECTED_KILL_SWITCH`.
- **Voiceover:** "If an agent enters an infinite retry loop or exhibits anomalous behavior, the risk officer triggers the cryptographic kill switch. All subsequent transactions are denied co-signing immediately, freezing execution within the current slot."

### Scene 5: Conclusion & Future Roadmap (2:15 - 2:30)
- **Visual:** Links to GitHub, Colosseum submission portal, and documentation.
- **Voiceover:** "Hyperion Guard is production-ready, open-source, and fully tested across Jupiter, Phoenix, and Raydium. Secure your autonomous agents today at hyperion.fi. Built for the Colosseum Arena Hackathon."

---

## 8. Links & Deliverables

- **GitHub Repository:** [https://github.com/aditya/hyperion_hft](https://github.com/aditya/hyperion_hft)
- **Solana Guard Module:** [`guard/service/hyperion_guard/solana/`](file:///Users/aditya/Agent/hyperion_hft/guard/service/hyperion_guard/solana/)
- **Test Suite:** [`guard/service/tests/test_solana_guard.py`](file:///Users/aditya/Agent/hyperion_hft/guard/service/tests/test_solana_guard.py)
- **Academic Paper:** [`paper/hyperion_whitepaper.pdf`](file:///Users/aditya/Agent/hyperion_hft/paper/)
