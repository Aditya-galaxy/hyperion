"""
Tests for Jito MEV and Sandwich Attack simulation harness.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root and service dir to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[3]
SERVICE_DIR = PROJECT_ROOT / "guard" / "service"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from hyperion_guard.solana import SolanaAgentPolicy, SolanaGuardEngine
from jito_mev_harness import AMMPool, JitoSandwichSimulator, build_jupiter_swap_tx


def test_amm_pool_constant_product_invariant():
    pool = AMMPool("TestPool", reserve_sol=10_000.0, reserve_usdc=1_500_000.0, fee_bps=0)
    k_initial = pool.reserve_sol * pool.reserve_usdc

    # Swap 15,000 USDC -> SOL
    sol_out = pool.execute_swap(15_000.0, is_usdc_to_sol=True)
    assert sol_out > 0.0
    k_after = pool.reserve_sol * pool.reserve_usdc
    assert abs(k_initial - k_after) < 1e-4


def test_jito_sandwich_simulation_extracts_profit():
    pool = AMMPool("RaydiumTest", reserve_sol=50_000.0, reserve_usdc=7_500_000.0, fee_bps=25)
    jito = JitoSandwichSimulator(jito_tip_share=0.75)

    # 200 bps slippage on $25,000 swap should yield an active sandwich
    res = jito.simulate_sandwich(pool, 25_000.0, 200)
    assert res.is_profitable
    assert res.frontrun_in_usdc > 0.0
    assert res.searcher_gross_profit_usdc > 0.0
    assert res.jito_validator_tip_usdc > 0.0
    assert res.victim_loss_usdc > 100.0


def test_guard_intercepts_jito_vulnerable_transaction():
    engine = SolanaGuardEngine()
    policy = SolanaAgentPolicy(
        agent_id="test-agent",
        owner_solana_pubkey="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        max_order_notional_usd=50_000.0,
        max_slippage_bps=50,
    )
    engine.set_policy(policy)

    # Build tx with 200 bps slippage
    tx_bytes = build_jupiter_swap_tx(25_000_000_000, 160_000_000_000, 200, guard_pubkey_b58=engine.pubkey_b58)
    verdict = engine.evaluate_transaction("test-agent", tx_bytes)

    assert not verdict.approved
    assert verdict.status == "REJECTED_EXCESSIVE_SLIPPAGE"
    assert verdict.cosigner_signature_b58 is None

    # Safe tx with 30 bps slippage
    safe_tx_bytes = build_jupiter_swap_tx(25_000_000_000, 165_000_000_000, 30, guard_pubkey_b58=engine.pubkey_b58)
    safe_verdict = engine.evaluate_transaction("test-agent", safe_tx_bytes)

    assert safe_verdict.approved
    assert safe_verdict.status == "APPROVED"
    assert safe_verdict.cosigner_signature_b58 is not None
