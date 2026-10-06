"""
Who may ask the Guard about a transaction: only the agent, shown by its
signature on the transaction itself. And asking twice counts once.
"""

from __future__ import annotations

import os

import pytest
from Crypto.PublicKey import ECC
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58encode
from hyperion_guard.solana.control import policy_message
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.tx import compile_message, pubkey, serialize, sign

VAULT_PID = b58encode(bytes([7] * 32))
SOL = 1_000_000_000


@pytest.fixture
def world():
    v.register_vault_program(VAULT_PID)
    agent_key, stranger_key = ECC.generate(curve="ed25519"), ECC.generate(curve="ed25519")
    agent, owner = pubkey(agent_key), b58encode(os.urandom(32))
    vault, _ = v.vault_address(VAULT_PID, owner, agent)
    guard = SolanaGuardEngine()
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey=owner, agent_solana_pubkey=agent,
                                       max_order_notional_usd=100.0, daily_notional_cap_usd=250.0,
                                       max_orders_per_minute=3, allowed_programs=[VAULT_PID], vault_address=vault))

    def payment(lamports: int = SOL // 10, signed_by: ECC.EccKey | None = agent_key, fee_payer: str | None = None):
        """A vault payment of 0.1 SOL ($15), as the agent would build it."""
        ix = v.transfer_sol(VAULT_PID, vault, agent, guard.pubkey_b58, b58encode(os.urandom(32)), lamports)
        msg, keys, n = compile_message([ix], fee_payer or agent, b58encode(os.urandom(32)))
        sigs = {pubkey(signed_by): sign(msg, signed_by)} if signed_by else {}
        return serialize(msg, keys, n, sigs)

    def ask(raw: bytes):
        return guard.evaluate_transaction("a", raw, sol_price_usd=150.0)
    return {"guard": guard, "payment": payment, "ask": ask, "agent_key": agent_key, "stranger_key": stranger_key,
            "agent": agent}


def counted(w) -> tuple[int, int]:
    g = w["guard"]
    return len(g.order_timestamps.get("a", [])), len(g.daily_spend_tracker.get("a", []))


def test_the_agents_own_transaction_is_judged(world):
    verdict = world["ask"](world["payment"]())
    assert verdict.approved and counted(world) == (1, 1)


def test_an_unsigned_transaction_is_not_judged(world):
    verdict = world["ask"](world["payment"](signed_by=None))
    assert (verdict.approved, verdict.status, verdict.cosigner_signature_b58) == (False, "REJECTED_NOT_SIGNED_BY_AGENT", None)
    assert counted(world) == (0, 0)


def test_a_strangers_signature_in_the_agents_slot_is_not_the_agents(world):
    raw = world["payment"](signed_by=None)
    msg = raw[1 + 64 * 2:]                                                      # past the two signature slots
    forged = raw[:1] + sign(msg, world["stranger_key"]) + raw[1 + 64:]          # slot 0 is the agent's
    assert world["ask"](forged).status == "REJECTED_NOT_SIGNED_BY_AGENT"
    assert counted(world) == (0, 0)


def test_a_signature_over_a_different_message_is_not_a_signature(world):
    one, other = world["payment"](), world["payment"]()
    swapped = one[:1] + other[1:65] + one[65:]                                  # the agent's signature, on another message
    assert world["ask"](swapped).status == "REJECTED_NOT_SIGNED_BY_AGENT"


def test_a_stranger_cant_use_up_the_agents_throttle_or_cap(world):
    """Before: anyone who knew the agent's id could submit transactions that pass
    the policy until the throttle (3 a minute here) and the daily cap were spent."""
    stranger = pubkey(world["stranger_key"])
    for _ in range(10):
        # paid for and signed by the stranger; the agent is named but hasn't signed
        raw = world["payment"](signed_by=world["stranger_key"], fee_payer=stranger)
        assert world["ask"](raw).status == "REJECTED_NOT_SIGNED_BY_AGENT"
    assert counted(world) == (0, 0)
    assert world["ask"](world["payment"]()).approved                            # the agent isn't locked out


def test_asking_again_about_an_approved_transaction_counts_once(world):
    """A broadcast transaction is public. Resubmitting it must not spend the agent's limits."""
    raw = world["payment"]()
    first = world["ask"](raw)
    for _ in range(20):                                                         # well past the 3-a-minute throttle
        again = world["ask"](raw)
        assert (again.approved, again.cosigner_signature_b58) == (True, first.cosigner_signature_b58)
    assert counted(world) == (1, 1)

    assert world["ask"](world["payment"]()).approved                            # the agent's next two still fit
    assert world["ask"](world["payment"]()).approved
    assert world["ask"](world["payment"]()).status == "REJECTED_THROTTLE_LIMIT"


def test_a_refused_transaction_is_judged_afresh_each_time(world):
    big = world["payment"](lamports=SOL)                                        # $150 against a $100 cap
    assert world["ask"](big).status == "REJECTED_ORDER_CAP"
    world["guard"].get_policy("a").max_order_notional_usd = 200.0               # the owner raises the cap
    assert world["ask"](big).approved


def test_a_kill_beats_an_earlier_approval(world):
    raw = world["payment"]()
    assert world["ask"](raw).approved
    world["guard"].kill_agent("a")
    again = world["ask"](raw)
    assert (again.approved, again.status, again.cosigner_signature_b58) == (False, "REJECTED_KILL_SWITCH", None)


def test_the_agents_key_is_part_of_what_the_owner_signs():
    fields = {"agent_id": "a", "owner": "o", "guardian": "g", "max_order_notional_usd": 1.0, "max_slippage_bps": 1,
              "policy_version": 1, "nonce": 1, "require_guard_signer": True, "allowed_programs": None}
    assert policy_message(agent="key-1", **fields) != policy_message(agent="key-2", **fields)
    assert policy_message(agent="key-1", **fields).startswith(b"hyperion-guard/solana/policy/v3:")
