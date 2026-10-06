"""
Raydium AMM V4 swaps: decoded, sized and held to a limit, directly and inside
a vault Execute. The layouts are from raydium-amm's program/src/instruction.rs;
the instruction data here is built to that layout, not captured from mainnet.
"""

from __future__ import annotations

import os
import struct

import pytest
from Crypto.PublicKey import ECC
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58encode
from hyperion_guard.solana.decoder import (
    RAYDIUM_V4_PROGRAM_ID,
    decode_raydium_instruction,
    decode_solana_transaction,
)
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.tx import compile_message, pubkey, serialize, sign

VAULT_PID = b58encode(bytes([7] * 32))
U64_MAX = 2**64 - 1
USDC = 1_000_000


def swap(tag: int, first: int, second: int) -> bytes:
    return bytes([tag]) + struct.pack("<QQ", first, second)


@pytest.mark.parametrize(("tag", "name", "exact"), [(9, "swapBaseIn", "in"), (16, "swapBaseInV2", "in"),
                                                    (11, "swapBaseOut", "out"), (17, "swapBaseOutV2", "out")])
def test_the_four_swaps_decode(tag, name, exact):
    op, amount_in, amount_out, slippage, d = decode_raydium_instruction(swap(tag, 500 * USDC, 3 * 10**9), [])
    assert (op, amount_in, amount_out, slippage) == ("RAYDIUM_SWAP", 500 * USDC, 3 * 10**9, None)
    assert (d["instruction_name"], d["exact"], d["unbounded"]) == (name, exact, False)


def test_a_swap_with_no_limit_is_flagged():
    assert decode_raydium_instruction(swap(9, 500 * USDC, 0), [])[4]["unbounded"]          # minimum out of 0
    assert decode_raydium_instruction(swap(11, U64_MAX, 3 * 10**9), [])[4]["unbounded"]    # no maximum in
    assert not decode_raydium_instruction(swap(11, 500 * USDC, 0), [])[4]["unbounded"]     # base-out: the 0 is the output


@pytest.mark.parametrize("data", [b"", bytes([3]) + bytes(24), bytes([4]) + bytes(8), bytes([6, 0]), bytes([18]),
                                  swap(9, 1, 1)[:-1], swap(9, 1, 1) + b"\x00"])
def test_everything_else_is_unknown(data):
    """Deposit (3), withdraw (4), admin (6, 18), and swaps of the wrong length."""
    op, *_, d = decode_raydium_instruction(data, [])
    assert op == "UNKNOWN_RAYDIUM" and d["error"]


@pytest.fixture
def world():
    v.register_vault_program(VAULT_PID)
    agent_key = ECC.generate(curve="ed25519")
    guard = SolanaGuardEngine()
    agent, owner = pubkey(agent_key), b58encode(os.urandom(32))
    vault, _ = v.vault_address(VAULT_PID, owner, agent)
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey=owner, max_order_notional_usd=1_000.0,
                                       allowed_programs=[VAULT_PID, RAYDIUM_V4_PROGRAM_ID], vault_address=vault))

    def judge(data: bytes, through_vault: bool = False):
        # the Guard is a read-only signer of the Raydium call, as it would be of any co-signed transaction
        ix = v.Ix(RAYDIUM_V4_PROGRAM_ID, [v.AccountMeta(agent, True, True),
                                          v.AccountMeta(guard.pubkey_b58, True, False)], data)
        if through_vault:
            inner = v.Ix(RAYDIUM_V4_PROGRAM_ID, [v.AccountMeta(vault, True, True)], data)
            ix = v.execute(VAULT_PID, vault, agent, guard.pubkey_b58, inner)
        msg, keys, n = compile_message([ix], agent, b58encode(os.urandom(32)))
        raw = serialize(msg, keys, n, {agent: sign(msg, agent_key)})
        return guard.evaluate_transaction("a", raw), decode_solana_transaction(raw).instructions[0]
    return judge


@pytest.mark.parametrize("through_vault", [False, True])
def test_the_guard_sizes_and_limits_raydium_swaps(world, through_vault):
    ok, ix = world(swap(9, 500 * USDC, 3 * 10**9), through_vault)
    assert ok.approved, ok.violation_details
    assert (ix.details.get("inner_operation") or ix.operation) == "RAYDIUM_SWAP"

    too_big, _ = world(swap(9, 1_500 * USDC, 9 * 10**9), through_vault)
    assert (too_big.approved, too_big.status) == (False, "REJECTED_ORDER_CAP")

    no_floor, _ = world(swap(16, 500 * USDC, 0), through_vault)
    assert (no_floor.approved, no_floor.status) == (False, "REJECTED_EXCESSIVE_SLIPPAGE")

    no_ceiling, _ = world(swap(17, U64_MAX, 3 * 10**9), through_vault)
    assert not no_ceiling.approved and no_ceiling.cosigner_signature_b58 is None

    withdraw, _ = world(bytes([4]) + struct.pack("<Q", 10**9), through_vault)
    assert (withdraw.approved, withdraw.status) == (False, "REJECTED_MALFORMED_INSTRUCTION")
