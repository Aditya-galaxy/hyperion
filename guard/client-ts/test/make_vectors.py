"""
Reference vectors for the TypeScript client, made with the Python client.

    guard/service/.venv/bin/python guard/client-ts/test/make_vectors.py

writes test/vectors.json. The TypeScript tests check src/index.ts against it,
and guard/service/tests/test_ts_client_vectors.py checks it is still what the
Python client produces, so the two can't drift apart unnoticed.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "service"))

from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58encode
from hyperion_guard.solana.control import action_message, policy_message
from hyperion_guard.solana.decoder import SPL_TOKEN_PROGRAM_ID

OUT = Path(__file__).with_name("vectors.json")


def key(n: int) -> str:
    return b58encode(bytes([n] * 32))


def ix(i: v.Ix) -> dict:
    return {"programId": i.program_id, "data": i.data.hex(),
            "keys": [{"pubkey": a.pubkey, "isSigner": a.is_signer, "isWritable": a.is_writable} for a in i.accounts]}


def vectors() -> dict:
    program, owner, agent, guardian, guard, to = (key(n) for n in (7, 1, 3, 4, 5, 6))
    programs = [key(9), SPL_TOKEN_PROGRAM_ID]
    vault, bump = v.vault_address(program, owner, agent)
    # a token transfer out of one of the vault's accounts: the vault is its signer
    inner = v.Ix(SPL_TOKEN_PROGRAM_ID, [v.AccountMeta(key(11), False, True), v.AccountMeta(key(12), False, True),
                                         v.AccountMeta(vault, True, False)], bytes([3]) + struct.pack("<Q", 2_500_000))
    policies = [
        {"agent_id": "agent-1", "agent": agent, "owner": owner, "guardian": "", "max_order_notional_usd": 5000.0,
         "max_slippage_bps": 100, "policy_version": 1, "nonce": 1, "require_guard_signer": True,
         "allowed_programs": None, "vault_address": ""},
        {"agent_id": "desk/agent 2", "agent": agent, "owner": owner, "guardian": guardian, "max_order_notional_usd": 3.96,
         "max_slippage_bps": 25, "policy_version": 1791356763, "nonce": 1791356763, "require_guard_signer": False,
         "allowed_programs": [SPL_TOKEN_PROGRAM_ID, program, key(9)], "vault_address": vault},
        {"agent_id": "agent-é-東", "agent": agent, "owner": owner, "guardian": guardian, "max_order_notional_usd": 1234.5,
         "max_slippage_bps": 0, "policy_version": 2, "nonce": 7, "require_guard_signer": True,
         "allowed_programs": [program], "vault_address": ""},
    ]
    return {
        "keys": {"program": program, "owner": owner, "agent": agent, "guardian": guardian, "guard": guard, "to": to,
                 "allowedPrograms": programs},
        "vault": {"address": vault, "bump": bump},
        "initialize": {"maxLamports": str(50_000_000), **ix(v.initialize(program, owner, agent, guardian, guard, 50_000_000, programs))},
        "transferSol": {"lamports": str(20_000_000), **ix(v.transfer_sol(program, vault, agent, guard, to, 20_000_000))},
        "transferSolMax": {"lamports": str(2**64 - 1), **ix(v.transfer_sol(program, vault, agent, guard, to, 2**64 - 1))},
        "execute": {"inner": ix(inner), **ix(v.execute(program, vault, agent, guard, inner))},
        "kill": ix(v.simple(program, 3, guardian, vault)),
        "revive": ix(v.simple(program, 4, owner, vault)),
        "withdraw": {"lamports": str(80_000_000), **ix(v.withdraw(program, owner, vault, to, 80_000_000))},
        "policyMessages": [{"policy": p, "hex": policy_message(**p).hex()} for p in policies],
        "actionMessages": [{"action": a, "agentId": i, "nonce": n, "hex": action_message(a, i, n).hex()}
                           for a, i, n in (("kill", "agent-1", 2), ("revive", "desk/agent 2", 1791356764))],
    }


if __name__ == "__main__":
    OUT.write_text(json.dumps(vectors(), indent=1) + "\n")
    print(f"wrote {OUT}")
