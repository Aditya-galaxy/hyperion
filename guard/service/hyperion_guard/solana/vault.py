"""
HYPERION SOLANA GUARD: THE GUARDED VAULT PROGRAM, FROM PYTHON
=============================================================
Builds and decodes instructions for the vault program in
guard/contracts_solana (see its README), byte for byte the same encoding.

The Guard decodes vault instructions so it can check what the agent is
actually doing:

  * TransferSol: a SOL amount, checked against the policy like a SOL transfer;
  * Execute: unwrapped into the inner call (a Jupiter swap, a token transfer)
    and checked as if it were sent directly; the inner program must be
    allowed too;
  * anything else (Initialize, Kill, Revive, SetPolicy, Withdraw,
    OwnerExecute) is the owner's or guardian's business, and the Guard refuses
    to co-sign it for an agent.

The vault program's id is set when it's deployed, so it's registered at
runtime (`register_vault_program`) or through HYPERION_VAULT_PROGRAM_ID.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Any

from Crypto.Signature import eddsa

from .base58 import b58decode, b58encode

SEED = b"hyperion-vault"
TAGS = {0: "INITIALIZE", 1: "TRANSFER_SOL", 2: "EXECUTE", 3: "KILL", 4: "REVIVE", 5: "SET_POLICY",
        6: "WITHDRAW", 7: "OWNER_EXECUTE"}
AGENT_TAGS = {1, 2}                      # the only instructions the Guard will co-sign
SYSTEM_PROGRAM = "11111111111111111111111111111111"

VAULT_PROGRAM_IDS: set[str] = {p for p in os.environ.get("HYPERION_VAULT_PROGRAM_ID", "").split(",") if p}


def register_vault_program(program_id: str) -> None:
    VAULT_PROGRAM_IDS.add(program_id)


# ── addresses ────────────────────────────────────────────────────────────────

def _on_curve(b: bytes) -> bool:
    try:
        eddsa.import_public_key(b)
        return True
    except ValueError:
        return False


def find_program_address(seeds: list[bytes], program_id: str) -> tuple[str, int]:
    """Solana's find_program_address: the first bump, from 255 down, whose
    hash is not a valid Ed25519 point."""
    prog = b58decode(program_id)
    for bump in range(255, -1, -1):
        h = hashlib.sha256(b"".join(seeds) + bytes([bump]) + prog + b"ProgramDerivedAddress").digest()
        if not _on_curve(h):
            return b58encode(h), bump
    raise ValueError("no viable bump")


def vault_address(program_id: str, owner: str, agent: str) -> tuple[str, int]:
    return find_program_address([SEED, b58decode(owner), b58decode(agent)], program_id)


# ── building instructions ────────────────────────────────────────────────────

@dataclass(frozen=True)
class AccountMeta:
    pubkey: str
    is_signer: bool
    is_writable: bool


@dataclass(frozen=True)
class Ix:
    program_id: str
    accounts: list[AccountMeta]
    data: bytes


def _policy_bytes(guardian: str, guard: str, max_lamports: int, programs: list[str]) -> bytes:
    if len(programs) > 8:
        raise ValueError("at most 8 allowed programs")
    return (b58decode(guardian) + b58decode(guard) + struct.pack("<Q", max_lamports) + bytes([len(programs)])
            + b"".join(b58decode(p) for p in programs))


def initialize(program_id: str, owner: str, agent: str, guardian: str, guard: str, max_lamports: int,
               programs: list[str]) -> Ix:
    vault, _ = vault_address(program_id, owner, agent)
    data = bytes([0]) + b58decode(guardian) + b58decode(agent) + _policy_bytes(guardian, guard, max_lamports, programs)[32:]
    return Ix(program_id, [AccountMeta(owner, True, True), AccountMeta(vault, False, True),
                           AccountMeta(SYSTEM_PROGRAM, False, False)], data)


def transfer_sol(program_id: str, vault: str, agent: str, guard: str, to: str, lamports: int) -> Ix:
    return Ix(program_id, [AccountMeta(agent, True, False), AccountMeta(guard, True, False),
                           AccountMeta(vault, False, True), AccountMeta(to, False, True)],
              bytes([1]) + struct.pack("<Q", lamports))


def execute(program_id: str, vault: str, agent: str, guard: str, inner: Ix) -> Ix:
    """Wrap `inner` so the vault makes the call, signing as itself."""
    metas = [AccountMeta(agent, True, False), AccountMeta(guard, True, False), AccountMeta(vault, False, True),
             AccountMeta(inner.program_id, False, False)]
    metas += [AccountMeta(a.pubkey, a.is_signer and a.pubkey != vault, a.is_writable) for a in inner.accounts]
    return Ix(program_id, metas, bytes([2]) + inner.data)


def simple(program_id: str, tag: int, caller: str, vault: str) -> Ix:
    """Kill (3) or Revive (4)."""
    return Ix(program_id, [AccountMeta(caller, True, False), AccountMeta(vault, False, True)], bytes([tag]))


# ── decoding, for the Guard ──────────────────────────────────────────────────

def decode_vault_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None,
                                                                         int | None, dict[str, Any]]:
    """(operation, input amount, min out, slippage bps, details), in the shape the
    other decoders return. Execute carries the inner call's decoded fields."""
    if not data or data[0] not in TAGS:
        return "UNKNOWN_VAULT", None, None, None, {"error": "unrecognized vault instruction"}
    tag, name = data[0], TAGS[data[0]]
    vault = accounts[2] if tag in AGENT_TAGS and len(accounts) > 2 else None
    if tag not in AGENT_TAGS:
        return f"VAULT_ADMIN_{name}", None, None, None, {"vault_instruction": name}
    if tag == 1:
        if len(data) != 9 or len(accounts) < 4:
            return "UNKNOWN_VAULT", None, None, None, {"error": "malformed TransferSol"}
        lamports = struct.unpack_from("<Q", data, 1)[0]
        return "VAULT_TRANSFER_SOL", lamports, None, None, {"vault": vault, "to": accounts[3], "lamports": lamports}
    # Execute: accounts are agent, guard, vault, inner program, then the inner call's accounts
    if len(accounts) < 4:
        return "UNKNOWN_VAULT", None, None, None, {"error": "malformed Execute"}
    from .decoder import (
        decode_instruction_for_program,  # here, to avoid an import cycle
    )
    inner_program, inner_accounts, inner_data = accounts[3], accounts[4:], data[1:]
    op, amount, min_out, slip, det = decode_instruction_for_program(inner_program, inner_data, inner_accounts)
    details = {"vault": vault, "inner_program": inner_program, "inner_operation": op, "inner": det}
    if det.get("error") or op.startswith("UNKNOWN_"):
        details["error"] = f"inner call could not be decoded: {det.get('error') or op}"
    return "VAULT_EXECUTE", amount, min_out, slip, details
