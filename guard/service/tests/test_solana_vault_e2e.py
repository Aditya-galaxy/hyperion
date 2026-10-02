"""
End to end: the Python vault client builds the transaction, the Guard checks
and co-signs it, and the compiled vault program (guard/contracts_solana, built
with `cargo build-sbf`) executes it in LiteSVM via solders. This is the test
that the three agree byte for byte.

Skipped unless solders is installed and the program has been built.
"""

from __future__ import annotations

from pathlib import Path

import pytest

litesvm = pytest.importorskip("solders.litesvm")
from Crypto.PublicKey import ECC
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58decode, b58encode
from hyperion_guard.solana.guard import (
    SolanaAgentPolicy,
    SolanaGuardEngine,
)
from hyperion_guard.solana.tx import (
    add_signature,
    compile_message,
    pubkey,
    serialize,
    sign,
)
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

SO = Path(__file__).resolve().parents[2] / "contracts_solana" / "target" / "deploy" / "hyperion_solana_vault.so"
if not SO.exists():
    pytest.skip(f"build the program first: cd guard/contracts_solana && cargo build-sbf ({SO} missing)",
                allow_module_level=True)

SOL = 1_000_000_000
PROGRAM = b58encode(bytes([42] * 32))


@pytest.fixture
def chain():
    svm = litesvm.LiteSVM()
    svm.add_program_from_file(Pubkey.from_string(PROGRAM), str(SO))
    keys = {n: ECC.generate(curve="ed25519") for n in ("owner", "agent", "guardian")}
    guard = SolanaGuardEngine()
    ids = {n: pubkey(k) for n, k in keys.items()}
    for who in (ids["owner"], ids["agent"]):
        svm.airdrop(Pubkey.from_string(who), 10 * SOL)
    vault, _ = v.vault_address(PROGRAM, ids["owner"], ids["agent"])
    v.register_vault_program(PROGRAM)
    guard.set_policy(SolanaAgentPolicy(agent_id="agent-1", owner_solana_pubkey=ids["owner"],
                                       max_order_notional_usd=500.0, allowed_programs=[PROGRAM],
                                       vault_address=vault))

    def send(ixs: list[v.Ix], payer: str, signers: list[str], extra_sigs: dict | None = None):
        svm.expire_blockhash()
        msg, order, n = compile_message(ixs, payer, str(svm.latest_blockhash()))
        sigs = {who: sign(msg, keys[name]) for name, who in ids.items() if who in signers}
        raw = serialize(msg, order, n, {**sigs, **(extra_sigs or {})})
        return raw, svm.send_transaction(VersionedTransaction.from_bytes(raw))

    # the owner creates the vault: guard key, $-cap enforced by the Guard, 3 SOL per tx on-chain
    _, res = send([v.initialize(PROGRAM, ids["owner"], ids["agent"], ids["guardian"], guard.pubkey_b58,
                                3 * SOL, [])], ids["owner"], [ids["owner"]])
    assert "Failed" not in type(res).__name__, res
    svm.airdrop(Pubkey.from_string(vault), 5 * SOL)
    return {"svm": svm, "send": send, "ids": ids, "keys": keys, "guard": guard, "vault": vault}


def ok(res) -> bool:
    return "Failed" not in type(res).__name__


def test_guard_co_signed_transfer_executes_on_chain(chain):
    to = b58encode(bytes(range(32)))
    ix = v.transfer_sol(PROGRAM, chain["vault"], chain["ids"]["agent"], chain["guard"].pubkey_b58, to, 2 * SOL)
    # the agent signs and leaves the Guard's slot empty
    svm, ids = chain["svm"], chain["ids"]
    svm.expire_blockhash()
    msg, order, n = compile_message([ix], ids["agent"], str(svm.latest_blockhash()))
    raw = serialize(msg, order, n, {})
    raw = add_signature(raw, ids["agent"], sign(msg, chain["keys"]["agent"]))
    verdict = chain["guard"].evaluate_transaction("agent-1", raw, sol_price_usd=150.0)   # $300 < $500
    assert verdict.approved, verdict.violation_details
    full = add_signature(raw, chain["guard"].pubkey_b58, b58decode(verdict.cosigner_signature_b58))
    res = svm.send_transaction(VersionedTransaction.from_bytes(full))
    assert ok(res), res
    assert svm.get_balance(Pubkey.from_string(to)) == 2 * SOL


def test_without_the_guard_the_program_refuses(chain):
    to = b58encode(bytes(range(1, 33)))
    base = v.transfer_sol(PROGRAM, chain["vault"], chain["ids"]["agent"], chain["guard"].pubkey_b58, to, SOL)
    # the agent drops the Guard's signer flag and sends it alone
    unsigned = v.Ix(base.program_id, [base.accounts[0], v.AccountMeta(chain["guard"].pubkey_b58, False, False),
                                      *base.accounts[2:]], base.data)
    _, res = chain["send"]([unsigned], chain["ids"]["agent"], [chain["ids"]["agent"]])
    assert not ok(res)
    assert "Custom(3)" in str(res)                               # VaultError::MissingGuardCoSignature
    assert not chain["svm"].get_balance(Pubkey.from_string(to))   # never created


def test_the_guard_refuses_what_the_policy_forbids_so_it_never_executes(chain):
    ix = v.transfer_sol(PROGRAM, chain["vault"], chain["ids"]["agent"], chain["guard"].pubkey_b58,
                        b58encode(bytes(range(2, 34))), 3 * SOL)   # $450 at $150 is fine...
    svm, ids = chain["svm"], chain["ids"]
    msg, order, n = compile_message([ix], ids["agent"], str(svm.latest_blockhash()))
    raw = serialize(msg, order, n, {ids["agent"]: sign(msg, chain["keys"]["agent"])})
    verdict = chain["guard"].evaluate_transaction("agent-1", raw, sol_price_usd=200.0)   # ...$600 at $200 is not
    assert (verdict.approved, verdict.status, verdict.cosigner_signature_b58) == (False, "REJECTED_ORDER_CAP", None)


def test_guardian_kill_stops_co_signed_transfers_on_chain(chain):
    ids = chain["ids"]
    _, res = chain["send"]([v.simple(PROGRAM, 3, ids["guardian"], chain["vault"])], ids["owner"],
                           [ids["owner"], ids["guardian"]])
    assert ok(res), res
    ix = v.transfer_sol(PROGRAM, chain["vault"], ids["agent"], chain["guard"].pubkey_b58,
                        b58encode(bytes(range(3, 35))), SOL)
    svm = chain["svm"]
    msg, order, n = compile_message([ix], ids["agent"], str(svm.latest_blockhash()))
    raw = serialize(msg, order, n, {ids["agent"]: sign(msg, chain["keys"]["agent"])})
    verdict = chain["guard"].evaluate_transaction("agent-1", raw, sol_price_usd=150.0)
    assert verdict.approved                       # the Guard's own kill switch wasn't touched...
    full = add_signature(raw, chain["guard"].pubkey_b58, b58decode(verdict.cosigner_signature_b58))
    res = svm.send_transaction(VersionedTransaction.from_bytes(full))
    assert not ok(res) and "Custom(4)" in str(res)   # ...but the vault was killed on-chain: VaultKilled
