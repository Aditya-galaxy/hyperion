"""
HYPERION GUARD ON SOLANA: THE LIVE DEMO
=======================================
An agent with a Guarded Vault on Solana devnet. Every transaction below is
real and comes with an explorer link. Six scenes:

  1. the owner opens a vault for the agent and funds it
  2. a normal payment: the Guard checks it and co-signs, the vault pays
  3. the agent tries to go around the Guard: the program refuses on-chain
  4. an order over the policy's dollar cap: the Guard won't sign, so there is
     nothing to send
  5. the guardian kills the vault on-chain: even a transfer the Guard approved
     a moment before is refused
  6. the owner takes the money back out of the killed vault

The vault program must be deployed first (guard/contracts_solana/README.md).
The owner is the Solana CLI wallet and pays for everything, about 0.01 SOL a
run; the agent, guardian and Guard keys are made fresh each run, so each run
opens a new vault.

    python guard/demo/solana_devnet.py

    [SOLANA_RPC_URL=https://api.devnet.solana.com]
    [SOLANA_KEYPAIR=~/.config/solana/id.json]
    [HYPERION_VAULT_PROGRAM_ID=9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq]
"""

from __future__ import annotations

import base64
import json
import os
import struct
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service"))

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58decode
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.tx import add_signature, compile_message, pubkey, serialize, sign

RPC = os.environ.get("SOLANA_RPC_URL", "https://api.devnet.solana.com")
PROGRAM = os.environ.get("HYPERION_VAULT_PROGRAM_ID", "9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq")
KEYPAIR = Path(os.environ.get("SOLANA_KEYPAIR", "~/.config/solana/id.json")).expanduser()
CLUSTER = "devnet" if "devnet" in RPC else "custom"
SOL = 1_000_000_000
SOL_PRICE_USD = 150.0                      # fixed for the demo, so the dollar figures are repeatable
VAULT_ERRORS = {3: "MissingGuardCoSignature", 4: "VaultKilled", 5: "OverCap", 6: "ProgramNotAllowed"}


def rpc(method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def blockhash() -> str:
    return rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"]


def balance(who: str) -> int:
    return rpc("getBalance", [who, {"commitment": "confirmed"}])["value"]


def send(raw: bytes) -> tuple[str, object]:
    """Send without preflight, so a refused transaction is recorded on-chain
    too, and wait for it. Returns (signature, error or None)."""
    sig = rpc("sendTransaction", [base64.b64encode(raw).decode(),
                                  {"encoding": "base64", "skipPreflight": True, "maxRetries": 5}])
    for _ in range(60):
        st = rpc("getSignatureStatuses", [[sig]])["value"][0]
        if st and st.get("confirmationStatus") in ("confirmed", "finalized"):
            return sig, st.get("err")
        time.sleep(1)
    raise TimeoutError(f"{sig} wasn't confirmed in 60 s")


def link(sig: str) -> str:
    return f"https://explorer.solana.com/tx/{sig}?cluster={CLUSTER}"


def custom_error(err) -> str:
    try:
        code = err["InstructionError"][1]["Custom"]
        return f"Custom({code}) {VAULT_ERRORS.get(code, '')}".strip()
    except (KeyError, TypeError, IndexError):
        return json.dumps(err)


def system_transfer(frm: str, to: str, lamports: int) -> v.Ix:
    return v.Ix(v.SYSTEM_PROGRAM, [v.AccountMeta(frm, True, True), v.AccountMeta(to, False, True)],
                struct.pack("<IQ", 2, lamports))


def withdraw(owner: str, vault: str, to: str, lamports: int) -> v.Ix:
    return v.Ix(PROGRAM, [v.AccountMeta(owner, True, False), v.AccountMeta(vault, False, True),
                          v.AccountMeta(to, False, True)], bytes([6]) + struct.pack("<Q", lamports))


def scene(n: int, title: str) -> None:
    print(f"\n── {n}. {title} " + "─" * max(0, 66 - len(title)))


def main() -> None:
    owner_key = eddsa.import_private_key(bytes(json.loads(KEYPAIR.read_text())[:32]))
    keys = {"owner": owner_key, "agent": ECC.generate(curve="ed25519"), "guardian": ECC.generate(curve="ed25519")}
    ids = {name: pubkey(k) for name, k in keys.items()}
    guard = SolanaGuardEngine()
    v.register_vault_program(PROGRAM)
    vault, _ = v.vault_address(PROGRAM, ids["owner"], ids["agent"])
    merchant = pubkey(ECC.generate(curve="ed25519"))

    def owner_tx(ixs: list[v.Ix], also: tuple[str, ...] = ()) -> tuple[str, object]:
        msg, order, n = compile_message(ixs, ids["owner"], blockhash())
        return send(serialize(msg, order, n, {ids[s]: sign(msg, keys[s]) for s in ("owner", *also)}))

    def agent_tx(ix: v.Ix) -> bytes:
        """Signed by the agent, the Guard's slot (if any) left empty."""
        msg, order, n = compile_message([ix], ids["agent"], blockhash())
        return serialize(msg, order, n, {ids["agent"]: sign(msg, keys["agent"])})

    def pay(lamports: int) -> v.Ix:
        return v.transfer_sol(PROGRAM, vault, ids["agent"], guard.pubkey_b58, merchant, lamports)

    print(f"program   {PROGRAM}\nowner     {ids['owner']}\nagent     {ids['agent']}\nguardian  {ids['guardian']}"
          f"\nGuard     {guard.pubkey_b58}\nvault     {vault}\nmerchant  {merchant}")

    scene(1, "The owner opens a vault for the agent and funds it")
    sig, err = owner_tx([
        v.initialize(PROGRAM, ids["owner"], ids["agent"], ids["guardian"], guard.pubkey_b58, SOL // 20, []),
        system_transfer(ids["owner"], vault, SOL // 10),            # the agent's working money
        system_transfer(ids["owner"], ids["agent"], SOL // 100),    # the agent's own fees
    ])
    assert err is None, err
    guard.set_policy(SolanaAgentPolicy(agent_id="agent-1", owner_solana_pubkey=ids["owner"],
                                       max_order_notional_usd=5.0, allowed_programs=[PROGRAM], vault_address=vault))
    print(f"   vault holds {balance(vault) / SOL:.4f} SOL; on-chain cap 0.05 SOL a transaction; "
          f"Guard policy $5 an order\n   {link(sig)}")

    scene(2, "A normal payment: the Guard co-signs, the vault pays")
    raw = agent_tx(pay(SOL // 50))                                  # 0.02 SOL = $3
    verdict = guard.evaluate_transaction("agent-1", raw, sol_price_usd=SOL_PRICE_USD)
    assert verdict.approved, verdict.violation_details
    sig, err = send(add_signature(raw, guard.pubkey_b58, b58decode(verdict.cosigner_signature_b58)))
    assert err is None, err
    print(f"   Guard: {verdict.status} ($3.00 of a $5 cap)\n   merchant received {balance(merchant) / SOL:.4f} SOL"
          f"\n   {link(sig)}")

    scene(3, "The agent goes around the Guard: the program refuses on-chain")
    ix = pay(SOL // 50)
    solo = v.Ix(ix.program_id, [ix.accounts[0], v.AccountMeta(guard.pubkey_b58, False, False), *ix.accounts[2:]],
                ix.data)                                            # the Guard is named but hasn't signed
    sig, err = send(agent_tx(solo))
    assert err is not None, "the program accepted a transfer without the Guard"
    print(f"   failed on-chain: {custom_error(err)}\n   merchant still has {balance(merchant) / SOL:.4f} SOL"
          f"\n   {link(sig)}")

    scene(4, "An order over the dollar cap: the Guard won't sign")
    raw = agent_tx(pay(SOL // 25))                                  # 0.04 SOL = $6, under the on-chain cap
    verdict = guard.evaluate_transaction("agent-1", raw, sol_price_usd=SOL_PRICE_USD)
    assert not verdict.approved and verdict.cosigner_signature_b58 is None
    print(f"   Guard: {verdict.status}\n   {verdict.violation_details}\n   no signature, so nothing to send")

    scene(5, "The guardian kills the vault: an approved transfer is refused")
    raw = agent_tx(pay(SOL // 100))                                 # approved before the kill
    verdict = guard.evaluate_transaction("agent-1", raw, sol_price_usd=SOL_PRICE_USD)
    assert verdict.approved, verdict.violation_details
    approved = add_signature(raw, guard.pubkey_b58, b58decode(verdict.cosigner_signature_b58))
    kill_sig, err = owner_tx([v.simple(PROGRAM, 3, ids["guardian"], vault)], also=("guardian",))
    assert err is None, err
    print(f"   guardian killed the vault\n   {link(kill_sig)}")
    sig, err = send(approved)
    assert err is not None, "a killed vault paid out"
    print(f"   the transfer the Guard approved before the kill: {custom_error(err)}\n   {link(sig)}")

    scene(6, "The owner takes the money back out of the killed vault")
    rent = rpc("getMinimumBalanceForRentExemption", [rpc("getAccountInfo", [vault, {"encoding": "base64"}])
                                                     ["value"]["space"]])
    spare = balance(vault) - rent
    sig, err = owner_tx([withdraw(ids["owner"], vault, ids["owner"], spare)])
    assert err is None, err
    print(f"   withdrew {spare / SOL:.4f} SOL to the owner; the agent could not have\n   {link(sig)}")

    print(f"\nvault: https://explorer.solana.com/address/{vault}?cluster={CLUSTER}")


if __name__ == "__main__":
    main()
