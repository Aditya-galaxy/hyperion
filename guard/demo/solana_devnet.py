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

By default the Guard runs inside this script, with a fixed SOL price so the
dollar figures repeat. To use a hosted Guard instead (deploy_guard.sh), over
its HTTP API and at its live SOL price:

    HYPERION_GUARD_URL=https://<your-guard> python guard/demo/solana_devnet.py

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
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service"))

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58decode, b58encode
from hyperion_guard.solana.control import policy_message
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.prices import JupiterTokenPrices
from hyperion_guard.solana.tx import add_signature, compile_message, pubkey, serialize, sign

RPC = os.environ.get("SOLANA_RPC_URL", "https://api.devnet.solana.com")
PROGRAM = os.environ.get("HYPERION_VAULT_PROGRAM_ID", "9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq")
KEYPAIR = Path(os.environ.get("SOLANA_KEYPAIR", "~/.config/solana/id.json")).expanduser()
CLUSTER = "devnet" if "devnet" in RPC else "custom"
SOL = 1_000_000_000
GUARD_URL = os.environ.get("HYPERION_GUARD_URL", "").rstrip("/")
SOL_PRICE_USD = 150.0                      # the local Guard's, fixed so the dollar figures are repeatable
WSOL_MINT = "So11111111111111111111111111111111111111112"
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


class LocalGuard:
    """The Guard, running inside this script."""
    where = "in this script"

    def __init__(self) -> None:
        self.engine = SolanaGuardEngine()
        self.pubkey_b58, self.sol_price = self.engine.pubkey_b58, SOL_PRICE_USD

    def set_policy(self, owner_key, owner: str, agent: str, vault: str, cap_usd: float) -> None:
        self.engine.set_policy(SolanaAgentPolicy(agent_id="agent-1", owner_solana_pubkey=owner,
                                                 agent_solana_pubkey=agent, max_order_notional_usd=cap_usd,
                                                 allowed_programs=[PROGRAM], vault_address=vault))

    def check(self, raw: bytes) -> dict:
        verdict = self.engine.evaluate_transaction("agent-1", raw, sol_price_usd=SOL_PRICE_USD)
        return {"approved": verdict.approved, "status": verdict.status, "violation_details": verdict.violation_details,
                "cosigner_signature_b58": verdict.cosigner_signature_b58}


class HostedGuard:
    """A Guard somewhere else, over its HTTP API. The owner signs the policy;
    the Guard prices SOL itself."""

    def __init__(self, url: str) -> None:
        self.url, self.where = url, url
        self.pubkey_b58 = self.call("GET", "/v1/solana/health")["cosigner_pubkey"]
        sol = JupiterTokenPrices().price(WSOL_MINT)          # the same source the hosted Guard uses
        assert sol, "no SOL price available"
        self.sol_price = sol.usd

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(self.url + path, json.dumps(body).encode() if body is not None else None,
                                     {"Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"{method} {path}: {e.code} {e.read().decode()[:300]}") from None

    def set_policy(self, owner_key, owner: str, agent: str, vault: str, cap_usd: float) -> None:
        # one agent id per owner, updated each run: version and nonce only need to go up
        self.agent_id, now = f"devnet-demo-{owner[:8]}", int(time.time())
        fields = {"agent_id": self.agent_id, "max_order_notional_usd": cap_usd, "max_slippage_bps": 100,
                  "policy_version": now, "nonce": now, "require_guard_signer": True, "allowed_programs": [PROGRAM],
                  "vault_address": vault}
        signature = sign(policy_message(agent=agent, owner=owner, guardian="", **fields), owner_key)
        self.call("POST", "/v1/solana/policy", {**fields, "agent_solana_pubkey": agent, "owner_solana_pubkey": owner,
                                                "signature_b58": b58encode(signature)})

    def check(self, raw: bytes) -> dict:
        return self.call("POST", "/v1/solana/check", {"agent_id": self.agent_id, "encoding": "base64",
                                                      "tx_bytes": base64.b64encode(raw).decode()})


def scene(n: int, title: str) -> None:
    print(f"\n── {n}. {title} " + "─" * max(0, 66 - len(title)))


def main() -> None:
    owner_key = eddsa.import_private_key(bytes(json.loads(KEYPAIR.read_text())[:32]))
    keys = {"owner": owner_key, "agent": ECC.generate(curve="ed25519"), "guardian": ECC.generate(curve="ed25519")}
    ids = {name: pubkey(k) for name, k in keys.items()}
    v.register_vault_program(PROGRAM)
    guard = HostedGuard(GUARD_URL) if GUARD_URL else LocalGuard()
    # The policy's dollar cap is worth 0.0333 SOL at the Guard's SOL price, so a 0.02 SOL
    # payment fits and a 0.04 SOL one doesn't, whatever SOL is worth today.
    cap_usd = round(guard.sol_price / 30, 2)

    def usd(lamports: int) -> str:
        return f"${lamports / SOL * guard.sol_price:.2f}"
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
          f"\nGuard     {guard.pubkey_b58}  ({guard.where})\nvault     {vault}\nmerchant  {merchant}"
          f"\nSOL       ${guard.sol_price:.2f}")

    scene(1, "The owner opens a vault for the agent and funds it")
    sig, err = owner_tx([
        v.initialize(PROGRAM, ids["owner"], ids["agent"], ids["guardian"], guard.pubkey_b58, SOL // 20, []),
        system_transfer(ids["owner"], vault, SOL // 10),            # the agent's working money
        system_transfer(ids["owner"], ids["agent"], SOL // 100),    # the agent's own fees
    ])
    assert err is None, err
    guard.set_policy(keys["owner"], ids["owner"], ids["agent"], vault, cap_usd)
    print(f"   vault holds {balance(vault) / SOL:.4f} SOL; on-chain cap 0.05 SOL a transaction; "
          f"Guard policy ${cap_usd:.2f} an order\n   {link(sig)}")

    scene(2, "A normal payment: the Guard co-signs, the vault pays")
    raw = agent_tx(pay(SOL // 50))                                  # 0.02 SOL
    verdict = guard.check(raw)
    assert verdict["approved"], verdict["violation_details"]
    sig, err = send(add_signature(raw, guard.pubkey_b58, b58decode(verdict["cosigner_signature_b58"])))
    assert err is None, err
    print(f"   Guard: {verdict['status']} ({usd(SOL // 50)} of a ${cap_usd:.2f} cap)\n   merchant received {balance(merchant) / SOL:.4f} SOL"
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
    raw = agent_tx(pay(SOL // 25))                                  # 0.04 SOL: under the on-chain cap, over the policy's
    verdict = guard.check(raw)
    assert not verdict["approved"] and verdict["cosigner_signature_b58"] is None
    print(f"   Guard: {verdict['status']}\n   {verdict['violation_details']}\n   no signature, so nothing to send")

    scene(5, "The guardian kills the vault: an approved transfer is refused")
    raw = agent_tx(pay(SOL // 100))                                 # approved before the kill
    verdict = guard.check(raw)
    assert verdict["approved"], verdict["violation_details"]
    approved = add_signature(raw, guard.pubkey_b58, b58decode(verdict["cosigner_signature_b58"]))
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
    sig, err = owner_tx([v.withdraw(PROGRAM, ids["owner"], vault, ids["owner"], spare)])
    assert err is None, err
    print(f"   withdrew {spare / SOL:.4f} SOL to the owner; the agent could not have\n   {link(sig)}")

    print(f"\nvault: https://explorer.solana.com/address/{vault}?cluster={CLUSTER}")


if __name__ == "__main__":
    main()
