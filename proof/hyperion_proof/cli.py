"""
HYPERION PROOF: VERIFIED TRACK RECORDS FOR TRADING AGENTS
=========================================================
    hyperion-proof request --agent-id 12 --chain 5042 --window month > req.json
        signed by the trading account (key in PROOF_ACCOUNT_KEY)
    hyperion-proof attest req.json [--post]
        run by the validator (key in PROOF_VALIDATOR_KEY, RPC in PROOF_RPC_URL):
        checks the request, fetches the account's public Hyperliquid history,
        computes the metrics, writes the evidence file, and with --post records
        it in the ERC-8004 Reputation Registry on Arc
    hyperion-proof verify evidence.json|<data: or https URI> [--chain 5042 --agent-id 12 --validator 0x…]
        anyone: recompute the metrics, check the hash and the request's
        signature, and with --chain check the on-chain record commits to it

Keys come from the environment only, never from flags.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

import httpx
from eth_account import Account

from . import erc8004, evidence, hyperliquid
from .request import Request, check, sign

RPC_DEFAULTS = {5042: "https://rpc.mainnet.arc.io", 5042002: "https://rpc.testnet.arc.network"}


def _env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"  set {name}")
    return v


def _registry_id(chain: int) -> str:
    return f"eip155:{chain}:{erc8004.REGISTRIES[chain]['identity']}"


def cmd_request(args) -> int:
    key = _env("PROOF_ACCOUNT_KEY")
    r = Request(agentRegistry=_registry_id(args.chain), agentId=args.agent_id, venue="hyperliquid",
                account=Account.from_key(key).address, window=args.window, issuedAt=int(time.time()))
    json.dump({**r.message(), "signature": sign(r, key)}, sys.stdout, indent=1)
    print()
    return 0


def _load_request(path: str) -> tuple[Request, str]:
    d = json.loads(Path(path).read_text())
    sig = d.pop("signature")
    return Request(**d), sig


def data_uri(doc: dict) -> str:
    return "data:application/json;base64," + base64.b64encode(evidence.canonical(doc)).decode()


def load_evidence(src: str) -> dict:
    if src.startswith("data:application/json;base64,"):
        return json.loads(base64.b64decode(src.split(",", 1)[1]))
    if src.startswith("https://"):
        r = httpx.get(src, timeout=20)
        r.raise_for_status()
        return r.json()
    return json.loads(Path(src).read_text())


def cmd_attest(args) -> int:
    req, sig = _load_request(args.request)
    problem = check(req, sig, int(time.time()))
    if problem:
        sys.exit(f"  refused: {problem}")
    chain = int(req.agentRegistry.split(":")[1])
    if chain not in erc8004.REGISTRIES or req.agentRegistry != _registry_id(chain):
        sys.exit(f"  refused: unknown agent registry {req.agentRegistry}")
    key = _env("PROOF_VALIDATOR_KEY")
    validator = Account.from_key(key).address
    rpc = erc8004.Rpc(os.environ.get("PROOF_RPC_URL", RPC_DEFAULTS[chain]), chain)
    if rpc.is_owner_or_operator(erc8004.REGISTRIES[chain]["identity"], validator, req.agentId):
        sys.exit("  refused: the validator controls this agent; ERC-8004 forbids self-feedback")

    fixture = os.environ.get("PROOF_PORTFOLIO_FIXTURE")          # tests and demos only
    if fixture:
        data, retrieved = dict(json.loads(Path(fixture).read_text())), "fixture"
        print(f"  using recorded portfolio {fixture}, not live Hyperliquid data")
    else:
        data, retrieved = hyperliquid.portfolio(req.account)
    if req.window not in data:
        sys.exit(f"  no {req.window} window in the account's history")
    doc = evidence.build(req, sig, data[req.window], f"{hyperliquid.INFO_URL} portfolio", retrieved, validator)
    h = evidence.digest(doc)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{h}.json").write_bytes(evidence.canonical(doc))
    uri = f"{args.uri_base.rstrip('/')}/{h}.json" if args.uri_base else data_uri(doc)
    m = doc["metrics"]
    print(f"  {req.account} on hyperliquid, {req.window}: TWR {float(m['timeWeightedReturn']) * 100:+.2f}%, "
          f"max drawdown {float(m['maxDrawdown']) * 100:.2f}%, {m['intervals']} intervals")
    print(f"  evidence {out / (h + '.json')}  hash {h}")
    if not args.post:
        print("  not posted (add --post to record it on Arc)")
        return 0
    reputation = erc8004.REGISTRIES[chain]["reputation"]
    txs = []
    for tag1, tag2, value in erc8004.feedback_entries(doc):
        tx = rpc.transact(key, reputation, erc8004.give_feedback_calldata(req.agentId, value, tag1, tag2, uri, h))
        txs.append(tx)
        print(f"  posted {tag1} {tag2} = {value / 10**erc8004.DECIMALS:+.4f}%  tx {tx}")
    # The evidence hash is committed before posting, so the transactions live beside it.
    (out / f"{h}.receipt.json").write_text(json.dumps({"chain": chain, "agentId": req.agentId,
                                                       "reputation": reputation, "txs": txs}, indent=1))
    print(f"  verify: hyperion-proof verify {out / (h + '.json')} --chain {chain} --tx {' '.join(txs)}")
    return 0


def cmd_verify(args) -> int:
    doc = load_evidence(args.evidence)
    ok = True

    def line(passed: bool, text: str):
        nonlocal ok
        ok &= passed
        print(f"  {'✓' if passed else '✗'} {text}")

    h = evidence.digest(doc)
    line(evidence.recompute(doc) == doc["metrics"], "metrics recompute exactly from the file's own inputs")
    rq = dict(doc["request"])
    sig = rq.pop("signature")
    req = Request(**rq)
    line(check(req, sig, req.issuedAt) is None, f"request is signed by the scored account {req.account}")
    print(f"  evidence hash {h}")
    if args.chain:
        rpc = erc8004.Rpc(os.environ.get("PROOF_RPC_URL", RPC_DEFAULTS[args.chain]), args.chain)
        reputation = erc8004.REGISTRIES[args.chain]["reputation"]
        client = (args.validator or doc["validator"]).lower()
        found = ([e for tx in args.tx for e in rpc.feedback_in_tx(reputation, tx)] if args.tx
                 else rpc.feedback(reputation, req.agentId, client))
        entries = [e for e in found if e["feedbackHash"] == h and e["agentId"] == req.agentId
                   and e["client"].lower() == client]
        want = {(t1, t2, v) for t1, t2, v in erc8004.feedback_entries(doc)}
        got = {(e["tag1"], e["tag2"], e["value"]) for e in entries}
        line(bool(entries) and want <= got,
             f"on-chain feedback commits to this file ({len(entries)} entries on chain {args.chain})")
    print("  VERIFIED" if ok else "  NOT VERIFIED")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hyperion-proof", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("request", help="sign a track-record request with the trading account's key")
    r.add_argument("--agent-id", type=int, required=True)
    r.add_argument("--chain", type=int, choices=sorted(erc8004.REGISTRIES), default=5042002)
    r.add_argument("--window", default="month")
    r.set_defaults(run=cmd_request)
    a = sub.add_parser("attest", help="validator: compute, write evidence, optionally post to ERC-8004")
    a.add_argument("request")
    a.add_argument("--out", default="data/proofs")
    a.add_argument("--uri-base", help="publish evidence at <uri-base>/<hash>.json instead of inline data: URIs")
    a.add_argument("--post", action="store_true")
    a.set_defaults(run=cmd_attest)
    v = sub.add_parser("verify", help="recompute and check an evidence file")
    v.add_argument("evidence")
    v.add_argument("--chain", type=int, choices=sorted(erc8004.REGISTRIES))
    v.add_argument("--validator")
    v.add_argument("--tx", nargs="*", default=[], help="the posting transactions, instead of searching logs")
    v.set_defaults(run=cmd_verify)
    args = p.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
