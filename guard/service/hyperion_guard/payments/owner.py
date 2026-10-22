"""
HYPERION PAYMENTS GUARD: THE OWNER'S CONTROLS
=============================================
    python -m hyperion_guard.payments.owner new-key  ~/.hyperion/owner.key
    python -m hyperion_guard.payments.owner policy   --key-file ~/.hyperion/owner.key --agent 0x… \\
        --payers 0x… --chains base base-sepolia --tokens 0x… \\
        --max-per-payment 50 --daily-cap 250 --max-per-recipient-daily 100
    python -m hyperion_guard.payments.owner kill     --key-file ~/.hyperion/owner.key --agent 0x…
    python -m hyperion_guard.payments.owner revive   --key-file ~/.hyperion/owner.key --agent 0x…
    python -m hyperion_guard.payments.owner show     --agent 0x…

--guard (or HYPERION_GUARD_URL) is the Guard; the hosted one by default. A
key file holds a 0x-hex private key and nothing else, and is written readable
by its owner only. Nonces and policy versions are taken from the clock and
the current policy, so nothing needs remembering between commands.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx
from eth_account import Account

from . import control

HOSTED = "https://hyperion-guard-dijsyl2kwq-uc.a.run.app"


def _key(path: str) -> Account:
    return Account.from_key(Path(path).expanduser().read_text().strip())


def _show(res: httpx.Response) -> None:
    try:
        print(json.dumps(res.json(), indent=1))
    except ValueError:
        print(res.text)
    if res.status_code >= 400:
        sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m hyperion_guard.payments.owner", description=__doc__.split("\n\n")[0])
    ap.add_argument("--guard", default=os.environ.get("HYPERION_GUARD_URL", HOSTED))
    sub = ap.add_subparsers(dest="command", required=True)
    new = sub.add_parser("new-key", help="make a key and write it to a file")
    new.add_argument("path")
    for name in ("policy", "kill", "revive"):
        p = sub.add_parser(name)
        p.add_argument("--key-file", required=True, help="the owner's key (or, to kill, the guardian's)")
        p.add_argument("--agent", required=True)
    pol = sub.choices["policy"]
    pol.add_argument("--guardian", default="")
    pol.add_argument("--payers", nargs="+", required=True)
    pol.add_argument("--chains", nargs="+", required=True)
    pol.add_argument("--tokens", nargs="+", required=True)
    pol.add_argument("--max-per-payment", type=float, required=True)
    pol.add_argument("--daily-cap", type=float, required=True)
    pol.add_argument("--max-per-recipient-daily", type=float, required=True)
    sub.add_parser("show").add_argument("--agent", required=True)
    args = ap.parse_args(argv)
    guard = args.guard.rstrip("/")
    nonce = int(time.time() * 1000)

    if args.command == "new-key":
        path = Path(args.path).expanduser()
        if path.exists():
            sys.exit(f"{path} exists; not overwriting a key")
        path.parent.mkdir(parents=True, exist_ok=True)
        account = Account.create()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("0x" + account.key.hex().removeprefix("0x") + "\n")
        print(f"wrote {path} (address {account.address})")
    elif args.command == "show":
        _show(httpx.get(f"{guard}/v1/payments/policy/{args.agent}", timeout=15))
    elif args.command == "policy":
        owner = _key(args.key_file)
        current = httpx.get(f"{guard}/v1/payments/policy/{args.agent}", timeout=15)
        version = current.json()["policy_version"] + 1 if current.status_code == 200 else 1
        body = dict(agent=args.agent, owner=owner.address, guardian=args.guardian, payers=args.payers, chains=args.chains,
                    tokens=args.tokens, max_per_payment_usdc=args.max_per_payment, daily_cap_usdc=args.daily_cap,
                    max_per_recipient_daily_usdc=args.max_per_recipient_daily, policy_version=version, nonce=nonce)
        signature = control.sign_message(owner.key, control.policy_message(**body))
        _show(httpx.post(f"{guard}/v1/payments/policy", json={**body, "signature": signature}, timeout=15))
    else:
        signer = _key(args.key_file)
        signature = control.sign_message(signer.key, control.action_message(args.command, args.agent, nonce))
        _show(httpx.post(f"{guard}/v1/payments/{args.command}",
                         json={"agent": args.agent, "nonce": nonce, "signature": signature}, timeout=15))


if __name__ == "__main__":
    main()
