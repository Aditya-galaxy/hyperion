"""
HYPERION GUARD ON HYPERLIQUID: THE LIVE DEMO
============================================
A trading agent on Hyperliquid testnet whose account the Guard co-signs.
Every order below is real; the account's history is on the testnet explorer.

  1. the account is made a native multi-sig: owner + agent + Guard, two of three
  2. the owner sets the agent's policy at the Guard
  3. the agent buys about $15 of BTC: the Guard co-signs, Hyperliquid fills it
  4. the agent tries $60: over the owner's cap, the Guard won't sign
  5. the agent tries to withdraw to itself: the Guard never signs that
  6. the agent alone, without the Guard: Hyperliquid itself refuses
  7. the owner kills the agent: a new buy is refused, closing the position isn't
  8. the owner and the Guard turn the account back into a plain one

You need a Hyperliquid testnet account with some USDC in its perp balance
(about $25 is plenty; the testnet faucet is at
https://app.hyperliquid-testnet.xyz/drip). Its key is used to turn it into the
multi-sig and is given control back at the end. The owner and agent keys are
made fresh each run; the script sends each of them, and the Guard, $2 so they
exist on Hyperliquid, which a multi-sig's signers must.

    HL_ACCOUNT_KEY=0x… python guard/demo/hyperliquid_testnet.py

By default the Guard runs inside this script, against Hyperliquid's real
testnet API. To use a hosted Guard over its HTTP API instead:

    HYPERION_GUARD_URL=https://<your-guard> HL_ACCOUNT_KEY=0x… python guard/demo/hyperliquid_testnet.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from decimal import ROUND_DOWN, Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service"))

import httpx
from eth_account import Account
from hyperion_guard.hyperliquid import control, signing
from hyperion_guard.hyperliquid.market import API

NET = "testnet"
HL = API[NET]
EXPLORER = "https://app.hyperliquid-testnet.xyz/explorer/address/"
http = httpx.Client(timeout=15, headers={"user-agent": "hyperion-guard-demo"})


def now_ms() -> int:
    return int(time.time() * 1000)


def info(body: dict):
    return http.post(HL + "/info", json=body).raise_for_status().json()


def exchange(action: dict, nonce: int, signature: dict, expires_after: int | None = None) -> dict:
    body = {"action": action, "nonce": nonce, "signature": signature, "vaultAddress": None, "expiresAfter": expires_after}
    return http.post(HL + "/exchange", json=body).raise_for_status().json()


def ok(res: dict, what: str) -> dict:
    statuses = (res.get("response") or {}).get("data", {}).get("statuses", []) if isinstance(res.get("response"), dict) else []
    errors = [s["error"] for s in statuses if isinstance(s, dict) and "error" in s]
    if res.get("status") != "ok" or errors:
        raise SystemExit(f"{what} failed: {json.dumps(res)}")
    return res


def scene(n: int, title: str) -> None:
    print(f"\n── {n}. {title} {'─' * max(0, 66 - len(title))}")


class LocalGuard:
    """The Guard's HTTP API, served inside this script."""

    def __init__(self):
        from fastapi.testclient import TestClient
        from hyperion_guard.api import create_app
        self.client = TestClient(create_app())

    def post(self, path: str, body: dict) -> httpx.Response:
        return self.client.post(path, json=body)

    def get(self, path: str) -> httpx.Response:
        return self.client.get(path)


class RemoteGuard:
    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def post(self, path: str, body: dict) -> httpx.Response:
        return http.post(self.url + path, json=body)

    def get(self, path: str) -> httpx.Response:
        return http.get(self.url + path)


def main() -> None:
    if not os.environ.get("HL_ACCOUNT_KEY"):
        raise SystemExit(__doc__)
    account = Account.from_key(os.environ["HL_ACCOUNT_KEY"])
    owner, agent = Account.create(), Account.create()
    url = os.environ.get("HYPERION_GUARD_URL")
    guard = RemoteGuard(url) if url else LocalGuard()
    guard_address = guard.get("/v1/hyperliquid/health").json()["cosigner_address"]
    acct = account.address.lower()

    universe = info({"type": "meta"})["universe"]
    btc = next(i for i, m in enumerate(universe) if m["name"] == "BTC")
    sz_decimals = universe[btc]["szDecimals"]

    def mid() -> Decimal:
        return Decimal(info({"type": "allMids"})["BTC"])

    def px(value: Decimal) -> str:
        """Five significant figures and no more decimals than 6 − szDecimals: Hyperliquid's tick rule."""
        rounded = Decimal(f"{value:.5g}").quantize(Decimal(1).scaleb(-(6 - sz_decimals)))
        return format(rounded.normalize(), "f")

    def size_for(usd: float, price: Decimal) -> str:
        return format((Decimal(str(usd)) / price).quantize(Decimal(1).scaleb(-sz_decimals), rounding=ROUND_DOWN), "f")

    def position() -> Decimal:
        state = info({"type": "clearinghouseState", "user": acct})
        return sum((Decimal(p["position"]["szi"]) for p in state["assetPositions"] if p["position"]["coin"] == "BTC"), Decimal(0))

    def ask(action: dict, signer=agent, nonce: int | None = None, expires_after: int | None = None) -> tuple[dict, int, int | None]:
        """Sign as `signer`, ask the Guard. Returns its verdict, and the nonce and expiry used."""
        nonce = nonce or now_ms()
        owner_user_signed = signer is owner and action["type"] in signing.USER_SIGNED
        if expires_after is None and not owner_user_signed:
            expires_after = nonce + 60_000
        if owner_user_signed:
            mine = signing.sign_multi_sig_user_signed(signer.key, action, acct, signer.address, False)
        else:
            mine = signing.sign_l1(signer.key, signing.envelope(acct, signer.address, action), nonce, expires_after, False)
        verdict = guard.post("/v1/hyperliquid/check", {"account": acct, "action": action, "nonce": nonce,
                                                       "expires_after": expires_after, "signer": signer.address,
                                                       "signature": mine}).json()
        verdict["_mine"] = mine
        return verdict, nonce, expires_after

    def send(action: dict, signer, signatures: list[dict], nonce: int, expires_after: int | None) -> dict:
        """Post a multiSig action, `signer` as the leader."""
        multi = signing.multi_sig_action(acct, signer.address, action, signatures)
        return exchange(multi, nonce, signing.sign_multi_sig(signer.key, multi, nonce, expires_after, False), expires_after)

    def order(is_buy: bool, size: str, price: str, reduce_only: bool = False) -> dict:
        return {"type": "order", "orders": [{"a": btc, "b": is_buy, "p": price, "s": size, "r": reduce_only,
                                             "t": {"limit": {"tif": "Ioc"}}}], "grouping": "na"}

    print(f"""account   {account.address}   (becomes the multi-sig)
owner     {owner.address}
agent     {agent.address}
Guard     {guard_address}   ({url or 'in this script'})
BTC       ${mid()} (testnet), asset {btc}
explorer  {EXPLORER}{account.address}""")

    scene(1, "The account becomes a multi-sig: owner + agent + Guard, two of three")
    for who in (owner.address, agent.address, guard_address):
        if info({"type": "userRole", "user": who}).get("role") == "missing":
            send_usd = {"type": "usdSend", "destination": who.lower(), "amount": "2", "time": now_ms()}
            ok(exchange(send_usd, send_usd["time"], signing.sign_user_signed(account.key, send_usd, False)), f"sending $2 to {who}")
    users = sorted(a.lower() for a in (owner.address, agent.address, guard_address))
    convert = {"type": "convertToMultiSigUser", "signers": json.dumps({"authorizedUsers": users, "threshold": 2}), "nonce": now_ms()}
    ok(exchange(convert, convert["nonce"], signing.sign_convert_to_multi_sig(account.key, convert, False)), "converting")
    print(f"   signers {info({'type': 'userToMultiSigSigners', 'user': acct})}")

    scene(2, "The owner sets the agent's policy at the Guard")
    policy = dict(network=NET, account=acct, agent=agent.address.lower(), owner=owner.address.lower(), guardian="",
                  max_order_notional_usd=30.0, daily_notional_cap_usd=100.0, max_slippage_bps=50, max_leverage=3,
                  allowed_coins=["BTC", "ETH"], policy_version=1, nonce=now_ms())
    res = guard.post("/v1/hyperliquid/policy", {**policy, "signature": control.sign_message(owner.key, control.policy_message(**policy))})
    if res.status_code != 200:
        raise SystemExit(f"policy refused: {res.text}")
    print("   $30 an order, $100 a day, BTC and ETH, 50 bps from the mid, 3x leverage at most")

    scene(3, "The agent buys about $15 of BTC: the Guard co-signs, Hyperliquid fills it")
    m = mid()
    buy = order(True, size_for(15, m), px(m * Decimal("1.003")))
    verdict, nonce, expires = ask(buy)
    if not verdict["approved"]:
        raise SystemExit(f"the Guard refused: {verdict}")
    print(f"   Guard: APPROVED {verdict['operations']}")
    res = ok(send(buy, agent, [verdict["_mine"], verdict["cosigner_signature"]], nonce, expires), "the order")
    print(f"   Hyperliquid: {res['response']['data']['statuses'][0]}\n   position {position()} BTC")

    scene(4, "The agent tries $60: over the owner's cap")
    verdict, _, _ = ask(order(True, size_for(60, m), px(m * Decimal("1.003"))))
    print(f"   Guard: {verdict['status']}: {verdict['violation_details']}\n   no co-signature, so nothing to send")

    scene(5, "The agent tries to withdraw to itself")
    grab = {"type": "withdraw3", "signatureChainId": "0x66eee", "hyperliquidChain": "Testnet",
            "destination": agent.address.lower(), "amount": "5", "time": now_ms()}
    verdict, _, _ = ask(grab)
    print(f"   Guard: {verdict['status']}: {verdict['violation_details']}")

    scene(6, "The agent alone, without the Guard: Hyperliquid itself refuses")
    m = mid()
    alone = order(True, size_for(15, m), px(m * Decimal("1.003")))
    nonce = now_ms()
    mine = signing.sign_l1(agent.key, signing.envelope(acct, agent.address, alone), nonce, nonce + 60_000, False)
    res = send(alone, agent, [mine], nonce, nonce + 60_000)
    if res.get("status") == "ok" and "error" not in json.dumps(res):
        raise SystemExit(f"Hyperliquid accepted an order without the Guard: {res}")
    print(f"   Hyperliquid: {res.get('response')}")

    scene(7, "The owner kills the agent: no new buys, but it can close the position")
    kill_nonce = now_ms()
    res = guard.post("/v1/hyperliquid/kill", {"account": acct, "nonce": kill_nonce,
                                              "signature": control.sign_message(owner.key, control.action_message("kill", acct, kill_nonce))})
    print(f"   killed: {res.json()}")
    m = mid()
    verdict, _, _ = ask(order(True, size_for(15, m), px(m * Decimal("1.003"))))
    print(f"   a new buy → Guard: {verdict['status']}")
    held = position()
    close = order(False, format(held, "f"), px(m * Decimal("0.997")), reduce_only=True)
    verdict, nonce, expires = ask(close)
    print(f"   closing {held} BTC → Guard: {verdict['status']} {verdict['operations']}")
    res = ok(send(close, agent, [verdict["_mine"], verdict["cosigner_signature"]], nonce, expires), "closing")
    print(f"   Hyperliquid: {res['response']['data']['statuses'][0]}\n   position {position()} BTC")

    scene(8, "The owner and the Guard turn it back into a plain account")
    back = {"type": "convertToMultiSigUser", "signatureChainId": "0x66eee", "hyperliquidChain": "Testnet",
            "signers": "null", "nonce": now_ms()}
    verdict, nonce, _ = ask(back, signer=owner, nonce=back["nonce"])
    if not verdict["approved"]:
        raise SystemExit(f"the Guard refused the owner: {verdict}")
    ok(send(back, owner, [verdict["_mine"], verdict["cosigner_signature"]], nonce, None), "converting back")
    print(f"   signers now {info({'type': 'userToMultiSigSigners', 'user': acct})}: the account key is in control again")
    print(f"\n{EXPLORER}{account.address}")


if __name__ == "__main__":
    main()
