"""The Hyperliquid Guard: what it co-signs for an agent, what it refuses, and
the owner's controls, against a stand-in for Hyperliquid's info API."""

from decimal import Decimal

import pytest
from eth_account import Account
from fastapi.testclient import TestClient
from hyperion_guard.api import create_app
from hyperion_guard.hyperliquid import control, signing
from hyperion_guard.hyperliquid.guard import HyperliquidGuardEngine
from hyperion_guard.hyperliquid.market import MarketUnavailable, Perp
from hyperion_guard.solana.store import SqliteStore

NOW = 1_760_000_000_000
BTC, ETH = 3, 4
OWNER, AGENT, GUARDIAN, ACCOUNT, GUARD = (Account.from_key("0x" + bytes([i]).hex() * 32) for i in range(11, 16))


class StandInMarket:
    def __init__(self):
        self.perps = {BTC: Perp(BTC, "BTC", 5, 40), ETH: Perp(ETH, "ETH", 4, 25), 7: Perp(7, "OLD", 2, 3, delisted=True)}
        self.mids = {"BTC": Decimal(80000), "ETH": Decimal(2400)}
        self.accounts = {ACCOUNT.address.lower(): (sorted(a.address.lower() for a in (OWNER, AGENT, GUARD)), 2)}
        self.down = False

    def perp(self, network, asset):
        if self.down:
            raise MarketUnavailable("can't read Hyperliquid testnet: timed out")
        return self.perps.get(asset)

    def mid(self, network, coin):
        return self.mids.get(coin)

    def signers(self, network, account):
        return self.accounts.get(account.lower())


@pytest.fixture
def market():
    return StandInMarket()


@pytest.fixture
def client(market, tmp_path):
    engine = HyperliquidGuardEngine(market, cosigner_key=GUARD.key, store=SqliteStore(tmp_path / "state.db"), clock_ms=lambda: NOW)
    return TestClient(create_app(hyperliquid_guard=engine))


POLICY = dict(network="testnet", account=ACCOUNT.address, agent=AGENT.address, owner=OWNER.address, guardian=GUARDIAN.address,
              max_order_notional_usd=500.0, daily_notional_cap_usd=1_200.0, max_slippage_bps=100, max_leverage=3,
              allowed_coins=["BTC", "ETH"], policy_version=1, nonce=1)


def register(client, signer=OWNER, **changes):
    body = {**POLICY, **changes}
    message = control.policy_message(**{k: body[k] for k in POLICY})
    return client.post("/v1/hyperliquid/policy", json={**body, "signature": control.sign_message(signer.key, message)})


def order(asset=BTC, buy=True, px="80400", sz="0.005", reduce_only=False, tif="Ioc", **extra):
    return {"type": "order", "orders": [{"a": asset, "b": buy, "p": px, "s": sz, "r": reduce_only, "t": {"limit": {"tif": tif}}}],
            "grouping": "na", **extra}


def ask(client, action, signer=AGENT, nonce=NOW, expires_after=NOW + 60_000, sign_as=None):
    env = signing.envelope(ACCOUNT.address, signer.address, action)
    signature = signing.sign_l1((sign_as or signer).key, env, nonce, expires_after, False)
    return client.post("/v1/hyperliquid/check", json={
        "account": ACCOUNT.address, "action": action, "nonce": nonce, "expires_after": expires_after,
        "signer": signer.address, "signature": signature}).json()


def control_call(client, action, signer, nonce):
    message = control.action_message(action, ACCOUNT.address, nonce)
    return client.post(f"/v1/hyperliquid/{action}", json={"account": ACCOUNT.address, "nonce": nonce,
                                                          "signature": control.sign_message(signer.key, message)})


# ── trading ─────────────────────────────────────────────────────────────────

def test_an_order_within_policy_is_cosigned_for_the_multi_sig(client):
    assert register(client).status_code == 200
    action = order()
    v = ask(client, action)
    assert v["approved"] and v["status"] == "APPROVED"
    assert v["operations"] == ["BUY 0.005 BTC @ 80400 (≈$400.00)"]
    # the co-signature is Guard's, over exactly what Hyperliquid will check for this account and leader
    env = signing.envelope(ACCOUNT.address, AGENT.address, action)
    assert signing.recover_l1(env, NOW, NOW + 60_000, False, v["cosigner_signature"]) == GUARD.address
    assert v["cosigner_address"] == GUARD.address


@pytest.mark.parametrize("action,status", [
    (order(sz="0.01"), "REJECTED_ORDER_CAP"),                        # $800, over $500
    (order(px="81000"), "REJECTED_SLIPPAGE"),                       # 125 bps over the mid
    (order(buy=False, px="79000"), "REJECTED_SLIPPAGE"),
    (order(builder={"b": "0x" + "ee" * 20, "f": 100}), "REJECTED_FIELD"),   # a fee the agent could route to itself
    (order(asset=10_001), "REJECTED_MARKET"),                       # spot
    (order(asset=7), "REJECTED_MARKET"),                            # delisted
    (order(asset=99), "REJECTED_MARKET"),                           # not listed
    ({"type": "withdraw3", "destination": "0x" + "ee" * 20, "amount": "100", "time": NOW}, "REJECTED_ACTION_TYPE"),
    ({"type": "usdSend", "destination": "0x" + "ee" * 20, "amount": "100", "time": NOW}, "REJECTED_ACTION_TYPE"),
    ({"type": "convertToMultiSigUser", "signers": "null", "nonce": NOW}, "REJECTED_ACTION_TYPE"),
    ({"type": "approveAgent", "agentAddress": "0x" + "ee" * 20, "agentName": None, "nonce": NOW}, "REJECTED_ACTION_TYPE"),
    ({"type": "updateLeverage", "asset": BTC, "isCross": True, "leverage": 10}, "REJECTED_LEVERAGE"),
    ({"type": "order", "orders": [{"a": BTC, "b": False, "p": "70000", "s": "0.001", "r": False,
                                   "t": {"trigger": {"isMarket": True, "triggerPx": "70000", "tpsl": "sl"}}}], "grouping": "na"},
     "REJECTED_TRIGGER"),                                           # a stop that isn't reduce-only
    ({"type": "order", "orders": [{"a": BTC, "b": True, "p": 80000, "s": "0.001", "r": False, "t": {"limit": {"tif": "Gtc"}}}],
      "grouping": "na"}, "REJECTED_MALFORMED"),                     # a float price: not the wire format
])
def test_what_the_guard_wont_sign_for_the_agent(client, action, status):
    register(client)
    v = ask(client, action)
    assert (v["approved"], v["status"]) == (False, status), v
    assert v["cosigner_signature"] is None


def test_coins_off_the_owners_list_are_refused(client):
    register(client, allowed_coins=["ETH"])
    assert ask(client, order())["status"] == "REJECTED_MARKET"
    assert ask(client, order(asset=ETH, px="2410", sz="0.1"))["approved"]


def test_only_actions_that_expire_soon(client):
    register(client)
    assert ask(client, order(), expires_after=NOW + 10 * 60_000)["status"] == "REJECTED_EXPIRY"
    assert ask(client, order(), expires_after=NOW - 1)["status"] == "REJECTED_EXPIRY"
    assert ask(client, order(), nonce=NOW - 3_600_000)["status"] == "REJECTED_EXPIRY"
    body = {"account": ACCOUNT.address, "action": order(), "nonce": NOW, "expires_after": None, "signer": AGENT.address,
            "signature": {"r": "0x1", "s": "0x1", "v": 27}}
    assert client.post("/v1/hyperliquid/check", json=body).json()["status"] == "REJECTED_EXPIRY"


def test_only_the_agent_or_owner_may_ask_and_must_have_signed(client):
    register(client)
    assert ask(client, order(), signer=GUARDIAN)["status"] == "REJECTED_SIGNER"
    assert ask(client, order(), sign_as=GUARDIAN)["status"] == "REJECTED_SIGNATURE"   # names the agent, signed by someone else


def test_the_daily_cap_and_a_repeated_request_counts_once(client):
    register(client)
    first = ask(client, order())                                    # $400
    assert ask(client, order())["cosigner_signature"] == first["cosigner_signature"]    # the same request again
    assert ask(client, order(), nonce=NOW + 1)["approved"]          # $800
    assert ask(client, order(), nonce=NOW + 2)["approved"]          # $1,200
    v = ask(client, order(sz="0.001"), nonce=NOW + 3)               # $80 more
    assert v["status"] == "REJECTED_DAILY_CAP"
    assert ask(client, order(buy=False, px="79500", reduce_only=True), nonce=NOW + 4)["approved"]   # closing never counts


def test_leverage_within_the_owners_maximum(client):
    register(client)
    v = ask(client, {"type": "updateLeverage", "asset": BTC, "isCross": False, "leverage": 3})
    assert v["approved"] and v["operations"] == ["leverage BTC 3x isolated"]


def test_a_guard_that_cant_see_the_market_refuses(client, market):
    register(client)
    market.down = True
    assert ask(client, order())["status"] == "REJECTED_MARKET_UNAVAILABLE"
    market.down = False
    del market.mids["BTC"]
    assert ask(client, order())["status"] == "REJECTED_MARKET_UNAVAILABLE"


# ── kill switch and the owner ───────────────────────────────────────────────

def test_after_a_kill_the_agent_can_only_cancel_and_reduce(client):
    register(client)
    assert control_call(client, "kill", GUARDIAN, 2).status_code == 200
    assert ask(client, order())["status"] == "REJECTED_KILL_SWITCH"
    assert ask(client, {"type": "updateLeverage", "asset": BTC, "isCross": True, "leverage": 2})["status"] == "REJECTED_KILL_SWITCH"
    assert ask(client, {"type": "cancel", "cancels": [{"a": BTC, "o": 1}]})["approved"]
    assert ask(client, order(buy=False, px="79500", reduce_only=True))["approved"]
    assert control_call(client, "revive", GUARDIAN, 3).status_code == 403      # only the owner revives
    assert control_call(client, "revive", OWNER, 2).status_code == 409         # a used nonce
    assert control_call(client, "revive", OWNER, 4).status_code == 200
    assert ask(client, order(), nonce=NOW + 9)["approved"]


def test_the_owner_can_take_the_money_out_and_undo_the_setup(client):
    register(client)
    for action in ({"type": "withdraw3", "signatureChainId": "0x66eee", "hyperliquidChain": "Testnet",
                    "destination": OWNER.address.lower(), "amount": "100", "time": NOW},
                   {"type": "convertToMultiSigUser", "signatureChainId": "0x66eee", "hyperliquidChain": "Testnet",
                    "signers": "null", "nonce": NOW}):
        mine = signing.sign_multi_sig_user_signed(OWNER.key, action, ACCOUNT.address, OWNER.address, False)
        v = client.post("/v1/hyperliquid/check", json={"account": ACCOUNT.address, "action": action, "nonce": NOW,
                                                       "expires_after": None, "signer": OWNER.address, "signature": mine}).json()
        assert v["approved"] and v["operations"] == [f"owner: {action['type']}"]
        assert signing.recover_multi_sig_user_signed(action, ACCOUNT.address, OWNER.address, False,
                                                     v["cosigner_signature"]) == GUARD.address
        # signed as an L1 action instead, it isn't the owner's: refused
        assert ask(client, action, signer=OWNER, sign_as=OWNER)["status"] == "REJECTED_SIGNATURE"
    # an ordinary trade the owner places, even over the agent's cap
    assert ask(client, order(sz="1"), signer=OWNER)["approved"]
    # a withdrawal on the wrong chain is refused rather than signed for nothing
    mainnet = {"type": "withdraw3", "signatureChainId": "0x66eee", "hyperliquidChain": "Mainnet",
               "destination": OWNER.address.lower(), "amount": "1", "time": NOW}
    assert ask(client, mainnet, signer=OWNER)["status"] == "REJECTED_MALFORMED"


# ── registering a policy ────────────────────────────────────────────────────

def test_the_policy_must_be_signed_by_its_owner(client):
    assert register(client, signer=AGENT).status_code == 401


def test_the_account_must_be_owner_agent_and_guard_two_of_three(client, market):
    key = ACCOUNT.address.lower()
    market.accounts[key] = (sorted(a.address.lower() for a in (OWNER, AGENT, GUARD)), 1)        # the agent alone could trade
    assert "threshold 1" in register(client).json()["detail"]
    market.accounts[key] = (sorted(a.address.lower() for a in (OWNER, AGENT, GUARDIAN)), 2)     # the Guard isn't a signer
    assert register(client).status_code == 422
    del market.accounts[key]
    assert "isn't a multi-sig" in register(client).json()["detail"]


def test_a_stolen_agent_key_cant_register_a_looser_policy(client, market):
    # the thief holds the agent's key and names a fresh key as "owner"
    thief = Account.create()
    assert register(client, owner=thief.address, signer=thief, max_order_notional_usd=1e9, daily_notional_cap_usd=1e9).status_code == 422
    assert register(client, owner=AGENT.address, signer=AGENT).status_code == 422        # or itself


def test_updates_need_the_owner_a_higher_version_and_a_fresh_nonce(client, market):
    assert register(client).status_code == 200
    assert register(client, policy_version=1, nonce=2).status_code == 409
    assert register(client, policy_version=2, nonce=1).status_code == 409
    assert register(client, policy_version=2, nonce=2, max_order_notional_usd=100.0).status_code == 200
    assert client.get(f"/v1/hyperliquid/policy/{ACCOUNT.address}").json()["max_order_notional_usd"] == 100.0


def test_state_survives_a_restart(market, tmp_path):
    def app():
        engine = HyperliquidGuardEngine(market, cosigner_key=GUARD.key, store=SqliteStore(tmp_path / "s.db"), clock_ms=lambda: NOW)
        return TestClient(create_app(hyperliquid_guard=engine))
    first = app()
    register(first)
    assert ask(first, order(sz="0.015", px="80400"))["status"] == "REJECTED_ORDER_CAP"
    assert ask(first, order())["approved"]
    control_call(first, "kill", OWNER, 5)
    again = app()
    assert again.get(f"/v1/hyperliquid/policy/{ACCOUNT.address}").json()["killed"] is True
    assert control_call(again, "revive", OWNER, 5).status_code == 409           # the nonce was remembered
    control_call(again, "revive", OWNER, 6)
    assert ask(again, order(), nonce=NOW + 1)["approved"]
    assert ask(again, order(), nonce=NOW + 2)["approved"]
    assert ask(again, order(), nonce=NOW + 3)["status"] == "REJECTED_DAILY_CAP"  # usage was remembered too
