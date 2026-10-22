"""
HYPERION HYPERLIQUID GUARD: THE CO-SIGNER FOR A MULTI-SIG TRADING ACCOUNT
=========================================================================
The agent trades from a Hyperliquid account converted to a native multi-sig
with three authorized users, any two of which may act:

    owner    the person whose money it is; keeps their key offline
    agent    the trading bot's hot key
    Guard    this service

The agent's key alone can do nothing. With the Guard it can trade, within the
owner's policy. The owner, with either of the others, can do anything,
including take the money out. Hyperliquid enforces this itself: no contract,
nothing to deploy.

What the Guard co-signs for the agent:

  order, modify, batchModify   perps only; each order sized against the
                               owner's cap at the mid price, its limit price
                               held to a collar around the mid, its market on
                               the owner's list; a daily cap across them
  updateLeverage               up to the owner's maximum
  cancel, cancelByCloid,       always, even after a kill: stopping is never
  scheduleCancel               blocked

It never co-signs for the agent anything that moves money out of the account
or changes who controls it (withdrawals, transfers, signer changes, agent or
builder approvals), or an order carrying a builder fee. An action of a type,
or with a field, it doesn't know is refused.

After a kill it co-signs only cancels and reduce-only orders: the agent can
close positions but not open them.

Every action it signs must expire within MAX_EXPIRY_MS (Hyperliquid's
expiresAfter, which is part of what's signed). Hyperliquid accepts nonces up
to two days old, so without this an action approved before a kill could be
held back and sent after it.

The owner can also ask the Guard to co-sign anything, as the outer signer
with the owner's own signature: that's how money gets out if the agent's key
is lost, and how the account is converted back.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field, replace
from decimal import Decimal, InvalidOperation
from typing import Any

from eth_account import Account

from ..solana.store import MemoryStore, StateStore
from . import signing
from .market import Market, MarketUnavailable

MAX_EXPIRY_MS = 120_000           # an approval is good for at most two minutes
NONCE_SKEW_MS = 120_000           # the leader's nonce is a timestamp in ms, within this of the Guard's clock
DAY_MS = 86_400_000
SPOT_ASSETS = 10_000              # asset ids from here up are spot pairs (and, higher, builder-deployed perps)

CANCELS = frozenset({"cancel", "cancelByCloid", "scheduleCancel"})
ORDER_KEYS = frozenset({"type", "orders", "grouping"})               # no "builder": a fee the agent could route to itself
WIRE_KEYS = frozenset({"a", "b", "p", "s", "r", "t", "c"})
ACTION_KEYS = {
    "modify": frozenset({"type", "oid", "order"}),
    "batchModify": frozenset({"type", "modifies"}),
    "updateLeverage": frozenset({"type", "asset", "isCross", "leverage"}),
    "cancel": frozenset({"type", "cancels"}),
    "cancelByCloid": frozenset({"type", "cancels"}),
    "scheduleCancel": frozenset({"type", "time"}),
}


@dataclass
class HyperliquidPolicy:
    account: str                  # the multi-sig account, lower-case
    network: str                  # "mainnet" or "testnet"
    agent: str
    owner: str
    guardian: str = ""
    max_order_notional_usd: float = 1_000.0
    daily_notional_cap_usd: float = 10_000.0
    max_slippage_bps: int = 100
    max_leverage: int = 3
    allowed_coins: list[str] | None = None      # None: any listed perp
    policy_version: int = 1
    is_killed: bool = False

    @property
    def is_mainnet(self) -> bool:
        return self.network == "mainnet"


@dataclass
class HyperliquidVerdict:
    approved: bool
    status: str                   # "APPROVED", or why not: "REJECTED_ORDER_CAP", "REJECTED_KILL_SWITCH", ...
    violation_details: str | None
    account: str
    operations: list[str] = field(default_factory=list)
    cosigner_address: str = ""
    cosigner_signature: signing.Signature | None = None


class Refused(Exception):
    def __init__(self, status: str, details: str):
        super().__init__(details)
        self.status, self.details = status, details


def _decimal(value: Any, what: str) -> Decimal:
    if not isinstance(value, str):
        raise Refused("REJECTED_MALFORMED", f"{what} must be a decimal string, as Hyperliquid's wire format has it")
    try:
        d = Decimal(value)
    except InvalidOperation:
        raise Refused("REJECTED_MALFORMED", f"{what} {value!r} isn't a number") from None
    if not d.is_finite() or d <= 0:
        raise Refused("REJECTED_MALFORMED", f"{what} must be above zero, got {value}")
    return d


class HyperliquidGuardEngine:
    def __init__(self, market: Market, cosigner_key: bytes | str | None = None, store: StateStore | None = None,
                 clock_ms=lambda: int(time.time() * 1000)):
        self.market = market
        self.account_key = Account.from_key(cosigner_key) if cosigner_key else Account.create()
        self.store: StateStore = store if store is not None else MemoryStore()
        self.clock_ms = clock_ms
        self.lock = threading.RLock()
        self.policies: dict[str, HyperliquidPolicy] = {}
        self.nonces: dict[str, int] = {}
        self.usage: dict[str, list[list[float]]] = {}           # account → [[time ms, notional]], the last day's
        for account, saved in self.store.items("hl_policy"):
            self.policies[account] = HyperliquidPolicy(**saved)
        for account, saved in self.store.items("hl_nonce"):
            self.nonces[account] = int(saved["nonce"])
        for account, saved in self.store.items("hl_usage"):
            self.usage[account] = saved["orders"]

    @property
    def address(self) -> str:
        return self.account_key.address

    # ── owner and guardian controls ─────────────────────────────────────────

    def get_policy(self, account: str) -> HyperliquidPolicy | None:
        return self.policies.get(account.lower())

    def check_account(self, policy: HyperliquidPolicy) -> None:
        """Refuse a policy for an account Hyperliquid doesn't have set up as owner + agent + Guard, two of three.

        Otherwise someone holding only the agent's key could register a looser policy of their
        own for the account, naming a fresh key as its "owner"."""
        found = self.market.signers(policy.network, policy.account)
        if found is None:
            raise Refused("REJECTED_ACCOUNT", f"{policy.account} isn't a multi-sig account on Hyperliquid {policy.network}")
        users, threshold = found
        want = {policy.owner, policy.agent, self.address.lower()}
        if len(want) != 3:
            raise Refused("REJECTED_ACCOUNT", "the owner, the agent and the Guard must be three different keys")
        if set(users) != want or threshold != 2:
            raise Refused("REJECTED_ACCOUNT",
                          f"the account's signers must be exactly the owner, the agent and this Guard ({self.address}), "
                          f"any two of three; Hyperliquid has {sorted(users)}, threshold {threshold}")

    def _accept_nonce(self, account: str, nonce: int) -> bool:
        return nonce > self.nonces.get(account, -1)

    def set_policy(self, policy: HyperliquidPolicy, nonce: int) -> bool:
        """Save a policy; False if the nonce was already used. Call check_account first."""
        with self.lock:
            if not self._accept_nonce(policy.account, nonce):
                return False
            self.store.put_many([("hl_policy", policy.account, asdict(policy)), ("hl_nonce", policy.account, {"nonce": nonce})])
            self.policies[policy.account], self.nonces[policy.account] = policy, nonce
            return True

    def set_killed(self, account: str, killed: bool, nonce: int) -> bool:
        with self.lock:
            policy = self.policies[account]
            if not self._accept_nonce(account, nonce):
                return False
            changed = replace(policy, is_killed=killed)
            self.store.put_many([("hl_policy", account, asdict(changed)), ("hl_nonce", account, {"nonce": nonce})])
            self.policies[account], self.nonces[account] = changed, nonce
            return True

    # ── the check ───────────────────────────────────────────────────────────

    def evaluate(self, account: str, action: Any, nonce: Any, expires_after: Any, signer: str,
                 signature: signing.Signature) -> HyperliquidVerdict:
        """Judge `action` for `account`, asked for by `signer` (the agent, or the owner) with its
        own signature over the same envelope. If approved, the verdict carries the Guard's."""
        account = account.lower()
        with self.lock:
            try:
                policy = self.policies.get(account)
                if policy is None:
                    raise Refused("REJECTED_UNKNOWN_ACCOUNT", f"no policy for {account}")
                if signer.lower() == policy.owner:
                    return self._for_owner(policy, action, nonce, expires_after, signature)
                ops, notional = self._judge(policy, action, nonce, expires_after, signer.lower(), signature)
            except Refused as r:
                return HyperliquidVerdict(False, r.status, r.details, account, cosigner_address=self.address)
            except MarketUnavailable as exc:
                return HyperliquidVerdict(False, "REJECTED_MARKET_UNAVAILABLE", str(exc), account, cosigner_address=self.address)
            env = signing.envelope(account, signer, action)
            key = f"{account}:{signing.action_hash(env, nonce, expires_after).hex()}"
            saved = self.store.get("hl_approved", key)
            if saved is not None:                       # asked again: the same answer, counted once
                return HyperliquidVerdict(True, "APPROVED", None, account, ops, self.address, saved["signature"])
            mine = signing.sign_l1(self.account_key.key, env, nonce, expires_after, policy.is_mainnet)
            records = [("hl_approved", key, {"signature": mine, "expires_after": expires_after})]
            if notional:
                orders = self._recent(account) + [[float(self.clock_ms()), float(notional)]]
                records.append(("hl_usage", account, {"orders": orders}))
                self.usage[account] = orders
            self.store.put_many(records)
            return HyperliquidVerdict(True, "APPROVED", None, account, ops, self.address, mine)

    def _for_owner(self, policy: HyperliquidPolicy, action: Any, nonce: Any, expires_after: Any,
                   signature: signing.Signature) -> HyperliquidVerdict:
        """The owner may have anything co-signed: it's their money. A user-signed action (a
        withdrawal, a transfer, a change of signers) is signed as one; anything else as an L1 action."""
        if not isinstance(action, dict) or not isinstance(action.get("type"), str):
            raise Refused("REJECTED_MALFORMED", "action must be an object with a type")
        chain = "Mainnet" if policy.is_mainnet else "Testnet"
        user_signed = action["type"] in signing.USER_SIGNED
        if user_signed:
            if action.get("hyperliquidChain") != chain or action.get("signatureChainId") != signing.SIGNATURE_CHAIN_ID:
                raise Refused("REJECTED_MALFORMED", f'a {action["type"]} must carry hyperliquidChain "{chain}" and '
                                                    f'signatureChainId "{signing.SIGNATURE_CHAIN_ID}"')
            def sign(key):
                return signing.sign_multi_sig_user_signed(key, action, policy.account, policy.owner, policy.is_mainnet)
            def recover():
                return signing.recover_multi_sig_user_signed(action, policy.account, policy.owner, policy.is_mainnet, signature)
        else:
            if not isinstance(nonce, int) or (expires_after is not None and not isinstance(expires_after, int)):
                raise Refused("REJECTED_MALFORMED", "nonce must be an integer, and expires_after one or null")
            env = signing.envelope(policy.account, policy.owner, action)
            def sign(key):
                return signing.sign_l1(key, env, nonce, expires_after, policy.is_mainnet)
            def recover():
                return signing.recover_l1(env, nonce, expires_after, policy.is_mainnet, signature)
        try:
            recovered = recover().lower()
        except Exception:  # noqa: BLE001
            recovered = ""
        if recovered != policy.owner:
            raise Refused("REJECTED_SIGNATURE", f"the request isn't signed by the owner {policy.owner} over this action")
        return HyperliquidVerdict(True, "APPROVED", None, policy.account, [f"owner: {action['type']}"], self.address,
                                  sign(self.account_key.key))

    def _recent(self, account: str) -> list[list[float]]:
        since = self.clock_ms() - DAY_MS
        return [o for o in self.usage.get(account, []) if o[0] > since]

    def _judge(self, policy: HyperliquidPolicy, action: Any, nonce: Any, expires_after: Any, signer: str,
               signature: signing.Signature) -> tuple[list[str], Decimal]:
        if not isinstance(action, dict) or not isinstance(action.get("type"), str):
            raise Refused("REJECTED_MALFORMED", "action must be an object with a type")
        kind = action["type"]
        if kind not in CANCELS and kind not in ("order", "modify", "batchModify", "updateLeverage"):
            raise Refused("REJECTED_ACTION_TYPE", f"the Guard doesn't co-sign {kind!r} for an agent")
        if not isinstance(nonce, int) or not isinstance(expires_after, int):
            raise Refused("REJECTED_EXPIRY", "nonce and expires_after must be integers (ms): the Guard signs only actions that expire")
        now = self.clock_ms()
        if abs(nonce - now) > NONCE_SKEW_MS:
            raise Refused("REJECTED_EXPIRY", f"nonce {nonce} is more than {NONCE_SKEW_MS // 1000} s from now")
        if not now < expires_after <= now + MAX_EXPIRY_MS:
            raise Refused("REJECTED_EXPIRY", f"expires_after must be in the next {MAX_EXPIRY_MS // 1000} s")

        if signer != policy.agent:
            raise Refused("REJECTED_SIGNER", "only the account's agent or owner may ask")
        env = signing.envelope(policy.account, signer, action)
        try:
            recovered = signing.recover_l1(env, nonce, expires_after, policy.is_mainnet, signature).lower()
        except Exception:  # noqa: BLE001 — a malformed signature is a missing one
            recovered = ""
        if recovered != signer:
            raise Refused("REJECTED_SIGNATURE", f"the request isn't signed by {signer} over this action, nonce and expiry")

        if kind in CANCELS:
            self._keys(action, ACTION_KEYS[kind])
            return [kind], Decimal(0)
        if kind == "order":
            self._keys(action, ORDER_KEYS)
            orders = action.get("orders")
        elif kind == "modify":
            self._keys(action, ACTION_KEYS[kind])
            orders = [action.get("order")]
        elif kind == "batchModify":
            self._keys(action, ACTION_KEYS[kind])
            mods = action.get("modifies")
            if not isinstance(mods, list) or not all(isinstance(m, dict) and set(m) <= {"oid", "order"} for m in mods):
                raise Refused("REJECTED_MALFORMED", "modifies must be a list of {oid, order}")
            orders = [m.get("order") for m in mods]
        elif kind == "updateLeverage":
            self._keys(action, ACTION_KEYS[kind])
            if policy.is_killed:
                raise Refused("REJECTED_KILL_SWITCH", "the agent is killed: it may cancel and reduce, nothing else")
            perp = self._perp(policy, action.get("asset"))
            leverage = action.get("leverage")
            if not isinstance(leverage, int) or not 1 <= leverage <= policy.max_leverage:
                raise Refused("REJECTED_LEVERAGE", f"leverage {leverage} is over the owner's maximum of {policy.max_leverage}x")
            return [f"leverage {perp.coin} {leverage}x {'cross' if action.get('isCross') else 'isolated'}"], Decimal(0)
        else:
            raise Refused("REJECTED_ACTION_TYPE", f"the Guard doesn't co-sign {kind!r} for an agent")

        if not isinstance(orders, list) or not orders:
            raise Refused("REJECTED_MALFORMED", "no orders")
        ops, opening = [], Decimal(0)
        for order in orders:
            op, notional, reduce_only = self._order(policy, order)
            ops.append(op)
            if not reduce_only:
                opening += notional
        if policy.is_killed and opening:
            raise Refused("REJECTED_KILL_SWITCH", "the agent is killed: it may cancel and reduce, nothing else")
        spent = sum(Decimal(str(o[1])) for o in self._recent(policy.account))
        if opening and spent + opening > Decimal(str(policy.daily_notional_cap_usd)):
            raise Refused("REJECTED_DAILY_CAP", f"${spent + opening:.2f} in the last day would exceed the daily cap of "
                                                f"${policy.daily_notional_cap_usd:.2f}")
        return ops, opening

    @staticmethod
    def _keys(obj: dict, allowed: frozenset[str]) -> None:
        extra = set(obj) - allowed
        if extra:
            raise Refused("REJECTED_FIELD", f"the Guard doesn't co-sign an action with {sorted(extra)}")

    def _perp(self, policy: HyperliquidPolicy, asset: Any):
        if not isinstance(asset, int) or isinstance(asset, bool) or asset < 0:
            raise Refused("REJECTED_MALFORMED", f"asset must be a market number, got {asset!r}")
        if asset >= SPOT_ASSETS:
            raise Refused("REJECTED_MARKET", f"asset {asset} isn't a perp; the Guard co-signs perps only")
        perp = self.market.perp(policy.network, asset)
        if perp is None or perp.delisted:
            raise Refused("REJECTED_MARKET", f"asset {asset} isn't a listed perp on {policy.network}")
        if policy.allowed_coins is not None and perp.coin not in policy.allowed_coins:
            raise Refused("REJECTED_MARKET", f"{perp.coin} isn't on the owner's list: {', '.join(policy.allowed_coins)}")
        return perp

    def _order(self, policy: HyperliquidPolicy, wire: Any) -> tuple[str, Decimal, bool]:
        if not isinstance(wire, dict):
            raise Refused("REJECTED_MALFORMED", "an order must be an object")
        self._keys(wire, WIRE_KEYS)
        perp = self._perp(policy, wire.get("a"))
        is_buy, reduce_only, kind = wire.get("b"), wire.get("r"), wire.get("t")
        if not isinstance(is_buy, bool) or not isinstance(reduce_only, bool) or not isinstance(kind, dict) or len(kind) != 1:
            raise Refused("REJECTED_MALFORMED", "an order needs b and r (booleans) and t (limit or trigger)")
        price, size = _decimal(wire.get("p"), "price"), _decimal(wire.get("s"), "size")
        mid = self.market.mid(policy.network, perp.coin)
        if mid is None or mid <= 0:
            raise MarketUnavailable(f"no mid price for {perp.coin}")
        collar = Decimal(policy.max_slippage_bps) / Decimal(10_000)

        if "limit" in kind:
            reference = mid
        elif "trigger" in kind:
            # take-profit and stop-loss orders: they close positions, so they must be reduce-only,
            # and their limit price is held to the collar around their own trigger price
            if not reduce_only:
                raise Refused("REJECTED_TRIGGER", "a trigger order must be reduce-only")
            reference = _decimal((kind["trigger"] or {}).get("triggerPx"), "trigger price")
        else:
            raise Refused("REJECTED_MALFORMED", f"unknown order type {sorted(kind)}")
        worst = reference * (1 + collar) if is_buy else reference * (1 - collar)
        if (is_buy and price > worst) or (not is_buy and price < worst):
            raise Refused("REJECTED_SLIPPAGE", f"{'buy' if is_buy else 'sell'} {perp.coin} at {price} is more than "
                                               f"{policy.max_slippage_bps} bps from {reference}")
        notional = size * mid
        if not reduce_only and notional > Decimal(str(policy.max_order_notional_usd)):
            raise Refused("REJECTED_ORDER_CAP", f"Order notional ${notional:.2f} exceeds cap of ${policy.max_order_notional_usd:.2f}")
        side = "BUY" if is_buy else "SELL"
        return (f"{side} {size} {perp.coin} @ {price} (≈${notional:.2f}{', reduce-only' if reduce_only else ''})",
                notional, reduce_only)
