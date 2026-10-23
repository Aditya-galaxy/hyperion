"""
HYPERION PAYMENTS GUARD: A SECOND KEY ON AN AGENT'S PAYOUTS
===========================================================
For an agent that pays out USDC from a wallet the Guard can't co-sign for: a
custodial one, such as a Circle agent wallet. Before each payout the agent's
payer asks the Guard and sends only with its approval: an EIP-712 signature
over exactly that payout (payer, recipient, token, chain, amount, intent id),
good for a few minutes.

What it checks, against limits the owner signed:

  kill switch          the owner or guardian can stop every payout at once
  payer, chain, token  only the wallets, chains and tokens the owner listed
  per payment          an amount cap
  per day              a cap across all payouts, and one per recipient, over
                       the last 24 hours; shared by every instance of the
                       agent, since they all ask the same Guard
  intent               one intent id is one payout: asking again for the same
                       payout returns the same approval and counts once;
                       reusing the id for a different payout is refused

What it can't do: stop someone holding the wallet's own credentials. The
enforcement is in the payer's code, which refuses to send without a valid
approval. What the Guard adds is a kill switch and limits that live outside
the agent's deployment, held by the owner, and a signed record of every
payout it allowed.

Approved amounts count from the moment of approval, whether or not the
transfer then lands: the cap is on what the agent was allowed to send.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field, replace
from decimal import Decimal, InvalidOperation

from eth_account import Account

from ..solana.store import MemoryStore, StateStore
from . import control

MAX_TTL_S = 300
DAY_S = 86_400
UNITS = Decimal(10) ** 6          # USDC has six decimals
ZERO = "0x" + "0" * 40
CHAINS = frozenset({"base", "base-sepolia", "ethereum", "eth-sepolia", "polygon", "polygon-amoy", "arbitrum",
                    "arbitrum-sepolia", "arc", "arc-testnet"})


@dataclass
class PaymentPolicy:
    agent: str                    # the key the agent signs requests with, lower-case
    owner: str
    guardian: str = ""
    payers: list[str] = field(default_factory=list)
    chains: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    max_per_payment_usdc: str = "10.00"
    daily_cap_usdc: str = "100.00"
    max_per_recipient_daily_usdc: str = "50.00"
    policy_version: int = 1
    is_killed: bool = False


@dataclass
class PaymentVerdict:
    approved: bool
    status: str                   # "APPROVED", or why not: "REJECTED_PAYMENT_CAP", "REJECTED_KILL_SWITCH", ...
    violation_details: str | None
    agent: str
    approval: dict | None = None  # the EIP-712 typed data the signature is over
    signature: str | None = None
    cosigner_address: str = ""


class Refused(Exception):
    def __init__(self, status: str, details: str):
        super().__init__(details)
        self.status, self.details = status, details


def amount_units(amount: str) -> int:
    """'12.5' → 12500000. A string with at most six decimals, above zero; anything else is refused."""
    if not isinstance(amount, str):
        raise Refused("REJECTED_MALFORMED", "amount must be a decimal string, e.g. \"12.50\"")
    try:
        d = Decimal(amount)
    except InvalidOperation:
        raise Refused("REJECTED_MALFORMED", f"amount {amount!r} isn't a number") from None
    units = d * UNITS
    if not d.is_finite() or d <= 0 or units != units.to_integral_value():
        raise Refused("REJECTED_MALFORMED", f"amount must be above zero with at most six decimals, got {amount}")
    return int(units)


class PaymentGuardEngine:
    def __init__(self, cosigner_key: bytes | str | None = None, store: StateStore | None = None, clock=time.time):
        self.account = Account.from_key(cosigner_key) if cosigner_key else Account.create()
        self.store: StateStore = store if store is not None else MemoryStore()
        self.clock = clock
        self.lock = threading.Lock()
        self.policies = {k: PaymentPolicy(**v) for k, v in self.store.items("pay_policy")}
        self.nonces = {k: int(v["nonce"]) for k, v in self.store.items("pay_nonce")}
        self.usage: dict[str, list[list]] = {k: v["payouts"] for k, v in self.store.items("pay_usage")}

    @property
    def address(self) -> str:
        return self.account.address

    def get_policy(self, agent: str) -> PaymentPolicy | None:
        return self.policies.get(agent.lower())

    def set_policy(self, policy: PaymentPolicy, nonce: int) -> bool:
        with self.lock:
            if nonce <= self.nonces.get(policy.agent, -1):
                return False
            self.store.put_many([("pay_policy", policy.agent, asdict(policy)), ("pay_nonce", policy.agent, {"nonce": nonce})])
            self.policies[policy.agent], self.nonces[policy.agent] = policy, nonce
            return True

    def set_killed(self, agent: str, killed: bool, nonce: int) -> bool:
        with self.lock:
            if nonce <= self.nonces.get(agent, -1):
                return False
            changed = replace(self.policies[agent], is_killed=killed)
            self.store.put_many([("pay_policy", agent, asdict(changed)), ("pay_nonce", agent, {"nonce": nonce})])
            self.policies[agent], self.nonces[agent] = changed, nonce
            return True

    def _recent(self, agent: str) -> list[list]:
        since = self.clock() - DAY_S
        return [p for p in self.usage.get(agent, []) if p[0] > since]      # [time, recipient, units, intent, chain]

    def check(self, *, agent: str, payer: str, recipient: str, token: str, chain: str, amount: str, intent_id: str,
              expires_at: int, simulate: bool, signature: str) -> PaymentVerdict:
        agent = agent.lower()
        with self.lock:
            try:
                policy = self.policies.get(agent)
                if policy is None:
                    raise Refused("REJECTED_UNKNOWN_AGENT", f"no policy for agent {agent}")
                message = control.request_message(agent=agent, payer=payer, recipient=recipient, token=token, chain=chain,
                                                  amount=amount, intent_id=intent_id, expires_at=expires_at, simulate=simulate)
                if control.signer_of(message, signature) != agent:
                    raise Refused("REJECTED_SIGNATURE", "the request isn't signed by the agent's key")
                units = self._judge(policy, payer.lower(), recipient.lower(), token.lower(), chain, amount, intent_id,
                                    expires_at)
            except Refused as r:
                return PaymentVerdict(False, r.status, r.details, agent, cosigner_address=self.address)

            typed = control.approval_typed_data(agent=agent, payer=payer, recipient=recipient, token=token, chain=chain,
                                                amount_units=units, intent_id=intent_id,
                                                policy_version=policy.policy_version, expires_at=expires_at)
            if simulate:                                # a dry run: judged, not signed, not counted
                return PaymentVerdict(True, "APPROVED", None, agent, typed, None, self.address)
            key = f"{agent}:{intent_id}"
            saved = self.store.get("pay_approved", key)
            if saved is not None:
                if saved["payout"] != [payer.lower(), recipient.lower(), token.lower(), chain, units]:
                    return PaymentVerdict(False, "REJECTED_INTENT_REUSED",
                                          f"intent {intent_id} was approved for a different payout", agent,
                                          cosigner_address=self.address)
                # the same payout asked about again, perhaps after a crash and with a new expiry:
                # signed afresh, counted once
                signed = control.sign_approval(self.account.key, typed)
                self.store.put_many([("pay_approved", key, {**saved, "approval": typed, "signature": signed})])
                return PaymentVerdict(True, "APPROVED", None, agent, typed, signed, self.address)
            signed = control.sign_approval(self.account.key, typed)
            payouts = self._recent(agent) + [[self.clock(), recipient.lower(), units, intent_id, chain]]
            self.store.put_many([
                ("pay_approved", key, {"payout": [payer.lower(), recipient.lower(), token.lower(), chain, units],
                                       "approval": typed, "signature": signed}),
                ("pay_usage", agent, {"payouts": payouts}),
            ])
            self.usage[agent] = payouts
            return PaymentVerdict(True, "APPROVED", None, agent, typed, signed, self.address)

    def activity(self, agent: str) -> dict:
        """The last 24 hours: what was approved, and what's left under each cap."""
        agent = agent.lower()
        with self.lock:
            policy = self.policies.get(agent)
            if policy is None:
                return {}
            recent = self._recent(agent)
        spent = sum(p[2] for p in recent)
        daily = amount_units(policy.daily_cap_usdc)
        by_recipient: dict[str, int] = {}
        for p in recent:
            by_recipient[p[1]] = by_recipient.get(p[1], 0) + p[2]
        usd = lambda units: f"{Decimal(units) / UNITS:.2f}"  # noqa: E731
        return {
            "spent_24h_usdc": usd(spent), "remaining_24h_usdc": usd(max(0, daily - spent)),
            "by_recipient_24h_usdc": {r: usd(u) for r, u in sorted(by_recipient.items(), key=lambda kv: -kv[1])},
            # newest first; entries from before intents were recorded have none
            "approvals": [{"at": int(p[0]), "recipient": p[1], "amount_usdc": usd(p[2]),
                           "intent_id": p[3] if len(p) > 3 else None, "chain": p[4] if len(p) > 4 else None}
                          for p in reversed(recent)],
        }

    def _judge(self, policy: PaymentPolicy, payer: str, recipient: str, token: str, chain: str, amount: str,
               intent_id: str, expires_at: int) -> int:
        if policy.is_killed:
            raise Refused("REJECTED_KILL_SWITCH", "the owner has stopped this agent's payouts")
        if not isinstance(intent_id, str) or not 0 < len(intent_id) <= 128:
            raise Refused("REJECTED_MALFORMED", "intent_id must be 1–128 characters")
        now = self.clock()
        if not isinstance(expires_at, int) or not now < expires_at <= now + MAX_TTL_S:
            raise Refused("REJECTED_EXPIRY", f"expires_at must be within the next {MAX_TTL_S} s")
        if payer not in policy.payers:
            raise Refused("REJECTED_PAYER", f"{payer} isn't one of the owner's listed wallets")
        if chain not in policy.chains:
            raise Refused("REJECTED_CHAIN", f"{chain} isn't one of the owner's chains: {', '.join(policy.chains)}")
        if token not in policy.tokens:
            raise Refused("REJECTED_TOKEN", f"{token} isn't one of the owner's tokens")
        if recipient in (ZERO, payer):
            raise Refused("REJECTED_RECIPIENT", "a payout can't go to the zero address or back to the payer")
        units = amount_units(amount)
        cap = amount_units(policy.max_per_payment_usdc)
        if units > cap:
            raise Refused("REJECTED_PAYMENT_CAP", f"${Decimal(units) / UNITS} is over the cap of ${policy.max_per_payment_usdc} a payment")
        if self.store.get("pay_approved", f"{policy.agent}:{intent_id}") is not None:
            return units                                # already counted; the caller checks it's the same payout
        recent = self._recent(policy.agent)
        spent = sum(p[2] for p in recent)
        if spent + units > amount_units(policy.daily_cap_usdc):
            raise Refused("REJECTED_DAILY_CAP", f"${Decimal(spent + units) / UNITS} in 24 h would be over the daily cap "
                                                f"of ${policy.daily_cap_usdc}")
        to_them = sum(p[2] for p in recent if p[1] == recipient)
        if to_them + units > amount_units(policy.max_per_recipient_daily_usdc):
            raise Refused("REJECTED_RECIPIENT_CAP", f"${Decimal(to_them + units) / UNITS} to {recipient} in 24 h would be over "
                                                    f"the cap of ${policy.max_per_recipient_daily_usdc} per recipient")
        return units
