"""The payments Guard: approvals for an agent's payouts from a custodial
wallet, what it refuses, and the owner's controls."""

import time

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

from hyperion_guard.api import create_app
from hyperion_guard.payments import control
from hyperion_guard.payments.guard import PaymentGuardEngine
from hyperion_guard.solana.store import SqliteStore

NOW = 1_760_000_000
OWNER, AGENT, GUARDIAN, GUARD = (Account.from_key("0x" + bytes([i]).hex() * 32) for i in range(21, 25))
PAYER = "0x0003a59858f44451be2a5b486ee612b4139700f0"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
ALICE, BOB = "0x" + "a1" * 20, "0x" + "b0" * 20

POLICY = dict(agent=AGENT.address, owner=OWNER.address, guardian=GUARDIAN.address, payers=[PAYER], chains=["base"],
              tokens=[USDC], max_per_payment_usdc=10.0, daily_cap_usdc=25.0, max_per_recipient_daily_usdc=15.0,
              policy_version=1, nonce=1)


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


def make_client(tmp_path, clock):
    engine = PaymentGuardEngine(cosigner_key=GUARD.key, store=SqliteStore(tmp_path / "state.db"), clock=clock)
    return TestClient(create_app(payments_guard=engine))


@pytest.fixture
def client(tmp_path, clock):
    c = make_client(tmp_path, clock)
    assert register(c).status_code == 200
    return c


def register(client, signer=OWNER, **changes):
    body = {**POLICY, **changes}
    message = control.policy_message(**body)
    return client.post("/v1/payments/policy", json={**body, "signature": control.sign_message(signer.key, message)})


def ask(client, *, recipient=ALICE, amount="5.00", intent="pay-sub1-1000", payer=PAYER, token=USDC, chain="base",
        expires_at=NOW + 120, simulate=False, signer=AGENT):
    fields = dict(agent=AGENT.address, payer=payer, recipient=recipient, token=token, chain=chain, amount=amount,
                  intent_id=intent, expires_at=expires_at, simulate=simulate)
    signature = control.sign_message(signer.key, control.request_message(**fields))
    return client.post("/v1/payments/check", json={**fields, "signature": signature}).json()


def control_call(client, action, signer, nonce):
    message = control.action_message(action, AGENT.address, nonce)
    return client.post(f"/v1/payments/{action}", json={"agent": AGENT.address, "nonce": nonce,
                                                       "signature": control.sign_message(signer.key, message)})


def test_an_approval_is_the_guards_signature_over_exactly_that_payout(client):
    v = ask(client, amount="5.5")
    assert v["approved"] and v["status"] == "APPROVED"
    m = v["approval"]["message"]
    assert (m["payer"].lower(), m["recipient"].lower(), m["token"].lower(), m["chain"], m["amount"], m["intentId"]) == \
        (PAYER, ALICE, USDC, "base", 5_500_000, "pay-sub1-1000")
    assert control.approval_signer(v["approval"], v["signature"]) == GUARD.address
    tampered = {**v["approval"], "message": {**m, "amount": 55_000_000}}
    assert control.approval_signer(tampered, v["signature"]) != GUARD.address


@pytest.mark.parametrize("change,status", [
    ({"amount": "10.01"}, "REJECTED_PAYMENT_CAP"),
    ({"amount": "0"}, "REJECTED_MALFORMED"),
    ({"amount": "1.0000001"}, "REJECTED_MALFORMED"),
    ({"payer": "0x" + "cc" * 20}, "REJECTED_PAYER"),
    ({"chain": "ethereum"}, "REJECTED_CHAIN"),
    ({"token": "0x" + "dd" * 20}, "REJECTED_TOKEN"),
    ({"recipient": "0x" + "00" * 20}, "REJECTED_RECIPIENT"),
    ({"recipient": PAYER}, "REJECTED_RECIPIENT"),
    ({"expires_at": NOW + 3600}, "REJECTED_EXPIRY"),
    ({"expires_at": NOW}, "REJECTED_EXPIRY"),
    ({"signer": GUARDIAN}, "REJECTED_SIGNATURE"),
])
def test_what_it_refuses(client, change, status):
    v = ask(client, **change)
    assert (v["approved"], v["status"], v["signature"]) == (False, status, None), v


def test_daily_caps_overall_and_per_recipient(client, clock):
    assert ask(client, amount="10", intent="a")["approved"]
    assert ask(client, amount="5", intent="b")["approved"]                   # $15 to Alice
    assert ask(client, amount="1", intent="c")["status"] == "REJECTED_RECIPIENT_CAP"
    assert ask(client, amount="10", intent="d", recipient=BOB)["approved"]   # $25 in all
    assert ask(client, amount="1", intent="e", recipient=BOB)["status"] == "REJECTED_DAILY_CAP"
    clock.now += 86_401                                                      # a day later the window has moved on
    assert ask(client, amount="10", intent="f", expires_at=clock.now + 60)["approved"]


def test_one_intent_is_one_payout(client, clock):
    first = ask(client, amount="10", intent="pay-1")
    again = ask(client, amount="10", intent="pay-1")                        # a retry: approved, counted once
    assert again["approved"] and again["approval"] == first["approval"]
    clock.now += 200                                                         # retried after the first approval expired
    later = ask(client, amount="10", intent="pay-1", expires_at=clock.now + 60)
    assert later["approved"] and later["approval"]["message"]["expiresAt"] == clock.now + 60
    assert ask(client, amount="5", intent="pay-2", expires_at=clock.now + 60)["approved"]   # $15: the $10 counted once
    reused = ask(client, amount="9", intent="pay-1", expires_at=clock.now + 60)
    assert reused["status"] == "REJECTED_INTENT_REUSED"


def test_a_simulation_is_judged_but_not_signed_or_counted(client):
    sim = ask(client, amount="10", intent="dry", simulate=True)
    assert sim["approved"] and sim["signature"] is None
    assert ask(client, amount="10", intent="real-1")["approved"]
    assert ask(client, amount="5", intent="real-2")["approved"]              # the simulated $10 didn't count
    assert ask(client, amount="20", intent="dry-2", simulate=True)["status"] == "REJECTED_PAYMENT_CAP"


def test_the_kill_switch(client):
    assert control_call(client, "kill", GUARDIAN, 2).status_code == 200
    assert ask(client)["status"] == "REJECTED_KILL_SWITCH"
    assert control_call(client, "revive", GUARDIAN, 3).status_code == 403
    assert control_call(client, "revive", OWNER, 2).status_code == 409
    assert control_call(client, "revive", OWNER, 3).status_code == 200
    assert ask(client)["approved"]


def test_policy_updates(client):
    assert register(client, signer=AGENT).status_code == 401
    thief = Account.create()
    assert register(client, owner=thief.address, signer=thief, policy_version=2, nonce=2).status_code == 403
    assert register(client, policy_version=1, nonce=2).status_code == 409
    assert register(client, policy_version=2, nonce=1).status_code == 409
    assert register(client, policy_version=2, nonce=2, max_per_payment_usdc=3.0).status_code == 200
    assert ask(client, amount="5")["status"] == "REJECTED_PAYMENT_CAP"
    assert register(client, owner=AGENT.address, signer=AGENT, policy_version=3, nonce=3).status_code == 422


def test_state_survives_a_restart(tmp_path, clock):
    first = make_client(tmp_path, clock)
    register(first)
    assert ask(first, amount="10", intent="a")["approved"]
    control_call(first, "kill", OWNER, 4)
    again = make_client(tmp_path, clock)
    assert again.get(f"/v1/payments/policy/{AGENT.address}").json()["killed"] is True
    assert control_call(again, "revive", OWNER, 4).status_code == 409
    control_call(again, "revive", OWNER, 5)
    assert ask(again, amount="5", intent="b")["approved"]
    assert ask(again, amount="1", intent="c")["status"] == "REJECTED_RECIPIENT_CAP"   # $15 to Alice, remembered


def test_the_owner_command_line(tmp_path, clock, monkeypatch, capsys):
    from hyperion_guard.payments import owner as cli
    c = make_client(tmp_path, clock)
    monkeypatch.setattr(cli.httpx, "get", lambda url, **kw: c.get(url.removeprefix("https://g")))
    monkeypatch.setattr(cli.httpx, "post", lambda url, json, **kw: c.post(url.removeprefix("https://g"), json=json))
    key = tmp_path / "owner.key"
    cli.main(["new-key", str(key)])
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    with pytest.raises(SystemExit):
        cli.main(["new-key", str(key)])                                      # never overwrites a key
    policy = ["--guard", "https://g", "policy", "--key-file", str(key), "--agent", AGENT.address, "--payers", PAYER,
              "--chains", "base", "--tokens", USDC, "--max-per-payment", "10", "--daily-cap", "25",
              "--max-per-recipient-daily", "15"]
    cli.main(policy)
    cli.main(policy[:-1] + ["20"])                                           # an update: the version goes up by itself
    assert c.get(f"/v1/payments/policy/{AGENT.address}").json()["policy_version"] == 2
    cli.main(["--guard", "https://g", "kill", "--key-file", str(key), "--agent", AGENT.address])
    assert ask(c)["status"] == "REJECTED_KILL_SWITCH"
    time.sleep(0.002)
    cli.main(["--guard", "https://g", "revive", "--key-file", str(key), "--agent", AGENT.address])
    assert ask(c)["approved"]
