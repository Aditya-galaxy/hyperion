"""
A restart forgets nothing: policies and the kill switch, control-message
nonces, the throttle and the day's spend, the transactions already approved,
and the co-signing key.
"""

from __future__ import annotations

import os

import pytest
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from fastapi.testclient import TestClient
from hyperion_guard.api import create_app
from hyperion_guard.solana import vault as v
from hyperion_guard.solana.base58 import b58encode
from hyperion_guard.solana.control import action_message, policy_message
from hyperion_guard.solana.guard import SolanaAgentPolicy, SolanaGuardEngine
from hyperion_guard.solana.store import (
    FirestoreStore,
    MemoryStore,
    SqliteStore,
    store_from_env,
)
from hyperion_guard.solana.tx import compile_message, pubkey, serialize, sign

VAULT_PID = b58encode(bytes([7] * 32))
SOL = 1_000_000_000
SEED = bytes(range(32))


class FakeFirestore:
    """The few calls FirestoreStore makes, over a dict."""

    def __init__(self):
        self.docs: dict[tuple[str, str], dict] = {}

    def collection(self, name):
        client = self

        class Collection:
            def document(self, doc_id):
                assert "/" not in doc_id
                return (name, doc_id)

            def stream(self):
                return [Snapshot(value) for (coll, _), value in client.docs.items() if coll == name]

            def select(self, fields):
                return self
        return Collection()

    def batch(self):
        client, pending = self, []

        class Batch:
            def set(self, ref, value):
                pending.append((ref, value))

            def commit(self):
                client.docs.update(dict(pending))
        return Batch()


class Snapshot:
    def __init__(self, value):
        self.exists, self._value = value is not None, value

    def to_dict(self):
        return self._value


def fake_firestore_store():
    client = FakeFirestore()
    store = FirestoreStore("test", client=client)
    store._doc = lambda kind, key: type("Ref", (), {       # a reference that reads from the dict
        "get": lambda self: Snapshot(client.docs.get((f"test_{kind}", key.replace("/", "_")))),
        "__hash__": lambda self: hash((f"test_{kind}", key.replace("/", "_"))),
        "__eq__": lambda self, other: hash(self) == hash(other),
    })()
    real_batch = client.batch

    def batch():
        b = real_batch()
        inner_set = b.set
        b.set = lambda ref, value: inner_set((f"test_{ref_kind(ref)}", ref_key(ref)), value)
        return b
    refs: dict[int, tuple[str, str]] = {}
    make = store._doc

    def doc(kind, key):
        ref = make(kind, key)
        refs[id(ref)] = (kind, key.replace("/", "_"))
        return ref
    ref_kind, ref_key = (lambda r: refs[id(r)][0]), (lambda r: refs[id(r)][1])
    store._doc = doc
    client.batch = batch
    return store


@pytest.fixture(params=["memory", "sqlite", "firestore"])
def store(request, tmp_path):
    if request.param == "memory":
        return MemoryStore()
    if request.param == "sqlite":
        return SqliteStore(tmp_path / "state" / "guard.db")
    return fake_firestore_store()


def test_a_store_keeps_what_its_given(store):
    assert store.get("policy", "a") is None and store.count("policy") == 0
    store.put_many([("policy", "a", {"x": 1, "list": [1.5, "two"]}), ("nonce", "a", {"nonce": 7}),
                    ("approved", "a:ab/cd", {"signature": "s"})])
    assert store.get("policy", "a") == {"x": 1, "list": [1.5, "two"]}
    assert store.get("approved", "a:ab/cd") == {"signature": "s"}
    store.put_many([("policy", "a", {"x": 2}), ("policy", "b", {"x": 3})])
    assert dict(store.items("policy")) == {"a": {"x": 2}, "b": {"x": 3}}
    assert (store.count("policy"), store.count("nonce"), store.count("usage")) == (2, 1, 0)


def test_store_from_env(tmp_path, monkeypatch):
    assert isinstance(store_from_env(None), MemoryStore) and isinstance(store_from_env(""), MemoryStore)
    assert isinstance(store_from_env(str(tmp_path / "g.db")), SqliteStore)
    monkeypatch.setattr(FirestoreStore, "__init__", lambda self, prefix="hyperion_guard_solana", client=None:
                        setattr(self, "prefix", prefix))
    assert store_from_env("firestore").prefix == "hyperion_guard_solana"
    assert store_from_env("firestore:staging").prefix == "staging"


@pytest.fixture
def world(store):
    v.register_vault_program(VAULT_PID)
    agent_key = ECC.generate(curve="ed25519")
    agent, owner = pubkey(agent_key), b58encode(os.urandom(32))

    def start() -> SolanaGuardEngine:
        """Start the Guard, as after a restart: same key, same store, nothing else carried over."""
        return SolanaGuardEngine(cosigner_private_key_bytes=SEED, store=store)

    guard = start()
    vault, _ = v.vault_address(VAULT_PID, owner, agent)
    guard.set_policy(SolanaAgentPolicy(agent_id="a", owner_solana_pubkey=owner, agent_solana_pubkey=agent,
                                       max_order_notional_usd=100.0, daily_notional_cap_usd=40.0,
                                       max_orders_per_minute=3, allowed_programs=[VAULT_PID], vault_address=vault))

    def payment(lamports: int = SOL // 10):                         # 0.1 SOL = $15
        ix = v.transfer_sol(VAULT_PID, vault, agent, guard.pubkey_b58, b58encode(os.urandom(32)), lamports)
        msg, keys, n = compile_message([ix], agent, b58encode(os.urandom(32)))
        return serialize(msg, keys, n, {agent: sign(msg, agent_key)})
    return {"start": start, "guard": guard, "payment": payment, "store": store, "vault": vault}


def ask(guard, raw):
    return guard.evaluate_transaction("a", raw, sol_price_usd=150.0)


def test_the_cosigning_key_is_the_one_its_given(world):
    assert world["start"]().pubkey_b58 == world["guard"].pubkey_b58 == pubkey(eddsa.import_private_key(SEED))
    assert SolanaGuardEngine().pubkey_b58 != SolanaGuardEngine().pubkey_b58          # made up when none is given


def test_a_policy_survives_a_restart(world):
    restarted = world["start"]()
    policy = restarted.get_policy("a")
    assert policy == world["guard"].get_policy("a")
    assert (policy.vault_address, policy.allowed_programs, policy.daily_notional_cap_usd) == (
        world["vault"], [VAULT_PID], 40.0)
    assert ask(restarted, world["payment"]()).approved


def test_a_kill_survives_a_restart_and_so_does_a_revive(world):
    assert world["guard"].kill_agent("a")
    restarted = world["start"]()
    assert restarted.get_policy("a").is_killed
    assert ask(restarted, world["payment"]()).status == "REJECTED_KILL_SWITCH"
    assert restarted.revive_agent("a")
    assert ask(world["start"](), world["payment"]()).approved


def test_a_used_nonce_stays_used_after_a_restart(world):
    """Otherwise an old signed revive could bring back an agent killed since."""
    guard = world["guard"]
    assert guard.revive_agent("a", nonce=5)                         # the owner's revive, nonce 5
    assert guard.kill_agent("a", nonce=6)                           # then the guardian's kill
    restarted = world["start"]()
    assert not restarted.revive_agent("a", nonce=5)                 # the old revive, replayed
    assert not restarted.consume_nonce("a", 6)
    assert restarted.get_policy("a").is_killed
    assert restarted.revive_agent("a", nonce=7)


def test_the_days_spend_and_the_throttle_survive_a_restart(world):
    """Otherwise restarting the Guard would hand every agent a fresh daily cap."""
    assert ask(world["guard"], world["payment"]()).approved         # $15
    assert ask(world["guard"], world["payment"]()).approved         # $30 of a $40 day
    restarted = world["start"]()
    over = ask(restarted, world["payment"]())                       # $45
    assert (over.approved, over.status) == (False, "REJECTED_DAILY_CAP")

    raised = restarted.get_policy("a")
    raised.daily_notional_cap_usd = 1_000.0                         # the owner makes room in the day
    restarted.set_policy(raised)
    assert ask(restarted, world["payment"]()).approved              # the third order this minute
    again = world["start"]()
    assert again.get_policy("a").daily_notional_cap_usd == 1_000.0
    assert ask(again, world["payment"]()).status == "REJECTED_THROTTLE_LIMIT"       # three a minute, restart or not


def test_an_approval_is_remembered_after_a_restart(world):
    raw = world["payment"]()
    first = ask(world["guard"], raw)
    restarted = world["start"]()
    again = ask(restarted, raw)
    assert (again.approved, again.cosigner_signature_b58) == (True, first.cosigner_signature_b58)
    assert len(restarted.daily_spend_tracker["a"]) == 1             # and not counted a second time
    assert world["store"].count("approved") == 1


class FailingStore(MemoryStore):
    broken = False

    def put_many(self, items):
        if self.broken:
            raise OSError("store unreachable")
        super().put_many(items)


def test_nothing_is_approved_if_it_cant_be_recorded():
    v.register_vault_program(VAULT_PID)
    store, agent_key = FailingStore(), ECC.generate(curve="ed25519")
    agent, owner = pubkey(agent_key), b58encode(os.urandom(32))
    guard = SolanaGuardEngine(cosigner_private_key_bytes=SEED, store=store)
    vault, _ = v.vault_address(VAULT_PID, owner, agent)
    policy = SolanaAgentPolicy(agent_id="a", owner_solana_pubkey=owner, agent_solana_pubkey=agent,
                               allowed_programs=[VAULT_PID], vault_address=vault)
    assert guard.set_policy(policy, nonce=1)
    ix = v.transfer_sol(VAULT_PID, vault, agent, guard.pubkey_b58, b58encode(os.urandom(32)), 5)
    msg, keys, n = compile_message([ix], agent, b58encode(os.urandom(32)))
    raw = serialize(msg, keys, n, {agent: sign(msg, agent_key)})

    store.broken = True
    with pytest.raises(OSError):
        ask(guard, raw)                                             # no verdict, so no signature
    assert guard.order_timestamps.get("a", []) == [] and guard.approved_messages.get("a", {}) == {}
    with pytest.raises(OSError):
        guard.kill_agent("a", nonce=2)
    assert not guard.get_policy("a").is_killed and guard.last_nonce["a"] == 1       # neither half happened
    with pytest.raises(OSError):
        guard.set_policy(SolanaAgentPolicy(agent_id="b", owner_solana_pubkey=owner), nonce=1)
    assert guard.get_policy("b") is None and "b" not in guard.last_nonce

    store.broken = False
    assert ask(guard, raw).approved


def signed(key, message: bytes) -> str:
    return b58encode(sign(message, key))


def test_the_hosted_api_restarts_with_its_key_and_its_agents(tmp_path, monkeypatch):
    owner_key, agent_key = ECC.generate(curve="ed25519"), ECC.generate(curve="ed25519")
    owner, agent = pubkey(owner_key), pubkey(agent_key)
    monkeypatch.setenv("HYPERION_SOLANA_COSIGNER_KEY", SEED.hex())
    monkeypatch.setenv("HYPERION_SOLANA_STATE", str(tmp_path / "guard.db"))
    monkeypatch.setenv("HYPERION_VAULT_PROGRAM_ID", VAULT_PID)
    monkeypatch.setenv("HYPERION_SOLANA_MAX_AGENTS", "1")

    def policy_body(agent_id: str, nonce: int, version: int) -> dict:
        fields = {"agent_id": agent_id, "owner": owner, "guardian": "", "max_order_notional_usd": 100.0,
                  "max_slippage_bps": 100, "policy_version": version, "nonce": nonce, "require_guard_signer": True,
                  "allowed_programs": [VAULT_PID]}
        return {"agent_id": agent_id, "agent_solana_pubkey": agent, "owner_solana_pubkey": owner,
                "max_order_notional_usd": 100.0, "max_slippage_bps": 100, "policy_version": version, "nonce": nonce,
                "allowed_programs": [VAULT_PID],
                "signature_b58": signed(owner_key, policy_message(agent=agent, **fields))}

    first = TestClient(create_app())
    cosigner = first.get("/v1/solana/health").json()["cosigner_pubkey"]
    assert first.post("/v1/solana/policy", json=policy_body("a", 1, 1)).status_code == 200
    assert first.post("/v1/solana/policy", json=policy_body("b", 1, 1)).status_code == 507     # the limit is one agent
    assert first.post("/v1/solana/kill", json={
        "agent_id": "a", "caller_pubkey": owner, "nonce": 2,
        "signature_b58": signed(owner_key, action_message("kill", "a", 2))}).status_code == 200

    restarted = TestClient(create_app())                            # a new process: same environment, nothing else
    assert restarted.get("/v1/solana/health").json()["cosigner_pubkey"] == cosigner
    saved = restarted.get("/v1/solana/policy/a").json()
    assert (saved["killed"], saved["agent_solana_pubkey"], saved["allowed_programs"]) == (True, agent, [VAULT_PID])
    replay = restarted.post("/v1/solana/policy", json=policy_body("a", 1, 2))
    assert replay.status_code == 409                                # nonce 1 was used before the restart
    assert restarted.post("/v1/solana/policy", json=policy_body("a", 3, 2)).status_code == 200
