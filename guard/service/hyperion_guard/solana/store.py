"""
HYPERION SOLANA GUARD: WHERE ITS STATE LIVES
============================================
What the Guard must not forget across a restart:

  policy     each agent's policy, with its kill switch
  nonce      the highest control-message nonce accepted per agent, so an old
             signed "revive" can't be replayed after a restart
  usage      each agent's recent orders and the last day's spend, so a
             restart doesn't hand back a fresh throttle and daily cap
  approved   the transactions already approved and the signature given, so
             resubmitting one still counts once

A store is a small key-value table per kind. The Guard writes through it on
every change and reads it all back when it starts (approvals are read one at
a time, as they're asked about).

  MemoryStore      nothing survives; the default, and what the tests use
  SqliteStore      one file; for a single host
  FirestoreStore   Google Cloud Firestore; for a hosted Guard whose container
                   has no disk of its own (Cloud Run)

The Guard is written for one running instance. Two instances sharing a store
would each keep their own copy of usage in memory and let more through than
the caps allow; run one.

The co-signing key is not in the store. It comes from the environment
(HYPERION_SOLANA_COSIGNER_KEY), which on a host means a secret manager.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol

KINDS = ("policy", "nonce", "usage", "approved")


class StateStore(Protocol):
    def get(self, kind: str, key: str) -> dict[str, Any] | None: ...
    def put_many(self, items: list[tuple[str, str, dict[str, Any]]]) -> None:
        """Write every (kind, key, value), all or nothing."""
    def items(self, kind: str) -> Iterable[tuple[str, dict[str, Any]]]: ...
    def count(self, kind: str) -> int: ...


class MemoryStore:
    def __init__(self) -> None:
        self.data: dict[str, dict[str, dict[str, Any]]] = {k: {} for k in KINDS}

    def get(self, kind: str, key: str) -> dict[str, Any] | None:
        return self.data[kind].get(key)

    def put_many(self, items: list[tuple[str, str, dict[str, Any]]]) -> None:
        for kind, key, value in items:
            self.data[kind][key] = json.loads(json.dumps(value))       # a copy, as a real store would keep

    def items(self, kind: str) -> Iterable[tuple[str, dict[str, Any]]]:
        return list(self.data[kind].items())

    def count(self, kind: str) -> int:
        return len(self.data[kind])


class SqliteStore:
    def __init__(self, path: Path | str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.lock = threading.Lock()
        with self.conn:
            self.conn.execute("CREATE TABLE IF NOT EXISTS solana_state ("
                              "kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (kind, key))")

    def get(self, kind: str, key: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute("SELECT value FROM solana_state WHERE kind = ? AND key = ?", (kind, key)).fetchone()
        return json.loads(row[0]) if row else None

    def put_many(self, items: list[tuple[str, str, dict[str, Any]]]) -> None:
        with self.lock, self.conn:                                      # one transaction
            self.conn.executemany("INSERT OR REPLACE INTO solana_state (kind, key, value) VALUES (?, ?, ?)",
                                  [(kind, key, json.dumps(value)) for kind, key, value in items])

    def items(self, kind: str) -> Iterable[tuple[str, dict[str, Any]]]:
        with self.lock:
            rows = self.conn.execute("SELECT key, value FROM solana_state WHERE kind = ?", (kind,)).fetchall()
        return [(key, json.loads(value)) for key, value in rows]

    def count(self, kind: str) -> int:
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM solana_state WHERE kind = ?", (kind,)).fetchone()[0]


class FirestoreStore:
    """One collection per kind, named `<prefix>_<kind>`; the document id is the
    key. Needs `google-cloud-firestore` and credentials that can read and
    write the database."""

    def __init__(self, prefix: str = "hyperion_guard_solana", client: Any = None):
        if client is None:
            from google.cloud import (
                firestore,  # imported here: only a hosted Guard needs it
            )
            client = firestore.Client()
        self.client, self.prefix = client, prefix

    def _doc(self, kind: str, key: str) -> Any:
        # a document id can't contain "/"
        return self.client.collection(f"{self.prefix}_{kind}").document(key.replace("/", "_"))

    def get(self, kind: str, key: str) -> dict[str, Any] | None:
        snapshot = self._doc(kind, key).get()
        return json.loads(snapshot.to_dict()["json"]) if snapshot.exists else None

    def put_many(self, items: list[tuple[str, str, dict[str, Any]]]) -> None:
        batch = self.client.batch()                                     # committed together
        for kind, key, value in items:
            # stored as one JSON string, so numbers and lists come back exactly as written
            batch.set(self._doc(kind, key), {"key": key, "json": json.dumps(value)})
        batch.commit()

    def items(self, kind: str) -> Iterable[tuple[str, dict[str, Any]]]:
        out = []
        for snapshot in self.client.collection(f"{self.prefix}_{kind}").stream():
            doc = snapshot.to_dict()
            out.append((doc["key"], json.loads(doc["json"])))
        return out

    def count(self, kind: str) -> int:
        return sum(1 for _ in self.client.collection(f"{self.prefix}_{kind}").select([]).stream())


def store_from_env(value: str | None) -> StateStore:
    """HYPERION_SOLANA_STATE: unset for memory, "firestore" (or
    "firestore:<prefix>"), or a path for a SQLite file."""
    if not value:
        return MemoryStore()
    if value == "firestore" or value.startswith("firestore:"):
        prefix = value.partition(":")[2]
        return FirestoreStore(prefix) if prefix else FirestoreStore()
    return SqliteStore(value)
