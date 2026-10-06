"""
HYPERION SOLANA GUARD: ADDRESS LOOKUP TABLES
============================================
A v0 transaction names most of its accounts by index into address lookup
tables, which live on-chain, not in the transaction. To know which token a
swap spends, the Guard has to read them.

`RpcLookupTables` fetches a table with getAccountInfo and caches it. A table
is append-only: an address, once at an index, stays there for the table's
life. So a cached table never goes wrong, only short, and it's fetched again
when a transaction uses an index past what's cached.

The Guard believes its RPC node about a table's contents, as it believes it
about everything else on-chain. Point it at a node you trust.
"""

from __future__ import annotations

import base64
import json
import urllib.request

from .base58 import b58encode

LOOKUP_TABLE_PROGRAM_ID = "AddressLookupTab1e1111111111111111111111111"
LOOKUP_TABLE_META_SIZE = 56          # header before the 32-byte addresses


def parse_lookup_table(data: bytes) -> list[str]:
    """The addresses in a lookup table account's data, in order."""
    body = data[LOOKUP_TABLE_META_SIZE:]
    if len(data) < LOOKUP_TABLE_META_SIZE or len(body) % 32:
        raise ValueError("not an address lookup table")
    return [b58encode(body[i:i + 32]) for i in range(0, len(body), 32)]


class RpcLookupTables:
    def __init__(self, rpc_url: str, timeout: float = 3.0):
        self.rpc_url = rpc_url
        self.timeout = timeout
        self._cache: dict[str, list[str]] = {}

    def fetch(self, table: str) -> list[str] | None:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
                           "params": [table, {"encoding": "base64", "commitment": "confirmed"}]}).encode()
        req = urllib.request.Request(self.rpc_url, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            value = json.load(r).get("result", {}).get("value")
        if not value or value.get("owner") != LOOKUP_TABLE_PROGRAM_ID:
            return None
        return parse_lookup_table(base64.b64decode(value["data"][0]))

    def __call__(self, table: str, highest_index: int) -> list[str] | None:
        cached = self._cache.get(table)
        if cached is None or highest_index >= len(cached):
            fetched = self.fetch(table)
            if fetched is None:
                return cached
            self._cache[table] = cached = fetched
        return cached
