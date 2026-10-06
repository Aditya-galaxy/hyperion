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

`RpcTokenAccounts` reads which mint a token account holds, for the
instructions that spend a token account without naming its mint (Jupiter's
`route`, Raydium's swaps, a plain token Transfer). An associated token
account's mint is fixed by its address, so those are cached for good. Any
other token account could be closed and opened again for a different mint,
so it's read every time.

The Guard believes its RPC node about a table's contents, as it believes it
about everything else on-chain. Point it at a node you trust.
"""

from __future__ import annotations

import base64
import json
import urllib.request

from .base58 import b58encode
from .decoder import associated_token_address

LOOKUP_TABLE_PROGRAM_ID = "AddressLookupTab1e1111111111111111111111111"
LOOKUP_TABLE_META_SIZE = 56          # header before the 32-byte addresses


def parse_lookup_table(data: bytes) -> list[str]:
    """The addresses in a lookup table account's data, in order."""
    body = data[LOOKUP_TABLE_META_SIZE:]
    if len(data) < LOOKUP_TABLE_META_SIZE or len(body) % 32:
        raise ValueError("not an address lookup table")
    return [b58encode(body[i:i + 32]) for i in range(0, len(body), 32)]


TOKEN_PROGRAM_IDS = ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
TOKEN_ACCOUNT_SIZE = 165             # Token-2022 accounts are longer, with the same first 165 bytes


def parse_token_account(data: bytes) -> tuple[str, str] | None:
    """(mint, owner) of a token account, or None if it isn't an initialized one."""
    if len(data) < TOKEN_ACCOUNT_SIZE or data[108] not in (1, 2):      # state: 1 initialized, 2 frozen
        return None
    return b58encode(data[:32]), b58encode(data[32:64])


def rpc_account(rpc_url: str, address: str, timeout: float) -> dict | None:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
                       "params": [address, {"encoding": "base64", "commitment": "confirmed"}]}).encode()
    req = urllib.request.Request(rpc_url, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r).get("result", {}).get("value")


class RpcTokenAccounts:
    def __init__(self, rpc_url: str, timeout: float = 3.0):
        self.rpc_url = rpc_url
        self.timeout = timeout
        self._fixed: dict[str, str] = {}        # associated token accounts only

    def fetch(self, address: str) -> tuple[str, str] | None:
        value = rpc_account(self.rpc_url, address, self.timeout)
        if not value or value.get("owner") not in TOKEN_PROGRAM_IDS:
            return None
        return parse_token_account(base64.b64decode(value["data"][0]))

    def __call__(self, address: str) -> str | None:
        if address in self._fixed:
            return self._fixed[address]
        found = self.fetch(address)
        if found is None:
            return None
        mint, owner = found
        try:
            if associated_token_address(owner, mint) == address:
                self._fixed[address] = mint
        except ValueError:
            pass
        return mint


class RpcLookupTables:
    def __init__(self, rpc_url: str, timeout: float = 3.0):
        self.rpc_url = rpc_url
        self.timeout = timeout
        self._cache: dict[str, list[str]] = {}

    def fetch(self, table: str) -> list[str] | None:
        value = rpc_account(self.rpc_url, table, self.timeout)
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
