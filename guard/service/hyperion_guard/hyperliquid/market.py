"""
HYPERION HYPERLIQUID GUARD: WHAT IT KNOWS ABOUT THE MARKET
==========================================================
An order names its market by number: the asset id is the market's position
in the perp universe, which differs between mainnet and testnet (BTC is 0 on
one, 3 on the other). The Guard reads the universe and the mid prices from
Hyperliquid's public info API, for the network the agent's policy names.

If it can't read them it can't size an order, and it refuses: a Guard that
can't see the market doesn't sign.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

import httpx

API = {"mainnet": "https://api.hyperliquid.xyz", "testnet": "https://api.hyperliquid-testnet.xyz"}
META_TTL_S = 60.0           # markets are listed rarely
MIDS_TTL_S = 1.0            # prices move


class MarketUnavailable(Exception):
    """The Guard can't read the market right now."""


@dataclass(frozen=True)
class Perp:
    asset: int
    coin: str
    sz_decimals: int
    max_leverage: int
    delisted: bool = False


class Market(Protocol):
    def perp(self, network: str, asset: int) -> Perp | None: ...
    def mid(self, network: str, coin: str) -> Decimal | None: ...
    def signers(self, network: str, account: str) -> tuple[list[str], int] | None: ...


class HyperliquidMarket:
    def __init__(self, api: dict[str, str] | None = None, timeout_s: float = 3.0, client: httpx.Client | None = None):
        self.api = api or API
        self.client = client or httpx.Client(timeout=timeout_s, headers={"user-agent": "hyperion-guard"})
        self.lock = threading.Lock()
        self.meta: dict[str, tuple[float, list[Perp]]] = {}
        self.mids: dict[str, tuple[float, dict[str, Decimal]]] = {}

    def _info(self, network: str, body: dict) -> object:
        if network not in self.api:
            raise MarketUnavailable(f"unknown network {network!r}")
        try:
            res = self.client.post(self.api[network] + "/info", json=body)
            res.raise_for_status()
            return res.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise MarketUnavailable(f"can't read Hyperliquid {network}: {exc}") from None

    def _universe(self, network: str) -> list[Perp]:
        with self.lock:
            cached = self.meta.get(network)
            if cached and time.monotonic() - cached[0] < META_TTL_S:
                return cached[1]
        meta = self._info(network, {"type": "meta"})
        perps = [Perp(asset=i, coin=m["name"], sz_decimals=int(m["szDecimals"]), max_leverage=int(m["maxLeverage"]),
                      delisted=bool(m.get("isDelisted", False)))
                 for i, m in enumerate(meta["universe"])]  # type: ignore[index]
        with self.lock:
            self.meta[network] = (time.monotonic(), perps)
        return perps

    def perp(self, network: str, asset: int) -> Perp | None:
        universe = self._universe(network)
        return universe[asset] if 0 <= asset < len(universe) else None

    def mid(self, network: str, coin: str) -> Decimal | None:
        with self.lock:
            cached = self.mids.get(network)
        if not cached or time.monotonic() - cached[0] >= MIDS_TTL_S:
            raw = self._info(network, {"type": "allMids"})
            cached = (time.monotonic(), {k: Decimal(v) for k, v in raw.items()})  # type: ignore[union-attr]
            with self.lock:
                self.mids[network] = cached
        return cached[1].get(coin)

    def signers(self, network: str, account: str) -> tuple[list[str], int] | None:
        """A multi-sig account's authorized users (lower-case) and threshold; None if it isn't one."""
        raw = self._info(network, {"type": "userToMultiSigSigners", "user": account.lower()})
        if not raw:
            return None
        return [u.lower() for u in raw["authorizedUsers"]], int(raw["threshold"])  # type: ignore[index]
