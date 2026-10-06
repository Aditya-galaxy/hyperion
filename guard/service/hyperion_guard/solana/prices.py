"""
HYPERION SOLANA GUARD: TOKEN PRICES
===================================
What a token is worth in dollars, and how many decimals it has, so the Guard
can hold a swap or transfer of any priced token to the owner's dollar caps.

`JupiterTokenPrices` asks Jupiter's price API. Three rules keep a bad answer
from becoming an approval:

  * no answer is no price. A failed or malformed request isn't papered over
    with an old figure; the Guard refuses what it can't price;
  * a price is used for `ttl` seconds and then asked for again;
  * a token with less than `min_liquidity_usd` behind its price has no price.
    A thin market's price is cheap to push around, and a price pushed down
    would let a large sale through under the cap.

`FixedTokenPrices` is for tests and demos.

The Guard believes this source about prices, as it believes its RPC node
about the chain. USDC and USDT don't come through here: they're taken at $1.
"""

from __future__ import annotations

import json
import math
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class TokenPrice:
    usd: float          # dollars for one whole token
    decimals: int

    def value(self, raw_amount: int) -> float:
        return raw_amount / 10 ** self.decimals * self.usd


class TokenPrices(Protocol):
    def price(self, mint: str) -> TokenPrice | None: ...


class FixedTokenPrices:
    def __init__(self, prices: dict[str, TokenPrice | tuple[float, int]]):
        self.prices = {mint: p if isinstance(p, TokenPrice) else TokenPrice(*p) for mint, p in prices.items()}

    def price(self, mint: str) -> TokenPrice | None:
        return self.prices.get(mint)


class JupiterTokenPrices:
    URL = "https://lite-api.jup.ag/price/v3"

    def __init__(self, url: str = URL, ttl: float = 10.0, timeout: float = 2.0, min_liquidity_usd: float = 100_000.0,
                 clock: Callable[[], float] = time.monotonic):
        self.url, self.ttl, self.timeout, self.min_liquidity_usd, self.clock = url, ttl, timeout, min_liquidity_usd, clock
        self._cache: dict[str, tuple[float, TokenPrice | None]] = {}

    def fetch(self, mint: str) -> dict | None:
        """The API's entry for `mint`, or None if it has none. Raises on a failed request."""
        # the API turns away Python's default user agent
        req = urllib.request.Request(f"{self.url}?ids={urllib.parse.quote(mint)}",
                                     headers={"User-Agent": "hyperion-guard", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.load(r).get(mint)

    def price(self, mint: str) -> TokenPrice | None:
        now = self.clock()
        cached = self._cache.get(mint)
        if cached and now - cached[0] < self.ttl:
            return cached[1]
        try:
            entry = self.fetch(mint)
            price = self._read(entry) if entry else None
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            self._cache.pop(mint, None)         # no answer: no price, and nothing stale to fall back on
            return None
        self._cache[mint] = (now, price)
        return price

    def _read(self, entry: dict) -> TokenPrice | None:
        usd, decimals, liquidity = float(entry["usdPrice"]), entry["decimals"], float(entry.get("liquidity") or 0)
        if not (math.isfinite(usd) and usd > 0) or not isinstance(decimals, int) or not 0 <= decimals <= 18:
            raise ValueError(f"unusable price entry: {entry}")
        if liquidity < self.min_liquidity_usd:
            return None
        return TokenPrice(usd, decimals)
