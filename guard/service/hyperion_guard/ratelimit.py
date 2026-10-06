"""
HYPERION GUARD: RATE LIMITS FOR A PUBLIC API
============================================
A Guard reachable from the internet answers anyone. The signatures decide who
may change a policy or have a transaction judged; these limits decide how
often anyone may ask, so one caller can't crowd out the rest or run up the
store's bill.

Three limits, each a number of requests in any 60 seconds, each off unless set:

    HYPERION_RATE_LIMIT           per client, all requests
    HYPERION_RATE_LIMIT_WRITES    per client, requests that write to the store:
                                  setting a policy, kill, revive
    HYPERION_RATE_LIMIT_GLOBAL    all clients together

A client is its IP address. Behind a proxy every request seems to come from
the proxy, so:

    HYPERION_TRUSTED_PROXIES      how many proxies stand in front (Cloud Run: 1)

With n trusted proxies the client is the n-th address from the right of
X-Forwarded-For: each proxy appends the address it saw, so those are the ones
a caller can't forge. Addresses further left are whatever the caller sent.

Counts are kept in this process. That fits a Guard run as one instance, which
the Solana Guard already must be.
"""

from __future__ import annotations

import os
import time
from collections import OrderedDict, deque
from collections.abc import Callable

WINDOW = 60.0


class RateLimiter:
    """At most `limit` events per key in any WINDOW seconds."""

    def __init__(self, limit: int, clock: Callable[[], float] = time.monotonic, max_keys: int = 20_000):
        self.limit, self.clock, self.max_keys = limit, clock, max_keys
        self.events: OrderedDict[str, deque[float]] = OrderedDict()

    def allow(self, key: str) -> tuple[bool, float]:
        """(allowed, seconds until the next one would be). An allowed request is counted."""
        now = self.clock()
        seen = self.events.get(key)
        if seen is None:
            seen = self.events[key] = deque()
            if len(self.events) > self.max_keys:        # a flood of addresses can't grow this without bound
                self.events.popitem(last=False)
        else:
            self.events.move_to_end(key)
        while seen and now - seen[0] >= WINDOW:
            seen.popleft()
        if len(seen) >= self.limit:
            return False, WINDOW - (now - seen[0])
        seen.append(now)
        return True, 0.0


def client_address(peer: str | None, forwarded_for: str | None, trusted_proxies: int) -> str:
    """The caller's address: the connection's peer, or with trusted proxies in
    front, the address the outermost of them saw."""
    if trusted_proxies > 0 and forwarded_for:
        hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
        if len(hops) >= trusted_proxies:
            return hops[-trusted_proxies]
    return peer or "unknown"


def is_write(method: str, path: str) -> bool:
    """Requests that change what the Guard has stored."""
    return method == "POST" and not path.rstrip("/").endswith("/check")


class Limits:
    def __init__(self, per_client: int = 0, writes_per_client: int = 0, overall: int = 0, trusted_proxies: int = 0,
                 clock: Callable[[], float] = time.monotonic):
        self.trusted_proxies = trusted_proxies
        self.per_client = RateLimiter(per_client, clock) if per_client > 0 else None
        self.writes = RateLimiter(writes_per_client, clock) if writes_per_client > 0 else None
        self.overall = RateLimiter(overall, clock, max_keys=1) if overall > 0 else None

    @classmethod
    def from_env(cls) -> Limits:
        def number(name: str) -> int:
            return int(os.environ.get(name, "0") or 0)
        return cls(number("HYPERION_RATE_LIMIT"), number("HYPERION_RATE_LIMIT_WRITES"),
                   number("HYPERION_RATE_LIMIT_GLOBAL"), number("HYPERION_TRUSTED_PROXIES"))

    @property
    def enabled(self) -> bool:
        return bool(self.per_client or self.writes or self.overall)

    def check(self, method: str, path: str, peer: str | None, forwarded_for: str | None) -> tuple[str, float] | None:
        """None if the request may go ahead, else (which limit, seconds to wait).
        The caller's own limits are tried first, so a caller over its limit
        doesn't use up everyone's."""
        client = client_address(peer, forwarded_for, self.trusted_proxies)
        tests = [(self.writes if is_write(method, path) else None, client, "writes from this address"),
                 (self.per_client, client, "requests from this address"),
                 (self.overall, "all", "requests to this Guard")]
        for limiter, key, what in tests:
            if limiter is not None:
                allowed, wait = limiter.allow(key)
                if not allowed:
                    return what, wait
        return None
