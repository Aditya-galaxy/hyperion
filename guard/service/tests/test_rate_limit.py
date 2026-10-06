"""
Rate limits for a Guard on the public internet: per caller, stricter for
requests that write, and overall. The caller is the address a trusted proxy
saw, not whatever the caller claims.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from hyperion_guard.api import create_app
from hyperion_guard.ratelimit import Limits, RateLimiter, client_address, is_write


def test_a_limiter_allows_so_many_in_any_minute():
    now = [0.0]
    limiter = RateLimiter(3, clock=lambda: now[0])
    assert [limiter.allow("a")[0] for _ in range(4)] == [True, True, True, False]
    assert limiter.allow("b") == (True, 0.0)                    # another caller is unaffected
    now[0] = 59.9
    allowed, wait = limiter.allow("a")
    assert not allowed and wait == pytest.approx(0.1)
    now[0] = 60.0                                               # the first three have aged out
    assert [limiter.allow("a")[0] for _ in range(4)] == [True, True, True, False]


def test_a_refused_request_isnt_counted():
    now = [0.0]
    limiter = RateLimiter(1, clock=lambda: now[0])
    assert limiter.allow("a")[0]
    for t in (10.0, 20.0, 59.0):                                # hammering doesn't push the wait back
        now[0] = t
        assert not limiter.allow("a")[0]
    now[0] = 60.0
    assert limiter.allow("a")[0]


def test_a_flood_of_addresses_doesnt_grow_without_bound():
    limiter = RateLimiter(5, clock=lambda: 0.0, max_keys=100)
    for i in range(10_000):
        limiter.allow(f"10.0.{i // 256}.{i % 256}")
    assert len(limiter.events) == 100


@pytest.mark.parametrize(("peer", "forwarded", "proxies", "expected"), [
    ("9.9.9.9", None, 0, "9.9.9.9"),
    ("9.9.9.9", "1.1.1.1", 0, "9.9.9.9"),                       # no proxy trusted: the header is just a claim
    ("10.0.0.1", "203.0.113.7", 1, "203.0.113.7"),              # Cloud Run: the proxy appended what it saw
    ("10.0.0.1", "1.1.1.1, 203.0.113.7", 1, "203.0.113.7"),     # the caller put 1.1.1.1 in front: ignored
    ("10.0.0.1", "1.1.1.1, 203.0.113.7, 10.0.0.9", 2, "203.0.113.7"),
    ("10.0.0.1", "203.0.113.7", 2, "10.0.0.1"),                 # fewer hops than proxies: not what was promised
    ("10.0.0.1", "", 1, "10.0.0.1"),
    (None, None, 0, "unknown"),
])
def test_the_client_is_the_address_a_trusted_proxy_saw(peer, forwarded, proxies, expected):
    assert client_address(peer, forwarded, proxies) == expected


def test_which_requests_write():
    assert is_write("POST", "/v1/solana/policy") and is_write("POST", "/v1/solana/kill")
    assert is_write("POST", "/v1/solana/revive") and is_write("POST", "/v1/policy/")
    assert not is_write("POST", "/v1/solana/check") and not is_write("POST", "/v1/check/")
    assert not is_write("GET", "/v1/solana/policy/agent-1")


def test_limits_are_off_unless_set(monkeypatch):
    for name in ("HYPERION_RATE_LIMIT", "HYPERION_RATE_LIMIT_WRITES", "HYPERION_RATE_LIMIT_GLOBAL",
                 "HYPERION_TRUSTED_PROXIES"):
        monkeypatch.delenv(name, raising=False)
    assert not Limits.from_env().enabled
    client = TestClient(create_app())
    assert all(client.get("/v1/solana/health").status_code == 200 for _ in range(300))

    monkeypatch.setenv("HYPERION_RATE_LIMIT", "5")
    monkeypatch.setenv("HYPERION_TRUSTED_PROXIES", "1")
    limits = Limits.from_env()
    assert (limits.enabled, limits.per_client.limit, limits.writes, limits.trusted_proxies) == (True, 5, None, 1)


def get(client: TestClient, caller: str, path: str = "/v1/solana/health"):
    return client.get(path, headers={"X-Forwarded-For": caller})


def test_one_caller_over_its_limit_gets_429_and_others_dont():
    client = TestClient(create_app(limits=Limits(per_client=3, trusted_proxies=1)))
    assert [get(client, "203.0.113.7").status_code for _ in range(4)] == [200, 200, 200, 429]
    refused = get(client, "203.0.113.7")
    assert refused.status_code == 429 and 1 <= int(refused.headers["Retry-After"]) <= 60
    assert "requests from this address" in refused.json()["detail"]
    assert get(client, "198.51.100.2").status_code == 200       # someone else


def test_a_forged_header_doesnt_get_a_fresh_allowance():
    client = TestClient(create_app(limits=Limits(per_client=2, trusted_proxies=1)))
    codes = [get(client, f"{i}.{i}.{i}.{i}, 203.0.113.7").status_code for i in range(1, 5)]
    assert codes == [200, 200, 429, 429]                        # the proxy saw the same caller every time


def test_writes_have_their_own_tighter_limit():
    client = TestClient(create_app(limits=Limits(per_client=100, writes_per_client=2, trusted_proxies=1)))
    caller = {"X-Forwarded-For": "203.0.113.7"}
    writes = [client.post("/v1/solana/policy", json={}, headers=caller).status_code for _ in range(4)]
    assert writes == [422, 422, 429, 429]                       # the first two reached the endpoint and were judged
    assert "writes from this address" in client.post("/v1/solana/kill", json={}, headers=caller).json()["detail"]
    assert client.post("/v1/solana/check", json={}, headers=caller).status_code == 422      # a check isn't a write
    assert get(client, "203.0.113.7").status_code == 200


def test_the_overall_limit_covers_everyone_together():
    client = TestClient(create_app(limits=Limits(per_client=2, overall=5, trusted_proxies=1)))
    codes = [get(client, f"203.0.113.{i}").status_code for i in range(7)]
    assert codes == [200] * 5 + [429] * 2
    assert "requests to this Guard" in get(client, "203.0.113.99").json()["detail"]


def test_a_caller_over_its_own_limit_doesnt_use_up_everyones():
    client = TestClient(create_app(limits=Limits(per_client=1, overall=3, trusted_proxies=1)))
    assert [get(client, "203.0.113.7").status_code for _ in range(50)] == [200] + [429] * 49
    assert [get(client, f"198.51.100.{i}").status_code for i in range(3)] == [200, 200, 429]
