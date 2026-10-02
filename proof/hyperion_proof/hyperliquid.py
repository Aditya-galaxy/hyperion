"""
HYPERION PROOF: HYPERLIQUID'S PUBLIC ACCOUNT DATA
=================================================
One read-only POST to the public info endpoint: an account's `portfolio`,
which holds the value and cumulative-PnL histories per window. No key, no
account. Hyperliquid's terms (§3.1.8) forbid only automated use beyond
reasonable rates; this makes one request per attestation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

INFO_URL = "https://api.hyperliquid.xyz/info"


def portfolio(account: str, client: httpx.Client | None = None, url: str = INFO_URL) -> tuple[dict, str]:
    """({window: {accountValueHistory, pnlHistory, vlm}}, retrieved-at ISO time)."""
    c = client or httpx.Client(timeout=20)
    r = c.post(url, json={"type": "portfolio", "user": account.lower()})
    r.raise_for_status()
    return dict(r.json()), datetime.now(timezone.utc).isoformat(timespec="seconds")


def fills(account: str, client: httpx.Client | None = None, url: str = INFO_URL) -> tuple[list[dict], str]:
    """Fetches user executed fills (trades) for trade-by-trade ingestion."""
    c = client or httpx.Client(timeout=20)
    r = c.post(url, json={"type": "userFills", "user": account.lower()})
    r.raise_for_status()
    return list(r.json()), datetime.now(timezone.utc).isoformat(timespec="seconds")


def ledger_updates(account: str, client: httpx.Client | None = None, url: str = INFO_URL) -> tuple[list[dict], str]:
    """Fetches non-funding ledger updates (deposits, withdrawals, transfers) for Modified Dietz."""
    c = client or httpx.Client(timeout=20)
    r = c.post(url, json={"type": "userNonFundingLedgerUpdates", "user": account.lower()})
    r.raise_for_status()
    return list(r.json()), datetime.now(timezone.utc).isoformat(timespec="seconds")

