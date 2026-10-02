"""
HYPERION PROOF: THE EVIDENCE FILE
=================================
One JSON document per attestation: the signed request, the raw inputs as
fetched, the metrics computed from them, and who attested. Its keccak256
over a canonical encoding is the `feedbackHash` posted to the ERC-8004
Reputation Registry, so the on-chain record commits to exactly this file.

Canonical encoding: UTF-8 JSON, keys sorted, no insignificant whitespace,
ASCII-only. Numbers from the source stay as the strings they arrived as.
"""

from __future__ import annotations

import json

from eth_utils import keccak

from . import metrics
from .request import Request

SCHEMA = "hyperion-proof/track-record/v1"


def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(doc: dict) -> str:
    return "0x" + keccak(canonical(doc)).hex()


def build(
    request: Request,
    signature: str,
    portfolio_window: dict,
    source: str,
    retrieved_at: str,
    validator: str,
    method: str = metrics.METHOD_V1,
    num_trials: int | None = None,
) -> dict:
    """The evidence document for one request and the data fetched for it."""
    pts = metrics.points(portfolio_window["accountValueHistory"], portfolio_window["pnlHistory"])
    return {
        "schema": SCHEMA,
        "request": {**request.message(), "signature": signature},
        "inputs": {
            "source": source,
            "retrievedAt": retrieved_at,
            "accountValueHistory": portfolio_window["accountValueHistory"],
            "pnlHistory": portfolio_window["pnlHistory"],
        },
        "metrics": metrics.compute(pts, method=method, num_trials=num_trials),
        "validator": validator,
    }


def recompute(doc: dict) -> dict:
    """The metrics the evidence's own inputs give. An honest file returns
    exactly `doc["metrics"]`."""
    inputs = doc["inputs"]
    m_info = doc.get("metrics", {})
    method = m_info.get("method", metrics.METHOD_V1)
    num_trials = m_info.get("numTrials")
    pts = metrics.points(inputs["accountValueHistory"], inputs["pnlHistory"])
    return metrics.compute(pts, method=method, num_trials=num_trials)
