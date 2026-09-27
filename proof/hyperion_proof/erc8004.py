"""
HYPERION PROOF: WRITING TO AND READING FROM ERC-8004
===================================================
Posts an attestation to the ERC-8004 Reputation Registry (v2.0.0, as
deployed on Arc) as feedback from the validator's address, one entry per
metric, each carrying the evidence file's URI and keccak256:

    tag1 = "tradingYield"  value = time-weighted return, percent, 4 decimals
    tag1 = "maxDrawdown"   value = max drawdown, percent, 4 decimals
    tag2 = "<venue>:<window>", e.g. "hyperliquid:month"

The registry itself refuses feedback from the agent's owner or operators,
so a validator can't be the agent grading itself.

Reading goes through the NewFeedback event, the only place the registry
keeps the URI and hash.
"""

from __future__ import annotations

import time
from decimal import Decimal

import httpx
from eth_abi import decode, encode
from eth_account import Account
from eth_utils import function_signature_to_4byte_selector, keccak, to_checksum_address

GIVE_FEEDBACK = function_signature_to_4byte_selector(
    "giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)")
NEW_FEEDBACK = "0x" + keccak(
    b"NewFeedback(uint256,address,uint64,int128,uint8,string,string,string,string,string,bytes32)").hex()
IS_AUTHORIZED = function_signature_to_4byte_selector("isAuthorizedOrOwner(address,uint256)")
DECIMALS = 4
MIN_BASE_FEE = 20 * 10**9          # Arc drops transactions priced under 20 gwei

# Deployed ERC-8004 v2.0.0 registries (checked with eth_getCode).
REGISTRIES = {
    5042: {"identity": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
           "reputation": "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"},
    5042002: {"identity": "0x8004A818BFB912233c491871b3d84c89A494BD9e",
              "reputation": "0x8004B663056A597Dffe9eCcC1965A193B7388713"},
}


def percent_value(fraction: str) -> int:
    """'0.0123456' (a fraction) → 12346 (1.2346%, 4 decimals)."""
    return int((Decimal(fraction) * 100 * 10**DECIMALS).to_integral_value())


def feedback_entries(evidence: dict) -> list[tuple[str, str, int]]:
    """(tag1, tag2, value) for each metric posted."""
    m, r = evidence["metrics"], evidence["request"]
    tag2 = f"{r['venue']}:{r['window']}"
    return [("tradingYield", tag2, percent_value(m["timeWeightedReturn"])),
            ("maxDrawdown", tag2, percent_value(m["maxDrawdown"]))]


def give_feedback_calldata(agent_id: int, value: int, tag1: str, tag2: str, uri: str, feedback_hash: str) -> bytes:
    return GIVE_FEEDBACK + encode(
        ["uint256", "int128", "uint8", "string", "string", "string", "string", "bytes32"],
        [agent_id, value, DECIMALS, tag1, tag2, "", uri, bytes.fromhex(feedback_hash.removeprefix("0x"))])


class Rpc:
    def __init__(self, url: str, chain_id: int, client: httpx.Client | None = None):
        self.url, self.chain_id = url, chain_id
        self.client = client or httpx.Client(timeout=20)
        self._id = 0

    def __call__(self, method: str, params: list):
        self._id += 1
        body = self.client.post(self.url, json={"jsonrpc": "2.0", "id": self._id, "method": method,
                                                "params": params}).json()
        if "error" in body:
            raise RuntimeError(f"{method}: {body['error']}")
        return body["result"]

    def call(self, to: str, data: bytes) -> bytes:
        return bytes.fromhex(self("eth_call", [{"to": to, "data": "0x" + data.hex()}, "latest"])[2:])

    def transact(self, key: str, to: str, data: bytes, wait: float = 60.0) -> str:
        acct = Account.from_key(key)
        tx = {"from": acct.address, "to": to_checksum_address(to), "data": "0x" + data.hex(), "value": 0}
        gas = int(self("eth_estimateGas", [tx]), 16)
        base = max(int(self("eth_gasPrice", []), 16), MIN_BASE_FEE)
        signed = acct.sign_transaction({
            "type": 2, "chainId": self.chain_id, "to": tx["to"], "data": tx["data"], "value": 0,
            "nonce": int(self("eth_getTransactionCount", [acct.address, "pending"]), 16),
            "gas": gas * 12 // 10, "maxPriorityFeePerGas": 10**9, "maxFeePerGas": base * 2 + 10**9})
        txh = self("eth_sendRawTransaction", ["0x" + signed.raw_transaction.hex().removeprefix("0x")])
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            receipt = self("eth_getTransactionReceipt", [txh])
            if receipt:
                if int(receipt["status"], 16) != 1:
                    raise RuntimeError(f"{txh} reverted")
                return txh
            time.sleep(0.5)
        raise RuntimeError(f"{txh} not mined in {wait:.0f}s")

    def is_owner_or_operator(self, identity: str, who: str, agent_id: int) -> bool:
        out = self.call(identity, IS_AUTHORIZED + encode(["address", "uint256"], [to_checksum_address(who), agent_id]))
        return decode(["bool"], out)[0]

    def _decode_feedback(self, log: dict) -> dict:
        idx, value, dec, tag1, tag2, _endpoint, uri, fhash = decode(
            ["uint64", "int128", "uint8", "string", "string", "string", "string", "bytes32"],
            bytes.fromhex(log["data"][2:]))
        return {"feedbackIndex": idx, "value": value, "valueDecimals": dec, "tag1": tag1, "tag2": tag2,
                "feedbackURI": uri, "feedbackHash": "0x" + fhash.hex(), "tx": log["transactionHash"],
                "agentId": int(log["topics"][1], 16), "client": "0x" + log["topics"][2][-40:]}

    def feedback(self, reputation: str, agent_id: int, client: str, lookback: int = 200_000,
                 chunk: int = 10_000) -> list[dict]:
        """Every NewFeedback from `client` about `agent_id` in the last
        `lookback` blocks. Arc's nodes prune old history and cap the range of
        one query, so this walks back from the latest block, halving the
        chunk whenever the node says the range is too large. For anything
        older, verify with the posting transactions instead (`--tx`)."""
        topics = [NEW_FEEDBACK, "0x" + agent_id.to_bytes(32, "big").hex(),
                  "0x" + bytes.fromhex(client[2:].lower()).rjust(32, b"\0").hex()]
        latest = int(self("eth_blockNumber", []), 16)
        out: list[dict] = []
        hi = latest
        while hi >= 0 and latest - hi < lookback:
            lo = max(0, hi - chunk + 1)
            try:
                logs = self("eth_getLogs", [{"address": to_checksum_address(reputation), "fromBlock": hex(lo),
                                             "toBlock": hex(hi), "topics": topics}])
            except RuntimeError as exc:
                if "pruned" in str(exc):
                    break                  # older than the node keeps; nothing more to find
                if "range" in str(exc) and chunk > 500:
                    chunk //= 2            # the node caps the range per query; ask for less
                    continue
                raise
            out = [self._decode_feedback(log) for log in logs] + out
            hi = lo - 1
        return out

    def feedback_in_tx(self, reputation: str, tx_hash: str) -> list[dict]:
        """The NewFeedback events in one transaction's receipt. Works however
        old the transaction is, as long as the node serves receipts."""
        receipt = self("eth_getTransactionReceipt", [tx_hash]) or {}
        return [self._decode_feedback(log) for log in receipt.get("logs", [])
                if log["address"].lower() == reputation.lower() and log["topics"][0] == NEW_FEEDBACK]
