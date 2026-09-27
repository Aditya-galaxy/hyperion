#!/usr/bin/env bash
set -euo pipefail

# Hyperion Proof end to end, against the real ERC-8004 registries, with no
# funds: fork Arc testnet locally, register an agent, sign a request with the
# trading account, attest and post as an independent validator, verify, and
# show the owner being refused when it tries to grade its own agent.
#
# Needs Foundry and the package's Python deps
# (python3 -m venv .venv && .venv/bin/pip install -e proof).
# Keys are generated fresh and only ever used on the local fork. The account's
# history is a recorded Hyperliquid response (a fresh key has none of its own).

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-python3}"
PORT="${ANVIL_PORT:-8547}"
RPC="http://127.0.0.1:${PORT}"
IDENTITY=0x8004A818BFB912233c491871b3d84c89A494BD9e
REPUTATION=0x8004B663056A597Dffe9eCcC1965A193B7388713
OUT="$(mktemp -d)"
export PYTHONPATH="$ROOT/proof${PYTHONPATH:+:$PYTHONPATH}"

anvil --fork-url https://rpc.testnet.arc.network --port "$PORT" --silent &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null' EXIT
for _ in $(seq 30); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 1; done

key() { "$PY" -c "from eth_account import Account; print('0x' + Account.create().key.hex().removeprefix('0x'))"; }
OWNER_KEY=$(key); VALIDATOR_KEY=$(key); ACCOUNT_KEY=$(key)
for k in "$OWNER_KEY" "$VALIDATOR_KEY" "$ACCOUNT_KEY"; do
  cast rpc anvil_setBalance "$(cast wallet address "$k")" 0x56BC75E2D63100000 --rpc-url "$RPC" >/dev/null
done

echo "1. the owner registers an agent in the ERC-8004 Identity Registry"
AGENT_ID=$(cast send "$IDENTITY" "register(string)" 'data:application/json,{"name":"demo-trading-agent"}' \
  --private-key "$OWNER_KEY" --rpc-url "$RPC" --json | "$PY" -c "
import json, sys
r = json.load(sys.stdin); r = r.get('data') or r
for log in r['logs']:
    if log['address'].lower() == '$IDENTITY'.lower() and len(log['topics']) == 3 \
            and not log['topics'][0].startswith('0xddf252ad'):
        print(int(log['topics'][1], 16)); break")
echo "   agent $AGENT_ID, owner $(cast wallet address "$OWNER_KEY")"

echo "2. the trading account signs a request for that agent"
PROOF_ACCOUNT_KEY="$ACCOUNT_KEY" "$PY" -m hyperion_proof.cli request --agent-id "$AGENT_ID" --chain 5042002 > "$OUT/req.json"

echo "3. an independent validator attests and posts to the Reputation Registry"
PROOF_VALIDATOR_KEY="$VALIDATOR_KEY" PROOF_RPC_URL="$RPC" \
PROOF_PORTFOLIO_FIXTURE="$ROOT/proof/tests/fixtures/portfolio_hlp.json" \
  "$PY" -m hyperion_proof.cli attest "$OUT/req.json" --out "$OUT" --post
EVIDENCE=$(ls "$OUT"/0x*.json | grep -v receipt | head -1)

echo "4. anyone verifies"
PROOF_RPC_URL="$RPC" "$PY" -m hyperion_proof.cli verify "$EVIDENCE" --chain 5042002

echo "5. the registry's own summary"
cast call "$REPUTATION" "getSummary(uint256,address[],string,string)(uint64,int128,uint8)" \
  "$AGENT_ID" "[$(cast wallet address "$VALIDATOR_KEY")]" "tradingYield" "" --rpc-url "$RPC"

echo "6. the owner tries to grade its own agent"
PROOF_VALIDATOR_KEY="$OWNER_KEY" PROOF_RPC_URL="$RPC" \
PROOF_PORTFOLIO_FIXTURE="$ROOT/proof/tests/fixtures/portfolio_hlp.json" \
  "$PY" -m hyperion_proof.cli attest "$OUT/req.json" --out "$OUT" --post || true
