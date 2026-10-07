#!/usr/bin/env bash
set -euo pipefail

# Deploy Hyperion Guard on Arc and run the demo there.
#
#   bash guard/demo/arc.sh testnet     # Arc testnet (default)
#   bash guard/demo/arc.sh mainnet     # Arc mainnet: real USDC for gas (a few cents)
#
# Before running:
#   1. An encrypted Foundry keystore for the owner, funded with USDC on that network:
#        cast wallet import guard-owner --interactive
#      (testnet USDC: https://faucet.circle.com, choose Arc Testnet)
#   2. guard/demo/.env.arc.<network>, or guard/demo/.env.arc for both (git-ignored),
#      with three hot keys used only by the demo:
#        GUARD_SIGNER_KEY=0x…   the Guard service's signing key
#        AGENT_KEY=0x…          the demo trading agent
#        GUARDIAN_KEY=0x…       the monitoring bot that can kill the agent
#      Make them with `cast wallet new`. Optional: PYTH_API_KEY=… for live prices.
#
# On testnet only, the owner may instead be a throwaway key in .env.arc:
#        GUARD_OWNER_KEY=0x…
#    so the script can run unattended. Testnet USDC is worth nothing; never
#    put a key that holds real funds there. Mainnet always uses the keystore.
#
# The owner's keystore password is asked for on each transaction it signs.
# Private keys are never printed. Addresses are saved to
# guard/deployments/<network>.json.

NETWORK="${1:-testnet}"
case "$NETWORK" in
  testnet) RPC=https://rpc.testnet.arc.network; CHAIN_ID=5042002; EXPLORER=https://testnet.arcscan.app ;;
  mainnet) RPC=https://rpc.mainnet.arc.io;      CHAIN_ID=5042;    EXPLORER=https://explorer.arc.io ;;
  *) echo "usage: $0 [testnet|mainnet]"; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# Each network can have its own keys: .env.arc.<network> if it exists, else .env.arc.
ENV_FILE="$ROOT/guard/demo/.env.arc.$NETWORK"
[ -f "$ENV_FILE" ] || ENV_FILE="$ROOT/guard/demo/.env.arc"
PY="${PYTHON:-$ROOT/guard/service/.venv/bin/python}"
ACCOUNT="${GUARD_ACCOUNT:-guard-owner}"
[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE (see the header of this script)"; exit 1; }
set -a; source "$ENV_FILE"; set +a
for v in GUARD_SIGNER_KEY AGENT_KEY GUARDIAN_KEY; do [ -n "${!v:-}" ] || { echo "set $v in $ENV_FILE"; exit 1; }; done

[ "$(cast chain-id --rpc-url "$RPC")" = "$CHAIN_ID" ] || { echo "RPC $RPC isn't chain $CHAIN_ID"; exit 1; }
# How the owner signs: the encrypted keystore, or on testnet a throwaway key from .env.arc.
if [ -n "${GUARD_OWNER_KEY:-}" ]; then
  [ "$NETWORK" = testnet ] || { echo "GUARD_OWNER_KEY is for testnet only; mainnet uses the keystore ($ACCOUNT)"; exit 1; }
  SIGN=(--private-key "$GUARD_OWNER_KEY")
  OWNER=$(cast wallet address "$GUARD_OWNER_KEY")
else
  SIGN=(--account "$ACCOUNT")
  OWNER=$(cast wallet address --account "$ACCOUNT")
fi
SIGNER=$(cast wallet address "$GUARD_SIGNER_KEY")
AGENT=$(cast wallet address "$AGENT_KEY")
GUARDIAN=$(cast wallet address "$GUARDIAN_KEY")
echo "network $NETWORK (chain $CHAIN_ID)"
echo "owner $OWNER  signer $SIGNER  agent $AGENT  guardian $GUARDIAN"
echo "owner balance: $(cast balance "$OWNER" --rpc-url "$RPC" --ether) USDC"
if [ "$NETWORK" = mainnet ]; then
  read -r -p "Deploy to Arc MAINNET, paying gas in real USDC? [y/N] " ok
  [ "$ok" = y ] || exit 1
fi

# Gas for the hot wallets: the signer anchors, the agent executes, the
# guardian kills. Native USDC on Arc has 18 decimals, so 0.2 "ether" = 0.2 USDC.
TOPUP="${TOPUP_USDC:-0.2}"
for who in "$SIGNER" "$AGENT" "$GUARDIAN"; do
  if [ "$(cast balance "$who" --rpc-url "$RPC")" = "0" ]; then
    cast send "$who" --value "${TOPUP}ether" --rpc-url "$RPC" "${SIGN[@]}" >/dev/null
    echo "sent $TOPUP USDC of gas to $who"
  fi
done

cd "$ROOT/guard/contracts"
NONCE=$(cast nonce "$OWNER" --rpc-url "$RPC")
GUARD=$(cast compute-address "$OWNER" --nonce "$NONCE" | awk '{print $NF}')
# --sender: with a keystore, forge doesn't take the script's msg.sender from the signer on its own
GUARD_SIGNER="$SIGNER" forge script script/Deploy.s.sol:Deploy --rpc-url "$RPC" "${SIGN[@]}" --sender "$OWNER" --broadcast \
  | grep -E "HyperionGuard|admin|guardSigner"
EXECUTOR=$(cast compute-address "$OWNER" --nonce $((NONCE + 2)) | awk '{print $NF}')   # +1 is registerAgent
VENUE=$(cast compute-address "$OWNER" --nonce $((NONCE + 3)) | awk '{print $NF}')
GUARD="$GUARD" AGENT="$AGENT" GUARDIAN="$GUARDIAN" \
  forge script script/Deploy.s.sol:DemoSetup --rpc-url "$RPC" "${SIGN[@]}" --sender "$OWNER" --broadcast \
  | grep -E "agent|GuardedExecutor|DemoVenue"
[ "$(cast code "$GUARD" --rpc-url "$RPC")" != "0x" ] || { echo "no code at $GUARD"; exit 1; }

mkdir -p "$ROOT/guard/deployments"
cat > "$ROOT/guard/deployments/$NETWORK.json" <<EOF
{
  "network": "arc-$NETWORK",
  "chainId": $CHAIN_ID,
  "HyperionGuard": "$GUARD",
  "GuardedExecutor": "$EXECUTOR",
  "DemoVenue": "$VENUE",
  "admin": "$OWNER",
  "guardSigner": "$SIGNER",
  "demoAgent": "$AGENT",
  "demoGuardian": "$GUARDIAN",
  "explorer": "$EXPLORER/address/$GUARD"
}
EOF
echo "saved guard/deployments/$NETWORK.json"

cd "$ROOT"
PRICES='{"BTC-USD": "65000"}'
[ -n "${PYTH_API_KEY:-}" ] && PRICES=""
GUARD_RPC_URL="$RPC" GUARD_CHAIN_ID="$CHAIN_ID" GUARD_CONTRACT="$GUARD" EXECUTOR="$EXECUTOR" VENUE="$VENUE" \
GUARD_FIXED_PRICES="$PRICES" EXPLORER="$EXPLORER" GUARD_DB="$ROOT/data/guard-$NETWORK.db" \
  "$PY" guard/demo/demo.py
