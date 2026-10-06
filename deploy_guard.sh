#!/usr/bin/env bash
set -euo pipefail

# Host the Hyperion Guard API (the Solana Guard) on Cloud Run.
#
# What this sets up, all in one project:
#   - a service account for the Guard, allowed to read and write Firestore and
#     to read one secret, and nothing else;
#   - the Guard's co-signing key, a 32-byte Ed25519 seed, in Secret Manager.
#     It is generated here the first time and never printed. Every vault that
#     names this Guard depends on it: deleting the secret orphans them;
#   - the service itself, public, one instance at most. The Guard keeps a copy
#     of its state in memory and must not run as two instances.
#
# State (policies, nonces, usage, approvals) is kept in the project's default
# Firestore database, in collections named hyperion_guard_solana_*.
#
# The endpoint is public. Setting a policy needs the owner's signature and
# checking a transaction needs the agent's, but anyone can register an agent,
# so GUARD_MAX_AGENTS caps how many it will hold, and requests are rate
# limited per caller and overall (guard/service/hyperion_guard/ratelimit.py):
# GUARD_RATE_LIMIT a minute per address, GUARD_RATE_LIMIT_WRITES of them
# writes, GUARD_RATE_LIMIT_GLOBAL from everyone together.

PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${GUARD_REGION:-us-central1}"
SERVICE="${GUARD_SERVICE:-hyperion-guard}"
SECRET="${GUARD_SECRET:-hyperion-guard-solana-cosigner}"
SA_NAME="${GUARD_SERVICE_ACCOUNT:-hyperion-guard}"
SOLANA_RPC_URL="${GUARD_SOLANA_RPC_URL:-https://api.devnet.solana.com}"
VAULT_PROGRAM_ID="${GUARD_VAULT_PROGRAM_ID:-9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq}"
MAX_AGENTS="${GUARD_MAX_AGENTS:-200}"
RATE_LIMIT="${GUARD_RATE_LIMIT:-120}"
RATE_LIMIT_WRITES="${GUARD_RATE_LIMIT_WRITES:-10}"
RATE_LIMIT_GLOBAL="${GUARD_RATE_LIMIT_GLOBAL:-1200}"

if [ -z "$PROJECT_ID" ]; then
    echo "[-] Error: GCP Project ID could not be determined. Set GCP_PROJECT_ID or run 'gcloud config set project <PROJECT_ID>'."
    exit 1
fi
SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "================================================================================"
echo "  HYPERION GUARD: HOSTING THE API"
echo "================================================================================"
echo "  Project: ${PROJECT_ID}"
echo "  Service: ${SERVICE} (Cloud Run, ${REGION}, public, 1 instance at most)"
echo "  Solana:  ${SOLANA_RPC_URL}, vault program ${VAULT_PROGRAM_ID}"
echo "  Limits:  ${RATE_LIMIT}/min per address (${RATE_LIMIT_WRITES} writes), ${RATE_LIMIT_GLOBAL}/min overall, ${MAX_AGENTS} agents"
echo

if ! gcloud iam service-accounts describe "$SA" --project "$PROJECT_ID" >/dev/null 2>&1; then
    echo "[+] Creating service account ${SA}"
    gcloud iam service-accounts create "$SA_NAME" --project "$PROJECT_ID" \
        --display-name "Hyperion Guard API" >/dev/null
fi
echo "[+] Letting it use Firestore"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:${SA}" \
    --role roles/datastore.user --condition=None >/dev/null

if ! gcloud secrets describe "$SECRET" --project "$PROJECT_ID" >/dev/null 2>&1; then
    echo "[+] Generating the co-signing key into secret ${SECRET} (not shown)"
    python3 -c "import os, sys; sys.stdout.write(os.urandom(32).hex())" \
        | gcloud secrets create "$SECRET" --project "$PROJECT_ID" --replication-policy automatic --data-file=- >/dev/null
else
    echo "[+] Using the co-signing key already in secret ${SECRET}"
fi
gcloud secrets add-iam-policy-binding "$SECRET" --project "$PROJECT_ID" --member "serviceAccount:${SA}" \
    --role roles/secretmanager.secretAccessor >/dev/null

echo "[+] Building and deploying"
gcloud run deploy "$SERVICE" --project "$PROJECT_ID" --region "$REGION" \
    --source "$ROOT/guard/service" \
    --service-account "$SA" \
    --allow-unauthenticated \
    --min-instances 0 --max-instances 1 --concurrency 20 --memory 512Mi --cpu 1 --timeout 30 \
    --set-secrets "HYPERION_SOLANA_COSIGNER_KEY=${SECRET}:latest" \
    --set-env-vars "HYPERION_SOLANA_STATE=firestore,HYPERION_SOLANA_PRICES=jupiter,HYPERION_SOLANA_RPC_URL=${SOLANA_RPC_URL},HYPERION_VAULT_PROGRAM_ID=${VAULT_PROGRAM_ID},HYPERION_SOLANA_MAX_AGENTS=${MAX_AGENTS},HYPERION_RATE_LIMIT=${RATE_LIMIT},HYPERION_RATE_LIMIT_WRITES=${RATE_LIMIT_WRITES},HYPERION_RATE_LIMIT_GLOBAL=${RATE_LIMIT_GLOBAL},HYPERION_TRUSTED_PROXIES=1" \
    --quiet

URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --format 'value(status.url)')"
echo
echo "[+] Live at ${URL}"
curl -fsS "${URL}/v1/solana/health" && echo
