# The Hyperion Guard API, for a host with no disk of its own (Cloud Run).
# Build from guard/service. See deploy_guard.sh at the repository root.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY hyperion_guard ./hyperion_guard
RUN pip install --no-cache-dir ".[hosted]"

# One worker: the Solana Guard keeps a copy of its state in memory and is
# written for a single running instance (see hyperion_guard/solana/store.py).
ENV PORT=8080
CMD ["sh", "-c", "exec uvicorn hyperion_guard.api:create_app --factory --host 0.0.0.0 --port ${PORT} --workers 1"]
