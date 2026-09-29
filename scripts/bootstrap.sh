#!/usr/bin/env bash
# Bring the T1 stack up and provision teams + per-agent virtual keys.
# Idempotent: re-running keeps existing teams/keys (keys file .local/agent-keys.json).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
bash scripts/gen-env.sh
set -a; . deploy/.env; set +a
export GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT:-4000}"

echo ">> docker compose up (build + wait for healthy)"
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build --wait --wait-timeout 300

echo ">> provisioning teams and agent keys"
mkdir -p .local
PY="$(command -v python3 || command -v python)"
"$PY" scripts/provision.py

echo ">> done. stack is running; agent keys in .local/agent-keys.json (gitignored)"
