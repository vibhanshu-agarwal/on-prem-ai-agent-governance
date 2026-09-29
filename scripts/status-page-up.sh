#!/usr/bin/env bash
# Build and start the agent status page (http://127.0.0.1:8400). Requires scripts/control-plane-up.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ -f .local/control-plane.env ]] || { echo "run scripts/control-plane-up.sh first"; exit 1; }
docker compose -f deploy/compose.status-page.yml --env-file .local/control-plane.env up -d --build --wait
echo "status page: http://127.0.0.1:${STATUS_PAGE_PORT:-8400}"
