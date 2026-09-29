#!/usr/bin/env bash
# Start the T6 discovery service on top of the control plane (and, for two of the feeds, the observability stack).
#  - registers IdP clients `gateway-logs` and `openlit-controller` (role feed) through the IdP admin API
#    (the T3 config only ships `docker-events`); their secrets go to .local/discovery.env (gitignored)
#  - builds govpilot/discovery:1 and starts gov-discovery
# Requires: scripts/control-plane-up.sh; scripts/observability-up.sh for the gateway-otel/eBPF evidence.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ -f .local/control-plane.env ]] || { echo "run scripts/control-plane-up.sh first"; exit 1; }
[[ -f .local/observability.env ]] || { echo "run scripts/observability-up.sh first"; exit 1; }
PY=.venv/Scripts/python; [[ -x "$PY" ]] || PY=python3
"$PY" scripts/discovery_clients.py
docker compose -f deploy/compose.discovery.yml --env-file .local/control-plane.env --env-file .local/observability.env \
  --env-file .local/discovery.env up -d --build --wait
docker logs --tail 5 gov-discovery
