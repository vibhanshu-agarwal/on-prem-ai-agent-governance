#!/usr/bin/env bash
# Bring up the T4 sample agents (HR, Finance Reconciliation, Coding) + the delegation broker.
# Needs the base stack (scripts/bootstrap.sh) and the control plane (scripts/control-plane-up.sh).
# Never restarts base or control-plane services.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ -f deploy/.env ]] || { echo "deploy/.env missing: run scripts/bootstrap.sh first"; exit 1; }
[[ -f .local/control-plane.env ]] || { echo ".local/control-plane.env missing: run scripts/control-plane-up.sh first"; exit 1; }
set -a; . deploy/.env; set +a
PY="${PYTHON:-.venv/Scripts/python}"; [[ -x "$PY" ]] || PY="${PYTHON:-.venv/bin/python}"
echo ">> syncing gateway keys (budget, models, token policy, attribution mode)"
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT:-4000}" "$PY" scripts/provision.py
echo ">> syncing register + IdP client, writing .local/agents.env"
"$PY" scripts/agents_provision.py
echo ">> building and starting agents"
docker compose -f deploy/compose.agents.yml --env-file .local/agents.env up -d --build
echo ">> agents:  docker logs -f gov-agent-hr | gov-agent-finance | gov-agent-coding"
echo ">> rates:   python scripts/agents_ctl.py status | rogue <agent> | calm <agent>"
echo ">> report:  python scripts/attribution_report.py --since 10m"
