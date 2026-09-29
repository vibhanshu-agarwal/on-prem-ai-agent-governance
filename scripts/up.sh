#!/usr/bin/env bash
# One-command bring-up of the whole pilot, in dependency order, from scratch or on top of a running stack.
#
#   scripts/up.sh              build + start everything (idempotent)
#   scripts/up.sh --recreate   also force-recreate the gateway, control plane and agents (pick up code changes)
#   UP_EBPF=0 scripts/up.sh    skip the privileged OpenLIT Controller (eBPF discovery)
#
# Order (each step waits for health before the next):
#   1. secrets              deploy/.env (scripts/gen-env.sh; kept if present)
#   2. observability        govpilot_obs network, ClickHouse, OpenLIT, Grafana (+ eBPF controller)
#   3. base                 Postgres, Redis, mock providers, Presidio, gateway (budget guard, run
#                           attribution, guardrails, OTel -> OpenLIT); teams + agent keys (provision.py)
#   4. control plane        rebuilt image; cp-postgres, migrate, IdP, control plane, auth proxy, estop
#   5. policy               signed bundle built from policy/ and activated (policyctl build --activate)
#   6. discovery            feed IdP clients + gov-discovery
#   7. agents               keys/register/IdP sync, admission gate, HR / Finance / Coding + broker
# Tear down with scripts/down.sh [--volumes|--purge].
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
RECREATE=0
for a in "$@"; do
  case "$a" in
    --recreate) RECREATE=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done
PY="${PYTHON:-.venv/Scripts/python}"; [[ -x "$PY" ]] || PY="${PYTHON:-.venv/bin/python}"
[[ -x "$PY" ]] || { echo "no venv python (.venv); see README / docs/results/ACCEPTANCE.md"; exit 1; }
export PYTHON="$PY"
T0=$(date +%s)
step() { echo; echo "==[$(( $(date +%s) - T0 ))s] $*"; }

step "1/7 secrets"
bash scripts/gen-env.sh
mkdir -p .local/guardrails .local/observability .local/policy
docker network inspect govpilot_obs >/dev/null 2>&1 || docker network create govpilot_obs >/dev/null

step "2/7 observability (OpenLIT, ClickHouse, Grafana)"
if [[ "${UP_EBPF:-1}" == "1" ]]; then bash scripts/observability-up.sh ebpf; else bash scripts/observability-up.sh; fi

step "3/7 base stack (gateway, providers, Postgres, Redis, Presidio) + agent keys"
bash scripts/bootstrap.sh
if [[ $RECREATE == 1 ]]; then
  set -a; . deploy/.env; set +a
  docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --no-deps --force-recreate --wait gateway
fi

step "4/7 control plane (image rebuilt)"
bash scripts/control-plane-up.sh
if [[ $RECREATE == 1 ]]; then
  docker compose -f deploy/docker-compose.yml -f deploy/compose.control-plane.yml --env-file deploy/.env \
    --env-file .local/control-plane.env up -d --no-deps --force-recreate --wait idp control-plane authproxy estop
fi

step "5/7 policy bundle (signed, activated)"
if [[ ! -f .local/policy/signing.key ]]; then
  echo "no policy signing key: generating one (adds policy/trust/<id>.pub.json; commit it via PR)"
  PYTHONPATH=services/policy "$PY" -c "from govpolicy.cli import main; main(['keygen'])"
fi
PYTHONPATH=services/policy "$PY" -c "from govpolicy.cli import main; main(['build','--activate'])" | head -3
PYTHONPATH=services/policy "$PY" -c "from govpolicy.cli import main; main(['drift'])" || echo "WARNING: policy drift (see above)"

step "6/7 discovery feeds"
bash scripts/discovery-up.sh

step "7/7 agents (admission gate first)"
bash scripts/agents-up.sh
if [[ $RECREATE == 1 ]]; then
  docker compose -f deploy/compose.agents.yml --env-file .local/agents.env up -d --force-recreate
fi

# Optional: the read-only status page (T10), when its compose file is present.
if [[ -f deploy/compose.status-page.yml && -f scripts/status-page-up.sh ]]; then
  step "status page"; bash scripts/status-page-up.sh || echo "WARNING: status page did not start"
fi

step "done"
docker ps --filter name=gov- --format 'table {{.Names}}\t{{.Status}}' | sort
cat <<EOT

Gateway           http://127.0.0.1:4000      (agents: gateway:4000; SSO agents: sso-gateway:8080)
Control plane     http://127.0.0.1:8100/docs
Emergency stop    http://127.0.0.1:8190      (token in .local/control-plane.env)
Grafana (cost)    http://127.0.0.1:3400
OpenLIT           http://127.0.0.1:3300
Acceptance suite  bash scripts/acceptance.sh
EOT
