#!/usr/bin/env bash
# Bring up the T6 observability stack (separate compose project; never touches the governance stack).
#   scripts/observability-up.sh                 OpenLIT + ClickHouse + Grafana
#   scripts/observability-up.sh gateway-demo    ... plus the OTel-enabled gateway twin on :4200
#   scripts/observability-up.sh ebpf            ... plus the OpenLIT Controller (eBPF discovery attempt)
# Secrets are generated once into .local/observability.env (gitignored).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ENVF=.local/observability.env
mkdir -p .local/observability
if [[ ! -f "$ENVF" ]]; then
  umask 077
  cat > "$ENVF" <<EOT
OBS_CH_USER=openlit
OBS_CH_PASSWORD=$(openssl rand -hex 16)
OBS_GRAFANA_PASSWORD=$(openssl rand -hex 12)
EOT
  echo "wrote $ENVF"
fi
PROFILES=()
for p in "$@"; do PROFILES+=(--profile "$p"); done
ENVS=(--env-file "$ENVF")
if [[ " $* " == *" gateway-demo "* ]]; then
  [[ -f deploy/.env ]] || { echo "deploy/.env missing: run scripts/bootstrap.sh first"; exit 1; }
  PY=.venv/Scripts/python; [[ -x "$PY" ]] || PY=python3
  "$PY" deploy/observability/make-gateway-config.py
  ENVS=(--env-file deploy/.env --env-file "$ENVF")
fi
docker compose -f deploy/compose.observability.yml "${ENVS[@]}" "${PROFILES[@]}" up -d --wait
echo "OpenLIT   http://127.0.0.1:3300   (first login: user@openlit.io / openlituser)"
echo "Grafana   http://127.0.0.1:3400   (anonymous viewer; admin password in $ENVF)"
