#!/usr/bin/env bash
# Bring up the T6 observability stack (separate compose project; never touches the governance stack).
#   scripts/observability-up.sh                 OpenLIT + ClickHouse + Grafana
#   scripts/observability-up.sh ebpf            ... plus the OpenLIT Controller (eBPF discovery attempt)
# The real gateway exports OTel spans to OpenLIT over the shared external network govpilot_obs
# (the T6 "gateway-demo" twin was retired in T8). Secrets are generated once into
# .local/observability.env (gitignored).
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
docker network inspect govpilot_obs >/dev/null 2>&1 || docker network create govpilot_obs >/dev/null
PROFILES=()
for p in "$@"; do PROFILES+=(--profile "$p"); done
docker compose -f deploy/compose.observability.yml --env-file "$ENVF" "${PROFILES[@]}" up -d --wait
echo "OpenLIT   http://127.0.0.1:3300   (first login: user@openlit.io / openlituser)"
echo "Grafana   http://127.0.0.1:3400   (anonymous viewer; admin password in $ENVF)"
