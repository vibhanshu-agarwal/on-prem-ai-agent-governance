#!/usr/bin/env bash
# Stop and remove only the T3 control-plane services. --volumes also drops their data
# (register, audit log, IdP keys, secrets, estop journal). The base stack is untouched.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose -f deploy/docker-compose.yml -f deploy/compose.control-plane.yml
         --env-file deploy/.env --env-file .local/control-plane.env)
SERVICES=(estop authproxy control-plane idp cp-migrate cp-postgres)
"${COMPOSE[@]}" rm -s -f "${SERVICES[@]}"
if [[ "${1:-}" == "--volumes" ]]; then
  for v in cpdata idpdata cpsecrets estopjournal; do docker volume rm -f "govpilot_$v" >/dev/null || true; done
  echo "control-plane volumes removed"
fi
docker ps -aq --filter label=govpilot.test=t3 | xargs -r docker rm -f >/dev/null || true
