#!/usr/bin/env bash
# Bring up the T3 control plane on top of the running T1 stack (never restarts base services).
#   - generates .local/control-plane.env (random secrets, gitignored) on first run
#   - builds govpilot/control-plane:1 and starts: cp-postgres, cp-migrate (one-shot), idp,
#     control-plane, authproxy, estop
# Requires: scripts/bootstrap.sh has been run (deploy/.env exists, gateway up).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ -f deploy/.env ]] || { echo "deploy/.env missing: run scripts/bootstrap.sh first"; exit 1; }
ENV_CP=.local/control-plane.env
mkdir -p .local
if [[ ! -f "$ENV_CP" ]]; then
  rnd() { openssl rand -hex 24; }
  umask 077
  ESTOP_TOKEN="estop-$(rnd)"
  cat > "$ENV_CP" <<EOT
CP_PG_SUPER_PASSWORD=$(rnd)
CP_OWNER_PASSWORD=$(rnd)
CP_APP_PASSWORD=$(rnd)
IDP_ADMIN_TOKEN=idpadm-$(rnd)
IDP_PASSWORD_ALICE=$(rnd)
IDP_PASSWORD_BOB=$(rnd)
IDP_PASSWORD_CAROL=$(rnd)
IDP_PASSWORD_DAVE=$(rnd)
IDP_PASSWORD_ERIN=$(rnd)
IDP_CLIENT_SECRET_AUTHPROXY=$(rnd)
IDP_CLIENT_SECRET_FEED_DOCKER_EVENTS=$(rnd)
IDP_CLIENT_SECRET_FEED_TEST=$(rnd)
ESTOP_TOKEN=$ESTOP_TOKEN
ESTOP_TOKEN_SHA256=$(printf '%s' "$ESTOP_TOKEN" | openssl dgst -sha256 | awk '{print $NF}')
CP_PG_PORT=55432
CP_PORT=8100
IDP_PORT=8300
AUTHPROXY_PORT=4180
ESTOP_PORT=8190
EOT
  echo "wrote $ENV_CP"
fi
COMPOSE=(docker compose -f deploy/docker-compose.yml -f deploy/compose.control-plane.yml
         --env-file deploy/.env --env-file "$ENV_CP")
SERVICES=(cp-postgres cp-migrate idp control-plane authproxy estop)
echo ">> building + starting control plane services (base stack untouched)"
"${COMPOSE[@]}" build cp-migrate
"${COMPOSE[@]}" up -d --wait --wait-timeout 180 "${SERVICES[@]}"
echo ">> control plane:  http://127.0.0.1:8100/docs"
echo ">> IdP:            http://127.0.0.1:8300/.well-known/openid-configuration"
echo ">> auth proxy:     http://127.0.0.1:4180/v1  (agents: http://sso-gateway:8080/v1)"
echo ">> emergency stop: http://127.0.0.1:8190  (token in $ENV_CP)"
