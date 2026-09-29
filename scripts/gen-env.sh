#!/usr/bin/env bash
# Generate deploy/.env with random local secrets. Refuses to overwrite unless --force.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/deploy/.env"
if [[ -f "$ENV_FILE" && "${1:-}" != "--force" ]]; then
  echo "deploy/.env already exists (use --force to regenerate; that invalidates existing keys/DB)"; exit 0
fi
rnd() { openssl rand -hex 24; }
LOCAL_KEY="sk-mock-local-$(rnd)"
REMOTE_KEY="sk-mock-remote-$(rnd)"
sha() { printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}'; }
umask 077
cat > "$ENV_FILE" <<EOT
LITELLM_MASTER_KEY=sk-master-$(rnd)
LITELLM_SALT_KEY=sk-salt-$(rnd)
POSTGRES_PASSWORD=$(rnd)
REDIS_PASSWORD=$(rnd)
MOCK_LOCAL_API_KEY=$LOCAL_KEY
MOCK_REMOTE_API_KEY=$REMOTE_KEY
MOCK_LOCAL_API_KEY_SHA256=$(sha "$LOCAL_KEY")
MOCK_REMOTE_API_KEY_SHA256=$(sha "$REMOTE_KEY")
GATEWAY_PORT=4000
EOT
echo "wrote $ENV_FILE"
