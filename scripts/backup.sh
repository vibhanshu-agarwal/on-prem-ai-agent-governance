#!/usr/bin/env bash
# Back up the pilot's state: LiteLLM Postgres (keys, teams, budgets, spend logs), control-plane Postgres
# (register, audit hash chain, proposals, quarantine rules) and a Redis snapshot (spend counters).
#
#   scripts/backup.sh [OUT_DIR]        default .local/backups/<UTC timestamp>/
#
# Dumps are made inside the containers (pg_dump custom format, consistent snapshot per database) and copied
# out, with a SHA-256 manifest. Restore test: scripts/restore.sh OUT_DIR (restores into a scratch Postgres and
# verifies it; tests/acceptance M-09 runs both). Secrets (deploy/.env, .local/*.env, the control plane's
# secret volume) are NOT in the backup: keep them in your secret manager.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite container paths like /tmp/x
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="${1:-.local/backups/$TS}"
mkdir -p "$OUT"
dump() {  # container user db file
  # streamed through stdout: the hardened Postgres has a tmpfs /tmp, which `docker cp` cannot read
  docker exec "$1" pg_dump -U "$2" -d "$3" -Fc > "$OUT/$4"
  [[ -s "$OUT/$4" ]] || { echo "empty dump for $3"; exit 1; }
}
echo ">> LiteLLM Postgres";       dump gov-postgres litellm litellm litellm.dump
echo ">> control-plane Postgres"; dump gov-cp-postgres cp_super controlplane controlplane.dump
echo ">> Redis snapshot (spend counters)"
RPW=$(docker exec gov-redis sh -c 'printf %s "$REDIS_PASSWORD"')
docker exec gov-redis redis-cli -a "$RPW" --no-auth-warning SAVE >/dev/null
docker cp gov-redis:/data/dump.rdb "$OUT/redis.rdb" >/dev/null
( cd "$OUT" && sha256sum litellm.dump controlplane.dump redis.rdb > MANIFEST.sha256 )
cat > "$OUT/INFO.json" <<EOT
{"created_utc": "$TS", "litellm_image": "$(docker inspect -f '{{.Config.Image}}' gov-gateway)",
 "postgres_image": "$(docker inspect -f '{{.Config.Image}}' gov-postgres)"}
EOT
echo ">> backup written to $OUT"
cat "$OUT/MANIFEST.sha256"
