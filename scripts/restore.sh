#!/usr/bin/env bash
# Restore test for a backup made by scripts/backup.sh: verifies the manifest, restores both Postgres dumps into
# a SCRATCH Postgres container (never the live one) and prints row counts, so the backup is proven restorable.
#
#   scripts/restore.sh BACKUP_DIR [--keep]     --keep leaves the scratch container running (port in the output)
#
# In-place disaster recovery (destructive) is the same pg_restore into the live containers after
#   docker stop gov-gateway gov-control-plane; dropdb/createdb; pg_restore; docker start ...
# and is described in the runbook (T9); it is deliberately not automated here.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite container paths like /tmp/x
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DIR="${1:?usage: scripts/restore.sh BACKUP_DIR [--keep]}"
KEEP="${2:-}"
( cd "$DIR" && sha256sum -c MANIFEST.sha256 )
NAME="t8-restore-$(date +%s)"
PW=$(openssl rand -hex 12)
docker run -d --name "$NAME" --label govpilot.t8test=1 -e POSTGRES_PASSWORD="$PW" -e POSTGRES_USER=restore \
  -p 127.0.0.1::5432 postgres:16.14-alpine >/dev/null
until docker exec "$NAME" pg_isready -U restore >/dev/null 2>&1; do sleep 1; done
sleep 2
for db in litellm controlplane; do
  docker exec "$NAME" createdb -U restore "$db"
  docker cp "$DIR/$db.dump" "$NAME:/tmp/$db.dump" >/dev/null
  # --no-owner/--no-acl: the scratch server has none of the production roles
  docker exec "$NAME" pg_restore -U restore -d "$db" --no-owner --no-acl --exit-on-error "/tmp/$db.dump"
done
q() { docker exec "$NAME" psql -U restore -d "$1" -tA -c "$2"; }
PORT=$(docker port "$NAME" 5432/tcp | head -1 | awk -F: '{print $NF}')
echo "{\"container\": \"$NAME\", \"password\": \"$PW\", \"port\": $PORT,"
echo " \"litellm_keys\": $(q litellm 'select count(*) from "LiteLLM_VerificationToken"'),"
echo " \"litellm_spend_logs\": $(q litellm 'select count(*) from "LiteLLM_SpendLogs"'),"
echo " \"litellm_key_spend_usd\": $(q litellm 'select coalesce(sum(spend),0) from "LiteLLM_VerificationToken"'),"
echo " \"cp_agents\": $(q controlplane "select count(*) from documents where collection = 'agents'"),"
echo " \"cp_audit_records\": $(q controlplane 'select count(*) from audit_log')}"
if [[ "$KEEP" != "--keep" ]]; then docker rm -f "$NAME" >/dev/null; fi
