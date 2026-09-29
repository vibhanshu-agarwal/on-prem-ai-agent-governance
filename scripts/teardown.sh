#!/usr/bin/env bash
# Stop the stack. --volumes also deletes Postgres/Redis data (all keys, teams, spend).
# --purge additionally removes deploy/.env and .local/ (all generated secrets).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ARGS=(down --remove-orphans)
[[ "${1:-}" == "--volumes" || "${1:-}" == "--purge" ]] && ARGS+=(--volumes)
ENVARG=(); [[ -f deploy/.env ]] && ENVARG=(--env-file deploy/.env)
docker compose -f deploy/docker-compose.yml -f deploy/hardening/compose.hardening.yml "${ENVARG[@]}" "${ARGS[@]}"
if [[ "${1:-}" == "--purge" ]]; then rm -rf .local deploy/.env; echo "purged secrets"; fi
