#!/usr/bin/env bash
# Tear the whole pilot down (reverse of scripts/up.sh), including throwaway test containers.
#
#   scripts/down.sh            stop + remove containers and networks; keep data volumes and secrets
#   scripts/down.sh --volumes  ... and delete all data volumes (keys, spend, register, audit, telemetry)
#   scripts/down.sh --purge    ... and delete generated secrets (deploy/.env, .local/) EXCEPT the policy
#                              signing key .local/policy/signing.key: its public half is committed in
#                              policy/trust/, so deleting it would orphan the trust anchor.
#
# Only govpilot projects and containers are touched (names gov-*/t2-*, compose projects govpilot*,
# labels govpilot.test*). Unrelated containers on the host are left alone.
set -uo pipefail
# Compose projects are addressed by name (-p), so this works even after the env files are gone.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MODE="${1:-}"
case "$MODE" in ""|--volumes|--purge) ;; *) echo "usage: $0 [--volumes|--purge]"; exit 2 ;; esac
V=(); [[ -n "$MODE" ]] && V=(-v)
q() { "$@" >/dev/null 2>&1 || true; }

echo ">> agents"
q docker compose -p govpilot-agents down --remove-orphans "${V[@]}"
if [[ -f deploy/compose.status-page.yml ]]; then
  echo ">> status page"
  q docker compose -p govpilot-status-page down --remove-orphans
fi
echo ">> discovery"
q docker compose -p govpilot-discovery down --remove-orphans "${V[@]}"

echo ">> throwaway test containers (T2 isolated stack, T3/T5/T6/T8 test containers)"
q docker compose -p govpilot-t2 down --remove-orphans -v
ids=$( { docker ps -aq --filter "name=^t2-"; docker ps -aq --filter "name=^gov-t5-"; docker ps -aq --filter "name=^t8-";
         docker ps -aq --filter label=govpilot.test; docker ps -aq --filter label=govpilot.t6test;
         docker ps -aq --filter label=govpilot.t8test; docker ps -aq --filter label=com.docker.compose.oneoff=True \
           --filter label=com.docker.compose.project=govpilot; } | sort -u)
[[ -n "$ids" ]] && docker rm -f $ids >/dev/null

echo ">> control plane + base stack"
q docker compose -p govpilot down --remove-orphans "${V[@]}"

echo ">> observability"
q docker compose -p govpilot-obs down --remove-orphans "${V[@]}"

for n in $(docker network ls --format "{{.Name}}" | grep -E "^govpilot_" || true); do q docker network rm "$n"; done
if [[ -n "$MODE" ]]; then
  for v in $(docker volume ls -q | grep -E '^govpilot(-t2|-obs|-discovery|-agents)?_' || true); do q docker volume rm "$v"; done
fi

if [[ "$MODE" == "--purge" ]]; then
  KEEP=""
  if [[ -f .local/policy/signing.key ]]; then KEEP=$(mktemp); cp .local/policy/signing.key "$KEEP"; fi
  rm -rf .local deploy/.env
  if [[ -n "$KEEP" ]]; then mkdir -p .local/policy; mv "$KEEP" .local/policy/signing.key; chmod 600 .local/policy/signing.key; fi
  echo "purged generated secrets and state (kept .local/policy/signing.key)"
fi
echo ">> remaining govpilot containers:"
docker ps -a --format '{{.Names}}' | grep -E '^(gov-|t2-|t8-)' || echo "   none"
