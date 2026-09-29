#!/usr/bin/env bash
# Narrated walkthrough of the pilot, about two and a half minutes at presenting pace, against the running stack (bash scripts/up.sh first).
#
#   scripts/demo.sh              run it (open http://127.0.0.1:8400 and http://127.0.0.1:3400/d/govpilot-cost beside it)
#   DEMO_FAST=1 scripts/demo.sh  no narration pauses (about one minute; used to check the script)
#   DEMO_KEEP=1 scripts/demo.sh  leave the shadow container and its pending proposal in place at the end
#   DEMO_CLEAR_QUEUE=1 ...       first reject the stale pending discovery proposals left by earlier runs (audited)
#
# What it shows, in order:
#   1  three governed agents are running, each with its own key, team and budget
#   2  one agent (coding-agent) is made to go rogue with scripts/agents_ctl.py: parallel calls, big completions,
#      ignores the "budget exceeded" answers; the control plane's live view shows its spend rising
#   3  an operator stops it through the control plane: key blocked, connections cut, restart disabled, credentials
#      revoked, verified; the spend line freezes
#   4  somebody restarts the container anyway: the reconciler stops it again; its key is dead at the gateway
#   5  an unregistered container starts calling the gateway: it lands in the discovery queue with zero budget and no
#      key, and every call it makes is refused
#   6  the audit log's hash chain verifies
# Everything is put back at the end (agent resumed and calm, shadow container removed, proposal rejected), also when
# the script is interrupted. It changes nothing outside the pilot's own containers and files.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-.venv/Scripts/python}"; [[ -x "$PY" ]] || PY="${PYTHON:-.venv/bin/python}"
[[ -x "$PY" ]] || { echo "no venv python (.venv); see README.md quick start"; exit 1; }
H="$PY scripts/demo_helper.py"
ROGUE="${DEMO_ROGUE_AGENT:-coding-agent}"
ROGUE_CONTAINER="${DEMO_ROGUE_CONTAINER:-gov-agent-coding}"
# a fresh name per run: a proposal that was rejected stays rejected, so the same name would never show up again
SHADOW="demo-shadow-scraper-$(date +%H%M%S)"
CONC="${DEMO_ROGUE_CONCURRENCY:-12}"
MAXTOK="${DEMO_ROGUE_MAX_TOKENS:-384}"
WATCH_S="${DEMO_WATCH_SECONDS:-36}"

if [[ -t 1 ]]; then B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'; G=$'\e[32m'; Y=$'\e[33m'; RD=$'\e[31m'; else B=; D=; R=; G=; Y=; RD=; fi
T0=$(date +%s)
pause() { [[ "${DEMO_FAST:-0}" == 1 ]] || sleep "$1"; }
scene() { echo; echo "${B}[$(printf '%3ds' $(( $(date +%s) - T0 )))] $*${R}"; }
say() { echo "  ${D}$*${R}"; }
run() { echo "  ${G}\$ $*${R}"; }

STOPPED_BY_DEMO=0
WENT_ROGUE=0
RATES=deploy/agents/config/rates.json
RATES_BAK="$(mktemp)"; cp "$RATES" "$RATES_BAK"
cleanup() {
  trap - EXIT INT TERM
  echo; echo "${B}-- putting everything back${R}"
  if [[ "$WENT_ROGUE" == 1 ]]; then
    $PY scripts/agents_ctl.py calm "$ROGUE" >/dev/null 2>&1 || true
    cp "$RATES_BAK" "$RATES"                     # byte for byte what it was (agents_ctl re-formats the JSON)
  fi
  rm -f "$RATES_BAK"
  if [[ "$STOPPED_BY_DEMO" == 1 ]]; then $H resume "$ROGUE" 2>&1 || true; fi
  if [[ "${DEMO_KEEP:-0}" != 1 ]]; then
    $H reject-discovery "$SHADOW" 2>&1 || true
    docker rm -f "$SHADOW" >/dev/null 2>&1 || true
  fi
  $H fleet 2>&1 || true
}
trap cleanup EXIT INT TERM

# ---- preflight ------------------------------------------------------------------------------------------------------
for c in gov-control-plane gov-gateway gov-gateway-edge "$ROGUE_CONTAINER" gov-discovery; do
  [[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" == "true" ]] \
    || { echo "${RD}$c is not running: start the stack with bash scripts/up.sh${R}"; trap - EXIT; exit 1; }
done
docker rm -f "$SHADOW" >/dev/null 2>&1 || true
$H feeds-ok
[[ "${DEMO_CLEAR_QUEUE:-0}" == 1 ]] && $H clear-queue

echo "${B}Governing AI agents on-prem: a short tour${R}"
say "status page  http://127.0.0.1:8400        cost dashboard  http://127.0.0.1:3400/d/govpilot-cost"
say "everything below is real: a LiteLLM gateway with budget guard, guardrails and attribution, a control plane, three sample agents"
pause 8

# ---- 1 ---------------------------------------------------------------------------------------------------------------
scene "1/6  Three agents, each with its own key, team and budget"
say "They reach models only through the gateway; the gateway holds the provider credentials and enforces the budgets."
run "python scripts/demo_helper.py fleet"
$H fleet
pause 10

# ---- 2 ---------------------------------------------------------------------------------------------------------------
scene "2/6  $ROGUE goes rogue"
say "A runaway loop: $CONC parallel iterations, ${MAXTOK}-token completions, and it keeps hammering when the gateway says no."
run "python scripts/agents_ctl.py rogue $ROGUE --concurrency $CONC --max-tokens $MAXTOK"
WENT_ROGUE=1
$PY scripts/agents_ctl.py rogue "$ROGUE" --concurrency "$CONC" --max-tokens "$MAXTOK" --interval 0.05
say "Live spend from the control plane (the budget bar on the status page moves the same way):"
$H watch "$ROGUE" --seconds "$WATCH_S" --every 2
pause 1

# ---- 3 ---------------------------------------------------------------------------------------------------------------
scene "3/6  An operator stops it through the control plane"
run "POST /v1/agents/$ROGUE/stop   (alice, operator)"
STOPPED_BY_DEMO=1
$H stop "$ROGUE" --reason "demo: runaway spend, stopping the agent"
say "Spend is written in 5-second batches, so the last increments land just after the stop; then the line is flat although the loop keeps asking:"
$H watch "$ROGUE" --seconds 12 --every 2
pause 4

# ---- 4 ---------------------------------------------------------------------------------------------------------------
scene "4/6  It cannot come back by itself"
say "Restarting the container by hand (docker start), as a script or a well-meaning colleague might:"
run "docker start $ROGUE_CONTAINER"
docker start "$ROGUE_CONTAINER" >/dev/null 2>&1
for i in $(seq 1 20); do
  [[ "$(docker inspect -f '{{.State.Running}}' "$ROGUE_CONTAINER")" == "false" ]] && break
  sleep 0.5
done
up=$(docker inspect -f '{{.State.Running}}' "$ROGUE_CONTAINER"); pol=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$ROGUE_CONTAINER")
echo "  container running: $up   restart policy: $pol   (the reconciler stopped it again; desired state is 'stopped')"
say "And its key at the gateway:"
$H probe "$ROGUE"
pause 10

# ---- 5 ---------------------------------------------------------------------------------------------------------------
scene "5/6  A shadow agent appears"
say "Somebody starts an unregistered container that calls the gateway (no key, then a made-up key)."
run "docker run -d --name $SHADOW --network govpilot_agents ... (an unregistered, unlabelled service)"
docker run -d --name "$SHADOW" --label owner=growth-hacks --network govpilot_agents --entrypoint python \
  govpilot/mock-provider:1 -u -c '
import json, time, urllib.request, urllib.error
def call(key):
    req = urllib.request.Request("http://gateway:4000/v1/chat/completions", method="POST",
        data=json.dumps({"model": "mock-local", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}).encode(),
        headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + key} if key else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return type(e).__name__
while True:
    print("STATUS", call(None), call("sk-made-up"), flush=True)
    time.sleep(3)
' >/dev/null
$H discovery "$SHADOW" --timeout 60
sleep 3
echo "  what the shadow container got back from the gateway: $(docker logs "$SHADOW" 2>&1 | grep -c '^STATUS 401 401') x 'STATUS 401 401' (refused, refused); it can spend nothing"
pause 16

# ---- 6 ---------------------------------------------------------------------------------------------------------------
scene "6/6  The audit trail"
say "Every step above is an append-only, hash-chained audit record. Verify the chain and show the last records:"
run "GET /v1/audit/verify ; GET /v1/audit"
$H audit --limit 10
pause 10

scene "done"
say "Stop it -> 'cannot restart' -> shadow discovery -> audit chain: the proof numbers are in docs/results/ACCEPTANCE.md."
pause 6
