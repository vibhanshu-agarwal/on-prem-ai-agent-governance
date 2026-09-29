#!/usr/bin/env bash
# Run every test of the pilot and write docs/results/ACCEPTANCE.md.
#
#   scripts/acceptance.sh                   task suites + acceptance suite + pilot simulation + report (~80 min)
#   scripts/acceptance.sh --fresh           first scripts/down.sh --purge && scripts/up.sh (clean-room run)
#   scripts/acceptance.sh --only-acceptance skip the task suites (tests/foundation ... tests/budget)
#   scripts/acceptance.sh --report          only re-render the report from the last results
#   T8_RESTART_ITERATIONS=21                restarts in the M-02b drill (default 21)
#
# Needs the full stack (scripts/up.sh). Suites run one pytest process each (their conftest modules share names).
# Results: .local/acceptance/ (junit per suite, results.json, pilot_sim.json, evidence/); the report is
# regenerated from them, so a failing test shows up as FAIL with its message.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-.venv/Scripts/python}"; [[ -x "$PY" ]] || PY="${PYTHON:-.venv/bin/python}"
RES=.local/acceptance
FRESH=0; SUITES=1; ONLY_REPORT=0
for a in "$@"; do
  case "$a" in
    --fresh) FRESH=1 ;;
    --only-acceptance) SUITES=0 ;;
    --report) ONLY_REPORT=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done
T0=$(date +%s)
step() { echo; echo "==[$(( $(date +%s) - T0 ))s] $*"; }
FAILED=()

if [[ $ONLY_REPORT == 0 ]]; then
  if [[ $FRESH == 1 ]]; then
    step "clean-room bring-up"
    bash scripts/down.sh --purge
    bash scripts/up.sh || { echo "bring-up failed"; exit 1; }
  fi
  mkdir -p "$RES"
  rm -f "$RES/results.json"
  "$PY" -c "import sys; sys.path.insert(0,'tests/control'); import cpclient; sys.exit(0 if cpclient.stack_up() else 1)" \
    || { echo "stack not running: bash scripts/up.sh"; exit 1; }

  if [[ $SUITES == 1 ]]; then
    for s in foundation policy discovery control agents guardrails budget; do
      step "tests/$s"
      "$PY" -m pytest "tests/$s" -q -p no:cacheprovider --junitxml="$RES/junit-$s.xml" -o junit_family=xunit2 \
        2>&1 | tail -5 || true
      grep -q 'failures="0"' "$RES/junit-$s.xml" && grep -q 'errors="0"' "$RES/junit-$s.xml" || FAILED+=("tests/$s")
      if [[ $s == guardrails ]]; then
        # the T5 live tests re-create Presidio with a test overlay (host ports, extra network): restore production
        docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --no-deps --wait \
          presidio-analyzer presidio-anonymizer >/dev/null 2>&1 || true
        docker network rm govpilot_t5host >/dev/null 2>&1 || true
      fi
    done
  fi

  step "tests/acceptance (report section 8 + July minimum criteria)"
  "$PY" -m pytest tests/acceptance -q -p no:cacheprovider --junitxml="$RES/junit-acceptance.xml" -o junit_family=xunit2 \
    2>&1 | tail -15 || true
  grep -q 'failures="0"' "$RES/junit-acceptance.xml" && grep -q 'errors="0"' "$RES/junit-acceptance.xml" \
    || FAILED+=("tests/acceptance")

  step "pilot-success simulation"
  "$PY" scripts/pilot_sim.py --requests 1000 || FAILED+=("pilot simulation")
fi

step "report"
"$PY" scripts/acceptance_report.py
step "done"
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "FAILED: ${FAILED[*]} (details in docs/results/ACCEPTANCE.md and $RES/)"
  exit 1
fi
echo "all green"
