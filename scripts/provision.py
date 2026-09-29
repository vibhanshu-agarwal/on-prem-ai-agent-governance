#!/usr/bin/env python3
"""Create teams and one virtual key per pilot agent through the LiteLLM admin API.

Stdlib only. Reads GATEWAY_URL and LITELLM_MASTER_KEY from env, and teams/agents
from deploy/agents.json (or $AGENTS_CONFIG). Idempotent:
teams are reused by alias; an agent's key is reused if the stored key still
validates, otherwise any old key with that alias is deleted and re-issued.
Output: .local/agent-keys.json (gitignored).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

URL = os.environ["GATEWAY_URL"].rstrip("/")
MASTER = os.environ["LITELLM_MASTER_KEY"]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".local", "agent-keys.json")

# Teams, agents, budgets (USD) and model allowlists come from config, not code.
# Budgets are deliberately small so T2 can exhaust them with the mock providers.
CONFIG = os.environ.get("AGENTS_CONFIG") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deploy", "agents.json")
with open(CONFIG) as _f:
    _cfg = json.load(_f)
TEAMS = _cfg["teams"]
AGENTS = _cfg["agents"]
BUDGET_DURATION = _cfg.get("budget_duration", "30d")


def call(method, path, body=None, key=MASTER, ok_statuses=(200,)):
    req = urllib.request.Request(URL + path, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw.decode(errors="replace")}


def wait_ready():
    for _ in range(90):
        try:
            with urllib.request.urlopen(URL + "/health/readiness", timeout=5) as r:
                if r.status == 200:
                    return
        except Exception:
            pass
        time.sleep(2)
    sys.exit("gateway not ready")


def ensure_team(alias, spec):
    st, data = call("GET", "/team/list")
    teams = data if isinstance(data, list) else data.get("teams", [])
    for t in teams:
        if t.get("team_alias") == alias:
            return t["team_id"]
    st, data = call("POST", "/team/new", {
        "team_alias": alias,
        "max_budget": spec["max_budget"],
        "budget_duration": BUDGET_DURATION,
        "metadata": {"team": alias},
    })
    if st != 200:
        sys.exit(f"team/new {alias} failed: {st} {data}")
    return data["team_id"]


def key_valid(key):
    st, data = call("GET", "/key/info", key=key)
    return st == 200


def main():
    wait_ready()
    existing = {}
    if os.path.exists(OUT):
        with open(OUT) as f:
            existing = json.load(f)
    team_ids = {t: ensure_team(t, s) for t, s in TEAMS.items()}
    result = {"gateway_url": URL, "teams": team_ids, "agents": {}}
    for agent, spec in AGENTS.items():
        prev = existing.get("agents", {}).get(agent)
        if prev and key_valid(prev["key"]):
            result["agents"][agent] = prev
            print(f"  reuse key for {agent}")
            continue
        st, found = call("GET", f"/key/list?key_alias={agent}")
        if st == 200 and found.get("keys"):
            call("POST", "/key/delete", {"key_aliases": [agent]})  # stale key whose secret we no longer hold
        st, data = call("POST", "/key/generate", {
            "key_alias": agent,
            "team_id": team_ids[spec["team"]],
            "models": spec["models"],
            "max_budget": spec["max_budget"],
            "budget_duration": BUDGET_DURATION,
            "metadata": {"agent_id": agent, "team": spec["team"]},
        })
        if st != 200:
            sys.exit(f"key/generate {agent} failed: {st} {data}")
        result["agents"][agent] = {"key": data["key"], "team": spec["team"], "team_id": team_ids[spec["team"]],
                                   "max_budget": spec["max_budget"], "models": spec["models"]}
        print(f"  issued key for {agent} (team={spec['team']}, budget=${spec['max_budget']}, models={spec['models']})")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(result, f, indent=2)
    try:
        os.chmod(OUT, 0o600)
    except OSError:
        pass


if __name__ == "__main__":
    main()
