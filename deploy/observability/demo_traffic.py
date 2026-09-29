"""Generate demo traffic so the Grafana cost dashboard has something to show.

Creates (idempotently) three throwaway `demo-*` virtual keys with small budgets, one per team, tagged
with metadata {agent_id, team}, then sends a mix of calls (models, streaming, sizes) through the
OTel-enabled gateway twin. It never touches the real agents' keys or budgets.

    .venv/Scripts/python deploy/observability/demo_traffic.py [--gateway http://127.0.0.1:4200] [--rounds 12]

Stdlib only. The master key is read from deploy/.env (generated locally, gitignored).
"""
from __future__ import annotations

import argparse
import json
import random
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DEMO_AGENTS = {
    "demo-hr-assistant": {"team": "hr", "models": ["mock-local"], "budget": 0.5},
    "demo-finance-recon": {"team": "finance", "models": ["mock-local", "mock-remote"], "budget": 1.0},
    "demo-coding-agent": {"team": "engineering", "models": ["mock-local", "mock-remote"], "budget": 2.0},
}


def env() -> dict[str, str]:
    out = {}
    for line in (ROOT / "deploy" / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def call(base, path, key, body=None, method="POST"):
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def ensure_keys(base: str, master: str) -> dict[str, str]:
    _, raw = call(base, "/team/list", master, method="GET")
    teams = {t.get("team_alias"): t["team_id"] for t in json.loads(raw)}
    keyfile = ROOT / ".local" / "observability" / "demo-keys.json"
    have = json.loads(keyfile.read_text()) if keyfile.exists() else {}
    for alias, spec in DEMO_AGENTS.items():
        if alias in have:
            st, _ = call(base, "/key/info?key=" + have[alias], master, method="GET")
            if st == 200:
                continue
        st, raw = call(base, "/key/generate", master, {
            "key_alias": alias, "team_id": teams[spec["team"]], "models": spec["models"],
            "max_budget": spec["budget"], "budget_duration": "30d",
            "metadata": {"agent_id": alias, "team": spec["team"], "demo": True}})
        assert st == 200, raw
        have[alias] = json.loads(raw)["key"]
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.write_text(json.dumps(have))
    return have


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://127.0.0.1:4200")
    ap.add_argument("--admin", default="http://127.0.0.1:4000", help="where to mint the demo keys")
    ap.add_argument("--rounds", type=int, default=12)
    a = ap.parse_args()
    master = env()["LITELLM_MASTER_KEY"]
    keys = ensure_keys(a.admin, master)
    rnd = random.Random(7)
    ok = 0
    for i in range(a.rounds):
        for alias, spec in DEMO_AGENTS.items():
            model = rnd.choice(spec["models"])
            body = {"model": model, "max_tokens": rnd.choice([16, 32, 64, 128]),
                    "messages": [{"role": "user", "content": "demo " + "word " * rnd.randint(3, 40)}],
                    "stream": rnd.random() < 0.3,
                    "metadata": {"run_id": f"run-{alias}-{i}"}}
            if body["stream"]:
                body["stream_options"] = {"include_usage": True}
            st, _ = call(a.gateway, "/v1/chat/completions", keys[alias], body)
            ok += st == 200
    print(f"sent {a.rounds * len(DEMO_AGENTS)} calls, {ok} ok")


if __name__ == "__main__":
    main()
