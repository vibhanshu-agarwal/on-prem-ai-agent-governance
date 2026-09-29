#!/usr/bin/env python3
"""Make the register, the IdP and the agent env file agree with deploy/agents.json (T4). Idempotent.

  1. control-plane register: for each agent, set its declared capabilities, bind its workload image
     (label `workload_image`, so discovery can tell a real agent container from one that merely copies
     the `govpilot.agent_id` label) and, for the SSO agent, bind its OIDC subject. There is no update endpoint in the control-plane API, so this runs the
     control plane's own domain service inside its container (`docker exec`), which also writes an
     audit record for every change. Nothing in services/control-plane is modified.
  2. IdP: create the OIDC client for the SSO agent (the secret is shown once, so it is kept in
     .local/agents.env and reused on later runs).
  3. .local/agents.env (0600, gitignored): the per-agent secrets compose.agents.yml needs
       HR_AGENT_KEY, CODING_AGENT_KEY            gateway virtual keys from .local/agent-keys.json
       FINANCE_CLIENT_ID / _SECRET               OIDC client credentials
       FINANCE_DELEGATION_TOKEN                  the finance agent's root delegation token (read from
                                                 the control plane's secret store; children are minted
                                                 from it with a strictly narrower scope)

Run scripts/provision.py first (gateway keys). scripts/agents-up.sh runs both.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = Path(os.environ.get("AGENTS_CONFIG") or ROOT / "deploy" / "agents.json")
KEYS = ROOT / ".local" / "agent-keys.json"
OUT = ROOT / ".local" / "agents.env"
CP_ENV = ROOT / ".local" / "control-plane.env"
CP_CONTAINER = os.environ.get("CP_CONTAINER", "gov-control-plane")
IDP_URL = os.environ.get("IDP_URL") or f"http://127.0.0.1:{os.environ.get('IDP_PORT', '8300')}"

# Runs inside the control-plane container: reuses its config, wiring and domain services.
REMOTE = r'''
import base64, json, os
from govcp.config import load_config
from govcp.wiring import build_app
spec = json.loads(base64.b64decode(os.environ["AGENTS_SYNC"]))
a = build_app(load_config())
out = {"tokens": {}, "changed": {}}
for agent_id, want in spec["agents"].items():
    ag = a.register.find(agent_id)
    if ag is None:
        out["changed"][agent_id] = "not registered (run scripts/control-plane-up.sh)"
        continue
    caps, subs = want.get("capabilities"), want.get("oidc_subjects") or []
    labels = want.get("labels") or {}
    changes = {}
    def fn(x):
        if caps is not None and sorted(x.capabilities) != sorted(caps):
            changes["capabilities"] = {"from": list(x.capabilities), "to": list(caps)}
            x.capabilities = list(caps)
        for k, v in labels.items():
            if (x.labels or {}).get(k) != v:
                changes.setdefault("labels", {})[k] = {"from": (x.labels or {}).get(k), "to": v}
                x.labels = {**(x.labels or {}), k: v}
        for s in subs:
            if s not in x.oidc_subjects:
                changes.setdefault("oidc_subjects_added", []).append(s)
                x.oidc_subjects.append(s)
    a.register.mutate(agent_id, fn)
    if changes:
        a.ports.audit.append("agents-provision", "agent.identity_synced", agent_id, changes)
    out["changed"][agent_id] = changes or "unchanged"
    if want.get("token"):
        s = a.ports.secrets.get(f"delegation/{agent_id}/token")
        out["tokens"][agent_id] = s.value if s is not None and not s.revoked else None
print("RESULT " + json.dumps(out))
'''


def load_env_file(p: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def sync_register(cfg: dict) -> dict:
    spec = {"agents": {}}
    for aid, a in cfg["agents"].items():
        spec["agents"][aid] = {"capabilities": a.get("capabilities"),
                               "oidc_subjects": [a["oidc_subject"]] if a.get("oidc_subject") else [],
                               # binds the agent to the image its containers run (discovery spoof check, T6)
                               "labels": {"workload_image": a["image"]} if a.get("image") else {},
                               "token": a.get("auth") == "oidc" and bool(a.get("delegation"))}
    b64 = base64.b64encode(json.dumps(spec).encode()).decode()
    p = subprocess.run(["docker", "exec", "-i", "-e", f"AGENTS_SYNC={b64}", CP_CONTAINER, "python", "-"],
                       input=REMOTE, capture_output=True, text=True, timeout=90)
    if p.returncode != 0:
        sys.exit(f"register sync failed:\n{p.stderr[-1500:]}")
    line = [ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")]
    if not line:
        sys.exit(f"register sync produced no result:\n{p.stdout[-800:]}\n{p.stderr[-800:]}")
    return json.loads(line[-1][len("RESULT "):])


def create_idp_client(client_id: str, admin_token: str) -> str | None:
    req = urllib.request.Request(f"{IDP_URL}/admin/clients", method="POST",
                                 data=json.dumps({"client_id": client_id, "roles": ["agent"]}).encode(),
                                 headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())["client_secret"]
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return None
        raise


def main() -> int:
    cfg = json.loads(CONFIG.read_text())
    if not KEYS.exists():
        sys.exit("run scripts/provision.py first (no .local/agent-keys.json)")
    keys = json.loads(KEYS.read_text())["agents"]
    cp_env, prev = load_env_file(CP_ENV), load_env_file(OUT)
    res = sync_register(cfg)
    for aid, ch in res["changed"].items():
        print(f"  register {aid}: {ch}")
    env: dict[str, str] = {}
    for aid, a in cfg["agents"].items():
        var = aid.split("-")[0].upper()          # hr, finance, coding
        if a.get("auth", "key") == "key":
            env[f"{var}_AGENT_KEY"] = keys[aid]["key"]
        else:
            cid = a["oidc_subject"]
            secret = prev.get(f"{var}_CLIENT_SECRET") if prev.get(f"{var}_CLIENT_ID") == cid else None
            if secret is None:
                secret = create_idp_client(cid, cp_env["IDP_ADMIN_TOKEN"])
            if secret is None:
                sys.exit(f"IdP client {cid!r} exists but its secret is not in {OUT}; delete the client or restore the file")
            env[f"{var}_CLIENT_ID"], env[f"{var}_CLIENT_SECRET"] = cid, secret
            tok = res["tokens"].get(aid)
            if not tok:
                sys.exit(f"no delegation token for {aid} (revoked or not issued)")
            env[f"{var}_DELEGATION_TOKEN"] = tok
            dl = a.get("delegation") or {}
            if dl:                                   # the scope this agent asks for when it delegates
                env[f"{var}_CHILD_BUDGET_USD"] = str(dl["budget_usd"])
                env[f"{var}_CHILD_MODELS"] = ",".join(dl["models"])
                env[f"{var}_CHILD_TTL_S"] = str(dl.get("ttl_s", 3600))
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("# generated by scripts/agents_provision.py; secrets, gitignored\n" +
                   "".join(f"{k}={v}\n" for k, v in env.items()))
    try:
        os.chmod(OUT, 0o600)
    except OSError:
        pass
    print(f"  wrote {OUT.relative_to(ROOT)} ({', '.join(sorted(env))})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
