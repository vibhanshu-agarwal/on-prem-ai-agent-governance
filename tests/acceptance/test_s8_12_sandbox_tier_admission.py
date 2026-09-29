"""S8-12 Sandbox tier admission: deploying an agent whose declared capability requires a stronger sandbox than
the tier requested is rejected at admission time."""
from __future__ import annotations

import subprocess
import sys

import pytest
import yaml

import acclib as L

pytestmark = pytest.mark.usefixtures("live")


def _admit(compose_path):
    return subprocess.run([sys.executable, str(L.ROOT / "scripts" / "admit_agents.py"), "--compose", str(compose_path),
                           "--json"], capture_output=True, text=True, timeout=60, cwd=L.ROOT)


@pytest.mark.accept(
    id="S8-12", title="Sandbox tier admission",
    criterion="The deploy path (scripts/agents-up.sh -> scripts/admit_agents.py, T7 signed policy) rejects the "
              "coding agent (executes_model_code) at tier gvisor/container and admits it at microvm; the control "
              "plane register refuses the same mismatch; nothing is started for a denied request",
    simplification="Tiers are labels on Docker containers (hardened: read-only, non-root, no capabilities); no "
                   "real gVisor/Firecracker runtime; admission is a deploy-script gate, not a Kubernetes webhook.")
def test_sandbox_tier_admission(alice, record, tmp_path):
    ok = _admit(L.ROOT / "deploy" / "compose.agents.yml")
    assert ok.returncode == 0, ok.stdout + ok.stderr
    results = {}
    for tier in ("gvisor", "container"):
        doc = yaml.safe_load((L.ROOT / "deploy" / "compose.agents.yml").read_text(encoding="utf-8"))
        doc["services"]["coding-agent"]["labels"]["govpilot.sandbox_tier"] = tier
        doc["services"]["coding-agent"]["container_name"] = "t8-coding-weak"
        p = tmp_path / f"compose.{tier}.yml"
        p.write_text(yaml.safe_dump(doc), encoding="utf-8")
        r = _admit(p)
        assert r.returncode == 1, r.stdout + r.stderr
        import json
        d = json.loads(r.stdout)
        coding = next(x for x in d["results"] if x["agent_id"] == "coding-agent")
        assert not coding["allowed"] and coding["required_tier"] == "microvm"
        assert any("weaker than required 'microvm'" in why for why in coding["reasons"])
        results[tier] = coding["reasons"]
    assert "t8-coding-weak" not in {c.name for c in L.dclient().containers.list(all=True)}
    # the register applies the same rule when an agent is registered through the API
    r = alice.post("/v1/agents", {"agent_id": L.uid("t8tier"), "team": "t8tier", "owner": "alice",
                                  "max_budget_usd": 0.1, "models": ["mock-local"], "sandbox_tier": "gvisor",
                                  "capabilities": ["executes_model_code"]})
    assert r.status_code in (400, 403, 422), r.text
    # no verified policy bundle = deny (fail closed)
    import os
    env = {**os.environ, "POLICY_STORE": str(tmp_path / "empty-store")}
    fc = subprocess.run([sys.executable, str(L.ROOT / "scripts" / "admit_agents.py")], capture_output=True, text=True,
                        timeout=60, cwd=L.ROOT, env=env)
    assert fc.returncode == 2, fc.stdout + fc.stderr
    record(deny_reasons=results, production_compose_admitted=True, register_status_for_mismatch=r.status_code,
           no_policy_bundle_exit_code=fc.returncode, admission_log=".local/policy/admission.jsonl")
