"""Emergency-stop path with the main control plane AND its database down
(report section 5 'emergency stop unavailable', section 8 'kill-plane outage')."""
from __future__ import annotations

import os
import subprocess
import sys
import time

import httpx
import pytest

import cpclient
from cpclient import record_result, wait_until

pytestmark = pytest.mark.usefixtures("live")


def _estop(path, reason="kill-plane outage drill", token=None, operator="bob"):
    return httpx.post(f"{cpclient.ESTOP_URL}{path}", json={"reason": reason}, timeout=60, headers={
        "Authorization": f"Bearer {token or cpclient.ENV['ESTOP_TOKEN']}", "X-Estop-Operator": operator})


def _streaming(make_agent):
    team = cpclient.uid("t3es")
    ag = make_agent(team)
    c = cpclient.run_agent_container(ag["agent"]["agent_id"], team, {
        "AGENT_KEY": ag["gateway_key"], "MODEL": "mock-local-slow", "MAX_TOKENS": "200"})
    cpclient.wait_for_log(c, r"TOK ", timeout=40)
    return ag, c


def test_estop_works_with_control_plane_and_db_down(alice, make_agent):
    ag, c = _streaming(make_agent)
    ag2, c2 = _streaming(make_agent)
    d = cpclient.dclient()
    cp, db = d.containers.get("gov-control-plane"), d.containers.get("gov-cp-postgres")
    cp.stop(timeout=5)
    db.stop(timeout=5)
    try:
        with pytest.raises(httpx.HTTPError):
            httpx.get(cpclient.CP_URL + "/healthz", timeout=3)
        # wrong credential is refused (and journaled)
        assert _estop(f"/estop/agents/{ag['agent']['agent_id']}", token="nope").status_code == 401
        t0 = time.time()
        r = _estop(f"/estop/agents/{ag['agent']['agent_id']}")
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["verify"]["ok"], out["verify"]
        assert out["timings_ms"]["total"] < 30_000
        assert cpclient.chat(ag["gateway_key"]).status_code == 401
        c.reload()
        assert c.status != "running" and c.attrs["HostConfig"]["RestartPolicy"]["Name"] == "no"
        record_result("estop_http", {"timings_ms": out["timings_ms"], "wall_s": round(time.time() - t0, 2),
                                     "network": out["network"]})

        # the CLI path works too, from the operator's machine, with only the gateway key and Docker
        env = {**os.environ, "LITELLM_MASTER_KEY": cpclient.ENV["LITELLM_MASTER_KEY"],
               "GATEWAY_URL": cpclient.GW_URL, "PYTHONPATH": str(cpclient.CP_SRC),
               "ESTOP_JOURNAL": str(cpclient.ROOT / ".local" / "estop-cli-journal.jsonl")}
        p = subprocess.run([sys.executable, "-m", "govcp.estop.cli", "agent", ag2["agent"]["agent_id"],
                            "--reason", "cli drill", "--operator", "alice"], env=env, capture_output=True,
                           text=True, timeout=120)
        assert p.returncode == 0, p.stdout[-2000:] + p.stderr[-2000:]
        assert cpclient.chat(ag2["gateway_key"]).status_code == 401
        c2.reload()
        assert c2.status != "running"
    finally:
        db.start()
        cp.start()
        assert wait_until(lambda: _healthy(), timeout=90), "control plane did not come back"

    # back up: the estop journal is ingested into the main audit log and the register reflects it
    r = alice.post("/v1/admin/estop-ingest")
    assert r.status_code == 200
    recs = alice.get("/v1/audit", params={"action_prefix": "estop.ingested", "target": ag["agent"]["agent_id"],
                                          "limit": 10}).json()["records"]
    assert any(x["details"]["action"] == "estop.agent_stopped" for x in recs)
    a = alice.get(f"/v1/agents/{ag['agent']['agent_id']}").json()
    assert a["status"] == "stopped" and a["desired_state"] == "stopped"
    j = httpx.get(f"{cpclient.ESTOP_URL}/estop/journal", timeout=10, headers={
        "Authorization": f"Bearer {cpclient.ENV['ESTOP_TOKEN']}", "X-Estop-Operator": "bob"}).json()
    assert j["verify"]["ok"]
    assert any(x["action"] == "estop.auth_failed" for x in j["records"])


def _healthy():
    try:
        return httpx.get(cpclient.CP_URL + "/healthz", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def test_estop_team_stop(make_agent):
    team = cpclient.uid("t3est")
    ags = [make_agent(team) for _ in range(2)]
    cs = [cpclient.run_agent_container(a["agent"]["agent_id"], team, {"AGENT_KEY": a["gateway_key"],
                                                                      "MODEL": "mock-local", "MAX_TOKENS": "2"})
          for a in ags]
    r = _estop(f"/estop/teams/{team}", operator="alice")
    assert r.status_code == 200 and r.json()["verify"]["ok"], r.text
    assert len(r.json()["keys"]) == 2 and len(r.json()["workloads"]) == 2
    assert all(cpclient.chat(a["gateway_key"]).status_code == 401 for a in ags)
    for c in cs:
        c.reload()
        assert c.status != "running"


def test_estop_requires_operator_identity():
    r = httpx.post(f"{cpclient.ESTOP_URL}/estop/agents/x", json={"reason": "r"}, timeout=10,
                   headers={"Authorization": f"Bearer {cpclient.ENV['ESTOP_TOKEN']}"})
    assert r.status_code == 400
