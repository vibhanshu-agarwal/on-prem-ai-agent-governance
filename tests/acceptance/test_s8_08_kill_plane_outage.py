"""S8-08 Kill-plane outage: the emergency stop still works with the main dashboard and evidence store down."""
from __future__ import annotations

import time

import httpx
import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")

DOWN = ["gov-control-plane", "gov-cp-postgres", "gov-status-page", "gov-obs-grafana", "gov-obs-openlit",
        "gov-obs-clickhouse"]


def _estop(path, reason="acceptance S8-08 kill-plane outage"):
    return httpx.post(f"{L.ESTOP_URL}{path}", json={"reason": reason}, timeout=60, headers={
        "Authorization": f"Bearer {L.ENV['ESTOP_TOKEN']}", "X-Estop-Operator": "bob"})


@pytest.mark.accept(
    id="S8-08", title="Kill-plane outage",
    criterion="With the control-plane API + its DB, the status page, Grafana, OpenLIT and ClickHouse all down, "
              "the separate emergency stop still stops a streaming agent (verified) within 30 s; its journal is "
              "ingested into the main audit log when the control plane returns",
    simplification="The estop runs on the same Docker host (a real one lives on separate infrastructure with its "
                   "own credentials store); its credential is one static bearer token, not a two-person rule.")
def test_kill_plane_outage(alice, drill, record):
    ag = drill.agent(L.uid("t8es"))
    aid, key = ag["agent"]["agent_id"], ag["gateway_key"]
    c = drill.run(ag)
    L.wait_for_log(c, r"TOK ")
    d = L.dclient()
    stopped = []
    try:
        for n in DOWN:
            try:
                d.containers.get(n).stop(timeout=5)
                stopped.append(n)
            except Exception:  # noqa: BLE001 - optional parts (status page) may not exist
                pass
        with pytest.raises(httpx.HTTPError):
            httpx.get(L.CP_URL + "/healthz", timeout=3)
        t0 = time.time()
        r = _estop(f"/estop/agents/{aid}")
        wall = time.time() - t0
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["verify"]["ok"], out["verify"]
        assert wall <= 30 and L.chat(key).status_code == 401
        c.reload()
        assert c.status != "running" and c.attrs["HostConfig"]["RestartPolicy"]["Name"] == "no"
        record(components_down=stopped, estop_wall_s=round(wall, 2), timings_ms=out["timings_ms"])
    finally:
        for n in reversed(stopped):
            d.containers.get(n).start()
        L.wait_healthy(*[n for n in stopped if n != "gov-status-page"], timeout=240)
    assert L.wait_until(lambda: alice.post("/v1/admin/estop-ingest").status_code == 200, timeout=60)
    recs = alice.get("/v1/audit", params={"action_prefix": "estop.ingested", "target": aid,
                                          "limit": 10}).json()["records"]
    assert any(x["details"]["action"] == "estop.agent_stopped" for x in recs)
    a = alice.get(f"/v1/agents/{aid}").json()
    assert a["status"] == "stopped" and a["desired_state"] == "stopped"
    assert alice.get("/v1/audit/verify").json()["ok"]
    record(journal_ingested=True, audit_chain_ok=True)
