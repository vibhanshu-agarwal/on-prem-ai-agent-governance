"""S8-06 Bulk quarantine: all workloads matching a selector are denied, stopped, and do not restart."""
from __future__ import annotations

import time

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")


def _down(cs):
    for c in cs:
        c.reload()
        if c.status == "running":
            return False
    return True


@pytest.mark.accept(
    id="S8-06", title="Bulk quarantine",
    criterion="A label selector spanning 4 agents in 2 teams (fleet-wide, so dual control) previews the blast "
              "radius, then denies, stops and pins down every match; revivals and new matching containers are "
              "re-stopped",
    simplification="Selectors are Docker labels / image / team / host (Docker daemon); 'namespace' maps to a "
                   "label. Kubernetes would scale Deployments to 0 and apply a NetworkPolicy.")
def test_bulk_quarantine(alice, bob, carol, drill, record):
    run = L.uid("fleet")
    fleet = []
    for team in (L.uid("t8qa"), L.uid("t8qb")):
        for _ in range(2):
            ag = drill.agent(team)
            c = drill.run(ag, env={"MODEL": "mock-local", "MAX_TOKENS": "2"}, labels={"t8.fleet": run})
            fleet.append((ag, c))
    for _, c in fleet:
        L.wait_for_log(c, r"(TOK|END) ")
    ids = sorted(a["agent"]["agent_id"] for a, _ in fleet)

    pv = alice.post("/v1/quarantine/preview", {"labels": {"t8.fleet": run}}).json()
    assert sorted(pv["agent_ids"]) == ids and pv["fleet_wide"] is True and pv["approvals_required"] == 2
    t0 = time.time()
    act = alice.post("/v1/quarantine/actions", {"preview_id": pv["preview_id"], "reason": "acceptance S8-06"}).json()
    assert act["status"] == "pending_approval", act
    assert all(L.chat(a["gateway_key"]).status_code == 200 for a, _ in fleet)       # nothing before approvals
    r1 = bob.post(f"/v1/quarantine/actions/{act['action_id']}/approve", {"reason": "confirmed"}).json()
    t_second = time.time()
    r2 = carol.post(f"/v1/quarantine/actions/{act['action_id']}/approve", {"reason": "confirmed"}).json()
    t_done = time.time()
    assert r2["status"] == "executed", r2
    rep = r2["report"]
    assert rep["verify"]["ok"], rep["verify"]["failed"]
    assert all(L.chat(a["gateway_key"]).status_code == 401 for a, _ in fleet)
    assert _down([c for _, c in fleet])
    assert all((c.reload(), c.attrs["HostConfig"]["RestartPolicy"]["Name"])[1] == "no" for _, c in fleet)

    # revival attempt: an operator (or the compromised workload) restarts one; the rule re-stops it
    victim = fleet[0][1]
    victim.start()
    t_rev = time.time()
    assert L.wait_until(lambda: _down([victim]), timeout=15), "revived container was not re-stopped"
    restop_s = time.time() - t_rev
    # a brand-new container matching the selector is stopped on sight
    late = drill.run(drill.agent(L.uid("t8qc")), env={"AGENT_KEY": "sk-none"}, labels={"t8.fleet": run},
                     name=L.uid("t8-late"))
    t_late = time.time()
    assert L.wait_until(lambda: _down([late]), timeout=15)
    late_s = time.time() - t_late
    record(agents=len(ids), teams=2, approvals=2, second_approval_to_contained_s=round(t_done - t_second, 2),
           timings_ms=rep["timings_ms"], revived_container_restopped_s=round(restop_s, 1),
           new_matching_container_stopped_s=round(late_s, 1), request_to_contained_s=round(t_done - t0, 1),
           first_approval_status=r1.get("status"))
    alice.post(f"/v1/quarantine/actions/{act['action_id']}/lift", {"resume_agents": False})
