"""Bulk quarantine by selector: blast-radius preview, human trigger, dual control, rules that stick
(report section 4 'mass-kill action', section 8 'bulk quarantine')."""
from __future__ import annotations

import time

import pytest

import cpclient
from cpclient import record_result, wait_until

pytestmark = pytest.mark.usefixtures("live")


def _fleet(make_agent, team, n, run_label, stream=False):
    out = []
    for _ in range(n):
        ag = make_agent(team)
        env = {"GATEWAY_URL": "http://gateway:4000", "AGENT_KEY": ag["gateway_key"],
               "MODEL": "mock-local-slow" if stream else "mock-local", "MAX_TOKENS": "200" if stream else "2"}
        c = cpclient.run_agent_container(ag["agent"]["agent_id"], team, env, extra_labels={"t3.run": run_label})
        out.append((ag, c))
    for _, c in out:
        cpclient.wait_for_log(c, r"(TOK|END) ", timeout=40)
    return out


def _all_down(containers):
    for c in containers:
        c.reload()
        if c.status == "running":
            return False
    return True


def test_team_selector_preview_then_quarantine_and_rule_sticks(alice, make_agent):
    team, run = cpclient.uid("t3q"), cpclient.uid("run")
    fleet = _fleet(make_agent, team, 3, run, stream=True)
    ids = sorted(a["agent"]["agent_id"] for a, _ in fleet)

    pv = alice.post("/v1/quarantine/preview", {"team": team})
    assert pv.status_code == 200, pv.text
    pv = pv.json()
    assert sorted(pv["agent_ids"]) == ids
    assert pv["counts"]["agents"] == 3 and pv["counts"]["running_workloads"] == 3 and pv["counts"]["gateway_keys"] == 3
    assert pv["fleet_wide"] is False and pv["approvals_required"] == 0
    # nothing happened yet: preview is read-only
    assert all(cpclient.chat(a["gateway_key"]).status_code == 200 for a, _ in fleet)

    t0 = time.time()
    r = alice.post("/v1/quarantine/actions", {"preview_id": pv["preview_id"], "reason": "suspect tool version"})
    assert r.status_code == 200, r.text
    act = r.json()
    assert act["status"] == "executed", act
    rep = act["report"]
    assert rep["verify"]["ok"], rep["verify"]["failed"]
    assert sorted(rep["agents"]) == ids
    assert rep["timings_ms"]["total"] < 30_000
    assert _all_down([c for _, c in fleet])
    assert all(cpclient.chat(a["gateway_key"]).status_code == 401 for a, _ in fleet)
    record_result("bulk_team_3_agents", {"timings_ms": rep["timings_ms"], "wall_s": round(time.time() - t0, 2)})

    # the rule keeps enforcing: a new container for that team is stopped on sight
    late = cpclient.run_agent_container(cpclient.uid("t3late"), team, {"AGENT_KEY": "sk-none"},
                                        extra_labels={"t3.run": run})
    assert wait_until(lambda: (late.reload(), late.status != "running")[1], timeout=10)

    # lift reverses it (reversible quarantine)
    lf = alice.post(f"/v1/quarantine/actions/{act['action_id']}/lift", {"resume_agents": True})
    assert lf.status_code == 200 and lf.json()["status"] == "lifted"
    assert all(cpclient.chat(a["gateway_key"]).status_code == 200 for a, _ in fleet)
    for _, c in fleet:
        c.reload()
        assert c.status == "running"
    pv2 = alice.post("/v1/quarantine/preview", {"team": team}).json()
    alice.post("/v1/quarantine/actions", {"preview_id": pv2["preview_id"], "reason": "cleanup"})


def test_label_and_image_selectors_include_unmanaged_workloads(alice, make_agent):
    team, run = cpclient.uid("t3img"), cpclient.uid("run")
    (ag, c), = _fleet(make_agent, team, 1, run)
    d = cpclient.dclient()
    # an unregistered container running the same (suspect) image, same label
    shadow = d.containers.run(cpclient.AGENT_IMAGE, ["sleep", "600"], detach=True, name=cpclient.uid("t3shadow"),
                              labels={**cpclient.TEST_LABEL, "t3.run": run}, network=cpclient.AGENTS_NET,
                              restart_policy={"Name": "unless-stopped"})
    pv = alice.post("/v1/quarantine/preview", {"labels": {"t3.run": run}, "image": cpclient.AGENT_IMAGE}).json()
    assert pv["agent_ids"] == [ag["agent"]["agent_id"]]
    assert [w["name"] for w in pv["unmanaged_workloads"]] == [shadow.name]
    act = alice.post("/v1/quarantine/actions", {"preview_id": pv["preview_id"], "reason": "poisoned image"}).json()
    assert act["status"] == "executed" and act["report"]["verify"]["ok"], act["report"]["verify"]
    assert _all_down([c, shadow])
    shadow.reload()
    assert shadow.attrs["HostConfig"]["RestartPolicy"]["Name"] == "no"
    assert cpclient.AGENTS_NET not in shadow.attrs["NetworkSettings"]["Networks"]


def test_host_selector_preview(alice, make_agent):
    run = cpclient.uid("run")
    (ag, _), = _fleet(make_agent, cpclient.uid("t3host"), 1, run)
    host = cpclient.dclient().info()["Name"]
    pv = alice.post("/v1/quarantine/preview", {"host": host}).json()
    assert pv["selector"]["host"] == host
    # every agent with a workload on this host is in the blast radius (preview only; not fired)
    assert ag["agent"]["agent_id"] in pv["agent_ids"]
    pv_other = alice.post("/v1/quarantine/preview", {"host": "some-other-host"}).json()
    assert pv_other["counts"]["agents"] == 0 and pv_other["counts"]["unmanaged_workloads"] == 0


def test_fleet_wide_needs_two_distinct_human_approvals(alice, bob, carol, make_agent):
    run = cpclient.uid("run")
    fleet = _fleet(make_agent, cpclient.uid("t3dcA"), 1, run) + _fleet(make_agent, cpclient.uid("t3dcB"), 1, run)
    pv = alice.post("/v1/quarantine/preview", {"labels": {"t3.run": run}}).json()
    assert pv["counts"]["agents"] == 2 and len(pv["teams"]) == 2
    assert pv["fleet_wide"] is True and pv["approvals_required"] == 2

    act = alice.post("/v1/quarantine/actions", {"preview_id": pv["preview_id"], "reason": "cross-team incident"})
    act = act.json()
    assert act["status"] == "pending_approval"
    assert all(cpclient.chat(a["gateway_key"]).status_code == 200 for a, _ in fleet)   # nothing fired yet

    aid = act["action_id"]
    assert alice.post(f"/v1/quarantine/actions/{aid}/approve").status_code == 403       # requester
    r1 = bob.post(f"/v1/quarantine/actions/{aid}/approve")
    assert r1.status_code == 200 and r1.json()["status"] == "pending_approval"
    assert bob.post(f"/v1/quarantine/actions/{aid}/approve").status_code == 403          # same person twice
    r2 = carol.post(f"/v1/quarantine/actions/{aid}/approve")
    assert r2.status_code == 200, r2.text
    done = r2.json()
    assert done["status"] == "executed" and done["report"]["verify"]["ok"]
    assert [x["by"] for x in done["approvals"]] == ["bob", "carol"]
    assert _all_down([c for _, c in fleet])
    assert all(cpclient.chat(a["gateway_key"]).status_code == 401 for a, _ in fleet)


def test_all_selector_is_fleet_wide_and_empty_selector_rejected(alice):
    pv = alice.post("/v1/quarantine/preview", {"all": True}).json()
    assert pv["fleet_wide"] is True and pv["approvals_required"] == 2
    assert alice.post("/v1/quarantine/preview", {}).status_code == 422


def test_stale_preview_is_refused(alice, make_agent):
    team = cpclient.uid("t3stale")
    make_agent(team)
    pv = alice.post("/v1/quarantine/preview", {"team": team}).json()
    make_agent(team)                                  # the fleet changed after the humans looked
    r = alice.post("/v1/quarantine/actions", {"preview_id": pv["preview_id"], "reason": "x"})
    assert r.status_code == 409 and r.json()["error"] == "stale_preview"


def test_viewer_cannot_preview_or_fire(erin):
    assert erin.post("/v1/quarantine/preview", {"team": "hr"}).status_code == 403
