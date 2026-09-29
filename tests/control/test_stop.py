"""Single-agent stop sequence against the live stack (report section 2 / section 8 'single-agent stop',
'quarantine kills live connections', 'restart and persistence')."""
from __future__ import annotations

import subprocess
import time

import pytest

import cpclient
from cpclient import record_result, wait_until

pytestmark = pytest.mark.usefixtures("live")


def _stream_agent(make_agent, team, **kw):
    ag = make_agent(team, credentials=[{"kind": "db", "value": "db-password-for-test"},
                                       {"kind": "tool", "value": "tool-token-for-test"}], **kw)
    agent_id, key = ag["agent"]["agent_id"], ag["gateway_key"]
    c = cpclient.run_agent_container(agent_id, team, {"GATEWAY_URL": "http://gateway:4000", "AGENT_KEY": key,
                                                      "MODEL": "mock-local-slow", "MAX_TOKENS": "200"})
    cpclient.wait_for_log(c, r"TOK .*\nTOK .*\nTOK ", timeout=40)
    return ag, c


def test_single_agent_stop_cuts_stream_blocks_key_and_stays_down(alice, make_agent):
    team = cpclient.uid("t3stop")
    ag, c = _stream_agent(make_agent, team)
    agent_id, key = ag["agent"]["agent_id"], ag["gateway_key"]
    assert cpclient.chat(key).status_code == 200            # key works before the stop

    with cpclient.DenialProbe(lambda: cpclient.chat(key)) as probe:
        t_decision = time.time()
        r = alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "drill: runaway spend"})
        assert r.status_code == 200, r.text
        rep = r.json()
        t_done = time.time()
        time.sleep(0.5)
    assert probe.first_denied is not None and probe.ok_after_denial == 0
    decision_to_denied = probe.first_denied - t_decision
    assert decision_to_denied < 30

    # --- timing target
    assert rep["within_target"] and rep["timings_ms"]["total"] < 30_000, rep["timings_ms"]
    # --- verification built into the stop passed
    assert rep["verify"]["ok"], rep["verify"]["failed"]
    kinds = {x["check"] for x in rep["verify"]["checks"]}
    assert {"gateway.key_blocked", "gateway.request_refused", "workload.not_running", "workload.no_restart",
            "network.isolated", "credential.revoked", "workload.stayed_down"} <= kinds

    # --- gateway: the same key is now refused
    denied = cpclient.chat(key)
    assert denied.status_code == 401 and "blocked" in denied.text.lower()

    # --- in-flight stream was cut: no token after network teardown finished
    net = rep["network"]["results"][0]
    # T8: since the budget guard closes a stream whose key was blocked (checked every second), the gateway may
    # already have ended it before the network phase counts connections; none may remain afterwards
    assert net["connections_before"] >= 0, net
    assert net["connections_after"] == 0, net
    cut_at = rep["phase_end_wall"]["network"]
    events = cpclient.parse_events(c.logs().decode())
    toks_after = [t for k, t, _ in events if k == "TOK" and t > cut_at + 0.25]
    assert not toks_after, f"tokens still arriving after teardown: {toks_after[:3]}"
    last_start = max(t for k, t, _ in events if k == "START")
    assert not any(k == "END" and t > last_start for k, t, _ in events), "stream completed instead of being cut"

    # --- desired state: restart=always was replaced, and it stays down
    c.reload()
    assert c.status != "running"
    assert c.attrs["HostConfig"]["RestartPolicy"]["Name"] == "no"
    time.sleep(4)
    c.reload()
    assert c.status != "running"

    # --- register + audit
    a = alice.get(f"/v1/agents/{agent_id}").json()
    assert a["status"] == "stopped" and a["desired_state"] == "stopped"
    acts = [x["action"] for x in alice.get("/v1/audit", params={"target": agent_id, "limit": 50}).json()["records"]]
    assert "stop.started" in acts and "stop.completed" in acts
    record_result("single_stop", {"agent": agent_id, "timings_ms": rep["timings_ms"],
                                  "decision_to_first_denied_request_s": round(decision_to_denied, 3),
                                  "wall_decision_to_response_s": round(t_done - t_decision, 3),
                                  "network": net, "last_token_before_cut_s": round(
                                      cut_at - max(t for k, t, _ in events if k == "TOK"), 3)})


def test_restart_attempts_are_reverted_by_reconciler(alice, make_agent):
    team = cpclient.uid("t3rst")
    ag, c = _stream_agent(make_agent, team)
    agent_id = ag["agent"]["agent_id"]
    rep = alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "drill"}).json()
    assert rep["verify"]["ok"], rep["verify"]["failed"]
    # someone (or something) starts it again by hand
    c.start()
    t0 = time.time()
    down = wait_until(lambda: (c.reload(), c.status != "running")[1], timeout=10)
    assert down, "reconciler did not stop the revived container"
    rec = alice.get("/v1/audit", params={"action_prefix": "reconciler.enforced_stop", "limit": 20}).json()
    assert any(x["target"] == c.name for x in rec["records"])
    record_result("reconciler_revive", {"docker_start_to_stopped_s": round(time.time() - t0, 2)})


COMPOSE_FILE = cpclient.ROOT / "tests" / "control" / "fixtures" / "compose.rogue.yml"


def test_compose_managed_agent_desired_state_and_no_revival(alice, make_agent, tmp_path):
    team = cpclient.uid("t3cmp")
    ag = make_agent(team)
    agent_id, key = ag["agent"]["agent_id"], ag["gateway_key"]
    project = f"t3rogue{agent_id.split('-')[-1]}"
    env = {"ROGUE_AGENT_ID": agent_id, "ROGUE_TEAM": team, "ROGUE_KEY": key}
    envfile = tmp_path / "rogue.env"
    envfile.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    base = ["docker", "compose", "-p", project, "-f", str(COMPOSE_FILE), "--env-file", str(envfile)]
    subprocess.run(base + ["up", "-d"], check=True, capture_output=True)
    try:
        d = cpclient.dclient()
        c = wait_until(lambda: next(iter(d.containers.list(filters={"label": f"govpilot.agent_id={agent_id}"})),
                                    None), timeout=20)
        assert c is not None
        assert c.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"
        cpclient.wait_for_log(c, r"TOK ", timeout=40)
        rep = alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "drill: compose-managed"}).json()
        assert rep["verify"]["ok"], rep["verify"]["failed"]
        assert rep["workloads"][0]["controller"].startswith("compose:")
        # the compose "controller" tries to bring it back
        t0 = time.time()
        subprocess.run(base + ["up", "-d"], check=True, capture_output=True)
        down = wait_until(lambda: all(x.status != "running" for x in d.containers.list(
            all=True, filters={"label": f"govpilot.agent_id={agent_id}"})), timeout=15)
        assert down, "compose up revived the agent and it was not re-stopped"
        t_down = time.time()
        time.sleep(3)
        assert all(x.status != "running" for x in d.containers.list(
            all=True, filters={"label": f"govpilot.agent_id={agent_id}"}))
        record_result("compose_revive", {"compose_up_to_stopped_s": round(t_down - t0, 2),
                                         "stop_timings_ms": rep["timings_ms"]})
    finally:
        subprocess.run(base + ["down", "-t", "0"], capture_output=True)


def test_resume_reverses_a_stop(alice, make_agent):
    team = cpclient.uid("t3res")
    ag, c = _stream_agent(make_agent, team)
    agent_id, key = ag["agent"]["agent_id"], ag["gateway_key"]
    assert alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "drill"}).json()["verify"]["ok"]
    r = alice.post(f"/v1/agents/{agent_id}/resume", {"reason": "false positive"})
    assert r.status_code == 200, r.text
    assert cpclient.chat(key).status_code == 200
    c.reload()
    assert c.status == "running" and cpclient.AGENTS_NET in c.attrs["NetworkSettings"]["Networks"]
    assert c.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"
    assert alice.get(f"/v1/agents/{agent_id}").json()["status"] == "active"
    # credentials stay revoked after resume (must be re-issued)
    assert "not restored" in r.json()["credentials_note"]
    alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "cleanup"})


def test_stop_requires_operator(erin, make_agent):
    ag = make_agent(cpclient.uid("t3auth"))
    r = erin.post(f"/v1/agents/{ag['agent']['agent_id']}/stop", {"reason": "x"})
    assert r.status_code == 403
