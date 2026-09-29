"""S8-01 Single-agent stop: a named agent's new model requests are denied within 30 s of the stop decision."""
from __future__ import annotations

import time

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")


@pytest.mark.accept(
    id="S8-01", title="Single-agent stop",
    criterion="New model requests of the named agent are denied <= 30 s after the stop decision; the agent "
              "stays stopped",
    simplification="Docker container + restart policy stand in for a Kubernetes Deployment; the stop "
                   "decision is an API call by an operator (no alerting pipeline triggers it).")
def test_single_agent_stop(alice, drill, record):
    ag = drill.agent(L.uid("t8stop"), credentials=[{"kind": "db", "value": "db-pass-drill"}])
    agent_id, key = ag["agent"]["agent_id"], ag["gateway_key"]
    c = drill.run(ag)
    L.wait_for_log(c, r"TOK .*\nTOK ")
    assert L.chat(key).status_code == 200

    with L.DenialProbe(lambda: L.chat(key)) as probe:
        t0 = time.time()
        r = alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "acceptance S8-01: runaway spend"})
        t_done = time.time()
        time.sleep(0.5)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert probe.first_denied is not None and probe.ok_after_denial == 0
    denied_s = probe.first_denied - t0
    assert denied_s <= 30
    assert rep["verify"]["ok"], rep["verify"]["failed"]
    assert L.chat(key).status_code == 401
    time.sleep(3)
    c.reload()
    assert c.status != "running" and c.attrs["HostConfig"]["RestartPolicy"]["Name"] == "no"
    record(decision_to_first_denied_request_s=round(denied_s, 3), full_stop_sequence_s=round(t_done - t0, 2),
           timings_ms=rep["timings_ms"], successful_requests_after_first_denial=probe.ok_after_denial,
           verify_checks=len(rep["verify"]["checks"]))
