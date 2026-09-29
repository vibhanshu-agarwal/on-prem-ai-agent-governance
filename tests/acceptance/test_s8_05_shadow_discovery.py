"""S8-05 Shadow discovery: a deliberately unregistered service making an AI call appears in the pending queue
and can spend nothing."""
from __future__ import annotations

import time

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")

SHADOW = r"""
import json, time, urllib.request, urllib.error
def call(key):
    req = urllib.request.Request("http://gateway:4000/v1/chat/completions", method="POST",
        data=json.dumps({"model": "mock-local", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}).encode(),
        headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + key} if key else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return type(e).__name__
while True:
    print("STATUS", call(None), call("sk-shadow-made-up"), flush=True)
    time.sleep(5)
"""


@pytest.mark.accept(
    id="S8-05", title="Shadow discovery",
    criterion="An unregistered container that calls the gateway appears as a pending proposal with budget 0 and "
              "no gateway key; every call it made was refused",
    simplification="Feeds are docker events, the gateway access log / OTel spans and eBPF (OpenLIT Controller); "
                   "no Kubernetes watch or cloud inventory. Approval stays a human action (not exercised here).")
def test_shadow_discovery(alice, drill, record):
    name = L.uid("t8-shadow")
    d = L.dclient()
    # deliberately NOT labelled govpilot.t8test (that label is on the discovery ignore list)
    c = d.containers.run(L.PROBE_IMAGE, entrypoint="python", command=["-u", "-c", SHADOW], name=name, detach=True,
                         labels={"owner": "mallory", "team": "growth-hacks"}, network=L.AGENTS_NET)
    drill.containers.append(c)
    t0 = time.time()
    prop = L.wait_until(lambda: next((p for p in alice.get("/v1/discovery/proposals").json()["proposals"]
                                      if p["observation"].get("name") == name), None), timeout=90, interval=1.0)
    assert prop, "shadow service never reached the pending queue"
    seconds = time.time() - t0
    assert prop["status"] == "pending" and prop["budget_usd"] == 0 and prop["gateway_key"] is None
    logs = c.logs().decode()
    statuses = {s for line in logs.splitlines() if line.startswith("STATUS") for s in line.split()[1:]}
    assert statuses and statuses <= {"401", "403"}, logs[-500:]
    keys = L.gw_admin().get("/key/list", params={"key_alias": name}).json().get("keys")
    assert not keys
    alice.post(f"/v1/discovery/proposals/{prop['proposal_id']}/reject", {"reason": "acceptance S8-05 cleanup"})
    record(seconds_to_pending_proposal=round(seconds, 1), feed=prop["feed"], budget_usd=prop["budget_usd"],
           gateway_statuses_seen=sorted(statuses), suggested_owner=prop["observation"].get("suggested_owner"))
