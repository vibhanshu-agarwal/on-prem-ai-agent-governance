"""T6 acceptance, live: an unregistered service making an AI call appears in the pending queue and can
spend nothing; a noisy feed is capped.

Needs: T1 stack, control plane, gov-discovery (scripts/discovery-up.sh). The gateway-key test also needs the
observability stack (the real gateway exports OTel spans to it since T8); the eBPF test needs the OpenLIT Controller
(scripts/observability-up.sh ebpf) and DNS for api.openai.com (it only opens a TCP connection, no request is sent).
"""
from __future__ import annotations

import json
import time
import uuid

import docker
import httpx
import pytest

import cpclient
from common import ROGUE_LABEL, ROOT, _running
from fakes import obs
from govdisc.adapters.controlplane_sink import ControlPlaneSink
from govdisc.ratelimit import DailyBudget
from govdisc.runner import FeedRunner
from fakes import ListFeed

pytestmark = pytest.mark.usefixtures("live")
RESULTS = ROOT / ".local" / "t6-results"
IMAGE = "govpilot/mock-provider:1"          # python + nothing else: stands in for a shadow agent

# What the rogue "agent" runs: an AI call to the gateway with no key, then with a made-up key.
ROGUE_CODE = r"""
import json, time, urllib.request, urllib.error
def call(key):
    h = {'content-type': 'application/json'}
    if key: h['authorization'] = 'Bearer ' + key
    r = urllib.request.Request('http://gateway:4000/v1/chat/completions', headers=h, data=json.dumps(
        {'model': 'mock-local', 'max_tokens': 8, 'messages': [{'role': 'user', 'content': 'hello'}]}).encode())
    try:
        with urllib.request.urlopen(r, timeout=10) as x: return x.status, x.read()[:120]
    except urllib.error.HTTPError as e: return e.code, e.read()[:120]
    except Exception as e: return 'ERR', str(e)[:120]
print('STATUS-NOKEY', call(None), flush=True)
print('STATUS-FAKEKEY', call('sk-not-a-real-key'), flush=True)
time.sleep(90)
"""

BYPASS_CODE = r"""
import socket, time
try:
    ips = {a[4][0] for a in socket.getaddrinfo('api.openai.com', 443, socket.AF_INET)}
except Exception as e:
    print('NODNS', e, flush=True); raise SystemExit(0)
t_end = time.time() + 100
first = True
while time.time() < t_end:                       # reconnect every few seconds: the eBPF probe sees a fresh connect each time
    socks = []
    for ip in ips:                               # TCP handshake only: no bytes are sent, no credentials, no spend
        try: socks.append(socket.create_connection((ip, 443), timeout=8))
        except Exception as e: print('connect-fail', ip, e, flush=True)
    if first: print('CONNECTED', len(socks), flush=True); first = False
    time.sleep(4)
    for s in socks: s.close()
"""


def _uid(p):
    return f"{p}-{uuid.uuid4().hex[:6]}"


def _run(name, code, networks=("govpilot_agents",), labels=None):
    d = docker.from_env()
    c = d.containers.run(IMAGE, ["python", "-u", "-c", code], name=name, detach=True,
                         labels={**ROGUE_LABEL, **(labels or {})},
                         network=networks[0] if networks else "bridge")
    return c


def _wait_proposal(alice, name, timeout=40, **match):
    t0 = time.time()
    while time.time() - t0 < timeout:
        for p in alice.get("/v1/discovery/proposals").json()["proposals"]:
            if p["observation"]["name"] == name and all(p.get(k) == v for k, v in match.items()):
                return p, time.time() - t0
        time.sleep(1)
    raise AssertionError(f"no proposal for {name!r} within {timeout}s")


def _save(name, data):
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{name}.json").write_text(json.dumps(data, indent=2))


def test_unregistered_container_making_an_ai_call_is_proposed_and_refused(alice, reject_after):
    name = _uid("t6-rogue")
    c = _run(name, ROGUE_CODE, labels={"owner": "mallory", "team": "finance"})
    p, seconds = _wait_proposal(alice, name)
    reject_after.append(p["proposal_id"])

    # --- it is in the pending queue, and it holds nothing
    assert p["status"] == "pending" and p["budget_usd"] == 0 and p["gateway_key"] is None
    assert p["feed"] in ("docker-events", "gateway-logs")
    o = p["observation"]
    assert o["image"] == IMAGE and o["suggested_owner"] == "mallory" and o["suggested_team"] == "finance"
    ev = o["evidence"]
    assert ev["image"] == IMAGE and ev["first_seen"].endswith("Z") and ev["labels"]["owner"] == "mallory"
    assert ev["probable_owner"]["value"] == "mallory" and "govpilot_agents" in ev["on_governed_network"]

    # --- and it can spend nothing: the call was refused, with or without a made-up key
    time.sleep(2)
    out = c.logs().decode()
    assert "STATUS-NOKEY (401," in out and "STATUS-FAKEKEY (401," in out, out
    ip = docker.from_env().containers.get(name).attrs["NetworkSettings"]["Networks"]["govpilot_agents"]["IPAddress"]
    gw = docker.from_env().containers.get("gov-gateway").logs(since=int(time.time()) - 120).decode()
    assert f"{ip}:" in gw and any(f'{ip}:' in l and '" 401 ' in l for l in gw.splitlines())
    # no gateway key exists that it could use, and it is not in the register
    assert cpclient.gw_admin().get("/key/list", params={"key_alias": name}).json().get("keys") == []
    assert name not in {a["agent_id"] for a in alice.get("/v1/agents").json()["agents"]}
    _save("rogue-container", {"seconds_to_pending_proposal": round(seconds, 1), "feed": p["feed"],
                              "gateway_result": "401 (no key) and 401 (made-up key)", "budget_usd": p["budget_usd"]})


def test_registered_agent_workloads_are_not_proposed(alice, reject_after):
    name = _uid("t6-known")
    _run(name, "import time; time.sleep(30)", labels={"govpilot.agent_id": "hr-agent"})
    time.sleep(10)                                              # several poll cycles
    props = alice.get("/v1/discovery/proposals").json()["proposals"]
    assert name not in {p["observation"]["name"] for p in props}


def test_gateway_key_that_is_not_in_the_register_is_proposed(alice, reject_after):
    if not _running("gov-obs-clickhouse"):
        pytest.skip("observability stack not running (scripts/observability-up.sh)")
    alias = _uid("t6-shadow-key")
    gw = cpclient.gw_admin()
    r = gw.post("/key/generate", json={"key_alias": alias, "max_budget": 0.05,
                                       "metadata": {"agent_id": alias, "owner": "mallory"}})
    assert r.status_code == 200, r.text
    key = r.json()["key"]
    try:
        for _ in range(3):
            resp = httpx.post("http://127.0.0.1:4000/v1/chat/completions", timeout=30,
                              headers={"Authorization": f"Bearer {key}"},
                              json={"model": "mock-local", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]})
            assert resp.status_code == 200, resp.text
        p, seconds = _wait_proposal(alice, alias, timeout=90, feed="gateway-logs")
        reject_after.append(p["proposal_id"])
        assert p["status"] == "pending" and p["budget_usd"] == 0 and p["gateway_key"] is None
        ev = p["observation"]["evidence"]
        assert ev["source"] == "gateway-otel" and ev["calls"] >= 1 and ev["models"] == ["mock-local"]
        assert p["observation"]["suggested_owner"] == "mallory" and ev["key_alias"] == alias
        assert key not in json.dumps(p)                          # never the key itself
        _save("unregistered-key", {"seconds_to_pending_proposal": round(seconds, 1), "calls": ev["calls"]})
    finally:
        gw.post("/key/delete", json={"keys": [key]})


def test_direct_to_provider_bypass_is_found_by_ebpf(alice, reject_after):
    if not _running("gov-obs-controller"):
        pytest.skip("OpenLIT Controller not running (scripts/observability-up.sh ebpf)")
    name = _uid("t6-bypass")
    c = _run(name, BYPASS_CODE, networks=(), labels={"owner": "erin"})       # default bridge: not on a governed network
    time.sleep(3)
    if "NODNS" in c.logs().decode() or "CONNECTED 0" in c.logs().decode():
        pytest.skip("cannot reach api.openai.com from here")
    p, seconds = _wait_proposal(alice, name, timeout=90)
    reject_after.append(p["proposal_id"])
    assert p["feed"] == "openlit-controller" and p["status"] == "pending" and p["budget_usd"] == 0
    ebpf = p["observation"]["evidence"]["ebpf"]
    assert ebpf["llm_providers"] == ["openai"] and ebpf["bypasses_gateway"] is True
    assert p["observation"]["suggested_owner"] == "erin"
    _save("ebpf-bypass", {"seconds_to_pending_proposal": round(seconds, 1), "evidence": ebpf})


def test_a_noisy_feed_is_capped_by_the_per_feed_daily_limit(alice, reject_after):
    """Real control plane, real sink, a feed that emits 40 things. The control plane's default per-feed cap
    (20/day for an unknown feed) is authoritative; the runner stops calling and keeps the rest for tomorrow."""
    cid = _uid("t6-noisy")
    sec = cpclient.idp_admin("POST", "/admin/clients", json={"client_id": cid, "roles": ["feed"]}).json()["client_secret"]
    sink = ControlPlaneSink(cpclient.CP_URL, cpclient.IDP_URL + "/token", cid, sec)
    feed = ListFeed(cid, [obs(i, fp=f"container:{cid}-{i}:img") for i in range(40)])
    runner = FeedRunner(feed, sink, DailyBudget(1000), backlog_max=200)     # client cap deliberately too generous
    runner.tick()
    mine = [p for p in alice.get("/v1/discovery/proposals").json()["proposals"] if p["feed"] == cid]
    reject_after.extend(p["proposal_id"] for p in mine)
    assert len(mine) == 20 and all(p["status"] == "pending" and p["budget_usd"] == 0 for p in mine)
    assert runner.stats.created == 20 and runner.stats.rate_limited == 1
    assert len(runner.backlog) == 20                            # held for tomorrow, not lost, not hammering the API
    runner.tick()
    assert len([p for p in alice.get("/v1/discovery/proposals").json()["proposals"] if p["feed"] == cid]) == 20
    # the refusal is audited by the control plane
    audit = alice.get("/v1/audit", params={"limit": 200}).json()
    recs = audit["records"] if isinstance(audit, dict) and "records" in audit else audit
    assert any(r.get("action") == "discovery.rate_limited" and r.get("actor") == cid for r in recs)
    _save("noisy-feed", {"feed_emitted": 40, "proposals_created": 20, "held_for_tomorrow": len(runner.backlog)})


def test_client_side_cap_means_the_control_plane_is_not_even_called(alice, reject_after):
    cid = _uid("t6-capped")
    sec = cpclient.idp_admin("POST", "/admin/clients", json={"client_id": cid, "roles": ["feed"]}).json()["client_secret"]
    inner = ControlPlaneSink(cpclient.CP_URL, cpclient.IDP_URL + "/token", cid, sec)
    calls = []

    class Counting:
        def submit(self, feed, o):
            calls.append(o.fingerprint)
            return inner.submit(feed, o)
    feed = ListFeed(cid, [obs(i, fp=f"container:{cid}-{i}:img") for i in range(12)])
    runner = FeedRunner(feed, Counting(), DailyBudget(5), backlog_max=200)
    runner.tick()
    runner.tick()
    mine = [p for p in alice.get("/v1/discovery/proposals").json()["proposals"] if p["feed"] == cid]
    reject_after.extend(p["proposal_id"] for p in mine)
    assert len(mine) == 5 and len(calls) == 5 and len(runner.backlog) == 7
