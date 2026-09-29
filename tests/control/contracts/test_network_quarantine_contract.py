"""NetworkQuarantine contract (Docker netns-RST + disconnect adapter, in-memory reference).

The Docker case also proves the report's hardest network claim on this stack:
a long-lived streaming connection opened BEFORE quarantine is terminated when the
quarantine lands, without stopping the workload (section 8 'quarantine kills live connections').
"""
from __future__ import annotations

import time
import uuid

import pytest

import cpclient
from cpclient import live_or_skip

from govcp.adapters.memory import MemoryNetwork, MemoryOrchestrator
from govcp.domain.models import Workload


@pytest.fixture(params=["memory", "docker"])
def fx(request):
    if request.param == "memory":
        o = MemoryOrchestrator()
        n = MemoryNetwork(o, governed=[cpclient.AGENTS_NET])

        def spawn():
            w = o.add(Workload(id=uuid.uuid4().hex, name="w", image="x", labels={}, host="h", running=True,
                               networks=[cpclient.AGENTS_NET, "other"]))
            n.connections[w.id] = 1
            return w, None
        yield "memory", o, n, spawn
        return
    live_or_skip()
    from govcp.adapters.docker_orchestrator import DockerNetworkQuarantine, DockerOrchestrator
    o = DockerOrchestrator()
    n = DockerNetworkQuarantine([cpclient.AGENTS_NET], ["gov-gateway", "gov-authproxy"], cpclient.AGENT_IMAGE)
    made = []

    def spawn():
        # a streaming agent with its own short-lived key on the coding-agent's allowlist
        import httpx
        gw = cpclient.gw_admin()
        alias = cpclient.uid("t3nq")
        k = gw.post("/key/generate", json={"key_alias": alias, "models": ["mock-local-slow"], "max_budget": 0.05,
                                           "metadata": {"agent_id": alias,
                                                                        **cpclient.DRILL_KEY_METADATA}}).json()
        c = cpclient.run_agent_container(alias, "t3nq", {"AGENT_KEY": k["key"], "MODEL": "mock-local-slow",
                                                         "MAX_TOKENS": "200"})
        made.append((c, k["token"]))
        cpclient.wait_for_log(c, r"TOK .*\nTOK ", timeout=40)
        return o.get(c.id), c
    yield "docker", o, n, spawn
    gw = cpclient.gw_admin()
    for c, h in made:
        c.remove(force=True)
        gw.post("/key/delete", json={"keys": [h]})


def test_isolate_cuts_live_connections_and_detaches(fx):
    kind, o, n, spawn = fx
    w, c = spawn()
    assert n.is_isolated(w.id) is False
    t_iso = time.time()
    (res,) = n.isolate([w])
    t_done = time.time()
    assert res.connections_before >= 1
    assert res.connections_after == 0
    assert cpclient.AGENTS_NET in res.networks_removed
    assert n.is_isolated(w.id) is True
    if kind == "docker":
        c.reload()
        assert c.status == "running"                     # the workload itself was NOT stopped...
        time.sleep(2)
        ev = cpclient.parse_events(c.logs().decode())
        late = [t for k, t, _ in ev if k == "TOK" and t > t_done + 0.25]
        assert not late, "...but its stream kept flowing after quarantine"
        assert not any(k == "END" and t > t_iso for k, t, _ in ev), "stream finished instead of being cut"
        # Note: the agent's own socket is not notified (this kernel lacks SOCK_DESTROY, so no `ss -K`);
        # it just stops receiving. The gateway side got the RST, so upstream generation/spend stops.


def test_restore_reattaches(fx):
    kind, o, n, spawn = fx
    w, c = spawn()
    (res,) = n.isolate([w])
    n.restore(w.id, res.networks_removed, res.network_aliases)
    assert n.is_isolated(w.id) is False


def test_isolating_a_stopped_workload_still_detaches(fx):
    kind, o, n, spawn = fx
    w, c = spawn()
    o.stop(w.id, grace_s=0)
    (res,) = n.isolate([o.get(w.id)])
    assert n.is_isolated(w.id) is True
