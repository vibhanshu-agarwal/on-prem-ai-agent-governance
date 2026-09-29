"""Orchestrator contract (Docker adapter + in-memory reference)."""
from __future__ import annotations

import uuid

import pytest

import cpclient
from cpclient import live_or_skip

from govcp.adapters.memory import MemoryOrchestrator
from govcp.domain.models import Workload


class MemoryFactory:
    def __init__(self):
        self.o = MemoryOrchestrator()

    def spawn(self, labels):
        wid = uuid.uuid4().hex
        return self.o.add(Workload(id=wid, name=f"w-{wid[:6]}", image=cpclient.AGENT_IMAGE, labels=labels,
                                   host=self.o.host_name(), running=True, restart_policy="always",
                                   networks=[cpclient.AGENTS_NET])).id

    def cleanup(self):
        pass


class DockerFactory:
    def __init__(self):
        from govcp.adapters.docker_orchestrator import DockerOrchestrator
        self.o = DockerOrchestrator()
        self.d = cpclient.dclient()
        self.made = []

    def spawn(self, labels):
        c = self.d.containers.run(cpclient.AGENT_IMAGE, ["sleep", "600"], detach=True, name=cpclient.uid("t3orc"),
                                  labels={**labels, **cpclient.TEST_LABEL}, network=cpclient.AGENTS_NET,
                                  restart_policy={"Name": "always"})
        self.made.append(c)
        return c.id

    def cleanup(self):
        for c in self.made:
            c.remove(force=True)


@pytest.fixture(params=["memory", "docker"])
def fx(request):
    if request.param == "docker":
        live_or_skip()
        f = DockerFactory()
    else:
        f = MemoryFactory()
    yield f
    f.cleanup()


def test_list_by_labels_image_host(fx):
    tag = cpclient.uid("orc")
    wid = fx.spawn({"t3.contract": tag})
    ws = fx.o.list_workloads(labels={"t3.contract": tag})
    assert [w.id for w in ws] == [wid]
    w = ws[0]
    assert w.running and w.restart_policy == "always" and cpclient.AGENTS_NET in w.networks
    assert w.host == fx.o.host_name()
    assert [x.id for x in fx.o.list_workloads(labels={"t3.contract": tag}, image=cpclient.AGENT_IMAGE)] == [wid]
    assert fx.o.list_workloads(labels={"t3.contract": tag}, image="no-such-image") == []
    assert fx.o.list_workloads(labels={"t3.contract": tag}, host="other-host") == []


def test_desired_state_then_stop_then_restore(fx):
    tag = cpclient.uid("orc")
    wid = fx.spawn({"t3.contract": tag})
    assert fx.o.prevent_restart(wid) == "always"
    assert fx.o.get(wid).restart_policy == "no"
    fx.o.stop(wid, grace_s=1)
    assert fx.o.get(wid).running is False
    assert fx.o.list_workloads(labels={"t3.contract": tag}, include_stopped=False) == []
    assert len(fx.o.list_workloads(labels={"t3.contract": tag}, include_stopped=True)) == 1
    fx.o.restore_restart(wid, "always")
    fx.o.start(wid)
    w = fx.o.get(wid)
    assert w.running and w.restart_policy == "always"


def test_unknown_workload(fx):
    assert fx.o.get("0" * 64) is None
