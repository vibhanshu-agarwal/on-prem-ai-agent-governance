"""DiscoveryFeed contract (interface only in T3; T6 implements feeds and adds them to FEEDS).

`assert_feed_contract` is what any feed (docker events, k8s watch, OpenLIT
Controller, gateway logs) must satisfy, including the governance rule that its
observations land as pending proposals with zero budget and no gateway key.
"""
from __future__ import annotations

import pytest

from govcp.adapters.memory import (ListFeed, MemoryAudit, MemoryGateway, MemoryIdentity, MemoryNetwork,
                                   MemoryOrchestrator, MemoryRepository, MemoryRevoker, MemorySecretStore)
from govcp.domain.context import Ports
from govcp.domain.models import DiscoveryObservation
from govcp.domain.ports import DiscoveryFeed
from govcp.domain.repository import PROPOSALS
from govcp.wiring import build_app


def _obs(i):
    return DiscoveryObservation(fingerprint=f"container:shadow-{i}", name=f"shadow-{i}", image="python:3.12",
                                evidence={"first_seen_call": "2026-09-29T10:00:00Z"})


FEEDS = {
    "reference-list-feed": lambda: ListFeed("reference-list-feed", [_obs(1), _obs(2)]),
}


def _memory_app():
    o = MemoryOrchestrator()
    ports = Ports(gateway=MemoryGateway(), orchestrator=o, network=MemoryNetwork(o), identity=MemoryIdentity(),
                  secrets=MemorySecretStore(), audit=MemoryAudit(), repo=MemoryRepository(),
                  revokers=[MemoryRevoker()])
    return build_app({"policy": {}}, ports)


def assert_feed_contract(feed: DiscoveryFeed):
    assert isinstance(feed, DiscoveryFeed) and isinstance(feed.name, str) and feed.name
    first = list(feed.observations())
    assert first, "a primed feed must yield observations"
    for o in first:
        assert isinstance(o, DiscoveryObservation) and o.fingerprint and o.evidence
    assert not {o.fingerprint for o in feed.observations()} & {o.fingerprint for o in first}, \
        "observations() must only return what is new since the last call"
    app = _memory_app()
    for o in first:
        app.discovery.submit(feed.name, o)
    props = app.ports.repo.list(PROPOSALS)
    assert len(props) == len(first)
    assert all(p["status"] == "pending" and p["budget_usd"] == 0 and p["gateway_key"] is None for p in props)
    assert app.ports.gateway.keys == {}, "discovery must never create gateway keys"


@pytest.mark.parametrize("name", sorted(FEEDS))
def test_feed_contract(name):
    assert_feed_contract(FEEDS[name]())
