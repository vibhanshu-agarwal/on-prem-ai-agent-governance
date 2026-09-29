"""A container that copies a registered agent's `govpilot.agent_id` label must not be silently folded.

When the register binds the agent to an image (agent label `workload_image`), only a workload running that
image (tag or content id) is "known"; anything else is filed as a high-priority suspected spoof, with zero
budget and no gateway key, and an alert-severity audit record. Runs against the control plane's domain with
its in-memory adapters; the observation is built by the real docker-events feed code.
"""
from __future__ import annotations

import pytest

from govcp.adapters.memory import (MemoryAudit, MemoryGateway, MemoryIdentity, MemoryNetwork, MemoryOrchestrator,
                                   MemoryRepository, MemoryRevoker, MemorySecretStore)
from govcp.domain.context import Ports
from govcp.domain.models import DiscoveryObservation, Principal
from govcp.wiring import build_app
from govdisc.feeds.docker_events import DockerFeedConfig, to_observation
from govdisc.model import ContainerInfo

OPS = Principal("alice", ["admin", "operator", "approver"], kind="user")


@pytest.fixture
def app():
    o = MemoryOrchestrator()
    ports = Ports(gateway=MemoryGateway(), orchestrator=o, network=MemoryNetwork(o, governed=["agents"]),
                  identity=MemoryIdentity(), secrets=MemorySecretStore(), audit=MemoryAudit(),
                  repo=MemoryRepository(), revokers=[MemoryRevoker()])
    a = build_app({"policy": {"discovery": {"feeds": {"docker-events": {"daily_limit": 5}}}}}, ports)
    a.register.register({"agent_id": "hr-agent", "team": "hr", "max_budget_usd": 1, "models": ["m1"],
                         "labels": {"workload_image": "govpilot/hr-agent:1"}}, OPS)
    a.register.register({"agent_id": "legacy-agent", "team": "hr", "max_budget_usd": 1, "models": ["m1"]}, OPS)
    return a


def _obs(name, image, agent_id, image_id=""):
    c = ContainerInfo(id="c" * 64, name=name, image=image, labels={"govpilot.agent_id": agent_id},
                      networks={"govpilot_agents": "172.30.0.9"}, image_id=image_id)
    o = to_observation(c, DockerFeedConfig(["govpilot_agents"]), "docker-events", 0.0)
    return DiscoveryObservation.from_dict(o.to_payload())


def test_bound_agent_running_its_image_is_known(app):
    r = app.discovery.submit("docker-events", _obs("hr-1", "govpilot/hr-agent:1", "hr-agent"))
    assert r["status"] == "known" and r["binding"] == "image"
    r = app.discovery.submit("docker-events", _obs("hr-2", "other:latest", "hr-agent",
                                                   image_id="govpilot/hr-agent:1"))
    assert r["status"] == "known"                     # binding may name the content id instead of the tag
    assert app.discovery.list() == []


def test_copied_label_on_another_image_is_a_high_priority_spoof_with_zero_budget(app):
    keys_before = dict(app.ports.gateway.keys)
    r = app.discovery.submit("docker-events", _obs("rogue", "evil/miner:1", "hr-agent"))
    assert r["status"] == "pending" and r["priority"] == "high"
    assert r["flags"] == ["label_spoof_suspected"]
    assert r["spoof"] == {"claimed_agent_id": "hr-agent", "expected_image": "govpilot/hr-agent:1",
                          "seen_image": "evil/miner:1"}
    assert r["budget_usd"] == 0 and r["gateway_key"] is None
    assert app.ports.gateway.keys == keys_before
    alerts = [x for x in app.ports.audit.records if x.action == "discovery.label_spoof_suspected"]
    assert alerts and alerts[0].severity == "alert"


def test_spoof_proposals_still_count_against_the_feed_cap(app):
    from govcp.domain.errors import RateLimited
    for i in range(5):
        app.discovery.submit("docker-events", _obs(f"rogue{i}", f"evil/{i}:1", "hr-agent"))
    with pytest.raises(RateLimited):
        app.discovery.submit("docker-events", _obs("rogue9", "evil/9:1", "hr-agent"))


def test_unbound_agent_keeps_legacy_behaviour(app):
    r = app.discovery.submit("docker-events", _obs("x", "anything:1", "legacy-agent"))
    assert r["status"] == "known" and r["binding"] == "unbound"


# ---- T8: gateway-key observations (gateway-logs feed, OTel spans) are not workloads -------------------------
def _key_obs(key_hash, agent_id):
    return DiscoveryObservation.from_dict({
        "fingerprint": f"key:{key_hash[:16]}", "kind": "traffic", "name": "k", "image": None,
        "labels": {"govpilot.agent_id": agent_id} if agent_id else {},
        "evidence": {"source": "gateway-otel", "key_hash_prefix": key_hash[:12], "calls": 1}})


def test_registered_agent_key_is_known_not_a_spoof(app):
    """Regression (T8 integration): the image binding made every registered agent's own gateway key look
    like a label spoof, so the queue filled with the agents themselves."""
    for agent_id in ("hr-agent", "legacy-agent"):
        key_hash = app.register.find(agent_id).gateway_keys[0].key_hash
        r = app.discovery.submit("gateway-logs", _key_obs(key_hash, agent_id))
        assert r["status"] == "known" and r["binding"] == "key", r
    assert app.discovery.list() == []


def test_unregistered_key_claiming_an_agent_is_flagged(app):
    r = app.discovery.submit("gateway-logs", _key_obs("f" * 64, "hr-agent"))
    assert r["status"] == "pending" and r["flags"] == ["label_spoof_suspected"] and r["budget_usd"] == 0
    assert r["spoof"]["claimed_agent_id"] == "hr-agent"
