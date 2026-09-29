"""Every discovery feed must satisfy the control plane's DiscoveryFeed contract
(tests/control/contracts/test_discovery_feed_contract.py::assert_feed_contract).

The discovery service does not import the control plane; this adapter shim turns a feed's observations
into the control plane's own types so the SAME contract function judges them: observations() yields only
what is new, every observation carries evidence, and filing them leaves pending proposals with zero budget
and no gateway key.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

import fakes
from govdisc.feeds.docker_events import DockerEventsFeed, DockerFeedConfig
from govdisc.feeds.gateway_logs import GatewayFeedConfig, GatewayLogsFeed
from govdisc.feeds.openlit_controller import ControllerFeedConfig, OpenlitControllerFeed

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control" / "contracts"))
from govcp.domain.models import DiscoveryObservation  # noqa: E402
from govcp.domain.ports import DiscoveryFeed as CpFeed  # noqa: E402
from test_discovery_feed_contract import assert_feed_contract  # noqa: E402


class AsCpFeed(CpFeed):
    def __init__(self, feed):
        self.feed = feed
        self.name = feed.name

    def observations(self):
        return [DiscoveryObservation(**o.to_payload()) for o in self.feed.observations()]


def _docker():
    c = fakes.container("shadow-a", labels={"owner": "x"})
    return DockerEventsFeed(fakes.FakeContainers([c, fakes.container("shadow-b")]),
                            DockerFeedConfig(fakes.GOVERNED, [], [], ))


def _gateway():
    return GatewayLogsFeed(GatewayFeedConfig(fakes.GOVERNED), fakes.FakeContainers([fakes.container("r")]),
                           fakes.FakeAccess([fakes.refused()]), fakes.FakeCalls([fakes.summary()]),
                           clock=lambda: 2000.0, lookback_s=1500)


def _controller():
    svc = {"service_name": "sneaky", "workload_key": "docker:sneaky", "llm_providers": ["openai"]}
    return OpenlitControllerFeed(fakes.FakeServices([svc, {**svc, "service_name": "sneaky2", "workload_key": "docker:sneaky2"}]),
                                 None, ControllerFeedConfig())


FEEDS = {"docker-events": _docker, "gateway-logs": _gateway, "openlit-controller": _controller}


@pytest.mark.parametrize("name", sorted(FEEDS))
def test_feed_contract(name):
    assert_feed_contract(AsCpFeed(FEEDS[name]()))
