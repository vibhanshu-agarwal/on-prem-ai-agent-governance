"""Feed logic over fake ports (no Docker, no network)."""
from __future__ import annotations

import fakes
from fakes import GOVERNED, container
from govdisc.adapters.docker_source import DockerLogAccessSource, parse_ts
from govdisc.evidence import Hints
from govdisc.feeds.docker_events import DockerEventsFeed, DockerFeedConfig
from govdisc.feeds.gateway_logs import GatewayFeedConfig, GatewayLogsFeed
from govdisc.feeds.openlit_controller import ControllerFeedConfig, OpenlitControllerFeed

CFG = DockerFeedConfig(GOVERNED, ["^gov-", "^t2-"], ["govpilot.test"], Hints())


# ------------------------------------------------------------------ docker events
def test_baseline_proposes_unregistered_container_on_governed_network_with_evidence():
    c = container("shadow-bot", labels={"owner": "mallory", "team": "finance", "com.docker.compose.project": "x"})
    feed = DockerEventsFeed(fakes.FakeContainers([c]), CFG, clock=lambda: 1_790_000_000.0)
    [o] = list(feed.observations())
    assert o.fingerprint == "container:shadow-bot:python:3.12-slim" and o.kind == "workload"
    assert o.suggested_owner == "mallory" and o.suggested_team == "finance"
    ev = o.evidence
    assert ev["image"] == "python:3.12-slim" and ev["first_seen"].endswith("Z") and ev["labels"]["owner"] == "mallory"
    assert ev["probable_owner"] == {"value": "mallory", "from": "label:owner"}
    assert ev["on_governed_network"] == ["govpilot_agents"] and ev["container_name"] == "shadow-bot"


def test_only_new_since_last_call_and_events_pick_up_new_containers():
    src = fakes.FakeContainers([container("old-one")])
    feed = DockerEventsFeed(src, CFG)
    assert [o.name for o in feed.observations()] == ["old-one"]
    assert list(feed.observations()) == []                         # contract: only what is new
    src.start(container("new-one", cid="n" * 64))
    assert [o.name for o in feed.observations()] == ["new-one"]
    assert list(feed.observations()) == []


def test_short_lived_container_seen_through_events_only_if_still_inspectable():
    src = fakes.FakeContainers()
    feed = DockerEventsFeed(src, CFG)
    list(feed.observations())
    src.start(container("blink"), keep=False)                      # gone before inspect: nothing to report
    assert list(feed.observations()) == []


def test_platform_and_test_containers_and_ungoverned_ones_are_ignored():
    src = fakes.FakeContainers([
        container("gov-gateway"), container("t2-gateway"),
        container("t3-agent", labels={"govpilot.test": "t3"}),
        container("db", nets={"bridge": "172.17.0.2"}),
        container("opted-in", nets={"bridge": "172.17.0.3"}, labels={"govpilot.discover": "true"}),
    ])
    assert [o.name for o in DockerEventsFeed(src, CFG).observations()] == ["opted-in"]


def test_platform_compose_projects_are_ignored_even_when_renamed_during_a_recreate():
    cfg = DockerFeedConfig(GOVERNED, ["^gov-"], [], Hints(), {"com.docker.compose.project": ["govpilot"]})
    src = fakes.FakeContainers([container("7144d42c726d_gov-gateway", labels={"com.docker.compose.project": "govpilot"}),
                                container("someone-elses", labels={"com.docker.compose.project": "other"})])
    assert [o.name for o in DockerEventsFeed(src, cfg).observations()] == ["someone-elses"]


def test_same_name_and_image_is_one_fingerprint_across_restarts():
    src = fakes.FakeContainers([container("svc", cid="a" * 64)])
    feed = DockerEventsFeed(src, CFG)
    assert len(list(feed.observations())) == 1
    src.running.clear()
    src.start(container("svc", cid="b" * 64))                      # recreated: new id, same identity
    assert list(feed.observations()) == []


def test_docker_failure_is_not_fatal():
    class Boom(fakes.FakeContainers):
        def list_running(self):
            raise RuntimeError("daemon down")
    assert list(DockerEventsFeed(Boom(), CFG).observations()) == []


# ------------------------------------------------------------------ gateway logs
def _gw(access=None, calls=None, containers=None, **kw):
    clock = kw.pop("clock", lambda: 2000.0)
    return GatewayLogsFeed(GatewayFeedConfig(GOVERNED, **kw), containers or fakes.FakeContainers(),
                           access, calls, clock=clock, lookback_s=1500)


def test_refused_call_from_known_container_becomes_traffic_proposal_with_zero_spend_evidence():
    rogue = container("rogue", labels={"owner": "mallory"})
    feed = _gw(access=fakes.FakeAccess([fakes.refused(), fakes.refused(ts=1500.0, status=403)]),
               containers=fakes.FakeContainers([rogue]))
    [o] = list(feed.observations())
    assert o.kind == "traffic" and o.fingerprint == "container:rogue:python:3.12-slim"   # folds with docker feed
    r = o.evidence["refused"]
    assert r["count"] == 2 and r["statuses"] == [401, 403] and r["spent_usd"] == 0.0
    assert o.evidence["probable_owner"]["value"] == "mallory"


def test_refused_call_from_unresolvable_caller_is_still_reported_by_ip():
    feed = _gw(access=fakes.FakeAccess([fakes.refused(ip="172.22.0.77")]))
    [o] = list(feed.observations())
    assert o.fingerprint == "caller:172.22.0.77" and "not resolvable" in o.evidence["note"]


def test_refused_call_from_an_ip_outside_the_governed_ranges_is_ignored():
    feed = _gw(access=fakes.FakeAccess([fakes.refused(ip="172.20.0.1")]))     # e.g. the host, via the published port
    assert list(feed.observations()) == []


def test_refused_calls_from_platform_and_throwaway_test_containers_are_not_shadow_ai():
    """T9: probes from `gov-*` containers and from containers carrying an ignore label must not spend the feed's
    daily proposal budget (the hardening checks probe the edge from throwaway containers)."""
    from govdisc.feeds.gateway_logs import GatewayFeedConfig, GatewayLogsFeed
    plat = container("gov-authproxy", nets={"govpilot_agents": "172.22.0.5"})
    probe = container("probe-1", labels={"govpilot.t8test": "1"}, nets={"govpilot_agents": "172.22.0.6"})
    rogue = container("rogue", labels={"owner": "mallory"}, nets={"govpilot_agents": "172.22.0.7"})
    cfg = GatewayFeedConfig(GOVERNED, 1, Hints(), [], 120.0, ["^gov-"], ["govpilot.t8test"])
    feed = GatewayLogsFeed(cfg, fakes.FakeContainers([plat, probe, rogue]),
                           fakes.FakeAccess([fakes.refused(ip="172.22.0.5"), fakes.refused(ip="172.22.0.6"),
                                             fakes.refused(ip="172.22.0.7")]), clock=lambda: 2000.0, lookback_s=1500)
    assert [o.name for o in feed.observations()] == ["rogue"]


def test_refused_call_from_outside_governed_networks_is_not_ours():
    outsider = container("elsewhere", nets={"bridge": "172.17.0.5"})
    feed = _gw(access=fakes.FakeAccess([fakes.refused(ip="172.17.0.5")]), containers=fakes.FakeContainers([outsider]))
    assert list(feed.observations()) == []


def test_unregistered_key_is_proposed_and_registered_agents_are_folded_via_label():
    feed = _gw(calls=fakes.FakeCalls([fakes.summary(), fakes.summary("bbbb" * 8, "hr-agent", "hr-agent", "hr")]))
    obs = list(feed.observations())
    assert {o.name for o in obs} == {"shadow-key", "hr-agent"}
    shadow = next(o for o in obs if o.name == "shadow-key")
    assert shadow.labels == {"govpilot.agent_id": "shadow-agent"} and shadow.suggested_team == "finance"
    assert shadow.evidence["calls"] == 3 and shadow.evidence["key_hash_prefix"] == "abcdef012345"
    assert "abcdef0123456789abcdef" not in str(shadow.evidence)          # only a hash prefix, never a key
    # the control plane folds the registered one; the feed itself never needs the register
    sink = fakes.RecordingSink(known_agent_ids={"hr-agent"})
    for o in obs:
        sink.submit("gateway-logs", o)
    assert [o.name for o in sink.created] == ["shadow-key"]


def test_gateway_feed_reports_each_thing_once():
    feed = _gw(access=fakes.FakeAccess([fakes.refused()]), calls=fakes.FakeCalls([fakes.summary()]))
    assert len(list(feed.observations())) == 2
    assert list(feed.observations()) == []


def test_min_refused_calls_threshold():
    feed = _gw(access=fakes.FakeAccess([fakes.refused()]), min_refused_calls=2)
    assert list(feed.observations()) == []


def test_source_failure_does_not_break_the_other_source():
    class Boom(fakes.FakeAccess):
        def refused_calls(self, since):
            raise RuntimeError("no logs")
    feed = _gw(access=Boom(), calls=fakes.FakeCalls([fakes.summary()]))
    assert [o.kind for o in feed.observations()] == ["traffic"]


def test_access_log_line_parsing_and_filtering():
    import docker as _d

    class FakeC:
        def logs(self, **kw):
            return (b'2026-09-29T10:51:02.123456789Z INFO:     172.22.0.3:56172 - "POST /v1/chat/completions HTTP/1.1" 401 Unauthorized\n'
                    b'2026-09-29T10:51:03.000000000Z INFO:     172.22.0.3:56173 - "POST /v1/chat/completions HTTP/1.1" 200 OK\n'
                    b'2026-09-29T10:51:04.000000000Z INFO:     127.0.0.1:1 - "GET /health/liveliness HTTP/1.1" 401 Unauthorized\n'
                    b'2026-09-29T10:51:05.000000000Z INFO:     172.22.0.4:5 - "POST /chat/completions?x=1 HTTP/1.1" 403 Forbidden\n'
                    b'garbage line\n')

    class FakeClient:
        class containers:
            @staticmethod
            def get(name):
                if name == "missing":
                    raise _d.errors.NotFound("x")
                return FakeC()

    src = DockerLogAccessSource(FakeClient(), ["gov-gateway", "missing"])
    got = src.refused_calls(parse_ts("2026-09-29T10:51:00Z"))
    assert [(r.src_ip, r.status, r.path) for r in got] == [("172.22.0.3", 401, "/v1/chat/completions"),
                                                           ("172.22.0.4", 403, "/chat/completions")]


# ------------------------------------------------------------------ openlit controller
SVC = {"service_name": "sneaky", "workload_key": "docker:sneaky", "language_runtime": "python",
       "llm_providers": ["openai"], "pid": 4242, "exe_path": "/usr/local/bin/python3.12",
       "first_seen": "2026-09-29T10:52:23Z", "last_seen": "2026-09-29T10:52:24Z"}


def test_ebpf_service_becomes_bypass_proposal_enriched_from_the_container():
    c = container("sneaky", nets={"bridge": "172.17.0.6"}, labels={"owner": "erin", "govpilot.team": "hr"})
    feed = OpenlitControllerFeed(fakes.FakeServices([SVC]), fakes.FakeContainers([c]),
                                 ControllerFeedConfig(GOVERNED, ["^gov-"]))
    [o] = list(feed.observations())
    assert o.fingerprint == "container:sneaky:python:3.12-slim" and o.kind == "traffic"
    assert o.evidence["ebpf"]["llm_providers"] == ["openai"] and o.evidence["ebpf"]["bypasses_gateway"] is True
    assert o.suggested_owner == "erin" and o.image == "python:3.12-slim"
    assert list(feed.observations()) == []


def test_ebpf_service_without_a_matching_container_still_reported_and_platform_names_ignored():
    feed = OpenlitControllerFeed(fakes.FakeServices([SVC, {**SVC, "service_name": "gov-gateway", "workload_key": "docker:gov-gateway"}]),
                                 fakes.FakeContainers(), ControllerFeedConfig(GOVERNED, ["^gov-"]))
    [o] = list(feed.observations())
    assert o.fingerprint == "ebpf:docker:sneaky" and o.name == "sneaky"


def test_controller_down_is_not_fatal():
    class Boom(fakes.FakeServices):
        def services(self):
            raise RuntimeError("connection refused")
    assert list(OpenlitControllerFeed(Boom(), None, ControllerFeedConfig()).observations()) == []


def test_settle_window_skips_containers_that_do_not_last_and_proposes_those_that_do():
    t = [1000.0]
    cfg = DockerFeedConfig(GOVERNED, [], [], Hints(), settle_s=5)
    src = fakes.FakeContainers([container("blink", cid="b" * 64), container("stays", cid="s" * 64)])
    feed = DockerEventsFeed(src, cfg, clock=lambda: t[0])
    assert list(feed.observations()) == []                         # just appeared: settling
    del src.running["b" * 64]                                      # one of them was a one-second container
    t[0] += 6
    assert [o.name for o in feed.observations()] == ["stays"]
    assert list(feed.observations()) == []
