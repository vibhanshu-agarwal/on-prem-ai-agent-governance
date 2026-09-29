"""The ONLY place adapter classes are named. Feeds and the runner see ports; config picks adapters.

Adopting this in another environment = new adapter classes for the ports + edits to
deploy/discovery/config.yaml (`type:` values), not changes to feeds.
"""
from __future__ import annotations

import os
from typing import Any

import yaml

from .evidence import Hints
from .feeds.docker_events import DockerEventsFeed, DockerFeedConfig
from .feeds.gateway_logs import GatewayFeedConfig, GatewayLogsFeed
from .feeds.openlit_controller import ControllerFeedConfig, OpenlitControllerFeed
from .model import Observation
from .ports import ContainerSource, DiscoveryFeed, ProposalSink
from .ratelimit import DailyBudget
from .runner import FeedRunner, Runner, load_state


def load_config(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _sink(cfg: dict, feed_cfg: dict) -> ProposalSink:
    kind = (cfg.get("control_plane") or {}).get("type", "http")
    if kind == "http":
        from .adapters.controlplane_sink import ControlPlaneSink
        cp = cfg["control_plane"]
        return ControlPlaneSink(cp["url"], cp["token_url"], feed_cfg["client_id"], os.environ[feed_cfg["secret_env"]],
                                audience=cp.get("audience", "govpilot-control-plane"))
    raise ValueError(f"unknown control_plane type {kind!r}")


def _containers(cfg: dict) -> ContainerSource:
    kind = (cfg.get("containers") or {}).get("type", "docker")
    if kind == "docker":
        from .adapters.docker_source import DockerSdkSource
        return DockerSdkSource()
    raise ValueError(f"unknown containers type {kind!r}")


def build_feed(name: str, fc: dict, cfg: dict, containers: ContainerSource, seen: set[str]) -> DiscoveryFeed:
    hints = Hints(**{k: v for k, v in (cfg.get("hints") or {}).items()})
    governed = cfg.get("governed_networks", [])
    plat = cfg.get("platform") or {}
    t = fc["type"]
    if t == "docker_events":
        return DockerEventsFeed(containers, DockerFeedConfig(governed, plat.get("ignore_names", []),
                                                              plat.get("ignore_labels", []), hints,
                                                              plat.get("ignore_label_values", {}),
                                                              float(fc.get("settle_s", 0))),
                                name=name, seen=seen)
    if t == "gateway_logs":
        access = calls = None
        if fc.get("access_log"):
            al = fc["access_log"]
            if al["type"] == "docker_logs":
                from .adapters.docker_source import DockerLogAccessSource
                access = DockerLogAccessSource(None, al["containers"])
            else:
                raise ValueError(f"unknown access_log type {al['type']!r}")
        if fc.get("call_records"):
            cr = fc["call_records"]
            if cr["type"] == "clickhouse":
                from .adapters.clickhouse_calls import ClickHouseCallSource
                calls = ClickHouseCallSource(cr["url"], os.environ.get(cr.get("user_env", ""), cr.get("user", "openlit")),
                                             os.environ[cr["password_env"]])
            else:
                raise ValueError(f"unknown call_records type {cr['type']!r}")
        return GatewayLogsFeed(GatewayFeedConfig(governed, fc.get("min_refused_calls", 1), hints,
                                                 fc.get("ignore_agent_id_prefixes", []),
                                                 float(fc.get("telemetry_slack_s", 120))),
                               containers, access, calls, name=name, seen=seen)
    if t == "openlit_controller":
        from .adapters.controller_http import ControllerHttpSource
        return OpenlitControllerFeed(ControllerHttpSource(fc["controller_url"]), containers,
                                     ControllerFeedConfig(governed, plat.get("ignore_names", []), hints),
                                     name=name, seen=seen)
    raise ValueError(f"unknown feed type {t!r}")


def build_runner(cfg: dict) -> Runner:
    containers = _containers(cfg)
    state = load_state(cfg.get("state_path"))
    runners = []
    for name, fc in (cfg.get("feeds") or {}).items():
        if not fc.get("enabled", True):
            continue
        st = state.get(name, {})
        seen = set(st.get("seen", []))
        feed = build_feed(name, fc, cfg, containers, seen)
        budget = DailyBudget.from_state(int(fc.get("daily_limit", 20)), st.get("budget"))
        r = FeedRunner(feed, _sink(cfg, fc), budget, int(cfg.get("backlog_max", 200)))
        for p in st.get("backlog", []):
            r.backlog.append(Observation(**p))
        runners.append(r)
    return Runner(runners, float(cfg.get("poll_interval_s", 5)), cfg.get("state_path"), cfg.get("heartbeat_path"))
