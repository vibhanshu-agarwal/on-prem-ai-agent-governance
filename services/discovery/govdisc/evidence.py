"""Turn a ContainerInfo into pre-screening evidence: image, labels, first-seen, probable owner.

Owner and team are *hints* taken from labels the deployer chose to set; they are never trusted for
anything but routing the proposal to a reviewer. A human owner still has to approve.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .model import ContainerInfo

# Labels that are noise for a reviewer (compose bookkeeping, build metadata) are still kept in full
# under evidence["labels"]; this list only controls what is *promoted* to the top-level labels field.
DEFAULT_OWNER_KEYS = ["govpilot.owner", "owner", "org.opencontainers.image.authors", "maintainer"]
DEFAULT_TEAM_KEYS = ["govpilot.team", "team"]


@dataclass
class Hints:
    owner_label_keys: list[str] = field(default_factory=lambda: list(DEFAULT_OWNER_KEYS))
    team_label_keys: list[str] = field(default_factory=lambda: list(DEFAULT_TEAM_KEYS))


def first_label(labels: dict[str, str], keys: list[str]) -> tuple[str | None, str | None]:
    for k in keys:
        v = (labels.get(k) or "").strip()
        if v:
            return v, k
    return None, None


def iso_now(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else \
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def matches_any(value: str, patterns: list[str]) -> bool:
    return any(re.search(p, value) for p in patterns)


def container_evidence(c: ContainerInfo, hints: Hints, source: str, governed: list[str], now: float) -> dict:
    owner, owner_key = first_label(c.labels, hints.owner_label_keys)
    team, team_key = first_label(c.labels, hints.team_label_keys)
    compose = {k.split(".")[-1]: v for k, v in c.labels.items()
               if k in ("com.docker.compose.project", "com.docker.compose.service")}
    return {
        "source": source,
        "container_id": c.id[:12],
        "container_name": c.name,
        "image": c.image,
        "image_id": c.image_id,                   # lets the control plane check a register image binding
        "labels": dict(sorted(c.labels.items())),
        "networks": dict(sorted(c.networks.items())),
        "on_governed_network": sorted(set(c.networks) & set(governed)),
        "created": c.created,
        "started": c.started,
        "first_seen": iso_now(now),               # first time THIS feed saw it
        "compose": compose,
        "probable_owner": {"value": owner, "from": f"label:{owner_key}"} if owner else None,
        "probable_team": {"value": team, "from": f"label:{team_key}"} if team else None,
    }
