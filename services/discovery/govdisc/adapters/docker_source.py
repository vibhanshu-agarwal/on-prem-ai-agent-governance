"""ContainerSource over the Docker Engine API (docker SDK) and AccessLogSource over `docker logs`.

Read-only use of the API: list/inspect/events/logs. The Docker socket is still root-equivalent when
mounted (see docs/results/T6.md); a Kubernetes adapter would use a namespaced read-only service account.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import docker

from ..model import ContainerInfo, RefusedCall
from ..ports import AccessLogSource, ContainerSource


def info_from_attrs(a: dict) -> ContainerInfo:
    cfg = a.get("Config") or {}
    nets = (a.get("NetworkSettings") or {}).get("Networks") or {}
    st = a.get("State") or {}
    return ContainerInfo(
        id=a.get("Id", ""), name=(a.get("Name") or "").lstrip("/"), image=cfg.get("Image") or "",
        labels=dict(cfg.get("Labels") or {}),
        networks={n: (v or {}).get("IPAddress", "") for n, v in nets.items()},
        created=a.get("Created", ""), started=st.get("StartedAt", ""), status=st.get("Status", ""),
        image_id=a.get("Image", ""))


class DockerSdkSource(ContainerSource):
    def __init__(self, client: docker.DockerClient | None = None):
        self.c = client or docker.from_env()

    def list_running(self) -> list[ContainerInfo]:
        return [info_from_attrs(x.attrs) for x in self.c.containers.list(ignore_removed=True)]

    def events(self, since: float, until: float) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for ev in self.c.events(since=since, until=until, decode=True,
                                filters={"type": ["container", "network"], "event": ["create", "start", "connect"]}):
            act = ev.get("Action") or ev.get("status") or ""
            attrs = (ev.get("Actor") or {}).get("Attributes") or {}
            cid = attrs.get("container") if ev.get("Type") == "network" else (ev.get("id") or ev.get("Actor", {}).get("ID"))
            if cid:
                out.append((act, cid))
        return out

    def inspect(self, container_id: str) -> ContainerInfo | None:
        try:
            return info_from_attrs(self.c.containers.get(container_id).attrs)
        except docker.errors.NotFound:
            return None                                       # short-lived container already gone

    def find_by_ip(self, ip: str) -> ContainerInfo | None:
        for c in self.list_running():
            if ip in c.networks.values():
                return c
        return None

    def find_by_name(self, name: str) -> ContainerInfo | None:
        try:
            return info_from_attrs(self.c.containers.get(name).attrs)
        except docker.errors.NotFound:
            return None

    def network_cidrs(self, networks: list[str]) -> list[str]:
        out = []
        for n in networks:
            try:
                for cfg in (self.c.networks.get(n).attrs.get("IPAM") or {}).get("Config") or []:
                    if cfg.get("Subnet"):
                        out.append(cfg["Subnet"])
            except docker.errors.NotFound:
                continue
        return out


# LiteLLM/uvicorn access log:  2026-09-29T10:51:02.123456789Z INFO:     172.22.0.3:56172 - "POST /v1/chat/completions HTTP/1.1" 401 Unauthorized
_LINE = re.compile(r'^(?P<ts>\S+)\s+INFO:\s+(?P<ip>\d+\.\d+\.\d+\.\d+):\d+ - "(?P<method>[A-Z]+) (?P<path>\S+) '
                   r'HTTP/[\d.]+" (?P<status>\d{3})')


def parse_ts(s: str) -> float:
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()


class DockerLogAccessSource(AccessLogSource):
    """Refused (401/403) AI-route calls in the gateway container's access log."""

    def __init__(self, client: docker.DockerClient | None, containers: list[str],
                 ai_paths: str = r"^/(v1/)?(chat/completions|completions|embeddings|responses|messages|images|audio)",
                 statuses: tuple[int, ...] = (401, 403)):
        self.c = client or docker.from_env()
        self.containers = containers
        self.ai_paths = re.compile(ai_paths)
        self.statuses = statuses

    def refused_calls(self, since: float) -> list[RefusedCall]:
        out: list[RefusedCall] = []
        for name in self.containers:
            try:
                raw = self.c.containers.get(name).logs(since=int(since), timestamps=True, stdout=True, stderr=True)
            except docker.errors.APIError:            # not found, or dead / being removed (409)
                continue
            for line in raw.decode("utf-8", "replace").splitlines():
                m = _LINE.match(line)
                if not m or int(m["status"]) not in self.statuses or not self.ai_paths.match(m["path"]):
                    continue
                ts = parse_ts(m["ts"])
                if ts >= since:
                    out.append(RefusedCall(ts, m["ip"], m["method"], m["path"].split("?")[0], int(m["status"])))
        return out
