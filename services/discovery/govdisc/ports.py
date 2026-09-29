"""Ports. Feeds depend on these interfaces only; each has one adapter today (see wiring.py).

Swapping environment: Kubernetes -> a ContainerSource over the pod API; another log platform -> an
AccessLogSource / CallRecordSource for it; a SIEM-side queue -> another ProposalSink.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from .model import CallSummary, ContainerInfo, Observation, RefusedCall, SubmitResult


class DiscoveryFeed(ABC):
    """Pull model, same contract as the control plane's DiscoveryFeed port:
    `observations()` returns only what is new since the previous call."""
    name: str

    @abstractmethod
    def observations(self) -> Iterable[Observation]: ...


class ProposalSink(ABC):
    """Where proposals go (the control plane's pending queue)."""

    @abstractmethod
    def submit(self, feed: str, obs: Observation) -> SubmitResult: ...


class ContainerSource(ABC):
    """The workload runtime (Docker today; a Kubernetes pod lister later)."""

    @abstractmethod
    def list_running(self) -> list[ContainerInfo]: ...

    @abstractmethod
    def events(self, since: float, until: float) -> list[tuple[str, str]]:
        """(action, container_id) pairs for container lifecycle events in the window."""

    @abstractmethod
    def inspect(self, container_id: str) -> ContainerInfo | None: ...

    @abstractmethod
    def find_by_ip(self, ip: str) -> ContainerInfo | None: ...

    @abstractmethod
    def find_by_name(self, name: str) -> ContainerInfo | None: ...

    @abstractmethod
    def network_cidrs(self, networks: list[str]) -> list[str]:
        """IP ranges of the named networks (to decide whether an unresolvable caller IP is one of ours)."""


class AccessLogSource(ABC):
    """Refused calls seen by the gateway (access log)."""

    @abstractmethod
    def refused_calls(self, since: float) -> list[RefusedCall]: ...


class CallRecordSource(ABC):
    """Per-key call summaries from the gateway's telemetry (OpenLIT / ClickHouse)."""

    @abstractmethod
    def calls_since(self, since: float) -> list[CallSummary]: ...


class ServiceListSource(ABC):
    """Workloads an eBPF agent saw talking to LLM endpoints (OpenLIT Controller)."""

    @abstractmethod
    def services(self) -> list[dict[str, Any]]: ...
