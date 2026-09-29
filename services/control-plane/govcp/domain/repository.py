"""Persistence port for control-plane state (agents, proposals, previews, actions...).

A tiny document store keeps the adapter surface small: Postgres today, anything
with atomic read-modify-write tomorrow. The audit log is NOT stored here; it has
its own append-only port (AuditSink).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

AGENTS = "agents"
PROPOSALS = "proposals"
PREVIEWS = "previews"
ACTIONS = "quarantine_actions"
RULES = "quarantine_rules"
DELEGATIONS = "delegations"
STOP_REPORTS = "stop_reports"
KV = "kv"


class Repository(ABC):
    @abstractmethod
    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        """Insert or replace."""

    @abstractmethod
    def insert(self, collection: str, doc_id: str, data: dict[str, Any]) -> bool:
        """Insert only if absent. Returns False if the id already exists."""

    @abstractmethod
    def list(self, collection: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def update(self, collection: str, doc_id: str,
               fn: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
        """Atomic read-modify-write (row locked for the duration of fn). Raises KeyError if absent."""

    @abstractmethod
    def delete(self, collection: str, doc_id: str) -> None: ...
