"""Agent-side event log: one JSON line per run / LLM attempt / tool / delegation.

The gateway is the source of truth for spend; these events are the agent's own account of
what it *intended* (run tree, attempts, tools). Comparing the two is how the attribution
completeness test proves nothing was spent outside a known run.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from typing import Protocol

PREFIX = "AGENT_EVENT "


class EventSink(Protocol):
    def emit(self, event: dict) -> None: ...


class StdoutSink:
    """Adapter: JSON lines on stdout (what `docker logs` and any log shipper see)."""

    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self._lock = threading.Lock()

    def emit(self, event: dict) -> None:
        line = PREFIX + json.dumps({"ts": round(time.time(), 3), **event}, separators=(",", ":"), default=str)
        with self._lock:
            print(line, file=self.stream, flush=True)


class MemorySink:
    """Adapter for tests."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self._lock = threading.Lock()

    def emit(self, event: dict) -> None:
        with self._lock:
            self.events.append({"ts": time.time(), **event})

    def of(self, name: str) -> list[dict]:
        return [e for e in self.events if e.get("event") == name]


def parse_log(text: str) -> list[dict]:
    """Events out of a `docker logs` dump."""
    out = []
    for line in text.splitlines():
        i = line.find(PREFIX)
        if i >= 0:
            try:
                out.append(json.loads(line[i + len(PREFIX):]))
            except ValueError:
                pass
    return out
