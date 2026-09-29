"""Agent-side event log: one JSON line per run / LLM attempt / tool / delegation.

The gateway is the source of truth for spend; these events are the agent's own account of
what it *intended* (run tree, attempts, tools). Comparing the two is how the attribution
completeness test proves nothing was spent outside a known run.

Two adapters carry the same events:
  StdoutSink    every event, on stdout (what `docker logs` and a log shipper see; lost when the container
                is re-created)
  JournalSink   the run-level events only (agent.start/stop, run.start/run.end), appended to a JSONL file
                on a volume that outlives the container. This is the durable record of a run's terminal
                state: a run that was refused or aborted before it made an LLM call of its own has no
                gateway row, so the journal is the only place its existence and outcome are written down
                (see scripts/attribution_report.py `journal_evidence` and acceptance test M-01).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from typing import Mapping, Protocol

PREFIX = "AGENT_EVENT "
JOURNAL_EVENTS = frozenset({"agent.start", "agent.stop", "run.start", "run.end"})


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


class JournalSink:
    """Adapter: durable run journal, one JSONL file per agent (`<dir>/<agent_id>.jsonl`).

    Only the run-level events are kept (a few hundred bytes per run, not per LLM attempt). Every record carries
    `boot`, an id of this process, so a later reader can tell "the process that started this run was replaced
    before the run ended" (killed by a stop / quarantine / crash) from "the run is still going". One rotated
    generation (`.1`) is kept when the file passes `max_bytes`. A journal that cannot be written never breaks
    the agent: the error is counted, reported once on stderr, and the loop carries on."""

    def __init__(self, directory: str, agent_id: str, *, max_bytes: int = 20_000_000,
                 only: frozenset[str] = JOURNAL_EVENTS) -> None:
        self.path = os.path.join(directory, f"{agent_id}.jsonl")
        self.max_bytes, self.only = max_bytes, only
        self.boot = uuid.uuid4().hex[:12]
        self.errors = 0
        self._lock = threading.Lock()
        self._fh = None
        self._size = 0

    def _open(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8")
        self._size = self._fh.tell()

    def emit(self, event: dict) -> None:
        if event.get("event") not in self.only:
            return
        line = json.dumps({"ts": round(time.time(), 3), "boot": self.boot, **event}, separators=(",", ":"), default=str)
        with self._lock:
            try:
                if self._fh is None:
                    self._open()
                if self._size + len(line) > self.max_bytes:
                    self._fh.close()
                    os.replace(self.path, self.path + ".1")
                    self._open()
                self._fh.write(line + "\n")
                self._fh.flush()
                self._size += len(line) + 1
            except OSError as e:
                self.errors += 1
                self._fh = None
                if self.errors == 1:
                    print(f"AGENT_JOURNAL_ERROR {e}", file=sys.stderr, flush=True)


class TeeSink:
    """Send every event to each sink; one failing sink never stops the others."""

    def __init__(self, *sinks: "EventSink") -> None:
        self.sinks = sinks

    def emit(self, event: dict) -> None:
        for s in self.sinks:
            try:
                s.emit(event)
            except Exception:  # noqa: BLE001 - an event sink must never take the agent down
                pass


def default_sink(env: Mapping[str, str], agent_id: str) -> EventSink:
    """stdout always; plus the durable journal when AGENT_JOURNAL_DIR is set (compose.agents.yml sets it)."""
    d = env.get("AGENT_JOURNAL_DIR")
    if not d:
        return StdoutSink()
    return TeeSink(StdoutSink(), JournalSink(d, agent_id, max_bytes=int(env.get("AGENT_JOURNAL_MAX_BYTES", 20_000_000))))


def error_fields(exc: BaseException) -> dict:
    """The terminal-state fields of a failed run: a short error text and, for a gateway refusal (duck-typed so this
    module does not import the client), what the gateway said and which request it was."""
    out: dict = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    status = getattr(exc, "status", None)
    etype = getattr(exc, "etype", None)
    if status is not None or etype is not None:
        out["gateway_error"] = {"http_status": status, "etype": etype, "request_run_id": getattr(exc, "run_id", None),
                                "attempts": getattr(exc, "attempts", None)}
    return out


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
