"""Run identity: the thing the gateway attributes spend to.

A *run* is one unit of work by one agent. Runs form a tree:

  task run (root)                        one loop iteration / one user request
    |-- tool run (kind=tool)             a tool call, child of the run that called it
    |-- delegation run (kind=delegation) sub-task handed to a child agent; the child agent
                                         works under this run id, under its own credential
  a run may make several LLM calls: each logical call gets the next `step` (1, 2, ...);
  retries are NOT new runs and NOT new steps: the same run id and step are sent again with attempt = 2, 3, ...
  so (run_id, step, attempt) names one gateway request

Every field travels two ways so it survives whichever hop drops one of them:
  * HTTP headers x-govpilot-*  (read by deploy/litellm/callbacks/run_attribution.py)
  * `x-litellm-spend-logs-metadata` (LiteLLM's own spend-log metadata header; works even if the
    attribution callback is not loaded)
plus a W3C `traceparent` derived from the run tree so a tracing backend can join the same tree.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
import itertools
from dataclasses import dataclass, field, replace
from typing import Iterator

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{5,79}$")   # keep identical to the gateway callback
KINDS = ("task", "tool", "delegation")


def new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


@dataclass(frozen=True)
class RunContext:
    agent_id: str
    run_id: str
    root_run_id: str
    parent_run_id: str | None = None
    kind: str = "task"
    name: str = ""
    tool: str | None = None
    user: str | None = None
    attempt: int = 1
    step: int = 0            # which logical LLM call of this run (0 = not yet assigned)
    # shared by every copy of this run (retries, user changes) so steps stay unique within the run
    _steps: Iterator[int] = field(default_factory=lambda: itertools.count(1), compare=False, repr=False)

    def __post_init__(self) -> None:
        if not RUN_ID_RE.match(self.run_id):
            raise ValueError(f"bad run id {self.run_id!r}")
        if self.parent_run_id is not None and self.parent_run_id == self.run_id:
            raise ValueError("a run cannot be its own parent")
        if self.kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")

    @classmethod
    def root(cls, agent_id: str, name: str = "", user: str | None = None) -> "RunContext":
        rid = new_run_id()
        return cls(agent_id=agent_id, run_id=rid, root_run_id=rid, name=name, user=user)

    def child(self, kind: str, name: str, *, tool: str | None = None, agent_id: str | None = None) -> "RunContext":
        """A new run caused by this one (tool call, delegation). Never reuse a parent's run id."""
        return RunContext(agent_id=agent_id or self.agent_id, run_id=new_run_id(), root_run_id=self.root_run_id,
                          parent_run_id=self.run_id, kind=kind, name=name, tool=tool, user=self.user)

    def next_step(self) -> "RunContext":
        """The context for the next logical LLM call of this run (a retry of it keeps the step)."""
        return replace(self, step=next(self._steps), attempt=1)

    def with_attempt(self, attempt: int) -> "RunContext":
        """Same run, next attempt: a retry keeps run_id/parent_run_id."""
        return replace(self, attempt=attempt)

    # ---- propagation ---------------------------------------------------------
    def traceparent(self) -> str:
        trace = hashlib.md5(self.root_run_id.encode()).hexdigest()
        span = hashlib.md5(self.run_id.encode()).hexdigest()[:16]
        return f"00-{trace}-{span}-01"

    def headers(self) -> dict[str, str]:
        h = {"x-govpilot-run-id": self.run_id, "x-govpilot-root-run-id": self.root_run_id,
             "x-govpilot-run-kind": self.kind, "x-govpilot-attempt": str(self.attempt),
             "x-govpilot-step": str(max(self.step, 1)),
             "traceparent": self.traceparent()}
        if self.parent_run_id:
            h["x-govpilot-parent-run-id"] = self.parent_run_id
        if self.tool:
            h["x-govpilot-tool"] = self.tool
        if self.user:
            h["x-govpilot-user"] = self.user
        h["x-litellm-spend-logs-metadata"] = json.dumps(self.spend_metadata(), separators=(",", ":"))
        return h

    def spend_metadata(self) -> dict:
        md = {"run_id": self.run_id, "root_run_id": self.root_run_id, "run_kind": self.kind,
              "attempt": self.attempt, "step": max(self.step, 1), "agent_run_name": self.name}
        if self.parent_run_id:
            md["parent_run_id"] = self.parent_run_id
        if self.tool:
            md["tool"] = self.tool
        if self.user:
            md["user"] = self.user
        return md
