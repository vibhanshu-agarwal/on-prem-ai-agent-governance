"""Tool calls as child runs.

  box = ToolBox("hr-agent", sink, allowed={"lookup_employee", "search_policies"})
  result = box.call(run, "lookup_employee", lookup_employee, emp_id="E1003")

`call` creates a child run (kind=tool, parent = the calling run), hands it to the tool function as
its first argument, and records start/end/duration/error. A tool that calls the LLM passes that
child run to GatewayClient.chat, so the spend is attributed to the tool call, and the tool call to
the run that made it. A tool that does not call the LLM still leaves a run event, so the run tree
in the agent log is complete even where the gateway saw nothing.

The allowlist is the agent-side half of "tool authorization"; T5's deterministic rules are the
gateway-side half.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from .context import RunContext
from .events import EventSink


class ToolNotAllowed(Exception):
    pass


class ToolBox:
    def __init__(self, agent_id: str, sink: EventSink, allowed: set[str] | None = None) -> None:
        self.agent_id, self.sink, self.allowed = agent_id, sink, allowed

    def call(self, run: RunContext, name: str, fn: Callable[..., Any], /, **kwargs: Any) -> Any:
        if self.allowed is not None and name not in self.allowed:
            self.sink.emit({"event": "tool.denied", "agent_id": self.agent_id, "run_id": run.run_id, "tool": name})
            raise ToolNotAllowed(f"tool {name!r} is not declared by {self.agent_id}")
        child = run.child("tool", f"tool:{name}", tool=name)
        base = {"agent_id": self.agent_id, "run_id": child.run_id, "parent_run_id": child.parent_run_id,
                "root_run_id": child.root_run_id, "run_kind": "tool", "tool": name}
        self.sink.emit({"event": "run.start", **base, "name": child.name})
        t0 = time.time()
        try:
            out = fn(child, **kwargs)
        except Exception as e:
            self.sink.emit({"event": "run.end", **base, "status": "error", "error": f"{type(e).__name__}: {e}"[:200],
                            "duration_ms": round((time.time() - t0) * 1000, 1)})
            raise
        self.sink.emit({"event": "run.end", **base, "status": "ok", "duration_ms": round((time.time() - t0) * 1000, 1)})
        return out
