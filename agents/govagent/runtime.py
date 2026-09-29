"""Config-driven agent loop.

Loop rate is configuration, not code. Effective settings for an agent are, lowest to highest:
  built-in defaults  <  env (AGENT_INTERVAL_S, AGENT_CONCURRENCY, ...)  <  rates file "default"
  <  rates file entry for the agent id

The rates file (JSON, default /etc/agents/rates.json, mounted from deploy/agents/config/) is
re-read whenever its mtime changes (a sleeping agent wakes within ~0.5 s of the change), so an operator can change
a rate on a RUNNING agent, e.g. make one "go rogue" for a demo, without a restart:

  python scripts/agents_ctl.py rogue finance-recon-agent      # 40 req/s-ish, ignores budget refusals
  python scripts/agents_ctl.py calm finance-recon-agent       # back to the configured rate

Keys: interval_s (delay between iterations), jitter (0..1 fraction), concurrency (parallel
iterations per tick), max_tokens (override for every LLM call, else the agent's own default),
on_budget_exceeded ("backoff" | "hammer": hammer keeps going at full rate when the gateway refuses),
paused (bool), profile (free text shown in the log, e.g. "rogue").
"""
from __future__ import annotations

import json
import os
import random
import signal
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .context import RunContext
from .events import EventSink, error_fields
from .gateway import GatewayError

HEARTBEAT = os.environ.get("AGENT_HEARTBEAT_FILE", "/tmp/agent.heartbeat")


@dataclass
class LoopSettings:
    interval_s: float = 10.0
    jitter: float = 0.2
    concurrency: int = 1
    max_tokens: int | None = None
    on_budget_exceeded: str = "backoff"
    paused: bool = False
    profile: str = "normal"

    @classmethod
    def merge(cls, *layers: dict) -> "LoopSettings":
        conv = {"interval_s": float, "jitter": float, "concurrency": int, "max_tokens": int,
                "on_budget_exceeded": str, "paused": _as_bool, "profile": str}
        cur: dict = {}
        for layer in layers:
            for k, v in (layer or {}).items():
                if k in conv and v is not None and v != "":
                    cur[k] = conv[k](v)
        return cls(**cur)


def _as_bool(v) -> bool:
    return v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")


def env_layer(env: dict[str, str] | None = None) -> dict:
    e = env if env is not None else os.environ
    m = {"AGENT_INTERVAL_S": "interval_s", "AGENT_JITTER": "jitter", "AGENT_CONCURRENCY": "concurrency",
         "AGENT_MAX_TOKENS": "max_tokens", "AGENT_ON_BUDGET_EXCEEDED": "on_budget_exceeded",
         "AGENT_PROFILE": "profile"}
    return {dst: e[src] for src, dst in m.items() if e.get(src)}


class RatesFile:
    def __init__(self, path: str | None) -> None:
        self.path = path
        self._mtime = -1.0
        self._data: dict = {}

    def mtime(self) -> float | None:
        """Modification time of the file (one stat); None when there is no file."""
        try:
            return os.stat(self.path).st_mtime if self.path else None
        except OSError:
            return None

    def get(self, agent_id: str) -> dict:
        if not self.path:
            return {}
        try:
            mt = os.stat(self.path).st_mtime
            if mt != self._mtime:
                with open(self.path, encoding="utf-8") as f:
                    self._data = json.load(f)
                self._mtime = mt
        except (OSError, ValueError):
            pass                                  # keep the last good copy; a half-written file must not kill the agent
        return {**(self._data.get("default") or {}), **(self._data.get(agent_id) or {})}


class AgentRuntime:
    """Runs `work(run)` forever (or `max_iterations` times) at the configured rate."""

    def __init__(self, agent_id: str, sink: EventSink, *, rates_path: str | None = None,
                 env: dict[str, str] | None = None, sleep: Callable[[float], None] | None = None,
                 max_iterations: int | None = None) -> None:
        self.agent_id, self.sink = agent_id, sink
        self.env = env if env is not None else dict(os.environ)
        self.rates = RatesFile(rates_path if rates_path is not None else self.env.get("AGENT_RATES_FILE", "/etc/agents/rates.json"))
        self.stop_evt = threading.Event()
        self.sleep = sleep or self._nap
        self.max_iterations = max_iterations if max_iterations is not None else (
            int(self.env["AGENT_MAX_ITERATIONS"]) if self.env.get("AGENT_MAX_ITERATIONS") else None)
        self.iterations = 0
        self.failures = 0
        self._last_profile = None
        self._budget_strikes = 0

    def _nap(self, seconds: float) -> None:
        """The default sleep between iterations: ends early on a stop signal or when the rates file changes, so an
        operator's change (e.g. `agents_ctl.py rogue`) reaches a slow agent within ~0.5 s instead of after its interval."""
        end = time.time() + seconds
        seen = self.rates.mtime()          # relative to the start of THIS nap: a file that stays unreadable wakes it once, not forever
        while not self.stop_evt.is_set():
            left = end - time.time()
            if left <= 0 or self.rates.mtime() != seen:
                return
            self.stop_evt.wait(min(0.5, left))

    def settings(self) -> LoopSettings:
        s = LoopSettings.merge(env_layer(self.env), self.rates.get(self.agent_id))
        if s.profile != self._last_profile:
            self.sink.emit({"event": "loop.settings", "agent_id": self.agent_id, "interval_s": s.interval_s,
                            "concurrency": s.concurrency, "max_tokens": s.max_tokens, "profile": s.profile,
                            "on_budget_exceeded": s.on_budget_exceeded, "paused": s.paused})
            self._last_profile = s.profile
        return s

    def install_signal_handlers(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, lambda *_: self.stop_evt.set())
            except (ValueError, OSError):
                pass

    def _one(self, work: Callable[[RunContext], None], s: LoopSettings) -> None:
        run = RunContext.root(self.agent_id, name=self.agent_id + ".iteration")
        self.sink.emit({"event": "run.start", "agent_id": self.agent_id, "run_id": run.run_id,
                        "root_run_id": run.root_run_id, "parent_run_id": None, "run_kind": "task", "name": run.name})
        t0 = time.time()
        status, err, gw_err = "ok", None, None
        try:
            work(run)
            self._budget_strikes = 0
        except GatewayError as e:
            status, err = "error", f"{e.status} {e.etype}: {e.message}"[:200]
            gw_err = error_fields(e).get("gateway_error")
            if e.budget_exceeded:
                self._budget_strikes += 1
            if e.stopped:
                status = "stopped"
        except Exception as e:  # noqa: BLE001 - an agent loop survives its own bugs and reports them
            status, err = "error", f"{type(e).__name__}: {e}"[:200]
        if status != "ok":
            self.failures += 1
        # The terminal state of the run, always written: a run that was refused or aborted before it made an LLM
        # call of its own (e.g. its first tool call got a fail-closed 503) has NO gateway row, so this record
        # (durable in the journal, see events.JournalSink) is what closes its children's parent link.
        end = {"event": "run.end", "agent_id": self.agent_id, "run_id": run.run_id,
               "root_run_id": run.root_run_id, "parent_run_id": None, "run_kind": "task", "status": status,
               "error": err, "duration_ms": round((time.time() - t0) * 1000, 1)}
        if gw_err:
            end["gateway_error"] = gw_err
        self.sink.emit(end)

    def run(self, work: Callable[[RunContext], None]) -> int:
        self.sink.emit({"event": "agent.start", "agent_id": self.agent_id, "pid": os.getpid()})
        while not self.stop_evt.is_set():
            if self.max_iterations is not None and self.iterations >= self.max_iterations:
                break
            s = self.settings()
            self._beat()
            if s.paused:
                self.sleep(1.0)
                continue
            n = max(1, s.concurrency)
            if self.max_iterations is not None:
                n = min(n, self.max_iterations - self.iterations)
            threads = [threading.Thread(target=self._one, args=(work, s), daemon=True) for _ in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.iterations += n
            delay = s.interval_s * (1 + random.uniform(-s.jitter, s.jitter))
            if self._budget_strikes and s.on_budget_exceeded != "hammer":
                delay = max(delay, min(300.0, 5.0 * 2 ** min(self._budget_strikes, 6)))   # back off when refused
            if self.max_iterations is None or self.iterations < self.max_iterations:
                self.sleep(max(0.0, delay))
        self.sink.emit({"event": "agent.stop", "agent_id": self.agent_id, "iterations": self.iterations,
                        "failures": self.failures})
        return 0

    def _beat(self) -> None:
        try:
            with open(HEARTBEAT, "w") as f:
                f.write(str(time.time()))
        except OSError:
            pass


def health_main() -> int:
    """Container healthcheck: the loop must have ticked within AGENT_HEALTH_MAX_AGE_S (default 900)."""
    try:
        age = time.time() - os.stat(HEARTBEAT).st_mtime
    except OSError:
        return 1
    return 0 if age < float(os.environ.get("AGENT_HEALTH_MAX_AGE_S", "900")) else 1


if __name__ == "__main__":
    raise SystemExit(health_main())
