"""Delegating a sub-task to a child agent.

The parent never hands its own credential to the child. It asks the delegation broker (a thin
forwarder to the control plane's POST /v1/delegations) for a child identity, presenting ITS OWN
delegation token; the control plane only mints a child whose budget, models, depth and lifetime
are a subset of the parent's (broadening is denied and alerted). The child then calls the gateway
with the attenuated token (`Authorization: Macaroon ...`, through the auth proxy), so its spend
lands on its OWN gateway key (own budget, own stop switch).

Runs: delegating creates a run of kind=delegation, child of the run that delegated. The child agent
does its work under that run id (and its own tool calls hang below it).
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .auth import MacaroonAuth
from .context import RunContext
from .events import EventSink, error_fields
from .gateway import GatewayClient, RetryPolicy
from .transport import Transport, TransportError, UrllibTransport


class DelegationDenied(Exception):
    def __init__(self, message: str, reasons: list[str] | None = None) -> None:
        super().__init__(message)
        self.reasons = reasons or []


@dataclass
class Delegated:
    child_agent_id: str
    token: str
    expires: float
    budget_usd: float
    models: list[str]


class Delegator:
    """Mints (and caches) one child identity per `worker` name until it expires, then re-mints."""

    def __init__(self, agent_id: str, broker_url: str, parent_token: str, gateway_url: str, sink: EventSink, *,
                 transport: Transport | None = None, client_factory: Callable[[str, MacaroonAuth], GatewayClient] | None = None,
                 budget_usd: float = 0.2, models: list[str] | None = None, ttl_s: float = 3600.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.agent_id, self.broker_url, self._parent_token = agent_id, broker_url.rstrip("/"), parent_token
        self.gateway_url, self.sink, self.transport = gateway_url, sink, transport or UrllibTransport()
        self.budget_usd, self.models, self.ttl_s, self.clock = budget_usd, models or ["mock-local"], ttl_s, clock
        self._factory = client_factory or (lambda url, auth: GatewayClient(url, auth, sink=sink, transport=self.transport,
                                                                            retry=RetryPolicy(max_attempts=3)))
        self._cache: dict[str, tuple[Delegated, GatewayClient]] = {}
        self._lock = threading.Lock()

    def mint(self, worker: str) -> Delegated:
        name = re.sub(r"[^a-z0-9_-]", "-", f"{worker}-{int(self.clock())}".lower())[:31]
        body = json.dumps({"parent_token": self._parent_token, "name": name, "max_budget_usd": self.budget_usd,
                           "models": self.models, "ttl_s": self.ttl_s}).encode()
        try:
            r = self.transport.send("POST", f"{self.broker_url}/v1/delegations",
                                    {"content-type": "application/json"}, body, 15.0)
        except TransportError as e:
            raise DelegationDenied(f"delegation broker unreachable: {e}") from None
        d: dict[str, Any] = json.loads(r.body or b"{}")
        if r.status != 201:
            reasons = (d.get("details") or {}).get("reasons") or []
            self.sink.emit({"event": "delegation.denied", "agent_id": self.agent_id, "worker": worker,
                            "http_status": r.status, "reasons": reasons, "message": d.get("message")})
            raise DelegationDenied(d.get("message") or f"HTTP {r.status}", reasons)
        rec = d["delegation"]
        out = Delegated(d["child_agent_id"], d["delegation_token"], float(rec["expires"]),
                        float(rec["max_budget_usd"]), list(rec["models"]))
        self.sink.emit({"event": "delegation.minted", "agent_id": self.agent_id, "child_agent_id": out.child_agent_id,
                        "budget_usd": out.budget_usd, "models": out.models, "expires": out.expires,
                        "delegation_id": rec.get("delegation_id")})
        return out

    def child(self, worker: str) -> tuple[Delegated, GatewayClient]:
        with self._lock:
            hit = self._cache.get(worker)
            if hit and hit[0].expires - self.clock() > 30:
                return hit
            dg = self.mint(worker)
            pair = (dg, self._factory(self.gateway_url, MacaroonAuth(dg.token)))
            self._cache[worker] = pair
            return pair

    def forget(self, worker: str) -> None:
        with self._lock:
            self._cache.pop(worker, None)

    def delegate(self, run: RunContext, worker: str, task: str,
                 fn: Callable[[RunContext, GatewayClient], Any]) -> Any:
        """Run `fn(child_run, child_gateway)` as the child agent; the child run is a kind=delegation run."""
        dg, gw = self.child(worker)
        child_run = run.child("delegation", f"delegate:{task}", agent_id=dg.child_agent_id)
        base = {"agent_id": self.agent_id, "child_agent_id": dg.child_agent_id, "run_id": child_run.run_id,
                "parent_run_id": child_run.parent_run_id, "root_run_id": child_run.root_run_id,
                "run_kind": "delegation"}
        self.sink.emit({"event": "run.start", **base, "name": child_run.name})
        t0 = time.time()
        try:
            out = fn(child_run, gw)
        except Exception as e:
            self.sink.emit({"event": "run.end", **base, "status": "error", **error_fields(e),
                            "duration_ms": round((time.time() - t0) * 1000, 1)})
            if getattr(e, "stopped", False):
                self.forget(worker)
            raise
        self.sink.emit({"event": "run.end", **base, "status": "ok", "duration_ms": round((time.time() - t0) * 1000, 1)})
        return out
