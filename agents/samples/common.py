"""Wiring shared by the three sample agents: everything environment-specific comes from env vars.

  AGENT_ID           the identity in the control-plane register (must equal the container label)
  GATEWAY_URL        http://gateway:4000 (key auth) or http://sso-gateway:8080 (JWT auth via the auth proxy)
  AUTH_MODE          key | oidc
    key:   AGENT_KEY
    oidc:  IDP_TOKEN_URL, CLIENT_ID, CLIENT_SECRET
  MODEL_SMALL/MODEL_LARGE  the approved models this agent uses (default mock-local / mock-remote)
  AGENT_RATES_FILE, AGENT_INTERVAL_S, ...   see govagent.runtime
"""
from __future__ import annotations

import os
from typing import Mapping

from govagent import (GatewayClient, MacaroonAuth, OIDCClientCredentialsAuth, RetryPolicy, StaticKeyAuth, StdoutSink,
                      ToolBox, Transport)
from govagent.events import EventSink
from govagent.runtime import AgentRuntime


def need(env: Mapping[str, str], name: str) -> str:
    v = env.get(name)
    if not v:
        raise SystemExit(f"missing required environment variable {name}")
    return v


def make_auth(env: Mapping[str, str], transport: Transport | None = None):
    mode = env.get("AUTH_MODE", "key")
    if mode == "key":
        return StaticKeyAuth(need(env, "AGENT_KEY"))
    if mode == "oidc":
        return OIDCClientCredentialsAuth(need(env, "IDP_TOKEN_URL"), need(env, "CLIENT_ID"), need(env, "CLIENT_SECRET"),
                                         transport=transport)
    if mode == "delegation":
        return MacaroonAuth(need(env, "DELEGATION_TOKEN"))
    raise SystemExit(f"unknown AUTH_MODE {mode!r}")


class SampleAgent:
    """Base: holds the gateway client, tool box and the loop runtime."""
    agent_id = "sample-agent"
    tools: set[str] = set()

    def __init__(self, env: Mapping[str, str] | None = None, *, sink: EventSink | None = None,
                 transport: Transport | None = None, runtime: AgentRuntime | None = None) -> None:
        self.env = dict(env if env is not None else os.environ)
        self.agent_id = self.env.get("AGENT_ID", self.agent_id)
        self.sink = sink or StdoutSink()
        self.transport = transport
        self.small = self.env.get("MODEL_SMALL", "mock-local")
        self.large = self.env.get("MODEL_LARGE", "mock-remote")
        self.gw = GatewayClient(self.env.get("GATEWAY_URL", "http://gateway:4000"), make_auth(self.env, transport),
                                transport=transport, sink=self.sink,
                                retry=RetryPolicy(max_attempts=int(self.env.get("AGENT_MAX_ATTEMPTS", "4")),
                                                  base_delay_s=float(self.env.get("AGENT_RETRY_BASE_S", "0.4"))))
        self.toolbox = ToolBox(self.agent_id, self.sink, allowed=set(self.tools) or None)
        self.runtime = runtime or AgentRuntime(self.agent_id, self.sink, env=self.env)

    def tokens(self, default: int) -> int:
        """The agent's own default max_tokens, unless an operator override is set (rogue profile)."""
        return self.runtime.settings().max_tokens or default

    def work(self, run) -> None:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError

    def main(self) -> int:
        self.runtime.install_signal_handlers()
        return self.runtime.run(self.work)
