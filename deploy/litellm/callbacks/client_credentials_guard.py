"""Client credential / endpoint guard for the LiteLLM gateway (T9 review follow-up: "client api_key passthrough").

The problem. The gateway holds the provider credentials; an agent holds only its own virtual key. LiteLLM copies
unknown request-body fields into the provider call, so a caller could bring its own provider credential or steer
the call:

  {"model": "mock-local", ..., "api_key": "sk-mine"}                 -> the call to the provider uses the caller's key
  {"model": ..., "extra_headers": {"Authorization": "Bearer sk-mine"}}  (or "headers")  -> same, through a header
  {"model": ..., "custom_llm_provider": ..., "api_version": ..., "aws_secret_access_key": ...}  -> other overrides

Measured on LiteLLM v1.100.3 (tests/hardening/test_client_credentials.py): native LiteLLM already refuses
`api_base` / `base_url` (and a long list of observability and price fields) unconditionally, but `api_key`,
`extra_headers` and `headers` went straight through. Two consequences, both real:

  * shadow credentials: spend on a provider account the organisation does not control (the gateway still counts
    the tokens at list price, but the provider-side allowlists, quotas and audit trail are bypassed), and a
    credential the platform never issued travelling through the platform;
  * cross-agent denial of service: a WRONG key makes the provider answer 401, LiteLLM's router puts the shared
    deployment into cooldown, and every other agent then gets "No deployments available" (429) for the cooldown.

The rule. An agent never chooses provider credentials, endpoints or provider-bound headers: a request that carries
any of them is refused with 400 `client_credentials_not_allowed` BEFORE anything reaches a provider (the native
budget reservation taken at auth is released by the failure hook). The refusal names the offending field names,
never their values, and emits one `GOVPILOT_REQUEST_GUARD {json}` audit line. Top-level fields and the nested
containers LiteLLM merges into the call (`extra_body`, `litellm_params`, `litellm_embedding_config`, `metadata`,
`litellm_metadata`) are checked.

Configuration (config, not code):
  GOVPILOT_CLIENT_CREDENTIALS_MODE   reject (default) | audit (log only; for a migration window) | off
  GOVPILOT_CLIENT_CREDENTIALS_ALLOW  comma list of fields to permit (an explicit, reviewable opt-in per field,
                                     the same idea as LiteLLM's `configurable_clientside_auth_params`)
  GOVPILOT_CLIENT_CREDENTIALS_EXTRA  comma list of further field names to block

Loose coupling: the audit line goes through a one-method port (`GuardEventSink`) with one adapter (stdout log).
Single file on purpose: LiteLLM loads it by path (callbacks.client_credentials_guard.client_credentials_guard).
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any, Protocol

from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

log = logging.getLogger("govpilot.client_credentials_guard")

# provider credential / endpoint / identity fields (top level and inside the nested containers)
CREDENTIAL_FIELDS = frozenset({
    "api_key", "api_base", "base_url", "api_version", "organization", "deployment_id", "custom_llm_provider",
    "azure_ad_token", "azure_ad_token_provider", "azure_username", "azure_password", "azure_scope",
    "aws_access_key_id", "aws_secret_access_key", "aws_session_token", "aws_region_name", "aws_role_name",
    "aws_profile_name", "aws_web_identity_token", "aws_bedrock_runtime_endpoint", "aws_sts_endpoint",
    "vertex_project", "vertex_location", "vertex_credentials", "vertex_ai_credentials",
    "watsonx_token", "user_config", "model_list",
})
# provider-bound headers and whole-object overrides: only meaningful at the top level (LiteLLM itself puts the
# inbound request headers under metadata["headers"], so `headers` is NOT checked in the nested containers)
TOP_LEVEL_ONLY = frozenset({"extra_headers", "headers", "litellm_params", "client"})
NESTED_CONTAINERS = ("extra_body", "litellm_params", "litellm_embedding_config", "metadata", "litellm_metadata")
MODES = ("reject", "audit", "off")


class GuardEventSink(Protocol):
    def emit(self, event: dict) -> None: ...


class LogEventSink:
    """Adapter: one JSON line per event on the gateway's stdout (collected by the container log driver)."""

    PREFIX = "GOVPILOT_REQUEST_GUARD "

    def emit(self, event: dict) -> None:
        print(self.PREFIX + json.dumps(event, sort_keys=True, default=str), file=sys.stdout, flush=True)


SINKS = {"log": LogEventSink}


def _csv(name: str) -> frozenset[str]:
    return frozenset(x.strip() for x in os.getenv(name, "").split(",") if x.strip())


def offending_fields(data: dict, blocked: frozenset[str], top_only: frozenset[str]) -> list[str]:
    """Names (never values) of the blocked fields present in a request body, as `field` or `container.field`."""
    found = [k for k in data if isinstance(k, str) and (k in blocked or k in top_only)]
    for c in NESTED_CONTAINERS:
        v = data.get(c)
        if isinstance(v, str):                      # LiteLLM accepts JSON-encoded metadata in form fields
            try:
                v = json.loads(v)
            except ValueError:
                v = None
        if isinstance(v, dict):
            found += [f"{c}.{k}" for k in v if isinstance(k, str) and k in blocked]
    return sorted(set(found))


def _reject(status: int, etype: str, message: str) -> Exception:
    try:
        from litellm.proxy._types import ProxyException
        return ProxyException(message=message, type=etype, param=None, code=status)
    except Exception:  # pragma: no cover - fallback if the proxy type moves
        return HTTPException(status_code=status, detail={"error": message, "type": etype})


class ClientCredentialsGuard(CustomLogger):
    def __init__(self, sink: GuardEventSink | None = None, mode: str | None = None) -> None:
        super().__init__()
        self.sink = sink or SINKS[os.getenv("GOVPILOT_REQUEST_GUARD_SINK", "log")]()
        self.mode = mode or os.getenv("GOVPILOT_CLIENT_CREDENTIALS_MODE", "reject").lower()
        if self.mode not in MODES:
            log.error("GOVPILOT_CLIENT_CREDENTIALS_MODE=%r is not one of %s; using reject", self.mode, MODES)
            self.mode = "reject"
        allow = _csv("GOVPILOT_CLIENT_CREDENTIALS_ALLOW")
        self.blocked = (CREDENTIAL_FIELDS | _csv("GOVPILOT_CLIENT_CREDENTIALS_EXTRA")) - allow
        self.top_only = TOP_LEVEL_ONLY - allow

    def _emit(self, ev: dict) -> None:
        try:
            self.sink.emit(ev)
        except Exception:  # auditing must never break the request path
            log.exception("request guard sink failed")

    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):
        if self.mode == "off" or not isinstance(data, dict):
            return data
        fields = offending_fields(data, self.blocked, self.top_only)
        if not fields:
            return data
        md: Any = getattr(user_api_key_dict, "metadata", None)
        self._emit({"event": "request.client_credentials_rejected" if self.mode == "reject" else
                    "request.client_credentials_seen", "ts": time.time(), "mode": self.mode, "fields": fields,
                    "call_type": str(call_type).split(".")[-1], "model": data.get("model"),
                    "key_alias": getattr(user_api_key_dict, "key_alias", None),
                    "agent_id": md.get("agent_id") if isinstance(md, dict) else None,
                    "team_id": getattr(user_api_key_dict, "team_id", None)})
        if self.mode == "reject":
            raise _reject(400, "client_credentials_not_allowed",
                          "Rejected Request: the request body carries provider credentials, endpoints or headers ("
                          + ", ".join(fields) + "). Agents use the gateway's credentials only; "
                          "remove these fields.")
        return data


client_credentials_guard = ClientCredentialsGuard()
