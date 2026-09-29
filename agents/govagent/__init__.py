"""govagent: the small adapter library every governed agent uses to talk to the gateway.

  RunContext      run_id / parent_run_id / root_run_id and how they travel (headers + LiteLLM metadata)
  GatewayClient   OpenAI-compatible chat calls; retries KEEP the run id and count attempts
  ToolBox         a tool call is a child run
  Delegator       delegating a sub-task is a child run under an attenuated delegation token
  AuthProvider    static key | OIDC client credentials (through the auth proxy) | delegation token
  AgentRuntime    config-driven loop (rate, concurrency, rogue profile) with graceful stop

Standard library only, so an agent image needs nothing but Python.
"""
from .auth import AuthError, AuthProvider, MacaroonAuth, OIDCClientCredentialsAuth, StaticKeyAuth
from .context import RunContext, new_run_id
from .delegation import Delegated, DelegationDenied, Delegator
from .events import EventSink, MemorySink, StdoutSink
from .gateway import ChatResult, GatewayClient, GatewayError, RetryPolicy
from .tools import ToolBox, ToolNotAllowed
from .transport import HttpResponse, Transport, TransportError, UrllibTransport

__all__ = ["AuthError", "AuthProvider", "MacaroonAuth", "OIDCClientCredentialsAuth", "StaticKeyAuth",
           "RunContext", "new_run_id", "Delegated", "DelegationDenied", "Delegator", "EventSink", "MemorySink",
           "StdoutSink", "ChatResult", "GatewayClient", "GatewayError", "RetryPolicy", "ToolBox",
           "ToolNotAllowed", "HttpResponse", "Transport", "TransportError", "UrllibTransport"]
