"""Build adapters and domain services from config. The only place adapter classes are named.

To adopt this in another environment, add an adapter class, register it in
ADAPTERS under its port, and select it in config (`adapters.<port>.type`).
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

from .config import env_secret
from .domain.context import Ports
from .domain.delegation import AccessService, DelegationService
from .domain.discovery import DiscoveryService
from .domain.policy import Policy
from .domain.quarantine import QuarantineService
from .domain.reconcile import Reconciler
from .domain.register import RegisterService
from .domain.stop import StopService

ADAPTERS: dict[str, dict[str, str]] = {
    "gateway_admin": {"litellm": "govcp.adapters.litellm_gateway:LiteLLMGatewayAdmin",
                      "memory": "govcp.adapters.memory:MemoryGateway"},
    "orchestrator": {"docker": "govcp.adapters.docker_orchestrator:DockerOrchestrator",
                     "memory": "govcp.adapters.memory:MemoryOrchestrator"},
    "network_quarantine": {"docker": "govcp.adapters.docker_orchestrator:DockerNetworkQuarantine",
                           "memory": "govcp.adapters.memory:MemoryNetwork"},
    "identity_provider": {"oidc": "govcp.adapters.oidc_identity:OIDCIdentityProvider",
                          "memory": "govcp.adapters.memory:MemoryIdentity"},
    "secret_store": {"file": "govcp.adapters.file_secrets:FileSecretStore",
                     "memory": "govcp.adapters.memory:MemorySecretStore"},
    "credential_revoker": {"secret_store": "govcp.adapters.secret_revoker:SecretStoreRevoker",
                           "memory": "govcp.adapters.memory:MemoryRevoker"},
    "audit_sink": {"postgres": "govcp.adapters.postgres:PostgresAuditSink",
                   "jsonl": "govcp.adapters.jsonl_audit:JsonlAuditSink",
                   "memory": "govcp.adapters.memory:MemoryAudit"},
    "repository": {"postgres": "govcp.adapters.postgres:PostgresRepository",
                   "memory": "govcp.adapters.memory:MemoryRepository"},
}


def _cls(port: str, typ: str):
    try:
        mod, name = ADAPTERS[port][typ].split(":")
    except KeyError:
        raise ValueError(f"no adapter {typ!r} registered for port {port!r}") from None
    return getattr(importlib.import_module(mod), name)


@dataclass
class App:
    config: dict[str, Any]
    policy: Policy
    ports: Ports
    register: RegisterService
    stop: StopService
    quarantine: QuarantineService
    discovery: DiscoveryService
    delegation: DelegationService
    access: AccessService
    reconciler: Reconciler


def build_ports(cfg: dict[str, Any]) -> Ports:
    a = cfg.get("adapters", {})
    pool = None

    def pg_pool():
        nonlocal pool
        if pool is None:
            from .adapters.postgres import make_pool
            pool = make_pool(env_secret(a["repository"], "dsn_env") or env_secret(a["audit_sink"], "dsn_env"))
        return pool

    def build(port: str):
        c = dict(a.get(port) or {})
        typ = c.pop("type")
        cls = _cls(port, typ)
        if typ == "litellm":
            return cls(url=c["url"], master_key=env_secret(c, "master_key_env"))
        if port == "orchestrator" and typ == "docker":
            return cls(base_url=c.get("base_url") or None, host_name=c.get("host_name") or None)
        if port == "network_quarantine" and typ == "docker":
            return cls(governed_networks=c["governed_networks"], chokepoints=c.get("chokepoints", []),
                       helper_image=c["helper_image"], drain_timeout_s=float(c.get("drain_timeout_s", 3)),
                       base_url=c.get("base_url") or None)
        if typ == "oidc":
            return cls(issuer=c["issuer"], jwks_url=c["jwks_url"], admin_url=c.get("admin_url"),
                       admin_token=env_secret(c, "admin_token_env"))
        if typ == "file":
            return cls(path=c["path"])
        if typ == "postgres":
            return cls(pg_pool())
        if typ == "jsonl":
            return cls(path=c["path"])
        return cls(**c)

    orchestrator = build("orchestrator")
    net_cfg = dict(a.get("network_quarantine") or {})
    network = (_cls("network_quarantine", "memory")(orchestrator) if net_cfg.get("type") == "memory"
               else build("network_quarantine"))
    secrets = build("secret_store")
    rv_cfg = dict(a.get("credential_revoker") or {"type": "secret_store"})
    revoker = (_cls("credential_revoker", "secret_store")(secrets, rv_cfg.get("kinds"))
               if rv_cfg.get("type") == "secret_store" else build("credential_revoker"))
    return Ports(gateway=build("gateway_admin"), orchestrator=orchestrator, network=network,
                 identity=build("identity_provider"), secrets=secrets, audit=build("audit_sink"),
                 repo=build("repository"), revokers=[revoker])


def build_app(cfg: dict[str, Any], ports: Ports | None = None) -> App:
    policy = Policy.from_dict(cfg.get("policy"))
    ports = ports or build_ports(cfg)
    register = RegisterService(ports, policy)
    delegation = DelegationService(ports, policy, register)
    register.delegation = delegation
    stop = StopService(ports, policy, register)
    quarantine = QuarantineService(ports, policy, register, stop)
    discovery = DiscoveryService(ports, policy, register)
    access = AccessService(ports, register, delegation, discovery)
    reconciler = Reconciler(ports, register, quarantine)
    return App(cfg, policy, ports, register, stop, quarantine, discovery, delegation, access, reconciler)
