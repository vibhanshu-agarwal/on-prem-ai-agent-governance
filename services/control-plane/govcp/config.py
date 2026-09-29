"""Config loading: YAML with ${VAR} / ${VAR:-default} interpolation from the environment.

Environment-specific values (hosts, teams, budgets, adapter choice) live in the
config file (deploy/control-plane/config.yaml); secrets arrive as env vars only.
"""
from __future__ import annotations

import os
import re
from typing import Any

import yaml

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _interp(v: Any) -> Any:
    if isinstance(v, str):
        def rep(m):
            return os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else "")
        return _VAR.sub(rep, v)
    if isinstance(v, list):
        return [_interp(x) for x in v]
    if isinstance(v, dict):
        return {k: _interp(x) for k, x in v.items()}
    return v


def load_config(path: str | None = None) -> dict[str, Any]:
    path = path or os.environ.get("GOVCP_CONFIG", "/etc/govcp/config.yaml")
    with open(path, encoding="utf-8") as f:
        return _interp(yaml.safe_load(f) or {})


def env_secret(cfg: dict[str, Any], key: str) -> str | None:
    """Adapter configs name the env var holding a secret (`*_env`), never the secret itself."""
    name = cfg.get(key)
    return os.environ.get(name) if name else None
