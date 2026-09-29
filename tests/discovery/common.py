"""Small helpers shared by the live tests (kept out of conftest so it cannot clash with other suites' conftest)."""
from __future__ import annotations

from pathlib import Path

import docker

ROOT = Path(__file__).resolve().parents[2]
ROGUE_LABEL = {"govpilot.t6test": "1"}


def _running(name: str) -> bool:
    try:
        return docker.from_env().containers.get(name).status == "running"
    except Exception:
        return False
