"""Fixtures for the T4 agent tests.

Offline tests (contracts, runtime, samples against a fake gateway) need nothing but pytest.
Live tests need the base stack + control plane + `scripts/agents-up.sh` having run once
(keys, IdP client, delegation token, image govpilot/agents:1); they skip otherwise.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agents"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))


def load_callback():
    """Import the gateway callback without LiteLLM installed (a stand-in CustomLogger is enough for its pure logic)."""
    try:
        import litellm  # noqa: F401
    except ImportError:
        pkg = types.ModuleType("litellm")
        integ = types.ModuleType("litellm.integrations")
        cl = types.ModuleType("litellm.integrations.custom_logger")

        class CustomLogger:  # noqa: D401 - stand-in
            def __init__(self, *a, **k):
                pass
        cl.CustomLogger = CustomLogger
        sys.modules.update({"litellm": pkg, "litellm.integrations": integ, "litellm.integrations.custom_logger": cl})
    sys.path.insert(0, str(ROOT / "deploy" / "litellm"))
    from callbacks import run_attribution
    return run_attribution


@pytest.fixture(scope="session")
def callback():
    return load_callback()


@pytest.fixture
def sink():
    from govagent import MemorySink
    return MemorySink()
