"""Test-only gateway config: the production config (deploy/litellm/config.yaml) plus the `mock-echo` model that
the guardrail tests use (an echo provider that records what it received and can emit tool calls).

The production config no longer carries this fixture (T9). The compose overlays in tests/guardrails/stack mount
the file written here instead of the production one, so production never lists a model whose backend does not
exist. Derived from the production file at run time, so the two cannot drift.
"""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROD = ROOT / "deploy" / "litellm" / "config.yaml"
OUT = ROOT / ".local" / "guardrails-test" / "config.yaml"

ECHO_MODEL = """\
  # ---- mock-echo: TEST FIXTURE (tests/guardrails). Served by tests/guardrails/stack/compose.echo.yml.
  - model_name: mock-echo
    litellm_params:
      model: openai/mock-echo
      api_base: http://mock-echo:8000/v1
      api_key: os.environ/MOCK_LOCAL_API_KEY
      input_cost_per_token: 0.000001
      output_cost_per_token: 0.000002
      max_tokens: 256
    model_info:
      max_output_tokens: 1024
      max_input_tokens: 8192

"""


def ensure() -> pathlib.Path:
    text = PROD.read_text(encoding="utf-8").replace("\r\n", "\n")
    marker = "\ngeneral_settings:"
    assert marker in text, "unexpected production config layout"
    head, tail = text.split(marker, 1)
    out = head.rstrip("\n") + "\n\n" + ECHO_MODEL + marker.lstrip("\n") + tail
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if not OUT.exists() or OUT.read_text(encoding="utf-8") != out:
        OUT.write_text(out, encoding="utf-8", newline="\n")
    return OUT
