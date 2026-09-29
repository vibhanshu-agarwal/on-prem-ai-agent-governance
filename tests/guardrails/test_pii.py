"""PII handling: mask or block on input per policy, redact on output, per-agent config, no PII in audit."""
import json

import pytest

from govguard import BuiltinEngine, GuardrailBlocked
from govguard.engine import Span

CARD = "4111 1111 1111 1111"          # Luhn-valid test number
IBAN = "DE89370400440532013000"
SSN = "219-09-9999"


class CountingEngine(BuiltinEngine):
    name = "counting"

    def __init__(self):
        self.analyzed: list[str] = []

    async def analyze(self, text, entities, language="en", score_threshold=0.5):
        self.analyzed.append(text)
        return await super().analyze(text, entities, language, score_threshold)


def test_input_pii_masked_before_it_reaches_the_model(harness):
    data, out = harness.request([{"role": "user", "content": "Mail bob@example.com, call 415-555-0134, host 10.20.30.40"}],
                                agent="coding-agent")
    text = data["messages"][0]["content"]
    assert text == "Mail <EMAIL_ADDRESS>, call <PHONE_NUMBER>, host <IP_ADDRESS>"
    assert out.modified and out.findings[0]["action"] == "mask"
    assert out.findings[0]["entities"] == {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1, "IP_ADDRESS": 1}


def test_input_pii_block_returns_structured_error_without_the_value(harness):
    with pytest.raises(GuardrailBlocked) as e:
        harness.request([{"role": "user", "content": f"charge card {CARD} for the invoice"}], agent="coding-agent")
    b = e.value
    assert (b.status, b.code) == (400, "pii_blocked") and b.extra["entities"] == {"CREDIT_CARD": 1}
    assert CARD not in json.dumps(b.body())
    assert "4111" not in json.dumps(harness.audit.events)


def test_ssn_blocked_and_reported_by_type_only(harness):
    with pytest.raises(GuardrailBlocked) as e:
        harness.request([{"role": "user", "content": f"employee ssn {SSN}"}], agent="hr-agent")
    assert e.value.extra["entities"] == {"US_SSN": 1}
    assert SSN not in json.dumps(harness.audit.events)


def test_policy_differs_per_agent_same_prompt(harness):
    msg = [{"role": "user", "content": f"pay into {IBAN} please"}]
    d, _ = harness.request(json.loads(json.dumps(msg)), agent="finance-recon-agent")   # default: mask
    assert d["messages"][0]["content"] == "pay into <IBAN_CODE> please"
    with pytest.raises(GuardrailBlocked):                                                # hr-agent: block
        harness.request(json.loads(json.dumps(msg)), agent="hr-agent")


def test_team_level_config_sits_between_defaults_and_agent(make_harness, raw_config):
    raw_config["teams"] = {"engineering": {"pii": {"entities": {"EMAIL_ADDRESS": "block"}}}}
    h = make_harness(raw=raw_config)
    with pytest.raises(GuardrailBlocked):
        run_req = h.pipeline.check_request(h.ctx("coding-agent", team="engineering"),
                                           {"messages": [{"role": "user", "content": "bob@example.com"}]})
        import asyncio
        asyncio.run(run_req)


def test_list_content_parts_and_system_role(harness):
    msgs = [{"role": "system", "content": "Escalate to ops@corp.example on failure."},
            {"role": "user", "content": [{"type": "text", "text": "my email is carol@example.com"},
                                         {"type": "image_url", "image_url": {"url": "http://x/y.png"}}]}]
    d, _ = harness.request(msgs, agent="coding-agent")
    assert d["messages"][0]["content"] == "Escalate to ops@corp.example on failure."     # system prompt is trusted config
    assert d["messages"][1]["content"][0]["text"] == "my email is <EMAIL_ADDRESS>"
    assert d["messages"][1]["content"][1]["type"] == "image_url"


def test_tool_results_are_scanned_too(harness):
    d, _ = harness.request([{"role": "user", "content": "look it up"},
                            {"role": "tool", "tool_call_id": "1", "content": '{"contact": "dave@example.com"}'}],
                           agent="coding-agent")
    assert "dave@example.com" not in d["messages"][1]["content"] and "<EMAIL_ADDRESS>" in d["messages"][1]["content"]


def test_output_pii_redacted(harness):
    new, out = harness.response("The customer is reachable at erin@example.com or 212-555-0199.", agent="finance-recon-agent")
    assert new == "The customer is reachable at <EMAIL_ADDRESS> or <PHONE_NUMBER>."
    assert out.findings[0]["action"] == "redact"


def test_output_pii_block_mode(make_harness, raw_config):
    raw_config["agents"]["finance-recon-agent"]["pii"] = {"output": "block"}
    h = make_harness(raw=raw_config)
    with pytest.raises(GuardrailBlocked) as e:
        h.response("send to erin@example.com", agent="finance-recon-agent")
    assert e.value.code == "pii_in_output_blocked" and e.value.status == 403


def test_output_secrets_redacted_or_blocked_per_agent(harness):
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    new, _ = harness.response(f"use {key} to log in", agent="finance-recon-agent")
    assert key not in new and "<REDACTED:aws_access_key>" in new
    with pytest.raises(GuardrailBlocked) as e:                       # hr-agent policy: secrets output = block
        harness.response(f"use {key} to log in", agent="hr-agent")
    assert e.value.code == "secret_in_output"
    assert key not in json.dumps(harness.audit.events)


def test_input_secrets_masked_or_blocked(harness):
    key = "ghp_" + "z" * 36
    d, _ = harness.request([{"role": "user", "content": f"my token is {key}"}], agent="coding-agent")
    assert key not in d["messages"][0]["content"]
    with pytest.raises(GuardrailBlocked) as e:
        harness.request([{"role": "user", "content": f"my token is {key}"}], agent="hr-agent")
    assert e.value.code == "secret_in_input"


def test_history_is_analysed_once_per_message(make_harness):
    eng = CountingEngine()
    h = make_harness(engine=eng)
    turn1 = [{"role": "user", "content": "first question about invoices " * 5}]
    h.request(json.loads(json.dumps(turn1)), agent="coding-agent")
    assert len(eng.analyzed) == 1
    turn2 = turn1 + [{"role": "assistant", "content": "the answer is forty two, roughly"},
                     {"role": "user", "content": "second question about reconciliations"}]
    h.request(json.loads(json.dumps(turn2)), agent="coding-agent")
    # only the two NEW messages went to the engine, in ONE call
    assert len(eng.analyzed) == 2 and "first question" not in eng.analyzed[1]
    h.request(json.loads(json.dumps(turn2)), agent="coding-agent")
    assert len(eng.analyzed) == 2                                   # fully cached: zero engine calls


def test_multiple_new_messages_cost_one_engine_call(make_harness):
    eng = CountingEngine()
    h = make_harness(engine=eng)
    h.request([{"role": "user", "content": f"message number {i} about ledgers"} for i in range(6)], agent="coding-agent")
    assert len(eng.analyzed) == 1


def test_span_does_not_leak_across_joined_messages(make_harness):
    class Straddle(BuiltinEngine):
        async def analyze(self, text, entities, language="en", score_threshold=0.5):
            i = text.index("\n\n")
            return [Span("EMAIL_ADDRESS", i - 3, i + 5, 1.0)]     # a span straddling a message boundary
    h = make_harness(engine=Straddle())
    d, _ = h.request([{"role": "user", "content": "aaaaaaaa"}, {"role": "user", "content": "bbbbbbbb"}], agent="coding-agent")
    assert [m["content"] for m in d["messages"]] == ["aaaaaaaa", "bbbbbbbb"]       # dropped, nothing corrupted


def test_unknown_agent_gets_defaults_and_is_flagged(harness):
    d, out = harness.request([{"role": "user", "content": "mail zed@example.com"}], agent="not-in-policy")
    assert d["messages"][0]["content"] == "mail <EMAIL_ADDRESS>"
    ev = harness.audit.of("guardrail.request")[-1]
    assert ev["known_agent"] is False
    # and it has no tools: least privilege by default
    with pytest.raises(GuardrailBlocked):
        harness.request([{"role": "user", "content": "x"}], agent="not-in-policy",
                        tools=[{"type": "function", "function": {"name": "anything"}}])
