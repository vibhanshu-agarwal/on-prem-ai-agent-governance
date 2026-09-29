"""The signed policy bundle (services/policy, T7) can only TIGHTEN guardrail behaviour, and a bad bundle fails closed."""
import shutil

import pytest

from conftest import ROOT, run
from govguard import GovpolicyOverlay, GuardrailBlocked, PolicyUnavailable
from govpolicy import Ed25519Signer, Ed25519Verifier, PolicyStore


@pytest.fixture
def signed(tmp_path):
    pdir = tmp_path / "policy"
    shutil.copytree(ROOT / "policy", pdir, ignore=shutil.ignore_patterns("trust"))
    trust = tmp_path / "trust"
    signer = Ed25519Signer.generate(tmp_path / "k", trust)
    store = PolicyStore(tmp_path / "store", Ed25519Verifier.from_trust_dir(trust))
    store.activate(store.publish(pdir, signer).version)
    return tmp_path / "store", trust


def test_capabilities_from_the_signed_bundle_remove_tools(make_harness, signed):
    h = make_harness(overlay=GovpolicyOverlay(str(signed[0]), str(signed[1])))
    # coding-agent: yaml allows git_push (external_send) but the signed policy never granted that capability
    pol = h.config.resolve("coding-agent", None)
    assert "git_push" not in pol.tools_allow and {"read_file", "run_tests"} <= pol.tools_allow
    with pytest.raises(GuardrailBlocked) as e:
        h.response(None, [{"name": "git_push", "arguments": "{}", "id": "1"}], agent="coding-agent")
    assert e.value.code == "tool_not_authorized"
    # finance-recon-agent has external_send + calls_tools: its tools survive
    assert {"send_email", "release_payment"} <= h.config.resolve("finance-recon-agent", None).tools_allow


def test_require_human_approval_from_the_bundle_is_enforced(make_harness, signed, raw_config):
    raw_config["defaults"]["approval"]["required_classes"] = []                 # yaml alone would not gate anything
    raw_config["agents"]["hr-agent"]["tools"]["catalog"]["lookup_employee"] = {"action": "employee_record.update"}
    h = make_harness(raw=raw_config, overlay=GovpolicyOverlay(str(signed[0]), str(signed[1])))
    assert "employee_record.update" in h.config.resolve("hr-agent", None).approval_actions
    with pytest.raises(GuardrailBlocked) as e:
        h.response(None, [{"name": "lookup_employee", "arguments": "{}", "id": "1"}], agent="hr-agent")
    assert e.value.code == "pending_approval"


def test_agent_absent_from_the_signed_policy_has_no_tools(make_harness, signed):
    h = make_harness(overlay=GovpolicyOverlay(str(signed[0]), str(signed[1])))
    assert h.config.resolve("ghost-agent", None).tools_allow == frozenset()


def test_tampered_or_missing_bundle_fails_closed(make_harness, signed, tmp_path):
    store_dir, trust = signed
    for f in (store_dir / "bundles").glob("*.bundle.json"):
        f.write_text(f.read_text().replace("hr-agent", "hr-agenT", 1))            # tamper after signing
    h = make_harness(overlay=GovpolicyOverlay(str(store_dir), str(trust)))
    with pytest.raises(PolicyUnavailable):
        h.config.resolve("hr-agent", None)
    with pytest.raises(PolicyUnavailable):                                          # the pipeline surfaces it (hook => 503)
        run(h.pipeline.check_request(h.ctx("hr-agent"), {"messages": []}))
    empty = make_harness(overlay=GovpolicyOverlay(str(tmp_path / "nostore"), str(trust)))
    with pytest.raises(PolicyUnavailable):
        empty.config.resolve("hr-agent", None)
