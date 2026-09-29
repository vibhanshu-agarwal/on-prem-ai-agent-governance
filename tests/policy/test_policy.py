import json
import pathlib
import subprocess
import sys

import pytest
import yaml

from govpolicy import (AdmissionRequest, BundleError, Ed25519Signer, Ed25519Verifier, PolicyError,
                       PolicyLoadError, PolicyStore, admit, build_bundle, compile_policy_dir,
                       verify_bundle)
from govpolicy.cli import run
from govpolicy.signing import Signature, SignatureError, Signer, Verifier

ROOT = pathlib.Path(__file__).resolve().parents[2]


def edit(path, fn):
    d = yaml.safe_load(path.read_text())
    fn(d)
    path.write_text(yaml.safe_dump(d))


# ---------------- 1. schema ----------------
def test_repo_policy_is_valid_and_matches_provisioning():
    p = compile_policy_dir(ROOT / "policy")
    prov = json.loads((ROOT / "deploy" / "agents.json").read_text())
    for name, cfg in prov["agents"].items():
        assert set(cfg["models"]) <= set(p.agents[name].models)
        assert cfg["max_budget"] <= p.agents[name].budget.max_usd


def test_policy_queries(policy_dir):
    p = compile_policy_dir(policy_dir)
    assert p.model_allowed("hr-agent", "mock-local")
    assert not p.model_allowed("hr-agent", "mock-remote")
    assert not p.model_allowed("ghost", "mock-local")
    assert p.max_tokens_ceiling("hr-agent") == 512
    assert p.max_tokens_ceiling("ghost") == p.globals.default_max_tokens_ceiling
    assert p.requires_approval("coding-agent", "git.push")
    assert not p.requires_approval("coding-agent", "read.file")
    assert p.requires_approval("ghost", "anything")  # fail closed


def test_unknown_field_rejected(policy_dir):
    edit(policy_dir / "agents" / "hr-agent.yaml", lambda d: d.update(surprise=1))
    with pytest.raises(PolicyError):
        compile_policy_dir(policy_dir)


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d.update(models=["mock-remote"]), "allowlist"),
    (lambda d: d.update(team="nope"), "unknown team"),
    (lambda d: d.update(capabilities=["telepathy"]), "unknown capability"),
    (lambda d: d.update(required_sandbox_tier="metal"), "unknown sandbox tier"),
    (lambda d: d.update(capabilities=["executes_model_code"]), "needs tier"),
    (lambda d: d["budget"].update(max_usd=99), "sum to"),
    (lambda d: d.update(max_tokens_ceiling=0), "max_tokens_ceiling"),
])
def test_invalid_agent_rejected(policy_dir, mutate, needle):
    edit(policy_dir / "agents" / "hr-agent.yaml", mutate)
    with pytest.raises(PolicyError, match=needle):
        compile_policy_dir(policy_dir)


def test_id_must_match_filename(policy_dir):
    edit(policy_dir / "agents" / "hr-agent.yaml", lambda d: d.update(id="other-agent"))
    with pytest.raises(PolicyError, match="must match file name"):
        compile_policy_dir(policy_dir)


def test_json_schema_export():
    from govpolicy.schema import json_schema
    assert "agents" in json_schema()["properties"]


# ---------------- 2. bundles ----------------
def test_build_and_verify_roundtrip(policy_dir, keys):
    signer, trust = keys
    b = build_bundle(policy_dir, signer, seq=1)
    assert b.manifest["effective_version"] == f"v1-{b.manifest['content_hash'][:12]}"
    assert {"git_commit", "created_at", "content_hash"} <= set(b.manifest)
    v = verify_bundle(b.to_json(), Ed25519Verifier.from_trust_dir(trust))
    assert v.policy == b.policy and v.version == b.version


def test_same_content_same_hash_and_content_change_changes_hash(policy_dir, keys):
    a = build_bundle(policy_dir, keys[0], 1)
    b = build_bundle(policy_dir, keys[0], 2)
    assert a.manifest["content_hash"] == b.manifest["content_hash"]
    edit(policy_dir / "teams" / "hr.yaml", lambda d: d.update(models=["mock-local"]) or d["budget"].update(max_usd=6))
    c = build_bundle(policy_dir, keys[0], 3)
    assert c.manifest["content_hash"] != a.manifest["content_hash"]


def test_build_refuses_invalid_policy(policy_dir, keys):
    edit(policy_dir / "agents" / "hr-agent.yaml", lambda d: d.update(team="nope"))
    with pytest.raises(PolicyError):
        build_bundle(policy_dir, keys[0], 1)


def test_unsigned_bundle_rejected(policy_dir, keys):
    verifier = Ed25519Verifier.from_trust_dir(keys[1])
    doc = json.loads(build_bundle(policy_dir, keys[0], 1).to_json())
    del doc["signature"]
    with pytest.raises(BundleError, match="unsigned"):
        verify_bundle(json.dumps(doc), verifier)
    doc["signature"] = None
    with pytest.raises(BundleError):
        verify_bundle(json.dumps(doc), verifier)


def test_tampered_payload_rejected(policy_dir, keys):
    verifier = Ed25519Verifier.from_trust_dir(keys[1])
    doc = json.loads(build_bundle(policy_dir, keys[0], 1).to_json())
    doc["payload"] = doc["payload"].replace('"max_usd":1.0', '"max_usd":1.0e3', 1)
    assert '1.0e3' in doc["payload"]
    with pytest.raises(BundleError, match="signature"):
        verify_bundle(json.dumps(doc), verifier)


def test_wrong_key_rejected(policy_dir, keys, tmp_path):
    verifier = Ed25519Verifier.from_trust_dir(keys[1])
    attacker = Ed25519Signer.generate(tmp_path / "evil.key", tmp_path / "evil-trust")
    with pytest.raises(BundleError, match="not in the trust store"):
        verify_bundle(build_bundle(policy_dir, attacker, 1).to_json(), verifier)


def test_forged_key_id_rejected(policy_dir, keys, tmp_path):
    """Attacker signs, then claims the trusted key_id: signature must not verify."""
    verifier = Ed25519Verifier.from_trust_dir(keys[1])
    attacker = Ed25519Signer.generate(tmp_path / "evil.key", tmp_path / "evil-trust")
    doc = json.loads(build_bundle(policy_dir, attacker, 1).to_json())
    doc["signature"]["key_id"] = keys[0].key_id
    with pytest.raises(BundleError, match="signature"):
        verify_bundle(json.dumps(doc), verifier)


def test_empty_trust_store_rejects_everything(policy_dir, keys, tmp_path):
    empty = Ed25519Verifier.from_trust_dir(tmp_path / "nothing")
    with pytest.raises(BundleError):
        verify_bundle(build_bundle(policy_dir, keys[0], 1).to_json(), empty)


@pytest.mark.parametrize("junk", ["", "not json", "[]", "{}", '{"format":"govpolicy-bundle/1"}',
                                  '{"format":"x","payload":"a","signature":{}}'])
def test_malformed_bundle_rejected(keys, junk):
    with pytest.raises(BundleError):
        verify_bundle(junk, Ed25519Verifier.from_trust_dir(keys[1]))


def test_signed_but_inconsistent_manifest_rejected(policy_dir, keys):
    """Even a correctly signed payload must have a manifest that matches its content."""
    signer, trust = keys
    b = build_bundle(policy_dir, signer, 1)
    inner = json.loads(b.payload)
    inner["manifest"]["content_hash"] = "0" * 64
    payload = json.dumps(inner, sort_keys=True, separators=(",", ":"))
    doc = {"format": "govpolicy-bundle/1", "payload": payload,
           "signature": signer.sign(payload.encode()).to_dict()}
    with pytest.raises(BundleError, match="content hash"):
        verify_bundle(json.dumps(doc), Ed25519Verifier.from_trust_dir(trust))


# ---------------- store / loader (fail closed) ----------------
def test_loader_fails_closed_without_active(store):
    with pytest.raises(PolicyLoadError):
        store.load_active()


def test_load_active_ok(active_store):
    assert "coding-agent" in active_store.load_active().policy.agents


def test_loader_rejects_tampered_stored_bundle(active_store):
    path = active_store.bundles / f"{active_store.active_version()}.bundle.json"
    path.write_text(path.read_text().replace("mock-local", "mock-evil", 1))
    with pytest.raises(PolicyLoadError):
        active_store.load_active()


def test_loader_rejects_bundle_from_wrong_key(active_store, policy_dir, tmp_path):
    evil = Ed25519Signer.generate(tmp_path / "e.key", tmp_path / "e-trust")
    b = build_bundle(policy_dir, evil, 99)
    (active_store.bundles / f"{b.version}.bundle.json").write_text(b.to_json())
    active_store.active_path.write_text(json.dumps({"version": b.version}))
    with pytest.raises(PolicyLoadError):
        active_store.load_active()


def test_activate_refuses_bad_bundle_and_keeps_previous(active_store):
    good = active_store.active_version()
    (active_store.bundles / "v9-aaaaaaaaaaaa.bundle.json").write_text("{}")
    with pytest.raises(PolicyLoadError):
        active_store.activate("v9-aaaaaaaaaaaa")
    assert active_store.active_version() == good


def test_version_path_traversal_rejected(active_store):
    with pytest.raises(PolicyLoadError):
        active_store.get("../../etc/passwd")


@pytest.mark.parametrize("bad", ["v1-abcdef012345\n", 5, None, ["v1-abcdef012345"]])
def test_bad_version_values_fail_closed(active_store, bad):
    with pytest.raises(PolicyLoadError):
        active_store.get(bad)
    active_store.active_path.write_text(json.dumps({"version": bad}))
    with pytest.raises(PolicyLoadError):
        active_store.load_active()


def test_signature_checked_before_payload_is_parsed(keys):
    """An unverifiable payload must fail on the signature, never reach the JSON/schema parser."""
    signer, trust = keys
    forged = {"alg": "ed25519", "key_id": signer.key_id, "value": "AAAA"}
    for payload in ["not json at all", '{"manifest":{},"policy":{}}']:
        doc = {"format": "govpolicy-bundle/1", "payload": payload, "signature": forged}
        with pytest.raises(BundleError, match="signature verification failed"):
            verify_bundle(json.dumps(doc), Ed25519Verifier.from_trust_dir(trust))


def test_unencodable_payload_is_bundle_error(keys):
    raw = '{"format":"govpolicy-bundle/1","payload":"\\ud800","signature":{"alg":"ed25519","key_id":"x","value":"AA=="}}'
    with pytest.raises(BundleError, match="malformed"):
        verify_bundle(raw, Ed25519Verifier.from_trust_dir(keys[1]))


def test_publish_is_idempotent_for_same_content(active_store, policy_dir, keys):
    again = active_store.publish(policy_dir, keys[0])
    assert again.version == active_store.active_version()
    assert len(active_store.versions()) == 1


# ---------------- 3. admission ----------------
@pytest.fixture
def pol(policy_dir):
    return compile_policy_dir(policy_dir)


def test_admit_ok(pol):
    d = admit(pol, AdmissionRequest("coding-agent", "govpilot/coding-agent:1",
                                    ["executes_model_code", "calls_tools"], "microvm"), "v1-x")
    assert d.allowed and d.required_tier == "microvm" and d.policy_version == "v1-x"


def test_admit_stronger_tier_is_fine(pol):
    assert admit(pol, AdmissionRequest("hr-agent", "govpilot/hr-agent:1", ["calls_tools"], "microvm")).allowed


@pytest.mark.parametrize("tier", ["container", "gvisor"])
def test_executes_model_code_needs_microvm(pol, tier):
    d = admit(pol, AdmissionRequest("coding-agent", "govpilot/coding-agent:1", ["executes_model_code"], tier))
    assert not d.allowed
    assert any("weaker than required 'microvm'" in r and "executes_model_code" in r for r in d.reasons)


def test_omitting_declared_capability_does_not_lower_bar(pol):
    d = admit(pol, AdmissionRequest("coding-agent", "govpilot/coding-agent:1", [], "container"))
    assert not d.allowed and d.required_tier == "microvm"


def test_external_send_needs_gvisor(pol):
    req = lambda t: AdmissionRequest("finance-recon-agent", "govpilot/finance-recon-agent:1", ["external_send"], t)
    assert not admit(pol, req("container")).allowed
    assert admit(pol, req("gvisor")).allowed


def test_unknown_agent_rejected(pol):
    d = admit(pol, AdmissionRequest("shadow-agent", "x:1", [], "microvm"))
    assert not d.allowed and "not in the signed policy" in d.reasons[0]


def test_undeclared_and_unknown_capability_rejected(pol):
    d = admit(pol, AdmissionRequest("hr-agent", "govpilot/hr-agent:1", ["executes_model_code", "telepathy"], "microvm"))
    assert not d.allowed
    assert any("not declared" in r for r in d.reasons) and any("unknown to policy" in r for r in d.reasons)


def test_image_and_unknown_tier_rejected(pol):
    d = admit(pol, AdmissionRequest("hr-agent", "evil/miner:latest", ["calls_tools"], "quantum"))
    assert not d.allowed and len(d.reasons) == 2


# ---------------- 4. rollback ----------------
def _publish_change(store, keys, policy_dir, ceiling):
    edit(policy_dir / "agents" / "hr-agent.yaml", lambda d: d.update(max_tokens_ceiling=ceiling))
    b = store.publish(policy_dir, keys[0])
    store.activate(b.version)
    return b


def test_rollback_restores_previous_and_keeps_history(active_store, keys, policy_dir):
    v1 = active_store.active_version()
    v2 = _publish_change(active_store, keys, policy_dir, 100).version
    assert active_store.load_active().policy.max_tokens_ceiling("hr-agent") == 100
    rolled = active_store.rollback(reason="bad change")
    assert rolled.version == v1 and active_store.active_version() == v1
    assert active_store.load_active().policy.max_tokens_ceiling("hr-agent") == 512
    events = [(e["event"], e["version"]) for e in active_store.history()]
    assert events == [("published", v1), ("activate", v1), ("published", v2), ("activate", v2),
                      ("rollback", v1)]
    assert active_store.versions() == [v1, v2]          # nothing deleted
    assert active_store.history()[-1]["previous"] == v2


def test_rollback_to_explicit_version_and_forward_again(active_store, keys, policy_dir):
    v1 = active_store.active_version()
    v2 = _publish_change(active_store, keys, policy_dir, 100).version
    v3 = _publish_change(active_store, keys, policy_dir, 200).version
    assert active_store.rollback(to=v1).version == v1
    assert active_store.activate(v3).version == v3
    assert v2 in active_store.versions()


def test_rollback_without_history_or_unknown_version_fails(active_store):
    with pytest.raises(PolicyLoadError):
        active_store.rollback()
    with pytest.raises(PolicyLoadError):
        active_store.rollback(to="v7-000000000000")


def test_rollback_refuses_tampered_target(active_store, keys, policy_dir):
    v1 = active_store.active_version()
    _publish_change(active_store, keys, policy_dir, 100)
    p = active_store.bundles / f"{v1}.bundle.json"
    p.write_text(p.read_text().replace("mock-local", "mock-evil", 1))
    current = active_store.active_version()
    with pytest.raises(PolicyLoadError):
        active_store.rollback()
    assert active_store.active_version() == current


# ---------------- pluggable Signer/Verifier ----------------
class _Hmac(Signer, Verifier):
    """Toy alternative backend proving the interface is all the bundle code needs."""
    import hmac as _h, hashlib as _hl

    def sign(self, data):
        return Signature("hmac", "k", self._h.new(b"s", data, self._hl.sha256).hexdigest())

    def verify(self, data, sig):
        if sig.alg != "hmac" or not self._h.compare_digest(sig.value, self.sign(data).value):
            raise SignatureError("bad hmac")


def test_pluggable_signer_verifier(policy_dir, tmp_path):
    impl = _Hmac()
    st = PolicyStore(tmp_path / "s", impl)
    b = st.publish(policy_dir, impl)
    st.activate(b.version)
    assert st.load_active().version == b.version
    with pytest.raises(BundleError):  # an ed25519 verifier will not accept it
        verify_bundle(b.to_json(), Ed25519Verifier({}))


# ---------------- CLI ----------------
@pytest.fixture
def cli(tmp_path, keys, policy_dir, capsys):
    base = ["--policy-dir", str(policy_dir), "--store", str(tmp_path / "store"),
            "--key", str(tmp_path / "signing.key"), "--trust-dir", str(keys[1])]

    def call(*args):
        capsys.readouterr()
        code = run(base + list(args))
        return code, capsys.readouterr().out
    return call


def test_cli_flow_admit_and_rollback(cli, policy_dir):
    assert cli("validate")[0] == 0
    code, out = cli("build", "--activate")
    assert code == 0 and json.loads(out)["active"].startswith("v1-")
    ok = cli("admit", "--agent", "coding-agent", "--image", "govpilot/coding-agent:1",
             "--capability", "executes_model_code", "--tier", "microvm")
    assert ok[0] == 0 and "ADMIT" in ok[1]
    bad = cli("admit", "--agent", "coding-agent", "--image", "govpilot/coding-agent:1",
              "--capability", "executes_model_code", "--tier", "container")
    assert bad[0] == 1 and "DENY" in bad[1] and "microvm" in bad[1]
    edit(policy_dir / "agents" / "hr-agent.yaml", lambda d: d.update(max_tokens_ceiling=64))
    cli("build", "--activate")
    assert json.loads(cli("rollback")[1])["rolled_back"] is True
    assert cli("drift", "--agents-json", str(ROOT / "deploy" / "agents.json"))[0] == 0
    assert len(cli("history")[1].strip().splitlines()) == 5


def test_cli_fails_closed_with_no_active_bundle(cli):
    with pytest.raises(PolicyLoadError):
        cli("admit", "--agent", "hr-agent", "--image", "govpilot/hr-agent:1", "--tier", "container")


def test_cli_main_exit_codes_via_subprocess(tmp_path, keys, policy_dir):
    env_args = ["--policy-dir", str(policy_dir), "--store", str(tmp_path / "st"),
                "--key", str(tmp_path / "signing.key"), "--trust-dir", str(keys[1])]

    def go(*a):
        return subprocess.run([sys.executable, "-m", "govpolicy", *env_args, *a], capture_output=True,
                              text=True, cwd=ROOT / "services" / "policy")
    r = go("admit", "--agent", "hr-agent", "--image", "govpilot/hr-agent:1", "--tier", "container")
    assert r.returncode == 2 and "fail closed" in r.stderr
    assert go("build", "--activate").returncode == 0
    r = go("admit", "--agent", "ghost", "--image", "x", "--tier", "microvm")
    assert r.returncode == 1 and "not in the signed policy" in r.stdout
    r = go("admit", "--agent", "hr-agent", "--image", "govpilot/hr-agent:1",
           "--capability", "calls_tools", "--tier", "container")
    assert r.returncode == 0


def test_committed_public_key_matches_trust_format():
    keys = list((ROOT / "policy" / "trust").glob("*.pub.json"))
    assert keys, "run `policyctl keygen` and commit the public key"
    Ed25519Verifier.from_trust_dir(ROOT / "policy" / "trust")
    assert not list(ROOT.glob("policy/**/*.key"))       # private key must never live in policy/
