"""M-06 Policy changes use Git PR approval, immutable diffs, effective versions and rollback.

Runs the real policyctl against a scratch Git repository (a copy of policy/): a change is committed with a
review trailer (stand-in for a merged, approved PR), built into a signed bundle, activated; a bad change follows,
is activated, detected and rolled back. The repository's own policy store is not touched.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

import acclib as L


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout.strip()


def _ctl(repo, store, *a):
    env = {**os.environ, "PYTHONPATH": str(L.ROOT / "services" / "policy"), "POLICY_DIR": str(repo / "policy"),
           "POLICY_STORE": str(store), "POLICY_TRUST_DIR": str(L.ROOT / "policy" / "trust"),
           "POLICY_SIGNING_KEY": str(L.ROOT / ".local" / "policy" / "signing.key")}
    return subprocess.run([sys.executable, "-c", "from govpolicy.cli import main; main()", *a], capture_output=True,
                          text=True, env=env, timeout=60)


@pytest.mark.accept(
    id="M-06", title="Policy: Git approval, immutable diffs, effective versions, rollback",
    criterion="Each activated bundle names the reviewed commit (clean tree) and a content-hash effective version; "
              "a dirty tree is flagged; a tampered bundle is refused; rollback re-verifies and restores the "
              "previous version; history is append-only",
    simplification="Approval = a commit with a Reviewed-by trailer in a scratch repo (no Git server, PR or branch "
                   "protection); CODEOWNERS uses placeholder handles; nothing proves the signer built from the "
                   "reviewed commit beyond the recorded hash.")
def test_policy_git_and_rollback(record, tmp_path):
    if not (L.ROOT / ".local" / "policy" / "signing.key").exists():
        pytest.skip("no policy signing key (.local/policy/signing.key)")
    repo, store = tmp_path / "repo", tmp_path / "store"
    shutil.copytree(L.ROOT / "policy", repo / "policy")
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "t8@example.invalid")
    _git(repo, "config", "user.name", "t8 acceptance")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "policy baseline\n\nReviewed-by: carol (hr owner)")
    b1 = json.loads(_ctl(repo, store, "build", "--activate").stdout)
    c1 = _git(repo, "rev-parse", "HEAD")
    assert b1["manifest"]["git_commit"] == c1 and b1["manifest"]["git_dirty"] is False

    # an approved change: lower the HR budget
    p = repo / "policy" / "agents" / "hr-agent.yaml"
    p.write_text(p.read_text().replace("max_usd: 1.0", "max_usd: 0.5"), encoding="utf-8")
    # built from an uncommitted tree: flagged. (Separate store on purpose: the store de-duplicates by content, so
    # a dirty build published first would be reused for the identical committed content and keep git_dirty=true;
    # the release job must therefore build from clean checkouts only.)
    dirty = json.loads(_ctl(repo, tmp_path / "scratch-store", "build").stdout)
    assert dirty["manifest"]["git_dirty"] is True
    _git(repo, "commit", "-q", "-am", "hr-agent: budget 1.0 -> 0.5\n\nReviewed-by: alice (secops)")
    c2 = _git(repo, "rev-parse", "HEAD")
    diff = _git(repo, "show", "--stat", "--format=%H %s", c2)
    b2 = json.loads(_ctl(repo, store, "build", "--activate").stdout)
    assert b2["active"] == b2["published"] and b2["manifest"]["git_commit"] == c2
    assert b2["manifest"]["content_hash"] != b1["manifest"]["content_hash"]
    status = json.loads(_ctl(repo, store, "status").stdout)
    assert status["active"] == b2["published"]

    # tamper with the active bundle on disk: refused, fail closed
    bf = next((store / "bundles").glob(f"{b2['published']}*"))
    orig = bf.read_bytes()
    bf.write_bytes(orig.replace(b"0.5", b"9.5", 1))
    tampered = _ctl(repo, store, "status")
    assert tampered.returncode == 2
    bf.write_bytes(orig)

    # rollback to the previous approved version
    rb = _ctl(repo, store, "rollback", "--reason", "acceptance M-06: budget change broke month-end")
    assert rb.returncode == 0, rb.stderr
    back = json.loads(_ctl(repo, store, "status").stdout)
    assert back["active"] == b1["published"]
    hist = [json.loads(l) for l in _ctl(repo, store, "history").stdout.splitlines() if l.strip()]
    events = [h["event"] for h in hist]
    record(v1=b1["published"], v1_commit=c1[:12], v2=b2["published"], v2_commit=c2[:12],
           dirty_build_flagged=True, tampered_status_exit=tampered.returncode, rolled_back_to=back["active"],
           history_events=events, change_stat=diff.splitlines()[-1] if diff else "",
           codeowners_present=(L.ROOT / "policy" / "CODEOWNERS").exists())
    assert events.count("activate") >= 2 and "rollback" in " ".join(events)
