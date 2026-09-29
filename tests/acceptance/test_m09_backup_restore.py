"""M-09 Backup/restore test for Postgres (LiteLLM spend/keys DB and the control-plane register + audit DB)."""
from __future__ import annotations

import json
import subprocess
import time

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")


def _psql(container, user, db, q):
    return L.dclient().containers.get(container).exec_run(["psql", "-U", user, "-d", db, "-tA", "-c", q]).output.decode().strip()


@pytest.mark.accept(
    id="M-09", title="Backup and restore (Postgres)",
    criterion="scripts/backup.sh dumps both databases (+ Redis snapshot) with a SHA-256 manifest; scripts/restore.sh "
              "restores them into a scratch Postgres; keys, agents and the audit log match the live system at "
              "backup time and the restored audit hash chain verifies",
    simplification="Restore is proven into a scratch container, not by an in-place disaster recovery of the live "
                   "stack; no point-in-time recovery (WAL archiving), no off-host copy, secrets are out of scope.")
def test_backup_restore(alice, record, tmp_path):
    keys_before = int(_psql("gov-postgres", "litellm", "litellm", 'select count(*) from "LiteLLM_VerificationToken"'))
    logs_before = int(_psql("gov-postgres", "litellm", "litellm", 'select count(*) from "LiteLLM_SpendLogs"'))
    agents_before = int(_psql("gov-cp-postgres", "cp_super", "controlplane",
                              "select count(*) from documents where collection = 'agents'"))
    audit_before = int(_psql("gov-cp-postgres", "cp_super", "controlplane", "select count(*) from audit_log"))
    out = tmp_path / "backup"
    t0 = time.time()
    b = subprocess.run([L.BASH, "scripts/backup.sh", str(out)], cwd=L.ROOT, capture_output=True, text=True, timeout=600)
    assert b.returncode == 0, b.stdout + b.stderr
    backup_s = time.time() - t0
    logs_after = int(_psql("gov-postgres", "litellm", "litellm", 'select count(*) from "LiteLLM_SpendLogs"'))
    t1 = time.time()
    r = subprocess.run([L.BASH, "scripts/restore.sh", str(out), "--keep"], cwd=L.ROOT, capture_output=True, text=True,
                       timeout=600)
    assert r.returncode == 0, r.stdout + r.stderr
    restore_s = time.time() - t1
    js = r.stdout[r.stdout.index("{"):]
    got = json.loads(js)
    try:
        # verify the restored audit hash chain with the control plane's own verifier
        import sys
        sys.path.insert(0, str(L.ROOT / "services" / "control-plane"))
        from psycopg_pool import ConnectionPool
        from govcp.adapters.postgres import PostgresAuditSink
        dsn = f"postgresql://restore:{got['password']}@127.0.0.1:{got['port']}/controlplane"
        with ConnectionPool(dsn, min_size=1, max_size=1, open=True) as pool:
            v = PostgresAuditSink(pool).verify()
    finally:
        L.dclient().containers.get(got["container"]).remove(force=True)
    sizes = {p.name: p.stat().st_size for p in out.iterdir()}
    record(backup_s=round(backup_s, 1), restore_s=round(restore_s, 1), files=sizes,
           keys_live=keys_before, keys_restored=got["litellm_keys"], spend_logs_live_window=[logs_before, logs_after],
           spend_logs_restored=got["litellm_spend_logs"], agents_live=agents_before, agents_restored=got["cp_agents"],
           audit_records_live_before=audit_before, audit_records_restored=got["cp_audit_records"],
           restored_audit_chain_ok=v.ok, restored_audit_chain_count=v.count)
    assert got["litellm_keys"] == keys_before
    assert logs_before <= got["litellm_spend_logs"] <= logs_after
    assert got["cp_agents"] == agents_before
    assert got["cp_audit_records"] >= audit_before and v.ok and v.count == got["cp_audit_records"]
