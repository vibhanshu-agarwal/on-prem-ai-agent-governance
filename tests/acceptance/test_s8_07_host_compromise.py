"""S8-07 Host-compromise drill (simplified Docker version).

"Host" = every agent container carrying the label govpilot.host=<drill host>. A simulated escape (a marker the
compromised workload drops, found by the watchdog) triggers, in order:
  1. isolate the host: bulk quarantine by host label (keys blocked, connections cut, containers stopped, pinned)
  2. preserve evidence BEFORE anything is removed: `docker export` of each container filesystem, its logs and its
     `docker inspect`, plus a SHA-256 manifest; the manifest hash is re-verified
  3. rotate secrets: every agent on the host gets a new gateway key, old keys are deleted, tool/DB creds re-issued
  4. rebuild from a clean image: the compromised containers are removed; new ones are created from the image id
     recorded at deploy time (known good), with the new keys; the quarantine is lifted and they work again
An agent on another "host" keeps running throughout (blast radius = the host, not the fleet).
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


@pytest.mark.accept(
    id="S8-07", title="Host-compromise drill",
    criterion="Simulated escape -> host isolation (all its agents denied + stopped), evidence preserved with a "
              "verifiable manifest, secrets rotated (old keys dead), rebuild from the known-good image; other "
              "hosts unaffected",
    simplification="A 'host' is a Docker label on one Docker Desktop VM; no node cordon/drain, no disk/memory "
                   "forensics, no hypervisor-level isolation. Detection is a marker file, not a real EDR/Falco alert.")
def test_host_compromise_drill(alice, drill, record):
    host, other = L.uid("drill-host"), L.uid("drill-host")
    img_id = L.dclient().images.get(L.DRILL_IMAGE).id                     # known-good image, recorded at deploy
    team = L.uid("t8host")
    on_host = []
    for _ in range(2):
        ag = drill.agent(team, credentials=[{"kind": "db", "value": "db-pass-" + L.uid()},
                                            {"kind": "tool", "value": "tool-token-" + L.uid()}])
        c = drill.run(ag, env={"MODEL": "mock-local", "MAX_TOKENS": "2"}, labels={"govpilot.host": host},
                      image=img_id)
        on_host.append((ag, c))
    bystander = drill.agent(L.uid("t8other"))
    bc = drill.run(bystander, env={"MODEL": "mock-local", "MAX_TOKENS": "2"}, labels={"govpilot.host": other})
    for _, c in on_host + [(bystander, bc)]:
        L.wait_for_log(c, r"(TOK|END) ")

    # --- simulated escape: the compromised workload drops a marker; the watchdog finds it
    victim = on_host[0][1]
    victim.exec_run(["sh", "-c", "echo 'escaped: /proc/1/root reachable' > /tmp/ESCAPE_MARKER"])
    t_detect = time.time()
    found = victim.exec_run(["cat", "/tmp/ESCAPE_MARKER"]).exit_code == 0
    assert found
    timings = {}

    # --- 1. isolate the host
    pv = alice.post("/v1/quarantine/preview", {"labels": {"govpilot.host": host}}).json()
    assert sorted(pv["agent_ids"]) == sorted(a["agent"]["agent_id"] for a, _ in on_host)
    act = alice.post("/v1/quarantine/actions", {"preview_id": pv["preview_id"],
                                                "reason": f"acceptance S8-07: escape detected on {host}"}).json()
    assert act["status"] == "executed" and act["report"]["verify"]["ok"], act
    timings["detect_to_isolated_s"] = round(time.time() - t_detect, 2)
    assert all(L.chat(a["gateway_key"]).status_code == 401 for a, _ in on_host)
    assert L.chat(bystander["gateway_key"]).status_code == 200                # other host unaffected
    bc.reload()
    assert bc.status == "running"

    # --- 2. evidence, before anything is removed
    t = time.time()
    import shutil
    shutil.rmtree(L.RESULTS / "evidence", ignore_errors=True)            # keep only the latest drill (~400 MB)
    ev_dir = L.RESULTS / "evidence" / host
    ev_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"host": host, "incident": "simulated escape", "collected_at": time.time(), "files": {}}
    for ag, c in on_host:
        c.reload()
        base = ev_dir / c.name
        with open(f"{base}.fs.tar", "wb") as f:
            for chunk in c.export():
                f.write(chunk)
        (ev_dir / f"{c.name}.log").write_bytes(c.logs(timestamps=True))
        (ev_dir / f"{c.name}.inspect.json").write_text(json.dumps(c.attrs, indent=1, default=str))
        for suffix in (".fs.tar", ".log", ".inspect.json"):
            p = ev_dir / f"{c.name}{suffix}"
            manifest["files"][p.name] = {"sha256": _sha(p), "bytes": p.stat().st_size}
    (ev_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    manifest_sha = _sha(ev_dir / "MANIFEST.json")
    # re-verify: every file still matches, and the marker is inside the exported filesystem
    for name, m in manifest["files"].items():
        assert _sha(ev_dir / name) == m["sha256"]
    import tarfile
    with tarfile.open(ev_dir / f"{victim.name}.fs.tar") as tf:
        assert "tmp/ESCAPE_MARKER" in tf.getnames()
    timings["evidence_s"] = round(time.time() - t, 2)

    # --- 3. rotate every secret of every agent on the host
    t = time.time()
    rotated = {}
    for ag, _ in on_host:
        aid = ag["agent"]["agent_id"]
        r = alice.post(f"/v1/agents/{aid}/rotate-secrets", {"reason": f"host {host} compromised"})
        assert r.status_code == 200, r.text
        rotated[aid] = r.json()
        drill.extra_keys.append(r.json()["key_hash"])
        assert L.chat(ag["gateway_key"]).status_code == 401                   # old key is dead
        assert all(k["result"] == "deleted" for k in r.json()["old_keys"])
        assert len(r.json()["credentials"]) == 2
    timings["rotation_s"] = round(time.time() - t, 2)

    # --- 4. rebuild from the known-good image, then lift the quarantine
    t = time.time()
    for ag, c in on_host:
        assert c.attrs["Image"] == img_id, "running image differs from the known-good one: rebuild from source"
        c.remove(force=True)
    lf = alice.post(f"/v1/quarantine/actions/{act['action_id']}/lift", {"resume_agents": True}).json()
    assert lf["status"] == "lifted", lf
    fresh = []
    for ag, _ in on_host:
        aid = ag["agent"]["agent_id"]
        nc = drill.run({**ag, "gateway_key": rotated[aid]["gateway_key"]},
                       env={"MODEL": "mock-local", "MAX_TOKENS": "2"}, labels={"govpilot.host": host},
                       image=img_id, name=L.uid("t8-rebuilt"))
        fresh.append(nc)
    for nc in fresh:
        L.wait_for_log(nc, r"END ")
        assert nc.exec_run(["test", "-e", "/tmp/ESCAPE_MARKER"]).exit_code != 0   # clean filesystem
    assert all(L.chat(rotated[a["agent"]["agent_id"]]["gateway_key"]).status_code == 200 for a, _ in on_host)
    # the old keys stay dead after the lift + resume (deleted by the rotation, not merely blocked by the quarantine,
    # which the resume would have undone)
    assert all(L.chat(a["gateway_key"]).status_code == 401 for a, _ in on_host), "an old key came back with the resume"
    timings["rebuild_s"] = round(time.time() - t, 2)
    record(agents_on_host=len(on_host), bystander_unaffected=True, evidence_files=len(manifest["files"]),
           evidence_bytes=sum(m["bytes"] for m in manifest["files"].values()), manifest_sha256=manifest_sha,
           evidence_dir=str(ev_dir.relative_to(L.ROOT)), keys_rotated=len(rotated), credentials_reissued=4,
           **timings)
