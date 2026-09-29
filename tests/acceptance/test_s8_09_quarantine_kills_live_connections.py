"""S8-09 Quarantine kills live connections: a long-lived connection opened before the quarantine (a streaming
LLM response, and a simulated exfiltration stream to an outside sink) is terminated when the deny lands."""
from __future__ import annotations

import time

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")

AGENT = r"""
import os, socket, threading, time
def exfil():
    while True:                      # the sink network is attached just after start
        try:
            s = socket.create_connection(("sink", 9100), timeout=10); break
        except Exception:
            time.sleep(0.5)
    print("EXF-CONNECTED", time.time(), flush=True)
    n = 0
    try:
        while True:
            s.sendall(b"x" * 1024); n += 1
            if n % 10 == 0: print("EXF", time.time(), n, flush=True)
            time.sleep(0.1)
    except Exception as e:
        print("EXF-ERR", time.time(), type(e).__name__, flush=True)
threading.Thread(target=exfil, daemon=True).start()
from govcp.tools.sample_agent import main
main()
"""

SINK = r"""
import socket, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 9100)); srv.listen(5)
while True:
    c, a = srv.accept(); print("ACCEPT", time.time(), a[0], flush=True)
    c.settimeout(None)
    try:
        while True:
            b = c.recv(65536)
            if not b: print("CLOSED", time.time(), "fin", flush=True); break
            print("RX", time.time(), len(b), flush=True)
    except Exception as e:
        print("CLOSED", time.time(), type(e).__name__, flush=True)
"""


def _last(logs, tag):
    ts = [float(l.split()[1]) for l in logs.splitlines() if l.startswith(tag + " ")]
    return max(ts) if ts else None


@pytest.mark.accept(
    id="S8-09", title="Quarantine kills live connections",
    criterion="A streaming LLM response and an exfiltration TCP stream, both opened before the quarantine, stop "
              "carrying data when the deny lands; the gateway holds no connection from the agent afterwards",
    simplification="Docker Desktop's kernel has no SOCK_DESTROY (`ss -K`), so the adapter injects TCP resets "
                   "with iptables inside the agent's network namespace and then disconnects it; production would "
                   "use the CNI's policy + conntrack flush (tested per CNI). The sink keeps a half-open socket "
                   "(no FIN reaches it), which is expected with reject-in-the-agent's-namespace.")
def test_quarantine_kills_live_connections(alice, drill, record):
    d = L.dclient()
    net = d.networks.create(L.uid("govpilot_t8_exfil"), driver="bridge", internal=True, labels=L.T8_LABEL)
    try:
        sink = drill.container(L.uid("t8-sink"), image=L.DRILL_IMAGE, network=net.name,
                               command=["python", "-u", "-c", SINK])
        net.disconnect(sink)
        net.connect(sink, aliases=["sink"])
        run = L.uid("q")
        ag = drill.agent(L.uid("t8live"))
        c = drill.run(ag, command=["python", "-u", "-c", AGENT], labels={"t8.q": run})
        net.connect(c)
        L.wait_for_log(c, r"TOK .*\nTOK ")
        assert L.wait_until(lambda: "EXF " in c.logs().decode(), timeout=30), c.logs().decode()[-800:]
        assert L.wait_until(lambda: "RX " in sink.logs().decode(), timeout=10)

        pv = alice.post("/v1/quarantine/preview", {"labels": {"t8.q": run}}).json()
        assert pv["agent_ids"] == [ag["agent"]["agent_id"]]
        t0 = time.time()
        act = alice.post("/v1/quarantine/actions", {"preview_id": pv["preview_id"],
                                                    "reason": "acceptance S8-09: exfiltration stream"}).json()
        assert act["status"] == "executed", act
        rep = act["report"]
        cut = rep["phase_end_wall"]["network"]
        time.sleep(3)
        alogs, slogs = c.logs().decode(), sink.logs().decode()
        tok_after = [t for k, t, _ in L.events(c) if k == "TOK" and t > cut + 0.25]
        rx_last = _last(slogs, "RX")
        net_res = rep["network"]["results"][0]
        assert not tok_after, f"LLM stream kept flowing: {tok_after[:3]}"
        assert rx_last is not None and rx_last <= cut + 0.25, f"exfil bytes after the cut: last {rx_last} > {cut}"
        # the gateway may already have closed the LLM stream itself (budget guard in-flight kill after the key block,
        # T8) before the network phase counted, so connections_before can be 0; none may remain afterwards
        assert net_res["connections_after"] == 0, net_res
        record(llm_tokens_after_cut=len(tok_after), exfil_last_byte_before_cut_s=round(cut - rx_last, 3),
               decision_to_network_cut_s=round(cut - t0, 2), chokepoint_connections_before=net_res["connections_before"],
               chokepoint_connections_after=net_res["connections_after"],
               sink_saw_close="CLOSED" in slogs, agent_saw_exfil_error="EXF-ERR" in alogs)
    finally:
        for x in list(drill.containers):
            try:
                x.remove(force=True)
            except Exception:  # noqa: BLE001
                pass
        drill.containers.clear()
        net.remove()
