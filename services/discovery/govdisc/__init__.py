"""Discovery feeds: find AI callers nobody registered and file them in the control plane's pending queue.

Nothing here creates agents, keys or budgets. A feed only *proposes*; the control plane keeps the
proposal at zero budget with no gateway key until a human owner approves it.

Layout (ports first, adapters named only in wiring.py):
  model.py        Observation (what a feed saw)
  ports.py        DiscoveryFeed, ProposalSink, ContainerSource, AccessLogSource, CallRecordSource, ServiceListSource
  feeds/          docker_events, gateway_logs, openlit_controller     (pure logic over the ports)
  adapters/       docker SDK, ClickHouse (OpenLIT), control-plane HTTP, controller REST
  ratelimit.py    per-feed daily budget (client side; the control plane's cap stays authoritative)
  runner.py       poll loop, backlog, state
"""
