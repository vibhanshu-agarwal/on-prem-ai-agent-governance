"""Contract suites: every adapter of a port must pass the same tests.

Each port's fixture is parametrised over its adapters: the in-memory reference
adapter (always runs) and the production adapter (needs the live stack; skipped
otherwise). A sponsor writing a new adapter (Kubernetes, Vault, Keycloak, a SIEM)
adds one more param to the fixture and runs the same suite.
"""
