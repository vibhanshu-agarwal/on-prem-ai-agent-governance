"""govcp: thin governance control plane for AI agents (ports and adapters).

`govcp.domain` holds the business rules and the port interfaces; it imports
nothing environment-specific (no Docker, no LiteLLM, no Postgres).
`govcp.adapters` holds one implementation per port, chosen by config.
"""
__version__ = "0.1.0"
