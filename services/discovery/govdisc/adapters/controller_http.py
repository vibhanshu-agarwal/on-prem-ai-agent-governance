"""ServiceListSource over the OpenLIT Controller's local REST API (GET /api/services)."""
from __future__ import annotations

from typing import Any

import httpx

from ..ports import ServiceListSource


class ControllerHttpSource(ServiceListSource):
    def __init__(self, url: str, client: httpx.Client | None = None):
        self.url = url.rstrip("/")
        self.http = client or httpx.Client(timeout=5)

    def services(self) -> list[dict[str, Any]]:
        r = self.http.get(self.url + "/api/services")
        r.raise_for_status()
        return r.json() or []
