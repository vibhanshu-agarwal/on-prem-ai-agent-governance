"""HTTP port. One stdlib adapter; tests inject a fake."""
from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol


class TransportError(Exception):
    """Connection-level failure (refused, reset, timeout): no HTTP status exists."""


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)   # lower-cased names
    body: bytes = b""


class Transport(Protocol):
    def send(self, method: str, url: str, headers: dict[str, str], body: bytes | None,
             timeout: float) -> HttpResponse: ...


class UrllibTransport:
    def send(self, method, url, headers, body, timeout):
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return HttpResponse(r.status, {k.lower(): v for k, v in r.headers.items()}, r.read())
        except urllib.error.HTTPError as e:
            return HttpResponse(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read() or b"")
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
            raise TransportError(f"{type(e).__name__}: {e}") from None
