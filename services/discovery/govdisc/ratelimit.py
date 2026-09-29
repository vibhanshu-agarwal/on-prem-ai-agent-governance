"""Per-feed daily budget on the client side.

The control plane enforces the real cap (429 + audit record). This mirrors it so a noisy feed stops
calling early, does not burn requests against a closed door, and keeps its unsent observations in a
bounded backlog for the next UTC day instead of losing them.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone


def utc_day(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


class DailyBudget:
    def __init__(self, limit: int, clock=time.time, day: str | None = None, used: int = 0):
        self.limit = limit
        self.clock = clock
        self.day = day or utc_day(clock())
        self.used = used
        self.blocked_day: str | None = None      # set when the server said 429

    def _roll(self):
        today = utc_day(self.clock())
        if today != self.day:
            self.day, self.used, self.blocked_day = today, 0, None

    def available(self) -> bool:
        self._roll()
        return self.blocked_day != self.day and self.used < self.limit

    def record(self, n: int = 1):
        self._roll()
        self.used += n

    def block_today(self):
        """The server refused: it holds the authoritative counter."""
        self._roll()
        self.blocked_day = self.day

    def to_state(self) -> dict:
        return {"day": self.day, "used": self.used, "blocked_day": self.blocked_day}

    @classmethod
    def from_state(cls, limit: int, state: dict | None, clock=time.time) -> "DailyBudget":
        b = cls(limit, clock)
        if state and state.get("day") == b.day:
            b.used = int(state.get("used", 0))
            b.blocked_day = state.get("blocked_day")
        return b
