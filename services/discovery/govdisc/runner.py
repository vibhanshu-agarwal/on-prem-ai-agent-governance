"""Poll loop: feed -> (daily budget, backlog) -> sink.

Behaviour per feed per tick:
  1. pull new observations from the feed and append them to a bounded backlog;
  2. while the feed still has budget today, submit from the backlog (oldest first);
       created      -> count against today's budget
       duplicate    -> already queued: free, drop
       known        -> a registered agent's own workload: free, drop
       rate_limited -> the control plane's counter is authoritative: stop for the day, keep the item
       error        -> transient (network/5xx): keep the item, retry next tick
       rejected     -> permanent (4xx): drop and log
  3. observations that did not fit stay in the backlog for the next UTC day; a backlog that overflows
     drops its OLDEST entries and counts them (a flood cannot grow memory or the queue without bound).
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .model import Observation
from .ports import DiscoveryFeed, ProposalSink
from .ratelimit import DailyBudget

log = logging.getLogger("govdisc.runner")


@dataclass
class FeedStats:
    created: int = 0
    duplicate: int = 0
    known: int = 0
    rate_limited: int = 0
    rejected: int = 0
    errors: int = 0
    overflow_dropped: int = 0
    last_error: str = ""


class FeedRunner:
    def __init__(self, feed: DiscoveryFeed, sink: ProposalSink, budget: DailyBudget, backlog_max: int = 200):
        self.feed, self.sink, self.budget = feed, sink, budget
        self.backlog: deque[Observation] = deque()
        self.backlog_max = backlog_max
        self.stats = FeedStats()

    def tick(self) -> int:
        """One poll. Returns the number of proposals created."""
        try:
            new = list(self.feed.observations())
        except Exception as e:  # a broken feed must not stop the others
            log.warning("feed %s failed: %s", self.feed.name, e)
            self.stats.last_error = str(e)
            new = []
        for o in new:
            self.backlog.append(o)
        while len(self.backlog) > self.backlog_max:
            dropped = self.backlog.popleft()
            self.stats.overflow_dropped += 1
            log.warning("feed %s backlog full: dropped %s", self.feed.name, dropped.fingerprint)
        created = 0
        while self.backlog and self.budget.available():
            o = self.backlog[0]
            r = self.sink.submit(self.feed.name, o)
            if r.status == "created":
                self.budget.record()
                self.stats.created += 1
                created += 1
                log.info("feed %s proposed %s (%s)", self.feed.name, o.fingerprint, r.proposal_id)
            elif r.status == "duplicate":
                self.stats.duplicate += 1
            elif r.status == "known":
                self.stats.known += 1
            elif r.status == "rate_limited":
                self.stats.rate_limited += 1
                self.budget.block_today()
                log.warning("feed %s hit the control plane's daily limit; holding %d observation(s) until tomorrow",
                            self.feed.name, len(self.backlog))
                break
            elif r.status == "rejected":
                self.stats.rejected += 1
                log.warning("feed %s: proposal %s rejected: %s", self.feed.name, o.fingerprint, r.detail)
            else:
                self.stats.errors += 1
                self.stats.last_error = r.detail
                log.warning("feed %s: submit failed (will retry): %s", self.feed.name, r.detail)
                break
            self.backlog.popleft()
        if self.backlog and not self.budget.available():
            log.info("feed %s: %d observation(s) waiting for tomorrow's budget", self.feed.name, len(self.backlog))
        return created

    # ---- persistence (budget, seen fingerprints, backlog) so a restart neither loses nor re-files things
    def state(self) -> dict:
        seen = getattr(self.feed, "seen", set())
        return {"budget": self.budget.to_state(), "seen": sorted(seen),
                "backlog": [o.to_payload() for o in self.backlog]}


class Runner:
    def __init__(self, runners: list[FeedRunner], interval_s: float = 5.0, state_path: str | None = None,
                 heartbeat_path: str | None = None):
        self.runners = runners
        self.interval = interval_s
        self.state_path = state_path
        self.heartbeat_path = heartbeat_path
        self._stop = False

    def stop(self):
        self._stop = True

    def tick(self):
        for r in self.runners:
            r.tick()
        self._save()

    def _save(self):
        if self.state_path:
            p = Path(self.state_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps({r.feed.name: r.state() for r in self.runners}), encoding="utf-8")
            os.replace(tmp, p)
        if self.heartbeat_path:
            Path(self.heartbeat_path).parent.mkdir(parents=True, exist_ok=True)
            Path(self.heartbeat_path).write_text(str(time.time()))

    def run_forever(self):
        log.info("discovery runner started: feeds=%s interval=%ss", [r.feed.name for r in self.runners], self.interval)
        while not self._stop:
            t0 = time.time()
            try:
                self.tick()
            except Exception:
                log.exception("tick failed")
            time.sleep(max(0.2, self.interval - (time.time() - t0)))


def load_state(path: str | None) -> dict:
    if not path or not Path(path).exists():
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
