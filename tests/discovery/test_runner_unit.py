"""Rate limit, backlog and persistence behaviour of the runner (no Docker, no network)."""
from __future__ import annotations

import fakes
from govdisc.ratelimit import DailyBudget, utc_day
from govdisc.runner import FeedRunner, Runner


class Clock:
    def __init__(self, t=1_790_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def _runner(feed, sink, limit, clock, backlog_max=200):
    return FeedRunner(feed, sink, DailyBudget(limit, clock), backlog_max)


def test_client_side_cap_stops_a_noisy_feed_before_it_reaches_the_control_plane():
    clock, sink = Clock(), fakes.RecordingSink()
    feed = fakes.ListFeed("noisy", [fakes.obs(i) for i in range(30)])
    r = _runner(feed, sink, 5, clock)
    r.tick()
    assert len(sink.created) == 5 and len(sink.calls) == 5         # not one wasted call past the cap
    assert len(r.backlog) == 25
    r.tick()
    assert len(sink.calls) == 5


def test_server_side_429_is_authoritative_even_when_the_client_limit_is_too_generous():
    clock, sink = Clock(), fakes.RecordingSink(server_limit=3)
    feed = fakes.ListFeed("noisy", [fakes.obs(i) for i in range(10)])
    r = _runner(feed, sink, 50, clock)
    r.tick()
    assert len(sink.created) == 3 and r.stats.rate_limited == 1
    assert len(sink.calls) == 4                                    # exactly one refused attempt, then it stops
    r.tick()
    assert len(sink.calls) == 4 and len(r.backlog) == 7


def test_backlog_is_held_and_resumes_after_utc_midnight():
    clock, sink = Clock(), fakes.RecordingSink()
    feed = fakes.ListFeed("noisy", [fakes.obs(i) for i in range(6)])
    r = _runner(feed, sink, 4, clock)
    r.tick()
    assert len(sink.created) == 4
    day = utc_day(clock.t)
    clock.t += 86_400
    assert utc_day(clock.t) != day
    r.tick()
    assert len(sink.created) == 6 and not r.backlog


def test_backlog_overflow_drops_oldest_and_counts_it():
    clock, sink = Clock(), fakes.RecordingSink()
    feed = fakes.ListFeed("flood", [fakes.obs(i) for i in range(50)])
    r = _runner(feed, sink, 0, clock, backlog_max=10)
    r.tick()
    assert len(r.backlog) == 10 and r.stats.overflow_dropped == 40
    assert r.backlog[0].name == "noisy-40"                         # the newest are kept


def test_duplicates_and_known_agents_do_not_consume_budget():
    clock = Clock()
    sink = fakes.RecordingSink(known_agent_ids={"hr-agent"})
    known = fakes.obs(0)
    known.labels = {"govpilot.agent_id": "hr-agent"}
    feed = fakes.ListFeed("f", [known, fakes.obs(1), fakes.obs(1, fp="container:noisy-1:img"), fakes.obs(2)])
    r = _runner(feed, sink, 2, clock)
    r.tick()
    assert r.stats.known == 1 and r.stats.duplicate == 1 and r.stats.created == 2
    assert not r.backlog


def test_transient_errors_are_retried_and_permanent_rejections_dropped():
    clock, sink = Clock(), fakes.RecordingSink()
    sink.fail_next = 1
    sink.rejected_fps = {"container:noisy-1:img"}
    feed = fakes.ListFeed("f", [fakes.obs(0), fakes.obs(1), fakes.obs(2)])
    r = _runner(feed, sink, 10, clock)
    r.tick()
    assert r.stats.errors == 1 and len(sink.created) == 0 and len(r.backlog) == 3   # kept for retry
    r.tick()
    assert [o.name for o in sink.created] == ["noisy-0", "noisy-2"] and r.stats.rejected == 1 and not r.backlog


def test_a_broken_feed_does_not_stop_the_others():
    class Broken(fakes.ListFeed):
        def observations(self):
            raise RuntimeError("boom")
    clock, sink = Clock(), fakes.RecordingSink()
    good = _runner(fakes.ListFeed("good", [fakes.obs(1)]), sink, 5, clock)
    Runner([_runner(Broken("bad", []), sink, 5, clock), good]).tick()
    assert len(sink.created) == 1


def test_state_survives_a_restart(tmp_path):
    clock, sink = Clock(), fakes.RecordingSink()
    feed = fakes.ListFeed("f", [fakes.obs(i) for i in range(5)])
    feed.seen = {"container:noisy-0:img"}
    r = _runner(feed, sink, 2, clock)
    path = tmp_path / "state.json"
    Runner([r], state_path=str(path), heartbeat_path=str(tmp_path / "hb")).tick()
    import json
    st = json.loads(path.read_text())["f"]
    assert st["budget"]["used"] == 2 and len(st["backlog"]) == 3 and st["seen"] == ["container:noisy-0:img"]
    b = DailyBudget.from_state(2, st["budget"], clock)
    assert not b.available()                                       # a restart does not reset today's budget
    assert (tmp_path / "hb").exists()
