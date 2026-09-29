"""AuditSink contract (Postgres append-only, JSONL journal, in-memory reference)."""
from __future__ import annotations

import pytest

import cpclient
from cpclient import live_or_skip

from govcp.adapters.jsonl_audit import JsonlAuditSink
from govcp.adapters.memory import MemoryAudit, MemoryRepository
from govcp.domain.audit import GENESIS


def _pg_pool():
    from govcp.adapters.postgres import make_pool
    dsn = (f"postgresql://cp_app:{cpclient.ENV['CP_APP_PASSWORD']}@127.0.0.1:"
           f"{cpclient.ENV.get('CP_PG_PORT', '55432')}/controlplane")
    return make_pool(dsn, max_size=2)


@pytest.fixture(params=["memory", "jsonl", "postgres"])
def sink(request, tmp_path):
    if request.param == "memory":
        yield MemoryAudit()
    elif request.param == "jsonl":
        yield JsonlAuditSink(str(tmp_path / "j.jsonl"))
    else:
        live_or_skip()
        from govcp.adapters.postgres import PostgresAuditSink
        pool = _pg_pool()
        yield PostgresAuditSink(pool)
        pool.close()


def test_append_chains_and_verifies(sink):
    tag = cpclient.uid("aud")
    r1 = sink.append("contract", "contract.one", tag, {"n": 1, "f": 0.1})
    r2 = sink.append("contract", "contract.two", tag, {"n": 2, "nested": {"b": [1, 2]}}, severity="alert")
    assert r2.seq > r1.seq and len(r1.hash) == 64
    assert r1.seq > 1 or r1.prev_hash == GENESIS
    v = sink.verify()
    assert v.ok is True and v.count >= 2, v


def test_list_filters(sink):
    tag = cpclient.uid("aud")
    base = sink.append("contract", "contract.a", tag, {}).seq - 1
    sink.append("contract", "contract.b", tag, {}, severity="alert")
    sink.append("contract", "other.c", tag, {})
    got = sink.list(since_seq=base, target=tag)
    assert [r.action for r in got] == ["contract.a", "contract.b", "other.c"]
    assert [r.action for r in sink.list(since_seq=base, target=tag, action_prefix="contract.")] == \
        ["contract.a", "contract.b"]
    assert [r.action for r in sink.list(since_seq=base, target=tag, severity="alert")] == ["contract.b"]
    assert got[1].details == {} and got[1].severity == "alert"


# ---- Repository (persistence port) contract, same idea ----
@pytest.fixture(params=["memory", "postgres"])
def repo(request):
    if request.param == "memory":
        yield MemoryRepository()
        return
    live_or_skip()
    from govcp.adapters.postgres import PostgresRepository
    pool = _pg_pool()
    yield PostgresRepository(pool)
    pool.close()


def test_repository_contract(repo):
    col, i = "contract-test", cpclient.uid("doc")
    assert repo.get(col, i) is None
    assert repo.insert(col, i, {"n": 1}) is True
    assert repo.insert(col, i, {"n": 99}) is False
    repo.put(col, i, {"n": 2})
    assert repo.get(col, i) == {"n": 2}
    assert repo.update(col, i, lambda d: {**d, "n": d["n"] + 1}) == {"n": 3}
    with pytest.raises(KeyError):
        repo.update(col, cpclient.uid("missing"), lambda d: d)
    assert any(d == {"n": 3} for d in repo.list(col))
    repo.delete(col, i)
    assert repo.get(col, i) is None
