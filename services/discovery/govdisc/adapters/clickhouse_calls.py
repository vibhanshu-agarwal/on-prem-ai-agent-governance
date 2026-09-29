"""CallRecordSource over OpenLIT's ClickHouse (spans written by LiteLLM's `otel` callback).

Read-only: SELECT on otel_traces through the HTTP interface. Needs no gateway admin credential.
Gateway span attributes used (see deploy/observability/build_dashboard.py for the same mapping):
  metadata.user_api_key_hash / _alias / _team_alias / _auth_metadata (agent_id, owner), gen_ai.cost.total_cost
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

from ..model import CallSummary
from ..ports import CallRecordSource

A = "SpanAttributes"
_AUTH_MD = f"{A}['metadata.user_api_key_auth_metadata']"


def _md(key: str) -> str:
    return f"extract({_AUTH_MD}, '''{key}'': ''([^'']*)''')"


QUERY = f"""
SELECT {A}['metadata.user_api_key_hash'] AS key_hash,
       any({A}['metadata.user_api_key_alias']) AS key_alias,
       any({A}['metadata.user_api_key_team_alias']) AS team,
       any({_md('agent_id')}) AS agent_id,
       any({_md('owner')}) AS owner,
       count() AS calls,
       sum(toFloat64OrZero({A}['gen_ai.cost.total_cost'])) AS spend,
       groupUniqArray({A}['gen_ai.request.model']) AS models,
       toString(min(Timestamp)) AS first_seen,
       toString(max(Timestamp)) AS last_seen
FROM otel_traces
WHERE SpanName = 'litellm_request' AND Timestamp >= toDateTime64(%(since)s, 3, 'UTC')
  AND {A}['metadata.user_api_key_hash'] != ''
GROUP BY key_hash
FORMAT JSONEachRow
"""


class ClickHouseCallSource(CallRecordSource):
    def __init__(self, url: str, user: str, password: str, database: str = "openlit", client: httpx.Client | None = None):
        self.url, self.user, self.password, self.db = url.rstrip("/"), user, password, database
        self.http = client or httpx.Client(timeout=15)

    def calls_since(self, since: float) -> list[CallSummary]:
        ts = datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        r = self.http.post(self.url + "/", params={"database": self.db, "param_since": ts},
                           auth=(self.user, self.password),
                           content=QUERY.replace("%(since)s", "{since:String}"))
        r.raise_for_status()
        out = []
        for line in r.text.splitlines():
            d = json.loads(line)
            out.append(CallSummary(key_hash=d["key_hash"], key_alias=d["key_alias"], team=d["team"],
                                   agent_id=d["agent_id"], owner=d["owner"], calls=int(d["calls"]),
                                   spend_usd=float(d["spend"]), models=sorted(d["models"]),
                                   first_seen=d["first_seen"], last_seen=d["last_seen"]))
        return out
