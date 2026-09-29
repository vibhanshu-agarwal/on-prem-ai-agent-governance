"""Generate the provisioned Grafana dashboard `Cost by agent and team` (dashboards/cost-by-agent.json).

Kept as a generator so the SQL is readable and the JSON never has quoting bugs. Data source: the
OpenLIT ClickHouse database (`otel_traces`, spans named `litellm_request` written by LiteLLM's `otel`
callback). Attribution comes straight from the gateway span:
  agent    metadata.user_api_key_auth_metadata.agent_id  (falls back to the key alias)
  team     metadata.user_api_key_team_alias
  cost     gen_ai.cost.total_cost   (LiteLLM's own price calculation, USD)
  run      metadata.requester_metadata.run_id  (T4 attribution adds parent_run_id)

    python deploy/observability/build_dashboard.py
"""
import json
from pathlib import Path

OUT = Path(__file__).parent / "grafana" / "dashboards" / "cost-by-agent.json"
DS = {"type": "grafana-clickhouse-datasource", "uid": "openlit-ch"}

A = "SpanAttributes"
AGENT = (f"coalesce(nullIf(extract({A}['metadata.user_api_key_auth_metadata'], '''agent_id'': ''([^'']+)'''), ''), "
         f"{A}['metadata.user_api_key_alias'])")
TEAM = f"{A}['metadata.user_api_key_team_alias']"
COST = f"toFloat64OrZero({A}['gen_ai.cost.total_cost'])"
TOK = f"toUInt64OrZero({A}['gen_ai.usage.total_tokens'])"
MODEL = f"{A}['gen_ai.request.model']"
RUN = f"extract({A}['metadata.requester_metadata'], '''run_id'': ''([^'']+)''')"
BASE = ("FROM otel_traces WHERE SpanName = 'litellm_request' AND $__timeFilter(Timestamp) "
        f"AND {TEAM} IN ($team) AND {AGENT} IN ($agent)")

_id = [0]


def _p(kind, title, x, y, w, h, sql, fmt, **extra):
    _id[0] += 1
    p = {"id": _id[0], "type": kind, "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "datasource": DS,
         "targets": [{"refId": "A", "datasource": DS, "editorType": "sql", "format": fmt, "rawSql": sql,
                      "queryType": "timeseries" if fmt == 0 else "table"}]}
    p.update(extra)
    return p


def stat(title, x, sql, unit, color, decimals=None):
    d = {"unit": unit, "color": {"mode": "fixed", "fixedColor": color}}
    if decimals is not None:
        d["decimals"] = decimals
    return _p("stat", title, x, 0, 4, 4, sql, 1,
              fieldConfig={"defaults": d, "overrides": []},
              options={"colorMode": "background_solid", "graphMode": "none", "textMode": "value",
                       "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}})


def dashboard():
    panels = [
        stat("Spend", 0, f"SELECT sum({COST}) AS spend {BASE}", "currencyUSD", "#3b82f6", 4),
        stat("Calls", 4, f"SELECT count() AS calls {BASE}", "short", "#8b5cf6"),
        stat("Tokens", 8, f"SELECT sum({TOK}) AS tokens {BASE}", "short", "#14b8a6"),
        stat("Avg cost per call", 12, f"SELECT sum({COST}) / greatest(count(), 1) AS c {BASE}", "currencyUSD",
             "#f59e0b", 6),
        stat("p95 gateway latency", 16, f"SELECT quantile(0.95)(Duration) / 1e9 AS s {BASE}", "s", "#ec4899", 2),
        stat("Errored calls", 20,
             f"SELECT countIf(StatusCode = 'Error') AS e {BASE}", "short", "#ef4444"),
        _p("timeseries", "Spend per agent over time", 0, 4, 16, 9,
           f"SELECT $__timeInterval(Timestamp) AS time, {AGENT} AS agent, sum({COST}) AS spend {BASE} "
           "GROUP BY time, agent ORDER BY time", 0,
           fieldConfig={"defaults": {"unit": "currencyUSD", "decimals": 5, "displayName": "${__field.labels.agent}",
                                     "custom": {"drawStyle": "bars", "fillOpacity": 80, "stacking": {"mode": "normal"},
                                                "lineWidth": 0}}, "overrides": []},
           options={"legend": {"displayMode": "table", "placement": "bottom", "calcs": ["sum"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}}),
        _p("piechart", "Spend by model", 16, 4, 8, 9,
           f"SELECT {MODEL} AS model, sum({COST}) AS spend {BASE} GROUP BY model ORDER BY spend DESC", 1,
           fieldConfig={"defaults": {"unit": "currencyUSD", "decimals": 5}, "overrides": []},
           options={"pieType": "donut", "legend": {"displayMode": "table", "placement": "bottom", "values": ["value", "percent"]},
                    "reduceOptions": {"calcs": ["lastNotNull"], "values": True, "fields": "/^spend$/"}}),
        _p("bargauge", "Spend by team", 0, 13, 8, 8,
           f"SELECT {TEAM} AS team, sum({COST}) AS spend {BASE} GROUP BY team ORDER BY spend DESC", 1,
           fieldConfig={"defaults": {"unit": "currencyUSD", "decimals": 5, "color": {"mode": "continuous-BlPu"}},
                        "overrides": []},
           options={"orientation": "horizontal", "displayMode": "gradient", "showUnfilled": True,
                    "reduceOptions": {"calcs": ["lastNotNull"], "values": True, "fields": "/^spend$/"}}),
        _p("table", "Agent leaderboard", 8, 13, 16, 8,
           f"SELECT {AGENT} AS agent, {TEAM} AS team, count() AS calls, sum({TOK}) AS tokens, "
           f"sum({COST}) AS spend, sum({COST}) / count() AS cost_per_call, "
           f"quantile(0.95)(Duration) / 1e9 AS p95_latency_s, countIf(StatusCode = 'Error') AS errors "
           f"{BASE} GROUP BY agent, team ORDER BY spend DESC", 1,
           fieldConfig={"defaults": {}, "overrides": [
               {"matcher": {"id": "byName", "options": "spend"},
                "properties": [{"id": "unit", "value": "currencyUSD"}, {"id": "decimals", "value": 5},
                               {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "gradient"}}]},
               {"matcher": {"id": "byName", "options": "cost_per_call"},
                "properties": [{"id": "unit", "value": "currencyUSD"}, {"id": "decimals", "value": 6}]},
               {"matcher": {"id": "byName", "options": "p95_latency_s"},
                "properties": [{"id": "unit", "value": "s"}, {"id": "decimals", "value": 3}]}]},
           options={"showHeader": True, "cellHeight": "md"}),
        _p("table", "Most expensive runs (run_id from the agent)", 0, 21, 24, 8,
           f"SELECT {RUN} AS run_id, {AGENT} AS agent, {TEAM} AS team, {MODEL} AS model, count() AS calls, "
           f"sum({TOK}) AS tokens, sum({COST}) AS spend {BASE} AND {RUN} != '' "
           "GROUP BY run_id, agent, team, model ORDER BY spend DESC LIMIT 15", 1,
           fieldConfig={"defaults": {}, "overrides": [
               {"matcher": {"id": "byName", "options": "spend"},
                "properties": [{"id": "unit", "value": "currencyUSD"}, {"id": "decimals", "value": 6}]}]},
           options={"showHeader": True}),
    ]

    def var(name, label, col):
        return {"name": name, "label": label, "type": "query", "datasource": DS, "multi": True, "includeAll": True,
                "allValue": None, "refresh": 2, "sort": 1, "current": {"text": "All", "value": "$__all"},
                "query": {"rawSql": f"SELECT DISTINCT {col} FROM otel_traces WHERE SpanName = 'litellm_request' "
                                    "AND $__timeFilter(Timestamp) ORDER BY 1", "editorType": "sql", "format": 1,
                          "queryType": "table"}}

    return {
        "uid": "govpilot-cost", "title": "Cost by agent and team", "tags": ["govpilot", "cost"],
        "schemaVersion": 39, "version": 1, "editable": False, "timezone": "browser",
        "refresh": "10s", "time": {"from": "now-1h", "to": "now"},
        "description": "Per-agent and per-team AI spend from the gateway's OpenTelemetry spans (OpenLIT ClickHouse).",
        "templating": {"list": [var("team", "Team", TEAM), var("agent", "Agent", AGENT)]},
        "annotations": {"list": []}, "panels": panels,
    }


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(dashboard(), indent=2) + "\n", encoding="utf-8")
    print("wrote", OUT)
