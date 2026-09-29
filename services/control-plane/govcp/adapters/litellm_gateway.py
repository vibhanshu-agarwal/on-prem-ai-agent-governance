"""GatewayAdmin adapter for the LiteLLM OSS proxy admin API (v1.100.x).

Uses only open-source endpoints: /key/generate, /key/block, /key/unblock,
/key/info, /key/list, /key/delete, /team/new, /team/list, /v1/models.
"""
from __future__ import annotations

import threading
import time

import httpx

from ..domain.errors import AdapterError
from ..domain.models import IssuedKey, KeyStatus
from ..domain.ports import GatewayAdmin


class LiteLLMGatewayAdmin(GatewayAdmin):
    def __init__(self, url: str, master_key: str, timeout_s: float = 10.0):
        self.url = url.rstrip("/")
        self._h = {"Authorization": f"Bearer {master_key}"}
        self._c = httpx.Client(base_url=self.url, timeout=timeout_s)
        self._teams: dict[str, str] = {}
        self._lock = threading.Lock()

    def _req(self, method, path, **kw):
        try:
            r = self._c.request(method, path, headers=self._h, **kw)
        except httpx.HTTPError as e:
            raise AdapterError(f"gateway unreachable: {e}") from None
        return r

    def _ok(self, r: httpx.Response):
        if r.status_code >= 400:
            raise AdapterError(f"gateway {r.request.method} {r.request.url.path} -> {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else {}

    def health(self):
        try:
            return self._c.get("/health/liveliness", timeout=3).status_code == 200
        except httpx.HTTPError:
            return False

    # ---- teams -------------------------------------------------------------
    def _team_list(self):
        data = self._ok(self._req("GET", "/team/list"))
        return data if isinstance(data, list) else data.get("teams", [])

    def ensure_team(self, team, max_budget_usd=None):
        with self._lock:
            if team in self._teams:
                return self._teams[team]
            for t in self._team_list():
                if t.get("team_alias") == team:
                    self._teams[team] = t["team_id"]
                    return t["team_id"]
            body = {"team_alias": team, "metadata": {"team": team, "governed_by": "govcp"}}
            if max_budget_usd is not None:
                body["max_budget"] = max_budget_usd
            tid = self._ok(self._req("POST", "/team/new", json=body))["team_id"]
            self._teams[team] = tid
            return tid

    def _team_id(self, team):
        with self._lock:
            if team in self._teams:
                return self._teams[team]
        for t in self._team_list():
            if t.get("team_alias") == team:
                with self._lock:
                    self._teams[team] = t["team_id"]
                return t["team_id"]
        return None

    # ---- keys --------------------------------------------------------------
    def create_key(self, alias, team, models, max_budget_usd, metadata, blocked=False, budget_duration=None):
        body = {"key_alias": alias, "models": list(models), "max_budget": max_budget_usd,
                "metadata": {k: v for k, v in metadata.items() if v is not None}, "blocked": bool(blocked)}
        if team:
            body["team_id"] = self.ensure_team(team)
        if budget_duration:
            body["budget_duration"] = budget_duration
        d = self._ok(self._req("POST", "/key/generate", json=body))
        return IssuedKey(key_hash=d["token"], raw_key=d["key"], alias=alias)

    def block_key(self, key_hash):
        self._ok(self._req("POST", "/key/block", json={"key": key_hash}))

    def unblock_key(self, key_hash):
        self._ok(self._req("POST", "/key/unblock", json={"key": key_hash}))

    @staticmethod
    def _status(k: dict) -> KeyStatus:
        return KeyStatus(key_hash=k.get("token"), alias=k.get("key_alias"), blocked=bool(k.get("blocked")),
                         team_id=k.get("team_id"), models=k.get("models") or [], max_budget=k.get("max_budget"),
                         spend=float(k.get("spend") or 0.0), metadata=k.get("metadata") or {})

    def key_status(self, key_hash):
        r = self._req("GET", "/key/info", params={"key": key_hash})
        if r.status_code == 404:
            return None
        info = self._ok(r).get("info") or {}
        info.setdefault("token", key_hash)
        return self._status(info)

    def _list(self, **params):
        out, page = [], 1
        while True:
            d = self._ok(self._req("GET", "/key/list", params={**params, "return_full_object": "true",
                                                                 "page": page, "size": 100}))
            out.extend(k for k in d.get("keys", []) if isinstance(k, dict))
            if page >= int(d.get("total_pages") or 1):
                return out
            page += 1

    def find_keys(self, alias=None, team=None, agent_id=None):
        params = {}
        if alias:
            params["key_alias"] = alias
        if team:
            tid = self._team_id(team)
            if tid is None:
                return []
            params["team_id"] = tid
        keys = self._list(**params)
        if agent_id:
            keys = [k for k in keys if agent_id in ((k.get("metadata") or {}).get("agent_id"),
                                                    (k.get("metadata") or {}).get("root_agent_id"))
                    or k.get("key_alias") == agent_id]
        return [self._status(k) for k in keys]

    def delete_key(self, key_hash):
        r = self._req("POST", "/key/delete", json={"keys": [key_hash]})
        if r.status_code not in (200, 404):
            self._ok(r)

    def probe(self, raw_key):
        try:
            r = self._c.get("/v1/models", headers={"Authorization": f"Bearer {raw_key}"}, timeout=5)
        except httpx.HTTPError as e:
            raise AdapterError(f"gateway unreachable: {e}") from None
        if r.status_code in (401, 403):
            return False
        if r.status_code == 200:
            return True
        raise AdapterError(f"unexpected probe status {r.status_code}")


def wait_ready(url: str, timeout_s: float = 120) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if httpx.get(url.rstrip("/") + "/health/readiness", timeout=3).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return False
