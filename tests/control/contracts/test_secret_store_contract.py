"""SecretStore + CredentialRevoker contracts (file / secret-store adapters, in-memory references)."""
from __future__ import annotations

import pytest

from govcp.adapters.file_secrets import FileSecretStore
from govcp.adapters.memory import MemoryRevoker, MemorySecretStore
from govcp.adapters.secret_revoker import SecretStoreRevoker
from govcp.domain.models import CredentialRef


@pytest.fixture(params=["memory", "file"])
def store(request, tmp_path):
    return MemorySecretStore() if request.param == "memory" else FileSecretStore(str(tmp_path / "s.json"))


def test_put_get_version(store):
    assert store.get("a/b") is None
    s1 = store.put("a/b", "v1", {"owner": "x"})
    s2 = store.put("a/b", "v2")
    assert s1.version == 1 and s2.version == 2
    got = store.get("a/b")
    assert got.value == "v2" and got.revoked is False


def test_revoke_destroys_value(store):
    store.put("creds/x/db", "pw")
    r = store.revoke("creds/x/db")
    assert r.revoked is True and r.value is None
    got = store.get("creds/x/db")
    assert got.revoked is True and got.value is None
    assert store.revoke("nope") is None


def test_list_prefix(store):
    for p in ("gateway-keys/a/1", "gateway-keys/b/1", "creds/a/db"):
        store.put(p, "v")
    assert store.list("gateway-keys/") == ["gateway-keys/a/1", "gateway-keys/b/1"]


@pytest.fixture(params=["memory", "secret_store"])
def revoker(request, tmp_path):
    if request.param == "memory":
        return MemoryRevoker(), None
    st = FileSecretStore(str(tmp_path / "s.json"))
    return SecretStoreRevoker(st), st


def test_revoker_contract(revoker):
    rv, st = revoker
    a, b = CredentialRef("db", "creds/a/db"), CredentialRef("tool", "creds/a/tool")
    if st:
        st.put(a.ref, "pw")
        st.put(b.ref, "tok")
    assert rv.supports("db") and rv.supports("tool") and not rv.supports("x509-unknown-kind")
    assert rv.is_revoked(a) is False
    res = rv.revoke(a)
    assert res.revoked is True and res.ref == a.ref
    assert rv.is_revoked(a) is True
    assert rv.is_revoked(b) is False
