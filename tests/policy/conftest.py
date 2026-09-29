import pathlib
import shutil
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "policy"))

from govpolicy import Ed25519Signer, Ed25519Verifier, PolicyStore  # noqa: E402


@pytest.fixture
def policy_dir(tmp_path):
    """A private copy of the real policy/ (minus trust/) that tests may mutate."""
    dst = tmp_path / "policy"
    shutil.copytree(ROOT / "policy", dst, ignore=shutil.ignore_patterns("trust"))
    return dst


@pytest.fixture
def keys(tmp_path):
    """Fresh keypair: private key in tmp, public key in a tmp trust dir."""
    trust = tmp_path / "trust"
    signer = Ed25519Signer.generate(tmp_path / "signing.key", trust)
    return signer, trust


@pytest.fixture
def store(tmp_path, keys):
    return PolicyStore(tmp_path / "store", Ed25519Verifier.from_trust_dir(keys[1]))


@pytest.fixture
def active_store(store, keys, policy_dir):
    b = store.publish(policy_dir, keys[0])
    store.activate(b.version)
    return store
