"""Native library load order: the explicit environment variable wins, then the copy bundled in the wheel, then the system lookup."""
import ctypes
import ctypes.util

import pytest

from atlas_pca import bls12, fhe_seal, fndsa_native, mpc_lwe_ot, pq_backends

CASES = [
    (fhe_seal, "ATLAS_PCA_LIBSEALC", "sealc"),
    (fndsa_native, "ATLAS_PCA_LIBFNDSA", "fndsa"),
    (mpc_lwe_ot, "ATLAS_PCA_LIBLWEOT", "lweot"),
]


@pytest.mark.parametrize("mod,var,sysname", CASES)
def test_env_then_bundled_then_system(mod, var, sysname, monkeypatch):
    tried = []

    def fake_cdll(path, *a, **k):
        tried.append(path)
        raise OSError("probe")

    monkeypatch.setattr(mod.C, "CDLL", fake_cdll)
    monkeypatch.setattr(mod, "bundled", lambda *n: "BUNDLED")
    monkeypatch.setattr(ctypes.util, "find_library", lambda n: "SYSTEM")
    for env, want in (("ENV", "ENV"), (None, "BUNDLED")):
        monkeypatch.setattr(mod, "_lib", None)
        monkeypatch.delenv(var, raising=False)
        if env:
            monkeypatch.setenv(var, env)
        del tried[:]
        with pytest.raises(Exception):
            mod._load()
        assert tried == [want]
    monkeypatch.setattr(mod, "bundled", lambda *n: None)
    monkeypatch.setattr(mod, "_lib", None)
    del tried[:]
    with pytest.raises(Exception):
        mod._load()
    assert tried == ["SYSTEM"]


def test_blst_env_before_bundled(monkeypatch):
    seen = []
    monkeypatch.setattr(bls12, "_lib", None)
    monkeypatch.setattr(bls12, "_bundled", lambda *n: "BUNDLED")
    monkeypatch.setattr(ctypes.util, "find_library", lambda n: "SYSTEM")
    monkeypatch.setenv("PCA_BLST_LIB", "ENV")
    monkeypatch.setattr(bls12.ctypes, "CDLL", lambda n, *a, **k: seen.append(n) or (_ for _ in ()).throw(OSError("probe")))
    with pytest.raises(bls12.Bls12LibraryMissing):
        bls12.lib()
    assert seen[:3] == ["ENV", "BUNDLED", "SYSTEM"]


def test_less_env_before_bundled(monkeypatch):
    monkeypatch.setenv("ATLAS_PCA_LIBLESS", "ENV")
    monkeypatch.setattr(pq_backends, "bundled", lambda *n: "BUNDLED")
    c = pq_backends._less_candidates()
    assert c.index("ENV") < c.index("BUNDLED")
