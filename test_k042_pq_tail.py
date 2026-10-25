"""Kill tests for atlas_pca.pq_backends: the probe receives the loaded library, and the OpenSSL verify asks about its own
key type (the fakes in test_k042_pq_backends ignore these arguments)."""
from atlas_pca import pq_backends as pq
from test_k042_pq_backends import _verify_lib, fresh_state  # noqa: F401 - the autouse fixture


def test_probe_is_given_the_loaded_library(monkeypatch):
    lib = object()
    seen = []
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    monkeypatch.setattr(pq, "_builds", lambda l, kt: seen.append((l, kt)) or True)
    assert pq._openssl_available("SLH-DSA-SHA2-128f") is True
    assert len(seen) == 1 and seen[0][0] is lib and seen[0][1] == "SLH-DSA-SHA2-128f"


def test_openssl_verify_asks_about_its_own_key_type(monkeypatch):
    lib = _verify_lib()
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    asked = []
    monkeypatch.setattr(pq, "_openssl_available", lambda kt: asked.append(kt) or kt == "SLH-DSA-SHA2-128f")
    assert pq._openssl_verify("SLH-DSA-SHA2-128f", b"K" * 32, b"m", b"s") is True
    assert pq._openssl_verify("SLH-DSA-SHA2-256s", b"K" * 64, b"m", b"s") is False
    assert asked == ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-256s"]
