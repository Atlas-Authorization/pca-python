"""Direct unit tests for helpers the corpus only reaches indirectly (mutation-kill)."""
import builtins
import math
import sys

import pytest

from atlas_pca import mldsa
from atlas_pca.pca import (
    MAX_SAFE, _is_safe_int, _path_shape, _plain, _plan_leaf, _split, decode_b64u_strict, b64u, merkle_root,
    verify_artifact_suite, verify_inclusion,
)
from test_conformance import DOC


def test_is_safe_int():
    f = _is_safe_int
    assert f(0) and f(0.0) and f(5.0) and f(-1.0) and f(-5.0) and f(MAX_SAFE) and f(-MAX_SAFE) and f(float(MAX_SAFE)) and f(-float(MAX_SAFE))
    assert not f(MAX_SAFE + 1) and not f(-MAX_SAFE - 1) and not f(float(MAX_SAFE + 1))
    assert not f(-0.0) and not f(2.5) and not f(float("nan")) and not f(float("inf")) and not f(1e300)
    assert not f(True) and not f(False) and not f("1") and not f(None)
    assert f(1.0) and f(-2.0)


def test_plain_formats():
    assert _plain(1e-6) == "0.000001"
    assert _plain(1e21) == "1000000000000000000000"
    assert _plain(1.5e-5) == "0.000015"
    assert _plain(1.5) == "1.5"
    assert _plain(123456789012345680000.0) == "123456789012345680000"
    assert _plain(-2.5e-5) == "-0.000025"
    assert _plain(1e22) == "10000000000000000000000"


def test_merkle_and_shape():
    with pytest.raises(ValueError, match="^merkle_root: empty leaf set$"):
        merkle_root([])
    assert [_split(n) for n in (2, 3, 4, 5, 8, 9)] == [1, 2, 2, 4, 4, 8]
    assert _path_shape(0, 1) == []
    assert _path_shape(0, 2) == ["R"] and _path_shape(1, 2) == ["L"]
    assert _path_shape(2, 3) == ["L"] and _path_shape(4, 5) == ["L"] and _path_shape(3, 5) == ["L", "L", "R"]


def _tree(n):
    leaves = [{"i": i} for i in range(n)]
    return leaves, merkle_root(leaves)


def _proofs():
    for m in DOC["primitives"]["merkle"]:
        for i, pr in enumerate(m["proofs"]):
            yield m, i, pr


def test_verify_inclusion_rejections():
    m, i, pr = next((m, i, pr) for m, i, pr in _proofs() if pr["size"] >= 2)
    leaf, root = m["leaves"][i], m["root"]
    assert verify_inclusion(root, pr, leaf)
    bad = lambda **kw: verify_inclusion(root, {**pr, **kw}, leaf)
    assert not verify_inclusion(root, "x", leaf) and not verify_inclusion(root, None, leaf)
    assert not verify_inclusion(root, {k: v for k, v in pr.items() if k != "path"}, leaf)
    assert not bad(path="x") and not bad(path={}) and not bad(path=None)
    assert not bad(index=pr["index"] + 0.5) and not bad(size=pr["size"] + 0.5) and not bad(index="1") and not bad(size=None)
    assert not bad(index=-1) and not bad(index=pr["size"]) and not bad(size=0) and not bad(size=-1)
    assert not bad(path=pr["path"][:-1]) and not bad(path=pr["path"] + pr["path"][:1])
    assert not verify_inclusion(root + "A", pr, leaf) and not verify_inclusion(root, pr, {"other": 1})
    flipped = [dict(s, side=("R" if s["side"] == "L" else "L")) for s in pr["path"]]
    assert not bad(path=flipped)
    assert not bad(path=[dict(pr["path"][0], hash=pr["path"][0]["hash"][:-2])] + pr["path"][1:])
    assert not bad(path=[dict(pr["path"][0], hash=None)] + pr["path"][1:])
    assert not bad(path=["x"] + pr["path"][1:])
    # single-leaf trees: only index 0 / size 1 with an empty path; index == size, size 0 and a non-list empty path are refused
    leaves, r1 = _tree(1)
    ok1 = {"index": 0, "size": 1, "path": []}
    assert verify_inclusion(r1, ok1, leaves[0])
    for kw in ({"index": 1}, {"size": 0}, {"index": 0, "size": 0}, {"path": ""}, {"path": {}}, {"index": 1, "size": 1}):
        assert not verify_inclusion(r1, {**ok1, **kw}, leaves[0]), kw
    assert not verify_inclusion(r1, {"index": 0, "size": 1, "path": ""}, leaves[0])
    assert not verify_inclusion(r1, {"index": 0, "size": 1}, leaves[0])


def test_plan_leaf_defaults_and_error():
    with pytest.raises(ValueError, match="^missing node_id$"):
        _plan_leaf(None, {"verb": "v", "resource": "r"}, "c")
    from atlas_pca.pca import DEFAULT_REVERSIBILITY_CLASS, EMPTY_PARAMS_DIGEST
    d = _plan_leaf("n", {"verb": "v", "resource": "r"}, "c")
    assert d["params_digest"] == EMPTY_PARAMS_DIGEST and d["reversibility_class"] == DEFAULT_REVERSIBILITY_CLASS
    e = _plan_leaf("n", {"verb": "v", "resource": "r", "params_digest": "PD", "reversibility_class": "RC"}, "c")
    assert e["params_digest"] == "PD" and e["reversibility_class"] == "RC"


def test_mldsa_guards(monkeypatch):
    assert mldsa.ml_dsa65_available() is (mldsa._ML_DSA_65 is not None)
    pk, sg = b"\0" * mldsa.ML_DSA_65_PUBLIC_KEY_BYTES, b"\0" * mldsa.ML_DSA_65_SIGNATURE_BYTES
    assert mldsa.ml_dsa65_verify(pk, b"m", sg) is False
    assert mldsa.ml_dsa65_verify(pk[:-1], b"m", sg) is False and mldsa.ml_dsa65_verify(pk, b"m", sg[:-1]) is False
    assert mldsa.ml_dsa65_verify(pk[:-1], b"m", sg[:-1]) is False and mldsa.ml_dsa65_verify(pk + b"\0", b"m", sg) is False
    monkeypatch.setattr(mldsa, "_ML_DSA_65", None)
    assert mldsa.ml_dsa65_available() is False and mldsa.ml_dsa65_verify(pk, b"m", sg) is False

    class Raises:
        @staticmethod
        def verify(*a):
            raise RuntimeError

    monkeypatch.setattr(mldsa, "_ML_DSA_65", Raises)
    assert mldsa.ml_dsa65_verify(pk, b"m", sg) is False

    class Yes:
        @staticmethod
        def verify(*a):
            return 1

    monkeypatch.setattr(mldsa, "_ML_DSA_65", Yes)
    assert mldsa.ml_dsa65_verify(pk, b"m", sg) is True
    assert mldsa.ml_dsa65_verify(pk[:-1], b"m", sg) is False


def test_artifact_suite_rejections():
    assert verify_artifact_suite("x") is False and verify_artifact_suite({}) is False
    assert verify_artifact_suite({"message": "!!"}) is False
    arts = DOC["primitives"]["pq_artifact"]
    for a in arts:
        if a.get("alg", "ed25519") == "ed25519":
            assert verify_artifact_suite(a) == a["valid"]
            assert verify_artifact_suite({**a, "message": b64u(b"tampered")}) is False
            assert verify_artifact_suite({k: v for k, v in a.items() if k != "message"}) is False


def test_import_error_messages(monkeypatch):
    import importlib
    real = builtins.__import__

    def deny(name, *a, **k):
        if name.split(".")[0] in ("django", "fastapi", "starlette"):
            raise ImportError(name)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", deny)
    from atlas_pca.django import PCAMiddleware
    with pytest.raises(ImportError) as e:
        PCAMiddleware(lambda r: None)
    assert str(e.value) == "atlas_pca.django requires Django. Install with: pip install 'atlas-pca[django]'"
    from atlas_pca.fastapi import RequirePCA
    with pytest.raises(ImportError) as e:
        RequirePCA(audience="a", resolve_grant=lambda r: None)
    assert str(e.value) == "atlas_pca.fastapi requires FastAPI. Install with: pip install 'atlas-pca[fastapi]'"
    _ = importlib


def test_response_header_names_and_403_pcactn():
    from test_server import PCACTN, AUD, _guard, _header_value
    r = _guard(audience="zzz")({"PCA-Action": _header_value(PCACTN)}, None)
    assert r.status == 403 and r.pcactn == PCACTN
    pytest.importorskip("django")
    from test_server_exact import _django
    settings = _django()
    from test_server import NOW, _resolver
    from django.test import RequestFactory
    from atlas_pca.django import PCAMiddleware
    settings.PCA_AUDIENCE = "zzz"
    settings.PCA_RESOLVE_GRANT = _resolver
    settings.PCA_NOW = NOW
    resp = PCAMiddleware(lambda r: None)(RequestFactory().post("/x", HTTP_PCA_ACTION=_header_value(PCACTN)))
    assert "WWW-Authenticate" in [k for k, _ in resp.items()]
    pytest.importorskip("fastapi")
    import asyncio
    from fastapi import HTTPException
    from atlas_pca.fastapi import RequirePCA

    class Req:
        headers = {}

        async def body(self):
            return b""

        class state:  # noqa: N801
            pass

    with pytest.raises(HTTPException) as ei:
        asyncio.run(RequirePCA(audience=AUD, resolve_grant=_resolver, now=NOW)(Req()))
    assert list(ei.value.headers) == ["WWW-Authenticate"]
