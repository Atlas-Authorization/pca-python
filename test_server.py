"""Tests for the PCA server guard and the FastAPI / Django integrations.

The valid PCActn fixture is loaded from the shared conformance vectors (same source as
test_conformance.py) rather than minted here, so the signed bytes are known-good. The FastAPI and
Django cases are skipped unless those packages are installed, so the base run stays dependency-free.
"""
import json
import os

import pytest

from atlas_pca import require_pca
from atlas_pca.pca import b64u, canonical_bytes_strict

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "packages", "pca", "conformance")


def _valid_vector():
    with open(os.path.join(DIR, "vectors.json"), encoding="utf-8") as f:
        doc = json.load(f)
    v = next(x for x in doc["vectors"] if x["name"] == "valid-in-plan-action")
    return v


VEC = _valid_vector()
PCACTN = VEC["pcactn"]
GRANT = VEC["grant"]
NOW = VEC["context"]["now"]
AUD = VEC["context"]["aud"]


def _resolver(grant_ref):
    """Return the fixture grant only for its own grant_ref; everything else is unknown."""
    return GRANT if grant_ref == PCACTN["grant_ref"] else None


def _header_value(pcactn):
    return b64u(canonical_bytes_strict(pcactn))


def _guard(audience=AUD, resolve_grant=_resolver):
    return require_pca(audience=audience, resolve_grant=resolve_grant, now=NOW)


# ---- framework-agnostic guard --------------------------------------------------------

def test_valid_via_header():
    res = _guard()({"PCA-Action": _header_value(PCACTN)}, None)
    assert res.ok is True
    assert res.status == 200
    assert res.verdict is not None and res.verdict.allow is True
    assert res.pcactn["aud"] == AUD
    assert res["ok"] is True  # dict-style access


def test_valid_via_header_case_insensitive():
    res = _guard()({"pca-action": _header_value(PCACTN)}, None)
    assert res.ok is True and res.status == 200


def test_valid_via_body():
    body = json.dumps({"pcactn": PCACTN}).encode("utf-8")
    res = _guard()({}, body)
    assert res.ok is True
    assert res.status == 200
    assert res.verdict.allow is True


def test_no_header_is_401_with_challenge():
    res = _guard()({}, None)
    assert res.ok is False
    assert res.status == 401
    assert res.error == "absent"
    assert res.www_authenticate is not None
    assert res.www_authenticate.startswith('PCA realm="pca"')


def test_undecodable_header_is_401():
    res = _guard()({"PCA-Action": "!!!not-base64url!!!"}, None)
    assert res.ok is False
    assert res.status == 401
    assert res.error == "undecodable"
    assert res.www_authenticate.startswith("PCA ")


def test_wrong_audience_fails():
    res = _guard(audience="rs-wrong")({"PCA-Action": _header_value(PCACTN)}, None)
    assert res.ok is False
    assert res.status == 403
    assert res.verdict is not None and res.verdict.allow is False
    assert res.verdict.checks["audience"] is False
    assert res.www_authenticate is not None


def test_unknown_grant_is_401():
    res = _guard(resolve_grant=lambda ref: None)({"PCA-Action": _header_value(PCACTN)}, None)
    assert res.ok is False
    assert res.status == 401
    assert res.error == "unknown_grant"
    assert "invalid_token" in res.www_authenticate


def test_expired_is_403():
    # a now far past exp denies on validity (well-formed, so 403 not 401)
    guard = require_pca(audience=AUD, resolve_grant=_resolver, now=NOW + 10 ** 12)
    res = guard({"PCA-Action": _header_value(PCACTN)}, None)
    assert res.ok is False
    assert res.status == 403
    assert res.verdict.checks["validity"] is False


# ---- FastAPI integration (skipped unless installed) ----------------------------------

def test_fastapi_dependency():
    pytest.importorskip("fastapi")
    starlette_testclient = pytest.importorskip("starlette.testclient")
    from fastapi import Depends, FastAPI, Request

    from atlas_pca.fastapi import RequirePCA

    app = FastAPI()
    guard = RequirePCA(audience=AUD, resolve_grant=_resolver, now=NOW)

    @app.post("/protected")
    async def protected(request: Request, pca=Depends(guard)):
        assert request.state.pca is pca
        return {"allow": pca.verdict.allow, "aud": pca.pcactn["aud"]}

    client = starlette_testclient.TestClient(app)

    ok = client.post("/protected", headers={"PCA-Action": _header_value(PCACTN)})
    assert ok.status_code == 200
    assert ok.json() == {"allow": True, "aud": AUD}

    missing = client.post("/protected")
    assert missing.status_code == 401
    assert missing.headers["WWW-Authenticate"].startswith('PCA realm="pca"')

    bad_aud = RequirePCA(audience="rs-wrong", resolve_grant=_resolver, now=NOW)
    app2 = FastAPI()

    @app2.post("/p2")
    async def p2(pca=Depends(bad_aud)):
        return {"ok": True}

    client2 = starlette_testclient.TestClient(app2)
    forbidden = client2.post("/p2", headers={"PCA-Action": _header_value(PCACTN)})
    assert forbidden.status_code == 403
    assert "WWW-Authenticate" in forbidden.headers


# ---- Django integration (skipped unless installed) -----------------------------------

def test_django_middleware():
    pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], DATABASES={})

    import django

    django.setup()
    from django.test import RequestFactory

    # Expose the resolver at an importable dotted path for the string-config form.
    import atlas_pca.django as dj

    settings.PCA_AUDIENCE = AUD
    settings.PCA_RESOLVE_GRANT = _resolver  # callable form
    settings.PCA_NOW = NOW

    from atlas_pca.django import PCAMiddleware

    sentinel = {"called": False}

    def get_response(request):
        sentinel["called"] = True
        from django.http import JsonResponse

        return JsonResponse({"allow": request.pca.verdict.allow, "aud": request.pca.pcactn["aud"]})

    mw = PCAMiddleware(get_response)
    rf = RequestFactory()

    ok_req = rf.post("/protected", HTTP_PCA_ACTION=_header_value(PCACTN))
    ok = mw(ok_req)
    assert ok.status_code == 200
    assert sentinel["called"] is True
    assert json.loads(ok.content) == {"allow": True, "aud": AUD}

    sentinel["called"] = False
    missing = mw(rf.post("/protected"))
    assert missing.status_code == 401
    assert sentinel["called"] is False
    assert missing["WWW-Authenticate"].startswith('PCA realm="pca"')

    # unknown grant -> 401
    settings.PCA_RESOLVE_GRANT = lambda ref: None
    mw_unknown = PCAMiddleware(get_response)
    unknown = mw_unknown(rf.post("/protected", HTTP_PCA_ACTION=_header_value(PCACTN)))
    assert unknown.status_code == 401

    # wrong audience -> 403
    settings.PCA_AUDIENCE = "rs-wrong"
    settings.PCA_RESOLVE_GRANT = _resolver
    mw_bad = PCAMiddleware(get_response)
    forbidden = mw_bad(rf.post("/protected", HTTP_PCA_ACTION=_header_value(PCACTN)))
    assert forbidden.status_code == 403
    _ = dj  # keep the import referenced
