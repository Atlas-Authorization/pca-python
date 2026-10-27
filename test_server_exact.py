"""Exact-output tests for the server guard and the FastAPI / Django adapters (challenge text, error codes, header/body extraction paths,
adapter configuration errors). Complements test_server.py with precise assertions so formatting and branch mutants cannot survive."""
import json

import pytest

from atlas_pca import server
from atlas_pca.pca import b64u, canonical_bytes_strict
from test_server import AUD, GRANT, NOW, PCACTN, _guard, _header_value, _resolver


def test_challenge_exact():
    assert server.challenge(None) == 'PCA realm="pca"'
    assert server.challenge("a") == 'PCA realm="pca", audience="a"'
    assert server.challenge("a", "e") == 'PCA realm="pca", audience="a", error="e"'
    assert server.challenge("a", "e", "d") == 'PCA realm="pca", audience="a", error="e", error_description="d"'
    assert server.challenge(None, None, "d") == 'PCA realm="pca", error_description="d"'
    assert server.challenge(None, "e") == 'PCA realm="pca", error="e"'
    assert server.challenge('x"y\\z') == 'PCA realm="pca", audience="x\\"y\\\\z"'
    assert server.challenge("", "", "") == 'PCA realm="pca", audience="", error="", error_description=""'
    assert server._quote(5) == '"5"'
    assert server.PCA_HEADER == "PCA-Action" and server.REALM == "pca"


def test_get_header_paths():
    g = server._get_header
    assert g(None, "X") is None
    assert g({"X": "1"}, "X") == "1"
    assert g({"x": "1"}, "X") == "1"
    assert g({"X": "1"}, "x") == "1"
    assert g({"a": "0", "pca-ACTION": "v"}, "PCA-Action") == "v"
    assert g({1: "z", "other": "o"}, "other") == "o"
    assert g({1: "z"}, "x") is None
    assert g({}, "x") is None

    class Boom:
        def get(self, k):
            raise RuntimeError

        def items(self):
            return [("PCA-ACTION", "w")]

    assert g(Boom(), "pca-action") == "w"

    class Boom2:
        def get(self, k):
            raise RuntimeError

        def items(self):
            raise RuntimeError

    assert g(Boom2(), "x") is None

    class OnlyItems:
        def get(self, k):
            return None

        def items(self):
            return [(7, "no"), ("Y", "yes")]

    assert g(OnlyItems(), "y") == "yes"
    assert g({"Y": "yes", "y": "second"}, "Y") == "yes"
    assert g({"y": "first", "Y": "second"}, "Y") == "second"
    assert g({"k": ""}, "k") == ""


def test_to_text_paths():
    t = server._to_text
    assert t(None) is None
    assert t(b"") is None and t(bytearray()) is None
    assert t(b"ab") == "ab" and t(bytearray(b"ab")) == "ab"
    assert t(b"\xff") is None
    assert t("") is None and t("s") == "s"
    assert t(5) is None and t([1]) is None
    assert t("é".encode()) == "é"


def test_extract_paths():
    e = server.extract_pcactn
    hv = _header_value(PCACTN)
    assert e({"PCA-Action": hv}, None) == (PCACTN, None)
    assert e({}, json.dumps({"pcactn": PCACTN})) == (PCACTN, None)
    assert e({}, None) == (None, "absent")
    assert e({}, b"") == (None, "absent")
    assert e({}, "[1]") == (None, "absent")
    assert e({}, '{"other":1}') == (None, "absent")
    assert e({}, '{"pcactn":1}') == (None, "undecodable")
    assert e({}, '{"pcactn":[]}') == (None, "undecodable")
    assert e({}, "{") == (None, "undecodable")
    assert e({}, b"\xff") == (None, "absent")
    assert e({"PCA-Action": "!!"}, None) == (None, "undecodable")
    assert e({"PCA-Action": b64u(b"[1]")}, None) == (None, "undecodable")
    assert e({"PCA-Action": b64u(b"{")}, None) == (None, "undecodable")
    assert e({"PCA-Action": b64u(b'{"a":1,"a":2}')}, None) == (None, "undecodable")
    assert e({"PCA-Action": b64u(b" " * 524289)}, None) == (None, "undecodable")
    # header wins over body; an empty header value is still "present" (and undecodable) and does not fall through to the body
    assert e({"PCA-Action": hv}, '{"pcactn":{"x":1}}') == (PCACTN, None)
    assert e({"PCA-Action": ""}, json.dumps({"pcactn": PCACTN}))[1] == "undecodable"
    # a max-size but otherwise valid JSON object is accepted by the size gate
    big = b'{"a":"' + b"x" * (524288 - 8) + b'"}'
    assert len(big) == 524288
    obj, err = e({"PCA-Action": b64u(big)}, None)
    assert err is None and obj["a"].startswith("xxx")
    assert e({"PCA-Action": b64u(big + b" ")}, None) == (None, "undecodable")


def test_guard_results_exact():
    hv = _header_value(PCACTN)
    r = _guard()({}, None)
    assert (r.ok, r.status, r.error, r.verdict, r.pcactn) == (False, 401, "absent", None, None)
    assert r.www_authenticate == f'PCA realm="pca", audience="{AUD}", error="invalid_request", error_description="no PCActn presented"'
    r = _guard()({"PCA-Action": "!"}, None)
    assert (r.status, r.error) == (401, "undecodable")
    assert r.www_authenticate == f'PCA realm="pca", audience="{AUD}", error="invalid_request", error_description="PCActn could not be decoded"'
    r = _guard()({}, "{")
    assert (r.status, r.error) == (401, "undecodable")
    r = _guard(resolve_grant=lambda ref: None)({"PCA-Action": hv}, None)
    assert (r.ok, r.status, r.error, r.pcactn) == (False, 401, "unknown_grant", PCACTN)
    assert r.www_authenticate == f'PCA realm="pca", audience="{AUD}", error="invalid_token", error_description="grant_ref does not resolve to a known grant"'
    r = _guard(resolve_grant=lambda ref: [1])({"PCA-Action": hv}, None)
    assert r.status == 401
    seen = []
    _guard(resolve_grant=lambda ref: seen.append(ref) or GRANT)({"PCA-Action": hv}, None)
    assert seen == [PCACTN["grant_ref"]]
    r = _guard()({"PCA-Action": hv}, None)
    assert (r.ok, r.status, r.error, r.www_authenticate) == (True, 200, None, None)
    assert r.verdict.allow and r.pcactn == PCACTN
    r = _guard(audience="other")({"PCA-Action": hv}, None)
    assert (r.ok, r.status) == (False, 403)
    assert r.error == r.verdict.reason and r.error
    assert r.www_authenticate == 'PCA realm="pca", audience="other", error="insufficient_authority"'
    # PCAResult accessors
    assert r.get("status") == 403 and r.get("nope", 7) == 7 and r["ok"] is False
    # a verdict that denies with no reason maps to "insufficient_authority"
    from atlas_pca.pca import Verdict
    orig = server.verify_pcactn_core
    try:
        server.verify_pcactn_core = lambda *a, **k: Verdict(allow=False, checks={}, reason=None)
        r = _guard()({"PCA-Action": hv}, None)
        assert r.error == "insufficient_authority"
        assert r.www_authenticate == f'PCA realm="pca", audience="{AUD}", error="insufficient_authority"'
        got = {}
        server.verify_pcactn_core = lambda p, g, now=None, audience=None, **_kw: got.update(p=p, g=g, now=now, aud=audience) or Verdict(allow=True)
        _guard()({"PCA-Action": hv}, None)
        assert got == {"p": PCACTN, "g": GRANT, "now": NOW, "aud": AUD}
    finally:
        server.verify_pcactn_core = orig


# ---- FastAPI ----

def test_fastapi_exact():
    pytest.importorskip("fastapi")
    tc = pytest.importorskip("starlette.testclient")
    from fastapi import Depends, FastAPI, Request

    from atlas_pca.fastapi import PCAContext, RequirePCA

    hv = _header_value(PCACTN)
    app = FastAPI()
    seen = {}

    @app.post("/p")
    async def p(request: Request, pca=Depends(RequirePCA(audience=AUD, resolve_grant=_resolver, now=NOW, signature_only=True))):
        seen["ctx"] = (pca, request.state.pca)
        return {"t": type(pca).__name__}

    c = tc.TestClient(app)
    r = c.post("/p", headers={"PCA-Action": hv})
    assert r.status_code == 200 and r.json() == {"t": "PCAContext"}
    assert seen["ctx"][0] is seen["ctx"][1]
    assert isinstance(seen["ctx"][0], PCAContext) and seen["ctx"][0].pcactn == PCACTN and seen["ctx"][0].verdict.allow
    r = c.post("/p")
    assert r.status_code == 401 and r.json() == {"detail": "absent"}
    assert r.headers["WWW-Authenticate"] == f'PCA realm="pca", audience="{AUD}", error="invalid_request", error_description="no PCActn presented"'
    r = c.post("/p", content=json.dumps({"pcactn": PCACTN}))
    assert r.status_code == 200
    r = c.post("/p", headers={"PCA-Action": "!"})
    assert r.status_code == 401 and r.json() == {"detail": "undecodable"}
    app2 = FastAPI()

    @app2.post("/q")
    async def q(pca=Depends(RequirePCA(audience="zz", resolve_grant=_resolver, now=NOW, signature_only=True))):
        return {}

    r = tc.TestClient(app2).post("/q", headers={"PCA-Action": hv})
    assert r.status_code == 403 and r.json()["detail"] and r.headers["WWW-Authenticate"].startswith('PCA realm="pca", audience="zz", error="insufficient_authority"')

    # body-read failure is treated as "no body"
    import asyncio

    dep = RequirePCA(audience=AUD, resolve_grant=_resolver, now=NOW, signature_only=True)

    class Req:
        headers = {"PCA-Action": hv}

        async def body(self):
            raise RuntimeError

        class state:  # noqa: N801
            pass

    ctx = asyncio.run(dep(Req()))
    assert ctx.verdict.allow and Req.state.pca is ctx

    class Req2(Req):
        headers = {}

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        asyncio.run(dep(Req2()))
    assert ei.value.status_code == 401 and ei.value.detail == "absent"


# ---- Django ----

def _django():
    pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], DATABASES={})
    import django

    django.setup()
    return settings


def resolve_for_dotted(ref):
    return _resolver(ref)


def test_django_exact():
    settings = _django()
    from django.core.exceptions import ImproperlyConfigured
    from django.http import JsonResponse
    from django.test import RequestFactory

    from atlas_pca.django import PCAContext, PCAMiddleware

    hv = _header_value(PCACTN)
    rf = RequestFactory()
    for name in ("PCA_SIGNATURE_ONLY", "PCA_AUDIENCE", "PCA_RESOLVE_GRANT", "PCA_NOW"):
        if hasattr(settings, name):
            delattr(settings, name)
    with pytest.raises(ImproperlyConfigured, match="^PCAMiddleware requires settings.PCA_AUDIENCE$"):
        PCAMiddleware(lambda r: None)
    settings.PCA_AUDIENCE = ""
    with pytest.raises(ImproperlyConfigured, match="PCA_AUDIENCE"):
        PCAMiddleware(lambda r: None)
    settings.PCA_AUDIENCE = AUD
    settings.PCA_SIGNATURE_ONLY = True
    with pytest.raises(ImproperlyConfigured, match="^PCAMiddleware requires settings.PCA_RESOLVE_GRANT$"):
        PCAMiddleware(lambda r: None)
    settings.PCA_RESOLVE_GRANT = 5
    with pytest.raises(ImproperlyConfigured, match="^settings.PCA_RESOLVE_GRANT must be a dotted path or a callable$"):
        PCAMiddleware(lambda r: None)
    settings.PCA_RESOLVE_GRANT = "test_server_exact.resolve_for_dotted"
    settings.PCA_NOW = NOW
    called = []

    def get_response(request):
        called.append(request)
        return JsonResponse({"ok": True})

    mw = PCAMiddleware(get_response)
    assert mw.get_response is get_response and mw._now == NOW
    req = rf.post("/x", HTTP_PCA_ACTION=hv)
    assert mw(req).status_code == 200
    assert isinstance(req.pca, PCAContext) and req.pca.pcactn == PCACTN and req.pca.verdict.allow
    called.clear()
    r = mw(rf.generic("POST", "/x"))
    assert called == [] and r.status_code == 401
    assert json.loads(r.content) == {"error": "absent", "status": 401, "decision": "deny"}
    assert r["WWW-Authenticate"] == f'PCA realm="pca", audience="{AUD}", error="invalid_request", error_description="no PCActn presented"'
    r = mw(rf.post("/x", data=json.dumps({"pcactn": PCACTN}), content_type="application/json"))
    assert r.status_code == 200
    # _deny edge cases: no error text -> "forbidden"; no challenge -> no header
    from atlas_pca.server import PCAResult
    r = mw._deny(PCAResult(ok=False, status=403))
    assert json.loads(r.content) == {"error": "forbidden", "status": 403, "decision": "deny"} and r.status_code == 403 and not r.has_header("WWW-Authenticate")
    r = mw._deny(PCAResult(ok=False, status=401, error="e", www_authenticate="w"))
    assert json.loads(r.content) == {"error": "e", "status": 401, "decision": "deny"} and r["WWW-Authenticate"] == "w"
    r = mw._deny(PCAResult(ok=False, status=403, error="q", decision="escalate", escalation={"kind": "pca-escalation-request"}))
    assert json.loads(r.content) == {"error": "q", "status": 403, "decision": "escalate", "escalation": {"kind": "pca-escalation-request"}}

    # unreadable body is treated as absent
    class BadBody:
        headers = {"PCA-Action": hv}

        @property
        def body(self):
            raise RuntimeError

    assert mw(BadBody()).status_code == 200

    class BadBody2:
        headers = {}

        @property
        def body(self):
            raise RuntimeError

    assert mw(BadBody2()).status_code == 401
    settings.PCA_NOW = None
    assert PCAMiddleware(get_response)._now is None
