"""Kill tests: require_pca's error results (the PCActn it carries, exact challenge text), the policy / intent_v2 forwarded
to the verifier by the guard and by the FastAPI and Django adapters, and Django's PCA_INTENT_V2 setting forms."""
import asyncio

import pytest

from atlas_pca import server
from atlas_pca.pca import Verdict
from test_server import AUD, NOW, PCACTN, _header_value, _resolver

HV = _header_value(PCACTN)


def _guard(audience=AUD, resolve_grant=_resolver, **kw):
    return server.require_pca(audience=audience, resolve_grant=resolve_grant, now=NOW, **kw, signature_only=True)
POLICY = {"require": False, "min_fidelity_ppm": 1}


def test_malformed_grant_ref_result():
    p = dict(PCACTN, grant_ref=5)
    body = '{"pcactn": %s}' % __import__("json").dumps(p)
    r = _guard()({}, body)
    assert (r.ok, r.status, r.error) == (False, 401, "malformed")
    assert r.pcactn == p and r.verdict is None
    assert r.www_authenticate == f'PCA realm="pca", audience="{AUD}", error="invalid_pcactn", error_description="malformed PCActn"'


def test_resolver_failure_result():
    def boom(ref):
        raise RuntimeError("db down")

    r = _guard(resolve_grant=boom)({"PCA-Action": HV}, None)
    assert (r.ok, r.status, r.error) == (False, 403, "resolve_grant_error")
    assert r.pcactn == PCACTN
    assert r.www_authenticate == (f'PCA realm="pca", audience="{AUD}", error="insufficient_authority", '
                                  'error_description="grant resolution failed (fail closed)"')


def test_intent_v2_callable_failure_result():
    def boom(pcactn):
        raise RuntimeError("store down")

    r = _guard(intent_v2=boom)({"PCA-Action": HV}, None)
    assert (r.ok, r.status, r.error) == (False, 403, "intent_v2_context_error")
    assert r.pcactn == PCACTN
    assert r.www_authenticate == (f'PCA realm="pca", audience="{AUD}", error="insufficient_authority", '
                                  'error_description="intent v2 verifier state unavailable (fail closed)"')


def test_guard_forwards_policy_and_v2(monkeypatch):
    got = {}
    monkeypatch.setattr(server, "verify_pcactn_core", lambda p, g, **kw: got.update(kw) or Verdict(allow=True))
    v2 = {"policy": {}}
    _guard(intent_policy=POLICY, intent_v2=v2)({"PCA-Action": HV}, None)
    assert got["intent_policy"] is POLICY and got["intent_v2"] is v2
    seen = []
    _guard(intent_v2=lambda p: seen.append(p) or v2)({"PCA-Action": HV}, None)
    assert got["intent_v2"] is v2 and seen == [PCACTN] and got["intent_policy"] is None
    _guard(intent_v2=lambda p: None)({"PCA-Action": HV}, None)
    assert got["intent_v2"] is None


def test_to_text_utf8_alias_only():
    assert server._to_text(b"\xc3\xa9") == "é"
    assert server._to_text(bytearray(b"ab")) == "ab"
    assert server._to_text(b"\xff") is None


def test_fastapi_forwards_policy_and_v2(monkeypatch):
    pytest.importorskip("fastapi")
    from atlas_pca.fastapi import RequirePCA

    got = {}
    monkeypatch.setattr(server, "verify_pcactn_core", lambda p, g, **kw: got.update(kw) or Verdict(allow=True))
    v2 = {"policy": {}}
    dep = RequirePCA(audience=AUD, resolve_grant=_resolver, now=NOW, intent_policy=POLICY, intent_v2=v2, signature_only=True)

    class Req:
        headers = {"PCA-Action": HV}

        async def body(self):
            return b""

        class state:  # noqa: N801
            pass

    asyncio.run(dep(Req()))
    assert got["intent_policy"] is POLICY and got["intent_v2"] is v2

    class NoBody(Req):
        async def body(self):
            raise RuntimeError

    asyncio.run(dep(NoBody()))  # an unreadable body is treated as no body (None), never an empty string


def test_django_settings_forms(monkeypatch):
    pytest.importorskip("django")
    from test_server_exact import _django

    settings = _django()
    from django.core.exceptions import ImproperlyConfigured

    from atlas_pca import django as dj

    settings.PCA_AUDIENCE = AUD

    settings.PCA_SIGNATURE_ONLY = True
    settings.PCA_RESOLVE_GRANT = _resolver
    settings.PCA_NOW = NOW
    got = {}

    def fake_require(**kw):
        got.update(kw)
        return lambda h, b: None

    monkeypatch.setattr(dj, "require_pca", fake_require)
    for name in ("PCA_INTENT_V2", "PCA_INTENT_POLICY"):
        if hasattr(settings, name):
            delattr(settings, name)
    dj.PCAMiddleware(lambda r: None)
    assert got["intent_v2"] is None and got["intent_policy"] is None
    v2 = {"policy": {}}
    settings.PCA_INTENT_V2 = v2
    settings.PCA_INTENT_POLICY = POLICY
    dj.PCAMiddleware(lambda r: None)
    assert got["intent_v2"] is v2 and got["intent_policy"] is POLICY
    fn = lambda pcactn: v2  # noqa: E731
    settings.PCA_INTENT_V2 = fn
    dj.PCAMiddleware(lambda r: None)
    assert got["intent_v2"] is fn
    settings.PCA_INTENT_V2 = "test_server_exact.resolve_for_dotted"
    dj.PCAMiddleware(lambda r: None)
    from django.utils.module_loading import import_string
    assert got["intent_v2"] is import_string("test_server_exact.resolve_for_dotted")
    for bad in (5, "x", [1], True):
        settings.PCA_INTENT_V2 = bad
        with pytest.raises((ImproperlyConfigured, ImportError)) as e:
            dj.PCAMiddleware(lambda r: None)
        if isinstance(e.value, ImproperlyConfigured):
            assert str(e.value) == "settings.PCA_INTENT_V2 must be a dict, a callable or a dotted path to a callable"
    settings.PCA_INTENT_V2 = 5
    with pytest.raises(ImproperlyConfigured) as e:
        dj.PCAMiddleware(lambda r: None)
    assert str(e.value) == "settings.PCA_INTENT_V2 must be a dict, a callable or a dotted path to a callable"
    delattr(settings, "PCA_INTENT_V2")
    delattr(settings, "PCA_INTENT_POLICY")


def test_django_unreadable_body_is_none(monkeypatch):
    pytest.importorskip("django")
    from test_server_exact import _django

    settings = _django()
    settings.PCA_AUDIENCE = AUD
    settings.PCA_SIGNATURE_ONLY = True
    settings.PCA_RESOLVE_GRANT = _resolver
    settings.PCA_NOW = NOW
    for name in ("PCA_INTENT_V2", "PCA_INTENT_POLICY"):
        if hasattr(settings, name):
            delattr(settings, name)
    from atlas_pca.django import PCAMiddleware

    seen = {}
    mw = PCAMiddleware(lambda r: None)
    mw._guard = lambda headers, body: seen.update(body=body) or server.PCAResult(ok=False, status=401, error="absent")

    class BadBody:
        headers = {}

        @property
        def body(self):
            raise RuntimeError

    mw(BadBody())
    assert seen["body"] is None
