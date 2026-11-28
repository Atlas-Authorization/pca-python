"""The Flask adapter (atlas_pca.flask): decorator and app-wide hook, allow / refuse paths, configuration errors."""
import json

import pytest

from test_server import AUD, NOW, PCACTN, _header_value, _resolver

flask = pytest.importorskip("flask")

from atlas_pca.flask import PCAContext, PCAFlask  # noqa: E402

CHALLENGE = f'PCA realm="pca", audience="{AUD}", error="missing_pcactn", error_description="no PCActn presented"'


def _app(guard, wide=False):
    app = flask.Flask("t")
    seen = {}

    @app.post("/p")
    def p():
        seen["ctx"] = flask.g.pca
        return {"t": type(flask.g.pca).__name__}

    if wide:
        guard.init_app(app)
    else:
        app.view_functions["p"] = guard.require(p)
    return app.test_client(), seen


@pytest.mark.parametrize("wide", [False, True])
def test_signature_only_allow_and_refuse(wide):
    c, seen = _app(PCAFlask(audience=AUD, resolve_grant=_resolver, now=NOW, signature_only=True), wide)
    r = c.post("/p", headers={"PCA-Action": _header_value(PCACTN)})
    assert r.status_code == 200 and r.get_json() == {"t": "PCAContext"}
    assert isinstance(seen["ctx"], PCAContext) and seen["ctx"].pcactn == PCACTN and seen["ctx"].verdict.allow
    r = c.post("/p", data=json.dumps({"pcactn": PCACTN}))
    assert r.status_code == 200
    seen.clear()
    r = c.post("/p")
    assert r.status_code == 401 and r.get_json()["error"] == "absent" and "ctx" not in seen
    assert r.headers["WWW-Authenticate"] == CHALLENGE
    r = c.post("/p", headers={"PCA-Action": "!"})
    assert r.status_code == 401 and r.get_json()["error"] == "undecodable"


def test_wrong_audience_is_403():
    c, seen = _app(PCAFlask(audience="zz", resolve_grant=_resolver, now=NOW, signature_only=True))
    r = c.post("/p", headers={"PCA-Action": _header_value(PCACTN)})
    assert r.status_code == 403 and "ctx" not in seen
    assert r.headers["WWW-Authenticate"].startswith('PCA realm="pca", audience="zz", error="insufficient_authority"')


def test_default_without_authorize_refuses_everything():
    c, seen = _app(PCAFlask(audience=AUD, resolve_grant=_resolver, now=NOW))
    r = c.post("/p", headers={"PCA-Action": _header_value(PCACTN)})
    assert r.status_code == 403 and r.get_json()["error"].startswith("authorize_config") and "ctx" not in seen


def test_operation_mapper_failure_denies():
    def boom(_request):
        raise RuntimeError("x")

    c, seen = _app(PCAFlask(audience=AUD, resolve_grant=_resolver, now=NOW, authorize={}, operation=boom))
    r = c.post("/p", headers={"PCA-Action": _header_value(PCACTN)})
    assert r.status_code in (401, 403) and "ctx" not in seen


def test_configuration_errors():
    with pytest.raises(ValueError):
        PCAFlask(audience="", resolve_grant=_resolver)
    with pytest.raises(ValueError):
        PCAFlask(audience=AUD, resolve_grant=None)
    with pytest.raises(ValueError):
        PCAFlask(audience=AUD, resolve_grant=_resolver, signature_only=True, authorize={})
    with pytest.raises(ValueError):
        PCAFlask(audience=AUD, resolve_grant=_resolver, authorize={})


def test_hooks_and_attestation_are_forwarded_only_when_given(monkeypatch):
    import atlas_pca.flask as fl

    seen = {}
    monkeypatch.setattr(fl, "require_pca", lambda **kw: seen.update(kw) or (lambda headers, body: None))
    PCAFlask(audience=AUD, resolve_grant=_resolver, signature_only=True)
    assert "hooks" not in seen and "attestation" not in seen
    hooks, att = {"zk": lambda ctx: {"enforced": True, "ok": True}}, {"trustedAttestorKeys": ["k"]}
    PCAFlask(audience=AUD, resolve_grant=_resolver, hooks=hooks, attestation=att)
    assert seen["hooks"] is hooks and seen["attestation"] is att
