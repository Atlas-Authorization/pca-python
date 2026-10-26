"""0.5 breaking changes: check names (`counter_format` / `replay`), limit-naming denial reasons, and the authorize default."""
import json
import os

import pytest

from atlas_pca import AuthorizeOptions, ClaimResult, MemoryStateStore, authorize, evaluate_predicates, require_pca
from atlas_pca.authorize import DEFAULT_REQUIRED_CHECKS
from test_authorize import AUD, NOW, _hdr, case
from test_mutation_kill_b import AGENT, ROOT, _pcactn, _verify

HERE = os.path.dirname(os.path.abspath(__file__))
# Inputs and expected reasons were produced by the TypeScript evaluatePredicates.
with open(os.path.join(HERE, "testdata", "b6-limit-reasons.json"), encoding="utf-8") as f:
    LIMITS = json.load(f)


# ---- B6: the limit is named --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("c", LIMITS, ids=[c["name"] for c in LIMITS])
def test_limit_reason_equals_typescript(c):
    r = evaluate_predicates(c["predicates"], c["ctx"])
    assert r["allowed"] is c["allowed"]
    assert r.get("reason") == c.get("reason")


def test_limit_reason_headline_cases():
    pred = [{"verb": "stripe.refund", "resource": "charge:*", "where": [{"field": "action.params.amount", "op": "lte", "value": 500}]}]
    ctx = {"action": {"verb": "stripe.refund", "resource": "charge:ch_1", "params": {"amount": 900}}}
    assert evaluate_predicates(pred, ctx) == {"allowed": False,
                                              "reason": "amount <= 500 not satisfied for stripe.refund on charge:ch_1"}
    assert evaluate_predicates(pred, {"action": dict(ctx["action"], resource="other:1")})["reason"] == \
        "no predicate permits stripe.refund on other:1"
    assert evaluate_predicates([], ctx)["reason"] == "envelope grants no predicates"


# ---- B6: check names ----------------------------------------------------------------------------------------------------

def test_core_emits_counter_format_never_counter():
    ok = _verify(_pcactn([ROOT], AGENT, counter=3))
    assert ok.allow is True and ok.checks["counter_format"] is True and "counter" not in ok.checks
    bad = _verify(_pcactn([ROOT], AGENT, counter=-1))
    assert bad.allow is False
    assert bad.checks["counter_format"] is False and "counter" not in bad.checks
    assert bad.reason == "counter_format: missing or not a non-negative safe integer"


def test_required_list_names():
    assert DEFAULT_REQUIRED_CHECKS == ("counter_format", "replay", "revocation", "plan_root_authorized", "audience",
                                       "validity", "grant_ref_bound", "operation", "params_digest", "policy")


def _run(name="envelope-max-spend-within", store=None, **kw):
    c = case(name)
    s = c["steps"][0]
    opts = dict(operation=s["operation"], audience=AUD, resolve_grant=lambda ref: c["grant"],
                state_store=store if store is not None else MemoryStateStore(), is_revoked=lambda p, g: False,
                now=NOW, plan="single-step")
    opts.update(kw)
    return authorize(s["pcactn"], **opts)


def test_authorize_checks_use_replay_not_counter():
    r = _run()
    assert r.allow is True
    assert r.checks["counter_format"] == "pass" and r.checks["replay"] == "pass" and "counter" not in r.checks


def test_replay_failure_reasons():
    store = MemoryStateStore()
    assert _run(store=store).allow is True
    again = _run(store=store)
    assert again.checks["replay"] == "fail" and "counter" not in again.checks
    assert again.reason == "replay: 1 is not greater than last seen 1 (replay)"

    class Claimed:
        def claim(self, key, counter):
            return ClaimResult(False)

    assert _run(store=Claimed()).reason == "replay: 1 was already claimed (replay)"

    class Broken:
        def claim(self, key, counter):
            raise RuntimeError("down")

    r = _run(store=Broken())
    assert r.reason == "replay: the replay store failed (fail closed)" and r.checks["replay"] == "fail"


def test_a_denied_request_still_reports_replay_pass_and_never_claims():
    seen = []

    class Rec:
        def claim(self, key, counter):
            seen.append(key)
            return ClaimResult(True)

    r = _run("envelope-max-spend-400-refused", store=Rec())
    assert r.allow is False and r.checks["replay"] == "pass" and seen == []


def test_counter_is_an_alias_of_replay_in_require():
    r = _run(require=["counter"])
    assert r.allow is True and "counter" not in r.checks
    assert _run(require=["counter"], store=_used_store()).reason == "replay: 1 is not greater than last seen 1 (replay)"


def _used_store():
    store = MemoryStateStore()
    assert _run(store=store).allow is True
    return store


def test_tool_guard_without_options_reports_the_config_before_the_missing_capability():
    from atlas_pca.authorize import authorize_tool_call

    c = case("envelope-max-spend-within")
    p = c["steps"][0]["pcactn"]
    for verb, resource, params in ((None, None, {}), ("payments.send", "payments/acme", None)):
        r = authorize_tool_call(AuthorizeOptions(), p, verb=verb, resource=resource, params=params, audience=AUD,
                                resolve_grant=lambda ref: c["grant"], now=NOW)
        assert r.allow is False and r.missing == ["state_store", "is_revoked"]
        assert r.reason == "authorize_config: missing required component(s): state_store, is_revoked (fail closed)"
    # with a complete configuration the capability problem is what is reported
    full = AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False)
    r = authorize_tool_call(full, p, verb=None, resource=None, params={}, audience=AUD,
                            resolve_grant=lambda ref: c["grant"], now=NOW)
    assert r.reason.startswith("operation: the tool declares no capability")


# ---- B3: the guard defaults to the full authorize path --------------------------------------------------------------------

def _operation(c):
    return lambda headers, body: c["steps"][0]["operation"]


def test_default_guard_without_authorize_options_refuses_with_authorize_config():
    c = case("envelope-max-spend-within")
    g = require_pca(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW, operation=_operation(c))
    r = g(_hdr(c["steps"][0]["pcactn"]))
    assert (r.ok, r.status) == (False, 403)
    assert r.authorization.missing == ["state_store", "is_revoked"]
    assert r.error.startswith("authorize_config: missing required component(s): state_store, is_revoked")


def test_default_guard_with_store_and_revocation_enforces_the_limit():
    c = case("envelope-predicate-400-refused")
    g = require_pca(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW, operation=_operation(c),
                    authorize={"state_store": MemoryStateStore(), "is_revoked": lambda p, g: False})
    r = g(_hdr(c["steps"][0]["pcactn"]))
    assert r.status == 403 and "amount <= 100 not satisfied for payments.send on payments/acme" in r.error


def test_signature_only_is_an_explicit_opt_in_and_checks_the_signature_only():
    c = case("envelope-predicate-400-refused")
    g = require_pca(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW, signature_only=True)
    r = g(_hdr(c["steps"][0]["pcactn"]))
    assert (r.ok, r.status, r.authorization) == (True, 200, None)
    assert g({}).status == 401  # still needs a proof


def test_signature_only_and_authorize_together_is_a_construction_error():
    with pytest.raises(ValueError, match="mutually exclusive"):
        require_pca(audience=AUD, resolve_grant=lambda ref: None, signature_only=True,
                    authorize={"state_store": MemoryStateStore(), "is_revoked": lambda p, g: False})
    with pytest.raises(ValueError):
        require_pca(audience=AUD, resolve_grant=lambda ref: None, signature_only=True, authorize=AuthorizeOptions())


def test_fastapi_default_refuses_and_signature_only_runs_the_handler():
    pytest.importorskip("fastapi")
    tc = pytest.importorskip("starlette.testclient")
    from fastapi import Depends, FastAPI

    from atlas_pca.fastapi import RequirePCA

    c = case("envelope-predicate-400-refused")
    ran = []
    app = FastAPI()
    default = RequirePCA(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW)
    sig = RequirePCA(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW, signature_only=True)

    @app.post("/default")
    async def a(pca=Depends(default)):
        ran.append("default")

    @app.post("/sig")
    async def b(pca=Depends(sig)):
        ran.append("sig")

    client = tc.TestClient(app)
    h = _hdr(c["steps"][0]["pcactn"])
    r = client.post("/default", headers=h)
    assert r.status_code == 403 and r.json()["detail"].startswith("authorize_config: missing required component(s)")
    assert ran == []
    assert client.post("/sig", headers=h).status_code == 200 and ran == ["sig"]
    with pytest.raises(ValueError):
        RequirePCA(audience=AUD, resolve_grant=lambda ref: None, signature_only=True,
                   authorize={"state_store": MemoryStateStore(), "is_revoked": lambda p, g: False})


def test_django_default_refuses_and_signature_only_runs_the_handler():
    pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], DATABASES={})
    import django

    django.setup()
    from django.core.exceptions import ImproperlyConfigured
    from django.http import JsonResponse
    from django.test import RequestFactory

    from atlas_pca.django import PCAMiddleware

    c = case("envelope-predicate-400-refused")
    ran = []

    def view(request):
        ran.append(1)
        return JsonResponse({"ok": True})

    settings.PCA_AUDIENCE = AUD
    settings.PCA_RESOLVE_GRANT = lambda ref: c["grant"]
    settings.PCA_NOW = NOW
    rf = RequestFactory()
    req = lambda: rf.post("/pay", data="{}", content_type="application/json",  # noqa: E731
                          HTTP_PCA_ACTION=_hdr(c["steps"][0]["pcactn"])["PCA-Action"])
    try:
        r = PCAMiddleware(view)(req())
        assert r.status_code == 403 and json.loads(r.content)["error"].startswith("authorize_config: missing required")
        assert ran == []
        settings.PCA_SIGNATURE_ONLY = True
        assert PCAMiddleware(view)(req()).status_code == 200 and ran == [1]
        settings.PCA_AUTHORIZE = {"state_store": MemoryStateStore(), "is_revoked": lambda p, g: False}
        settings.PCA_OPERATION = lambda request: None  # complete, so only the signature_only + authorize clash can raise
        with pytest.raises(ImproperlyConfigured, match="mutually exclusive"):
            PCAMiddleware(view)
        del settings.PCA_SIGNATURE_ONLY
        PCAMiddleware(view)  # the same settings without the opt-in construct fine
    finally:
        for n in ("PCA_AUTHORIZE", "PCA_OPERATION", "PCA_SIGNATURE_ONLY"):
            if hasattr(settings, n):
                delattr(settings, n)
