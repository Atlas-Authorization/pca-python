"""protect() secure defaults and explain_refusal(); mirrors packages/pca/src/refusal-help.test.ts and server/protect.ts."""
import json
import os

import pytest

from atlas_pca import MemoryStateStore, explain_refusal, protect, refusal_doc_url, require_pca
from atlas_pca.pca import b64u, canonical_bytes_strict

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as f:
    FIX = json.load(f)
NOW, AUD = FIX["now"], FIX["audience"]


def case(name):
    return next(c for c in FIX["cases"] if c["name"] == name)


def hdr(step):
    return {"PCA-Action": b64u(canonical_bytes_strict(step["pcactn"]))}


def guard_for(c, **kw):
    p = protect(AUD, [c["grant"]], now=NOW, **kw)
    o = p.options
    return p, require_pca(audience=o["audience"], resolve_grant=o["resolve_grant"], now=o["now"], authorize=o["authorize"])


def test_allow_replay_and_unknown_grant():
    c = case("envelope-predicate-within")
    s = c["steps"][0]
    _, g = guard_for(c)
    assert g(hdr(s), None, operation=s["operation"]).ok is True
    r = g(hdr(s), None, operation=s["operation"])  # the same proof again
    assert not r.ok and r.error.startswith("replay")
    other = protect(AUD, [], now=NOW).options
    g2 = require_pca(audience=AUD, resolve_grant=other["resolve_grant"], now=NOW, authorize=other["authorize"])
    assert not g2(hdr(s), None, operation=s["operation"]).ok  # the grant comes from your list, never the request


def test_policy_refusal():
    c = case("envelope-predicate-400-refused")
    s = c["steps"][0]
    _, g = guard_for(c)
    r = g(hdr(s), None, operation=s["operation"])
    assert not r.ok and r.status == 403 and explain_refusal(r.error)["check"] == "policy"


def test_revoke_and_extra_revocation_source():
    c = case("envelope-predicate-within")
    s = c["steps"][0]
    p, g = guard_for(c)
    p.revoke(c["grant"]["id"])
    r = g(hdr(s), None, operation=s["operation"])
    assert not r.ok and r.error.startswith("revocation")
    _, g = guard_for(c, is_revoked=lambda pcactn, grant: True)
    assert not g(hdr(s), None, operation=s["operation"]).ok


def test_callable_grants_and_caller_overrides_win():
    c = case("envelope-predicate-within")
    store = MemoryStateStore()
    p = protect(AUD, lambda ref: c["grant"] if ref == c["grant"]["id"] else None, lambda req, body: None, state_store=store, plan="single-step")
    assert p.options["authorize"].state_store is store and callable(p.options["operation"]) and "now" not in p.options
    assert p.options["resolve_grant"]("nope") is None
    assert p.options["resolve_grant"](None) is None
    assert protect(AUD, [c["grant"]]).options["authorize"].state_store is not None


def test_fastapi_body_has_doc():
    pytest.importorskip("fastapi")
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from atlas_pca.fastapi import RequirePCA, add_pca_handler

    c = case("envelope-predicate-400-refused")
    s = c["steps"][0]
    app = FastAPI()
    add_pca_handler(app)

    @app.post("/pay")
    async def pay(pca=Depends(RequirePCA(**protect(AUD, [c["grant"]], lambda req, body: s["operation"], now=NOW).options))):
        return {}

    r = TestClient(app).post("/pay", headers=hdr(s))
    assert r.status_code == 403 and r.json()["detail"].startswith("policy:")
    assert r.json()["doc"].endswith("/reference/refusals.md#policy")


# ---- explain_refusal ------------------------------------------------------------------------------------------------

def test_maps_by_leading_check_and_links_a_doc():
    h = explain_refusal("audience: signed aud ins_a is not ins_b")
    assert h["check"] == "audience" and h["docs"].startswith("https://")


def test_missing_component_points_at_protect():
    assert "protect()" in explain_refusal("authorize: missing required component(s): budgetStore (fail closed)")["fix"]


def test_contains_form_and_unknown_and_junk():
    assert explain_refusal("x: replay: counter 3 <= 3")["check"] == "replay"
    for junk in (None, 42, b"x", {}):
        h = explain_refusal(junk)
        assert h["check"] == "unknown" and "refusals" in h["docs"]
    assert refusal_doc_url("nonsense") == explain_refusal("nonsense")["docs"]
    assert refusal_doc_url("validity: expired").endswith("/refusals.md#validity")
