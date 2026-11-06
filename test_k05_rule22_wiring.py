"""Rule 22 (`traits`) and the grant pin (`pin`) inside decide_intent_v2, plus the context members they read. Expectations are the
TypeScript reference (packages/pca/src/intent-v2.ts:83-87, :321-325, :614-634; packages/pca-actions/test/verifier.test.ts); the v2
documents are the shared conformance vectors, re-signed by a test site key."""
import copy
import json
import os

import pytest

import atlas_pca.intent_v2 as V2
from atlas_pca.pca import params_digest
from test_actions_vectors import _vector_dir
from test_mutation_kill_intent_v2 import SITE, _pub, _sign_schema

with open(os.path.join(_vector_dir(), "rule22-allow.json"), encoding="utf-8") as _f:
    _VEC = json.load(_f)["input"]
VERB = _VEC["verb"]
AUD = _VEC["doc"]["aud"]
PINS = _VEC["pins"]
CONTEXT = _VEC["context"]
NOW = 1_800_000_000_000
PARAMS = {"amount": 1000, "charge": "ch_abcdefgh", "idempotency_key": "k1"}
KEYS = [{"kid": "site-1", "alg": "ed25519", "pk": _pub(SITE)}]
ROOT = "A" * 43
SPEND = {"weights": {"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0}, "theta1": 1, "theta2": 1, "kappa": 100,
         "lambda": 0, "rho": 0.5, "bMax": 1_000_000}
FLOOR_CAVEATS = _VEC["grant"]["caveats"]


def _doc(mutate=None):
    d = dict(copy.deepcopy(_VEC["doc"]), pack={"ns": "stripe", "version": "1.0.0", "root": ROOT})
    if mutate:
        mutate(next(v for v in d["verbs"] if v["verb"] == VERB))
    return _sign_schema(d, kid="site-1")


def _def():
    return next(v for v in _VEC["doc"]["verbs"] if v["verb"] == VERB)["def"]


def _pin(**kw):
    p = {"pack": {"ns": "stripe", "root": ROOT}, "defs": {VERB: _def()}, "on_new_action": "deny", "max_esc": 3, "preauth_esc": 2, "caveats": FLOOR_CAVEATS}
    p.update(kw)
    return p


def _grant(pin=None, caveats=()):
    env = {"type": "envelope", "goal_commit": "gc", "predicates": [], "caveats": list(caveats), "agent_binding": {}, "risk_policy": SPEND}
    if pin is not None:
        env["actions"] = pin
    return {"id": "g", "issuer": "i", "caveats": [env]}


def _ctx(doc, **kw):
    c = {"schema": {"docs": [doc], "keys": KEYS}, "reviewers": PINS, "call_context": CONTEXT, "params": PARAMS,
         "policy": {"schema": {"closed_world": True}}}
    c.update(kw)
    return {k: v for k, v in c.items() if v is not None}


def _checks(grant, ctx):
    p = {"aud": AUD, "action": {"verb": VERB, "resource": "x", "params_digest": params_digest(PARAMS)}}
    return V2.decide_intent_v2(p, grant, ctx, NOW)["checks"]


def _by(checks, name):
    return next(c for c in checks if c["name"] == name)


ESCALATE = {"name": "traits", "ok": False, "reason": "escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)"}
DENY = {"name": "traits", "ok": False, "reason": "the action floors exceed what the grant authorizes (rule 22)"}


def test_control_consistent_schema_exact_pin_in_order():
    assert _checks(_grant(_pin()), _ctx(_doc())) == [{"name": "schema", "ok": True}, {"name": "pin", "ok": True}, {"name": "traits", "ok": True}]


@pytest.mark.parametrize("mutate,code", [
    (lambda v: v["floors"].update(esc=0, caveats=[], risk=0), "schema_floor_forged"),
    (lambda v: v["floors"].update(rev="reversible"), "schema_floor_forged"),
    (lambda v: v.update(traits=[t for t in v["traits"] if t != "pca.irreversible"]), "schema_traits_forged"),
    (lambda v: v.update(traits=sorted(v["traits"] + ["pca.nonexistent"])), "unknown_trait"),
])
def test_forged_schema_is_refused_by_schema_and_pin(mutate, code):
    checks = _checks(_grant(_pin()), _ctx(_doc(mutate)))
    assert [c["name"] for c in checks] == ["schema", "pin"]  # no accepted document: `traits` is not reported
    r = _by(checks, "schema")
    assert r["ok"] is False and r["reason"].startswith("schema_floor_forged: ") and code in r["reason"]
    assert _by(checks, "pin") == {"name": "pin", "ok": False, "reason": r["reason"]}


def test_reviewers_reach_the_integrity_check():
    # the vector's verbs are confirmed by the pinned reviewer; with no pins no verb is confirmed
    r = _by(_checks(_grant(), _ctx(_doc(), reviewers=None)), "schema")
    assert r["ok"] is False and r["reason"].startswith("schema_floor_forged: ")
    assert _by(_checks(_grant(_pin()), _ctx(_doc())), "schema") == {"name": "schema", "ok": True}
    other = {"keys": []}
    assert _by(_checks(_grant(), _ctx(_doc(), reviewers=other)), "schema")["ok"] is False


def test_aud_is_checked_before_the_floors():
    doc = _doc(lambda v: v["floors"].update(esc=0))
    doc = _sign_schema(dict({k: v for k, v in doc.items() if k != "sig"}, aud="elsewhere"), kid="site-1")
    assert _by(_checks(_grant(), _ctx(doc)), "schema")["reason"] == "schema aud does not match the PCActn aud"


def test_floors_are_checked_before_the_params():
    doc = _doc(lambda v: v["floors"].update(esc=0))
    assert _by(_checks(_grant(), _ctx(doc, params={"x": 1})), "schema")["reason"].startswith("schema_floor_forged: ")


@pytest.mark.parametrize("pin,want", [
    (_pin(), {"name": "traits", "ok": True}),
    (_pin(caveats=[]), ESCALATE),
    (_pin(caveats=FLOOR_CAVEATS[1:]), ESCALATE),
    (_pin(preauth_esc=1), ESCALATE),
    (_pin(max_esc=1, preauth_esc=0), DENY),
])
def test_floor_decision(pin, want):
    assert _by(_checks(_grant(pin), _ctx(_doc())), "traits") == want


def test_absent_pin_defaults_and_unpinned_grant():
    # no pin at all, a v2 schema: max_esc 3 and preauth 0, so a tier 2 verb escalates, never allows
    checks = _checks(_grant(), _ctx(_doc()))
    assert [c["name"] for c in checks] == ["schema", "traits"] and _by(checks, "traits") == ESCALATE
    full = [{"type": k} for k in FLOOR_CAVEATS]
    assert _by(_checks(_grant(caveats=full), _ctx(_doc())), "traits") == ESCALATE
    # max_esc absent means 3, preauth_esc absent means 0
    pin = {k: v for k, v in _pin().items() if k != "max_esc"}
    assert _by(_checks(_grant(pin), _ctx(_doc())), "traits") == {"name": "traits", "ok": True}
    pin = {k: v for k, v in _pin().items() if k != "preauth_esc"}
    assert _by(_checks(_grant(pin), _ctx(_doc())), "traits") == ESCALATE


def test_envelope_and_pin_caveats_are_both_counted():
    env = [{"type": k} for k in FLOOR_CAVEATS[1:]] + ["bare", {"type": 5}, {}, None]
    pin = _pin(caveats=FLOOR_CAVEATS[:1])
    assert _by(_checks(_grant(pin, env), _ctx(_doc())), "traits") == {"name": "traits", "ok": True}
    assert _by(_checks(_grant(_pin(caveats=[]), env), _ctx(_doc())), "traits") == ESCALATE
    # no caveats member on the pin
    pin = {k: v for k, v in _pin().items() if k != "caveats"}
    assert _by(_checks(_grant(pin, [{"type": k} for k in FLOOR_CAVEATS]), _ctx(_doc())), "traits") == {"name": "traits", "ok": True}


def test_call_context_is_verifier_state():
    assert _by(_checks(_grant(_pin()), _ctx(_doc(), call_context=[])), "traits") == ESCALATE
    assert _by(_checks(_grant(_pin()), _ctx(_doc(), call_context=None)), "traits") == ESCALATE  # absent is []
    assert _by(_checks(_grant(_pin()), _ctx(_doc(), call_context=CONTEXT[:1])), "traits") == ESCALATE


def test_pin_reasons():
    pin = lambda **kw: _by(_checks(_grant(_pin(**kw)), _ctx(_doc())), "pin")  # noqa: E731
    assert pin(defs={}) == {"name": "pin", "ok": False, "reason": "new_action: the grant does not name '%s' (on_new_action: deny)" % VERB}
    assert pin(defs={}, on_new_action="escalate") == {"name": "pin", "ok": False, "reason": "escalate: new_action: the grant does not name '%s' (on_new_action: escalate)" % VERB}
    assert pin(pack={"ns": "other", "root": ROOT}) == {"name": "pin", "ok": False, "reason": "pack_mismatch: the schema does not come from the pinned pack 'other'"}
    r = pin(defs={VERB: "B" * 43})
    assert r["ok"] is False and r["reason"].startswith("def_changed: ")


def test_pack_pin_and_malformed_pin():
    p = {k: v for k, v in _pin().items() if k != "defs"}
    checks = _checks(_grant(p), _ctx(_doc()))
    assert _by(checks, "pin") == {"name": "pin", "ok": True}
    checks = _checks(_grant(dict(p, pack={"ns": "stripe", "root": "B" * 43})), _ctx(_doc()))
    assert _by(checks, "pin") == {"name": "pin", "ok": False, "reason": "pack_mismatch: the pack root differs from the pinned root (the grant pins the pack as a whole)"}
    # a malformed pin fails `pin`; `traits` still runs, with no pin facts
    checks = _checks(_grant({"bad": 1}), _ctx(_doc()))
    assert [c["name"] for c in checks] == ["schema", "pin", "traits"]
    assert _by(checks, "pin") == {"name": "pin", "ok": False, "reason": "bad_pin: actions: unknown member 'bad'"}
    assert _by(checks, "traits") == ESCALATE
    # a malformed pin's caveats are not credited
    bad = _pin(bad=1)
    assert _by(_checks(_grant(bad), _ctx(_doc())), "traits") == ESCALATE


def test_v1_schema_gets_no_traits_check():
    v1 = _sign_schema({"v": 1, "kind": "pca-action-schema", "site": "https://pay.example", "aud": AUD, "version": "1", "verbs": [{
        "verb": VERB, "kind": "write", "reversibility": "reversible",
        "params": {"action.params.ok": {"type": "boolean", "semantic": "flag", "sensitivity": "material"}}}]}, kid="site-1")
    params = {"ok": True}
    p = {"aud": AUD, "action": {"verb": VERB, "resource": "x", "params_digest": params_digest(params)}}
    ctx = _ctx(v1, params=params)
    assert V2.decide_intent_v2(p, _grant(), ctx, NOW)["checks"] == [{"name": "schema", "ok": True}]
    assert V2.decide_intent_v2(p, _grant(_pin()), ctx, NOW)["checks"] == [
        {"name": "schema", "ok": True},
        {"name": "pin", "ok": False, "reason": "pack_mismatch: the schema does not come from the pinned pack 'stripe'"}]


def test_a_pin_without_the_closed_world_schema_check_still_gets_both():
    ctx = _ctx(_doc(), policy=None)
    assert _checks(_grant(_pin()), ctx) == [{"name": "pin", "ok": True}, {"name": "traits", "ok": True}]
    # no schema step ran and no pin: nothing is reported
    assert _checks(_grant(), ctx) == []


@pytest.mark.parametrize("ctx,want", [
    ({"reviewers": 5}, "reviewers must be {keys: [...]}"),
    ({"reviewers": None}, "reviewers must be {keys: [...]}"),
    ({"reviewers": []}, "reviewers must be {keys: [...]}"),
    ({"reviewers": {}}, "reviewers must be {keys: [...]}"),
    ({"reviewers": {"keys": 5}}, "reviewers must be {keys: [...]}"),
    ({"reviewers": {"keys": []}}, None),
    ({"call_context": 5}, "call_context must be an array of strings"),
    ({"call_context": None}, "call_context must be an array of strings"),
    ({"call_context": "a"}, "call_context must be an array of strings"),
    ({"call_context": ["a", 1]}, "call_context must be an array of strings"),
    ({"call_context": ["a"]}, None),
    ({"call_context": []}, None),
    ({"actions": 5}, "actions must be an object"),
    ({"actions": None}, "actions must be an object"),
    ({"actions": []}, "actions must be an object"),
    ({"actions": {}}, None),
    ({"actions": {"records": 5}}, "actions.records must be an array"),
    ({"actions": {"keys": None}}, "actions.keys must be an array"),
    ({"actions": {"reapprovals": {}}}, "actions.reapprovals must be an array"),
    ({"actions": {"records": [], "keys": [], "reapprovals": []}}, None),
    # order: reviewers, call_context, actions, params
    ({"reviewers": 5, "call_context": 5}, "reviewers must be {keys: [...]}"),
    ({"call_context": 5, "actions": 5}, "call_context must be an array of strings"),
    ({"actions": 5, "params": 5}, "actions must be an object"),
    ({"policy": 5, "reviewers": 5}, "policy must be an object"),
])
def test_context_validation(ctx, want):
    assert V2.intent_v2_context_error(ctx) == want


def test_malformed_context_fails_closed_through_the_decision():
    checks = _checks(_grant(_pin()), {"reviewers": 5})
    assert _by(checks, "schema") == {"name": "schema", "ok": False, "reason": "malformed v2 context: reviewers must be {keys: [...]}"}
