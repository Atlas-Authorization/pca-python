"""k05 mutation kill (group authz): authorize.py (_check_value / _check_object / evaluate_tool_schema, the _authorize pipeline
seams, authorize_tool_call), server.py require_pca, obligations.py pep_obligation_gate, operations.py Executor.__call__ and
blueprint.py check_blueprints. Exact results on every branch; strings/limits are the TypeScript reference's
(agent-native.ts checkValue/evaluateToolSchema, obligations.ts pepObligationGate, pca-grants blueprint.ts checkBlueprints);
the authorize/require_pca refusal texts with no TypeScript counterpart are this SDK's documented ones."""
import copy
import importlib
import json
import os

import pytest

from atlas_pca import blueprint as B
from atlas_pca import obligations as OB
from atlas_pca import operations as O
from atlas_pca import server as S
from atlas_pca.caveat_lang import discharge_action_digest
from atlas_pca.pca import Verdict, hash_canonical, params_digest
from prov_harness import prov

Z = importlib.import_module("atlas_pca.authorize")  # the module (the package attribute is the function)

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as _f:
    FIX = json.load(_f)
NOW, AUD = FIX["now"], FIX["audience"]
CASE = next(c for c in FIX["cases"] if c["name"] == "envelope-max-spend-within")
P0, OP, G = CASE["steps"][0]["pcactn"], CASE["steps"][0]["operation"], CASE["grant"]
PARAMS = {"amount": 50, "currency": "usd"}
INNER = {"verb": "payments.send", "resource": "payments/acme", "params": PARAMS, "reversibility_class": "irreversible"}
NODE = {"id": "n1", "verb": "payments.send", "resource": "payments/acme", "params_digest": P0["action"]["params_digest"],
        "reversibility_class": "irreversible"}


def run(**kw):
    """authorize() over the signed allowing fixture (single-step plan, principal-direct provenance)."""
    p = kw.pop("pcactn", None)
    p = copy.deepcopy(P0) if p is None else p
    opts = dict(operation=OP, audience=AUD, resolve_grant=lambda ref: G, state_store=Z.MemoryStateStore(),
                is_revoked=lambda _p, _g: False, now=NOW, plan="single-step")
    opts.update(prov(OP))
    opts.update(kw)
    return Z.authorize(p, **opts)


def az(p, **kw):
    """authorize() over a minimal, unsigned PCActn (the refusals before the core checks)."""
    opts = dict(operation=OP, audience=AUD, resolve_grant=lambda ref: {"id": ref}, state_store=Z.MemoryStateStore(),
                is_revoked=lambda _p, _g: False, now=NOW)
    opts.update(kw)
    return Z.authorize(p, **opts)


def refused(status, check, reason, pcactn=None, missing=None):
    return Z.AuthorizeResult(allow=False, status=status, checks={check: "fail"}, reasons=[reason], reason=reason,
                             missing=missing, pcactn=pcactn, assurance={check: {"outcome": "fail"}})


def failed(r):
    return sorted(k for k, s in r.checks.items() if s == "fail")


def _raise(*_a, **_k):
    raise RuntimeError("boom")


# ---- _check_value / _check_object (TS checkValue / checkObject) -----------------------------------------------------------

def cv(spec, v, depth=1, budget=None):
    return Z._check_value(spec, v, "p", depth, {"n": 0} if budget is None else budget)


BOOL = {"type": "boolean"}
ARR = {"type": "array", "items": BOOL}


def test_check_value_depth_boundary():
    assert cv(BOOL, True, depth=9) is None
    assert cv(BOOL, True, depth=10) == "p: too deep"
    # array items are one level deeper (depth + 1, never - 1)
    assert cv(ARR, [True], depth=8) is None
    assert cv(ARR, [True], depth=9) == "p[0]: too deep"
    # object members are one level deeper too
    props = {"a": BOOL}
    assert Z._check_object(props, None, {"a": True}, "args", 8, {"n": 0}) is None
    assert Z._check_object(props, None, {"a": True}, "args", 9, {"n": 0}) == "args.a: too deep"
    assert cv({"type": "object", "props": props}, {"a": True}, depth=9) == "p.a: too deep"
    assert cv({"type": "object", "props": props}, {"a": True}, depth=8) is None


def test_check_value_budget_boundary():
    b = {"n": 9999}
    assert cv(BOOL, True, budget=b) is None and b == {"n": 10000}
    assert cv(BOOL, True, budget={"n": 10000}) == "p: too many values"
    b = {"n": 0}
    assert cv(ARR, [True, False, True], budget=b) is None and b == {"n": 4}
    assert cv(ARR, [True, True, True], budget={"n": 9997}) == "p[2]: too many values"
    b = {"n": 0}
    assert Z._check_object({"a": BOOL, "b": BOOL}, None, {"a": True, "b": False}, "args", 1, b) is None and b == {"n": 2}


def test_check_value_unknown_type():
    assert cv({"type": "x"}, 1) == "p: unknown type"
    assert cv({}, 1) == "p: unknown type"
    assert cv({"type": None}, None) == "p: unknown type"


def test_check_value_array():
    assert cv(ARR, {"a": 1}) == "p: expected array"
    assert cv(ARR, "ab") == "p: expected array"
    assert cv(ARR, [True] * 256) is None  # default maxItems 256
    assert cv(ARR, [True] * 257) == "p: exceeds maxItems"
    big = dict(ARR, maxItems=5000)  # capped at the absolute 4096
    assert cv(big, [True] * 4096) is None
    assert cv(big, [True] * 4097) == "p: exceeds maxItems"
    two = dict(ARR, maxItems=2, minItems=2)
    assert cv(two, [True, True]) is None
    assert cv(two, [True]) == "p: below minItems"
    assert cv(two, [True, True, True]) == "p: exceeds maxItems"
    assert cv(dict(ARR, minItems=0), []) is None
    assert cv(ARR, [True, 1, "x"]) == "p[1]: wrong type (expected boolean)"
    nested = {"type": "array", "items": {"type": "object", "props": {"x": {"type": "string"}}}}
    assert cv(nested, [{"x": "a"}, {"x": 1}]) == "p[1].x: wrong type (expected string)"


def test_check_value_string():
    S0 = {"type": "string"}
    assert cv(S0, 5) == "p: wrong type (expected string)"
    assert cv(S0, None) == "p: wrong type (expected string)"
    assert cv(S0, "a" * 65536) is None  # default maxLength 65536
    assert cv(S0, "a" * 65537) == "p: exceeds maxLength"
    big = dict(S0, maxLength=2_000_000)  # capped at the absolute 1048576
    assert cv(big, "a" * 1_048_576) is None
    assert cv(big, "a" * 1_048_577) == "p: exceeds maxLength"
    s = dict(S0, minLength=2, maxLength=3)
    assert cv(s, "ab") is None
    assert cv(s, "abc") is None
    assert cv(s, "a") == "p: below minLength"
    assert cv(s, "abcd") == "p: exceeds maxLength"
    assert cv(s, "\U0001F600") is None  # UTF-16 length 2
    assert cv(dict(S0, maxLength=1), "\U0001F600") == "p: exceeds maxLength"
    pre = dict(S0, prefix="ab")
    assert cv(pre, "abz") is None
    assert cv(pre, "ab") is None
    assert cv(pre, "zab") == "p: violates prefix"
    assert cv(dict(S0, const="x"), "x") is None
    assert cv(dict(S0, const="x"), "y") == "p: violates const"
    assert cv(dict(S0, enum=["a", "b"]), "b") is None
    assert cv(dict(S0, enum=["a", "b"]), "c") == "p: violates enum"
    # const is checked before enum
    assert cv(dict(S0, const="a", enum=["b"]), "b") == "p: violates const"
    assert cv(dict(S0, const="a", enum=["b"]), "a") == "p: violates enum"


def test_check_value_numbers():
    n = {"type": "number", "min": 1, "max": 3}
    assert cv(n, 1) is None
    assert cv(n, 3) is None
    assert cv(n, 2.5) is None
    assert cv(n, 0.5) == "p: below min"
    assert cv(n, 3.5) == "p: above max"
    assert cv(n, "2") == "p: wrong type (expected number)"
    assert cv(n, True) == "p: wrong type (expected number)"
    assert cv(n, float("inf")) == "p: wrong type (expected number)"
    assert cv({"type": "number"}, -0.0) is None
    i = {"type": "integer", "min": 0, "max": 10}
    assert cv(i, 0) is None
    assert cv(i, 10) is None
    assert cv(i, 4.0) is None
    assert cv(i, 4.5) == "p: wrong type (expected integer)"
    assert cv(i, -0.0) == "p: wrong type (expected integer)"
    assert cv(i, False) == "p: wrong type (expected integer)"
    assert cv(i, -1) == "p: below min"
    assert cv(i, 11) == "p: above max"
    assert cv({"type": "integer", "const": 2}, 2.0) is None
    assert cv({"type": "integer", "const": 2}, 3) == "p: violates const"
    assert cv({"type": "number", "enum": [1, 2.5]}, 2.5) is None
    assert cv({"type": "number", "enum": [1, 2.5]}, 2) == "p: violates enum"


def test_check_value_boolean_and_object():
    assert cv(BOOL, 1) == "p: wrong type (expected boolean)"
    assert cv(BOOL, False) is None
    assert cv(dict(BOOL, const=True), False) == "p: violates const"
    assert cv(dict(BOOL, const=True), 1) == "p: wrong type (expected boolean)"
    assert cv(dict(BOOL, enum=[True]), False) == "p: violates enum"
    o = {"type": "object", "props": {"a": BOOL}, "required": ["a"]}
    assert cv(o, [True]) == "p: expected object"
    assert cv(o, {}) == "p: missing required argument 'a'"
    assert cv(o, {"a": True}) is None
    assert cv({"type": "object", "props": {"a": BOOL}}, {}) is None


def test_check_object_messages():
    props = {"n": {"type": "integer"}, "s": {"type": "string"}}
    co = lambda obj, req=None: Z._check_object(props, req, obj, "args", 1, {"n": 0})  # noqa: E731
    assert co({"zz": 1}, ["n"]) == 'args: unexpected argument "zz"'  # unexpected before missing
    assert co({}, ["s", "n"]) == "args: missing required argument 's'"
    assert co({"s": "x"}, ["s", "n"]) == "args: missing required argument 'n'"
    assert co({"n": "x", "s": 1}) == "args.n: wrong type (expected integer)"
    assert co({"s": 1, "n": "x"}) == "args.s: wrong type (expected string)"  # in the object's key order
    assert co({"k" * 48: 1}) == 'args: unexpected argument "%s"' % ("k" * 48)
    assert co({"k" * 49: 1}) == 'args: unexpected argument "%s…"' % ("k" * 48)
    assert co({"\ud800": 1}) == 'args: unexpected argument "\\ud800"'  # JSON.stringify escapes a lone surrogate


# ---- evaluate_tool_schema (TS evaluateToolSchema) ---------------------------------------------------------------------

def _tool_caveat(schema, tool="pay", sig="sigdigest"):
    return {"type": "tool_schema", "tool": tool, "signature_digest": sig, "schema": schema, "schema_digest": hash_canonical(schema),
            "binding_digest": hash_canonical({"tool": tool, "signature_digest": sig, "schema": schema})}


SCHEMA = {"props": {"n": {"type": "integer", "max": 5}}, "required": ["n"]}


def test_evaluate_tool_schema_caveat_shape():
    good = _tool_caveat(SCHEMA)
    call = {"tool": "pay", "args": {"n": 1}}
    assert Z.evaluate_tool_schema(good, call) == (True, None)
    for bad in (None, [good], dict(good, type="tool"), dict(good, tool=5), dict(good, tool="")):
        assert Z.evaluate_tool_schema(bad, call) == (False, "malformed tool_schema caveat")
    no_type = dict(good)
    del no_type["type"]
    assert Z.evaluate_tool_schema(no_type, call) == (False, "malformed tool_schema caveat")
    assert Z.evaluate_tool_schema(dict(good, schema=5), call) == (False, "malformed tool_schema caveat: schema must be an object")
    assert Z.evaluate_tool_schema(dict(good, schema_digest="x"), call) == (False, "schema digest mismatch")
    assert Z.evaluate_tool_schema(dict(good, binding_digest="x"), call) == (False, "binding digest mismatch")


def test_evaluate_tool_schema_signature_digest_string_form():
    # String(caveat.signature_digest): an absent one binds as "undefined", a number as its JS string
    c = _tool_caveat(SCHEMA, sig="undefined")
    del c["signature_digest"]
    assert Z.evaluate_tool_schema(c, {"tool": "pay", "args": {"n": 1}}) == (True, None)
    c5 = _tool_caveat(SCHEMA, sig="5")
    c5["signature_digest"] = 5
    assert Z.evaluate_tool_schema(c5, {"tool": "pay", "args": {"n": 1}}) == (True, None)
    c5b = dict(c5, binding_digest=hash_canonical({"tool": "pay", "signature_digest": 5, "schema": SCHEMA}))
    assert Z.evaluate_tool_schema(c5b, {"tool": "pay", "args": {"n": 1}}) == (False, "binding digest mismatch")


def test_evaluate_tool_schema_call():
    good = _tool_caveat(SCHEMA, sig=hash_canonical({"name": "pay"}))
    ev = lambda call: Z.evaluate_tool_schema(good, call)  # noqa: E731
    assert ev(None) == (False, "malformed call")
    assert ev({"tool": 5, "args": {}}) == (False, "malformed call")
    assert ev({"tool": "pay", "args": [1]}) == (False, "malformed call")
    assert ev({"tool": "pay"}) == (False, "malformed call")
    assert ev({"args": {"n": 1}}) == (False, "malformed call")
    assert ev({"tool": "refund", "args": {"n": 1}}) == (False, 'tool "refund" not authorized')
    assert ev({"tool": "t" * 49, "args": {"n": 1}}) == (False, 'tool "%s…" not authorized' % ("t" * 48))
    assert ev({"tool": "pay", "args": {"n": 1}, "tool_signature": {"name": "pay"}}) == (True, None)
    assert ev({"tool": "pay", "args": {"n": 1}, "tool_signature": {"name": "other"}}) == \
        (False, "tool signature differs from the authorized signature")
    sd = good["signature_digest"]
    assert ev({"tool": "pay", "args": {"n": 1}, "tool_signature_digest": sd}) == (True, None)
    assert ev({"tool": "pay", "args": {"n": 1}, "tool_signature_digest": "x"}) == \
        (False, "signed tool_binding differs from the authorized tool signature")
    # the signature check comes first
    assert ev({"tool": "pay", "args": {"n": 1}, "tool_signature": "x", "tool_signature_digest": "x"}) == \
        (False, "tool signature differs from the authorized signature")
    assert ev({"tool": "pay", "args": {"n": 6}}) == (False, "args.n: above max")
    assert ev({"tool": "pay", "args": {}}) == (False, "args: missing required argument 'n'")


def test_evaluate_tool_schema_fail_closed_on_error():
    good = _tool_caveat(SCHEMA)
    # an out-of-profile value (unsafe integer) cannot be hashed: the reference throws inside the try as well
    assert Z.evaluate_tool_schema(good, {"tool": "pay", "args": {"n": 1}, "tool_signature": {"x": 2 ** 60}}) == \
        (False, "evaluation error (fail closed)")


# ---- authorize(): the refusals before the core checks ------------------------------------------------------------------

def test_refusals_before_core():
    p = {"grant_ref": "g"}
    assert az(None) == refused(401, "wire", "wire: no PCActn presented")
    for bad in ("{", "[1]", 5, b"\xff"):
        assert az(bad) == refused(401, "pcactn", "undecodable PCActn: could not be decoded")
    for q in ({"grant_ref": 5}, {}, {"grant_ref": None}):
        assert az(q) == refused(401, "malformed", "malformed: grant_ref is not a string", pcactn=q)
    assert az(p, resolve_grant=_raise) == refused(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)", pcactn=p)
    assert az(p, resolve_grant=lambda ref: None) == refused(401, "grant_ref", "grant_ref: does not resolve to a known grant", pcactn=p)
    assert az(p, resolve_grant=lambda ref: [ref]) == refused(401, "grant_ref", "grant_ref: does not resolve to a known grant", pcactn=p)
    assert az(p, context=_raise) == refused(403, "context", "context: the context callback failed (fail closed)", pcactn=p)
    assert az(p, context=lambda _p: [1]) == \
        refused(403, "context", "context: the context callback must return a dict (fail closed)", pcactn=p)
    assert az(p, intent_v2=_raise) == refused(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)", pcactn=p)
    assert az(p, fresh_at=_raise) == refused(403, "fresh_at", "fresh_at: verifier state unavailable (fail closed)", pcactn=p)


def test_refusals_config_operation_workflow():
    p = {"grant_ref": "g"}
    m = ["revocation_staleness (must be a RevocationStaleness)"]
    assert az(p, revocation_staleness="x") == refused(
        403, "authorize_config", "authorize_config: missing required component(s): %s (fail closed)" % m[0], missing=m)
    assert az(p, plan="multi") == refused(
        403, "authorize_config", "authorize_config: missing required component(s): plan (only 'single-step' or None) (fail closed)",
        missing=["plan (only 'single-step' or None)"])
    assert az(p, operation={"verb": "v", "resource": "r"}) == refused(
        403, "operation", "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)")
    assert az(None, workflow="x") == refused(403, "workflow", "workflow: invalid workflow option (fail closed)")
    assert az(None, workflow={"required": True}) == refused(403, "workflow", "workflow: this call carries no workflow step (fail closed)")
    # required must be exactly True: otherwise the PCActn is read (and is absent here)
    assert az(None, workflow={"required": "yes"}) == refused(401, "wire", "wire: no PCActn presented")
    assert az(None, workflow={}) == refused(401, "wire", "wire: no PCActn presented")


def test_internal_error_fails_closed(monkeypatch):
    monkeypatch.setattr(Z, "_authorize", lambda *a, **k: (_ for _ in ()).throw(ValueError("x")))
    assert az({"grant_ref": "g"}) == refused(403, "authorize", "authorize: error (fail closed): ValueError")


def test_wire_failure_is_401_with_malformed(monkeypatch):
    p, grant = {"grant_ref": "g"}, {"id": "g"}
    core = Z.verify_pcactn_core(p, grant, now=NOW, audience=AUD, allowed_suites=None, intent_policy=None, intent_v2=None,
                                fresh_at=None)
    assert core.checks.get("wire") is False and core.reason
    r = az(p)
    assert (r.allow, r.status, r.checks, r.reasons, r.reason, r.pcactn, r.verdict, r.decision) == \
        (False, 401, {"wire": "fail", "malformed": "fail"}, [core.reason], core.reason, p, core, "deny")
    # a wire verdict without a reason falls back to the fixed text
    v = Verdict(False, {"wire": False}, None)
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: v)
    r = az(p)
    assert (r.status, r.checks, r.reasons, r.reason, r.verdict) == \
        (401, {"wire": "fail", "malformed": "fail"}, ["wire: malformed PCActn"], "wire: malformed PCActn", v)


# ---- authorize(): the plan registry -------------------------------------------------------------------------------------

class Plans:
    def __init__(self, ret=None, exc=False):
        self.ret, self.exc, self.calls = ret, exc, []

    def context(self, grant_ref, root, now):
        self.calls.append((grant_ref, root, now))
        if self.exc:
            raise RuntimeError("down")
        return self.ret


def test_plans_registry_failure_and_root_argument():
    pl = Plans(exc=True)
    p = copy.deepcopy(P0)
    assert run(pcactn=p, plans=pl) == refused(403, "plans", "plans: the plan registry failed (fail closed)", pcactn=p)
    assert pl.calls == [(P0["grant_ref"], P0["plan"]["root"], NOW)]
    for q, root in (({"grant_ref": "g", "plan": {"root": "R"}}, "R"), ({"grant_ref": "g", "plan": {"root": 5}}, ""),
                    ({"grant_ref": "g", "plan": ["R"]}, ""), ({"grant_ref": "g"}, "")):
        pl = Plans()
        az(q, plans=pl)
        assert pl.calls == [("g", root, NOW)]


def test_plans_unknown_root():
    r = run(plans=Plans(), plan=None)
    assert r.allow is False and r.status == 403
    assert r.checks["plan_state"] == "fail"
    assert "plan_state: plan %s is unknown to the plan registry" % P0["plan"]["root"] in r.reasons
    assert failed(r) == ["plan_root_authorized", "plan_state"]
    # single-step applies instead: no plan_state at all
    r = run(plans=Plans())
    assert r.allow is True and "plan_state" not in r.checks


def test_plans_registered_plan_states():
    ok = Plans({"plan": [NODE], "planAuthorized": True, "status": {"state": "authorized", "executable": True}})
    r = run(plans=ok, plan=None)
    assert r.allow is True and r.checks["plan_state"] == "pass" and r.checks["plan_root_authorized"] == "pass"
    r = run(plans=Plans({"plan": [NODE], "planAuthorized": True, "status": {"state": "expired", "executable": False}}), plan=None)
    assert failed(r) == ["plan_state"] and r.reason == "plan_state: plan is expired" and r.allow is False
    r = run(plans=Plans({"plan": [NODE], "planAuthorized": True,
                         "status": {"state": "revoked", "executable": False, "reason": "revoked by the principal"}}), plan=None)
    assert failed(r) == ["plan_state"] and r.reason == "plan_state: revoked by the principal"
    r = run(plans=Plans({"plan": [NODE], "planAuthorized": False, "status": {"state": "committed", "executable": True}}), plan=None)
    assert failed(r) == ["plan_root_authorized"]
    assert r.reason == "plan_root_authorized: the plan root has not been authorized by the principal"


def test_plans_not_consulted_when_context_supplies_the_plan():
    pl = Plans(exc=True)
    r = run(plans=pl, plan=None, context=lambda _p: {"plan": [NODE], "plan_authorized": True})
    assert pl.calls == [] and r.allow is True


# ---- authorize(): the context plan (merkle root over pre/post conditions) ------------------------------------------------

def test_context_plan_leaf_includes_conditions():
    ctx = lambda node, auth=True: (lambda _p: {"plan": [node], "plan_authorized": auth})  # noqa: E731
    assert run(plan=None, context=ctx(NODE)).allow is True
    mism = "plan_root_authorized: known plan does not match plan.root"
    for node in (dict(NODE, pre={"x": 1}), dict(NODE, post={"x": 1}), dict(NODE, id="n2"),
                 dict(NODE, params_digest="x"), dict(NODE, reversibility_class="reversible")):
        r = run(plan=None, context=ctx(node))
        assert failed(r) == ["plan_root_authorized"] and r.reason == mism
    r = run(plan=None, context=lambda _p: {"plan": [5], "plan_authorized": True})
    assert failed(r) == ["plan_root_authorized"] and r.reason == mism
    for auth in (None, "true", 1):
        r = run(plan=None, context=ctx(NODE, auth))
        assert failed(r) == ["plan_root_authorized"]
        assert r.reason == "plan_root_authorized: the plan root has not been authorized by the principal"


# ---- authorize(): the caveat contexts handed to the evaluators -----------------------------------------------------------

def _capture(monkeypatch):
    calls = []

    def fake(cavs, cctx, actx=None, tc=None):
        calls.append((copy.deepcopy(cavs), copy.deepcopy(cctx), copy.deepcopy(actx), copy.deepcopy(tc)))
        return True, []
    monkeypatch.setattr(Z, "evaluate_agent_caveats", fake)
    return calls


TC = {"tool": "payments.send", "args": PARAMS}
ENV_CAVEATS = [{"type": "max_spend", "usd": 100}]


def test_caveat_contexts_with_host_context(monkeypatch):
    calls = _capture(monkeypatch)
    r = run(context=lambda _p: {"recent_action_times": [1, 2], "blast_radius": 0, "subject": {"id": "s"}, "env": {"e": 1}})
    assert r.allow is True
    cctx = {"now": NOW, "action": INNER, "delegation_depth": 0, "blast_radius": 0, "reversibility_class": "irreversible",
            "recent_action_times": [1, 2]}
    actx = {"action": INNER, "subject": {"id": "s"}, "env": {"e": 1}}
    # delegated (leaf extras) first, then the envelope caveats, then the root caveats
    assert calls == [([], cctx, actx, TC), (ENV_CAVEATS, cctx, actx, TC), ([], cctx, actx, TC)]


def test_caveat_contexts_without_host_context(monkeypatch):
    calls = _capture(monkeypatch)
    assert run().allow is True
    cctx = {"now": NOW, "action": INNER, "delegation_depth": 0, "reversibility_class": "irreversible"}
    actx = {"action": INNER}
    assert calls == [([], cctx, actx, TC), (ENV_CAVEATS, cctx, actx, TC), ([], cctx, actx, TC)]


def test_server_reversibility_class(monkeypatch):
    calls = _capture(monkeypatch)
    # signed irreversible is stricter than the server's reversible: pass, the signed class is effective
    r = run(context=lambda _p: {"reversibility_class": "reversible"})
    assert r.allow is True and r.checks["reversibility"] == "pass"
    assert calls[0][1]["reversibility_class"] == "irreversible" and calls[0][2]["action"]["reversibility_class"] == "irreversible"
    r = run(context=lambda _p: {"reversibility_class": "irreversible"})
    assert r.allow is True and r.checks["reversibility"] == "pass"
    assert "reversibility" not in run().checks


def test_server_reversibility_rank_seam(monkeypatch):
    calls = _capture(monkeypatch)
    # equal rank: the server's class is effective
    monkeypatch.setattr(Z, "_class_rank", lambda c: 1)
    r = run(context=lambda _p: {"reversibility_class": "zz"})
    assert r.checks["reversibility"] == "pass" and calls[-1][1]["reversibility_class"] == "zz"
    assert calls[-1][2]["action"]["reversibility_class"] == "zz"
    # the declared class is less restrictive than the authoritative one: refused, the server's class is effective
    monkeypatch.setattr(Z, "_class_rank", lambda c: {"irreversible": 0}.get(c, 1))
    del calls[:]
    r = run(context=lambda _p: {"reversibility_class": "zz"})
    assert r.allow is False and r.status == 403 and failed(r) == ["reversibility"]
    assert r.reason == "reversibility: declared class 'irreversible' is less restrictive than the authoritative 'zz'"
    assert calls[0][1]["reversibility_class"] == "zz"


# ---- authorize(): K1 narrow ----------------------------------------------------------------------------------------------

def _k1(monkeypatch, ret):
    calls = []

    def fake(grant, chain, kin, ctx):
        calls.append((copy.deepcopy(grant), copy.deepcopy(chain), copy.deepcopy(kin), copy.deepcopy(ctx)))
        return copy.deepcopy(ret)
    monkeypatch.setattr(Z, "evaluate_k1", fake)
    return calls


K1_OK = {"ok": True, "failed": [], "reasons": [], "plain": [], "bound": []}


def test_k1_narrow_triggers_evaluation(monkeypatch):
    calls = _k1(monkeypatch, K1_OK)
    p = copy.deepcopy(P0)
    r = run(pcactn=p, k1={"narrow": {"n": 1}, "pins": []})
    assert r.allow is True and r.checks["delegated_caveats"] == "pass"
    assert calls == [(G, P0["cap_chain"], {"narrow": {"n": 1}, "pins": [], "action_digest": discharge_action_digest(P0)},
                      {"now": NOW, "action": INNER})]
    for k1 in ({"pins": []}, {}, "narrow", None):
        del calls[:]
        assert run(k1=k1).allow is True and calls == []


def test_k1_failure_and_max_uses(monkeypatch):
    _k1(monkeypatch, {"ok": False, "failed": ["spiffe_id"], "reasons": ["r1", "r2"], "plain": [], "bound": []})
    r = run(k1={"narrow": {}})
    assert failed(r) == ["delegated_caveats"]
    assert r.reason == "delegated_caveats: delegation caveat(s) not satisfied: spiffe_id (r1; r2)"
    _k1(monkeypatch, dict(K1_OK, bound=[{"caveat": {"type": "max_uses", "n": 1}}]))
    r = run(k1={"narrow": {}})
    assert failed(r) == ["max_uses"]
    assert r.reason == "max_uses: the chain carries a max_uses caveat and this verifier has no uses_store (fail closed)"


# ---- authorize(): revocation staleness ------------------------------------------------------------------------------------

def _rs_patch(monkeypatch, ret, probe="cid"):
    seen = []

    def fake(policy, state, **kw):
        out = {"policy": policy, "state": state, "kw": kw}
        if kw.get("proof_for") is not None:
            out["proof"] = kw["proof_for"](probe)
        seen.append(out)
        return dict(ret)
    monkeypatch.setattr(Z, "check_revocation_state", fake)
    return seen


def test_revocation_staleness_forwarding_and_epoch_pin(monkeypatch):
    seen = _rs_patch(monkeypatch, {"ok": True, "epoch": 7})
    proofs, accepted = [], []
    rs = Z.RevocationStaleness(proof_for=lambda rid, p: proofs.append((rid, p)) or "PRF",
                               on_epoch_accepted=lambda e, p: accepted.append((e, p)))
    p = copy.deepcopy(P0)
    r = run(pcactn=p, revocation_staleness=rs,
            context=lambda _p: {"revocation_state": {"kind": "k"}, "reversibility_class": "reversible"})
    assert r.allow is True and r.checks["freshness"] == "pass"
    assert len(seen) == 1 and seen[0]["policy"] is rs and seen[0]["state"] == {"kind": "k"} and seen[0]["proof"] == "PRF"
    kw = seen[0]["kw"]
    assert sorted(kw) == ["grant_ref", "ids", "now", "pcactn_epoch", "proof_for", "server_class", "signed_class"]
    assert (kw["now"], kw["grant_ref"], kw["signed_class"], kw["server_class"], kw["pcactn_epoch"], kw["ids"]) == \
        (NOW, P0["grant_ref"], "irreversible", "reversible", 0, [P0["cap_chain"][0]["id"]])
    assert proofs == [("cid", p)] and proofs[0][1] is p
    assert accepted == [(7, p)] and accepted[0][1] is p


def test_revocation_staleness_variants(monkeypatch):
    ctx = lambda _p: {"revocation_state": {"kind": "k"}}  # noqa: E731
    seen = _rs_patch(monkeypatch, {"ok": True})
    accepted = []
    rs = Z.RevocationStaleness(on_epoch_accepted=lambda e, p: accepted.append(e), ids=lambda p: ["a", "b"])
    r = run(revocation_staleness=rs, context=ctx)
    assert r.allow is True and accepted == [] and seen[0]["kw"]["proof_for"] is None and seen[0]["kw"]["ids"] == ["a", "b"]
    assert seen[0]["kw"]["server_class"] is None
    seen = _rs_patch(monkeypatch, {"ok": True, "epoch": 3})
    r = run(revocation_staleness=Z.RevocationStaleness(on_epoch_accepted=_raise, ids=_raise), context=ctx)
    assert r.allow is True and seen[0]["kw"]["ids"] == [None]
    r = run(revocation_staleness=Z.RevocationStaleness(), context=ctx)
    assert r.allow is True
    seen = _rs_patch(monkeypatch, {"ok": False, "reason": "stale"})
    accepted = []
    r = run(revocation_staleness=Z.RevocationStaleness(on_epoch_accepted=lambda e, p: accepted.append(e)), context=ctx)
    assert r.allow is False and failed(r) == ["freshness"] and "freshness: stale" in r.reasons and accepted == []


def test_revocation_staleness_without_state(monkeypatch):
    seen = _rs_patch(monkeypatch, {"ok": True})
    r = run(revocation_staleness=Z.RevocationStaleness())
    assert failed(r) == ["freshness"] and seen == []
    assert "freshness: no verifiable (guardian-signed) revocation state for an irreversible action" in r.reasons
    r = run(revocation_staleness=Z.RevocationStaleness(allow_unsigned_root_for_irreversible=True))
    assert r.allow is True and r.checks["freshness"] == "not-enforced" and seen == []
    assert "freshness" not in run().checks


# ---- authorize_tool_call ----------------------------------------------------------------------------------------------

class RecOpts(Z.AuthorizeOptions):
    def run(self, pcactn, **kw):
        self.__dict__.setdefault("calls", []).append((pcactn, kw))
        return "RAN"


def test_authorize_tool_call_refusals():
    rg = lambda ref: None  # noqa: E731
    ok = RecOpts(state_store=Z.MemoryStateStore(), is_revoked=lambda p, g: False)
    kw = dict(verb="v", resource="r", params={}, audience="aud", resolve_grant=rg)
    assert Z.authorize_tool_call(object(), {}, **kw) == refused(
        403, "authorize_config", "authorize_config: authorize options are not an AuthorizeOptions (fail closed)", missing=["authorize"])
    assert Z.authorize_tool_call(Z.AuthorizeOptions(), {}, **kw) == refused(
        403, "authorize_config", "authorize_config: missing required component(s): state_store, is_revoked (fail closed)",
        missing=["state_store", "is_revoked"])
    assert Z.authorize_tool_call(ok, {}, **dict(kw, audience="")) == refused(
        403, "authorize_config", "authorize_config: missing required component(s): audience (fail closed)", missing=["audience"])
    nocap = refused(403, "operation", "operation: the tool declares no capability (verb:resource) to bind the proof to (fail closed)")
    for v, res in ((None, "r"), ("v", None), (5, "r"), ("v", 5)):
        assert Z.authorize_tool_call(ok, {}, **dict(kw, verb=v, resource=res)) == nocap
    assert Z.authorize_tool_call(ok, {}, **dict(kw, params=None)) == refused(
        403, "operation", "operation: the tool-call arguments could not be bound (pass them as keyword arguments) (fail closed)")
    assert getattr(ok, "calls", []) == []


def test_authorize_tool_call_forwards():
    rg = lambda ref: None  # noqa: E731
    ok = RecOpts(state_store=Z.MemoryStateStore(), is_revoked=lambda p, g: False)
    params = {"a": 1}
    assert Z.authorize_tool_call(ok, "PC", verb="v", resource="r", params=params, audience="aud", resolve_grant=rg,
                                 now=5, provenance="PV") == "RAN"
    assert ok.calls == [("PC", {"operation": {"verb": "v", "resource": "r", "params": {"a": 1}}, "audience": "aud",
                                "resolve_grant": rg, "now": 5, "provenance": "PV"})]
    assert ok.calls[0][1]["operation"]["params"] is not params
    Z.authorize_tool_call(ok, "PC", verb="", resource="", params={}, audience="aud", resolve_grant=rg)
    assert ok.calls[1] == ("PC", {"operation": {"verb": "", "resource": "", "params": {}}, "audience": "aud",
                                  "resolve_grant": rg, "now": None, "provenance": None})


# ---- require_pca (server.py) --------------------------------------------------------------------------------------------

def _core(monkeypatch, verdict):
    calls = []

    def fake(*a, **k):
        calls.append((a, k))
        return verdict
    monkeypatch.setattr(S, "verify_pcactn_core", fake)
    return calls


def _body(p):
    return json.dumps({"pcactn": p})


def test_require_pca_signature_only_paths(monkeypatch):
    v = Verdict(True, {"wire": True})
    calls = _core(monkeypatch, v)
    grant = {"id": "g"}
    p = {"grant_ref": "g"}
    g = S.require_pca(audience="aud", resolve_grant=lambda ref: grant if ref == "g" else None, signature_only=True, now=9,
                      intent_policy={"ip": 1}, intent_v2={"v": 2})
    assert g({}, _body(p)) == S.PCAResult(ok=True, status=200, verdict=v, pcactn=p, decision="allow")
    assert calls == [((p, grant), {"now": 9, "audience": "aud", "intent_policy": {"ip": 1}, "intent_v2": {"v": 2}, "fresh_at": None, "allowed_suites": None})]
    r = g({}, None)
    assert (r.ok, r.status, r.error, r.pcactn) == (False, 401, "absent", None)
    r = g({}, "{")
    assert (r.ok, r.status, r.error, r.pcactn) == (False, 401, "undecodable", None)
    for q in ({"grant_ref": 5}, {}):
        assert g({}, _body(q)) == S.PCAResult(ok=False, status=401, pcactn=q, error="malformed",
                                              www_authenticate='PCA realm="pca", audience="aud", error="invalid_pcactn", '
                                                               'error_description="malformed PCActn"')
    r = g({}, _body({"grant_ref": "nope"}))
    assert (r.ok, r.status, r.error, r.verdict) == (False, 401, "unknown_grant", None)


def test_require_pca_host_callbacks_fail_closed(monkeypatch):
    calls = _core(monkeypatch, Verdict(True, {}))
    p = {"grant_ref": "g"}
    ch = lambda d: 'PCA realm="pca", audience="aud", error="insufficient_authority", error_description="%s"' % d  # noqa: E731
    g = S.require_pca(audience="aud", resolve_grant=_raise, signature_only=True)
    assert g({}, _body(p)) == S.PCAResult(ok=False, status=403, pcactn=p, error="resolve_grant_error",
                                          www_authenticate=ch("grant resolution failed (fail closed)"))
    g = S.require_pca(audience="aud", resolve_grant=lambda ref: {"id": ref}, signature_only=True, fresh_at=_raise)
    assert g({}, _body(p)) == S.PCAResult(ok=False, status=403, pcactn=p, error="fresh_at_context_error",
                                          www_authenticate=ch("fresh_at verifier state unavailable (fail closed)"))
    g = S.require_pca(audience="aud", resolve_grant=lambda ref: {"id": ref}, signature_only=True, intent_v2=_raise)
    assert g({}, _body(p)) == S.PCAResult(ok=False, status=403, pcactn=p, error="intent_v2_context_error",
                                          www_authenticate=ch("intent v2 verifier state unavailable (fail closed)"))
    assert calls == []
    g = S.require_pca(audience="aud", resolve_grant=lambda ref: {"id": ref}, signature_only=True, intent_v2=lambda q: {"q": q})
    g({}, _body(p))
    assert calls[-1][1]["intent_v2"] == {"q": p}


def test_require_pca_deny_verdict(monkeypatch):
    p = {"grant_ref": "g"}
    for reason, err in (("policy: x", "policy: x"), (None, "insufficient_authority"), ("", "insufficient_authority")):
        v = Verdict(False, {"wire": True}, reason)
        _core(monkeypatch, v)
        g = S.require_pca(audience="aud", resolve_grant=lambda ref: {"id": ref}, signature_only=True)
        assert g({}, _body(p)) == S.PCAResult(ok=False, status=403, verdict=v, pcactn=p, error=err,
                                              www_authenticate='PCA realm="pca", audience="aud", error="insufficient_authority"')


def test_require_pca_fresh_at_side_carried(monkeypatch):
    calls = _core(monkeypatch, Verdict(True, {}))
    rg = lambda ref: {"id": ref}  # noqa: E731
    p = {"grant_ref": "g"}

    def fa_of(fresh_at, headers, q=p):
        del calls[:]
        S.require_pca(audience="aud", resolve_grant=rg, signature_only=True, fresh_at=fresh_at)(headers, _body(q))
        return calls[0][1]["fresh_at"]
    assert fa_of(lambda _q: {"x": 1}, {"pca-fresh-at": '{"t":1}'}) == {"x": 1, "side_carried": {"t": 1}}
    assert fa_of({"x": 1}, {"PCA-Fresh-At": '{"t":1}'}) == {"x": 1, "side_carried": {"t": 1}}
    assert fa_of({"x": 1}, {"pca-fresh-at": "x{"}) == {"x": 1, "side_carried": None}
    assert fa_of({"x": 1}, {}) == {"x": 1}
    assert fa_of({"x": 1, "side_carried": "s"}, {"pca-fresh-at": '{"t":1}'}) == {"x": 1, "side_carried": "s"}
    assert fa_of({"x": 1}, {"pca-fresh-at": '{"t":1}'}, q={"grant_ref": "g", "fresh_at": {}}) == {"x": 1}
    assert fa_of(None, {"pca-fresh-at": '{"t":1}'}) is None
    assert fa_of(lambda _q: None, {"pca-fresh-at": '{"t":1}'}) is None


def test_require_pca_exclusive_options():
    with pytest.raises(ValueError, match=r"^require_pca: signature_only and authorize are mutually exclusive$"):
        S.require_pca(audience="aud", resolve_grant=lambda r: None, signature_only=True, authorize={})


class GuardOpts(Z.AuthorizeOptions):
    def run(self, pcactn, **kw):
        self.__dict__.setdefault("calls", []).append((pcactn, kw))
        return self.__dict__["ret"]


def _gopts(ret, **kw):
    o = GuardOpts(state_store=Z.MemoryStateStore(), is_revoked=lambda p, g: False, **kw)
    o.__dict__["ret"] = ret
    return o


def test_require_pca_authorize_mode(monkeypatch):
    rg = lambda ref: None  # noqa: E731
    p = {"grant_ref": "g"}
    ok = Z.AuthorizeResult(allow=True, status=200, verdict=Verdict(True, {}), decision="allow", escalation={"answered_by": "x"})
    o = _gopts(ok)
    g = S.require_pca(audience="aud", resolve_grant=rg, authorize=o, now=4, intent_policy={"i": 1}, intent_v2={"v": 1},
                      fresh_at={"f": 1})
    body = _body(p)
    assert g({}, body, operation={"verb": "v"}) == S.PCAResult(ok=True, status=200, verdict=ok.verdict, pcactn=p, authorization=ok,
                                                              decision="allow", escalation={"answered_by": "x"})
    assert o.calls == [(p, {"operation": {"verb": "v"}, "audience": "aud", "resolve_grant": rg, "now": 4, "intent_policy": {"i": 1},
                            "intent_v2": {"v": 1}, "escalation_answer": None, "presented_k1": {}, "fresh_at": {"f": 1},
                            "workflow": None, "request": ({}, body), "allowed_suites": None})]
    for status, code in ((401, "invalid_pcactn"), (403, "insufficient_authority")):
        d = Z.AuthorizeResult(allow=False, status=status, reason="why", decision="escalate", escalation={"request": 1})
        g = S.require_pca(audience="aud", resolve_grant=rg, authorize=_gopts(d))
        assert g({}, body) == S.PCAResult(ok=False, status=status, verdict=None, pcactn=p, error="why",
                                          www_authenticate='PCA realm="pca", audience="aud", error="%s"' % code,
                                          authorization=d, decision="escalate", escalation={"request": 1})


def test_require_pca_authorize_operation_mapper():
    rg = lambda ref: None  # noqa: E731
    body = _body({"grant_ref": "g"})
    seen = []
    o = _gopts(Z.AuthorizeResult(allow=False, status=403))
    g = S.require_pca(audience="aud", resolve_grant=rg, authorize=o, operation=lambda h, b: seen.append((h, b)) or {"verb": "m"})
    g({"h": "1"}, body)
    assert seen == [({"h": "1"}, body)] and o.calls[-1][1]["operation"] == {"verb": "m"}
    g({}, body, operation={"verb": "x"})
    assert len(seen) == 1 and o.calls[-1][1]["operation"] == {"verb": "x"}
    g = S.require_pca(audience="aud", resolve_grant=rg, authorize=o, operation=_raise)
    g({}, body)
    assert o.calls[-1][1]["operation"] is None


def test_require_pca_authorize_workflow_gate():
    rg = lambda ref: None  # noqa: E731
    body = _body({"grant_ref": "g"})
    deny = Z.AuthorizeResult(allow=False, status=403)
    for wf in ("x", {"required": True}):
        o = _gopts(deny, workflow=wf)
        S.require_pca(audience="aud", resolve_grant=rg, authorize=o)({}, body)
        assert o.calls[0][0] is None and o.calls[0][1]["workflow"] is None
    o = _gopts(deny, workflow={"required": False})
    S.require_pca(audience="aud", resolve_grant=rg, authorize=o)({}, body)
    assert o.calls[0][0] == {"grant_ref": "g"}


def test_require_pca_default_authorize_refuses_without_components():
    g = S.require_pca(audience="aud", resolve_grant=lambda r: {"id": r})
    r = g({}, _body({"grant_ref": "g"}), operation=OP)
    assert (r.ok, r.status, r.error, r.decision) == \
        (False, 403, "authorize_config: missing required component(s): state_store, is_revoked (fail closed)", "deny")
    assert r.authorization.missing == ["state_store", "is_revoked"]
    assert r.www_authenticate == 'PCA realm="pca", audience="aud", error="insufficient_authority"'
    g = S.require_pca(audience="aud", resolve_grant=lambda r: {"id": r},
                      authorize={"state_store": Z.MemoryStateStore(), "is_revoked": lambda p, gr: False})
    assert g({}, None).status == 401


# ---- pep_obligation_gate (TS pepObligationGate) ----------------------------------------------------------------------------

LOG, NOTIFY, RECEIPT = {"kind": "log"}, {"kind": "notify", "params": {"to": "a"}}, {"kind": "require_receipt"}


def test_pep_gate_pass_through():
    gate = OB.pep_obligation_gate
    passthrough = lambda d: {"decision": d, "perform": [], "unsupported": []}  # noqa: E731
    assert gate("deny", True, [LOG], []) == passthrough("deny")
    assert gate("escalate", False, [LOG], []) == passthrough("escalate")
    assert gate("escalate", 1, [LOG], []) == passthrough("escalate")
    assert gate("weird", True, [LOG], []) == passthrough("deny")
    assert gate(None, True, None, []) == passthrough("deny")
    assert gate("escalate", True, [LOG], ["log"]) == {"decision": "allow", "perform": [LOG], "unsupported": []}


def test_pep_gate_allow_paths():
    gate = OB.pep_obligation_gate
    deny = lambda reason, uns=None: {"decision": "deny", "perform": [], "unsupported": uns or [], "reason": reason}  # noqa: E731
    assert gate("allow", False, None, []) == {"decision": "allow", "perform": [], "unsupported": []}
    assert gate("allow", False, [], []) == {"decision": "allow", "perform": [], "unsupported": []}
    lst = [LOG, NOTIFY]
    r = gate("allow", False, lst, ["notify", "log"])
    assert r == {"decision": "allow", "perform": lst, "unsupported": []} and r["perform"] is lst
    assert gate("allow", False, "x", []) == deny("malformed obligations: obligations must be an array")
    assert gate("allow", False, [{"kind": "zz"}], ["zz"]) == deny("malformed obligations: obligations[0]: unknown obligation kind 'zz'")
    assert gate("allow", False, [LOG], "log") == deny("the supported obligation kinds are malformed")
    assert gate("allow", False, [LOG], ["log", 5]) == deny("the supported obligation kinds are malformed")
    assert gate("allow", False, None, None) == deny("the supported obligation kinds are malformed")
    assert gate("allow", False, [NOTIFY, LOG, RECEIPT, {"kind": "log", "params": {"sink": "s"}}], ["require_receipt"]) == \
        deny("the enforcement point does not support obligation(s) log, notify", ["log", "notify"])
    assert gate("allow", False, [NOTIFY, LOG], ["log"]) == \
        deny("the enforcement point does not support obligation(s) notify", ["notify"])
    assert gate("allow", False, [LOG], []) == deny("the enforcement point does not support obligation(s) log", ["log"])


def test_pep_gate_fail_closed():
    class Bad(list):
        def __contains__(self, x):
            raise RuntimeError("x")
    assert OB.pep_obligation_gate("allow", False, [LOG], Bad(["log"])) == \
        {"decision": "deny", "perform": [], "unsupported": [], "reason": "evaluation error (fail closed)"}


# ---- Executor.__call__ ---------------------------------------------------------------------------------------------------

class FakeOpts:
    def __init__(self, r):
        self.r, self.calls = r, []

    def run(self, pcactn, **kw):
        self.calls.append((pcactn, kw))
        return self.r


EOP = {"verb": "v", "resource": "r", "params": {"a": 1}}


def _ex(r, store=None, **kw):
    store = O.MemoryOperationStore() if store is None else store
    opts = FakeOpts(r)
    clock = lambda: 77  # noqa: E731
    ex = O.Executor(operations=store, options=opts, audience="aud", resolve_grant=_raise, now=clock, **kw)
    return ex, opts, store, clock


def test_executor_store_required():
    ex = O.Executor(operations=None, options=FakeOpts(None), audience="aud", resolve_grant=_raise)
    assert ex({}, EOP, _raise) == O.ExecuteOutcome("refused", reason="createExecutor: missing required component: operations (fail closed)")
    assert ex.__dict__["_opts"].calls == []


def test_executor_denials():
    deny = Z.AuthorizeResult(allow=False, status=403, checks={"policy": "fail", "replay": "pass"}, reason="policy: x")
    ex, opts, _s, _c = _ex(deny)
    assert ex({"p": 1}, EOP, _raise, intent_policy="IP", intent_v2="V2", escalation_answer="EA", provenance="PV") == \
        O.ExecuteOutcome("denied", authorization=deny, reason="policy: x")
    assert opts.calls == [({"p": 1}, {"operation": EOP, "audience": "aud", "resolve_grant": _raise, "now": 77, "intent_policy": "IP",
                                      "intent_v2": "V2", "escalation_answer": "EA", "provenance": "PV"})]
    ex({"p": 1}, EOP, _raise)
    assert opts.calls[1][1] == {"operation": EOP, "audience": "aud", "resolve_grant": _raise, "now": 77, "intent_policy": None,
                                "intent_v2": None, "escalation_answer": None, "provenance": None}
    for r in (Z.AuthorizeResult(allow=False, status=401, checks={"replay": "fail"}, reason="replay: x"),
              Z.AuthorizeResult(allow=False, status=403, checks={"replay": "fail", "policy": "fail"}, reason="replay: x")):
        ex, _o, _s, _c = _ex(r)
        assert ex({"p": 1}, EOP, _raise) == O.ExecuteOutcome("denied", authorization=r, reason="replay: x")


def test_executor_replay_answered_from_record(monkeypatch):
    rep = Z.AuthorizeResult(allow=False, status=403, checks={"replay": "fail", "policy": "pass"}, reason="replay: r")
    denied = O.ExecuteOutcome("denied", authorization=rep, reason="replay: r")
    p = {"grant_ref": "g", "n": 1}
    rec = {"id": hash_canonical(p), "state": "committed", "verb": "v", "resource": "r", "params_digest": params_digest({"a": 1}),
           "result": 1}
    seen = []
    monkeypatch.setattr(O, "_from_record", lambda *a: seen.append(a) or "FROM")
    ex, _o, store, _c = _ex(rep, pending_timeout_ms=123)
    assert ex(p, EOP, _raise) == denied  # no record: the first attempt never reached execution
    assert ex("{", EOP, _raise) == denied
    store.create(rec)
    assert ex(p, EOP, _raise) == "FROM"
    assert seen == [(store, rec, 77, 123)]
    assert ex(json.dumps(p), EOP, _raise) == "FROM"
    for op in (dict(EOP, verb="x"), dict(EOP, resource="x"), dict(EOP, params={"a": 2}), None):
        assert ex(p, op, _raise) == denied
    ex2, _o, store2, _c = _ex(rep)
    store2.create(rec)
    del seen[:]
    ex2(p, EOP, _raise)
    assert seen == [(store2, rec, 77, O.OPERATION_PENDING_TIMEOUT_MS)]


def test_executor_allow_forwards(monkeypatch):
    allow = Z.AuthorizeResult(allow=True, status=200)
    seen = []
    monkeypatch.setattr(O, "execute_authorized", lambda *a, **k: seen.append((a, k)) or "EXEC")
    cls_calls = []
    ex, _o, store, clock = _ex(allow, recheck_for="reversible", pending_timeout_ms=123,
                               reversibility_class_of=lambda op: cls_calls.append(op) or "costly")
    fn = lambda h: None  # noqa: E731
    assert ex({"p": 1}, EOP, fn) == "EXEC"
    assert seen == [((allow, fn), {"store": store, "operation": EOP, "recheck": ex._recheck, "recheck_for": "reversible",
                                   "reversibility_class": "costly", "pending_timeout_ms": 123, "now": clock})]
    assert cls_calls == [EOP]
    ex({"p": 1}, "notadict", fn)
    assert seen[-1][1]["reversibility_class"] is None and seen[-1][1]["operation"] == "notadict" and cls_calls == [EOP]
    ex, _o, store, clock = _ex(allow)
    ex({"p": 1}, EOP, fn)
    assert seen[-1][1] == {"store": store, "operation": EOP, "recheck": ex._recheck, "recheck_for": "irreversible",
                           "reversibility_class": None, "pending_timeout_ms": O.OPERATION_PENDING_TIMEOUT_MS, "now": clock}


# ---- check_blueprints (TS checkBlueprints) -------------------------------------------------------------------------------

def _bp(id="bp1", key="K", **kw):
    b = {"id": id, "key": key, "status": "active", "ceiling": [], "epoch": 1, "operator": "op"}
    b.update(kw)
    return b


def _reg(*bps):
    return B.BlueprintRegistry(["op"], store={b["key"]: b for b in bps})


CHAIN = [{"issuer": "root", "holder": "K"}, {"issuer": "K", "holder": "inst"}]


def test_check_blueprints_bad_input():
    reg = _reg(_bp())
    bad = {"decision": "deny", "code": "bad_input"}
    for chain in (None, [], "x", [5], [{"issuer": "", "holder": "K"}], [{"issuer": "a"}], [{"issuer": "a", "holder": "h" * 129}],
                  [{"issuer": "i" * 129, "holder": "h"}], CHAIN + [{"issuer": 5, "holder": "x"}]):
        assert B.check_blueprints(chain, reg, 1, "any") == bad
    for now in (-1, 1.5, "1", None, 2 ** 53):
        assert B.check_blueprints(CHAIN, reg, now, "any") == bad
    assert B.check_blueprints([{"issuer": "i" * 128, "holder": "h" * 128}], reg, 0, "any") == {"decision": "allow", "governed": []}


def test_check_blueprints_min_epoch():
    reg = _reg(_bp(epoch=3), _bp(id="bp2", key="K2", epoch=2))
    assert B.check_blueprints(CHAIN, reg, 1, "any", 4) == {"decision": "escalate", "code": "stale_blueprint_state", "have": 3, "need": 4}
    assert B.check_blueprints(CHAIN, reg, 1, "any", 3) == {"decision": "allow", "governed": ["bp1"]}
    assert B.check_blueprints(CHAIN, _reg(), 1, "any", 1) == {"decision": "escalate", "code": "stale_blueprint_state", "have": 0, "need": 1}
    assert B.check_blueprints(CHAIN, _reg(), 1, "any", 0) == {"decision": "allow", "governed": []}


def test_check_blueprints_mode_and_link():
    assert B.check_blueprints(CHAIN, _reg(), 1, "require") == {"decision": "deny", "code": "no_blueprint"}
    assert B.check_blueprints(CHAIN, _reg(), 1, "any") == {"decision": "allow", "governed": []}
    assert B.check_blueprints(CHAIN, _reg(_bp()), 1, "require") == {"decision": "allow", "governed": ["bp1"]}
    # the first hop issued by a blueprint key, or a hop whose predecessor did not issue to the key
    assert B.check_blueprints([{"issuer": "K", "holder": "x"}], _reg(_bp()), 1, "any") == \
        {"decision": "deny", "code": "broken_link", "blueprint": "bp1"}
    assert B.check_blueprints([{"issuer": "root", "holder": "Z"}, {"issuer": "K", "holder": "x"}], _reg(_bp()), 1, "any") == \
        {"decision": "deny", "code": "broken_link", "blueprint": "bp1"}
    two = [{"issuer": "root", "holder": "K"}, {"issuer": "K", "holder": "K2"}, {"issuer": "K2", "holder": "i"}]
    assert B.check_blueprints(two, _reg(_bp(), _bp(id="bp2", key="K2")), 1, "require") == {"decision": "allow", "governed": ["bp1", "bp2"]}


def test_check_blueprints_status_expiry_depth():
    deny = lambda code: {"decision": "deny", "code": code, "blueprint": "bp1"}  # noqa: E731
    assert B.check_blueprints(CHAIN, _reg(_bp(status="disabled")), 1, "any") == deny("blueprint_disabled")
    assert B.check_blueprints(CHAIN, _reg(_bp(expires_at=10)), 9, "any") == {"decision": "allow", "governed": ["bp1"]}
    assert B.check_blueprints(CHAIN, _reg(_bp(expires_at=10)), 10, "any") == deny("blueprint_expired")
    assert B.check_blueprints(CHAIN, _reg(_bp(expires_at=10)), 11, "any") == deny("blueprint_expired")
    three = CHAIN + [{"issuer": "inst", "holder": "sub"}]
    assert B.check_blueprints(three, _reg(_bp(max_depth=2)), 1, "any") == {"decision": "allow", "governed": ["bp1"]}
    assert B.check_blueprints(three, _reg(_bp(max_depth=1)), 1, "any") == deny("too_deep")
    assert B.check_blueprints(CHAIN, _reg(_bp(max_depth=1)), 1, "any") == {"decision": "allow", "governed": ["bp1"]}
    # status before expiry before depth
    assert B.check_blueprints(three, _reg(_bp(status="disabled", expires_at=0, max_depth=1)), 5, "any") == deny("blueprint_disabled")
    assert B.check_blueprints(three, _reg(_bp(expires_at=0, max_depth=1)), 5, "any") == deny("blueprint_expired")


def test_check_blueprints_ceiling():
    ceiling = [{"type": "max_spend", "usd": 1}]
    bp = _bp(ceiling=ceiling)
    deny = lambda code, **kw: dict({"decision": "deny", "code": code, "blueprint": "bp1"}, **kw)  # noqa: E731
    assert B.check_blueprints(CHAIN, _reg(bp), 1, "any") == deny("ceiling_unevaluable")
    assert B.check_blueprints(CHAIN, _reg(bp), 1, "any", None, lambda c, b: None) == deny("ceiling_unevaluable")
    seen = []
    ev = lambda c, b: seen.append((c, b)) or {"ok": False, "failed": ["max_spend"]}  # noqa: E731
    assert B.check_blueprints(CHAIN, _reg(bp), 1, "any", None, ev) == deny("ceiling_violated", failed=["max_spend"])
    assert seen == [(ceiling, bp)]
    assert B.check_blueprints(CHAIN, _reg(bp), 1, "any", None, lambda c, b: {"ok": False}) == deny("ceiling_violated", failed=[])
    assert B.check_blueprints(CHAIN, _reg(bp), 1, "any", None, lambda c, b: {"ok": True}) == {"decision": "allow", "governed": ["bp1"]}
    # an empty ceiling is never evaluated
    assert B.check_blueprints(CHAIN, _reg(_bp()), 1, "any", None, _raise) == {"decision": "allow", "governed": ["bp1"]}


def test_check_blueprints_store_unreachable():
    reg = _reg(_bp(ceiling=[{"type": "x"}]))
    assert B.check_blueprints(CHAIN, reg, 1, "any", None, _raise) == {"decision": "deny", "code": "store_unreachable"}

    class Down(B.BlueprintRegistry):
        def epoch(self):
            raise RuntimeError("down")
    assert B.check_blueprints(CHAIN, Down(["op"]), 1, "any", 1) == {"decision": "deny", "code": "store_unreachable"}


# ---- authorize(): the allow result, revocation, required checks, the replay claim, max_uses ------------------------------

class ClaimStore:
    """A replay store without ``last``: ``ret`` is what claim answers (raises when it is an exception)."""

    def __init__(self, ret):
        self.ret, self.calls = ret, []

    def claim(self, key, counter):
        self.calls.append((key, counter))
        if isinstance(self.ret, Exception):
            raise self.ret
        return self.ret


HOLDER = P0["cap_chain"][-1]["holder"]


def test_allow_result_fields():
    r = run()
    assert (r.allow, r.status, r.reason, r.reasons, r.decision, r.escalation, r.undo, r.obligations, r.missing) == \
        (True, 200, None, [], "allow", None, None, None, None)
    assert r.operation == Z.AuthorizedOperation(verb="payments.send", resource="payments/acme",
                                                params_digest=P0["action"]["params_digest"], id=hash_canonical(P0))
    for name in ("operation", "grant_ref", "params_digest", "plan_root_authorized", "policy", "replay", "revocation", "provenance_flow",
                 "delegated_caveats"):
        assert r.checks[name] == "pass"
    assert r.checks["attestation"] == "not-enforced"


def test_revocation_outcomes():
    r = run(is_revoked=lambda _p, _g: True)
    assert (r.allow, r.status, failed(r), r.reason) == (False, 403, ["revocation"], "revocation: the grant is revoked")
    for hook in (_raise, lambda _p, _g: None, lambda _p, _g: 0):
        r = run(is_revoked=hook)
        assert (r.allow, r.status, failed(r), r.reason) == \
            (False, 403, ["revocation"], "revocation: the revocation check failed (fail closed)")


def test_require_list():
    dd = "%s: required check is %s (default-deny: not enforced by this resource server)"
    r = run(require=["nope"])
    assert (r.allow, failed(r), r.reason) == (False, ["nope"], dd % ("nope", "absent"))
    r = run(require=["attestation"])
    assert (r.allow, failed(r), r.reason) == (False, ["attestation"], dd % ("attestation", "not-enforced"))
    assert run(require=["counter"]).allow is True  # the old name of replay
    assert run(require=[5, "replay", "operation"]).allow is True


def test_assurance_policy_refused_before_the_replay_claim():
    store = ClaimStore(True)
    r = run(state_store=store, require_assurance="x")
    assert r.allow is False and r.checks["assurance"] == "fail" and r.reason.startswith("assurance: ") and store.calls == []


def test_replay_claim_outcomes():
    store = ClaimStore(True)
    assert run(state_store=store).allow is True
    assert store.calls == [(Z.state_key(G["id"], HOLDER), 1)]  # a store with no `last` stays on the 0.4 key
    assert run(state_store=ClaimStore(Z.ClaimResult(True))).allow is True
    assert run(state_store=ClaimStore((True,))).allow is True
    for ret, why in ((RuntimeError("x"), "replay: the replay store failed (fail closed)"),
                     (None, "replay: the replay store failed (fail closed)"),
                     (False, "replay: 1 was already claimed (replay)"),
                     (Z.ClaimResult(False), "replay: 1 was already claimed (replay)"),
                     (("yes",), "replay: 1 was already claimed (replay)"),
                     (1, "replay: 1 was already claimed (replay)"),
                     (Z.ClaimResult(False, 5), "replay: 1 is not greater than last seen 5 (replay)")):
        r = run(state_store=ClaimStore(ret))
        assert (r.allow, r.status, failed(r), r.reason) == (False, 403, ["replay"], why)


class LastStore(Z.MemoryStateStore):
    def __init__(self, last):
        super().__init__()
        self._last = last

    def last(self, key):
        if isinstance(self._last, Exception):
            raise self._last
        return self._last


def test_escalation_head_and_replay_boundary():
    # no provenance bundle: a sensitive action escalates; a replayed counter is a deny decided first
    r = run(provenance=None, state_store=LastStore(0))
    assert (r.allow, r.status, r.decision) == (False, 403, "escalate") and r.escalation is not None
    assert failed(r) == ["provenance_flow"]
    for last in (None, RuntimeError("x")):  # no history yet / an unreadable head: still an unanswered escalation
        r = run(provenance=None, state_store=LastStore(last))
        assert (r.allow, r.decision) == (False, "escalate") and r.escalation is not None
    for last in (1, 5):
        r = run(provenance=None, state_store=LastStore(last))
        assert (r.allow, r.status, r.decision, r.escalation) == (False, 403, "deny", None)
        assert failed(r) == ["provenance_flow", "replay"]
        assert "replay: 1 is not greater than last seen %d (replay)" % last in r.reasons


def test_max_uses_reserved_after_the_claim(monkeypatch):
    bound = [{"caveat": {"type": "max_uses", "n": 1}}]
    _k1(monkeypatch, dict(K1_OK, bound=bound))
    seen = []
    uses = object()
    monkeypatch.setattr(Z, "reserve_max_uses", lambda *a: seen.append(a) or {"ok": True})
    assert run(k1={"narrow": {}}, uses_store=uses).allow is True
    assert seen == [(uses, bound, NOW)]
    monkeypatch.setattr(Z, "reserve_max_uses", lambda *a: {"ok": False, "reason": "spent"})
    r = run(k1={"narrow": {}}, uses_store=uses)
    assert (r.allow, failed(r), r.reason) == (False, ["max_uses"], "max_uses: spent")
    # another K1 type never spends a slot, and needs no store
    _k1(monkeypatch, dict(K1_OK, bound=[{"caveat": {"type": "spiffe_id"}}, {"caveat": "x"}]))
    assert run(k1={"narrow": {}}).allow is True
