"""authorize(): the full pipeline (0.5, T6).

The signed fixtures come from the TypeScript reference (packages/pca/scripts/gen-authorize-fixtures.ts), which also
recorded the TypeScript authorize() outcome of every step (`ts`): each case asserts the exact Python outcome (allow,
status, sorted failing checks) and that it equals the TypeScript decision.
"""
import json
import multiprocessing
import os
import sqlite3
import threading

import pytest
import sys

from atlas_pca import (AuthorizeOptions, ClaimResult, MemoryStateStore, SqliteStateStore, authorize,
                       evaluate_agent_caveats, evaluate_tool_schema, is_authorized_for, policy_caveats, require_pca)
import atlas_pca.authorize  # noqa: F401  (the module; `atlas_pca.authorize` the attribute is the function)
from atlas_pca.pca import b64u, canonical_bytes_strict, hash_canonical

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as f:
    FIX = json.load(f)
CASES = FIX["cases"]
NOW = FIX["now"]
AUD = FIX["audience"]
with open(os.path.join(HERE, "conformance", "vectors.json"), encoding="utf-8") as f:
    CAVEAT_EVAL = json.load(f)["primitives"]["caveat_eval"]


def case(name):
    return next(c for c in CASES if c["name"] == name)


def settle(r):
    return {"allow": r.allow, "status": r.status, "failed": sorted(k for k, s in r.checks.items() if s == "fail")}


def run_case(c, store):
    revoked = {"v": False}
    out = []
    for s in c["steps"]:
        revoked["v"] = s["revoked"]
        r = authorize(s["pcactn"], operation=s["operation"], audience=AUD,
                      resolve_grant=lambda ref, g=c["grant"]: g if ref == g["id"] else None,
                      state_store=store, is_revoked=lambda p, g: revoked["v"], now=NOW, plan="single-step")
        got = settle(r)
        if "reason" in s["expect"]:  # the shared fixtures pin a substring of the decisive reason on some steps
            assert s["expect"]["reason"] in r.reason
            got["reason"] = s["expect"]["reason"]
        out.append(got)
    return out


# ---- the shared fixtures: exact outcome, and parity with the TypeScript authorize() --------------------------------

def test_fixture_shape():
    assert FIX["format"] == "pca-authorize-fixtures/1"
    assert len(CASES) >= 31
    # the TypeScript outcome was recorded for every step
    assert all("ts" in s for c in CASES for s in c["steps"])


@pytest.mark.parametrize("c", CASES, ids=[c["name"] for c in CASES])
def test_fixture_memory_store(c):
    got = run_case(c, MemoryStateStore())
    assert got == [s["expect"] for s in c["steps"]]
    assert [{"allow": g["allow"], "status": g["status"]} for g in got] == [s["ts"] for s in c["steps"]]


@pytest.mark.parametrize("c", CASES, ids=[c["name"] for c in CASES])
def test_fixture_sqlite_store(c, tmp_path):
    assert run_case(c, SqliteStateStore(str(tmp_path / "replay.db"))) == [s["expect"] for s in c["steps"]]


# ---- the reviewer acceptance, spelled out ----------------------------------------------------------------------------

def _authorize(c, step=0, **kw):
    s = c["steps"][step]
    opts = dict(operation=s["operation"], audience=AUD, resolve_grant=lambda ref: c["grant"],
                state_store=MemoryStateStore(), is_revoked=lambda p, g: False, now=NOW, plan="single-step")
    opts.update(kw)
    return authorize(s["pcactn"], **opts)


def test_400_under_100_refused_with_reason():
    r = _authorize(case("envelope-max-spend-400-refused"))
    assert settle(r) == {"allow": False, "status": 403, "failed": ["policy"]}
    assert r.reason == "policy: caveat(s) not satisfied: max_spend"
    r = _authorize(case("root-max-spend-400-refused"))
    assert r.reason == "policy: root caveat(s) not satisfied: max_spend"
    r = _authorize(case("delegated-max-spend-400-refused"))
    assert r.reason == "delegated_caveats: delegation caveat(s) not satisfied: max_spend"
    r = _authorize(case("envelope-predicate-400-refused"))
    assert r.reason == "policy: amount <= 100 not satisfied for payments.send on payments/acme"


def test_signed_50_executed_400_reports_the_binding_first():
    r = _authorize(case("envelope-max-spend-signed-50-executes-400"))
    assert r.reason == "operation: the proof's params_digest does not match the params of this payments.send operation"


def test_operation_x_for_y_reason():
    r = _authorize(case("operation-other-verb"))
    assert r.reason == ("operation: the proof is for payments.send on payments/acme, but this operation is "
                        "payments.refund on payments/acme")


def test_allow_binds_the_operation():
    c = case("envelope-max-spend-within")
    r = _authorize(c)
    s = c["steps"][0]
    assert r.allow is True and r.status == 200 and r.reason is None
    assert (r.operation.verb, r.operation.resource) == ("payments.send", "payments/acme")
    assert r.operation.params_digest == s["pcactn"]["action"]["params_digest"]
    assert r.operation.id == hash_canonical(s["pcactn"])
    assert is_authorized_for(r, s["operation"]) is True
    assert is_authorized_for(r, dict(s["operation"], params={"amount": 400, "currency": "usd"})) is False
    assert is_authorized_for(r, dict(s["operation"], verb="payments.refund")) is False
    assert is_authorized_for(r, None) is False
    denied = _authorize(case("envelope-max-spend-400-refused"))
    assert is_authorized_for(denied, case("envelope-max-spend-400-refused")["steps"][0]["operation"]) is False


def test_operation_params_are_copied_before_verification():
    c = case("envelope-max-spend-within")
    params = dict(c["steps"][0]["operation"]["params"])
    calls = []

    def revoked(p, g):  # runs after the copy: mutating the caller's dict must not change what was verified
        calls.append(1)
        params["amount"] = 400
        return False

    r = _authorize(c, operation=dict(c["steps"][0]["operation"], params=params), is_revoked=revoked)
    assert calls == [1] and r.allow is True


# ---- fail closed: configuration, operation, callbacks, store ---------------------------------------------------------

@pytest.mark.parametrize("missing,kw", [
    ("audience", {"audience": ""}),
    ("audience", {"audience": None}),
    ("resolve_grant", {"resolve_grant": None}),
    ("state_store", {"state_store": None}),
    ("state_store", {"state_store": object()}),
    ("is_revoked", {"is_revoked": None}),
])
def test_missing_component_refused_before_verification(missing, kw):
    c = case("envelope-max-spend-within")
    seen = []
    base = {"resolve_grant": lambda ref: seen.append(ref) or c["grant"]}
    base.update(kw)
    r = _authorize(c, **base)
    assert settle(r) == {"allow": False, "status": 403, "failed": ["authorize_config"]}
    assert r.missing == [missing] and seen == []


def test_all_missing_listed():
    r = authorize({}, operation=None, audience=None, resolve_grant=None, state_store=None, is_revoked=None)
    assert r.missing == ["audience", "resolve_grant", "state_store", "is_revoked"]


def test_unknown_plan_mode_refused():
    r = _authorize(case("envelope-max-spend-within"), plan="multi")
    assert r.missing == ["plan (only 'single-step' or None)"]


@pytest.mark.parametrize("op", [None, {}, {"verb": "payments.send", "resource": "payments/acme"},
                                {"verb": "payments.send", "resource": "payments/acme", "params": [1]},
                                {"verb": "", "resource": "payments/acme", "params": {}},
                                {"verb": "payments.send", "resource": "", "params": {}}])
def test_operation_required(op):
    r = _authorize(case("envelope-max-spend-within"), operation=op)
    assert settle(r) == {"allow": False, "status": 403, "failed": ["operation"]}


def test_no_plan_source_denies():
    r = _authorize(case("envelope-max-spend-within"), plan=None)
    assert settle(r) == {"allow": False, "status": 403, "failed": ["plan_root_authorized"]}
    assert r.reason.startswith("plan_root_authorized: required check is not-enforced")


def test_context_plan_must_be_authorized():
    c = case("envelope-max-spend-within")
    s = c["steps"][0]
    node = {"id": "n1", "verb": "payments.send", "resource": "payments/acme",
            "params_digest": s["pcactn"]["action"]["params_digest"], "reversibility_class": "irreversible"}
    ok = _authorize(c, plan=None, context=lambda p: {"plan": [node], "plan_authorized": True})
    assert ok.allow is True
    no = _authorize(c, plan=None, context=lambda p: {"plan": [node]})
    assert settle(no)["failed"] == ["plan_root_authorized"]
    other = _authorize(c, plan=None, context=lambda p: {"plan": [dict(node, verb="x")], "plan_authorized": True})
    assert other.reason == "plan_root_authorized: known plan does not match plan.root"


@pytest.mark.parametrize("ret", [None, 0, "no", [], ValueError])
def test_revocation_must_be_exactly_false(ret):
    def chk(p, g):
        if ret is ValueError:
            raise ValueError("down")
        return ret

    r = _authorize(case("envelope-max-spend-within"), is_revoked=chk)
    assert settle(r) == {"allow": False, "status": 403, "failed": ["revocation"]}


def test_store_failure_denies():
    class Broken:
        def claim(self, key, counter):
            raise sqlite3.OperationalError("locked")

    class Garbage:
        def claim(self, key, counter):
            return "yes"

    for st in (Broken(), Garbage()):
        r = _authorize(case("envelope-max-spend-within"), state_store=st)
        assert settle(r) == {"allow": False, "status": 403, "failed": ["replay"]}


def test_store_bool_and_key():
    seen = []

    class Rec:
        def claim(self, key, counter):
            seen.append((key, counter))
            return True

    c = case("envelope-max-spend-within")
    assert _authorize(c, state_store=Rec()).allow is True
    leaf = c["steps"][0]["pcactn"]["cap_chain"][-1]["holder"]
    assert seen == [("%s:%s" % (c["grant"]["id"], leaf), 1)]


def test_denied_request_never_reaches_the_store():
    seen = []

    class Rec:
        def claim(self, key, counter):
            seen.append(key)
            return ClaimResult(True)

    assert _authorize(case("envelope-max-spend-400-refused"), state_store=Rec()).allow is False
    assert seen == []


def test_callbacks_fail_closed():
    c = case("envelope-max-spend-within")

    def boom(*a):
        raise RuntimeError("x")

    assert settle(_authorize(c, resolve_grant=boom))["failed"] == ["resolve_grant"]
    assert settle(_authorize(c, context=boom))["failed"] == ["context"]
    assert settle(_authorize(c, context=lambda p: [1]))["failed"] == ["context"]
    assert settle(_authorize(c, intent_v2=boom))["failed"] == ["intent_v2"]
    unknown = _authorize(c, resolve_grant=lambda ref: None)
    assert settle(unknown) == {"allow": False, "status": 401, "failed": ["grant_ref"]}


def test_undecodable_and_absent_proofs():
    c = case("envelope-max-spend-within")
    op = c["steps"][0]["operation"]
    kw = dict(operation=op, audience=AUD, resolve_grant=lambda ref: c["grant"], state_store=MemoryStateStore(),
              is_revoked=lambda p, g: False, now=NOW, plan="single-step")
    assert settle(authorize(None, **kw)) == {"allow": False, "status": 401, "failed": ["wire"]}
    assert settle(authorize("{not json", **kw)) == {"allow": False, "status": 401, "failed": ["wire"]}
    assert settle(authorize(12, **kw)) == {"allow": False, "status": 401, "failed": ["wire"]}
    # JSON text of a valid proof is accepted
    assert authorize(json.dumps(c["steps"][0]["pcactn"]), **kw).allow is True


def test_zk_compliance_fails_closed():
    c = case("envelope-max-spend-within")
    p = dict(c["steps"][0]["pcactn"], zk_compliance={"x": 1})
    r = authorize(p, operation=c["steps"][0]["operation"], audience=AUD, resolve_grant=lambda ref: c["grant"],
                  state_store=MemoryStateStore(), is_revoked=lambda p, g: False, now=NOW, plan="single-step")
    assert r.allow is False and r.checks.get("zk_compliance") == "fail"


def test_require_adds_checks():
    r = _authorize(case("envelope-max-spend-within"), require=["freshness"])
    assert settle(r) == {"allow": False, "status": 403, "failed": ["freshness"]}


def test_reversibility_authoritative_class():
    c = case("envelope-max-spend-within")  # the agent declared "irreversible"
    assert _authorize(c, context=lambda p: {"reversibility_class": "reversible"}).checks["reversibility"] == "pass"
    unknown = _authorize(c, context=lambda p: {"reversibility_class": "nuclear"})  # unknown = most restrictive
    assert unknown.checks["reversibility"] == "pass"


def test_internal_error_denies(monkeypatch):
    monkeypatch.setattr(sys.modules["atlas_pca.authorize"], "verify_pcactn_core", lambda *a, **k: 1 / 0)
    r = _authorize(case("envelope-max-spend-within"))
    assert settle(r) == {"allow": False, "status": 403, "failed": ["authorize"]}


# ---- the replay stores -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("make", ["memory", "sqlite"])
def test_store_monotone(make, tmp_path):
    st = MemoryStateStore() if make == "memory" else SqliteStateStore(str(tmp_path / "r.db"))
    assert st.claim("k", 5) == ClaimResult(True)
    assert st.claim("k", 5) == ClaimResult(False, 5)
    assert st.claim("k", 4) == ClaimResult(False, 5)
    assert st.claim("k", 6) == ClaimResult(True)
    assert st.claim("other", 0) == ClaimResult(True)
    assert st.claim("other", 0) == ClaimResult(False, 0)


def test_sqlite_survives_reopen(tmp_path):
    path = str(tmp_path / "r.db")
    assert SqliteStateStore(path).claim("k", 1).ok is True
    assert SqliteStateStore(path).claim("k", 1) == ClaimResult(False, 1)


def test_sqlite_rejects_non_int_counter(tmp_path):
    st = SqliteStateStore(str(tmp_path / "r.db"))
    assert st.claim("k", True) == ClaimResult(False) and st.claim("k", "1") == ClaimResult(False)


@pytest.mark.parametrize("make", ["memory", "sqlite"])
def test_concurrent_claims_threads(make, tmp_path):
    st = MemoryStateStore() if make == "memory" else SqliteStateStore(str(tmp_path / "r.db"))
    barrier = threading.Barrier(16)
    wins = []

    def go():
        barrier.wait()
        if st.claim("k", 7).ok:
            wins.append(1)

    ts = [threading.Thread(target=go) for _ in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert wins == [1]


def _proc_claim(path, q):
    q.put(SqliteStateStore(path).claim("k", 9).ok)


def test_concurrent_claims_processes(tmp_path):
    path = str(tmp_path / "r.db")
    SqliteStateStore(path)  # create the table first
    ctx = multiprocessing.get_context("spawn")
    q = ctx.Queue()
    ps = [ctx.Process(target=_proc_claim, args=(path, q)) for _ in range(4)]
    for p in ps:
        p.start()
    for p in ps:
        p.join(60)
    assert sorted(q.get(timeout=5) for _ in ps) == [False, False, False, True]


def test_concurrent_authorize_same_proof_one_wins(tmp_path):
    c = case("envelope-max-spend-within")
    st = SqliteStateStore(str(tmp_path / "r.db"))
    barrier = threading.Barrier(8)
    res = []

    def go():
        barrier.wait()
        res.append(_authorize(c, state_store=st).allow)

    ts = [threading.Thread(target=go) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(res) == [False] * 7 + [True]


# ---- caveat semantics: conformance parity and the agent-native types ---------------------------------------------------

@pytest.mark.parametrize("v", CAVEAT_EVAL, ids=[v["name"] for v in CAVEAT_EVAL])
def test_caveat_eval_vectors_agent_evaluator(v):
    ctx = v["context"]
    ok, failed = evaluate_agent_caveats(policy_caveats(v["grant"], v["chain"]), ctx, {"action": ctx.get("action")})
    assert {"allow": ok, "failed": failed} == v["expect"]


def test_agent_caveats_predicates_and_unknown():
    ctx = {"now": 1, "action": {"verb": "pay", "resource": "inv:1", "params": {"amount": 5}}}
    actx = {"action": ctx["action"]}
    allow = {"type": "predicates", "allow": [{"verb": "pay", "resource": "inv:*"}]}
    deny = {"type": "predicates", "allow": [{"verb": "pay", "resource": "inv:2"}]}
    assert evaluate_agent_caveats([allow], ctx, actx) == (True, [])
    assert evaluate_agent_caveats([deny], ctx, actx) == (False, ["predicates"])
    assert evaluate_agent_caveats([{"type": "predicates", "allow": "x"}], ctx, actx) == (False, ["predicates"])
    assert evaluate_agent_caveats([allow], ctx, None) == (False, ["predicates"])
    assert evaluate_agent_caveats([{"type": "geo"}, 5], ctx, actx) == (False, ["geo", "<malformed>"])
    assert evaluate_agent_caveats("x", ctx, actx) == (False, ["<malformed caveats>"])
    assert evaluate_agent_caveats([], ctx, actx) == (True, [])


def _tool_caveat(schema, tool="pay", sig="sigdigest"):
    return {"type": "tool_schema", "tool": tool, "signature_digest": sig, "schema": schema,
            "schema_digest": hash_canonical(schema),
            "binding_digest": hash_canonical({"tool": tool, "signature_digest": sig, "schema": schema})}


def test_tool_schema_rules():
    cv = _tool_caveat({"props": {"n": {"type": "integer", "min": 0, "max": 10},
                                 "flag": {"type": "boolean", "const": True},
                                 "s": {"type": "string", "prefix": "ab", "maxLength": 3},
                                 "e": {"type": "number", "enum": [1, 2.5]},
                                 "o": {"type": "object", "props": {"x": {"type": "string"}}, "required": ["x"]},
                                 "a": {"type": "array", "items": {"type": "integer"}, "maxItems": 2}},
                       "required": ["n"]})
    ev = lambda args, **c: evaluate_tool_schema(cv, dict({"tool": "pay", "args": args}, **c))  # noqa: E731
    assert ev({"n": 3}) == (True, None)
    assert ev({"n": 3.0}) == (True, None)  # JS: 3.0 is an integer
    assert ev({"n": 3.5}) == (False, "args.n: wrong type (expected integer)")
    assert ev({"n": True}) == (False, "args.n: wrong type (expected integer)")  # a bool is never a number
    assert ev({"n": 11}) == (False, "args.n: above max")
    assert ev({}) == (False, "args: missing required argument 'n'")
    assert ev({"n": 1, "zz": 1}) == (False, 'args: unexpected argument "zz"')
    assert ev({"n": 1, "flag": 1}) == (False, "args.flag: wrong type (expected boolean)")
    assert ev({"n": 1, "flag": False}) == (False, "args.flag: violates const")
    assert ev({"n": 1, "s": "abc"}) == (True, None)
    assert ev({"n": 1, "s": "a\U0001F600"}) == (False, "args.s: violates prefix")
    assert ev({"n": 1, "s": "ab\U0001F600"}) == (False, "args.s: exceeds maxLength")  # UTF-16 length 4
    assert ev({"n": 1, "e": 2.5}) == (True, None)
    assert ev({"n": 1, "e": 3}) == (False, "args.e: violates enum")
    assert ev({"n": 1, "o": {}}) == (False, "args.o: missing required argument 'x'")
    assert ev({"n": 1, "a": [1, 2, 3]}) == (False, "args.a: exceeds maxItems")
    assert ev({"n": 1, "a": [1, "2"]}) == (False, "args.a[1]: wrong type (expected integer)")
    assert ev({"n": 1}, tool="refund") == (False, 'tool "refund" not authorized')
    assert ev({"n": 1}, tool_signature_digest="other") == (False, "signed tool_binding differs from the authorized tool signature")
    assert ev({"n": 1}, tool_signature_digest="sigdigest") == (True, None)


def test_tool_schema_caveat_integrity():
    schema = {"props": {"n": {"type": "number"}}}
    good = _tool_caveat(schema)
    call = {"tool": "pay", "args": {"n": 1}}
    assert evaluate_tool_schema(good, call)[0] is True
    assert evaluate_tool_schema(dict(good, schema_digest="x"), call) == (False, "schema digest mismatch")
    assert evaluate_tool_schema(dict(good, binding_digest="x"), call) == (False, "binding digest mismatch")
    assert evaluate_tool_schema(dict(good, tool=""), call) == (False, "malformed tool_schema caveat")
    bad = _tool_caveat({"props": {"n": {"type": "number", "pattern": "x"}}})
    assert evaluate_tool_schema(bad, call) == (False, "malformed tool_schema caveat: n: unknown spec key")
    assert evaluate_tool_schema(good, {"tool": "pay", "args": [1]}) == (False, "malformed call")


# ---- require_pca / FastAPI / Django: the acceptance before the handler runs ---------------------------------------------

def _hdr(p):
    return {"PCA-Action": b64u(canonical_bytes_strict(p))}


class _Server:
    """A tiny resource server over require_pca(authorize=...): the handler records what it executed."""

    def __init__(self, c, revoked=False):
        self.executed = []
        self.revoked = revoked
        self.guard = require_pca(
            audience=AUD, resolve_grant=lambda ref: c["grant"] if ref == c["grant"]["id"] else None, now=NOW,
            authorize=AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: self.revoked),
            operation=lambda headers, body: json.loads(body))

    def post(self, pcactn, op):
        r = self.guard(_hdr(pcactn), json.dumps(op))
        if r.ok:
            self.executed.append(op)
        return r


def test_require_pca_acceptance():
    within, over = case("envelope-max-spend-within"), case("envelope-max-spend-400-refused")
    srv = _Server(over)
    r = srv.post(over["steps"][0]["pcactn"], over["steps"][0]["operation"])
    assert (r.ok, r.status, r.error) == (False, 403, "policy: caveat(s) not satisfied: max_spend")
    assert r.www_authenticate == 'PCA realm="pca", audience="%s", error="insufficient_authority"' % AUD
    assert r.authorization.checks["policy"] == "fail"
    assert srv.executed == []

    srv = _Server(within)
    p, op = within["steps"][0]["pcactn"], within["steps"][0]["operation"]
    other = dict(op, verb="payments.refund")
    assert srv.post(p, other).status == 403 and srv.executed == []  # X used for Y
    ok = srv.post(p, op)
    assert ok.ok and ok.status == 200 and ok.authorization.operation.verb == "payments.send"
    assert srv.post(p, op).status == 403  # replay
    assert srv.executed == [op]

    srv = _Server(within, revoked=True)
    r = srv.post(p, op)
    assert (r.status, r.error) == (403, "revocation: the grant is revoked") and srv.executed == []


def test_require_pca_authorize_needs_an_operation():
    c = case("envelope-max-spend-within")
    g = require_pca(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW,
                    authorize={"state_store": MemoryStateStore(), "is_revoked": lambda p, g: False})
    r = g(_hdr(c["steps"][0]["pcactn"]))
    assert (r.ok, r.status, r.error) == (False, 403, "operation: authorize needs the operation to execute (verb, "
                                                    "resource, params) (fail closed)")
    assert g(_hdr(c["steps"][0]["pcactn"]), operation=c["steps"][0]["operation"]).ok is True
    boom = require_pca(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW,
                       authorize={"state_store": MemoryStateStore(), "is_revoked": lambda p, g: False},
                       operation=lambda h, b: 1 / 0)
    assert boom(_hdr(c["steps"][0]["pcactn"])).status == 403


def test_require_pca_authorize_missing_component():
    c = case("envelope-max-spend-within")
    g = require_pca(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW, authorize={"state_store": None},
                    operation=lambda h, b: c["steps"][0]["operation"])
    r = g(_hdr(c["steps"][0]["pcactn"]))
    assert r.status == 403 and r.authorization.missing == ["state_store", "is_revoked"]
    with pytest.raises(TypeError):
        require_pca(audience=AUD, resolve_grant=lambda ref: None, authorize=5)


def test_require_pca_authorize_wrong_audience_is_401():
    c = case("wrong-audience")
    g = require_pca(audience=AUD, resolve_grant=lambda ref: c["grant"], now=NOW,
                    authorize={"state_store": MemoryStateStore(), "is_revoked": lambda p, g: False},
                    operation=lambda h, b: c["steps"][0]["operation"])
    r = g(_hdr(c["steps"][0]["pcactn"]))
    assert r.status == 401 and r.www_authenticate.endswith('error="invalid_pcactn"')


def test_fastapi_acceptance():
    pytest.importorskip("fastapi")
    tc = pytest.importorskip("starlette.testclient")
    from fastapi import Depends, FastAPI

    from atlas_pca.fastapi import RequirePCA

    within, over = case("envelope-max-spend-within"), case("envelope-max-spend-400-refused")
    grants = {within["grant"]["id"]: within["grant"], over["grant"]["id"]: over["grant"]}
    revoked = {"v": False}
    executed = []

    async def operation(request, body):  # the route's own mapping: method + path + parsed body
        return {"verb": "payments.send", "resource": "payments/acme", "params": json.loads(body)}

    guard = RequirePCA(audience=AUD, resolve_grant=grants.get, now=NOW, operation=operation,
                       authorize=AuthorizeOptions(state_store=MemoryStateStore(),
                                                  is_revoked=lambda p, g: revoked["v"]))
    app = FastAPI()

    @app.post("/pay")
    async def pay(pca=Depends(guard)):
        executed.append(pca.operation.params_digest)
        return {"ok": True}

    client = tc.TestClient(app)
    post = lambda c, params: client.post("/pay", headers=_hdr(c["steps"][0]["pcactn"]), content=json.dumps(params))  # noqa: E731
    r = post(over, {"amount": 400, "currency": "usd"})
    assert r.status_code == 403 and r.json()["detail"] == "policy: caveat(s) not satisfied: max_spend"
    assert post(within, {"amount": 400, "currency": "usd"}).status_code == 403  # $50 proof, $400 body
    revoked["v"] = True
    assert post(within, {"amount": 50, "currency": "usd"}).status_code == 403
    revoked["v"] = False
    assert executed == []
    assert post(within, {"amount": 50, "currency": "usd"}).status_code == 200
    assert post(within, {"amount": 50, "currency": "usd"}).status_code == 403  # replay
    assert executed == [within["steps"][0]["pcactn"]["action"]["params_digest"]]

    # a proof for X used on a route that executes Y
    async def refund_op(request, body):
        return {"verb": "payments.refund", "resource": "payments/acme", "params": json.loads(body)}

    other = case("envelope-max-spend-within")
    g2 = RequirePCA(audience=AUD, resolve_grant=grants.get, now=NOW, operation=refund_op,
                    authorize=AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False))

    @app.post("/refund")
    async def refund(pca=Depends(g2)):
        executed.append("refund")
        return {"ok": True}

    r = client.post("/refund", headers=_hdr(other["steps"][0]["pcactn"]), content=json.dumps({"amount": 50, "currency": "usd"}))
    assert r.status_code == 403 and "refund" not in executed


def test_django_acceptance():
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

    within, over = case("envelope-max-spend-within"), case("envelope-max-spend-400-refused")
    grants = {within["grant"]["id"]: within["grant"], over["grant"]["id"]: over["grant"]}
    revoked = {"v": False}
    executed = []
    settings.PCA_AUDIENCE = AUD
    settings.PCA_RESOLVE_GRANT = grants.get
    settings.PCA_NOW = NOW
    settings.PCA_AUTHORIZE = {"state_store": MemoryStateStore(), "is_revoked": lambda p, g: revoked["v"]}
    settings.PCA_OPERATION = lambda request: {"verb": "payments.send", "resource": "payments/acme",
                                              "params": json.loads(request.body)}
    try:
        def view(request):
            executed.append(request.pca.operation.verb)
            return JsonResponse({"ok": True})

        mw = PCAMiddleware(view)
        rf = RequestFactory()
        post = lambda c, params: mw(rf.post("/pay", data=json.dumps(params), content_type="application/json",  # noqa: E731
                                            HTTP_PCA_ACTION=_hdr(c["steps"][0]["pcactn"])["PCA-Action"]))
        r = post(over, {"amount": 400, "currency": "usd"})
        assert r.status_code == 403 and json.loads(r.content)["error"] == "policy: caveat(s) not satisfied: max_spend"
        assert post(within, {"amount": 400, "currency": "usd"}).status_code == 403
        revoked["v"] = True
        assert post(within, {"amount": 50, "currency": "usd"}).status_code == 403
        revoked["v"] = False
        assert executed == []
        assert post(within, {"amount": 50, "currency": "usd"}).status_code == 200
        assert post(within, {"amount": 50, "currency": "usd"}).status_code == 403  # replay
        assert executed == ["payments.send"]
        settings.PCA_OPERATION = lambda request: {"verb": "payments.refund", "resource": "payments/acme",
                                                  "params": json.loads(request.body)}
        settings.PCA_AUTHORIZE = {"state_store": MemoryStateStore(), "is_revoked": lambda p, g: False}
        assert PCAMiddleware(view)(rf.post("/refund", data=json.dumps({"amount": 50, "currency": "usd"}),
                                           content_type="application/json",
                                           HTTP_PCA_ACTION=_hdr(within["steps"][0]["pcactn"])["PCA-Action"])).status_code == 403
        assert executed == ["payments.send"]
        del settings.PCA_OPERATION
        with pytest.raises(ImproperlyConfigured):
            PCAMiddleware(view)
        settings.PCA_AUTHORIZE = 5
        settings.PCA_OPERATION = lambda r: None
        with pytest.raises(ImproperlyConfigured):
            PCAMiddleware(view)
    finally:
        for n in ("PCA_AUTHORIZE", "PCA_OPERATION"):
            if hasattr(settings, n):
                delattr(settings, n)


# ---- the README samples run as written ---------------------------------------------------------------------------------

def _readme_blocks():
    with open(os.path.join(HERE, "README.md"), encoding="utf-8") as fh:
        text = fh.read()
    section = text[text.index("## Authorize an operation"):text.index("## Caveat enforcement")]
    return [b.split("```", 1)[0] for b in section.split("```python\n")[1:]]


def test_readme_samples_run(tmp_path, monkeypatch):
    import time

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(time, "time", lambda: NOW / 1000)  # the samples run on the wall clock; the fixtures are dated
    c = case("envelope-max-spend-within")
    sent = []
    env = {"pcactn": c["steps"][0]["pcactn"], "body": {"amount": 50, "currency": "usd"},
           "grants": {c["grant"]["id"]: c["grant"]}, "revoked_grant_ids": set(),
           "send_payment": lambda **kw: sent.append(kw)}
    authorize_block, guard_block = _readme_blocks()
    exec(compile(authorize_block, "README.md", "exec"), env)  # noqa: S102
    assert sent == [{"amount": 50, "currency": "usd"}] and env["result"].allow is True
    with pytest.raises(PermissionError, match="replay"):  # the same proof again: the SQLite store refuses it
        exec(compile(authorize_block, "README.md", "exec"), dict(env))  # noqa: S102
    env2 = {"json": json, "grants": env["grants"], "store": MemoryStateStore(), "is_revoked": lambda p, g: False}
    exec(compile(guard_block, "README.md", "exec"), env2)  # noqa: S102
    r = env2["guard"](_hdr(c["steps"][0]["pcactn"]), json.dumps({"amount": 50, "currency": "usd"}))
    assert r.ok is True and r.authorization.operation.verb == "payments.send"
