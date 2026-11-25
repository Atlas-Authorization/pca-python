"""k05 mutation kills (workflow group): workflow.py (shape validators, DAG, receipt chain, admission), k3.py (bundles, log
heads, list receipts and cursors, authority maths, amendments, need approval), k4.py (pricing, calibration, network-token
binding) and caveat_lang.py (narrow / discharge / max_uses / derive paths). Expectations follow the TypeScript reference
(workflow.ts, sig.ts, list-authorized.ts, grant-management, escalation-pricing.ts, caveat-lang.ts). Records are signed here."""
import json
import types

import pytest

from atlas_pca import caveat_lang as K
from atlas_pca import k3 as K3
from atlas_pca import k4 as K4
from atlas_pca import workflow as W
from atlas_pca.agent import KeyPair, _sign_body
from atlas_pca.pca import b64u, cap_hash, canonical_bytes_strict, hash_canonical

KP = KeyPair(bytes([1]) * 32)
KP2 = KeyPair(bytes([2]) * 32)


def _raiser(*_a, **_k):
    raise RuntimeError("boom")


# ===================================================================================================== workflow.py

P = KeyPair(bytes([81]) * 32)
RS = KeyPair(bytes([82]) * 32)
NOW = 1_800_000_000_000


def D(s):
    return hash_canonical({"v": s})


def step(i, deps=(), **o):
    s = dict(id=i, verb="v", resource="r", params_digest=None, deps=list(deps), sink=None, deny_labels=[], escalate_labels=[],
             fresh_ms=None, cost={})
    s.update(o)
    return s


def edge(f, t, op="eq", **o):
    e = dict({"from": {"step": f, "field": "out"}, "to": {"step": t, "param": "in"}}, op=op, unit=None, deny_labels=[], promise=None)
    e.update(o)
    return e


def body(**o):
    b = dict(v=1, id="w", principal=P.public, goal_digest=None, plan_root=None, issued_at=NOW - 10, expires_at=NOW + 10,
             steps=[step("a"), step("b", ["a"])], edges=[edge("a", "b")], budget={"max_steps": 5, "caps": {}})
    b.update(o)
    return b


def sign_wf(b, key=P):
    return {"body": b, "sig": _sign_body(key, W.WORKFLOW_DOMAIN, b)}


def rcpt(b, s, outputs=None, prev=None, outcome="ok", pd=None, issued=NOW - 1, **over):
    base = {"v": 1, "wf": W.workflow_digest(b), "step": s, "seq": prev["seq"] + 1 if prev else 0,
            "prev": W.receipt_ref(prev) if prev else None, "outcome": outcome, "params_digest": pd or D("p"),
            "outputs": outputs or {}, "issued_at": issued, "signer": RS.public}
    base.update(over)
    return dict(base, sig=_sign_body(RS, W.WF_RECEIPT_DOMAIN, base))


def wfo(value, labels=(), unit=None, num=False):
    return {"digest": W.value_digest(value), "num": value if num else None, "unit": unit, "labels": sorted(labels)}


def req(s, params, **o):
    r = dict(step=s, verb="v", resource="r", params=params, units={}, goal_digest=None, plan_root=None)
    r.update(o)
    return r


def inp(w, receipts, request, now=NOW):
    return {"workflow": w, "principal": P.public, "rs_signer": RS.public, "receipts": receipts, "now": now, "request": request}


def adm(w, receipts, request, now=NOW):
    return W.admit_step(inp(w, receipts, request, now))


def res(decision, code, stp, at=None, pending=()):
    return {"decision": decision, "code": code, "step": stp, "at": at, "pending": list(pending)}


def test_is_int_bounds():
    assert W.is_int(2**53 - 1) and W.is_int(-(2**53 - 1))
    assert not W.is_int(2**53) and not W.is_int(True) and not W.is_int(1.0)
    assert W.is_uint(0) and not W.is_uint(-1)


def test_scalar_and_uint_maps():
    assert W.is_scalar_map({"p%d" % i: 1 for i in range(32)})
    assert not W.is_scalar_map({"p%d" % i: 1 for i in range(33)})
    assert not W.is_scalar_map({"bad key": 1}) and not W.is_scalar_map({"k": 1.5}) and not W.is_scalar_map({"k": None})
    assert W._uint_map({"k": 1}, 8) and not W._uint_map({"bad key": 1}, 8) and not W._uint_map({"k": -1}, 8)
    assert not W._uint_map({"a": 1, "b": 1}, 1) and not W._uint_map([], 8)


def test_valid_step_single_faults():
    assert W._valid_step(step("a"))
    assert W._valid_step(step("a", verb="v" * 128, resource="r" * 512, params_digest=D("x"), sink="snk", fresh_ms=0, cost={"c": 0}))
    bad = [dict(id="bad id"), dict(verb=""), dict(verb="v" * 129), dict(resource=""), dict(resource="r" * 513), dict(params_digest="x"),
           dict(deps=["b", "a"]), dict(deps=["a", "a"]), dict(deps=["d%02d" % i for i in range(17)]), dict(sink="bad id"),
           dict(deny_labels=["B"]), dict(deny_labels=["b", "a"]), dict(escalate_labels=["B"]), dict(escalate_labels=["b", "a"]),
           dict(fresh_ms=-1), dict(fresh_ms=1.5), dict(cost={"bad key": 1}), dict(cost={"c": -1}),
           dict(cost={"c%d" % i: 1 for i in range(9)})]
    for o in bad:
        assert W._valid_step(step("a", **o)) is False, o
    s = step("a")
    s["extra"] = 1
    assert W._valid_step(s) is False and W._valid_step(None) is False
    s = step("a")
    del s["sink"]
    assert W._valid_step(s) is False
    assert W._valid_step(step("a", deps=["d%02d" % i for i in range(16)]))


def test_valid_edge_single_faults():
    assert W._valid_edge(edge("a", "b"))
    assert W._valid_edge(edge("a", "b", op="gt", unit="usd", deny_labels=["x", "y"], promise="p"))
    for op in W._OPS:
        assert W._valid_edge(edge("a", "b", op=op))
    bad = [dict(op="xx"), dict(op=5), dict(op=None), dict(unit="bad unit!"), dict(unit="u" * 17), dict(unit=5), dict(deny_labels=["b", "a"]),
           dict(deny_labels=["B"]), dict(promise="bad id"), dict(promise=5)]
    for o in bad:
        assert W._valid_edge(edge("a", "b", **o)) is False, o
    for mut in (lambda e: e.update({"from": None}), lambda e: e.update({"from": "ab"}), lambda e: e["from"].update(extra=1),
                lambda e: e["from"].update(step="bad id"), lambda e: e["from"].update(field="a b"),
                lambda e: e.update({"to": None}), lambda e: e.update({"to": "ab"}), lambda e: e["to"].update(extra=1),
                lambda e: e["to"].update(step="bad id"), lambda e: e["to"].update(param="a b"), lambda e: e.update(extra=1)):
        e = edge("a", "b")
        mut(e)
        assert W._valid_edge(e) is False
    assert W._valid_edge(None) is False


def test_valid_body_single_faults():
    assert W.valid_workflow_body(body()) is True
    assert W.valid_workflow_body(body(issued_at=2**53 - 1, expires_at=2**53 - 1))
    assert W.valid_workflow_body(body(plan_root=D("r"), goal_digest=D("g")))
    bad = [dict(v=2), dict(v=True), dict(id=""), dict(id="x" * 65), dict(id="__proto__"), dict(principal="x"), dict(goal_digest="x"),
           dict(plan_root="x"), dict(issued_at=-1), dict(issued_at=True), dict(issued_at=2**53), dict(expires_at=1.5),
           dict(steps=[], edges=[]), dict(steps="", edges=[]), dict(steps=tuple([step("a")]), edges=[]),
           dict(steps=[step("a"), step("a", verb="")], edges=[]), dict(steps=[step("s%d" % i) for i in range(65)], edges=[]),
           dict(edges={}), dict(edges=tuple([edge("a", "b")])), dict(edges=[edge("a", "b", op="xx")]),
           dict(edges=[edge("a", "b")] * 257), dict(budget=None), dict(budget={"max_steps": 1}),
           dict(budget={"max_steps": 1, "caps": {}, "extra": 1}), dict(budget=["max_steps", "caps"]),
           dict(budget={"max_steps": -1, "caps": {}}), dict(budget={"max_steps": True, "caps": {}}),
           dict(budget={"max_steps": 1, "caps": {"bad key": 1}}), dict(budget={"max_steps": 1, "caps": {"c": -1}}),
           dict(steps=[step("a", cost={"c": 1})], edges=[])]
    for o in bad:
        assert W.valid_workflow_body(body(**o)) is False, o
    assert W.valid_workflow_body(body(steps=[step("s%d" % i) for i in range(64)], edges=[]))
    assert W.valid_workflow_body(body(edges=[edge("a", "b")] * 256))
    assert W.valid_workflow_body(body(steps=[step("a", cost={"c": 1})], edges=[], budget={"max_steps": 1, "caps": {"c": 5}}))
    caps = {"c%d" % i: 5 for i in range(8)}
    assert W.valid_workflow_body(body(steps=[step("a", cost={k: 1 for k in caps})], edges=[], budget={"max_steps": 1, "caps": caps}))
    b = body()
    b["extra"] = 1
    assert W.valid_workflow_body(b) is False and W.valid_workflow_body(None) is False


def _rshape(**o):
    r = {"v": 1, "wf": D("w"), "step": "a", "seq": 0, "prev": None, "outcome": "ok", "params_digest": D("p"), "outputs": {},
         "issued_at": 1, "signer": D("s"), "sig": "x"}
    r.update(o)
    return r


def test_valid_receipt_shape_single_faults():
    assert W._valid_receipt_shape(_rshape()) is True
    assert W._valid_receipt_shape(_rshape(seq=1, prev=D("q"), outcome="failed")) is True
    out = lambda **k: dict({"digest": D("d"), "num": 1, "unit": "usd", "labels": ["a"]}, **k)  # noqa: E731
    assert W._valid_receipt_shape(_rshape(outputs={"o": out()}))
    assert W._valid_receipt_shape(_rshape(outputs={"o%d" % i: out() for i in range(32)}))
    bad = [dict(v=2), dict(wf="x"), dict(step="bad id"), dict(seq=-1), dict(prev=D("q")), dict(seq=1), dict(seq=1, prev="x"),
           dict(outcome="other"), dict(outcome=5), dict(params_digest="x"), dict(issued_at=-1), dict(signer="x"), dict(sig=5),
           dict(outputs=None), dict(outputs=[]), dict(outputs="x"), dict(outputs={"o%d" % i: out() for i in range(33)}),
           dict(outputs={"bad key": out()}), dict(outputs={"o": None}), dict(outputs={"o": []}),
           dict(outputs={"o": dict(out(), extra=1)}), dict(outputs={"o": out(digest="x")}), dict(outputs={"o": out(num=-1)}),
           dict(outputs={"o": out(num=1.5)}), dict(outputs={"o": out(unit="bad unit!")}), dict(outputs={"o": out(labels=["b", "a"])}),
           dict(outputs={"o": out(labels=["B"])})]
    for o in bad:
        assert W._valid_receipt_shape(_rshape(**o)) is False, o
    r = _rshape()
    r["extra"] = 1
    assert W._valid_receipt_shape(r) is False and W._valid_receipt_shape(None) is False
    o = out()
    del o["unit"]
    assert W._valid_receipt_shape(_rshape(outputs={"o": o})) is False


def test_valid_request_single_faults():
    assert W._valid_request(req("a", {})) is True
    assert W._valid_request(req("a", {"p": 1, "q": "s", "r": True}, verb="v" * 128, resource="r" * 512, units={"in": "usd"},
                                 goal_digest=D("g"), plan_root=D("r")))
    assert W._valid_request(req("a", {"p%d" % i: 1 for i in range(32)}))
    bad = [dict(step="bad id"), dict(verb=""), dict(verb="v" * 129), dict(resource=""), dict(resource="r" * 513), dict(params={"a": 1.5}),
           dict(params={"p%d" % i: 1 for i in range(33)}), dict(params=[]), dict(units=[]), dict(units={"bad key": "usd"}),
           dict(units={"in": "bad unit!"}), dict(units={"in": 5}), dict(goal_digest="x"), dict(plan_root="x")]
    for o in bad:
        r = req("a", {})
        r.update(o)
        assert W._valid_request(r) is False, o
    r = req("a", {})
    r["extra"] = 1
    assert W._valid_request(r) is False and W._valid_request(None) is False


def test_dag_error_exact():
    assert W.dag_error(body()) is None
    assert W.dag_error(body(steps=[step("a"), step("a")], edges=[])) == "duplicate step id"
    assert W.dag_error(body(steps=[step("a", ["a"])], edges=[])) == "bad dependency"
    assert W.dag_error(body(steps=[step("a", ["x"])], edges=[])) == "bad dependency"
    assert W.dag_error(body(steps=[step("a", ["b"]), step("b", ["a"])], edges=[])) == "cycle"
    assert W.dag_error(body(edges=[edge("b", "a")])) == "edge does not follow a dependency"
    assert W.dag_error(body(edges=[edge("a", "zz")])) == "edge does not follow a dependency"
    assert W.dag_error(body(edges=[edge("zz", "b")])) == "edge does not follow a dependency"
    assert W.dag_error(body(steps=[step("a"), step("b", ["a"]), step("c", ["b"])], edges=[edge("a", "c")])) is None


def test_ancestors_visits_each_step_once():
    reads = []

    class CD(dict):
        def __getitem__(self, k):
            if k == "deps":
                reads.append(self["id"])
            return super().__getitem__(k)
    steps = [CD(step("a")), CD(step("b", ["a"])), CD(step("c", ["a"])), CD(step("d", ["b", "c"]))]
    assert W.ancestors({"steps": steps}) == {"a": set(), "b": {"a"}, "c": {"a"}, "d": {"a", "b", "c"}}
    assert sorted(reads) == ["a", "b", "c", "d"]
    assert W.ancestors({"steps": [step("a", ["b"]), step("b", ["a"])]}) is None


def test_admit_basic_results_and_pins():
    w = sign_wf(body())
    assert adm(w, [], req("a", {})) == res("allow", None, "a")
    assert adm(w, [], req("zz", {})) == res("deny", "unplanned_step", "zz")
    assert adm(w, [], req("a", {}, verb="x")) == res("deny", "step_mismatch", "a")
    # principal and rs signer must be 32-byte keys (each checked on its own)
    i = inp(w, [], req("a", {}))
    assert W.admit_step(dict(i, principal="x")) == res("deny", "bad_workflow", None)
    assert W.admit_step(dict(i, rs_signer="x")) == res("deny", "bad_workflow", None)
    assert W.admit_step(dict(i, now=-1)) == res("deny", "bad_workflow", None)
    assert W.admit_step(dict(i, receipts="x")) == res("deny", "bad_workflow", None)
    assert W.bind_promises(None) == res("deny", "bad_workflow", None)


def test_receipt_chain_checks():
    b = body(steps=[step("d1"), step("d2"), step("x", ["d1", "d2"])], edges=[])
    w = sign_wf(b)
    d1 = rcpt(b, "d1")
    x = rcpt(b, "x", prev=d1)
    # d1 is receipted, d2 is not and has no promise: the second dependency is still checked
    assert adm(w, [d1, x], req("d2", {})) == res("deny", "bad_receipt", "d2", 1)
    # no edge at all / an unpromised edge from the missing dependency
    b1 = body(edges=[])
    assert adm(sign_wf(b1), [rcpt(b1, "b")], req("a", {})) == res("deny", "bad_receipt", "a", 0)
    b2 = body()
    assert adm(sign_wf(b2), [rcpt(b2, "b")], req("a", {})) == res("deny", "bad_receipt", "a", 0)
    # a promised edge admits it
    b3 = body(edges=[edge("a", "b", promise="dom")])
    assert adm(sign_wf(b3), [rcpt(b3, "b")], req("a", {})) == res("allow", None, "a")
    # one receipt per step
    ba = body(steps=[step("a"), step("z")], edges=[])
    a1 = rcpt(ba, "a")
    assert adm(sign_wf(ba), [a1, rcpt(ba, "a", prev=a1)], req("z", {})) == res("deny", "bad_receipt", "z", 1)
    # issued_at == now is fine, one more is future-dated; wrong signer / workflow / sequence refuse
    assert adm(sign_wf(ba), [rcpt(ba, "a", issued=NOW)], req("z", {})).get("code") is None
    assert adm(sign_wf(ba), [rcpt(ba, "a", issued=NOW + 1)], req("z", {}))["code"] == "bad_receipt"
    assert adm(sign_wf(ba), [rcpt(ba, "a", wf=D("other"))], req("z", {}))["code"] == "bad_receipt"
    assert adm(sign_wf(ba), [rcpt(ba, "a", prev=rcpt(ba, "z"))], req("z", {}))["code"] == "bad_receipt"


def test_pending_edge_does_not_end_the_checks():
    b = body(steps=[step("a"), step("c"), step("b", ["a", "c"])],
             edges=[edge("a", "b", promise="dom"), edge("c", "b", "le")])
    w = sign_wf(b)
    c_ok = rcpt(b, "c", {"out": wfo(5, num=True)})
    # the pending promised edge is skipped, the later edge is still enforced
    assert adm(w, [c_ok], req("b", {"in": 9})) == res("deny", "edge_relation", "b", 1)
    assert adm(w, [c_ok], req("b", {"in": 5})) == res("allow", None, "b", None, [0])
    # the promised dependency is skipped, the next dependency is still checked
    c_failed = rcpt(b, "c", {"out": wfo(5, num=True)}, outcome="failed")
    assert adm(w, [c_failed], req("b", {"in": 5})) == res("deny", "dep_failed", "b")


def test_bind_with_pending_edge_is_unmet():
    b = body(steps=[step("a"), step("b", ["a"]), step("c", ["b"])], edges=[edge("a", "b", promise="p"), edge("a", "c", promise="p")])
    w = sign_wf(b)
    pd = hash_canonical({"in": "x"})
    rb = rcpt(b, "b")
    rc = rcpt(b, "c", prev=rb, pd=pd)
    r = W.bind_promises(inp(w, [rb, rc], req("c", {"in": "x"})))
    assert r == res("deny", "deps_unmet", "c")


def test_plan_root_authorized_window_and_total():
    b = body(plan_root=D("root"))
    w = sign_wf(b)
    assert W.plan_root_authorized(w, P.public, NOW, D("root")) is True
    assert W.plan_root_authorized(w, P.public, b["issued_at"], D("root")) is True
    assert W.plan_root_authorized(w, P.public, b["issued_at"] - 1, D("root")) is False
    assert W.plan_root_authorized(w, P.public, b["expires_at"], D("root")) is False
    assert W.plan_root_authorized(w, P.public, NOW, D("other")) is False
    assert W.plan_root_authorized(w, RS.public, NOW, D("root")) is False
    assert W.plan_root_authorized(None, P.public, NOW, D("root")) is False


def test_plan_root_authorized_fail_closed_on_internal_error(monkeypatch):
    w = sign_wf(body(plan_root=D("root")))
    monkeypatch.setattr(W, "valid_workflow_body", _raiser)
    assert W.plan_root_authorized(w, P.public, NOW, D("root")) is False


# ============================================================================================================ k3.py

def test_is_str_bounds_and_u16key():
    assert K3.is_str("a" * 512, 512) and not K3.is_str("a" * 513, 512) and not K3.is_str("", 512) and not K3.is_str(5, 512)
    assert K3.u16key("\ud800") == b"\xd8\x00"
    assert K3.u16key("a") == b"\x00a"


def test_verify_body_total_and_exact():
    b = {"x": 1}
    sig = _sign_body(KP, "d\0", b)
    assert K3.verify_body("d\0", b, KP.public, sig) is True
    assert K3.verify_body("e\0", b, KP.public, sig) is False
    assert K3.verify_body("d\0", {"x": 1.5}, KP.public, "A" * 86) is False  # out of the canonical profile: refuse, never raise
    assert K3.verify_body("d\0", b, KP.public, sig + "A") is False and K3.verify_body("d\0", b, KP.public, 5) is False


def _bnd(**o):
    b = {"v": 1, "kind": "pca-policy-bundle", "revision": 1, "issued_at": 1, "grants": [], "template_digests": [],
         "min_verifier_version": "1.0.0"}
    b.update(o)
    return b


def test_bundle_shape_error_exact():
    assert K3.bundle_shape_error(_bnd()) is None
    assert K3.bundle_shape_error(_bnd(revision=2, prev="p" * 128)) is None
    assert K3.bundle_shape_error(_bnd(grants=["g" * 128] * 4096, template_digests=["t"] * 4096)) is None
    assert K3.bundle_shape_error(_bnd(schema_digest="s" * 128, constitution_digest="c", flow_rules_digest="f")) is None
    assert K3.bundle_shape_error(5) == "not a policy bundle"
    for rev in (0, -1, 1.5):
        assert K3.bundle_shape_error(_bnd(revision=rev)) == "bad revision or time", rev
    assert K3.bundle_shape_error(_bnd(revision="x")) == "bad revision or time"
    assert K3.bundle_shape_error(_bnd(issued_at=-1)) == "bad revision or time"
    prev = "prev must be absent at revision 1 and present after"
    assert K3.bundle_shape_error(_bnd(prev="p")) == prev
    assert K3.bundle_shape_error(_bnd(revision=2)) == prev
    assert K3.bundle_shape_error(_bnd(revision=2, prev="p" * 129)) == prev
    assert K3.bundle_shape_error(_bnd(revision=2, prev="")) == prev
    for v in (5, None, "x", ["g"] * 4097, ["g" * 129], [5], [""]):
        assert K3.bundle_shape_error(_bnd(grants=v)) == "bad grants", v
        assert K3.bundle_shape_error(_bnd(template_digests=v)) == "bad template_digests", v
    for k in ("schema_digest", "constitution_digest", "flow_rules_digest"):
        assert K3.bundle_shape_error(_bnd(**{k: "s" * 129})) == "bad " + k
        assert K3.bundle_shape_error(_bnd(**{k: ""})) == "bad " + k
    assert K3.bundle_shape_error(_bnd(min_verifier_version="x")) == "bad min_verifier_version"


def _signed_bundle(**o):
    b = _bnd(**o)
    return dict(b, sigs=[{"signer": KP.public, "sig": _sign_body(KP, K3.BUNDLE_DOMAIN, b)}])


def test_verify_bundle_limits_and_threshold():
    b = _signed_bundle()
    ok = K3.verify_bundle(b, [KP.public], 1, "1.0.0")
    assert ok["ok"] is True and ok["signers"] == [KP.public] and ok["revision"] == 1
    assert K3.verify_bundle(b, [KP.public], 2, "1.0.0") == {"ok": False, "code": "below_threshold", "reason": "1 valid pinned signature(s), need 2"}
    bad = {"ok": False, "code": "malformed", "reason": "bad sigs or threshold"}
    for t in (0, -1, 1.5, "1", None):
        assert K3.verify_bundle(b, [KP.public], t, "1.0.0") == bad, t
    assert K3.verify_bundle(dict(b, sigs=None), [KP.public], 1, "1.0.0") == bad
    assert K3.verify_bundle(b, "x", 1, "1.0.0") == bad
    assert K3.verify_bundle(dict(b, sigs=[{}] * 65), [KP.public], 1, "1.0.0") == bad
    assert K3.verify_bundle(dict(b, sigs=[{}] * 64), [KP.public], 1, "1.0.0")["code"] == "below_threshold"
    assert K3.verify_bundle(_bnd(grants=5), [KP.public], 1, "1.0.0")["reason"] == "bad grants"


def _head(**o):
    h = {"v": 1, "signer": KP.public, "size": 2, "issued_at": 5, "root": "r", "last_commit": "c"}
    h.update(o)
    return dict(h, sig=_sign_body(KP, K3.LOG_HEAD_DOMAIN, h))


def test_verify_log_head_single_faults():
    assert K3.verify_log_head(_head(), KP.public) is True
    for o in (dict(v=2), dict(signer=KP2.public), dict(size=-1), dict(size="2"), dict(issued_at=-1), dict(root=5), dict(last_commit=5)):
        assert K3.verify_log_head(_head(**o), KP.public) is False, o
    assert K3.verify_log_head(dict(_head(), size=3), KP.public) is False  # signature covers the size
    assert K3.verify_log_head(None, KP.public) is False and K3.verify_log_head({}, KP.public) is False


def test_log_head_and_inclusion_fail_closed(monkeypatch):
    h = _head()
    assert K3.verify_record_inclusion({"x": 1.5}, [], h, KP.public) is False  # record outside the canonical profile
    monkeypatch.setattr(K3, "verify_body", _raiser)
    assert K3.verify_log_head(h, KP.public) is False
    assert K3.verify_list_receipt(_lr(), KP.public) is False


def test_verify_batch_head_mismatch_exact():
    head = _head(size=1, last_commit="zzz")
    b = {"from": 0, "head": head, "records": [{"seq": 0, "prev": None}]}
    assert K3.verify_batch(b, {"next": 0, "lastCommit": None}, KP.public) == {"ok": False, "reason": "batch end does not match the signed head"}
    good = _head(size=1, last_commit=K3.record_commit({"seq": 0, "prev": None}))
    assert K3.verify_batch(dict(b, head=good), {"next": 0, "lastCommit": None}, KP.public) == {"ok": True, "next": 1, "lastCommit": good["last_commit"]}


def _lr(**o):
    r = {"v": 1, "signer": KP.public, "subject": "s", "resource_type": "t", "count": 1, "issued_at": 1}
    r.update(o)
    return dict(r, sig=_sign_body(KP, K3.LIST_RECEIPT_DOMAIN, r))


def test_verify_list_receipt_single_faults():
    assert K3.verify_list_receipt(_lr(), KP.public) is True
    assert K3.verify_list_receipt(_lr(subject="s" * 512, resource_type="t" * 512), KP.public) is True
    for o in (dict(v=2), dict(signer=KP2.public), dict(subject=""), dict(subject="s" * 513), dict(resource_type=""),
              dict(resource_type="t" * 513), dict(count=-1), dict(issued_at=-1), dict(count="1")):
        assert K3.verify_list_receipt(_lr(**o), KP.public) is False, o
    assert K3.verify_list_receipt(None, KP.public) is False


def _cursor(c, raw=None, key=KP, sig=None):
    payload = raw if raw is not None else json.dumps(c).encode("utf-8")
    s = sig if sig is not None else b64u(key.sign(K3.LIST_CURSOR_DOMAIN.encode("utf-8") + canonical_bytes_strict(c)))
    return b64u(payload) + "." + s


def _c(**o):
    c = {"v": 1, "bind": "b", "skip": 2, "signer": KP.public}
    c.update(o)
    return c


def test_verify_list_cursor_paths():
    M = {"ok": False, "reason": "malformed"}
    assert K3.verify_list_cursor(_cursor(_c()), KP.public) == {"ok": True, "skip": 2}
    assert K3.verify_list_cursor(_cursor(_c(inner="x")), KP.public) == {"ok": True, "inner": "x", "skip": 2}
    # a leading byte-order mark is skipped before parsing
    c = _c()
    assert K3.verify_list_cursor(_cursor(c, raw=b"\xef\xbb\xbf" + json.dumps(c).encode()), KP.public) == {"ok": True, "skip": 2}
    # invalid UTF-8 decodes with replacement characters
    raw = ('{"v":1,"bind":"b","skip":0,"signer":"%s","x":"' % KP.public).encode() + b"\xff" + b'"}'
    parsed = dict(_c(skip=0), x="�")
    assert K3.verify_list_cursor(_cursor(parsed, raw=raw), KP.public) == {"ok": True, "skip": 0}
    # JSON constants are refused as malformed, before any signature check
    nan = b'{"v":1,"bind":"b","skip":0,"signer":"%s","x":NaN}' % KP.public.encode()
    assert K3.verify_list_cursor(b64u(nan) + ".AAAA", KP.public) == M
    for t in (5, None, "", "x", "a.b.c", b64u(b"{}"), _cursor(_c(v=2)), _cursor(_c(bind=5)), _cursor(_c(skip=-1)), _cursor(_c(skip="2")),
              _cursor(_c(inner=5)), b64u(b"[]") + ".AAAA", b64u(b"not json") + ".AAAA"):
        assert K3.verify_list_cursor(t, KP.public) == M, t
    assert K3.verify_list_cursor(_cursor(_c()), KP2.public) == {"ok": False, "reason": "signature"}
    assert K3.verify_list_cursor(_cursor(_c(), sig="A" * 86), KP.public) == {"ok": False, "reason": "signature"}
    bind = {"subject": "s", "resourceType": "t", "filterId": "f", "policyDigest": "p", "limit": 1}
    assert K3.verify_list_cursor(_cursor(_c(bind=K3.list_bind(bind))), KP.public, bind) == {"ok": True, "skip": 2}
    assert K3.verify_list_cursor(_cursor(_c()), KP.public, bind) == {"ok": False, "reason": "bind"}
    assert K3.verify_list_cursor(_cursor(_c()), KP.public, {}) == {"ok": False, "reason": "bind"}


def test_resource_covering_and_subset():
    assert K3._res_covers("ab*", "abc") and not K3._res_covers("ab*", "ax") and K3._res_covers("ab*", "ab*")
    assert K3._res_covers("abc", "abc") and not K3._res_covers("abc", "abd")
    assert K3._res_subset(["a*"], ["a*"]) and not K3._res_subset(["a*"], ["a"]) and K3._res_subset(["ab"], ["a*"])
    assert not K3._res_subset(["a*"], ["ab*"]) and K3._res_subset([], []) and not K3._res_subset(["a"], [])


def test_authority_ok_bounds(monkeypatch):
    A = lambda **o: dict({"verbs": ["v"], "resources": ["r"]}, **o)  # noqa: E731
    assert K3.authority_ok(A()) is True
    assert K3.authority_ok(A(verbs=["v"] * 256, resources=["r"] * 1024)) is True
    assert K3.authority_ok(A(verbs=["v" * 128], resources=["r" * 512], limits={"k": 0}, expires_at=0)) is True
    for o in (dict(verbs=["v"] * 257), dict(verbs=["v" * 129]), dict(verbs=[""]), dict(verbs="v"), dict(resources=["r"] * 1025),
              dict(resources=["r" * 513]), dict(resources=[""]), dict(resources="r"), dict(limits=[]), dict(limits={"k": -1}),
              dict(expires_at=-1), dict(expires_at="1")):
        assert K3.authority_ok(A(**o)) is False, o
    assert K3.authority_ok(None) is False
    monkeypatch.setattr(K3, "is_obj", _raiser)
    assert K3.authority_ok(A()) is False


def test_merge_authority_keeps_omitted_ceiling():
    a = {"verbs": ["v"], "resources": ["r"], "limits": {"k": 5, "m": 1}}
    assert K3.merge_authority(a, {"verbs": ["w"], "resources": ["r"], "limits": {"m": 9}})["limits"] == {"k": 5, "m": 9}
    assert K3.merge_authority(a, {"verbs": [], "resources": []})["limits"] == {"k": 5, "m": 1}


def test_amendment_incomparable_widens():
    cur = {"id": "g", "rev": 1, "status": "active", "principal": KP.public, "agent": KP2.public,
           "authority": {"verbs": ["a"], "resources": ["r"]}}
    req_ = {"action": "replace", "authority": {"verbs": ["b"], "resources": ["r"]}, "signed_by": "holder", "sig": "x"}
    assert K3.verify_amendment(cur, req_, True) == {"ok": False, "code": "signature_required"}
    assert K3.verify_amendment(cur, dict(req_, action="narrow"), True) == {"ok": False, "code": "not_narrower"}


def _need(approved, needs, authority, adjustable=False):
    nr = {"id": "n1", "grant_id": "g1", "status": "pending", "needs": needs}
    g = {"rev": 1, "principal": KP.public, "authority": authority}
    sig = _sign_body(KP, K3.NEED_APPROVE_DOMAIN, K3.need_approve_message(nr, 1, approved))
    return nr, g, sig


def _item(k=10, **o):
    return dict({"verb": "v", "resource": "r", "limits": {"k": k}}, **o)


def test_need_approval_limits():
    auth = {"verbs": ["v"], "resources": ["r"], "limits": {"k": 0}}
    appr = [_item(10)]
    nr, g, sig = _need(appr, [_item(10, adjustable=False)], auth)
    assert K3.verify_need_approval(nr, g, appr, sig, True) == {"ok": True, "authority": {"verbs": ["v"], "resources": ["r"], "limits": {"k": 10}}}
    # an equal amount needs no adjustability; a lower one does
    appr = [_item(5)]
    nr, g, sig = _need(appr, [_item(10, adjustable=False)], auth)
    assert K3.verify_need_approval(nr, g, appr, sig, True) == {"ok": False, "code": "need_not_adjustable"}
    # the highest approved ceiling per limit wins across needs
    appr = [_item(10), _item(5)]
    nr, g, sig = _need(appr, [_item(10, adjustable=True), _item(10, adjustable=True)], auth)
    assert K3.verify_need_approval(nr, g, appr, sig, True)["authority"]["limits"] == {"k": 10}
    # a zero ceiling stays zero
    appr = [_item(0)]
    nr, g, sig = _need(appr, [_item(10, adjustable=True)], auth)
    assert K3.verify_need_approval(nr, g, appr, sig, True)["authority"]["limits"] == {"k": 0}
    appr = [_item(11)]
    nr, g, sig = _need(appr, [_item(10, adjustable=True)], auth)
    assert K3.verify_need_approval(nr, g, appr, sig, True) == {"ok": False, "code": "need_not_lowered_only"}


# ============================================================================================================ k4.py

PPM = K4.PPM


def _cfg(sign=True, drop=(), **o):
    c = {"v": 1, "principal": KP.public, "currency": "USD", "interruptionCost": 100, "maxInterruptionCost": 1000,
         "hardCeilingLoss": 100000, "tightenStepPpm": 1000, "epoch": 1}
    c.update(o)
    for k in drop:
        c.pop(k)
    if sign:
        c["sig"] = b64u(KP.sign(K4._msg("pca.escalation_pricing", {k: v for k, v in c.items() if k != "sig"})))
    return c


def test_pricing_config_error_exact():
    ok = _cfg()
    assert K4.pricing_config_error(ok) is None
    assert K4.pricing_config_error(_cfg(interruptionCost=1000)) is None  # equal to the maximum is allowed
    assert K4.pricing_config_error(_cfg(tightenStepPpm=0)) is None
    assert K4.pricing_config_error(_cfg(tightenStepPpm=K4.MAX_MULTIPLIER_PPM)) is None
    for c in (None, 5, dict(ok, v=2), dict(ok, v=True), dict(ok, principal=5), dict(ok, currency=5), dict(ok, sig=5)):
        assert K4.pricing_config_error(c) == "config_malformed", c
    for k in ("interruptionCost", "maxInterruptionCost", "hardCeilingLoss", "epoch"):
        assert K4.pricing_config_error(dict(ok, **{k: -1})) == "config_amounts_invalid"
    assert K4.pricing_config_error(_cfg(interruptionCost=1001)) == "config_cost_above_max"
    for st in (-1, K4.MAX_MULTIPLIER_PPM + 1):
        assert K4.pricing_config_error(_cfg(tightenStepPpm=st)) == "config_step_invalid", st
    assert K4.pricing_config_error(dict(ok, tightenStepPpm=1.5)) == "config_step_invalid"
    assert K4.pricing_config_error(_cfg(drop=("tightenStepPpm",))) == "config_step_invalid"
    assert K4.pricing_config_error(dict(ok, sig=b64u(bytes(64)))) == "config_signature_invalid"
    assert K4.pricing_config_error(_cfg(principal="!!", sign=False, sig="x")) == "config_malformed"
    # a key of the wrong length is a bad signature, decided before the body is even hashed
    short = dict(ok, principal=b64u(bytes(31)), sig=b64u(bytes(64)), extra=1.5)
    assert K4.pricing_config_error(short) == "config_signature_invalid"


def test_decide_escalation_input_checks():
    cfg, cal = _cfg(), {"multiplierPpm": PPM}
    a = lambda **o: dict({"currency": "USD", "loss": 1, "pBadUpperPpm": 0}, **o)  # noqa: E731
    assert K4.decide_escalation(cfg, cal, a()) == {"ask": False, "reason": "expected_loss_within_interruption_cost"}
    assert K4.decide_escalation(cfg, cal, a(pBadUpperPpm=PPM))["reason"] != "risk_input_invalid"
    bad = {"ask": True, "reason": "risk_input_invalid"}
    for o in (dict(loss=-1), dict(loss="1"), dict(pBadUpperPpm=None), dict(pBadUpperPpm=-1), dict(pBadUpperPpm=PPM + 1), dict(pBadUpperPpm=1.5)):
        assert K4.decide_escalation(cfg, cal, a(**o)) == bad, o
    assert K4.decide_escalation(cfg, None, a()) == {"ask": True, "reason": "calibration_invalid"}
    assert K4.decide_escalation(cfg, {"multiplierPpm": PPM - 1}, a())["reason"] == "calibration_invalid"
    assert K4.decide_escalation(cfg, cal, a(currency="EUR")) == {"ask": True, "reason": "currency_mismatch"}


def _ans(nonce, answer="deny", digest="d1", **o):
    a = {"v": 1, "principal": KP.public, "nonce": nonce, "action_digest": digest, "answer": answer}
    a.update(o)
    return dict(a, sig=b64u(KP.sign(K4._msg("pca.escalation_answer", a))))


def test_answer_ok_single_faults(monkeypatch):
    assert K4._answer_ok(_ans("n" * 8), KP.public) is True
    for o in (dict(v=2), dict(principal=KP2.public), dict(nonce="n" * 7), dict(nonce=5), dict(digest=5), dict(answer="maybe")):
        assert K4._answer_ok(_ans(**dict({"nonce": "n" * 8}, **o)), KP.public) is False, o
    assert K4._answer_ok(dict(_ans("n" * 8), sig=b64u(bytes(64))), KP.public) is False
    assert K4._answer_ok(None, KP.public) is False
    monkeypatch.setattr(K4, "_sig_ok", _raiser)
    assert K4._answer_ok(_ans("n" * 8), KP.public) is False


def test_update_calibration_processes_every_answer():
    cfg = _cfg()
    risks = {"d1": {"currency": "USD", "loss": 100, "pBadUpperPpm": 1000}, "d2": {"currency": "USD", "loss": 100, "pBadUpperPpm": 1000}}
    start = {"multiplierPpm": PPM, "seen": []}
    # an invalid answer first, a valid denial after it
    r = K4.update_calibration(cfg, start, [_ans("n" * 8, v=2), _ans("m" * 8, "deny", "d1")], risks)
    assert r == {"multiplierPpm": PPM + 1000, "seen": ["m" * 8]}
    # an approval first, a denial after it; a denial without a known risk is recorded but moves nothing
    r = K4.update_calibration(cfg, start, [_ans("a" * 8, "approve", "d1"), _ans("b" * 8, "deny", "zz"), _ans("c" * 8, "deny", "d2")], risks)
    assert r == {"multiplierPpm": PPM + 1000, "seen": ["a" * 8, "b" * 8, "c" * 8]}
    # a replayed nonce counts once
    r = K4.update_calibration(cfg, start, [_ans("c" * 8, "deny", "d2"), _ans("c" * 8, "deny", "d1")], risks)
    assert r["multiplierPpm"] == PPM + 1000


@pytest.mark.parametrize("n", [12, 13, 14, 19, 20])
def test_looks_like_pan_length_window(n):
    body_ = [int(c) for c in "5" * (n - 1)]
    s = sum((d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 == 0 else d for i, d in enumerate(reversed(body_)))
    num = "5" * (n - 1) + str((10 - s % 10) % 10)
    assert K4.looks_like_pan(num) is (13 <= n <= 19)


def test_luhn_digit_doubling():
    assert K4._luhn("5500000000000004") and K4._luhn("4111111111111111") and K4._luhn("79927398713")
    assert not K4._luhn("5500000000000005") and not K4._luhn("4111111111111112")
    assert K4.looks_like_pan("5500 0000-0000 0004") and not K4.looks_like_pan("hello")


H = KeyPair(bytes([9]) * 32)
_GRANT = {"g": 1}


def _nb(proof=None, **o):
    base = {"kind": K4.NETWORK_TOKEN_BINDING_KIND, "v": 1, "provider": "stripe", "token_ref": "tok_abcdefgh",
            "grant_digest": hash_canonical(_GRANT), "issuer_nonce": "n1", "holder": H.public}
    base.update(o)
    sig = proof if proof is not None else b64u(H.sign(hash_canonical(base).encode("utf-8")))
    return dict(base, binding_proof=sig)


def test_network_token_binding_paths():
    f = lambda b, holder=H.public, prov=None: K4.verify_network_token_binding(b, _GRANT, holder, "n1", prov)  # noqa: E731
    assert f(_nb()) is None and f(_nb(), prov="stripe") is None
    assert f(5) == "binding_malformed" and f(_nb(kind="x")) == "binding_malformed"
    assert f(_nb(provider="")) == "provider_mismatch"
    assert f(_nb(provider=None)) == "provider_mismatch"
    assert f(_nb(), prov="other") == "provider_mismatch"
    assert f(_nb(token_ref="x")) == "token_ref_malformed"
    assert f(_nb(token_ref="5500000000000004")) == "token_ref_looks_like_pan"
    assert f(_nb(grant_digest="x")) == "grant_digest_mismatch"
    assert f(_nb(), holder=KP.public) == "holder_mismatch"
    assert K4.verify_network_token_binding(_nb(), _GRANT, H.public, "n2") == "issuer_nonce_mismatch"
    assert f(_nb(proof=b64u(bytes(64)))) == "binding_proof_invalid"
    assert f(_nb(proof="!!")) == "binding_malformed"
    assert f(_nb(holder="!!"), holder="!!") == "binding_malformed"
    short = b64u(bytes(31))
    assert f(_nb(holder=short, proof="!!"), holder=short) == "binding_malformed"
    assert f(_nb(holder=short, proof=b64u(bytes(64))), holder=short) == "binding_proof_invalid"


# ===================================================================================================== caveat_lang.py

def test_bound_caveats_hop_of_introduction():
    h0 = {"caveats": [{"type": "a"}]}
    h1 = {"caveats": [{"type": "a"}, {"type": "b"}]}
    r = K.bound_caveats(None, [h0, h1])
    assert [(x["caveat"]["type"], x["hop"], x["cap_hash"]) for x in r] == [("a", 0, cap_hash(h0)), ("b", 1, cap_hash(h1))]
    assert K.bound_caveats(None, None) is None and K.bound_caveats({"caveats": 5}, None) is None


def test_spiffe_id_trust_domain_and_path_shapes():
    assert K.spiffe_id_error("spiffe://a") is None and K.spiffe_id_error("spiffe://a/b/c") is None
    assert K.spiffe_id_error("spiffe://a/") == "path must not end with a slash"
    assert K.spiffe_id_error("spiffe://a//b") == "invalid path segment"


def test_window_error_nonce_shapes():
    msg = "nonce must be canonical base64url of at least 16 bytes"
    assert K._window_error({"iat": 1, "not_after": 2, "nonce": 5, "sig": "x"}, "w") == msg
    assert K._window_error({"iat": 1, "not_after": 2, "nonce": b64u(bytes(15)), "sig": "x"}, "w") == msg
    assert K._window_error({"iat": 1, "not_after": 2, "nonce": b64u(bytes(16)), "sig": "x"}, "w") is None


def test_verify_discharge_and_narrow_fail_closed(monkeypatch):
    monkeypatch.setattr(K, "needs_discharge_error", _raiser)
    assert K.verify_discharge({}, {}, {"now": 1}) == {"ok": False, "reason": "discharge error (fail closed): boom"}
    monkeypatch.setattr(K, "narrow_shape_error", _raiser)
    assert K.verify_narrow({}, {}, None, {"now": 1}) == {"ok": False, "reason": "narrow error (fail closed): boom"}


def test_verify_narrow_post_quantum_key_selection(monkeypatch):
    seen = []
    monkeypatch.setattr(K, "narrow_shape_error", lambda n: None)
    monkeypatch.setattr(K, "cap_hash", lambda h: "CH")
    monkeypatch.setattr(K, "holder_pq_commitment", lambda pk: "C" + pk)
    monkeypatch.setattr(K, "verify_artifact_sig", lambda dom, n, sp: seen.append(sp) or False)
    n = {"holder": "H", "cap_hash": "CH", "pq_pk": "PK", "iat": 0, "not_after": 9}
    no_sig = {"ok": False, "reason": "narrow signature invalid"}
    assert K.verify_narrow(n, {"holder": "H", "holder_pq": "CPK"}, None, {"now": 1}) == no_sig
    assert K.verify_narrow(n, {"holder": "H", "holder_pq": "other"}, None, {"now": 1}) == no_sig
    assert K.verify_narrow(n, {"holder": "H"}, None, {"now": 1}) == no_sig
    n2 = {k: v for k, v in n.items() if k != "pq_pk"}
    assert K.verify_narrow(n2, {"holder": "H", "holder_pq": "CPK"}, None, {"now": 1}) == no_sig
    assert K.verify_narrow(n2, {"holder": "H"}, None, {"now": 1}) == no_sig
    assert seen == [{"pk": "H", "pq_pk": "PK"}, {"pk": "H"}, {"pk": "H"}, {"pk": "H"}, {"pk": "H"}]


def test_evaluate_k1_passes_grant_and_narrow_caveats(monkeypatch):
    calls = []
    monkeypatch.setattr(K, "cap_hash", lambda h: "H%s" % h["id"])
    monkeypatch.setattr(K, "verify_narrow", lambda *a: calls.append(a) or {"ok": True, "caveats": [{"type": "rate"}, {"type": "sealed"}]})
    grant = {"id": 1, "caveats": [{"type": "sealed"}]}
    r = K.evaluate_k1(grant, None, {"narrow": "N", "action_digest": "AD"}, {"now": 5})
    assert calls == [("N", grant, None, {"now": 5, "action_digest": "AD"})]
    assert r["ok"] is True and r["plain"] == [{"type": "rate"}]
    assert r["bound"] == [{"caveat": {"type": "sealed"}, "hop": 0, "cap_hash": "H1"}, {"caveat": {"type": "sealed"}, "hop": 0, "cap_hash": "H1"}]
    monkeypatch.setattr(K, "verify_narrow", lambda *a: {"ok": False, "reason": "why"})
    r = K.evaluate_k1(grant, None, {"narrow": "N"}, {"now": 5})
    assert (r["ok"], r["failed"], r["reasons"]) == (False, ["narrow"], ["why"])


def test_evaluate_k1_discharge_binding_defaults(monkeypatch):
    seen = []
    monkeypatch.setattr(K, "needs_discharge_error", lambda c: None)
    monkeypatch.setattr(K, "cap_hash", lambda h: "CH")
    monkeypatch.setattr(K, "verify_discharge", lambda d, c, b: seen.append(b) or {"ok": False, "reason": "r"})
    grant = {"caveats": [{"type": "needs_discharge", "id": "d1"}]}
    r = K.evaluate_k1(grant, None, {"discharges": [{"caveat_id": "d1"}]}, {"now": 5})
    assert (r["ok"], r["failed"], r["reasons"]) == (False, ["needs_discharge"], ["r"])
    K.evaluate_k1(grant, None, {"discharges": [{"caveat_id": "d1"}], "pins": ["p"], "action_digest": "AD", "revoked_discharges": ["x"]}, {"now": 5})
    assert seen == [{"cap_hash": "CH", "pins": [], "now": 5}, {"cap_hash": "CH", "pins": ["p"], "now": 5, "action_digest": "AD", "revoked": ["x"]}]


def test_evaluate_k1_duplicate_ids_fail():
    grant = {"caveats": [{"type": "max_uses", "id": "m1", "n": 1, "until": 100}, {"type": "max_uses", "id": "m1", "n": 1, "until": 100}]}
    r = K.evaluate_k1(grant, None, {}, {"now": 5})
    assert r["failed"] == ["max_uses", "max_uses"] and r["reasons"] == ["duplicate max_uses id 'm1'"] * 2
    one = {"caveats": [{"type": "max_uses", "id": "m1", "n": 1, "until": 100}]}
    assert K.evaluate_k1(one, None, {}, {"now": 5})["ok"] is True
    assert K.evaluate_k1(one, None, {}, {"now": 100})["reasons"] == ["max_uses 'm1' has expired"]


class _Once:
    def __init__(self, res):
        self.res, self.calls = list(res), []

    def consume_once(self, slot, until, now):
        self.calls.append((slot, until, now))
        return self.res.pop(0)


class _Claim:
    def __init__(self, res):
        self.res, self.calls = list(res), []

    def claim(self, key, n):
        self.calls.append((key, n))
        return types.SimpleNamespace(ok=self.res.pop(0))


def _mu(**o):
    return dict({"type": "max_uses", "id": "m1", "n": 2, "until": 100}, **o)


def test_reserve_max_uses_slots_and_messages():
    bound = [{"caveat": _mu(), "cap_hash": "ch"}]
    keys = [K.max_uses_slot_key("ch", "m1", i) for i in range(2)]
    s = _Once([False, True])
    assert K.reserve_max_uses(s, bound, 5) == {"ok": True, "spent": 1}
    assert s.calls == [(keys[0], 100, 5), (keys[1], 100, 5)]
    s = _Once([True])
    assert K.reserve_max_uses(s, bound, 5) == {"ok": True, "spent": 1} and s.calls == [(keys[0], 100, 5)]
    exhausted = {"ok": False, "reason": "max_uses 'm1' is exhausted"}
    s = _Once([False, 1])  # only an identical True counts
    assert K.reserve_max_uses(s, bound, 5) == exhausted and len(s.calls) == 2
    s = _Claim([False, True])
    assert K.reserve_max_uses(s, bound, 5) == {"ok": True, "spent": 1}
    assert s.calls == [(keys[0], 1), (keys[1], 1)]
    assert K.reserve_max_uses(_Claim([False, False]), bound, 5) == exhausted
    assert K.reserve_max_uses(_Once([]), [{"caveat": _mu(n=0), "cap_hash": "ch"}], 5) == \
        {"ok": False, "reason": "malformed max_uses caveat: n must be 1..%d" % K.MAX_USES_LIMIT}
    assert K.reserve_max_uses(_Once([True, True]), bound * 2, 5) == {"ok": False, "reason": "duplicate max_uses id 'm1'"}
    assert K.reserve_max_uses(_Once([]), bound, 100) == {"ok": False, "reason": "max_uses 'm1' has expired"}
    assert K.reserve_max_uses(_Once([]), bound, "x")["reason"] == "the verifier clock is not a safe integer (fail closed)"
    assert K.reserve_max_uses(_Once([]), None, 5)["reason"].startswith("max_uses error (fail closed): ")


def test_evaluate_derive_count_window():
    c = {"defs": [{"name": "n", "kind": "count", "window_ms": 10}], "check": {"op": "gte", "a": {"ref": "n"}, "b": {"const": 2}}}
    h = lambda t: {"t": t, "verb": "v", "resource": "r"}  # noqa: E731
    assert K.evaluate_derive(c, {"now": 100, "history": [h(95), h(100)]}) is True
    assert K.evaluate_derive(c, {"now": 100, "history": [h(90), h(100)]}) is False  # t == now - window is outside
    assert K.evaluate_derive(c, {"now": 100, "history": [h(101), h(100)]}) is False
    assert K.evaluate_derive(c, {"now": 100, "history": [h(95), {"t": "x"}, h(100)]}) is None
    assert K.evaluate_derive(c, {"now": 100}) is None
