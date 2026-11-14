"""k05 mutation kills (intent group): caveat_lang (spiffe_id_error, evaluate_caveats_k1 and evaluate_k1 guards), k3
(verify_amendment, verify_revoke_signature), k4 (verify_granted_permission) and policy_link (template_def_error,
tighten_overlay_error, verify_linked_policy). Expectations are the TypeScript reference (caveat-lang.ts,
pca-grants/src/grant-resource.ts, pca-erc7715/src/index.ts, policy-link.ts); inputs are the shared conformance vectors."""
import copy

import pytest

from atlas_pca import caveat_lang as K
from atlas_pca import k3 as K3
from atlas_pca import k4 as K4
from atlas_pca import policy_link as PL
from test_k3_vectors import DOC as K3_DOC
from test_k4_vectors import DOC as K4_DOC
from test_policy_link import DOC as PL_DOC


# ---- caveat_lang ------------------------------------------------------------------------------------------------------

def test_spiffe_id_error_table():
    TOO_LONG, TD, SEG = "SPIFFE ID is too long", "invalid trust domain", "invalid path segment"
    for ok in ("spiffe://a", "spiffe://a.b-c_d", "spiffe://a/b", "spiffe://a/b.c-d_e/F", "spiffe://a/..b",
               "spiffe://" + "a" * 255, "spiffe://a/" + "b" * 2037):
        assert K.spiffe_id_error(ok) is None
    for bad in ("", 5, None):
        assert K.spiffe_id_error(bad) == "SPIFFE ID must be a non-empty string"
    assert K.spiffe_id_error("spiffe://a/" + "b" * 2038) == TOO_LONG
    assert K.spiffe_id_error("spiffe://a/" + "é" * 1019) == TOO_LONG  # the bound is UTF-8 bytes, not characters
    for bad in ("SPIFFE://a", "http://a", "spiffe:/a"):
        assert K.spiffe_id_error(bad) == "SPIFFE ID must begin with spiffe://"
    for bad in ("spiffe://", "spiffe:///b", "spiffe://A", "spiffe://a b", "spiffe://" + "a" * 256):
        assert K.spiffe_id_error(bad) == TD
    for bad in ("spiffe://a/", "spiffe://a/b/"):
        assert K.spiffe_id_error(bad) == "path must not end with a slash"
    for bad in ("spiffe://a//b", "spiffe://a/.", "spiffe://a/..", "spiffe://a/b/./c", "spiffe://a/b c"):
        assert K.spiffe_id_error(bad) == SEG


def _raiser(*_a, **_k):
    raise RuntimeError("boom")


@pytest.mark.parametrize("seam", ["evaluate_k1", "policy_caveats", "evaluate_caveats"])
def test_evaluate_caveats_k1_internal_error_refuses(monkeypatch, seam):
    monkeypatch.setattr(K, seam, _raiser)
    assert K.evaluate_caveats_k1({"caveats": []}, None, {}, {"now": 1}) == (False, ["<malformed>"])


def _caveats_k1(monkeypatch, k1_ok, stock_ok, cs=None, context=None):
    seen = {}

    def ev(grant, chain, k1, ctx):
        seen["k1"] = (grant, chain, k1, ctx)
        return {"ok": k1_ok, "failed": ["m"] if not k1_ok else [], "plain": [{"type": "p"}]}

    def st(stock, ctx):
        seen["stock"] = (stock, ctx)
        return stock_ok, ["z", "a"] if not stock_ok else []
    monkeypatch.setattr(K, "evaluate_k1", ev)
    monkeypatch.setattr(K, "evaluate_caveats", st)
    monkeypatch.setattr(K, "policy_caveats", lambda g, c: cs)
    return K.evaluate_caveats_k1("G", "C", "K", context), seen


def test_evaluate_caveats_k1_merges_both_verdicts(monkeypatch):
    cs = [{"type": "rate"}, {"type": "sealed"}]
    ctx = {"now": 7, "action": "A", "x": 1}
    r, seen = _caveats_k1(monkeypatch, True, True, cs, ctx)
    assert r == (True, [])
    assert seen["k1"] == ("G", "C", "K", {"now": 7, "action": "A"})
    assert seen["stock"] == ([{"type": "rate"}, {"type": "p"}], ctx)  # K1 types go to evaluate_k1 only; plain is appended
    assert _caveats_k1(monkeypatch, False, True, cs, ctx)[0] == (False, ["m"])
    assert _caveats_k1(monkeypatch, True, False, cs, ctx)[0] == (False, ["a", "z"])
    assert _caveats_k1(monkeypatch, False, False, cs, ctx)[0] == (False, ["a", "m", "z"])
    r, seen = _caveats_k1(monkeypatch, True, True, None, "not an object")
    assert r == (True, [])
    assert seen["k1"][3] == {"now": None, "action": None}
    assert seen["stock"] == (None, {})  # a non-list goes to the stock evaluator as is


def test_evaluate_k1_guards(monkeypatch):
    res = lambda why: {"ok": False, "failed": ["<malformed>"], "reasons": [why], "plain": [], "bound": []}  # noqa: E731
    assert K.evaluate_k1({"caveats": "x"}, None, {}, {"now": 1}) == res("malformed capability chain")
    for bad in ({"now": "1"}, {"now": 1.5}, {"now": True}, {}, None):
        assert K.evaluate_k1({"caveats": []}, None, {}, bad) == res("the verifier clock is not a safe integer (fail closed)")
    assert K.evaluate_k1({"caveats": []}, None, {}, {"now": 1}) == {"ok": True, "failed": [], "reasons": [], "plain": [], "bound": []}
    monkeypatch.setattr(K, "bound_caveats", _raiser)
    r = K.evaluate_k1({"caveats": []}, None, {}, {"now": 1})
    assert (r["ok"], r["failed"], r["plain"], r["bound"]) == (False, ["<malformed>"], [], [])
    assert r["reasons"][0].startswith("caveat language error (fail closed): ")


# ---- k3 -----------------------------------------------------------------------------------------------------------------

def _k3(kind, name):
    return copy.deepcopy(next(e for e in K3_DOC[kind] if e["name"] == name))["input"]


def test_verify_amendment_signature_conditions_are_independent():
    i = _k3("amend_verify", "narrow by the holder")
    cur, req = i["grant"], i["request"]
    assert K3.verify_amendment(cur, req, False) == {"ok": True, "widens": False, "next": req["authority"]}
    assert K3.verify_amendment(cur, req, True) == {"ok": True, "widens": False, "next": req["authority"]}
    need = {"ok": False, "code": "signature_required"}
    no_sig = {k: v for k, v in req.items() if k != "sig"}
    no_by = {k: v for k, v in req.items() if k != "signed_by"}
    assert K3.verify_amendment(cur, no_sig, False) == need  # signer named, no signature
    assert K3.verify_amendment(cur, dict(req, sig=5), False) == need
    assert K3.verify_amendment(cur, dict(req, sig=None), False) == need
    assert K3.verify_amendment(cur, dict(req, signed_by="admin"), False) == need  # signature present, signer not a role
    assert K3.verify_amendment(cur, no_by, False) == need
    assert K3.verify_amendment(cur, dict(req, signed_by="principal"), False) == {"ok": False, "code": "bad_signature"}


def test_verify_amendment_refusal_order():
    i = _k3("amend_verify", "narrow by the holder")
    cur, req = i["grant"], i["request"]
    bad = {"ok": False, "code": "bad_request"}
    for r in ([], "x", None, {}, dict(req, action="Narrow"), dict(req, action=None), dict(req, authority=5)):
        assert K3.verify_amendment(cur, r, False) == bad
    assert K3.verify_amendment(dict(cur, status="revoked"), req, False) == {"ok": False, "code": "not_active"}
    assert K3.verify_amendment(dict(cur, status="revoked"), dict(req, authority=5), False) == bad
    assert K3.verify_amendment(None, req, False) == bad  # the total wrapper of a malformed current grant


def test_verify_revoke_signature_exact():
    i = _k3("revoke_verify", "grant scope")
    root, sig = i["root"], i["sig"]
    assert K3.verify_revoke_signature(root, "grant", sig) == {"ok": True, "scope": "grant"}
    bad = {"ok": False, "code": "bad_request"}
    for scope in ("Grant", "", None, 5):
        assert K3.verify_revoke_signature(root, scope, sig) == bad
    assert K3.verify_revoke_signature(None, "grant", sig) == bad
    sigbad = {"ok": False, "code": "bad_signature"}
    assert K3.verify_revoke_signature(root, "agent", sig) == sigbad and K3.verify_revoke_signature(root, "subtree", sig) == sigbad
    assert K3.verify_revoke_signature(root, "grant", None) == sigbad


# ---- k4: verify_granted_permission ------------------------------------------------------------------------------------

def _case(name):
    return copy.deepcopy(next(c for c in K4_DOC["erc7715"]["cases"] if c["name"] == name))


MANAGERS = ["0x" + "ab" * 20]
F = "0x" + "a" * 40


def _vgp(name="as requested (erc20)", got=None, sent=None, perm=None, data=None, sperm=None, drop=(), owner=None, env=None, managers=MANAGERS):
    c = _case(name)
    c["got"].update(got or {})
    c["sent"].update(sent or {})
    c["got"]["permission"].update(perm or {})
    c["got"]["permission"]["data"].update(data or {})
    c["sent"]["permission"].update(sperm or {})
    for k in drop:
        c["got"].pop(k)
    return K4.verify_granted_permission(dict(c["envelope"], **(env or {})), c["sent"], c["got"], managers, owner)


def test_granted_response_context_manager():
    assert _vgp() is None  # no callback: no owner check
    assert _vgp(owner=lambda x: None) is None and _vgp(owner=lambda x: "gd1") is None
    assert _vgp(owner=lambda x: "other") == "context_bound_to_other_grant"
    seen = []
    _vgp(owner=lambda x: seen.append(x))
    assert seen == ["0xabc123"]
    c = _case("as requested (erc20)")
    for r in ("x", 5, [], None, {}, {"permission": None}, {"permission": "x"}):
        assert K4.verify_granted_permission(c["envelope"], c["sent"], r, MANAGERS) == "response_malformed"
    for ctx in (5, None, "", "0x", "abc", "0xzz", "0xabc\n"):
        assert _vgp(got={"context": ctx}) == "context_malformed"
    assert _vgp(drop=("context",)) == "context_malformed"
    for m in (5, None, "0xab", "0x" + "cd" * 20, "0x" + "zz" * 20):
        assert _vgp(got={"delegationManager": m}) == "delegation_manager_not_allowed"
    assert _vgp(managers=["0x" + "AB" * 20]) is None and _vgp(got={"delegationManager": "0x" + "AB" * 20}) is None
    assert _vgp(managers=[]) == "delegation_manager_not_allowed"


def test_granted_chain_to_from_are_case_insensitive():
    assert _vgp(got={"chainId": "0X2105"}) is None
    assert _vgp(got={"chainId": "0x1"}) == "chain_mismatch" and _vgp(drop=("chainId",)) == "chain_mismatch"
    assert _vgp(got={"chainId": 8453}) == "chain_mismatch"
    assert _vgp(got={"to": "0x" + "1" * 40}) is None and _vgp(got={"to": "0x" + "2" * 40}) == "recipient_mismatch"
    assert _vgp(sent={"to": F}, got={"to": "0x" + "A" * 40}) is None
    assert _vgp(drop=("to",)) == "recipient_mismatch"
    assert _vgp(sent={"from": F}, got={"from": F}) is None
    assert _vgp(sent={"from": F}, got={"from": "0x" + "A" * 40}) is None
    assert _vgp(sent={"from": F}, got={"from": "0x" + "b" * 40}) == "from_mismatch"
    assert _vgp(sent={"from": F}) == "from_mismatch"  # the response omits it
    assert _vgp(got={"from": F}) is None  # the request named no sender


def test_granted_type_token_allowance_adjustment():
    assert _vgp(perm={"type": "native-token-allowance"}) == "permission_type_mismatch"
    assert _vgp(perm={"type": "x"}, sperm={"type": "x"}) == "permission_type_mismatch"  # equal but not an allowance type
    assert _vgp(perm={"type": None}) == "permission_type_mismatch"
    T = "0x" + "2" * 40
    assert _vgp(data={"tokenAddress": T}) is None
    assert _vgp(sperm={"data": {"tokenAddress": "0x" + "C" * 40, "allowance": "0x989680"}}, data={"tokenAddress": "0x" + "c" * 40}) is None
    assert _vgp(data={"tokenAddress": "0x" + "3" * 40}) == "token_mismatch"
    assert _vgp("as requested (native)") is None
    assert _vgp("as requested (native)", data={"tokenAddress": T}) == "token_mismatch"
    for al in (5, None, "", "0x", "989680", "0x0989680", "0xzz"):
        assert _vgp(data={"allowance": al}) == "amount_malformed"
    assert _vgp(data={"allowance": "0x0"}) is None and _vgp(data={"allowance": "0x989680"}) is None
    assert _vgp(data={"allowance": "0x989681"}) == "amount_widened"
    assert _vgp(perm={"isAdjustmentAllowed": False}) is None  # narrowed
    assert _vgp(sperm={"isAdjustmentAllowed": False}, perm={"isAdjustmentAllowed": False}) is None
    assert _vgp(sperm={"isAdjustmentAllowed": False}, perm={"isAdjustmentAllowed": True}) == "adjustment_widened"
    assert _vgp(sperm={"isAdjustmentAllowed": False}, perm={"isAdjustmentAllowed": None}) is None
    c = _case("as requested (erc20)")
    del c["got"]["permission"]["data"]
    assert K4.verify_granted_permission(c["envelope"], c["sent"], c["got"], MANAGERS) == "response_malformed"
    c = _case("as requested (erc20)")
    c["got"]["permission"]["data"] = None
    assert K4.verify_granted_permission(c["envelope"], c["sent"], c["got"], MANAGERS) == "response_malformed"


def test_granted_expiry_rules():
    E = 1800086400
    ok = {"type": "expiry", "data": {"timestamp": E}}
    r = lambda rules: _vgp(got={"rules": rules})  # noqa: E731
    assert r([ok]) is None
    assert r([{"type": "expiry", "data": {"timestamp": E - 1}}]) is None
    assert r([{"type": "expiry", "data": {"timestamp": float(E)}}]) is None
    assert r([{"type": "expiry", "data": {"timestamp": E + 1}}]) == "expiry_extended"
    assert r([]) == "expiry_missing" and r("x") == "expiry_missing" and r(None) == "expiry_missing"
    assert _vgp(drop=("rules",)) == "expiry_missing"
    for bad in (5, None, "expiry", {"type": "other"}, {}):
        assert r([bad]) == "unknown_rule_type"
    assert r([ok, ok]) == "duplicate_expiry"
    assert r([ok, {"type": "expiry"}]) == "duplicate_expiry"  # duplicate is decided before the second timestamp is read
    assert r([ok, {"type": "other"}]) == "unknown_rule_type"
    for ts in ("1", 1.5, 2 ** 53, -0.0, True, None):
        assert r([{"type": "expiry", "data": {"timestamp": ts}}]) == "expiry_malformed"
    for data in ({}, [], "x", 5):  # no own timestamp member
        assert r([{"type": "expiry", "data": data}]) == "expiry_malformed"
    assert r([{"type": "expiry", "data": None}]) == "response_malformed"  # `null.timestamp` throws
    assert r([{"type": "expiry"}]) == "response_malformed"  # `undefined.timestamp` throws


def test_granted_sent_members_and_lenient_shapes_match_the_reference():
    """pca-erc7715/src/index.ts:113-121: a non-string `sent` member throws, a non-string `got` member never matches "\\0"."""
    c = _case("as requested (erc20)")
    vgp = lambda sent, got=c["got"]: K4.verify_granted_permission(c["envelope"], sent, got, MANAGERS)  # noqa: E731
    for k in ("chainId", "to", "from"):
        for bad in (5, None, ["x"]):
            assert vgp(dict(c["sent"], **{k: bad})) == "response_malformed"
    for k, code in (("chainId", "chain_mismatch"), ("to", "recipient_mismatch"), ("from", "from_mismatch")):
        got = dict(c["got"])
        got.pop(k, None)
        assert vgp(dict(c["sent"], **{k: "\0"}), got) == code
        assert vgp(dict(c["sent"], **{k: "\0"}), dict(got, **{k: 5})) == code
    # stricter than String(got), kept
    assert vgp(c["sent"], dict(c["got"], chainId=[c["sent"]["chainId"]])) == "chain_mismatch"
    # permission and data of any non-null JSON type have no members
    T = lambda d: copy.deepcopy(c["got"]) | {"permission": dict(c["got"]["permission"], data=d)}  # noqa: E731
    assert vgp(c["sent"], dict(c["got"], permission=[])) == "permission_type_mismatch"
    for d in ("x", 5, []):
        assert vgp(c["sent"], T(d)) == "token_mismatch"
    n = _case("as requested (native)")
    assert K4.verify_granted_permission(n["envelope"], n["sent"], dict(n["got"], permission=dict(n["got"]["permission"], data="x")), MANAGERS) == "amount_malformed"
    assert K4.verify_granted_permission(n["envelope"], n["sent"], dict(n["got"], permission=dict(n["got"]["permission"], data=None)), MANAGERS) == "response_malformed"
    # tokenAddress ?? ''
    gd = dict(n["got"]["permission"]["data"], tokenAddress=None)
    assert K4.verify_granted_permission(n["envelope"], n["sent"], dict(n["got"], permission=dict(n["got"]["permission"], data=gd)), MANAGERS) is None
    assert K4.verify_granted_permission(n["envelope"], n["sent"], dict(n["got"], permission=dict(n["got"]["permission"], data=dict(gd, tokenAddress=5))), MANAGERS) == "token_mismatch"
    # sent members: String(sd.tokenAddress), BigInt(sd.allowance), an absent isAdjustmentAllowed
    def sent_with(**kw):
        s = copy.deepcopy(c["sent"])
        s["permission"]["data"].update(kw)
        return s
    assert vgp(sent_with(tokenAddress=5)) == "token_mismatch"
    al = c["got"]["permission"]["data"]["allowance"]
    assert vgp(sent_with(allowance=str(int(al, 16)))) is None  # a decimal string is decimal, not hex
    assert vgp(sent_with(allowance=str(int(al, 16) - 1))) == "amount_widened"
    assert vgp(sent_with(allowance=int(al, 16))) is None
    assert vgp(sent_with(allowance=None)) == "response_malformed"
    s = copy.deepcopy(c["sent"])
    s["permission"].pop("isAdjustmentAllowed", None)
    assert vgp(s, dict(c["got"], permission=dict(c["got"]["permission"], isAdjustmentAllowed=True))) == "adjustment_widened"
    assert vgp(s, dict(c["got"], permission=dict(c["got"]["permission"], isAdjustmentAllowed=False))) is None
    s["permission"]["isAdjustmentAllowed"] = 1  # `!==`, not ==
    assert vgp(s, dict(c["got"], permission=dict(c["got"]["permission"], isAdjustmentAllowed=True))) == "adjustment_widened"
    s = copy.deepcopy(c["sent"])
    s["permission"] = None
    assert vgp(s) == "response_malformed"
    s = copy.deepcopy(c["sent"])
    s["permission"]["data"] = None
    assert vgp(s) == "response_malformed"


def test_granted_malformed_request_is_response_malformed():
    c = _case("as requested (erc20)")
    for k in ("chainId", "to", "permission"):
        sent = {x: v for x, v in c["sent"].items() if x != k}
        assert K4.verify_granted_permission(c["envelope"], sent, c["got"], MANAGERS) == "response_malformed"
    sent = copy.deepcopy(c["sent"])
    sent["permission"]["data"]["allowance"] = "0xzz"
    assert K4.verify_granted_permission(c["envelope"], sent, c["got"], MANAGERS) == "response_malformed"
    assert K4.verify_granted_permission(c["envelope"], c["sent"], c["got"], None) == "response_malformed"


# ---- policy_link --------------------------------------------------------------------------------------------------------

DEF = PL_DOC["template"]["def"]
NAME = "^[a-z][a-z0-9_]{0,63}$"


def _td(**kw):
    return PL.template_def_error(dict(DEF, **kw))


def _slot(s):
    return _td(slots=dict(DEF["slots"], x=s))


def test_template_def_header():
    V = "template v / kind mismatch"
    assert _td() is None and _td(v=1.0) is None
    for bad in (2, 0, "1", None, True, False):
        assert _td(v=bad) == V
    assert _td(kind="x") == V and _td(v=2, kind="x") == V
    assert PL.template_def_error({"kind": DEF["kind"]}) == V
    I = "template id must match " + NAME
    assert _td(id="a" * 64) is None
    for bad in (5, None, "", "A", "1a", "a" * 65, "a-b"):
        assert _td(id=bad) == I
    W = "template version must be a string of 1..64 characters"
    assert _td(version="v" * 64) is None and _td(version="\U0001F600" * 32) is None
    for bad in (5, None, "", "v" * 65, "\U0001F600" * 33):
        assert _td(version=bad) == W
    for bad in ([], None, "x"):
        assert _td(slots=bad) == "slots must be an object"
    assert PL.template_def_error([]) == "template must be an object"


def test_template_def_slots():
    U = "slot 'x' is declared but never used"
    extra = {"s%d" % i: {"type": "string"} for i in range(29)}
    assert _td(slots=dict(DEF["slots"], **dict(list(extra.items())[:28]))) == "slot 's0' is declared but never used"  # 32 slots
    assert _td(slots=dict(DEF["slots"], **extra)) == "more than 32 slots"
    assert _td(slots={"A": 5}) == "slot name 'A' must match " + NAME
    assert _slot(5) == "slot 'x' must be an object"
    for bad in ({}, {"type": "bool"}, {"type": None}):
        assert _slot(bad) == "slot 'x'.type must be string, integer or set"
    for t in ("string", "integer"):
        assert _slot({"type": t}) == U
    assert _slot({"type": "set"}) == "set slot 'x' needs a closed values list"
    assert _slot({"type": "set", "values": "a"}) == "set slot 'x' needs a closed values list"
    assert _slot({"type": "set", "values": ["a"] * 64}) == U
    V = "slot 'x'.values must be a list of strings"
    assert _slot({"type": "set", "values": ["a"] * 65}) == V
    assert _slot({"type": "set", "values": [1]}) == V
    for bad in ("a", None, ["a", 1]):
        assert _slot({"type": "string", "values": bad}) == V
    assert _slot({"type": "string", "values": ["a"]}) == U
    for k in ("min", "max"):
        M = "slot 'x'.%s must be a safe integer" % k
        for bad in (1.5, "1", True, None, 2 ** 53, -(2 ** 53)):
            assert _slot({"type": "integer", k: bad}) == M
        assert _slot({"type": "integer", k: 2 ** 53 - 1}) == U and _slot({"type": "integer", k: 1.0}) == U
        assert _slot({"type": "string", k: "x"}) == U  # checked on integer slots only


def test_template_def_body():
    B = "body.predicates must be an array"
    base = {k: v for k, v in DEF.items() if k != "body"}
    assert PL.template_def_error(base) == B
    for bad in ([], "x", {}, {"predicates": {}}, {"predicates": None}):
        assert _td(body=bad) == B
    assert _td(slots={}, body={"predicates": []}) is None
    assert _td(slots={}, body={"predicates": [], "caveats": []}) is None
    for bad in ({}, None, "x"):
        assert _td(slots={}, body={"predicates": [], "caveats": bad}) == "body.caveats must be an array"
    S = {"s": {"type": "string"}}
    body = lambda ph: {"predicates": [ph]}  # noqa: E731
    assert _td(slots=S, body=body({"$slot": "s", "pre": "a", "post": "b"})) is None
    assert _td(slots=S, body=body({"$slot": "s"})) is None
    assert _td(slots=S, body={"predicates": [], "caveats": [{"$slot": "s"}]}) is None  # the scan covers caveats too
    assert _td(slots=S, body=body({"$slot": "s", "pre": 5})) == "placeholder pre must be a string"
    assert _td(slots=S, body=body({"$slot": "s", "post": 5})) == "placeholder post must be a string"
    assert _td(slots=S, body=body({"$slot": "s", "z": 1})) == "placeholder has unknown member 'z'"
    assert _td(slots=S, body=body({"$slot": "t"})) == "placeholder names undeclared slot 't'"
    assert _td(slots=S, body=body({"$slot": 5})) == "placeholder names undeclared slot '5'"
    assert _td(slots=S, body=body({"$slot": None})) == "placeholder names undeclared slot 'null'"
    assert _td(slots=S, body=body({"$slot": True})) == "placeholder names undeclared slot 'true'"
    for k in ("__proto__", "constructor", "prototype"):
        assert _td(slots={}, body=body({k: 1})) == "body has the forbidden key '%s'" % k
    assert _td(slots=S, body={"predicates": [[{"a": {"$slot": "s"}}]]}) is None  # nested list and object
    assert _td(slots=S, body={"predicates": [1, "x", None]}) == "slot 's' is declared but never used"


OVERLAY = {"v": 1, "kind": "pca-template-tighten", "template_id": "t", "version_digest": "d"}


def _ov(**kw):
    return PL.tighten_overlay_error(dict(OVERLAY, **kw))


def test_tighten_overlay_error():
    V = "overlay v / kind mismatch"
    assert _ov() is None and _ov(v=1.0) is None
    for bad in (2, "1", None, True):
        assert _ov(v=bad) == V
    assert _ov(kind="pca-policy-template") == V
    assert PL.tighten_overlay_error("x") == "overlay must be an object"
    assert _ov(z=1) == "overlay has unknown member 'z' (an overlay can only add where conditions and caveats)"
    for bad in (5, None, "A"):
        assert _ov(template_id=bad) == "overlay template_id invalid"
    for bad in (5, None, ""):
        assert _ov(version_digest=bad) == "overlay version_digest invalid"
    assert _ov(add_where=[{}], add_caveats=[{"type": "t"}]) is None and _ov(add_where=[], add_caveats=[]) is None
    for bad in ("x", None, [1]):
        assert _ov(add_where=bad) == "overlay add_where must be a list of conditions"
    for bad in ("x", None, [1], [{}], [{"type": 5}]):
        assert _ov(add_caveats=bad) == "overlay add_caveats must be a list of caveats"


def _resolve(name):
    return copy.deepcopy(next(e for e in PL_DOC["resolve"] if e["name"] == name))


def test_verify_linked_policy():
    e = _resolve("a reference resolves to the instantiation")
    ref, reg, pol = e["ref"], e["registry"], e["expect"]["policy"]
    env = {"template_ref": ref, "predicates": pol["predicates"], "caveats": pol["caveats"]}
    assert PL.verify_linked_policy(env, reg) == {"ok": True, "template": ref["version_digest"]}
    assert PL.verify_linked_policy({"predicates": [], "caveats": []}, reg) == {"ok": True}
    D = {"ok": False, "reason": "grant policy differs from the linked template instantiation"}
    assert PL.verify_linked_policy(dict(env, predicates=[]), reg) == D
    assert PL.verify_linked_policy(dict(env, caveats=[]), reg) == D
    no = _resolve("a registry without the version")
    assert PL.verify_linked_policy(dict(env, template_ref=no["ref"]), no["registry"]) == {
        "ok": False, "reason": "template version is not in the registry"}
    assert PL.verify_linked_policy(None, reg) == {"ok": False, "reason": "link verification error (fail closed)"}
