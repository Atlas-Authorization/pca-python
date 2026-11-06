"""k05 mutation-kill: agent (suite signing, escalation request/answer), actions (_jnum = JS ToNumber), actions_registry
(reapproval_valid), approval (render field order), arg_provenance (occurs_as_token), missing_context (_collect), workflow
(_evaluate edge relations and every admission code) and undo (undo_transition refusals). Every expectation is the TS
reference (packages/pca/src/{escalation,action-pin,arg-provenance,missing-context,workflow,undo}.ts,
packages/pca-actions/src/{approval-render,traits}.ts)."""
import copy
import math

import pytest

from atlas_pca import actions as A
from atlas_pca import actions_registry as R
from atlas_pca import agent as G
from atlas_pca import approval as AP
from atlas_pca import arg_provenance as AV
from atlas_pca import missing_context as MC
from atlas_pca import undo as U
from atlas_pca import workflow as W
from atlas_pca.pca import b64u, canonical_bytes_strict, hash_canonical

P = G.keypair_from_seed(bytes([81]) * 32)
RS = G.keypair_from_seed(bytes([82]) * 32)


# ---- agent: sign_with_suite / sign_artifact -------------------------------------------------------------------------------

class _FakePq:
    """Duck-typed PQ key pair: a deterministic 'signature' so the produced parts are exact."""

    def __init__(self, family="ML-DSA-65"):
        self.family, self.public = family, "PQPK"

    def sign(self, msg):
        return b"PQ:" + msg


MSG = b"hello"


def _raises(exc, msg, fn, *a):
    with pytest.raises(exc) as e:
        fn(*a)
    assert type(e.value) is exc and str(e.value) == msg


def test_sign_with_suite_ed25519_default_and_explicit():
    want = {"sig": b64u(P.sign(MSG))}
    assert G.sign_with_suite(None, P, None, MSG) == want
    assert G.sign_with_suite("", P, None, MSG) == want
    assert G.sign_with_suite("ed25519", P, None, MSG) == want
    _raises(TypeError, "'ed25519' needs an Ed25519 key", G.sign_with_suite, None, None, None, MSG)
    _raises(TypeError, "'ed25519' needs an Ed25519 key", G.sign_with_suite, "ed25519", None, _FakePq(), MSG)


def test_sign_with_suite_unknown_and_unsignable():
    _raises(ValueError, "unknown signature alg 'bogus'", G.sign_with_suite, "bogus", P, None, MSG)
    _raises(G.UnsupportedSuite, "unsupported_suite: fn-dsa-512", G.sign_with_suite, "fn-dsa-512", P, None, MSG)
    _raises(G.UnsupportedSuite, "unsupported_suite: fn-dsa-1024", G.sign_with_suite, "fn-dsa-1024", P, None, MSG)
    _raises(G.UnsupportedSuite, "unsupported_suite: less-cat1", G.sign_with_suite, "less-cat1", P, _FakePq("LESS-cat1"), MSG)
    _raises(G.UnsupportedSuite, "unsupported_suite: hybrid-ed25519-less-cat1", G.sign_with_suite, "hybrid-ed25519-less-cat1", P,
            _FakePq("LESS-cat1"), MSG)


def test_sign_with_suite_pq_key_checks():
    _raises(TypeError, "'ml-dsa-65' needs a ML-DSA-65 key pair", G.sign_with_suite, "ml-dsa-65", P, None, MSG)
    _raises(TypeError, "'ml-dsa-65' needs a ML-DSA-65 key pair", G.sign_with_suite, "ml-dsa-65", P, _FakePq("ML-DSA-87"), MSG)
    _raises(TypeError, "'hybrid-ed25519-ml-dsa-87' needs a ML-DSA-87 key pair", G.sign_with_suite, "hybrid-ed25519-ml-dsa-87", P,
            _FakePq("ML-DSA-65"), MSG)
    # hybrid without the Ed25519 half
    _raises(TypeError, "'hybrid-ed25519-ml-dsa-65' needs an Ed25519 key", G.sign_with_suite, "hybrid-ed25519-ml-dsa-65", None,
            _FakePq(), MSG)
    _raises(TypeError, "'hybrid-nested-ed25519-ml-dsa-65' needs an Ed25519 key", G.sign_with_suite,
            "hybrid-nested-ed25519-ml-dsa-65", None, _FakePq(), MSG)


def test_sign_with_suite_pq_parts_exact():
    pq = _FakePq()
    assert G.sign_with_suite("ml-dsa-65", None, pq, MSG) == {"sig": b64u(b"PQ:" + MSG)}
    e = P.sign(MSG)
    assert G.sign_with_suite("hybrid-ed25519-ml-dsa-65", P, pq, MSG) == {"sig": b64u(e), "pq_sig": b64u(b"PQ:" + MSG)}
    assert G.sign_with_suite("hybrid-nested-ed25519-ml-dsa-65", P, pq, MSG) == {"sig": b64u(e), "pq_sig": b64u(b"PQ:" + MSG + e)}


def test_sign_artifact_binds_the_suite():
    body = {"a": 1}
    d = "dom\0"
    assert G.sign_artifact(d, body, P) == {"a": 1, "sig": b64u(P.sign(d.encode() + canonical_bytes_strict(body)))}
    assert G.sign_artifact(d, body, P, "ed25519") == {"a": 1, "sig": b64u(P.sign(d.encode() + canonical_bytes_strict(body)))}
    full = {"a": 1, "alg": "ml-dsa-65", "pq_pk": "PQPK"}
    assert G.sign_artifact(d, body, P, "ml-dsa-65", _FakePq()) == dict(full, sig=b64u(b"PQ:" + d.encode() + canonical_bytes_strict(full)))
    assert body == {"a": 1}
    _raises(TypeError, "'ml-dsa-65' needs a PQ key pair", G.sign_artifact, d, body, P, "ml-dsa-65", None)


# ---- agent: escalation request / answer -----------------------------------------------------------------------------------

GRANT = {"id": "g1", "issuer": "x"}
PCACTN = {"action": {"verb": "pay.send", "resource": "acct:1"}, "counter": 4}


def _req_base(aud="rs", last=3, expires=1_000 + 3_600_000):
    return {
        "v": 1, "kind": "pca-escalation-request", "aud": aud,
        "policy_digest": hash_canonical({"d": "atlas-pca/escalation-policy/v1", "grant": GRANT}),
        "action_digest": hash_canonical({"d": "atlas-pca/escalation-action/v1", "pcactn": PCACTN}),
        "history_head": hash_canonical({"d": "atlas-pca/escalation-history/v1", "last_counter": last}),
        "verb": "pay.send", "resource": "acct:1", "reasons": ["r1"], "expires_at": expires,
    }


def test_escalation_digests_exact():
    assert G.escalation_policy_digest(GRANT) == hash_canonical({"d": "atlas-pca/escalation-policy/v1", "grant": GRANT})
    assert G.escalation_action_digest(PCACTN) == hash_canonical({"d": "atlas-pca/escalation-action/v1", "pcactn": PCACTN})
    assert G.escalation_history_head(None) == hash_canonical({"d": "atlas-pca/escalation-history/v1", "last_counter": None})
    assert G.escalation_history_head(0) == hash_canonical({"d": "atlas-pca/escalation-history/v1", "last_counter": 0})


def test_build_escalation_request_exact():
    assert G.build_escalation_request("rs", GRANT, PCACTN, 3, ["r1"], 1_000) == _req_base()
    assert G.build_escalation_request("rs", GRANT, PCACTN, 3, ["r1"], 1_000, 5) == _req_base(expires=1_005)
    assert G.build_escalation_request(None, GRANT, PCACTN, 3, ["r1"], 1_000) == _req_base(aud="")
    assert G.build_escalation_request(7, GRANT, PCACTN, 3, ["r1"], 1_000) == _req_base(aud="")
    assert G.build_escalation_request("rs", GRANT, PCACTN, None, ["r1"], 1_000) == _req_base(last=None)
    rd = hash_canonical({"x": 1})
    assert G.build_escalation_request("rs", GRANT, PCACTN, 3, ["r1"], 1_000, render_digest=rd) == dict(_req_base(), render_digest=rd)


def test_build_escalation_request_reason_caps():
    reasons = ["r%d" % i for i in range(17)]
    assert G.build_escalation_request("rs", GRANT, PCACTN, 3, reasons, 0)["reasons"] == reasons[:16]
    assert G.build_escalation_request("rs", GRANT, PCACTN, 3, reasons[:15], 0)["reasons"] == reasons[:15]
    assert G.build_escalation_request("rs", GRANT, PCACTN, 3, reasons[:16], 0)["reasons"] == reasons[:16]
    long = ["a" * 511, "b" * 512, "c" * 513]
    assert G.build_escalation_request("rs", GRANT, PCACTN, 3, long, 0)["reasons"] == ["a" * 511, "b" * 512, "c" * 512]
    assert G.build_escalation_request("rs", GRANT, PCACTN, 3, (r for r in ["x"]), 0)["reasons"] == ["x"]


PD, AD, HH, RQ, EX = (hash_canonical({"x": i}) for i in range(5))
NONCE = b64u(bytes(16))


def _answer_body(decision="allow", rd=None, nonce=NONCE):
    b = {"v": 1, "kind": "pca-escalation-answer", "principal": P.public, "policy_digest": PD, "action_digest": AD,
         "history_head": HH, "decision": decision, "iat": 10, "expires_at": 20, "nonce": nonce}
    if rd is not None:
        b["render_digest"] = rd
    return b


def _signed(body):
    return dict(body, sig=b64u(P.sign(G.ESCALATION_ANSWER_DOMAIN.encode() + canonical_bytes_strict(body))))


BIND = {"policy_digest": PD, "action_digest": AD, "history_head": HH}


def test_sign_escalation_answer_exact():
    assert G.ESCALATION_ANSWER_DOMAIN == "atlas-pca/escalation-answer/v1\0"
    assert G.sign_escalation_answer(P, BIND, "allow", 10, 20, NONCE) == _signed(_answer_body())
    assert G.sign_escalation_answer(P, BIND, "deny", 10, 20, NONCE) == _signed(_answer_body("deny"))
    # the render digest: explicit wins, else the request's, else absent
    assert G.sign_escalation_answer(P, dict(BIND, render_digest=RQ), "allow", 10, 20, NONCE) == _signed(_answer_body(rd=RQ))
    assert G.sign_escalation_answer(P, dict(BIND, render_digest=RQ), "allow", 10, 20, NONCE, EX) == _signed(_answer_body(rd=EX))
    assert G.sign_escalation_answer(P, BIND, "allow", 10, 20, NONCE, EX) == _signed(_answer_body(rd=EX))
    # escalation.ts signEscalationAnswer: the shape check throws, in escalationAnswerShapeError's order
    for bad in ("ALLOW", "", None, "approve"):
        _raises(ValueError, "sign_escalation_answer: decision must be 'allow' or 'deny'", G.sign_escalation_answer, P, BIND, bad, 10, 20, NONCE)
    _raises(ValueError, "sign_escalation_answer: policy_digest must be canonical base64url (32 bytes)",
            G.sign_escalation_answer, P, dict(BIND, policy_digest="pd"), "allow", 10, 20, NONCE)
    _raises(ValueError, "sign_escalation_answer: expires_at must be greater than iat", G.sign_escalation_answer, P, BIND, "allow", 20, 20, NONCE)
    _raises(ValueError, "sign_escalation_answer: nonce must be canonical base64url of at least 16 bytes", G.sign_escalation_answer, P, BIND, "allow", 10, 20, "N")
    _raises(ValueError, "sign_escalation_answer: render_digest must be canonical base64url (32 bytes)", G.sign_escalation_answer, P, BIND, "allow", 10, 20, NONCE, "EX")


def test_sign_escalation_answer_random_nonce(monkeypatch):
    monkeypatch.setattr(G.os, "urandom", lambda n: bytes([7]) * n)
    assert G.sign_escalation_answer(P, BIND, "allow", 10, 20) == _signed(_answer_body(nonce=b64u(bytes([7]) * 16)))


# ---- actions._jnum (JS ToNumber) / _jle -----------------------------------------------------------------------------------

@pytest.mark.parametrize("x,want", [
    (None, 0.0), (False, 0.0), (True, 1.0), (5, 5.0), (1.5, 1.5), (-2, -2.0), ([], 0.0), ([7], 7.0), (["0x10"], 16.0),
    ("", 0.0), ("   ", 0.0), (" 12 ", 12.0), ("\u000b5", 5.0), ("﻿3　", 3.0), ("0x1F", 31.0), ("0X1f", 31.0),
    ("0o17", 15.0), ("0O17", 15.0), ("0b101", 5.0), ("0B101", 5.0), ("Infinity", math.inf), ("+Infinity", math.inf),
    ("-Infinity", -math.inf), (" -Infinity ", -math.inf), ("1e3", 1000.0), ("1E+3", 1000.0), ("5e-1", 0.5), (".5", 0.5),
    ("5.", 5.0), ("+5", 5.0), ("-5", -5.0), ("007", 7.0), ("1e999", math.inf),
])
def test_jnum_numbers(x, want):
    assert A._jnum(x) == want


@pytest.mark.parametrize("x", [
    [1, 2], "0x", "0b2", "0o8", "0xg", "infinity", "INFINITY", "Inf", "1e", "e5", "abc", ".", "+", "-", "1_000", "1 000", "--5",
    "+-Infinity", "--Infinity", "++Infinity", "-+Infinity", "Infinityx", "0x+1", "0x-1", "0x1_0", "0x 1", "-0x1F", "+0x1F",
    "١", "١٢", "0x١", "1١", {}, {"a": 1}, A._UNDEF,
])
def test_jnum_nan(x):
    assert math.isnan(A._jnum(x))


def test_jle_is_js_less_or_equal():
    assert A._jle(5, 5) is True and A._jle(5, "5") is True and A._jle(6, "5") is False and A._jle(4, " 5 ") is True
    assert A._jle(10 ** 9, "Infinity") is True and A._jle(0, "-Infinity") is False and A._jle(0, None) is True
    # JS Number("+-Infinity") / Number("0x+1") is NaN: never <=, so a forged floor of that form never passes
    assert A._jle(0, "+-Infinity") is False and A._jle(0, "0x+1") is False and A._jle(0, "١") is False
    assert A._jle(0, "abc") is False and A._jle(0, {}) is False


# ---- actions_registry.reapproval_valid ------------------------------------------------------------------------------------

DIFF = hash_canonical({"diff": 1})


def _reapproval(**over):
    body = {"v": 1, "kind": "pca-reapproval", "grant": "g1", "verb": "pay.send", "diff": DIFF}
    body.update({k: v for k, v in over.items() if k != "sig"})
    body = {k: v for k, v in body.items() if v is not _DROP}
    sig = {"alg": "ed25519", "value": b64u(P.sign(R.REAPPROVAL_DOMAIN.encode() + canonical_bytes_strict(body)))}
    return dict(body, sig=over.get("sig", sig))


_DROP = object()


def _rv(r, grant="g1", issuer=None, verb="pay.send", diff=DIFF):
    return R.reapproval_valid(r, grant, P.public if issuer is None else issuer, verb, diff)


def test_reapproval_valid_accepts_the_signed_record():
    assert R.REAPPROVAL_KIND == "pca-reapproval" and R.REAPPROVAL_DOMAIN == "atlas-pca/action-reapproval/v1\x00"
    assert _rv(_reapproval()) is True


@pytest.mark.parametrize("name,r,kw", [
    ("not an object", "x", {}),
    ("a list", [], {}),
    ("unknown member", dict(_reapproval(), extra=1), {}),
    ("v 2", _reapproval(v=2), {}),
    ("v true", _reapproval(v=True), {}),
    ("v 1.5", _reapproval(v=1.5), {}),
    ("v missing", _reapproval(v=_DROP), {}),
    ("kind", _reapproval(kind="pca-reapprovalx"), {}),
    ("kind missing", _reapproval(kind=_DROP), {}),
    ("grant missing", _reapproval(grant=_DROP), {}),
    ("verb missing", _reapproval(verb=_DROP), {}),
    ("diff missing", _reapproval(diff=_DROP), {}),
    ("grant arg", _reapproval(), {"grant": "g2"}),
    ("verb arg", _reapproval(), {"verb": "pay.other"}),
    ("diff arg", _reapproval(), {"diff": hash_canonical({"diff": 2})}),
    ("issuer arg", _reapproval(), {"issuer": RS.public}),
    ("sig missing", _reapproval(sig=None), {}),
    ("sig not object", _reapproval(sig="abc"), {}),
    ("sig extra member", None, {}),
    ("sig alg", None, {}),
    ("sig alg missing", None, {}),
    ("sig value not str", None, {}),
    ("sig wrong key", None, {}),
    ("sig wrong domain", None, {}),
])
def test_reapproval_valid_refuses(name, r, kw):
    good = _reapproval()
    if name == "sig extra member":
        r = dict(good, sig=dict(good["sig"], kid="k"))
    elif name == "sig alg":
        r = dict(good, sig=dict(good["sig"], alg="ml-dsa-65"))
    elif name == "sig alg missing":
        r = dict(good, sig={"value": good["sig"]["value"]})
    elif name == "sig value not str":
        r = dict(good, sig={"alg": "ed25519", "value": 5})
    elif name == "sig wrong key":
        body = {k: v for k, v in good.items() if k != "sig"}
        r = dict(good, sig={"alg": "ed25519", "value": b64u(RS.sign(R.REAPPROVAL_DOMAIN.encode() + canonical_bytes_strict(body)))})
    elif name == "sig wrong domain":
        body = {k: v for k, v in good.items() if k != "sig"}
        r = dict(good, sig={"alg": "ed25519", "value": b64u(P.sign(b"atlas-pca/action-reapproval/v2\x00" + canonical_bytes_strict(body)))})
    assert _rv(r, **kw) is False


def test_reapproval_valid_each_binding_field_alone():
    # every field matches except one: each `or` operand refuses on its own
    good = _reapproval()
    assert _rv(good) is True
    assert _rv(good, grant="g1 ") is False
    assert _rv(good, verb="pay.send ") is False
    assert _rv(good, diff=DIFF + "A") is False


# ---- approval.render_approval ---------------------------------------------------------------------------------------------

def _def(params):
    return {"kind": "action", "verb": "pay.send", "title": "Pay", "effects": ["write"], "reversibility": "irreversible",
            "resource": {"type": "acct", "id": "acct", "scope": "one"}, "params": params}


def test_render_fields_sorted_by_utf16_code_units():
    astral, bmp_hi = "\U0001F600", "！"  # UTF-16: 0xD83D < 0xFF01 (code points: U+1F600 > U+FF01)
    d = _def({"a": {"type": "string"}, bmp_hi: {"type": "string"}, astral: {"type": "integer"}})
    r = AP.render_approval(d, {bmp_hi: "b", astral: 3.0, "a": "x"})
    assert r == {"v": 1, "kind": "pca-approval-render", "verb": "pay.send", "def_digest": A.def_digest(d), "unreviewed": True,
                 "fields": [{"id": "a", "class": "param", "value": "x"}, {"id": astral, "class": "param", "value": 3},
                            {"id": bmp_hi, "class": "param", "value": "b"}]}
    assert type(r["fields"][1]["value"]) is int
    assert AP.approval_render_shape_error(r) is None
    assert AP.render_approval(d, {bmp_hi: "b", astral: 3, "a": "x"}, True)["unreviewed"] is False


def test_render_units_and_refusals():
    d = _def({
        "amt": {"type": "integer", "role": "money.amount", "unit": {"kind": "money", "ccy": {"from": "cur"}, "exp": 2}},
        "cur": {"type": "string"},
        "n": {"type": "integer", "unit": {"kind": "count"}, "required": False},
    })
    r = AP.render_approval(d, {"amt": 100, "cur": "EUR"})
    assert r["fields"] == [{"id": "amt", "class": "money.amount", "value": 100, "unit": {"kind": "money", "ccy": "EUR", "exp": 2}},
                           {"id": "cur", "class": "param", "value": "EUR"}]
    r = AP.render_approval(d, {"amt": 1, "cur": "EUR", "n": 2})
    assert r["fields"][2] == {"id": "n", "class": "param", "value": 2, "unit": {"kind": "count"}}

    def code(params, dd=d):
        with pytest.raises(A.ActionKitError) as e:
            AP.render_approval(dd, params)
        return e.value.code, str(e.value)

    assert code([]) == ("render_bad_params", "params must be an object")
    assert code({"amt": 1, "cur": "EUR", "zz": 1}) == ("render_undeclared_param", "'zz' is not a parameter of pay.send")
    assert code({"amt": 1}) == ("render_missing_param", "required parameter 'cur' of pay.send is missing")
    assert code({"amt": 1, "cur": ""}) == ("render_unresolved_currency", "the currency of 'amt' is not a string")
    assert code({"amt": 1, "cur": 5}) == ("render_unresolved_currency", "the currency of 'amt' is not a string")  # amt renders first
    assert code({"amt": 1.5, "cur": "EUR"}) == ("render_bad_value", "'amt' is not a integer in the canonical domain (no floats, no null, no lone surrogates)")
    assert code({"a.b": 1}) == ("render_bad_params", "the parameter key 'a.b' contains a dot")
    fixed = _def({"amt": {"type": "integer", "unit": {"kind": "money", "ccy": "USD", "exp": 0}}})
    assert AP.render_approval(fixed, {"amt": 0})["fields"] == [{"id": "amt", "class": "param", "value": 0,
                                                                 "unit": {"kind": "money", "ccy": "USD", "exp": 0}}]
    empty_ccy = _def({"amt": {"type": "integer", "unit": {"kind": "money", "ccy": "", "exp": 0}}})
    assert code({"amt": 0}, empty_ccy) == ("render_unresolved_currency", "the currency of 'amt' is not a string")


# ---- arg_provenance.occurs_as_token ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("text,needle,want", [
    (None, "a", False), ("a", None, False), ("a", "", False), ("", "a", False), (5, "5", False),
    ("bob", "bob", True), ("pay bob now", "bob", True), ("bobby", "bob", False), ("xbob", "bob", False), ("bob_", "bob", False),
    ("_bob", "bob", False), ("1bob", "bob", False), ("bob9", "bob", False), ("Abob", "bob", False), ("bobZ", "bob", False),
    ("bobby bob", "bob", True), ("bobby xbob bob.", "bob", True), ("x-bob-y", "bob", True), ("ébob", "bob", False),
    ("bobé", "bob", False), ("\U0001F600bob", "bob", False), ("bob\U0001F600", "bob", False),
    ("x-bob", "-bob", True), ("-bob", "-bob", True), ("x-bobz", "-bob", False), ("x-bob z", "-bob", True),
    ("bob-x", "bob-", True), ("abob-", "bob-", False), ("--", "-", True), ("a-b", "-", True),
    ("a \U0001F600 b", "\U0001F600", True), ("\U0001F600", "😀", True), ("a\U0001F600", "\U0001F600", False),
    ("aaa", "aa", False), ("baaa a", "a", True), ("Bob", "bob", False),
])
def test_occurs_as_token(text, needle, want):
    assert AV.occurs_as_token(text, needle) is want


@pytest.mark.parametrize("c,want", [
    ("/", False), ("0", True), ("9", True), (":", False), ("@", False), ("A", True), ("Z", True), ("[", False), ("^", False),
    ("_", True), ("`", False), ("a", True), ("z", True), ("{", False), ("\x7f", False), ("\x80", True), ("\ud83d", True), (" ", False),
])
def test_word_boundary_classes(c, want):
    assert AV._is_word(c) is want
    assert AV.occurs_as_token(c + "bob", "bob") is (not want)
    assert AV.occurs_as_token("bob" + c, "bob") is (not want)


def test_units_surrogate_pairs():
    assert AV._units("ab") == "ab"
    assert AV._units("\U0001F600") == "\ud83d\ude00"
    assert AV._units("a\U00010000\U0010FFFF") == "a\ud800\udc00\udbff\udfff"
    assert AV._units("￿") == "￿"


# ---- missing_context._collect via decide_with_missing ---------------------------------------------------------------------

def _bound(params=None, **x):
    act = {"verb": "v", "resource": "r"}
    if params is not None:
        act["params"] = params
    return dict({"action": act}, **x)


ILL = {"decision": "deny", "reason": "ill_typed_context", "missing": []}


def _esc(*paths, sup="principal"):
    ms = [{"path": p, "supplier": sup} for p in paths]
    return {"decision": "escalate", "reason": "escalate: missing_context " + ",".join("%s:%s" % (sup, p) for p in paths), "missing": ms}


def test_collect_params_present_but_condition_unknown_is_ill_typed():
    # params is an object and the field resolves: nothing is missing, the condition is just undecidable
    assert MC.decide_with_missing([{"field": "action.params.x", "op": "bogus", "value": 1}], _bound({"x": 1})) == ILL
    assert MC.decide_with_missing([{"field": "action.params", "op": "bogus", "value": 1}], _bound({"x": 1})) == ILL
    # an array is an object in JS: params are available
    assert MC.decide_with_missing([{"field": "action.params.0", "op": "bogus", "value": 1}], _bound([5])) == ILL


def test_collect_params_unavailable_names_the_field():
    assert MC.decide_with_missing([{"field": "action.params", "op": "bogus", "value": 1}], _bound("s")) == _esc("action.params")
    assert MC.decide_with_missing([{"field": "action.params", "op": "bogus", "value": 1}], _bound(5)) == _esc("action.params")
    assert MC.decide_with_missing([{"field": "action.params.x", "op": "eq", "value": 1}], _bound()) == _esc("action.params.x")
    assert MC.decide_with_missing([{"field": "action.params.x", "op": "eq", "value": 1}], _bound({})) == _esc("action.params.x")


def test_collect_params_prefix_is_segment_exact():
    b = _bound("s")
    b["action"]["paramsx"] = 1
    assert MC.decide_with_missing([{"field": "action.paramsx", "op": "bogus", "value": 1}], b) == ILL


def test_collect_ref_and_field_absent():
    w = [{"field": "subject.a", "op": "eq", "ref": "subject.b"}]
    assert MC.decide_with_missing(w, _bound({}, subject={"a": 1})) == _esc("subject.b")
    assert MC.decide_with_missing(w, _bound({}, subject={})) == _esc("subject.a", "subject.b")
    assert MC.decide_with_missing([{"field": "subject.a", "op": "eq", "ref": ""}], _bound({}, subject={})) == _esc("subject.a")
    u = {"decision": "deny", "reason": "missing_context_untrusted: subject.b",
         "missing": [{"path": "subject.b", "supplier": "agent_declared_untrusted"}]}
    assert MC.decide_with_missing(w, _bound({}, subject={"a": 1}), None, {"subject.b": "agent_declared_untrusted"}) == u


def test_collect_ill_typed_shapes():
    ok = {"field": "subject.a", "op": "eq", "value": 1}
    assert MC.decide_with_missing([ok, 5], _bound({}, subject={})) == ILL
    assert MC.decide_with_missing([ok, {"any_of": []}], _bound({}, subject={})) == ILL
    assert MC.decide_with_missing([{"not": ok}], _bound({}, subject={})) == _esc("subject.a")
    assert MC.decide_with_missing([{"any_of": [ok, {"field": "subject.b", "op": "eq", "value": 1}]}], _bound({}, subject={})) == \
        _esc("subject.a", "subject.b")
    assert MC.decide_with_missing([{"field": "subject.a", "op": "eq"}], _bound({}, subject={"a": 1})) == ILL


def test_collect_depth_cap():
    ok = {"field": "subject.a", "op": "eq", "value": 1}
    deep = ok
    for _ in range(64):
        deep = {"all_of": [deep]}
    out, ill = set(), [False]
    MC._collect(deep, {"action": {}, "subject": {}}, out, ill)
    assert (out, ill) == ({"subject.a"}, [False])
    out, ill = set(), [False]
    MC._collect({"all_of": [deep]}, {"action": {}, "subject": {}}, out, ill)
    assert (out, ill) == (set(), [True])
    out, ill = set(), [False]
    MC._collect(ok, {"action": {}, "subject": {}}, out, ill, 64)
    assert (out, ill) == ({"subject.a"}, [False])
    out, ill = set(), [False]
    MC._collect(ok, {"action": {}, "subject": {}}, out, ill, 65)
    assert (out, ill) == (set(), [True])


# ---- workflow._evaluate ---------------------------------------------------------------------------------------------------

NOW = 1_800_000_000_000


def _D(s):
    return hash_canonical({"v": s})


def _step(i, deps=(), **o):
    return dict({"id": i, "verb": "v", "resource": "r", "params_digest": None, "deps": list(deps), "sink": None, "deny_labels": [],
                 "escalate_labels": [], "fresh_ms": None, "cost": {}}, **o)


def _edge(f, t, op="eq", **o):
    return dict({"from": {"step": f, "field": "out"}, "to": {"step": t, "param": "in"}, "op": op, "unit": None, "deny_labels": [],
                 "promise": None}, **o)


def _body(**o):
    return dict({"v": 1, "id": "w", "principal": P.public, "goal_digest": None, "plan_root": None, "issued_at": NOW - 10,
                 "expires_at": NOW + 10, "steps": [_step("a"), _step("b", ["a"])], "edges": [_edge("a", "b")],
                 "budget": {"max_steps": 5, "caps": {}}}, **o)


def _rq(s, params, **o):
    return dict({"step": s, "verb": "v", "resource": "r", "params": params, "units": {}, "goal_digest": None, "plan_root": None}, **o)


def _rc(b, s, outputs=None, outcome="ok", issued_at=NOW - 1, prev=None, pd=None):
    return G.sign_step_receipt(RS, b, s, outcome, pd or _D("p"), outputs or {}, issued_at, prev)


def _adm(w, receipts, request, now=NOW, bind=False):
    inp = {"workflow": w, "principal": P.public, "rs_signer": RS.public, "receipts": receipts, "now": now, "request": request}
    return W.bind_promises(inp) if bind else W.admit_step(inp)


def _res(decision, code, step="b", at=None, pending=()):
    return {"decision": decision, "code": code, "step": step, "at": at, "pending": list(pending)}


@pytest.mark.parametrize("op,val,src,code", [
    ("le", 5, 5, None), ("le", 6, 5, "edge_relation"), ("le", 4, 5, None),
    ("ge", 5, 5, None), ("ge", 4, 5, "edge_relation"), ("ge", 6, 5, None),
    ("lt", 5, 5, "edge_relation"), ("lt", 4, 5, None), ("lt", 6, 5, "edge_relation"),
    ("gt", 5, 5, "edge_relation"), ("gt", 6, 5, None), ("gt", 4, 5, "edge_relation"),
    ("le", -1, 0, None), ("gt", 1, 0, None), ("lt", 0, 0, "edge_relation"),
])
def test_edge_relations_exact(op, val, src, code):
    b = _body(edges=[_edge("a", "b", op)])
    w = G.sign_workflow(P, b)
    a = _rc(b, "a", {"out": G.wf_output(src, num=True)})
    want = _res("allow", None) if code is None else _res("deny", code, at=0)
    assert _adm(w, [a], _rq("b", {"in": val})) == want


def test_edge_value_digest_unit_taint():
    b = _body()
    w = G.sign_workflow(P, b)
    a = _rc(b, "a", {"out": G.wf_output("x")})
    assert _adm(w, [a], _rq("b", {"in": "x"})) == _res("allow", None)
    assert _adm(w, [a], _rq("b", {"in": "y"})) == _res("deny", "edge_digest", at=0)
    assert _adm(w, [a], _rq("b", {"other": "x"})) == _res("deny", "edge_missing", at=0)
    assert _adm(w, [_rc(b, "a", {"o2": G.wf_output("x")})], _rq("b", {"in": "x"})) == _res("deny", "edge_missing", at=0)
    b2 = _body(edges=[_edge("a", "b", "le")])
    w2 = G.sign_workflow(P, b2)
    assert _adm(w2, [_rc(b2, "a", {"out": G.wf_output(5)})], _rq("b", {"in": 5})) == _res("deny", "edge_value", at=0)
    assert _adm(w2, [_rc(b2, "a", {"out": G.wf_output(5, num=True)})], _rq("b", {"in": "5"})) == _res("deny", "edge_value", at=0)
    assert _adm(w2, [_rc(b2, "a", {"out": G.wf_output(5, num=True)})], _rq("b", {"in": True})) == _res("deny", "edge_value", at=0)
    b3 = _body(edges=[_edge("a", "b", "le", unit="usd")])
    w3 = G.sign_workflow(P, b3)
    ok = _rc(b3, "a", {"out": G.wf_output(5, unit="usd", num=True)})
    assert _adm(w3, [ok], _rq("b", {"in": 5}, units={"in": "usd"})) == _res("allow", None)
    assert _adm(w3, [ok], _rq("b", {"in": 5}, units={"in": "eur"})) == _res("deny", "edge_unit", at=0)
    assert _adm(w3, [ok], _rq("b", {"in": 5})) == _res("deny", "edge_unit", at=0)
    eur = _rc(b3, "a", {"out": G.wf_output(5, unit="eur", num=True)})
    assert _adm(w3, [eur], _rq("b", {"in": 5}, units={"in": "eur"})) == _res("deny", "edge_unit", at=0)
    b4 = _body(edges=[_edge("a", "b", deny_labels=["pii"])])
    w4 = G.sign_workflow(P, b4)
    assert _adm(w4, [_rc(b4, "a", {"out": G.wf_output("x", ["pii"])})], _rq("b", {"in": "x"})) == _res("deny", "taint_flow", at=0)
    assert _adm(w4, [_rc(b4, "a", {"out": G.wf_output("x", ["other"])})], _rq("b", {"in": "x"})) == _res("allow", None)


def test_admission_codes_in_order():
    b = _body()
    w = G.sign_workflow(P, b)
    assert _adm(w, [], _rq("a", {})) == _res("allow", None, "a")
    assert _adm(w, [], _rq("a", {}), now=NOW - 10) == _res("allow", None, "a")
    assert _adm(w, [], _rq("a", {}), now=NOW - 11) == _res("deny", "not_yet", "a")
    assert _adm(w, [], _rq("a", {}), now=NOW + 9) == _res("allow", None, "a")
    assert _adm(w, [], _rq("a", {}), now=NOW + 10) == _res("deny", "expired", "a")
    assert _adm(w, [], _rq("a", {}), now=-1) == _res("deny", "bad_workflow", None)
    assert _adm(w, "x", _rq("a", {})) == _res("deny", "bad_workflow", None)
    assert _adm(dict(w, extra=1), [], _rq("a", {})) == _res("deny", "bad_workflow", None)
    assert _adm(w, [], _rq("a", {}, goal_digest=_D("g"))) == _res("deny", "goal_mismatch", "a")
    assert _adm(w, [], _rq("a", {}, plan_root=_D("r"))) == _res("deny", "plan_root_mismatch", "a")
    assert _adm(w, [], _rq("zz", {})) == _res("deny", "unplanned_step", "zz")
    assert _adm(w, [], _rq("a", {}, verb="x")) == _res("deny", "step_mismatch", "a")
    assert _adm(w, [], _rq("a", {}, resource="x")) == _res("deny", "step_mismatch", "a")
    assert _adm({"body": b, "sig": G._sign_body(RS, W.WORKFLOW_DOMAIN, b)}, [], _rq("a", {})) == _res("deny", "bad_signature", "a")
    cyc = _body(steps=[_step("a", ["b"]), _step("b", ["a"])], edges=[])
    assert _adm({"body": cyc, "sig": G._sign_body(P, W.WORKFLOW_DOMAIN, cyc)}, [], _rq("a", {})) == _res("deny", "bad_dag", "a")
    a = _rc(b, "a", {"out": G.wf_output("x")})
    assert _adm(w, [a], _rq("a", {})) == _res("deny", "already_done", "a")
    assert _adm(w, [a], _rq("b", {"in": "x"}), now=NOW - 2) == _res("deny", "bad_receipt", "b", 0)
    assert _adm(G.sign_workflow(P, _body(edges=[])), [], _rq("b", {})) == _res("deny", "deps_unmet", "b")
    failed = _rc(b, "a", {"out": G.wf_output("x")}, outcome="failed")
    assert _adm(w, [failed], _rq("b", {"in": "x"})) == _res("deny", "dep_failed", "b")


def test_params_digest_budget_and_freshness():
    pd = hash_canonical({"k": 1})
    b = _body(steps=[_step("a", params_digest=pd), _step("b", ["a"])])
    w = G.sign_workflow(P, b)
    assert _adm(w, [], _rq("a", {"k": 1})) == _res("allow", None, "a")
    assert _adm(w, [], _rq("a", {"k": 2})) == _res("deny", "params_mismatch", "a")
    one = _body(budget={"max_steps": 1, "caps": {}})
    w1 = G.sign_workflow(P, one)
    a1 = _rc(one, "a", {"out": G.wf_output("x")})
    assert _adm(w1, [], _rq("a", {})) == _res("allow", None, "a")
    assert _adm(w1, [a1], _rq("b", {"in": "x"})) == _res("deny", "budget_exceeded", "b")
    two = _body(budget={"max_steps": 2, "caps": {}})
    assert _adm(G.sign_workflow(P, two), [_rc(two, "a", {"out": G.wf_output("x")})], _rq("b", {"in": "x"})) == _res("allow", None)
    zero = _body(budget={"max_steps": 0, "caps": {}})
    assert _adm(G.sign_workflow(P, zero), [], _rq("a", {})) == _res("deny", "budget_exceeded", "a")
    for cap, want in ((5, _res("allow", None)), (4, _res("deny", "budget_exceeded"))):
        cb = _body(steps=[_step("a", cost={"usd": 2}), _step("b", ["a"], cost={"usd": 3})], budget={"max_steps": 5, "caps": {"usd": cap}})
        assert _adm(G.sign_workflow(P, cb), [_rc(cb, "a", {"out": G.wf_output("x")})], _rq("b", {"in": "x"})) == want
    cb = _body(steps=[_step("a", cost={"usd": 2}), _step("b", ["a"])], budget={"max_steps": 5, "caps": {"usd": 2}})
    assert _adm(G.sign_workflow(P, cb), [_rc(cb, "a", {"out": G.wf_output("x")})], _rq("b", {"in": "x"})) == _res("allow", None)
    for fresh, want in ((100, _res("allow", None)), (99, _res("deny", "stale_dep"))):
        fb = _body(steps=[_step("a"), _step("b", ["a"], fresh_ms=fresh)])
        assert _adm(G.sign_workflow(P, fb), [_rc(fb, "a", {"out": G.wf_output("x")}, issued_at=NOW - 100)], _rq("b", {"in": "x"})) == want


def test_pipelining_taint_and_bind():
    pb = _body(edges=[_edge("a", "b", promise="p1")])
    pw = G.sign_workflow(P, pb)
    assert _adm(pw, [], _rq("b", {"in": "x"})) == _res("allow", None, pending=[0])
    ub = _body()
    assert _adm(G.sign_workflow(P, ub), [], _rq("b", {"in": "x"})) == _res("escalate", "pipeline_unconstrained")
    tb = _body(steps=[_step("a"), _step("b", ["a"], deny_labels=["pii"])])
    tw = G.sign_workflow(P, tb)
    assert _adm(tw, [_rc(tb, "a", {"out": G.wf_output("x", ["pii"])})], _rq("b", {"in": "x"})) == _res("deny", "taint_flow")
    eb = _body(steps=[_step("a"), _step("b", ["a"], escalate_labels=["pii"])])
    ew = G.sign_workflow(P, eb)
    assert _adm(ew, [_rc(eb, "a", {"out": G.wf_output("x", ["pii"])})], _rq("b", {"in": "x"})) == _res("escalate", "taint_escalate")
    assert _adm(ew, [_rc(eb, "a", {"out": G.wf_output("x", ["ok"])})], _rq("b", {"in": "x"})) == _res("allow", None)
    # bind: the step's own receipt must exist with the same params digest; a pending edge is unmet
    b = _body()
    w = G.sign_workflow(P, b)
    a = _rc(b, "a", {"out": G.wf_output("x")})
    pd = hash_canonical({"in": "x"})
    rb = _rc(b, "b", prev=a, pd=pd)
    assert _adm(w, [a, rb], _rq("b", {"in": "x"}), bind=True) == _res("allow", None)
    assert _adm(w, [a], _rq("b", {"in": "x"}), bind=True) == _res("deny", "params_mismatch")
    assert _adm(w, [a, _rc(b, "b", prev=a)], _rq("b", {"in": "x"}), bind=True) == _res("deny", "params_mismatch")
    assert _adm(w, [a, rb], _rq("b", {"in": "y"}), bind=True) == _res("deny", "params_mismatch")
    # bind with a dependency that has no receipt: deps_unmet even under a declared promise
    rb_first = _rc(pb, "b", pd=pd)
    assert _adm(pw, [rb_first], _rq("b", {"in": "x"}), bind=True) == _res("deny", "deps_unmet")


# ---- undo.undo_transition: exact refusals -------------------------------------------------------------------------------

END = 2_000


def _rec(state, **x):
    return dict({"state": state, "window_end": END, "ver": 3, "attempt": 0}, **x)


def _ref(code, reason):
    return {"outcome": "refused", "code": code, "reason": reason}


VETO = {"kind": "veto", "veto": {"at": 1, "via": "token", "by": "p"}}


@pytest.mark.parametrize("rec,ev,now,want", [
    ("x", VETO, 1, _ref("invalid", "malformed record")),
    (_rec("open", ver=1.5), VETO, 1, _ref("invalid", "malformed record")),
    (_rec("open", window_end=None), VETO, 1, _ref("invalid", "malformed record")),
    (_rec(5), VETO, 1, _ref("invalid", "malformed record")),
    (_rec("open"), VETO, 1.5, _ref("invalid", "now must be a safe integer")),
    (_rec("open"), VETO, True, _ref("invalid", "now must be a safe integer")),
    (_rec("open"), {"kind": "veto", "veto": {"at": 1, "via": "token"}}, 1, _ref("invalid", "malformed veto")),
    (_rec("open"), {"kind": "veto", "veto": {"at": 1, "via": "x", "by": "p"}}, 1, _ref("invalid", "malformed veto")),
    (_rec("open"), {"kind": "veto", "veto": {"at": "1", "via": "token", "by": "p"}}, 1, _ref("invalid", "malformed veto")),
    (_rec("open"), {"kind": "veto", "veto": {"at": 1, "via": "token", "by": 5}}, 1, _ref("invalid", "malformed veto")),
    (_rec("open"), {"kind": "veto", "veto": []}, 1, _ref("invalid", "malformed veto")),
    (_rec("finalized"), VETO, 1, _ref("finalized", "the window is closed and the action is final")),
    (_rec("open"), VETO, END + 1, _ref("window_closed", "the veto window closed at 2000")),
    (_rec("vetoed"), {"kind": "finalize"}, END + 1, _ref("vetoed", "a vetoed record is not finalized")),
    (_rec("compensation_failed"), {"kind": "finalize"}, END + 1, _ref("vetoed", "a compensation_failed record is not finalized")),
    (_rec("open"), {"kind": "finalize"}, END, _ref("window_open", "the veto window is open until 2000")),
    (_rec("compensated"), {"kind": "abort"}, 1, _ref("finalized", "a compensated record cannot be aborted")),
    (_rec("finalized"), {"kind": "abort"}, 1, _ref("finalized", "a finalized record cannot be aborted")),
    (_rec("finalized", outcome="aborted"), {"kind": "abort"}, 1, _ref("finalized", "a finalized record cannot be aborted")),
    (_rec("vetoed", effect={"at": 1}), {"kind": "abort"}, 1,
     _ref("effect_recorded", "the effect ran: it can only be compensated or finalized")),
    (_rec("finalized"), {"kind": "effect"}, 1, _ref("finalized", "a finalized record takes no effect report")),
    (_rec("compensated"), {"kind": "effect"}, 1, _ref("finalized", "a compensated record takes no effect report")),
    (_rec("open"), {"kind": "compensated"}, 1, _ref("not_vetoed", "a open record is not being compensated")),
    (_rec("finalized"), {"kind": "compensated"}, 1, _ref("not_vetoed", "a finalized record is not being compensated")),
    (_rec("open"), {"kind": "compensation_failed"}, 1, _ref("not_vetoed", "a open record is not being compensated")),
    (_rec("compensated"), {"kind": "compensation_failed"}, 1, _ref("not_vetoed", "a compensated record is not being compensated")),
    (_rec("vetoed"), {"kind": "retry"}, 1, _ref("not_failed", "a vetoed record is not retried")),
    (_rec("compensation_failed", attempt=-1), {"kind": "retry"}, 1, _ref("invalid", "malformed record")),
    (_rec("compensation_failed", attempt=1.5), {"kind": "retry"}, 1, _ref("invalid", "malformed record")),
    (_rec("compensation_failed", attempt=None), {"kind": "retry"}, 1, _ref("invalid", "malformed record")),
    (_rec("open"), {"kind": "nope"}, 1, _ref("invalid", "unknown event")),
    (_rec("open"), {}, 1, _ref("invalid", "unknown event")),
    (_rec("open"), "veto", 1, _ref("invalid", "unknown event")),
])
def test_undo_refusals_exact(rec, ev, now, want):
    before = copy.deepcopy(rec)
    assert U.undo_transition(rec, ev, now) == want
    assert rec == before


def test_undo_applied_exact():
    assert U.undo_transition(_rec("open"), VETO, END) == {
        "outcome": "applied", "record": _rec("vetoed", ver=4, veto={"at": 1, "via": "token", "by": "p"}),
        "receipt": {"event": "vetoed", "note": "token"}}
    assert U.undo_transition(_rec("open"), {"kind": "abort"}, 9) == {
        "outcome": "applied", "record": _rec("finalized", ver=4, outcome={"at": 9, "status": "aborted", "reason": "undefined"}),
        "receipt": {"event": "aborted", "note": "undefined"}}
    assert U.undo_transition(_rec("compensation_failed", attempt=0), {"kind": "retry"}, 9) == {
        "outcome": "applied", "record": _rec("vetoed", ver=4, attempt=1), "receipt": {"event": "retried", "note": ""}}
    assert U.undo_transition(_rec("open"), {"kind": "effect", "result": None}, 9)["record"]["effect"] == {"at": 9, "result": None}
    assert U.undo_transition(_rec("vetoed"), {"kind": "compensated"}, 9) == {
        "outcome": "applied", "record": _rec("compensated", ver=4, outcome={"at": 9, "status": "compensated"}),
        "receipt": {"event": "compensated", "note": ""}}
    assert U.undo_transition(_rec("vetoed"), {"kind": "compensation_failed", "reason": 5}, 9) == {
        "outcome": "applied", "record": _rec("compensation_failed", ver=4, outcome={"at": 9, "status": "compensation_failed", "reason": "5"}),
        "receipt": {"event": "compensation_failed", "note": "5"}}
    r = _rec("finalized", outcome={"status": "aborted"})
    assert U.undo_transition(r, {"kind": "abort"}, 9) == {"outcome": "replayed", "record": r}


class _Boom(dict):
    def get(self, *a):
        raise RuntimeError("boom")


def test_undo_evaluation_error_fails_closed():
    assert U.undo_transition(_rec("open"), _Boom(kind="veto"), 1) == _ref("invalid", "evaluation error (fail closed)")
