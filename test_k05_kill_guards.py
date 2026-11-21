"""k05 mutation-kill tests for refusal guards in verify / confirm / attest / authorize paths that a later check also refuses.
Each test calls the inner function directly, or replaces the later check with a stub, so that only the guard under test can
refuse. Expectations are the TypeScript reference's results (packages/pca/src)."""
import json
import types

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import ec

from atlas_pca import a2a
from atlas_pca import actions as A
from atlas_pca import attest_azure as AZ
from atlas_pca import attest_common as C
from atlas_pca import attest_intel as AI
Z = __import__("sys").modules["atlas_pca.authorize"]  # the package re-exports the function under the same name
from atlas_pca import caveat_lang as CL
from atlas_pca import intent_history as IH
from atlas_pca import intent_v2 as V2
from atlas_pca import k3 as K3
from atlas_pca import missing_context as MC
from atlas_pca import optimistic as OP
from atlas_pca import policy_link as PL
from atlas_pca import server as SV
from atlas_pca import sigstore_bundle as SB
from atlas_pca import undo as U
from atlas_pca.pca import b64u
from test_k05_kill_actions import TINY, overlay, signed_tpl, sv, KT
from test_k05_kill_attest_crypto import base, maa_token, run as az_run, xf
from test_k05_kill_attest_intel import _signed
from test_k05_kill_authorize import run as authz_run
from test_k05_kill_intent_v2_shapes import CONF
from test_k05_kill_intel import _keys
from test_k05_kill_ops import K, _rbody, _rsign


# ---- committed earlier ------------------------------------------------------------------------------------------------------

def test_signed_json_body_that_is_not_an_object_is_refused(monkeypatch):
    k = _keys()[0]
    raw = '{"a":1}'
    text = _signed(raw, k)
    orig = AI.js_json_loads
    monkeypatch.setattr(AI, "js_json_loads", lambda t: [1] if t == raw else orig(t))
    assert AI._verify_signed_json(text, "tcbInfo", k.public_key()) == {"error": "tcbInfo is not an object"}
    monkeypatch.setattr(AI, "js_json_loads", orig)
    assert AI._verify_signed_json(text, "tcbInfo", k.public_key()) == {"body": {"a": 1}}


def test_signed_json_document_that_is_not_an_object_has_no_signature(monkeypatch):
    k = _keys()[0]
    raw = '{"a":1}'
    text = _signed(raw, k)
    orig = AI.js_json_loads
    monkeypatch.setattr(AI, "js_json_loads", lambda t: [] if t == text else orig(t))
    assert AI._verify_signed_json(text, "tcbInfo", k.public_key()) == {"error": "tcbInfo signature missing or malformed"}


def test_ecdsa_raw_refuses_a_zero_r_or_s_before_the_verify(monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    monkeypatch.setattr(C, "ecdsa_verify_der", lambda *a: True)
    one = (1).to_bytes(32, "big")
    zero = bytes(32)
    assert C.ecdsa_verify_raw(key, one + one, b"d", "sha256") is True
    assert C.ecdsa_verify_raw(key, zero + one, b"d", "sha256") is False
    assert C.ecdsa_verify_raw(key, one + zero, b"d", "sha256") is False
    assert C.ecdsa_verify_raw(key, zero + zero, b"d", "sha256") is False


# ---- 1 a2a / 2 actions -------------------------------------------------------------------------------------------------------

def test_resume_gate_absent_need_is_refused_without_decoding(monkeypatch):
    monkeypatch.setattr(a2a, "decode_need", lambda v: {"ok": True, "need": {"verb": "v", "resource": "r"}})
    act = {"verb": "v", "resource": "r"}
    assert a2a.resume_gate("auth-required", None, "d", act) == "no_valid_need"
    assert a2a.resume_gate("auth-required", "x", "d", act) == "answer_not_bound_to_need"


def test_schema_floor_rev_order_with_only_the_rev_check(monkeypatch):
    monkeypatch.setattr(A, "_svf_leq", lambda p, q: True)
    low = "schema_floor_forged: floors.rev is below the declared reversibility"

    def fl(rev):
        return dict(A.profile(), rev=rev)
    assert A.schema_verb_floor_error(sv(reversibility="rate_limited", floors=fl("bogus")), TINY, None) == low
    assert A.schema_verb_floor_error(sv(reversibility="rate_limited", floors=fl("reversible")), TINY, None) == low
    assert A.schema_verb_floor_error(sv(reversibility="rate_limited", floors=fl("irreversible")), TINY, None) is None
    assert A.schema_verb_floor_error(sv(reversibility="bogus", floors=fl("bogus")), TINY, None) is None
    assert A.schema_verb_floor_error(sv(reversibility="bogus", floors=fl("reversible")), TINY, None) is None


# ---- 3 attest_azure ----------------------------------------------------------------------------------------------------------

def test_azure_missing_signing_x5c_has_a_default_reason(monkeypatch):
    monkeypatch.setattr(AZ, "_resolve_signing_x5c", lambda h, j: {})
    assert az_run(token=maa_token(base())) == xf("no signing x5c available")
    monkeypatch.setattr(AZ, "_resolve_signing_x5c", lambda h, j: {"reason": "why"})
    assert az_run(token=maa_token(base())) == xf("why")


# ---- 4 attest_common ---------------------------------------------------------------------------------------------------------

def test_js_json_loads_literal_scan_stops_at_the_end_of_the_literal(monkeypatch):
    def loads(text, **kw):
        raise json.JSONDecodeError("Expecting value", text, 0)
    monkeypatch.setattr(C, "json", types.SimpleNamespace(loads=loads))
    for text in ("truex", "nullx", "falsex"):
        with pytest.raises(C.JsError) as e:
            C.js_json_loads(text)
        assert str(e.value) == "Unexpected token 'x', \"%s\" is not valid JSON" % text


# ---- 7 authorize -------------------------------------------------------------------------------------------------------------

def test_non_mapping_require_assurance_is_replaced_before_unmet_assurance(monkeypatch):
    seen = []
    monkeypatch.setattr(Z, "unmet_assurance", lambda report, require: seen.append(require) or "assurance: spy")
    r = authz_run(require_assurance=["x"])
    assert seen == [{"invalid": True}] and "assurance: spy" in r.reasons and r.checks["assurance"] == "fail"


# ---- 8 caveat_lang -----------------------------------------------------------------------------------------------------------

def test_window_nonce_that_is_not_a_string_is_refused(monkeypatch):
    monkeypatch.setattr(CL, "decode_b64u_strict", lambda s, n=None: b"\0" * 16)
    a = {"iat": 1, "not_after": 2, "nonce": 5, "sig": "s"}
    assert CL._window_error(a, "a discharge") == "nonce must be canonical base64url of at least 16 bytes"
    assert CL._window_error(dict(a, nonce="x"), "a discharge") is None


# ---- 9 k3 -------------------------------------------------------------------------------------------------------------------

def test_verify_body_requires_a_canonical_64_byte_signature(monkeypatch):
    monkeypatch.setattr(K3, "_verify_b64u", lambda *a: True)
    assert K3.verify_body("d\0", {"a": 1}, "s", b64u(bytes(64))) is True
    assert K3.verify_body("d\0", {"a": 1}, "s", "AAAA") is False
    assert K3.verify_body("d\0", {"a": 1}, "s", b64u(bytes(63))) is False


def test_list_cursor_empty_payload_is_malformed_even_if_it_decoded(monkeypatch):
    c = json.dumps({"v": 1, "bind": "b", "skip": 0, "signer": "x"}).encode()
    monkeypatch.setattr(K3, "decode_b64u_strict", lambda s, n=None: c)
    assert K3.verify_list_cursor(".sig", "x") == {"ok": False, "reason": "malformed"}
    assert K3.verify_list_cursor("p.sig", "x") == {"ok": False, "reason": "signature"}


# ---- 10 undo -----------------------------------------------------------------------------------------------------------------

def test_undo_receipt_signature_shape_is_checked_before_the_verify(monkeypatch):
    monkeypatch.setattr(U, "_verify_b64u", lambda *a: True)
    good = _rsign(_rbody())
    assert U.verify_undo_receipt(good, K.public) is True
    assert U.verify_undo_receipt(dict(good, sig="AAAA"), K.public) is False
    assert U.verify_undo_receipt(dict(good, sig=b64u(bytes(65))), K.public) is False


def test_u16_head_never_splits_a_surrogate_pair():
    assert U._u16_head("a\U0001F600", 2) == "a"
    assert U._u16_head("\U0001F600", 1) == ""
    assert U._u16_head("a\U0001F600", 3) == "a\U0001F600"
    assert U._u16_head("ab", 2) == "ab"


# ---- 11 intent ---------------------------------------------------------------------------------------------------------------

def test_is_time_refuses_negative_zero_itself(monkeypatch):
    monkeypatch.setattr(IH, "_is_safe_int", lambda x: True)
    assert IH._is_time(-0.0) is False
    assert IH._is_time(0.0) is True and IH._is_time(0) is True


def test_confirmation_ts_must_be_a_number_before_the_safe_int_check(monkeypatch):
    monkeypatch.setattr(V2, "_is_safe_int", lambda v: True)
    TS = "confirmation: ts must be a non-negative safe integer"
    for bad in (True, False, "0", None):
        assert V2.confirmation_shape_error(dict(CONF, ts=bad)) == TS
    assert V2.confirmation_shape_error(dict(CONF, ts=0)) is None


# ---- 12 server ---------------------------------------------------------------------------------------------------------------

def test_extractors_ignore_a_non_object_envelope(monkeypatch):
    class Duck(list):
        def get(self, k):
            return "answer"
    monkeypatch.setattr(SV, "strict_parse", lambda t: Duck())
    assert SV.extract_escalation_answer({}, "x") is None
    assert SV.extract_workflow_step({}, "x") is None
    monkeypatch.setattr(SV, "strict_parse", lambda t: {"escalation_answer": "a", "workflow": "w"})
    assert SV.extract_escalation_answer({}, "x") == "a" and SV.extract_workflow_step({}, "x") == "w"


# ---- 13 missing_context ------------------------------------------------------------------------------------------------------

def _collect(field, ctx, monkeypatch):
    monkeypatch.setattr(MC, "evaluate_condition_tri", lambda c, x: "unknown")
    monkeypatch.setattr(MC, "resolve_path", lambda x, p: {"found": True, "value": None})
    out, ill = set(), [False]
    MC._collect({"field": field, "op": "eq", "value": 1}, ctx, out, ill)
    return out, ill[0]


def test_collect_params_guard_each_alone(monkeypatch):
    assert _collect("action.params.x", {"action": {"params": 5}}, monkeypatch) == ({"action.params.x"}, False)  # the sub-path form
    assert _collect("action.params", {"action": {"params": 5}}, monkeypatch) == ({"action.params"}, False)
    assert _collect("action.params", {"action": {"params": {}}}, monkeypatch) == (set(), True)
    assert _collect(5, {"action": {"params": 5}}, monkeypatch) == (set(), True)       # a non-string field
    assert _collect("action.params", 5, monkeypatch) == ({"action.params"}, False)    # a non-object context
    assert _collect("action.params", {"action": 5}, monkeypatch) == ({"action.params"}, False)


# ---- 14 sigstore_bundle ------------------------------------------------------------------------------------------------------

def test_oid_with_an_empty_body_is_not_an_oid():
    b = b"\x06\x80"
    assert _fails_oid(b, SB._Tlv(0x06, 0, 2, 2)) == "not an OID"


def _fails_oid(b, t):
    with pytest.raises(SB._Fail) as e:
        SB._oid(b, t)
    return str(e.value)


# ---- 15 policy_link ----------------------------------------------------------------------------------------------------------

def test_resolve_link_names_a_refusal_without_a_reason(monkeypatch):
    t = signed_tpl()
    dg = PL.template_digest(t["def"])
    reg = {"templates": {dg: t}, "trusted": [KT.public], "overlays": [overlay(dg)]}
    ref = {"template_id": "tpl", "version_digest": dg, "slots": {"s": "v"}}
    monkeypatch.setattr(PL, "verify_tighten", lambda o, tr: {"ok": False})
    assert PL.resolve_link(ref, reg) == {"ok": False, "reason": "overlay refused"}
    monkeypatch.setattr(PL, "verify_template", lambda tt, tr: {"ok": False})
    assert PL.resolve_link(ref, reg) == {"ok": False, "reason": "template refused"}


# ---- 16 optimistic -----------------------------------------------------------------------------------------------------------

def test_settlement_passes_absent_suite_members_as_undefined(monkeypatch):
    seen = []
    monkeypatch.setattr(OP, "_pinned_suite_error", lambda *a: seen.append(a) or None)
    rec = {"claimId": "c", "action": "open", "amount": 1, "from": "a", "to": "b", "at": 1, "evidenceDigest": "", "sig": "s"}
    assert OP.settlement_wire_check(rec, "g") == "ok"
    assert seen[0][2] is OP._UNDEF and seen[0][5] is OP._UNDEF
    assert OP.settlement_wire_check(dict(rec, pq_pk="k", pq_sig="q"), "g") == "ok"
    assert seen[1][2] == "k" and seen[1][5] == "q"
