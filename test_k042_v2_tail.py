"""Kill tests for the remaining atlas_pca.intent_v2 helpers: epoch/guardian pinning, hybrid PQ epochs, strict Merkle leaf
proofs, schema verification errors, ordering at the UTF-8 / UTF-16 boundary, exact error texts and small total wrappers."""
import copy

import pytest

import test_mutation_kill_intent_v2 as T
from atlas_pca import intent_v2 as V
from atlas_pca import pq_backends
from atlas_pca.pca import b64u, canonical_bytes_strict

U = V._UNDEF


def u(*parts):
    return "".join(chr(p) if isinstance(p, int) else p for p in parts)


# ---- check_revocation_epoch ---------------------------------------------------------------------------------------------

def _epoch_ok():
    ids, ep = T._epoch(["pca-intent:map:a"], T.NOW - 1000)
    return ep


def test_an_epoch_without_a_guardian_is_not_signed_by_a_null_guardian():
    ep = {k: v for k, v in _epoch_ok().items() if k != "guardian"}
    assert V.check_revocation_epoch(ep, None, T.NOW) == {"ok": False, "reason": "revocation epoch not signed by the pinned guardian"}
    ep2 = _epoch_ok()
    assert V.check_revocation_epoch(ep2, ep2["guardian"], T.NOW) == {"ok": True}


dil = pytest.importorskip("dilithium_py.ml_dsa")
needs_pq = pytest.mark.skipif(not pq_backends.available("ML-DSA-65"), reason="no ML-DSA-65 backend")


@needs_pq
def test_a_hybrid_epoch_verifies_with_its_pq_signature_under_the_pin():
    pk, sk = dil.ML_DSA_65.keygen()
    pkb = b64u(pk)
    ids, base = T._epoch(["pca-intent:map:a"], T.NOW - 1000)
    body = {k: base[k] for k in ("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after")}
    ep = dict(body, guardian=base["guardian"], alg="hybrid-ed25519-ml-dsa-65", pq_pk=pkb)
    msg = V._epoch_message(ep)
    ep["sig"] = b64u(T._sign(T.REV_AUTH, msg))
    ep["pq_sig"] = b64u(dil.ML_DSA_65.sign(sk, msg))
    g = ep["guardian"]
    assert V.check_revocation_epoch(ep, g, T.NOW, pq_pins={g: pkb}) == {"ok": True}
    assert V.check_revocation_epoch(ep, g, T.NOW, pq_pins={}) == {"ok": False, "reason": "revocation epoch signature invalid"}
    no_sig = {k: v for k, v in ep.items() if k != "pq_sig"}
    assert V.check_revocation_epoch(no_sig, g, T.NOW, pq_pins={g: pkb})["ok"] is False


@needs_pq
def test_a_pq_epoch_without_pq_pk_cannot_be_canonicalised():
    ep = _epoch_ok()
    ep = dict(ep, alg="ml-dsa-65")
    with pytest.raises(TypeError, match="^canonicalize: unsupported type undefined$"):
        V._epoch_message(ep)
    assert V.check_revocation_epoch(ep, ep["guardian"], T.NOW) == {"ok": False, "reason": "revocation epoch check error"}
    with pytest.raises(TypeError, match="^canonicalize: unsupported type undefined$"):
        V._bind_suite_fields({}, "ml-dsa-65", U)
    with pytest.raises(TypeError, match="^canonicalize: unsupported type undefined$"):
        V._epoch_message({k: v for k, v in _epoch_ok().items() if k != "root"})


# ---- verify_action_schema ---------------------------------------------------------------------------------------------

def test_schema_verification_errors_are_reported_exactly(monkeypatch):
    assert V.verify_action_schema(T.SCHEMA, T.KEYS) == {"ok": True}

    def boom(doc):
        raise RuntimeError("boom")

    monkeypatch.setattr(V, "_schema_message", boom)
    assert V.verify_action_schema(T.SCHEMA, T.KEYS) == {"ok": False, "reason": "schema verification error: boom"}


def test_schema_aud_is_bounded_at_256_bytes():
    doc = dict(T.UNSIGNED, aud="a" * 256)
    assert V.action_schema_shape_error(doc, signed=False) is None
    doc = dict(T.UNSIGNED, aud="a" * 257)
    assert V.action_schema_shape_error(doc, signed=False) == "site, aud and version must be non-empty strings"
    doc = dict(T.UNSIGNED, site="s" * 2049)
    assert V.action_schema_shape_error(doc, signed=False) == "site, aud and version must be non-empty strings"
    doc = dict(T.UNSIGNED, version="v" * 129)
    assert V.action_schema_shape_error(doc, signed=False) == "site, aud and version must be non-empty strings"


def test_schema_verb_lookup():
    doc = {"verbs": [{}, {"verb": "a", "n": 1}]}
    assert V.schema_verb(doc, None) is None
    assert V.schema_verb(doc, "a") == {"verb": "a", "n": 1}
    assert V.schema_verb({"verbs": [{"verb": None}]}, None) == {"verb": None}
    with pytest.raises(TypeError, match="^a verb entry must not be null$"):
        V.schema_verb({"verbs": [None]}, "a")
    assert V.schema_verb({"verbs": [5, "x", [1], {"verb": "a"}]}, "a") == {"verb": "a"}


def test_accumulation_params_order_and_errors():
    lo, hi = u(0xE000), u(0xFFFF)
    v = {"params": {"action.params.b": {"type": "integer", "accumulates_into": ["x"]},
                    "action.params." + hi: {"type": "integer", "accumulates_into": ["x"]},
                    "action.params." + lo: {"type": "integer", "accumulates_into": ["x"]},
                    "action.params.a": {"type": "integer", "accumulates_into": ["x"]}}}
    assert V.accumulation_params(v, "x") == ["action.params.a", "action.params.b", "action.params." + lo, "action.params." + hi]
    lone = u(0xD800)  # EF BF BD in UTF-8: after U+E000 although its code point is lower
    v2 = {"params": {"action.params." + lone: {"type": "integer", "accumulates_into": ["x"]},
                     "action.params." + lo: {"type": "integer", "accumulates_into": ["x"]}}}
    assert V.accumulation_params(v2, "x") == ["action.params." + lo, "action.params." + lone]
    with pytest.raises(TypeError, match="^a parameter declaration must be an object$"):
        V.accumulation_params({"params": {"action.params.a": 5}}, "x")
    with pytest.raises(TypeError, match="^expected a JSON object$"):
        V.accumulation_params({"params": [1]}, "x")
    with pytest.raises(TypeError, match="^expected a JSON object$"):
        V.accumulation_params({}, "x")


def test_conform_action_orders_parameters_by_utf8_bytes():
    # a lone surrogate encodes as U+FFFD (EF BF BD), after U+E000 (EE 80 80), though its code point is lower
    lone, bmp = u(0xD800), u(0xE000)
    doc = {"verbs": [{"verb": "v", "kind": "write", "params": {}}]}
    r = V.conform_action(doc, "v", {lone: 1, bmp: 1})
    assert r["code"] == "undeclared_param" and r["path"] == "action.params." + bmp
    d = {"type": "integer", "semantic": "s", "sensitivity": "free"}
    doc = {"verbs": [{"verb": "v", "kind": "write", "params": {"action.params." + lone: d, "action.params." + bmp: d}}]}
    r = V.conform_action(doc, "v", {})
    assert r["code"] == "missing_param" and r["path"] == "action.params." + bmp


def test_canon_projection_orders_parameter_paths_by_utf8_bytes():
    lone, bmp = u(0xD800), u(0xE000)
    doc = {"verbs": [{"verb": "v", "params": {"action.params." + lone: {"type": "boolean"}, "action.params." + bmp: {"type": "boolean"}}}]}
    assert list(V.canon_projection(doc, "v", {lone: True, bmp: False})) == [bmp, lone]


# ---- strict Merkle leaf proofs --------------------------------------------------------------------------------------------

def _proof_fixture():
    ids = ["a", "b", "c", "d", "e"]
    root = T._set(ids)[1]
    return ids, root, T._incl(ids, 2)


def test_leaf_ok_is_strict_about_every_part_of_the_proof():
    ids, root, pr = _proof_fixture()
    assert V._leaf_ok(root, 5, "c", pr) is True
    for bad in (None, 5, "x", [], [pr]):
        assert V._leaf_ok(root, 5, "c", bad) is False, bad
    for bad in (None, 5, ["c"], {"id": "c"}):
        assert V._leaf_ok(root, 5, bad, pr) is False, bad
    assert V._leaf_ok(root, 5, "d", pr) is False  # another leaf
    assert V._leaf_ok(root, 4, "c", pr) is False and V._leaf_ok(root, 6, "c", pr) is False
    assert V._leaf_ok(root, 5, "c", dict(pr, size=4)) is False
    assert V._leaf_ok(root, 5, "c", {k: v for k, v in pr.items() if k != "size"}) is False
    for idx in (5, 6, -1, 1.5, "2", None):
        assert V._leaf_ok(root, 5, "c", dict(pr, index=idx)) is False, idx
    assert V._leaf_ok(root, 5, "c", dict(pr, index=2.0)) is True
    assert V._leaf_ok(root, "5", "c", dict(pr, size="5")) is False  # an internal TypeError fails closed
    assert V._leaf_ok(root, 5, "c", dict(pr, path="x")) is False
    assert V._leaf_ok(root, 5, "c", dict(pr, path=None)) is False
    assert V._leaf_ok(root, 5, "c", dict(pr, path=pr["path"][:-1])) is False
    assert V._leaf_ok(root, 5, "c", dict(pr, path=pr["path"] + [pr["path"][0]])) is False
    flip = lambda s: {"L": "R", "R": "L"}[s]
    for i in range(len(pr["path"])):
        p2 = copy.deepcopy(pr)
        p2["path"][i]["side"] = flip(p2["path"][i]["side"])
        assert V._leaf_ok(root, 5, "c", p2) is False, i
        p3 = copy.deepcopy(pr)
        p3["path"][i] = "x"
        assert V._leaf_ok(root, 5, "c", p3) is False, i
        p4 = copy.deepcopy(pr)
        del p4["path"][i]["hash"]
        assert V._leaf_ok(root, 5, "c", p4) is False, i
        for hh in (b64u(bytes(31)), b64u(bytes(33)), "!!", 5, None, ""):
            p5 = copy.deepcopy(pr)
            p5["path"][i]["hash"] = hh
            assert V._leaf_ok(root, 5, "c", p5) is False, (i, hh)
    assert V._leaf_ok(b64u(bytes(32)), 5, "c", pr) is False


# ---- ordering and small helpers ---------------------------------------------------------------------------------------------

def test_compare_utf8_replaces_each_lone_surrogate_by_one_replacement_character():
    d800, dfff, e000, e001, fffd = u(0xD800), u(0xDFFF), u(0xE000), u(0xE001), u(0xFFFD)
    assert V.compare_utf8(d800, "a") == 1  # EF BF BD > 61
    assert V.compare_utf8("a", d800) == -1
    assert V.compare_utf8(dfff, fffd) == -1  # equal after replacement: UTF-16 code units decide (DFFF < FFFD)
    assert V.compare_utf8(fffd, dfff) == 1
    assert V.compare_utf8(e000, e001) == -1 and V.compare_utf8(e001, e000) == 1  # U+E000 is NOT a surrogate
    assert V.compare_utf8(e000, d800) == -1
    assert V.compare_utf8(d800, dfff) == -1 and V.compare_utf8(dfff, d800) == 1
    assert V.compare_utf8("", d800) == -1
    assert V._fffd("a" + d800 + e000 + dfff) == "a" + fffd + e000 + fffd


def test_sorted_join_is_utf16_code_unit_order():
    astral, ffff, lone = u(0x10000), u(0xFFFF), u(0xD800)
    assert V._sorted_join({ffff: 1, astral: 1}) == astral + "," + ffff
    assert V._sorted_join({"b": 1, "a": 1, "B": 1}) == "B,a,b"
    assert V._sorted_join({lone: 1, "a": 1}) == "a," + lone
    assert V._sorted_join({}) == ""


def test_u16len_at_the_astral_boundary():
    assert V._u16len("") == 0 and V._u16len("ab") == 2
    assert V._u16len(u(0xFFFF)) == 1 and V._u16len(u(0x10000)) == 2 and V._u16len(u(0x10FFFF)) == 2
    assert V._u16len(u("a", 0x10000, 0xFFFF)) == 4


def test_js_strict_eq_on_booleans_and_json_types():
    assert V._js_strict_eq(True, True) is True and V._js_strict_eq(False, False) is True
    assert V._js_strict_eq(True, False) is False and V._js_strict_eq(True, 1) is False and V._js_strict_eq(0, False) is False
    assert V._js_strict_eq(1, 1.0) is True and V._js_strict_eq("1", 1) is False and V._js_strict_eq(None, None) is True
    assert V._js_strict_eq(U, U) is True and V._js_strict_eq(U, None) is False and V._js_strict_eq(None, U) is False
    x = []
    assert V._js_strict_eq(x, x) is True and V._js_strict_eq([], []) is False


def test_error_text_helpers():
    with pytest.raises(TypeError, match="^expected a JSON object$"):
        V._obj_keys([])
    with pytest.raises(TypeError, match="^expected a JSON array$"):
        V._list("x")
    assert V._list([1]) == [1] and V._obj_keys({"a": 1}) == ["a"]
    assert V.intent_goal_v2("S", "D") == "pca-intent:v2:S:D"
    assert V.profile_revocation_scope("p") == "pca-intent-profile:p"
    assert V.profile_revocation_scope(5) == "pca-intent-profile:5"
    assert V.session_revocation_scope(U) == "pca-intent-session:undefined"
    assert V._js_str((1, 2)) == "(1, 2)" and V._js_str({}) == "[object Object]"
    assert type(V._ctx("p: ", "r")) is str and V._ctx("p: ", "r") == "p: r"
    assert V._unsupported(V._ctx("p: ", V.UnsupportedSuiteReason("r"))) is True and V._unsupported(V._ctx("p: ", "r")) is False
    with pytest.raises(TypeError, match="^canonicalize: unsupported type undefined$"):
        V._session_root_body({})
    s = {k: 1 for k in ("v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
                        "question_uri", "expires_at")}
    assert V._session_root_body(s) == s
    for k in s:
        with pytest.raises(TypeError, match="^canonicalize: unsupported type undefined$"):
            V._session_root_body({kk: vv for kk, vv in s.items() if kk != k})


def test_verify_receipt_against_holder_forwards_the_key_set_floor():
    h = T.SEQ_ACC["holder"]
    ks = T._keyset([{"kid": "s2", "pk": T._pub(T.SEQ), "not_before": 0}], version=1)
    assert V.verify_receipt_against_holder(T.RC, h, [ks], T.NOW) is True
    assert V.verify_receipt_against_holder(T.RC, h, [ks], T.NOW, None, None, 1) is True
    assert V.verify_receipt_against_holder(T.RC, h, [ks], T.NOW, None, None, 2) is False


# ---- context errors and the pipeline ---------------------------------------------------------------------------------------------

def test_context_error_texts():
    assert V._session_ctx_error({"session": 5}) == "the session context must be an object"
    assert V._acc_ctx_error({"acc": 5}) == "the accumulator context must be an object"
    assert V._session_ctx_error({}) is None and V._acc_ctx_error({}) is None


def test_layers_see_empty_params_when_the_verifier_holds_none():
    org = {"org": {"predicates": [{"verb": "air.book", "where": [{"field": "action.params.zzz", "op": "exists", "value": False}]}]}}
    c = T._ctx(layers=org)
    del c["params"]
    assert T._check(T._decide(ctx=c), "layers") == {"name": "layers", "ok": True}


def test_wb_internal_error_is_a_facts_failure(monkeypatch):
    def boom(inp):
        raise RuntimeError("boom")

    monkeypatch.setattr(V, "decide_intent_wb", boom)
    d = T._decide()
    assert T._check(d, "facts") == {"name": "facts", "ok": False, "reason": "W-B error (fail closed): boom"}
    assert "intent v2 error" not in str(d)


def test_delta_revocation_id_of_a_grant_without_an_id():
    S = T._root_of(revocation=T.REV_S)
    R = T.session_root_digest(S)
    g = T._grant(root=R)
    p = T._pcactn(g, intent_session=T._is(root=R))
    g2 = {k: v for k, v in g.items() if k != "id"}
    seen = {}

    def spy(ev, **kw):
        seen["ids"] = kw["ids"]
        return {"ok": True}

    orig = V.check_session_revocation
    V.check_session_revocation = spy
    try:
        ev = T._ev([], T.NOW - 1000)
        c = T._ctx(session={"root": S, "grants": [], "revocation": ev})
        T._sess(p, g2, c)
    finally:
        V.check_session_revocation = orig
    assert "pca-intent:delta:undefined" in seen["ids"]
