"""k05 mutation kills (misc group): fresh_at, runtime_claim, lease, passport, blueprint, forbid_certificate, pca_grant,
provenance_gate, predicates, policy_classes, protect, refusal_help, revocation_staleness and two pca.py paths.
Expectations follow the TypeScript reference (fresh-at.ts, passport.ts, pca-grants/src/blueprint.ts, lease.ts,
forbid-certificate.ts, pca-grant-details.ts, predicates.ts, policy-classes.ts, refusal-help.ts, intent-binding.ts)."""
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.blueprint import MemoryBlueprintStore
import collections
import importlib
import types

import pytest

from atlas_pca.agent import KeyPair, _sign_body, issue_passport, sign_artifact
from atlas_pca.pca import b64u, verify_pcactn_core
from test_fresh_at_vectors import DOC as FA_DOC

FA = importlib.import_module("atlas_pca.fresh_at")
RC = importlib.import_module("atlas_pca.runtime_claim")
L = importlib.import_module("atlas_pca.lease")
PP = importlib.import_module("atlas_pca.passport")
BP = importlib.import_module("atlas_pca.blueprint")
FC = importlib.import_module("atlas_pca.forbid_certificate")
PG = importlib.import_module("atlas_pca.pca_grant")
PV = importlib.import_module("atlas_pca.provenance_gate")
PR = importlib.import_module("atlas_pca.predicates")
PC = importlib.import_module("atlas_pca.policy_classes")
PT = importlib.import_module("atlas_pca.protect")
RH = importlib.import_module("atlas_pca.refusal_help")
RS = importlib.import_module("atlas_pca.revocation_staleness")
PCA = importlib.import_module("atlas_pca.pca")

KP = KeyPair(bytes([1]) * 32)
KP2 = KeyPair(bytes([2]) * 32)
MAX_SAFE = 9007199254740991


def _raiser(*_a, **_k):
    raise RuntimeError("boom")


# ===================================================================================================== fresh_at

def _tok(**over):
    body = dict(v=1, scope="s", revocation_epoch=1, ledger_tree_size=1, budget_version=1, policy_revision=1,
                policy_digest="d", issued_at=1000, signer=KP.public)
    body.update(over)
    sig = _sign_body(KP, FA.FRESH_AT_DOMAIN, {k: body[k] for k in FA._BODY_KEYS})
    return dict(body, sig=sig)


def test_fresh_at_verify_accepts_bounds():
    assert FA.verify_fresh_at(_tok(), KP.public) is True
    assert FA.verify_fresh_at(_tok(scope="x" * 256), KP.public) is True
    assert FA.verify_fresh_at(_tok(policy_digest="x" * 128), KP.public) is True


@pytest.mark.parametrize("over", [
    {"scope": "x" * 257}, {"scope": "x" * 300}, {"policy_digest": "x" * 129}, {"policy_digest": "x" * 200},
    {"scope": ""}, {"policy_digest": ""}, {"v": 2}, {"issued_at": -1}, {"revocation_epoch": -1}, {"ledger_tree_size": -1},
    {"budget_version": -1}, {"policy_revision": -1},
])
def test_fresh_at_verify_refuses_each_bad_field(over):
    assert FA.verify_fresh_at(_tok(**over), KP.public) is False


def test_fresh_at_verify_signer_must_equal_member():
    # member names KP2 but KP signed it: verifies under KP, so only the signer comparison refuses it
    assert FA.verify_fresh_at(_tok(signer=KP2.public), KP.public) is False


def test_fresh_at_verify_refuses_non_dict_mapping():
    assert FA.verify_fresh_at(types.MappingProxyType(_tok()), KP.public) is False


def test_fresh_at_verify_internal_error_refuses(monkeypatch):
    monkeypatch.setattr(FA, "verify_body", _raiser)
    assert FA.verify_fresh_at(_tok(), KP.public) is False


def test_check_fresh_at_internal_error_is_bad_token():
    assert FA.check_fresh_at(_tok(), None, KP.public, "s", 1000) == {"decision": "deny", "code": "bad_token"}


def test_fresh_at_wire_bounds_and_messages():
    assert FA.validate_fresh_at_wire(_tok()) is None
    assert FA.validate_fresh_at_wire(_tok(scope="x" * 256)) is None
    assert FA.validate_fresh_at_wire(_tok(policy_digest="x" * 128)) is None
    msg = "'fresh_at' scope and policy_digest must be non-empty strings"
    for over in ({"scope": "x" * 257}, {"scope": "x" * 300}, {"policy_digest": "x" * 129}, {"policy_digest": "x" * 200},
                 {"scope": ""}, {"policy_digest": ""}):
        assert FA.validate_fresh_at_wire(_tok(**over)) == msg
    short = _tok(signer=b64u(bytes(31)))
    assert FA.validate_fresh_at_wire(short) == "'fresh_at.signer' is not canonical base64url (32 bytes)"


def test_decide_fresh_at_none_results():
    assert FA.decide_fresh_at(FA.ABSENT, None, 0) == {"status": "none"}
    pol = {"signer": "s", "scope": "x", "local": {}}
    assert FA.decide_fresh_at(FA.ABSENT, pol, 0) == {"status": "none"}
    assert FA.decide_fresh_at(FA.ABSENT, dict(pol, require=False), 0) == {"status": "none"}


# ===================================================================================================== runtime_claim

def _claim(**over):
    c = {"v": 1, "class": "os_confined", "passport_digest": "pd", "evidence_digest": "ed", "iat": 1000, "exp": 2000,
         "attestor": KP.public}
    c.update(over)
    c["sig"] = _sign_body(KP, RC.RUNTIME_CLAIM_DOMAIN, {k: v for k, v in c.items() if k != "sig"})
    return c


def _rc(claim, now=1500, pd="pd", ev=("ed",)):
    return RC.verified_runtime_class(claim, [KP.public], pd, list(ev), now)


def test_runtime_claim_window_and_ok():
    assert _rc(_claim()) == "os_confined"
    assert _rc(_claim(), now=1000) == "os_confined"
    assert _rc(_claim(), now=2000) == "none"
    assert _rc(_claim(), now=999) == "none"


def test_runtime_claim_each_guard_alone():
    assert _rc(types.MappingProxyType(_claim())) == "none"
    assert _rc(_claim(extra=1)) == "none"
    assert _rc(_claim(v=2)) == "none"
    assert _rc(_claim(**{"class": "bogus"})) == "none"
    assert _rc(_claim(iat=-1)) == "none"
    assert _rc(_claim(iat=0, exp=2), now=True) == "none"


@pytest.mark.parametrize("n", [129, 200])
def test_runtime_claim_digest_length(n):
    d = "x" * n
    assert _rc(_claim(passport_digest=d), pd=d) == "none"
    assert _rc(_claim(evidence_digest=d), ev=(d,)) == "none"


def test_runtime_claim_digest_128_ok():
    d = "x" * 128
    assert _rc(_claim(passport_digest=d), pd=d) == "os_confined"
    assert _rc(_claim(evidence_digest=d), ev=(d,)) == "os_confined"


def test_runtime_claim_internal_error_is_none(monkeypatch):
    monkeypatch.setattr(RC, "verify_body", _raiser)
    assert _rc(_claim()) == "none"


# ===================================================================================================== lease

def _lbody(**over):
    b = dict(v=1, lease_id="L9", path="db/x", grant_ref="g9", holder="agent", requester="alice", approvers=["bob"],
             justification_digest="j1", seq=1, issued_at=1000, renewed_at=1000, expires_at=2000, max_ttl=10000, authority=KP.public)
    b.update(over)
    return b


def _lease(**over):
    b = _lbody(**over)
    b["sig"] = _sign_body(KP, L.LEASE_DOMAIN, {k: b[k] for k in L._BODY_KEYS})
    return b


def test_lease_renewal_may_keep_renewed_at():
    reg = L.LeaseRegistry({"authorities": [KP.public]}, MemoryAtomicKv())
    assert reg.accept(_lease()) == {"ok": True, "replaced": True, "seq": 1}
    assert reg.accept(_lease(seq=2, renewed_at=1000, expires_at=3000, justification_digest="j2")) == \
        {"ok": True, "replaced": True, "seq": 2}


# ===================================================================================================== passport

ISS = KeyPair(bytes([5]) * 32)
SUB = KeyPair(bytes([6]) * 32)
_DEL = object()


def _pp(hw=False, **over):
    ident = {"model_id": "m", "operator": "o", "hardware_rooted": hw, "issued_at": 1000}
    ident.update(over)
    return issue_passport(ident)


def _sp(passport=None, **over):
    body = {"typ": "atlas-pca/passport", "ver": 1, "passport": passport or _pp(), "iss": ISS.public, "sub": SUB.public,
            "iat": 1000, "nbf": 1000, "exp": 5000}
    body.update(over)
    for k in [k for k, v in body.items() if v is _DEL]:
        del body[k]
    return sign_artifact("atlas-pca/passport-sig/v1\0", body, ISS)


def _vp(sp, now=2000, **kw):
    kw.setdefault("revoked", lambda *_a: False)
    return PP.verify_passport(sp, [ISS.public], now, **kw)


def test_passport_ok_and_safe_integer_edge():
    assert _vp(_sp()) is None
    assert _vp(_sp(iat=MAX_SAFE)) is None
    assert _vp(_sp(iat=float(MAX_SAFE))) is None


def test_passport_typ_and_passport_object():
    assert _vp(_sp(typ="x")) == "malformed"
    assert _vp(_sp(passport=5)) == "malformed"


def test_passport_each_required_field_alone():
    assert _vp(_sp(iss="")) == "malformed"
    assert _vp(_sp(sub="")) == "malformed"
    sp = _sp()
    sp["sig"] = ""
    assert _vp(sp) == "malformed"
    pp = _pp()
    pp["id"] = ""
    assert _vp(_sp(passport=pp)) == "malformed"
    assert _vp(_sp(passport=_pp(model_id=""))) == "malformed"
    assert _vp(_sp(passport=_pp(operator=""))) == "malformed"
    pp = _pp()
    pp["hardware_rooted"] = "yes"
    assert _vp(_sp(passport=pp)) == "malformed"


def test_passport_time_members():
    assert _vp(_sp(iat=_DEL)) == "malformed"
    assert _vp(_sp(nbf=_DEL)) == "malformed"
    assert _vp(_sp(exp=_DEL)) == "malformed"
    assert _vp(_sp(nbf=1000, exp=1000)) == "malformed"
    assert _vp(_sp(nbf=1000, exp=999)) == "malformed"
    assert _vp(_sp(), now=MAX_SAFE + 1) == "malformed"
    assert _vp(_sp(), now=MAX_SAFE) == "expired"


def test_passport_uncanonical_body_is_malformed():
    sp = _sp()
    sp["extra"] = 2**60  # outside the strict profile (|n| > 2^53-1)
    assert _vp(sp) == "malformed"


def test_passport_id_mismatch(monkeypatch):
    pp = _pp()
    pp["id"] = "x" * 43
    assert _vp(_sp(passport=pp)) == "id_mismatch"
    monkeypatch.setattr(PP, "hash_canonical", lambda *_a: (_ for _ in ()).throw(TypeError("no")))
    assert _vp(_sp()) == "id_mismatch"


def test_passport_skew_and_expiry():
    assert _vp(_sp(), now=999, clock_skew_ms=0) == "not_yet_valid"
    assert _vp(_sp(), now=999, clock_skew_ms=1) is None
    assert _vp(_sp(), now=5004, clock_skew_ms=5) is None
    assert _vp(_sp(), now=5005, clock_skew_ms=5) == "expired"
    assert _vp(_sp(), now=5000, clock_skew_ms=0) == "expired"


def test_passport_revoked_callback_arguments():
    seen = []
    sp = _sp()
    assert _vp(sp, revoked=lambda *a: seen.append(a) or False) is None
    assert seen == [(sp["passport"]["id"], ISS.public, SUB.public)]


def _hw(doc, at=2000):
    return _sp(passport=_pp(hw=True), evidence={"document": doc, "at": at})


def test_passport_hardware_document_members():
    assert _vp(_hw({}, 2000)) == "hardware_evidence_missing"
    assert _vp(_hw({"nonce": ""}, 2000)) == "hardware_evidence_missing"
    sp = _sp(passport=_pp(hw=True), evidence={"document": {"nonce": "n"}})
    assert _vp(sp) == "hardware_evidence_missing"


def test_passport_hardware_age_bounds():
    ok = _hw({"nonce": "n"}, 2000)
    assert _vp(ok, max_evidence_age_ms=0) == "hardware_verifier_missing"
    assert _vp(ok, max_evidence_age_ms=-1) == "hardware_evidence_stale"
    assert _vp(_hw({"nonce": "n"}, 1900), max_evidence_age_ms=100) == "hardware_verifier_missing"
    assert _vp(_hw({"nonce": "n"}, 1899), max_evidence_age_ms=100) == "hardware_evidence_stale"
    assert _vp(_hw({"nonce": "n"}, 2005), clock_skew_ms=5) == "hardware_verifier_missing"
    assert _vp(_hw({"nonce": "n"}, 2006), clock_skew_ms=5) == "hardware_evidence_stale"


# ===================================================================================================== blueprint

def _bbody(**over):
    b = dict(v=1, id="bp1", key="K", ceiling=[], epoch=1, status="active", issued_at=1000, operator=KP.public)
    b.update(over)
    return b


def _bp(signer=KP, **over):
    b = _bbody(**over)
    b["sig"] = _sign_body(signer, BP.AGENT_BLUEPRINT_DOMAIN, BP._body(b))
    return b


def test_blueprint_well_formed_each_field():
    assert BP._well_formed(_bbody()) is True
    assert BP._well_formed(_bbody(id="x" * 128, key="y" * 128, operator="z" * 128)) is True
    for over in ({"id": ""}, {"key": ""}, {"operator": ""}, {"id": "x" * 129}, {"id": "x" * 200}, {"key": "x" * 129},
                 {"key": "x" * 200}, {"operator": "x" * 129}, {"operator": "x" * 200}, {"v": 2}, {"epoch": -1},
                 {"issued_at": -1}, {"status": "weird"}, {"max_depth": 0}, {"expires_at": -1}):
        assert BP._well_formed(_bbody(**over)) is False, over
    assert BP._well_formed(_bbody(max_depth=1, expires_at=0)) is True


def test_blueprint_runtime_pins_and_ceiling():
    assert BP._well_formed(_bbody(runtime_pins=[{"model_id": "m"}])) is True
    assert BP._well_formed(_bbody(runtime_pins=[])) is False
    assert BP._well_formed(_bbody(runtime_pins=[{"model_id": "m"}] * 17)) is False
    assert BP._well_formed(_bbody(ceiling=[{"type": "t"}] * 32)) is True
    assert BP._well_formed(_bbody(ceiling=[{"type": "t"}] * 33)) is False
    assert BP._well_formed(_bbody(ceiling={})) is False
    assert BP._well_formed(_bbody(ceiling=[{"type": 5}])) is False
    assert BP._well_formed(_bbody(ceiling=None)) is False


def test_blueprint_operator_changed():
    reg = BP.BlueprintRegistry([KP.public, KP2.public], MemoryBlueprintStore())
    assert reg.accept(_bp()) == {"ok": True, "replaced": True}
    assert reg.accept(_bp(signer=KP2, operator=KP2.public)) == {"ok": False, "code": "operator_changed"}


# ===================================================================================================== forbid_certificate

def _cert(rows, decision, kind, wid, shadowed):
    return {"v": 1, "kind": "forbid-wins", "clauses": rows, "decision": decision, "winner": {"kind": kind, "id": wid},
            "shadowed": shadowed}


def _row(i, kind, value="true", **kw):
    return dict({"id": i, "kind": kind, "value": value}, **kw)


def test_forbid_cert_baseline_and_kind():
    c = _cert([_row("p", "permit")], "allow", "permit", "p", [])
    assert FC.certificate_consistent(c) is True
    assert FC.certificate_consistent(dict(c, kind="x")) is False


def test_forbid_cert_winner_and_shadowed_shapes():
    c = _cert([_row("p", "permit")], "allow", "permit", "p", [])
    assert FC.certificate_consistent(dict(c, winner=types.MappingProxyType(c["winner"]))) is False
    assert FC.certificate_consistent(dict(c, winner=None)) is False
    mal = {"v": 1, "kind": "forbid-wins", "clauses": [], "decision": "deny", "winner": {"kind": "malformed", "id": None},
           "shadowed": []}
    assert FC.certificate_consistent(mal) is True
    assert FC.certificate_consistent(dict(mal, shadowed=())) is False
    assert FC.certificate_consistent(dict(mal, winner={"kind": "malformed", "id": "x"})) is False


def test_forbid_cert_row_must_be_dict():
    row = types.MappingProxyType(_row("p", "permit"))
    assert FC.certificate_consistent(_cert([row], "allow", "permit", "p", [])) is False


def test_forbid_cert_signer_precedence():
    rows = [_row("a", "forbid", signer="user"), _row("b", "forbid", signer="org"), _row("c", "forbid")]
    c = _cert(rows, "deny", "forbid", "b", ["a", "c"])
    assert FC.certificate_consistent(c, ["org", "user"]) is True
    assert FC.certificate_consistent(c) is False  # without precedence the id order names "a"


def test_forbid_cert_unreadable_precedence_refuses():
    c = _cert([_row("p", "permit")], "allow", "permit", "p", [])
    assert FC.certificate_consistent(c, 5) is False


def test_forbid_cert_ids_with_surrogates_sort_like_js():
    rows = [_row("\ud800a", "forbid"), _row("a", "forbid")]
    assert FC.certificate_consistent(_cert(rows, "deny", "forbid", "a", ["\ud800a"])) is True


# ===================================================================================================== pca_grant

def test_https_url_rules():
    ok = PG.is_https_url
    assert ok("https://" + "a" * (2048 - 8)) is True
    assert ok("https://" + "a" * (2049 - 8)) is False
    assert ok("https://a!b") is True and ok("https://a~b") is True and ok("https://aXb") is True
    assert ok("https://a\x7fb") is False and ok("https://a\x80b") is False
    assert ok("https://a#b") is False and ok("https://a\\b") is False and ok("https://a b") is False
    assert ok("https://a") is True
    assert ok("https://host/p@q/r") is True
    assert ok("https://host?x@y") is True
    assert ok("https://host?a@b?c") is True
    assert ok("https://u@host/") is False


def test_detail_digest_must_be_32_bytes():
    d = {"type": "pca_grant", "chain_digest": b64u(b"x" * 33), "chain_len": 1}
    assert PG.validate_detail(d) == {"ok": False, "code": "bad_chain_digest"}


def test_parse_details_returns_the_details():
    d = {"type": "pca_grant", "chain_digest": PG.chain_digest(["a"]), "chain_len": 1}
    assert PG.parse_details([d]) == {"ok": True, "details": [d]}


def test_presentation_skips_a_non_matching_detail():
    d0 = {"chain_len": 3, "chain_digest": "x"}
    d1 = {"chain_len": 1, "chain_digest": PG.chain_digest(["a"])}
    assert PG.check_presentation([d0, d1], "r", ["a", "b"], True) == {"allow": True, "index": 1}


# ===================================================================================================== provenance_gate

L0 = PV.rfc9162_leaf_hash(b"a")
L1 = PV.rfc9162_leaf_hash(b"b")
ROOT = PV._node(L0, L1)


def test_inclusion_baseline_and_strict_byte_types():
    assert PV.verify_rfc9162_inclusion(L0, 0, 2, [L1], ROOT) is True
    assert PV.verify_rfc9162_inclusion(L0, 0, 1, [], L0) is True
    assert PV.verify_rfc9162_inclusion(list(L0), 0, 1, [], L0) is False
    assert PV.verify_rfc9162_inclusion(L0, 0, 1, [], list(L0)) is False
    assert PV.verify_rfc9162_inclusion(L0, 0, 2, [list(L1)], ROOT) is False
    assert PV.verify_rfc9162_inclusion(L0, 0, 2, collections.deque([L1]), ROOT) is False


def test_inclusion_internal_error_is_false(monkeypatch):
    monkeypatch.setattr(PV, "_node", _raiser)
    assert PV.verify_rfc9162_inclusion(L0, 0, 2, [L1], ROOT) is False


def test_provenance_gate_internal_error_code(monkeypatch):
    monkeypatch.setattr(PV, "provenance_policy_error", _raiser)
    assert PV.provenance_gate({"facts": {}, "policy": {}, "now": 0}) == {"ok": False, "code": "malformed_facts"}


# ===================================================================================================== predicates

@pytest.mark.parametrize("s,want", [
    ("\udfff", '"..."'), ("\ud800", '"..."'), ("", '""'), (" ", '" "'), ("X", '"X"'),
    ("￿", '"￿"'), ("\U00010000", '"..."'), ("a\x1fb", '"..."'), ('a"b', '"..."'), ("a\\b", '"..."'),
])
def test_show_value_string_rules(s, want):
    assert PR._show_value(s) == want


def test_show_value_nested_array_depth():
    assert PR._show_value([[1], 2]) == "[<value>, 2]"


def test_describe_condition_fallbacks():
    assert PR._describe_condition(5) == "<condition>"
    assert PR._describe_condition({"all_of": 5}) == "<condition>"
    assert PR._describe_condition({"field": "f", "op": ["eq"]}) == "f <condition>"


def test_first_unmet_limit_needs_string_verb_and_resource():
    p = {"verb": "v", "where": [{"field": "action.params.a", "op": "eq", "value": 1}]}
    assert PR._first_unmet_limit([p], {"action": {"verb": "v", "resource": 5, "params": {"a": 2}}}) is None
    assert PR._first_unmet_limit([p], {"action": {"verb": 5, "resource": "r", "params": {"a": 2}}}) is None
    assert PR._first_unmet_limit([p], {"action": {"verb": "v", "resource": "r", "params": {"a": 2}}}) == "a == 1"


def test_unmet_limit_search_continues_past_non_array_where():
    p0 = {"verb": "v", "resource": "r", "where": "bad"}
    p1 = {"verb": "v", "resource": "r", "where": [{"field": "action.params.a", "op": "eq", "value": 1}]}
    ctx = {"action": {"verb": "v", "resource": "r", "params": {"a": 2}}}
    assert PR.evaluate_predicates([p0, p1], ctx) == {"allowed": False, "reason": "a == 1 not satisfied for v on r"}


# ===================================================================================================== policy_classes

def test_policy_class_digest_bound():
    mk = lambda d: [{"class": "org", "revision": 1, "digest": d, "decision": "allow"}]  # noqa: E731
    assert PC.class_verdicts_error(mk("d" * 128)) is None
    for n in (129, 200):
        assert PC.class_verdicts_error(mk("d" * n)) == "policy_classes[0].digest invalid"


def test_decide_classes_internal_error(monkeypatch):
    monkeypatch.setattr(PC, "meet_all", _raiser)
    lst = [{"class": "org", "revision": 1, "digest": "d", "decision": "allow"}]
    assert PC.decide_classes(lst) == {"decision": "deny", "classes": [], "denied_by": [], "escalated_by": [],
                                      "reason": "evaluation error (fail closed)"}


# ===================================================================================================== protect

def test_protect_passes_pcactn_and_grant_to_is_revoked():
    seen = []
    pcactn, grant = {"p": 1}, {"id": "g1"}

    def src(a, b):
        seen.append((a, b))
        return True

    p = PT.protect("aud", [grant], is_revoked=src)
    assert p.options["authorize"].is_revoked(pcactn, grant) is True
    assert seen == [(pcactn, grant)]


# ===================================================================================================== refusal_help

def test_explain_refusal_exact_entry():
    assert RH.explain_refusal("operation: x") == {
        "check": "operation",
        "meaning": "The signed action is not the operation this route executes (other verb, resource or params).",
        "fix": "Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.",
        "docs": "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#operation"}


def test_explain_refusal_matches_a_bare_head():
    assert RH.explain_refusal("replay")["check"] == "replay"
    assert RH.explain_refusal("plan_state 3")["check"] == "plan_state"
    assert RH.explain_refusal(5)["check"] == "unknown"


# ===================================================================================================== revocation_staleness

def _epoch_call(monkeypatch, policy, state):
    seen = []
    monkeypatch.setattr(RS, "check_revocation_epoch", lambda *a, **k: seen.append(a) or {"ok": False, "reason": "x"})
    RS.check_revocation_state(policy, state, now=5)
    return seen[0]


def test_revocation_state_forwards_last_accepted_epoch_and_pins(monkeypatch):
    pol = RS.RevocationStaleness(guardian_public="g", pq_pins={"g": "k"})
    st = {"kind": "epoch", "epoch": {}, "last_accepted_epoch": 7}
    a = _epoch_call(monkeypatch, pol, st)
    assert a[4] == 7 and a[6] == {"g": "k"}
    a = _epoch_call(monkeypatch, pol, {"kind": "epoch", "epoch": {}})
    assert a[4] is RS._UNDEF
    a = _epoch_call(monkeypatch, RS.RevocationStaleness(guardian_public="g", pq_pins={}), st)
    assert a[6] is None


# ===================================================================================================== pca.py

def _fa_vector():
    return next(v for v in FA_DOC["vectors"] if v["name"] == "member-stale-revocation_epoch")


def test_fresh_at_failure_is_listed_among_the_reasons():
    v = _fa_vector()
    ctx = v["context"]
    got = verify_pcactn_core(v["pcactn"], v["grant"], now=ctx["now"], audience="other-aud", fresh_at=ctx.get("fresh_at"), insecure_skip_plan_root_check=True)
    assert got.reason == "audience: aud does not match this resource server / instance"
    assert got.reasons == [got.reason, v["expect"]["reason"]]


def test_internal_error_keeps_legacy_polarity_false(monkeypatch):
    v = _fa_vector()
    ctx = v["context"]
    monkeypatch.setattr(PCA, "decide_intent_binding", _raiser)
    got = verify_pcactn_core(v["pcactn"], v["grant"], now=ctx["now"], audience=ctx["aud"], fresh_at=ctx.get("fresh_at"), insecure_skip_plan_root_check=True)
    assert got.allow is False and got.legacy_model_polarity is False
    assert got.reason == "malformed PCActn: boom"
    assert got.checks["malformed"] is False


def test_intent_binding_messages():
    from atlas_pca import decide_intent_binding, intent_goal_commit
    G = "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw"
    P = "9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo"
    intent = {"ref": G, "map_digest": P, "goal_salt": "s", "fidelity_ppm": 1, "residual_risk_ppm": 0}
    grant = {"caveats": [{"type": "envelope", "goal_commit": intent_goal_commit(G, P, "s")}]}
    assert decide_intent_binding(intent, grant, {"approved_goal": {"goal_digest": G}}) == (
        "fail", "intent policy misconfigured: approved_goal digests must be canonical base64url (32 bytes) (fail closed)")
    assert decide_intent_binding(intent, grant, {"approved_goal": {"goal_digest": G, "policy_digest": P}}) == (
        "fail", "the root grant's goal commitment does not open to the approved goal and compiled policy (v3)")
