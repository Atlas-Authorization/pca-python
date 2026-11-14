"""Exact-value tests for atlas_pca.prohibitions that the reference replay cannot reach: fail-closed handlers (driven by injected
failures), number helpers, trigger guards, composition and check-and-advance outcomes, evidence signing and verification messages."""
import pytest

from atlas_pca import ed25519
from atlas_pca import prohibitions as P
from atlas_pca.pca import b64u

SEED = b"\x31" * 32
NOW = 1_700_000_000_000


def _prin():
    return b64u(ed25519.public_key(SEED))


def act(verb, resource="/r"):
    return {"action": {"verb": verb, "resource": resource}}


def _const(principal="pp", extra=None):
    invs = [{"id": "n", "kind": "never", "when": {"verb": "delete"}}] + (extra or [])
    return {"version": 1, "principal": principal, "invariants": invs}


def _boom(*a, **k):
    raise RuntimeError("injected")


def _fail(id_, reason):
    return {"ok": False, "violated": [id_], "reasons": [reason], "evaluated": [{"id": id_, "kind": "structural", "result": "violated", "reason": reason}]}


# ---- helpers -----------------------------------------------------------------------------------------------------------------------

def test_neg_zero_is_only_the_negative_zero_float():
    assert P._neg_zero(-0.0) is True
    for v in (0.0, 0, -1.0, 1.0, -1, "x", None, True, [], float("-inf")):
        assert P._neg_zero(v) is False, v


def test_sum_amount_keeps_integers_exact_and_floats_float():
    s = P._sum_amount(1, 2)
    assert s == 3 and type(s) is int
    s = P._sum_amount(0.5, 0.25)
    assert s == 0.75 and type(s) is float
    s = P._sum_amount(2 ** 53 - 1, 1)
    assert s == 2 ** 53 and type(s) is int
    s = P._sum_amount(2 ** 53, 2)
    assert s == 2 ** 53 + 2 and type(s) is float
    s = P._sum_amount(1.5, 1.5)
    assert s == 3 and type(s) is int


def test_strict_equality_and_version_helpers():
    assert P._same(1, 1.0) and P._same(True, True) and P._same("a", "a") and P._same(None, None)
    for a, b in ((0, False), (1, True), ("1", 1), (None, ""), (None, 0), ([], []), ({}, {}), ("a", "b")):
        assert not P._same(a, b), (a, b)
    assert P._is_version(1, 1) and P._is_version(1.0, 1)
    for v in (True, 2, "1", None, 0):
        assert not P._is_version(v, 1), v


# ---- trigger guards ----------------------------------------------------------------------------------------------------------------

def test_when_matches_vetoes_whatever_it_cannot_decide():
    w = {"verb": "x"}
    assert P.when_matches(w, act("x")) is True and P.when_matches(w, act("y")) is False
    for ctx in (None, [], 5, {}, {"action": 5}, {"action": {"verb": 5, "resource": "/r"}}, {"action": {"verb": "x", "resource": 5}},
                {"action": {"verb": 5, "resource": 5}}, {"action": {"resource": "/r"}}, {"action": {"verb": "x"}}):
        assert P.when_matches(w, ctx) is True, ctx
    assert P.when_matches({"verb": ""}, act("x")) is True
    assert P.when_matches(None, act("x")) is True


def test_when_matches_oversized_subject_for_a_regex_resource():
    big = "/" + "b" * P.MAX_RE_RESOURCE_LEN
    rx = {"verb": "x", "resource": "re:^/a$"}
    assert P.when_matches(rx, act("x", "/a")) is True
    assert P.when_matches(rx, act("x", "/zzz")) is False
    assert P.when_matches(rx, act("x", big)) is True
    assert P.when_matches({"verb": "x", "resource": "/a"}, act("x", big)) is False
    assert P.when_matches({"verb": "x"}, act("x", big)) is True


def test_when_helpers_fail_closed_on_internal_errors(monkeypatch):
    assert P.when_affirmative({"verb": "x"}, act("x")) is True and P.when_affirmative({"verb": "x"}, act("y")) is False
    assert P.when_affirmative({"verb": ""}, act("x")) is False
    monkeypatch.setattr(P, "predicate_matches", _boom)
    assert P.when_matches({"verb": "x"}, act("y")) is True
    assert P.when_affirmative({"verb": "x"}, act("x")) is False


# ---- monitor ----------------------------------------------------------------------------------------------------------------------

def test_check_prohibitions_structural_refusals_and_errors(monkeypatch):
    c, s = _const(), P.empty_state(NOW)
    assert P.check_prohibitions(act("read"), None, s) == _fail("<constitution>", "constitution not an object")
    assert P.check_prohibitions(None, c, s) == _fail("<action>", "malformed action")
    assert P.check_prohibitions(act("read"), c, {}) == _fail("<state>", "malformed monitor state")
    monkeypatch.setattr(P, "_eval_one", _boom)
    boom = "evaluation error (fail closed)"
    assert P.check_prohibitions(act("read"), c, s) == {
        "ok": False, "violated": ["n"], "reasons": ["n: " + boom], "evaluated": [{"id": "n", "kind": "never", "result": "violated", "reason": boom}]}
    monkeypatch.undo()
    monkeypatch.setattr(P, "validate_constitution", _boom)
    assert P.check_prohibitions(act("read"), c, s) == _fail("<monitor>", "monitor error (fail closed)")


def test_advance_state_strict_refusals(monkeypatch):
    c, s, a = _const(), P.empty_state(NOW), act("read")
    assert P.advance_state_strict(a, None, s) == {"ok": False, "reason": "constitution not an object"}
    assert P.advance_state_strict(a, c, {}) == {"ok": False, "reason": "malformed monitor state"}
    assert P.advance_state_strict(a, c, s, NOW - 1) == {"ok": False, "reason": "clock regression"}
    assert P.advance_state_strict(a, c, s, None) == {"ok": False, "reason": "clock regression"}
    assert P.advance_state_strict(None, c, s) == {"ok": False, "reason": "malformed action"}
    assert P.advance_state_strict(a, c, s, NOW)["ok"] is True
    real = P.state_problem
    monkeypatch.setattr(P, "state_problem", lambda x: "boom" if isinstance(x, dict) and x.get("seq") == 1 else real(x))
    assert P.advance_state_strict(a, c, s) == {"ok": False, "reason": "resulting state invalid"}
    monkeypatch.undo()
    monkeypatch.setattr(P, "canonical_state", _boom)
    assert P.advance_state_strict(a, c, s) == {"ok": False, "reason": "advance error (fail closed)"}


def test_advance_state_returns_the_input_state_on_failure():
    c, s = _const(), P.empty_state(NOW)
    assert P.advance_state(act("read"), c, s)["seq"] == 1
    assert P.advance_state(act("read"), c, s, NOW - 1) is s


# ---- evidence ---------------------------------------------------------------------------------------------------------------------

def test_an_unhashable_constitution_makes_the_evidence_not_ok(monkeypatch):
    c, s, a = _const(), P.empty_state(NOW), act("read")
    assert P.prove_safety(a, c, s)["ok"] is True
    monkeypatch.setattr(P, "constitution_id", _boom)
    ev = P.prove_safety(a, c, s)
    assert (ev["constitution"], ev["ok"], ev["violated"]) == ("<unhashable>", False, ["<constitution>"])


def test_verify_safety_evidence_messages(monkeypatch):
    two = _const(extra=[{"id": "m", "kind": "never", "when": {"verb": "delete"}}])
    s, a = P.empty_state(NOW), act("delete")
    ev = P.prove_safety(a, two, s)
    assert P.verify_safety_evidence(ev, a, two, s) == {"ok": False, "reason": "prohibition violated: n,m"}
    ok = P.prove_safety(act("read"), two, s)
    assert P.verify_safety_evidence(ok, act("read"), two, s) == {"ok": True}
    for bad in (None, 5, {}, {**ok, "v": True}, {**ok, "v": 2}):
        assert P.verify_safety_evidence(bad, act("read"), two, s) == {"ok": False, "reason": "unsupported evidence version"}
    monkeypatch.setattr(P, "prove_safety", _boom)
    assert P.verify_safety_evidence(ok, act("read"), two, s) == {"ok": False, "reason": "verification error (fail closed)"}


def _bound():
    return {"v": 1, "constitution": "c", "action_digest": "a", "state_digest": "s", "now": NOW, "evaluated": [], "ok": True, "violated": []}


def test_sign_safety_evidence_refusals():
    ev = _bound()

    def refused(evidence, signer, message):
        with pytest.raises(TypeError) as ei:
            P.sign_safety_evidence(evidence, SEED, signer)
        assert str(ei.value) == message

    for bad in (None, 5, {}, {**ev, "v": True}, {**ev, "v": 2}):
        refused(bad, "x", "signSafetyEvidence: unsupported evidence")
    for k in ("constitution", "action_digest", "state_digest"):
        for v in ("", None, 5, P.UNHASHABLE):
            refused({**ev, k: v}, "x", "signSafetyEvidence: unbound evidence")
    for signer in ("", None, 5, ["x"]):
        refused(ev, signer, "signSafetyEvidence: signer missing")
    refused({**ev, "v": 2, "constitution": ""}, "", "signSafetyEvidence: unsupported evidence")
    refused({**ev, "constitution": ""}, "", "signSafetyEvidence: unbound evidence")


def test_sign_safety_evidence_binds_the_supplied_signer():
    ev, pub = _bound(), _prin()
    signed = P.sign_safety_evidence(ev, SEED, "label")
    assert signed["signer"] == "label" and signed["evidence"] is ev and signed["id"] == P.safety_binding_id(ev, "label")
    assert signed["id"] != P.safety_binding_id(ev, pub)
    with pytest.raises((KeyError, TypeError)):
        P.safety_binding_id({"constitution": "c", "action_digest": "a"}, "x")
    with pytest.raises((KeyError, TypeError)):
        P.safety_binding_id(None, "x")


def _signed(constitution=None):
    pub, s, a = _prin(), P.empty_state(NOW), act("read")
    c = constitution or _const(pub)
    ev = P.prove_safety(a, c, s)
    return P.sign_safety_evidence(ev, SEED, pub), {"signer": pub, "action": a, "constitution": c, "state": s}, ev


def test_verify_signed_safety_evidence_accepts_and_names_failures(monkeypatch):
    signed, exp, ev = _signed()
    assert P.verify_signed_safety_evidence(signed, exp) == {"ok": True}
    assert P.verify_signed_safety_evidence({**signed, "evidence": {**ev, "v": True}}, exp) == {"ok": False, "reason": "unsupported evidence version"}
    assert P.verify_signed_safety_evidence(signed, {**exp, "constitution": _const("zz")}) == {
        "ok": False, "reason": "constitution mismatch (evidence bound to another constitution)"}
    monkeypatch.setattr(P, "safety_binding_id", _boom)
    assert P.verify_signed_safety_evidence(signed, exp) == {"ok": False, "reason": "verification error (fail closed)"}


def test_a_principal_pin_must_be_a_string_that_matches():
    sc = P.sign_constitution(_const(_prin()), SEED)
    signed, exp, _ = _signed(sc)
    assert P.verify_signed_safety_evidence(signed, {**exp, "principal": _prin()}) == {"ok": True}
    for pin in (None, 5, "", "other", True, ["x"]):
        assert P.verify_signed_safety_evidence(signed, {**exp, "principal": pin}) == {
            "ok": False, "reason": "constitution not authentic: principal mismatch"}, pin
    assert P.verify_signed_safety_evidence(signed, {**exp, "constitution": _const(_prin()), "principal": _prin()}) == {
        "ok": False, "reason": "principal pin requires a signed constitution"}
    assert P.verify_constitution(sc, None) == {"ok": True}
    assert P.verify_constitution(sc, _prin()) == {"ok": True}
    assert P.verify_constitution(sc, "x") == {"ok": False, "reason": "principal mismatch"}


def test_verify_constitution_fails_closed(monkeypatch):
    sc = P.sign_constitution(_const(_prin()), SEED)
    assert P.verify_constitution(sc) == {"ok": True}
    monkeypatch.setattr(P, "constitution_id", _boom)
    assert P.verify_constitution(sc) == {"ok": False, "reason": "verification error (fail closed)"}


def test_violated_lists_print_like_array_join():
    pub = _prin()
    ev = {"v": 1, "constitution": P.constitution_id(_const(pub)), "action_digest": P.hash_canonical(act("delete")),
          "state_digest": P.state_digest(P.empty_state(NOW)), "now": NOW, "evaluated": [{"id": "n", "kind": "never", "result": "violated"}],
          "ok": False, "violated": [1, None, "a"]}
    signed = P.sign_safety_evidence(ev, SEED, pub)
    exp = {"signer": pub, "actionDigest": ev["action_digest"], "constitutionId": ev["constitution"], "stateDigest": ev["state_digest"]}
    assert P.verify_signed_safety_evidence(signed, exp) == {"ok": False, "reason": "prohibition violated: 1,,a"}
    assert P.verify_signed_safety_evidence(signed, {**exp, "requireOk": False}) == {"ok": True}


# ---- composition ------------------------------------------------------------------------------------------------------------------

def test_compose_authority_outcomes():
    c, s = _const(), P.empty_state(NOW)
    ok, bad = P.check_prohibitions(act("read"), c, s), P.check_prohibitions(act("delete"), c, s)
    assert P.compose_authority(True, act("read"), c, s) == {"allow": True, "decidedBy": "none", "permitted": True, "prohibition": ok}
    assert P.compose_authority(False, act("read"), c, s) == {"allow": False, "decidedBy": "permission", "permitted": False, "prohibition": ok}
    assert P.compose_authority("yes", act("read"), c, s) == {"allow": False, "decidedBy": "permission", "permitted": False, "prohibition": ok}
    assert P.compose_authority(True, act("delete"), c, s) == {"allow": False, "decidedBy": "prohibition", "permitted": True, "prohibition": bad}
    assert P.compose_authority(False, act("delete"), c, s) == {"allow": False, "decidedBy": "prohibition", "permitted": False, "prohibition": bad}


def _ctx(a, c, s):
    mon = P.check_prohibitions(a, c, s)
    return mon, P._evidence_from(mon, a, c, s)


def test_check_and_advance_outcomes(monkeypatch):
    c, s, a = _const(), P.empty_state(NOW), act("read")
    mon, evd = _ctx(a, c, s)
    assert P.check_and_advance(True, a, c, s) == {
        "allow": True, "decidedBy": "none", "evidence": evd, "prohibition": mon, "next": P.advance_state_strict(a, c, s)["state"]}
    assert P.check_and_advance(False, a, c, s) == {"allow": False, "decidedBy": "permission", "evidence": evd, "prohibition": mon, "next": s}
    dmon, devd = _ctx(act("delete"), c, s)
    for permitted in (True, False):
        assert P.check_and_advance(permitted, act("delete"), c, s) == {
            "allow": False, "decidedBy": "prohibition", "evidence": devd, "prohibition": dmon, "next": s}
    stale = {"allow": False, "decidedBy": "state", "evidence": evd, "prohibition": mon, "next": s}
    assert P.check_and_advance(True, a, c, s, {"expectedSeq": 1}) == {**stale, "reason": "stale state head (seq)"}
    assert P.check_and_advance(True, a, c, s, {"expectedSeq": False}) == {**stale, "reason": "stale state head (seq)"}
    assert P.check_and_advance(False, a, c, s, {"expectedSeq": 1}) == {**stale, "reason": "stale state head (seq)"}
    assert P.check_and_advance(True, a, c, s, {"expectedStateDigest": "bogus"}) == {**stale, "reason": "stale state head (digest)"}
    assert P.check_and_advance(True, a, c, s, {"expectedSeq": 0.0, "expectedStateDigest": P.state_digest(s)})["allow"] is True
    monkeypatch.setattr(P, "advance_state_strict", lambda *x, **k: {"ok": False, "reason": "boom"})
    assert P.check_and_advance(True, a, c, s) == {**stale, "reason": "advance failed: boom"}
    monkeypatch.setattr(P, "advance_state_strict", _boom)
    assert P.check_and_advance(True, a, c, s) == {**stale, "reason": "check-and-advance error (fail closed)"}


def test_check_and_advance_refuses_evidence_it_cannot_attest(monkeypatch):
    c, s, a = _const(), P.empty_state(NOW), act("read")
    monkeypatch.setattr(P, "constitution_id", _boom)
    mon, evd = _ctx(a, c, s)
    assert evd["ok"] is False
    assert P.check_and_advance(True, a, c, s) == {
        "allow": False, "decidedBy": "prohibition", "evidence": evd, "prohibition": mon, "next": s, "reason": "evidence not attestable"}
