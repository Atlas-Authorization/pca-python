"""Kill tests for small W-B helpers: decide_intent_wb entry conditions and its fail-closed fallback, scalar_eq's type
pairs, and _member's JavaScript property-read errors."""
import gzip
import json
import os

import pytest

from atlas_pca import intent_wb as W

D = "A" * 43
UNDEF = W._UNDEF


def test_decide_intent_wb_labels_alone_activate_provenance():
    out = W.decide_intent_wb({"intent_session": {"labels": [D]}, "aud": "x", "session": D, "action": {"params": {}}, "now": 5})
    assert out == {"outcome": "admit", "checks": {"provenance": "pass"}, "env": {"prov": {}}}


def test_decide_intent_wb_nothing_active():
    assert W.decide_intent_wb({"intent_session": {}}) == {"outcome": "admit", "checks": {}, "env": {}}


def test_decide_intent_wb_internal_error_fails_closed(monkeypatch):
    def boom(_):
        raise RuntimeError("boom")

    monkeypatch.setattr(W, "intent_wb_context_error", boom)
    assert W.decide_intent_wb({"intent_session": {}}) == {
        "outcome": "deny", "checks": {"facts": "fail"}, "env": {},
        "reason": "facts: evaluation error (fail closed): boom"}


def test_decide_intent_wb_malformed_context():
    out = W.decide_intent_wb({"intent_session": {}, "artifacts": None})
    assert out["outcome"] == "deny" and out["checks"] == {"facts": "fail"} and out["env"] == {}
    assert out["reason"] == "facts: the W-B context is malformed: artifacts must be an object"
    assert W.decide_intent_wb(5)["checks"] == {"facts": "fail"}


@pytest.mark.parametrize("a,b,want", [
    (UNDEF, UNDEF, True), (UNDEF, 1, False), (1, UNDEF, False), (UNDEF, None, False), (None, UNDEF, False),
    (None, None, True), (None, 0, False), (0, None, False), (None, "", False), ("", None, False),
    (True, True, True), (False, False, True), (True, False, False), (True, 1, False), (1, True, False), (0, False, False),
    (1, 1, True), (1, 1.0, True), (1, 2, False), (1, "1", False), ("1", 1, False), (0, -0.0, True),
    ("a", "a", True), ("a", "b", False), ("", "", True), ("a", 1, False), (1, "a", False),
])
def test_scalar_eq_scalars(a, b, want):
    assert W.scalar_eq(a, b) is want


def test_scalar_eq_objects_are_identity():
    x = {"a": 1}
    assert W.scalar_eq(x, x) is True and W.scalar_eq(x, {"a": 1}) is False
    y = [1]
    assert W.scalar_eq(y, y) is True and W.scalar_eq(y, [1]) is False
    assert W.scalar_eq(x, y) is False and W.scalar_eq(x, None) is False and W.scalar_eq(None, x) is False
    assert W.scalar_eq(x, 1) is False and W.scalar_eq(1, x) is False and W.scalar_eq(x, "a") is False


def test_member_reads():
    with pytest.raises(TypeError) as e:
        W._member(None, "k")
    assert str(e.value) == "Cannot read properties of null (reading 'k')"
    with pytest.raises(TypeError) as e:
        W._member(UNDEF, "kk")
    assert str(e.value) == "Cannot read properties of undefined (reading 'kk')"
    assert W._member({"k": 1}, "k") == 1
    assert W._member({"k": None}, "k") is None
    assert W._member({"k": 1}, "z") is UNDEF
    for o in (5, "s", [1], True, 0):
        assert W._member(o, "k") is UNDEF


def _sigfixture():
    with gzip.open(os.path.join(os.path.dirname(__file__), "testdata", "k042-mapartcls.json.gz"), "rt", encoding="utf-8") as fh:
        cs = json.load(fh)
    return next(c for c in cs if c["fn"] == "sigfixture")["args"]


def test_verify_artifact_sig_pin_forms():
    v, pk, other = _sigfixture()
    dom = W.INTENT_CLASSIFIER_DOMAIN
    assert W.verify_artifact_sig(dom, v, pk) is True
    assert W.verify_artifact_sig(dom, v, {"pk": pk}) is True
    assert W.verify_artifact_sig(dom, v, {"pk": pk, "pq_pk": "unused"}) is True
    assert W.verify_artifact_sig(dom, v, {"pk": other}) is False
    assert W.verify_artifact_sig(dom, v, {"pk": 5}) is False
    assert W.verify_artifact_sig(dom, v, {}) is False
    assert W.verify_artifact_sig(dom, v, [pk]) is False
    assert W.verify_artifact_sig(dom, v, None) is False
    assert W.verify_artifact_sig(dom, dict(v, alg=5), pk) is False
    assert W.verify_artifact_sig(dom, dict(v, alg="not-a-suite"), pk) is False
    assert W.verify_artifact_sig(dom, dict(v, alg="ed25519"), pk) is False  # alg is signed: the body changed
    assert W.verify_artifact_sig(dom, dict(v, sig=None), pk) is False
    assert W.verify_artifact_sig(dom, [v], pk) is False
    assert W.verify_artifact_sig(dom, "x", pk) is False
    # a sig present but the pin key not a string, and the converse
    assert W.verify_artifact_sig(dom, dict(v, sig=7), pk) is False
