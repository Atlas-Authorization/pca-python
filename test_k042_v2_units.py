"""Kill tests: decide_intent_v2's totality fallback, conform_action edge cases (verb params, required default, key order,
result members) and check_session_revocation's remaining refusals."""
import json
import os

import pytest

from atlas_pca import intent_v2 as V
from atlas_pca.intent_v2 import check_session_revocation, conform_action, decide_intent_v2

with open(os.path.join(os.path.dirname(__file__), "testdata", "k042-sessrevoc-cases.json"), encoding="utf-8") as fh:
    _REV = {c["name"]: c for c in json.load(fh)["rev"]}


def test_decide_intent_v2_internal_error_is_one_failed_check(monkeypatch):
    def boom(*a):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(V, "_decide_intent_v2", boom)
    assert decide_intent_v2({}, {}, None, 1) == {
        "checks": [{"name": "intent_session", "ok": False, "reason": "intent v2 error (fail closed): kaboom"}]}


def schema(params, extra=None):
    verb = {"verb": "v", "kind": "write", "params": params}
    verb.update(extra or {})
    return {"verbs": [verb]}


def decl(**kw):
    d = {"type": "integer", "semantic": "s", "sensitivity": "free"}
    d.update(kw)
    return d


def test_conform_ok_returns_the_verb_entry():
    doc = schema({"action.params.n": decl()})
    r = conform_action(doc, "v", {"n": 1})
    assert r == {"ok": True, "verb": doc["verbs"][0]} and r["verb"] is doc["verbs"][0]
    assert set(r) == {"ok", "verb"}


def test_conform_required_defaults_to_true():
    doc = schema({"action.params.n": decl()})
    assert conform_action(doc, "v", {})["code"] == "missing_param"
    assert conform_action(schema({"action.params.n": decl(required=True)}), "v", {})["code"] == "missing_param"
    assert conform_action(schema({"action.params.n": decl(required=False)}), "v", {}) ["ok"] is True
    for req in (None, 0, "no", [], {}):  # only the boolean false opts out
        assert conform_action(schema({"action.params.n": decl(required=req)}), "v", {})["code"] == "missing_param", req


def test_conform_error_texts_and_exceptions():
    with pytest.raises(TypeError) as e:
        conform_action(schema({"action.params.n": decl()}, {"params": 5}), "v", {})
    assert str(e.value) == "the verb's params must be an object"
    with pytest.raises(TypeError) as e:
        conform_action({"verbs": [{"verb": "v", "kind": "write"}]}, "v", {})  # params absent
    assert str(e.value) == "the verb's params must be an object"
    with pytest.raises(TypeError) as e:
        conform_action(schema({"action.params.n": 5}), "v", {})  # missing param with a non-object declaration
    assert str(e.value) == "a parameter declaration must be an object"
    with pytest.raises(TypeError):
        conform_action(schema({"action.params.n": None}), "v", {})


def test_conform_reports_the_first_failure_in_utf8_byte_order():
    # undeclared params are checked in UTF-8 byte order (U+FFFF encodes after U+10000? no: 3-byte EF.. < 4-byte F0..)
    doc = schema({})
    r = conform_action(doc, "v", {"\U00010000": 1, "￿": 2})
    assert r["code"] == "undeclared_param" and r["path"] == "action.params.￿"
    r = conform_action(doc, "v", {"b": 1, "a": 2})
    assert r["path"] == "action.params.a"
    # declared params: missing ones are reported in UTF-8 byte order too
    doc = schema({"action.params.b": decl(), "action.params.a": decl(), "action.params.￿": decl(), "action.params.\U00010000": decl()})
    assert conform_action(doc, "v", {})["path"] == "action.params.a"
    assert conform_action(doc, "v", {"a": 1, "b": 1})["path"] == "action.params.￿"
    assert conform_action(doc, "v", {"a": 1, "b": 1, "￿": 1})["path"] == "action.params.\U00010000"


def rev(name, **over):
    c = _REV[name]
    a = dict(session=c["session"], authority=json.loads(c["authority"]),
             ids=json.loads(c["ids"]) if c["ids"] is not None else None, now=c["now"], max_age_ms=c["maxAge"])
    if c["last"] is not None:
        a["last"] = json.loads(c["last"])
    a.update(over)
    return check_session_revocation(json.loads(c["ev"]), **a)


def test_revocation_base_ok_and_texts():
    assert rev("ok") == {"ok": True}
    assert rev("ok", ids=["pca-intent:session:other"]) == {"ok": True}
    assert rev("revoked") == {"ok": False, "reason": _REV["revoked"]["reason"]}
    assert rev("ok", max_age_ms=0)["reason"] == "the session revocation epoch is older than 0 ms"
    assert rev("ok", max_age_ms=9999)["reason"] == "the session revocation epoch is older than 9999 ms"


def test_revocation_last_epoch_rules():
    c = _REV["ok"]
    ev = json.loads(c["ev"])
    ok_last = {"epoch": ev["epoch"], "revoked": ev["revoked"]}
    assert rev("ok", last=ok_last) == {"ok": True}
    # the same epoch number with a different root is an equivocation (needs a well-formed last with that number)
    other = rev("ok-empty-set") if "ok-empty-set" in _REV else None
    assert other == {"ok": True}
    ev2 = json.loads(_REV["ok-empty-set"]["ev"])
    r = rev("ok", last={"epoch": dict(ev2["epoch"], epoch=ev["epoch"]["epoch"]), "revoked": ev2["revoked"]})
    assert r["ok"] is False
    for bad_last in ({}, {"epoch": ev["epoch"]}, {"revoked": ev["revoked"]}, "x", None, [], {"epoch": None, "revoked": []},
                     {"epoch": ev["epoch"], "revoked": None}, dict(ok_last, extra=1)):
        r = rev("ok", last=bad_last)
        assert r == {"ok": False, "reason": "the tracked last epoch is malformed (fail closed)"}, bad_last


def test_revocation_evidence_shape():
    c = _REV["ok"]
    ev = json.loads(c["ev"])
    a = dict(session=c["session"], authority=json.loads(c["authority"]), ids=[], now=c["now"], max_age_ms=c["maxAge"])
    assert check_session_revocation({"revoked": ev["revoked"]}, **a)["ok"] is False  # epoch absent
    assert check_session_revocation({"epoch": ev["epoch"]}, **a)["ok"] is False  # revoked absent
    assert check_session_revocation({"epoch": None, "revoked": ev["revoked"]}, **a)["ok"] is False
    assert check_session_revocation({"epoch": ev["epoch"], "revoked": None}, **a)["ok"] is False
    assert check_session_revocation(ev, **a) == {"ok": True}


def test_param_value_violation_requires_an_object_declaration():
    for bad in ("x", 5, None, [], ["type"]):
        with pytest.raises(TypeError) as e:
            V.param_value_violation(bad, 1)
        assert str(e.value) == "a parameter declaration must be an object"
