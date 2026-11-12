"""Forbid-wins clauses (reference forbid-certificate.ts, prohibitions.ts whenMatches): the shared prohibition-vectors.json `clauses` and `check`
sections and forbid-certificate-vectors.json `decide`, plus the veto-polarity trigger."""
import json
import os

import pytest

from atlas_pca.forbid_certificate import certify, check_forbid_certificate, clauses_error, decide_clauses
from atlas_pca.prohibitions import validate_condition, validate_when, when_affirmative, when_matches

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    for p in (os.path.join(_HERE, "conformance", name), os.path.join(_HERE, "conformance", name)):
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(name)


PV, FV = _load("prohibition-vectors.json"), _load("forbid-certificate-vectors.json")


@pytest.mark.parametrize("c", PV["clauses"], ids=[c["name"] for c in PV["clauses"]])
def test_prohibition_clause_vectors(c):
    e = c["expect"]
    assert clauses_error(c["clauses"]) == e["error"]
    if e["error"] is None:
        r = decide_clauses(c["clauses"], c["action"])
        assert {"decision": r["decision"], "winner": r["witness"]["winner"], "shadowed": r["witness"]["shadowed"], "values": r["values"]} == {
            k: e[k] for k in ("decision", "winner", "shadowed", "values")}


@pytest.mark.parametrize("c", PV["check"], ids=[c["name"] for c in PV["check"]])
def test_prohibition_check_vectors(c):
    o = c.get("options") or {}
    assert check_forbid_certificate(c["certificate"], c["clauses"], c["action"], o.get("precedence"), o.get("permitSigners")) == c["expect"]


@pytest.mark.parametrize("c", FV["decide"], ids=[c["name"] for c in FV["decide"]])
def test_forbid_certificate_decide_vectors(c):
    o = c.get("options", {})
    r = decide_clauses(c["clauses"], c["action"], o.get("precedence"), o.get("permitSigners"))
    e = c["expect"]
    assert {"decision": r["decision"], "winner": r["witness"]["winner"], "shadowed": r["witness"]["shadowed"], "values": r["values"]} == {
        k: e[k] for k in ("decision", "winner", "shadowed", "values")}


def test_a_certify_then_check_round_trip_and_a_tampered_certificate_is_refused():
    c = PV["check"][0]
    cert = certify(c["clauses"], c["action"], (c.get("options") or {}).get("precedence"))
    assert check_forbid_certificate(cert, c["clauses"], c["action"], (c.get("options") or {}).get("precedence")) == {"ok": True}
    bad = dict(cert, decision="allow")
    assert check_forbid_certificate(bad, c["clauses"], c["action"], (c.get("options") or {}).get("precedence"))["ok"] is False


def test_permit_signers_drop_other_permits():
    clauses = [{"id": "p1", "kind": "permit", "signer": "user", "when": {"verb": "v"}}]
    ctx = {"action": {"verb": "v", "resource": "/x"}}
    assert decide_clauses(clauses, ctx)["decision"] == "allow"
    assert decide_clauses(clauses, ctx, None, ["org"])["decision"] == "deny"
    assert decide_clauses(clauses, ctx, None, ["user"])["decision"] == "allow"


def test_a_malformed_action_or_policy_is_a_deny_naming_malformed():
    for clauses, ctx in (([], {}), ([], {"action": {"verb": 1, "resource": "/x"}}), ("x", {"action": {"verb": "v", "resource": "/x"}})):
        r = decide_clauses(clauses, ctx)
        assert r["decision"] == "deny" and r["witness"]["winner"] == {"kind": "malformed", "id": None} and r["values"] == []


# ---- the veto-polarity trigger -------------------------------------------------------------------------------------------------------------

CTX = {"action": {"verb": "pay.send", "resource": "/blocked/a", "params": {"amount": 50}}}


def test_when_matches_is_conservative_for_a_missing_param_and_exact_for_a_decided_miss():
    w = {"verb": "pay.send", "where": [{"field": "action.params.amount", "op": "gt", "value": 100}]}
    assert when_matches(w, CTX) is False  # a clean miss
    assert when_matches(w, {"action": {"verb": "pay.send", "resource": "/x", "params": {}}}) is True  # the amount cannot be read: the veto applies
    assert when_affirmative(w, {"action": {"verb": "pay.send", "resource": "/x", "params": {}}}) is False


def test_a_malformed_trigger_or_action_is_matched_for_a_veto_and_not_for_a_permit():
    assert when_matches({"verb": ""}, CTX) is True and when_affirmative({"verb": ""}, CTX) is False
    assert when_matches({"verb": "x"}, {"action": {"verb": 1}}) is True
    assert when_matches(None, CTX) is True


def test_verb_and_resource_must_match_when_decided():
    assert when_matches({"verb": "other"}, CTX) is False
    assert when_matches({"verb": "pay.send", "resource": "/blocked/*"}, CTX) is True
    assert when_matches({"verb": "pay.send", "resource": "/ok/*"}, CTX) is False
    assert when_matches({"verb": ["x", "pay.send"]}, CTX) is True


def test_an_unsafe_regex_resource_is_matched():
    assert when_matches({"verb": "pay.send", "resource": "re:(a+)+$"}, CTX) is True
    assert validate_when({"verb": "v", "resource": "re:(a+)+$"}, "when") == "when: unsafe regex resource"


@pytest.mark.parametrize("w,want", [
    (5, "w: not an object"), ({}, "w: bad verb"), ({"verb": []}, "w: bad verb"), ({"verb": ["a", ""]}, "w: bad verb"),
    ({"verb": "a", "resource": 5}, "w: bad resource"), ({"verb": "a", "where": "x"}, "w: where not an array"),
    ({"verb": "a", "where": [5]}, "w: condition not an object"), ({"verb": "a"}, None), ({"verb": ["a", "b"], "resource": "/x/*"}, None),
])
def test_validate_when(w, want):
    assert validate_when(w, "w") == want


@pytest.mark.parametrize("c,want", [
    (5, "condition not an object"), ({}, "condition.field missing"), ({"field": "action.verb", "op": "zz"}, "unknown condition op zz"),
    ({"field": "action.verb"}, "unknown condition op undefined"), ({"field": "a", "op": "eq", "ref": ""}, "bad condition.ref"),
    ({"field": "a", "op": "member_of", "collection": ""}, "bad condition.collection"), ({"all_of": []}, "condition.all_of must be a non-empty array"),
    ({"any_of": "x"}, "condition.any_of must be a non-empty array"), ({"not": 5}, "condition not an object"),
    ({"all_of": [{"field": "a", "op": "eq", "value": 1}]}, None), ({"field": "a", "op": "exists"}, None),
])
def test_validate_condition(c, want):
    assert validate_condition(c) == want


def test_condition_nesting_is_bounded():
    c = {"field": "a", "op": "eq", "value": 1}
    for _ in range(33):
        c = {"not": c}
    assert validate_condition(c) == "condition nesting too deep"
    c = {"field": "a", "op": "eq", "value": 1}
    for _ in range(32):
        c = {"not": c}
    assert validate_condition(c) is None
