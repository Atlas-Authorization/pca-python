"""Data-flow governance (DLP) decisions: the reference's documented outcomes, refusal reasons, class precedence and fail-closed paths."""
import math

import pytest

from atlas_pca import control_evals as CE
from atlas_pca.dlp import default_dlp_policy, evaluate_dlp

P = CE.example_dlp_policy()


def ev(verb, res, taint, policy=P):
    return evaluate_dlp(policy, {"verb": verb, "resource": res, "taint": taint})


def test_outcomes_and_reasons():
    assert ev("gmail.send", "external:a@b", 0) == {"outcome": "allow", "class": "external-send"}
    r = ev("gmail.send", "external:a@b", 2)
    assert r["outcome"] == "step_up" and r["reason"] == "taint 2 > 0 for 'external-send' — needs human review"
    r = ev("gmail.send", "external:a@b", 5)
    assert r["outcome"] == "deny" and r["reason"] == "taint 5 exceeds hard ceiling 3 for 'external-send'"
    assert ev("gmail.draft", "draft:x", 9) == {"outcome": "allow"}  # no class matches, no default ceiling
    assert ev("files.read", "secret:k", 1)["outcome"] == "deny"
    assert ev("files.read", "secret:k", 0)["outcome"] == "allow"
    assert ev("gmail.send", "external:a@b", 2.5)["reason"].startswith("taint 2.5 > 0")


def test_non_finite_taint_is_maximally_tainted():
    for t in (math.nan, math.inf, -math.inf, "0", None):
        r = ev("gmail.send", "external:a@b", t)
        assert r["outcome"] == "deny" and r["reason"] == "taint Infinity exceeds hard ceiling 3 for 'external-send'"


def test_malformed_policies_deny():
    for p in (None, 5, "x", [], {}, {"classes": {}}):
        assert evaluate_dlp(p, {"verb": "v", "resource": "r", "taint": 0}) == {"outcome": "deny", "reason": "malformed DLP policy"}
    bad = {"classes": [{"name": "c", "resource": "*", "maxTaintForAuto": "0"}]}
    assert ev("v", "r", 0, bad) == {"outcome": "deny", "class": "c", "reason": "malformed DLP policy: ceilings must be numbers"}
    hard = {"classes": [{"name": "c", "resource": "*", "maxTaintForAuto": 0, "hardDenyAbove": None}]}
    assert ev("v", "r", 0, hard)["outcome"] == "deny"
    dflt = {"classes": [], "defaultMaxTaintForAuto": "1"}
    assert ev("v", "r", 0, dflt) == {"outcome": "deny", "reason": "malformed DLP policy: ceilings must be numbers"}


def test_default_ceiling_and_label():
    p = {"classes": [], "defaultMaxTaintForAuto": 1}
    assert ev("v", "r", 1, p) == {"outcome": "allow"}
    assert ev("v", "r", 2, p) == {"outcome": "step_up", "reason": "taint 2 > 1 for '<default>' — needs human review"}


def test_most_specific_then_strictest_class_wins():
    two = {"classes": [
        {"name": "any", "resource": "*", "maxTaintForAuto": 9},
        {"name": "db", "resource": "db:*", "maxTaintForAuto": 1},
        {"name": "db-strict", "resource": "db:*", "maxTaintForAuto": 0},
    ]}
    assert ev("v", "db:x", 1, two)["class"] == "db-strict"
    exact = {"classes": [{"name": "p", "resource": "db:*", "maxTaintForAuto": 0}, {"name": "e", "resource": "db:x", "maxTaintForAuto": 5}]}
    assert ev("v", "db:x", 1, exact)["class"] == "e"
    unconstrained = {"classes": [{"name": "free", "resource": "db:*"}, {"name": "capped", "resource": "db:*", "maxTaintForAuto": 3}]}
    assert ev("v", "db:x", 1, unconstrained)["class"] == "capped"
    first = {"classes": [{"name": "a", "resource": "db:*", "maxTaintForAuto": 1}, {"name": "b", "resource": "db:*", "maxTaintForAuto": 1}]}
    assert ev("v", "db:x", 0, first)["class"] == "a"


def test_verbs_filter():
    p = {"classes": [{"name": "v", "resource": "*", "verbs": ["a.b"], "maxTaintForAuto": 0}]}
    assert ev("a.b", "r", 1, p)["outcome"] == "step_up"
    assert ev("a.c", "r", 1, p) == {"outcome": "allow"}


def test_reference_throws_become_type_errors():
    with pytest.raises(TypeError):
        ev("v", "r", 0, {"classes": [5]})
    with pytest.raises(TypeError):
        ev("v", "r", 0, {"classes": [{"name": "c", "resource": 5, "maxTaintForAuto": 0}]})
    with pytest.raises(TypeError):
        evaluate_dlp({"classes": [{"name": "c", "resource": "x*", "maxTaintForAuto": 0}]}, {"verb": "v", "resource": 5, "taint": 0})


def test_default_policy_preset():
    assert default_dlp_policy() == {"classes": []}
    p = default_dlp_policy({"piiResource": "customer:*", "secretsResource": "secret:*"})
    assert [c["name"] for c in p["classes"]] == ["pii", "secrets"]
    assert ev("v", "customer:1", 3, p)["outcome"] == "deny" and ev("v", "customer:1", 1, p)["outcome"] == "step_up"
    assert ev("v", "secret:1", 1, p)["outcome"] == "deny" and ev("v", "secret:1", 0, p)["outcome"] == "allow"
