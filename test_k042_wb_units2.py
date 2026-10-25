"""Kill tests: offer-set decision result shape and fail-closed results, world evaluation errors, closed-member naming, small
W-B validators (exact texts), flow-rule choice, label refs."""
import gzip
import json
import os

import pytest

from atlas_pca import intent_wb as W

with gzip.open(os.path.join(os.path.dirname(__file__), "testdata", "k042-oracleprov.json.gz"), "rt", encoding="utf-8") as fh:
    CASES = json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))["cases"]


def test_offer_set_success_result_has_the_exact_members(monkeypatch):
    seen = []
    orig = W.decide_offer_set

    def spy(*a, **k):
        r = orig(*a, **k)
        seen.append(r)
        return r

    monkeypatch.setattr(W, "decide_offer_set", spy)
    for c in CASES:
        if c["kind"] == "world":
            W.decide_intent_world(c["input"])
    oks = [r for r in seen if r["ok"]]
    assert oks, "the corpus must exercise a successful offer decision"
    for r in oks:
        assert list(r) == ["ok", "excess", "chosen_price", "min_price"]
        assert r["excess"] == r["chosen_price"] - r["min_price"] and r["excess"] >= 0 and r["min_price"] <= r["chosen_price"]
    assert any(r["excess"] > 0 for r in oks)


def test_offer_set_fail_closed_results(monkeypatch):
    r = W.decide_offer_set(5, W._UNDEF, W._UNDEF, {}, "a", "s", 1, 0)
    assert list(r) == ["ok", "reason"] and r["ok"] is False and r["reason"].startswith("offers: policy misconfigured (fail closed): ")

    def boom(*a):
        raise RuntimeError("kaput")

    monkeypatch.setattr(W, "_decide_offer_set", boom)
    assert W.decide_offer_set({}, W._UNDEF, W._UNDEF, {}, "a", "s", 1, 0) == {
        "ok": False, "reason": "offers: evaluation error (fail closed): kaput"}


def test_world_evaluation_error_is_exact(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaput")

    monkeypatch.setattr(W, "validate_world_policy", boom)
    assert W.decide_intent_world({"committed": {}, "policy": {}}) == {
        "ok": False, "reason": "facts: evaluation error (fail closed): kaput"}


def test_validator_texts():
    assert W.validate_offer_set_wire(5) == "offer set must be an object"
    assert W.validate_offer_set_wire(None) == "offer set must be an object"
    assert W.validate_labels_wire([]) == "label receipt must be an object"
    assert W.validate_labels_wire("x") == "label receipt must be an object"
    assert W.verify_labels({}, []).startswith("unknown member") or W.verify_labels({}, []).startswith("missing member")
    with pytest.raises(ValueError) as e:
        W.lower_median([])
    assert str(e.value) == "lowerMedian: empty"
    assert W.lower_median([3, 1, 2]) == 2 and W.lower_median([4, 1, 3, 2]) == 2 and W.lower_median([7]) == 7


def test_verify_labels_key_list_type():
    ok = next(c for c in CASES if c["kind"] == "fn" and c["fn"] == "validateLabelsWire" and c["want"] is None)["arg"]
    assert W.verify_labels(ok, "x") == "label keys must be an array"
    assert W.verify_labels(ok, None) == "label keys must be an array"
    assert W.verify_labels(ok, []) == "no pinned label key for site '%s' kid '%s'" % (ok["site"], ok["kid"])


def test_closed_members_naming():
    assert W._closed_members({"z": 1}, ("a",), (), "thing") == "unknown member 'thing.z'"
    assert W._closed_members({}, ("a",), (), "thing") == "missing member 'thing.a'"
    assert W._closed_members({"z": 1}, ("a",)) == "unknown member 'object.z'"
    assert W._closed_members({}, ("a",)) == "missing member 'object.a'"
    assert W._closed_members({"a": 1, "b": 2}, ("a",), ("b",), "t") is None


def test_offer_policy_filter_members_are_closed():
    base = next(c for c in CASES if c["kind"] == "fn" and c["fn"] == "validateOfferPolicy" and c["want"] is None)["arg"]
    assert W.validate_offer_policy(base) is None
    for extra in ("extra", "filter", "f", "fil", "q", "query2"):
        bad = json.loads(json.dumps(base))
        bad["filter"][extra] = 1
        assert W.validate_offer_policy(bad) == "offers policy: filter must be exactly {query: {}, offer: {}}", extra
        bad = json.loads(json.dumps(base))
        bad["site_keys"][0][extra] = 1
        assert W.validate_offer_policy(bad) is not None, extra


def test_world_oracle_members_are_closed():
    base = next(c for c in CASES if c["kind"] == "fn" and c["fn"] == "validateWorldPolicy" and c["want"] is None)["arg"]
    assert W.validate_world_policy(base) is None
    for extra in ("extra", "oracle", "o", "kid2", "k"):
        bad = json.loads(json.dumps(base))
        bad["worlds"][0]["oracles"][0][extra] = 1
        assert W.validate_world_policy(bad) is not None, extra


def test_label_key_and_classifier_members_are_closed():
    keys = next(c for c in CASES if c["kind"] == "fn" and c["fn"] == "validateProvenancePolicy" and c["want"] is None)["arg"]["label_keys"]
    k = dict(keys[0])
    assert W.is_label_key(k) is True
    for extra in ("extra", "label_key", "site2", "s", "kid"):
        if extra in k:
            continue
        assert W.is_label_key(dict(k, **{extra: 1})) is False, extra
    assert W.is_label_key("x") is False and W.is_label_key({kk: v for kk, v in k.items() if kk != "kid"}) is False
    base = {"id": "tone", "param": "action.params.text", "labels": ["a"], "keys": [k["pk"]], "k": 1}
    assert W.validate_classifier_policy({"classifiers": [base]}) is None
    for extra in ("extra", "classifier", "id2", "i", "k2"):
        assert W.validate_classifier_policy({"classifiers": [dict(base, **{extra: 1})]}) is not None, extra


def test_flow_rule_longest_prefix_and_ties():
    rules = {"pii.*": ["a"], "pii.identity.*": ["b"], "*": ["z"]}
    assert W.flow_rule_for(rules, "pii.identity.passport") == "pii.identity.*"
    assert W.flow_rule_for(rules, "pii.contact") == "pii.*"
    assert W.flow_rule_for(rules, "piix") == "*"
    assert W.flow_rule_for({"a.*": [], "a.*": []}, "a.b") == "a.*"
    assert W.flow_rule_for({"pii.*": ["a"]}, "other") is None
    assert W.flow_rule_for(rules, "pii.identity") == "pii.*"


def test_label_ref_parsing():
    d = "A" * 43
    assert W.parse_label_ref("pca-labels:" + d + "#f") == {"receipt": d, "field": "f"}
    assert W.parse_label_ref("pca-labels:" + d + "#") is None and W.parse_label_ref("pca-labels:" + d) is None
    assert W.parse_label_ref("pca-labels:" + d + "#a#b") == {"receipt": d, "field": "a#b"}
    assert W.parse_label_ref("pca-labels:#f") is None and W.parse_label_ref("x" + d + "#f") is None
    assert W.parse_label_ref(5) is None and W.parse_label_ref("pca-labels:" + d + "#ff") == {"receipt": d, "field": "ff"}


def test_resolve_param_path_and_sorted_utf8():
    assert W.resolve_param_path({"a": 1}, "action.params.a") == {"found": True, "value": 1}
    assert W.resolve_param_path({"a": 1}, "action.params.") == {"found": False}
    assert W.resolve_param_path({"a": 1}, "x.a") == {"found": False}
    assert W.resolve_param_path({"a": 1}, 5) == {"found": False}
    assert W.resolve_param_path({"a": {"b": 2}}, "action.params.a.b") == {"found": True, "value": 2}
    assert W.resolve_param_path({"a": 1}, "action.params.a.b") == {"found": False}
    assert W._sorted_utf8(["\U00010000", "￿", "b", "a"]) == ["a", "b", "￿", "\U00010000"]
    assert W._utf8_key("a") == (b"a", "a".encode("utf-16-be"))
    assert W._utf8_key("\ud800")[0] == "�".encode()


def test_read_purpose_field_validation():
    base = {"fields": [{"path": "p", "class": "c"}], "purpose": "x", "coverage": {"x": ["c"]}}
    assert W.decide_read_purpose(base)["outcome"] == "allow"
    deny = {"outcome": "deny", "minimise": [], "uncovered": []}
    for bad in (dict(base, fields=[5]), dict(base, fields=[{"path": 5, "class": "c"}]), dict(base, fields=[{"path": "p", "class": 5}]),
                dict(base, fields=[None]), dict(base, fields=[{"class": "c"}]), dict(base, fields=[{"path": "p"}]),
                dict(base, coverage={"x": "c"}), dict(base, coverage=5), dict(base, purpose=5), dict(base, fields="x"),
                dict(base, on_uncovered="maybe"), dict(base, on_uncovered=5)):
        assert W.decide_read_purpose(bad) == deny, bad


def test_safe_int_helper():
    assert W._is_safe_int(2 ** 53 - 1) is True and W._is_safe_int(2 ** 53) is False and W._is_safe_int(-0.0) is False
    assert W._is_safe_int(0.0) is True and W._is_safe_int(1.5) is False and W._is_safe_int(float("inf")) is False
    assert W._is_safe_int(-(2 ** 53 - 1)) is True and W._is_safe_int(True) is False
