"""Differential kill tests (predicates) against the shared TS-generated oracle testdata/k042-predjs.json
(tools/pca-audit/java-mutate/k042-predjs-oracle.mjs; the Java K042PredJsOracleTest runs the same file). Inputs are JSON text
so every side parses identical lexemes (1e400, -0, lone surrogates)."""
import json
import os

import pytest

from atlas_pca.intent_wb import _utf8_len
from atlas_pca.intent_v2 import compare_utf8
from atlas_pca.predicates import (
    _deep_eq, _js_number_string, _jsnum, evaluate_condition, evaluate_condition_tri, evaluate_predicates, predicate_matches,
)

with open(os.path.join(os.path.dirname(__file__), "testdata", "k042-predjs.json"), encoding="utf-8") as fh:
    G = json.load(fh)


def _j(t):
    return json.loads(t, parse_int=lambda s: -0.0 if s == "-0" else int(s))


def _id(c):
    """A test id without a backslash: a second in-process pytest invocation (mutmut's warm-up collect followed by the run of
    explicit node ids) cannot select an id containing one."""
    return c["name"].replace("\\", "<bs>")


def _ctx(name):
    return _j(G["ctx"][name])


def test_corpus_sizes():
    assert len(G["tri"]) > 400 and len(G["preds"]) > 50 and len(G["eq"]) > 50 and len(G["nums"]) > 40


@pytest.mark.parametrize("c", G["tri"], ids=[_id(c) for c in G["tri"]])
def test_condition_matches_reference(c):
    cond = _j(c["cond"])
    assert evaluate_condition_tri(cond, _ctx(c["ctx"])) == c["tri"]
    assert evaluate_condition(cond, _ctx(c["ctx"])) == (c["tri"] == "true")


@pytest.mark.parametrize("c", G["preds"], ids=[_id(c) for c in G["preds"]])
def test_predicates_match_reference(c):
    preds = _j(c["preds"])
    assert evaluate_predicates(preds, _ctx(c["ctx"]))["allowed"] == c["allowed"]
    if isinstance(preds, list):
        assert len(preds) == len(c["each"])
        for p, w in zip(preds, c["each"]):
            assert predicate_matches(p, _ctx(c["ctx"])) == w


def test_deep_equality_is_canonical_text_equality():
    bad = [(c["a"], c["b"]) for c in G["eq"] if _deep_eq(_j(c["a"]), _j(c["b"])) != c["eq"]]
    assert bad == []


def test_numbers_match_javascript():
    bad = []
    for c in G["nums"]:
        if not c["finite"]:
            continue
        v = _j(c["raw"])
        if c["js"] == "-0":
            continue  # String(-0) is "0" in JS; the oracle's spelling is the canonical one
        if c["plain"] and _js_number_string(_jsnum(v)) != c["js"]:
            bad.append((c["raw"], _js_number_string(_jsnum(v)), c["js"]))
    assert bad == []


def test_utf8_lengths_and_order():
    for c in G["u8"]:
        assert _utf8_len(c["s"]) == c["n"], c["s"].encode("utf-16", "surrogatepass")
        lone = any(0xD800 <= ord(ch) <= 0xDFFF for ch in c["s"])
        assert lone == c["lone"]
    for c in G["cmp"]:
        r = compare_utf8(c["a"], c["b"])
        assert (r > 0) - (r < 0) == c["sign"]


def _mo(v):
    return {"field": "subject.id", "op": "member_of", "collection": "subject.g", "value": v}


def _wrap(g, start):
    return {"action": {"verb": "v", "resource": "r"}, "subject": {"id": start, "g": g}}


def test_member_closure_is_capped_like_the_reference():
    chain = _wrap({"n%d" % i: "n%d" % (i + 1) for i in range(10005)}, "n0")
    for v, want in G["chain"].items():
        assert evaluate_condition_tri(_mo(v), chain) == want, v
    g = {"s": ["a%d" % i for i in range(100)]}
    cs = ["c%d" % j for j in range(100)]
    for i in range(100):
        g["a%d" % i] = cs
    g["c0"] = "e"
    g["e"] = "t"
    fan = _wrap(g, "s")
    for v, want in G["fan"].items():
        assert evaluate_condition_tri(_mo(v), fan) == want, v
