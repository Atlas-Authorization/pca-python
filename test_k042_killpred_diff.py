"""Differential kill tests (predicate DSL) against the shared TS-generated oracle testdata/killPred.json.gz
(tools/pca-audit/kotlin-mutate/killPred-oracle-gen.mjs; Kotlin KillPredTest runs the same file): path resolution over many
contexts, every leaf operator over fields x operands, `like` / `matches`, `member_of` closures (10,000-node bound, own
`__proto__` members), groupings, predicates and predicate lists."""
import gzip
import json
import os
import sys

import pytest

from atlas_pca.predicates import (
    evaluate_condition, evaluate_condition_tri, evaluate_predicates, predicate_matches, resolve_path,
)

def _load():
    """The corpus holds conditions nested 2,000 levels deep (a `not` chain); CPython's json decoder recurses per level (3.10
    needs far more than the default limit), so the limit is raised for the decode only and restored in a finally."""
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, 50000))
    try:
        with gzip.open(os.path.join(os.path.dirname(__file__), "testdata", "killPred.json.gz"), "rt", encoding="utf-8") as fh:
            return json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))
    finally:
        sys.setrecursionlimit(old)


D = _load()

TRI = {"T": "true", "F": "false", "U": "unknown"}


def _ctx(i):
    return D["ctxs"][i]


def _txt(v):
    """Order-insensitive JSON text, numbers by value (an integral float prints like its int)."""
    if isinstance(v, dict):
        return "{" + ",".join("%s:%s" % (json.dumps(k), _txt(v[k])) for k in sorted(v)) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_txt(x) for x in v) + "]"
    if isinstance(v, float) and v == v and abs(v) != float("inf") and v == int(v) and abs(v) < 1e17:
        return str(int(v)) if v != 0 or str(v)[0] != "-" else "-0"
    return json.dumps(v)


def _label(e):
    return "%s @ctx%s" % (_txt(e[0])[:160], e[1])


def test_corpus_is_the_full_oracle():
    assert len(D["rp"]) > 1500 and len(D["cond"]) > 100000 and len(D["pred"]) > 1000 and len(D["preds"]) > 80


def test_resolve_path_matches_the_reference():
    bad = []
    for e in D["rp"]:
        r = resolve_path(_ctx(e[1]), e[0])
        if r["found"] != e[2] or (r["found"] and _txt(r["value"]) != _txt(e[3])):
            bad.append(_label(e))
    assert bad == [], bad[:20]


def test_conditions_match_the_reference():
    bad = []
    for e in D["cond"]:
        got = evaluate_condition_tri(e[0], _ctx(e[1]))
        want = TRI[e[2]]
        if got != want or evaluate_condition(e[0], _ctx(e[1])) != (want == "true"):
            bad.append("%s: want %s got %s" % (_label(e), want, got))
    assert bad == [], "%d mismatches: %s" % (len(bad), bad[:20])


def test_predicates_match_the_reference():
    bad = [_label(e) for e in D["pred"] if predicate_matches(e[0], _ctx(e[1])) != e[2]]
    assert bad == [], bad[:20]


def test_predicate_lists_match_the_reference():
    bad = [_label(e) for e in D["preds"] if evaluate_predicates(e[0], _ctx(e[1]))["allowed"] != e[2]]
    assert bad == [], bad[:20]
