"""Differential kill tests (rule 19 map, rule 18 classifier, shared artifact helpers) against the shared TS-generated
oracle testdata/k042-mapartcls.json.gz (tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs; Java K042MapArtClsDiffTest
runs the same file). Every validator case asserts the EXACT reason (or None), every decision the exact verdict."""
import gzip
import json
import os

import pytest

from atlas_pca import intent_map as M
from atlas_pca import intent_wb as W
from atlas_pca.intent_wb import verify_artifact_sig

with gzip.open(os.path.join(os.path.dirname(__file__), "testdata", "k042-mapartcls.json.gz"), "rt", encoding="utf-8") as fh:
    CASES = json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))


def _of(fn):
    return [c for c in CASES if c["fn"] == fn]


def _ids(fn):
    return [c["name"] for c in _of(fn)]


VALIDATORS = {
    "header": M.map_header_error,
    "cell": M.map_cell_error,
    "metrics": M.map_metrics_error,
    "learner": M.map_learner_error,
    "disclosure": M.map_disclosure_error,
    "verdictwire": W.validate_classifier_verdict_wire,
    "policy": W.validate_classifier_policy,
}


def test_corpus_is_the_full_oracle():
    assert len(CASES) == 896


@pytest.mark.parametrize("fn", sorted(VALIDATORS))
def test_validators_match_the_reference(fn):
    bad = []
    for c in _of(fn):
        try:
            got = VALIDATORS[fn](c["args"][0])
        except Exception as e:  # noqa: BLE001
            got = "THROWS %r" % e
        if got != c["out"]:
            bad.append((c["name"], c["out"], got))
    assert bad == []


def test_numeric_cells():
    bad = []
    for c in _of("numcells"):
        got = [list(t) for t in M.map_num_cells(c["args"][0])]
        if got != c["out"]:
            bad.append((c["name"], c["out"], got))
    assert bad == []


def test_cell_of_the_action():
    bad = []
    for c in _of("cellof"):
        a = c["args"]
        try:
            r = M.map_cell_of(a[0], a[1], a[2] if len(a) > 2 else None)
            got = None if "error" in r else {"cell": r["cell"], "flat": r["flat"]}
        except Exception as e:  # noqa: BLE001
            got = "THROWS %r" % e
        if got != c["out"]:
            bad.append((c["name"], c["out"], got))
    assert bad == []


def test_commitment():
    for c in _of("commit"):
        assert M.commit_leaves(c["args"][0]) == c["out"], c["name"]


def test_map_decisions():
    bad = []
    for c in _of("decide"):
        got = M.decide_map_primitive(c["args"][0])
        if got != c["out"]:
            bad.append((c["name"], c["out"], got))
    assert bad == []


def test_classifier_decisions():
    bad = []
    for c in _of("classify"):
        r = W.decide_classifier_dimensions(c["args"][0])
        got = {"ok": r["ok"]}
        if r["ok"]:
            got["classes"] = r["classes"]
        else:
            got["reason"] = r["reason"]
        if got != c["out"]:
            bad.append((c["name"], c["out"], got))
    assert bad == []


def test_artifact_signature():
    verdict, pk, other = _of("sigfixture")[0]["args"]
    dom = W.INTENT_CLASSIFIER_DOMAIN if hasattr(W, "INTENT_CLASSIFIER_DOMAIN") else None
    assert dom is not None
    assert verify_artifact_sig(dom, verdict, pk) is True
    assert verify_artifact_sig(dom, verdict, other) is False
    assert verify_artifact_sig(dom + "x", verdict, pk) is False
    no_sig = {k: v for k, v in verdict.items() if k != "sig"}
    assert verify_artifact_sig(dom, no_sig, pk) is False
    assert verify_artifact_sig(dom, dict(verdict, sig=5), pk) is False
    assert verify_artifact_sig(dom, verdict, None) is False
    assert verify_artifact_sig(dom, verdict, 5) is False
    assert verify_artifact_sig(dom, dict(verdict, label="a\ud800"), pk) is False
