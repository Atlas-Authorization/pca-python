"""Assurance labels and the high-assurance gate (T8 / B7): replays packages/pca/conformance/assurance-vectors.json
(`signature_level`, `report`, `requirement`, `multi_root`). Reports and reasons are compared exactly (key order is
irrelevant). A missing vector file fails."""
import json
import os
from types import SimpleNamespace

import pytest

from atlas_pca import assurance_report, multi_root_level, set_assurance_label, signature_level, unmet_assurance

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "conformance", "assurance-vectors.json"), encoding="utf-8") as f:
    DOC = json.load(f)


def _hook(label):
    """A verifier hook carrying the declared label, or an unlabelled one."""
    h = SimpleNamespace()
    if label == "unlabelled":
        return h
    return set_assurance_label(h, label["level"], vendor=label.get("vendor"), preview=label.get("preview"), ceremony=label.get("ceremony"))


def build(v):
    hooks = {k: _hook(x) for k, x in (v.get("hooks") or {}).items()}
    return assurance_report(v.get("pcactn"), v["checks"], v.get("degraded"), hooks=hooks,
                            attestation_hook=_hook(v["attestation_hook"]) if "attestation_hook" in v else None,
                            threshold_t=v.get("threshold_t"), allow_unbound_pq=bool(v.get("allow_unbound_pq")))


def test_corpus_is_complete():
    assert [len(DOC[k]) for k in ("signature_level", "report", "requirement", "multi_root")] == [14, 37, 44, 10]


@pytest.mark.parametrize("v", DOC["signature_level"], ids=lambda v: str(v["alg"]))
def test_signature_level(v):
    assert signature_level(v["alg"]) == v["level"]


@pytest.mark.parametrize("v", DOC["report"], ids=lambda v: v["name"])
def test_report(v):
    assert build(v) == v["report"]


@pytest.mark.parametrize("v", DOC["requirement"], ids=lambda v: v["name"])
def test_requirement(v):
    assert unmet_assurance(v["report"], v["require"]) == v["unmet"]


@pytest.mark.parametrize("v", DOC["multi_root"], ids=lambda v: v["name"])
def test_multi_root(v):
    roots = [{"verifier": _hook({"level": r["level"]}), "required": r.get("required")} for r in v["roots"]]
    assert multi_root_level(roots, v["threshold"]) == v["level"]


def test_a_label_never_comes_from_the_presented_evidence():
    # the report reads the hook's label only; a PCActn claiming "hardware" changes nothing
    r = assurance_report({"attestation": {"level": "hardware"}}, {"attestation": "pass"}, hooks={"attestation": SimpleNamespace()})
    assert r["attestation"] == {"outcome": "pass", "level": "unknown"}


def test_unknown_requirement_values_fail_closed():
    ok = {"attestation": {"outcome": "pass", "level": "hardware"}, "zk_compliance": {"outcome": "pass", "level": "groth16"}}
    for req in ({"attestation": "unknown"}, {"attestation": "tpm"}, {"zk": "magic"}, {"threshold": "multisig"}, {"signature": "any"}):
        why = unmet_assurance(ok, req)
        assert why is not None and why.startswith("assurance: unknown ") and why.endswith("(fail closed)"), (req, why)
