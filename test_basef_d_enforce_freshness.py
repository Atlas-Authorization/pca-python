"""`enforce_freshness` (reference enforce.freshness): the signed freshness anchor as a gate, check `freshness_anchor`."""
import copy
import json
import os

import pytest

import atlas_pca.pca as PCA
from atlas_pca import verify_pcactn_core

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "conformance", "vectors.json"), os.path.join(_HERE, "conformance", "vectors.json")):
    if os.path.exists(_p):
        with open(_p, encoding="utf-8") as _f:
            V = {v["name"]: v for v in json.load(_f)["vectors"]}["valid-in-plan-action"]
        break
NOW = V["context"]["now"]


def run(freshness, gate, monkeypatch):
    monkeypatch.setattr(PCA, "_verify_suite", lambda *a, **k: True)  # the member is signed: only the gate is under test
    p = copy.deepcopy(V["pcactn"])
    if freshness is not None:
        p["freshness"] = freshness
    return verify_pcactn_core(p, V["grant"], now=NOW, audience=V["context"]["aud"], insecure_skip_plan_root_check=True, enforce_freshness=gate)


def anchor(epochs_ago, epoch_ms=60_000):
    return {"beacon_ref": "b", "epoch": NOW // epoch_ms - epochs_ago, "accumulator_witness": ""}


def test_the_gate_is_off_by_default():
    v = verify_pcactn_core(V["pcactn"], V["grant"], now=NOW, audience=V["context"]["aud"], insecure_skip_plan_root_check=True)
    assert v.allow is True and "freshness_anchor" not in v.checks


def test_a_stub_anchor_is_missing(monkeypatch):
    v = verify_pcactn_core(V["pcactn"], V["grant"], now=NOW, audience=V["context"]["aud"], insecure_skip_plan_root_check=True,
                           enforce_freshness={"max_age_ms": 10 ** 9})
    assert v.allow is False and v.checks["freshness_anchor"] is False
    assert v.reason == "freshness_anchor: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"


@pytest.mark.parametrize("fr", [{"beacon_ref": "", "epoch": 5}, {"beacon_ref": "b", "epoch": 0}, {"beacon_ref": "b", "epoch": -1},
                                {"beacon_ref": "b", "epoch": 1.5}, {"beacon_ref": "b", "epoch": True}, {"beacon_ref": 5, "epoch": 5},
                                {"beacon_ref": "b", "epoch": 9007199254740992}, {"epoch": 5}, "x", None])
def test_every_malformed_anchor_is_missing(fr, monkeypatch):
    v = run({"accumulator_witness": "", **fr} if isinstance(fr, dict) else fr, {"max_age_ms": 10 ** 9}, monkeypatch)
    assert v.allow is False
    if v.checks.get("wire") is False:  # a structurally malformed member is refused at the wire, before the gate (equally closed)
        assert "freshness_anchor" not in v.checks
    else:
        assert v.checks["freshness_anchor"] is False
        assert v.reason == "freshness_anchor: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"


@pytest.mark.parametrize("fr", [{"beacon_ref": "", "epoch": 5}, {"beacon_ref": "b", "epoch": 0}])
def test_these_malformed_anchors_reach_the_gate(fr, monkeypatch):
    v = run({"accumulator_witness": "", **fr}, {"max_age_ms": 10 ** 9}, monkeypatch)
    assert v.checks.get("wire") is not False and v.checks["freshness_anchor"] is False


def test_a_fresh_anchor_passes_and_the_age_boundary_is_inclusive(monkeypatch):
    a = anchor(2)
    age = NOW - a["epoch"] * 60_000
    ok = run(a, {"max_age_ms": age}, monkeypatch)
    assert ok.allow is True and ok.checks["freshness_anchor"] is True
    stale = run(a, {"max_age_ms": age - 1}, monkeypatch)
    assert stale.allow is False and stale.reason == "freshness_anchor: freshness anchor is stale (older than %d ms)" % (age - 1)


def test_a_future_anchor_is_refused_unless_the_skew_covers_it(monkeypatch):
    a = {"beacon_ref": "b", "epoch": NOW // 60_000 + 3, "accumulator_witness": ""}
    ahead = a["epoch"] * 60_000 - NOW
    assert run(a, {"max_age_ms": 10 ** 9}, monkeypatch).reason == "freshness_anchor: freshness anchor is in the future"
    assert run(a, {"max_age_ms": 10 ** 9, "clock_skew_ms": ahead - 1}, monkeypatch).reason == "freshness_anchor: freshness anchor is in the future"
    assert run(a, {"max_age_ms": 10 ** 9, "clock_skew_ms": ahead}, monkeypatch).checks["freshness_anchor"] is True
    assert run(a, {"max_age_ms": 10 ** 9, "clock_skew_ms": -5}, monkeypatch).reason == "freshness_anchor: freshness anchor is in the future"


def test_the_gate_clock_and_epoch_length_are_configurable(monkeypatch):
    a = {"beacon_ref": "b", "epoch": 10, "accumulator_witness": ""}
    assert run(a, {"max_age_ms": 5, "epoch_ms": 1000, "now": 10_005}, monkeypatch).checks["freshness_anchor"] is True
    assert run(a, {"max_age_ms": 4, "epoch_ms": 1000, "now": 10_005}, monkeypatch).checks["freshness_anchor"] is False


@pytest.mark.parametrize("gate", [{"max_age_ms": -1}, {"max_age_ms": float("nan")}, {"max_age_ms": "5"}, {}, {"max_age_ms": 5, "epoch_ms": 0},
                                  {"max_age_ms": 5, "epoch_ms": -3}, {"max_age_ms": 5, "epoch_ms": float("inf")}])
def test_a_misconfigured_gate_fails_closed(gate, monkeypatch):
    v = run(anchor(1), gate, monkeypatch)
    assert v.allow is False and v.checks["freshness_anchor"] is False
    assert v.reason == "freshness_anchor: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"
