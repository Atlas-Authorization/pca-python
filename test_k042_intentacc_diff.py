"""Differential kill tests (rule 15: accumulators, monitors, pre-states, reservation receipts, sequencer key sets,
receipt verification against the sequenced holder) against the shared TS-generated oracle testdata/k042-intentacc.json
(tools/pca-audit/java-mutate/k042-intentacc-oracle.mjs; Java K042IntentAccOracleTest runs the same file). Every case
asserts the exact reason / verdict / value (compared as canonical JSON)."""
import json
import os

import pytest

from atlas_pca import intent_v2 as V
from atlas_pca.intent_v2 import suite_capability_error
from atlas_pca.pca import canonicalize

with open(os.path.join(os.path.dirname(__file__), "testdata", "k042-intentacc.json"), encoding="utf-8") as fh:
    CASES = json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))

PQ_ALGS = ("ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s")


def _acc_value(a):
    r = V.acc_value_of(a[0], a[1], a[2], a[3])
    if not r["ok"]:
        return {"ok": False, "reason": r["reason"]}
    return {"ok": True, "val": r["val"], "key": r.get("key")}


def _combine(a):
    v = dict(a[2])
    return V.combine_acc({"agg": a[0]}, a[1], v)


FNS = {
    "accumulatorDeclError": lambda a: V.accumulator_decl_error(a[0]),
    "monitorDeclError": lambda a: V.monitor_decl_error(a[0]),
    "monitorStates": lambda a: V.monitor_states(a[0]),
    "trackedKeySetError": lambda a: V.tracked_key_set_error(a[0]),
    "preStateError": lambda a: V.pre_state_error({"agg": a[0]}, a[1]),
    "preValue": lambda a: V.pre_value({"agg": a[0]}, a[1]),
    "combineAcc": _combine,
    "accSelects": lambda a: V.acc_selects(a[0], a[1], a[2]),
    "accValueOf": _acc_value,
    "receiptArithmeticOk": lambda a: V.receipt_arithmetic_ok({"agg": a[0]}, a[1], a[2]),
    "pcactnReservationDigest": lambda a: V.pcactn_reservation_digest(a[0]),
    "receiptShapeError": lambda a: V.acc_receipt_shape_error(a[0]),
    "keySetShapeError": lambda a: V.sequencer_key_set_shape_error(a[0]),
    "verifyKeySet": lambda a: V.verify_sequencer_key_set(a[0], a[1], a[2] if a[3] else None),
    "verifyReceiptSignature": lambda a: V.verify_acc_receipt_signature(a[0], a[1], a[2]),
    "verifyReceiptAgainstHolder": lambda a: V.verify_receipt_against_holder(
        a[0], a[1], a[2], a[3], a[4], a[5], None, a[6]),
}


def _copy(x):
    if isinstance(x, list):
        return [_copy(e) for e in x]
    if isinstance(x, dict):
        return {k: _copy(v) for k, v in x.items()}
    return x


def test_corpus_is_the_full_oracle():
    assert len(CASES) > 1500
    assert {c["fn"] for c in CASES} == set(FNS)


def _uses_unavailable_pq(c):
    text = json.dumps(c["args"])
    return any(('"alg": "%s"' % a in text or '"alg": "hybrid-ed25519-%s"' % a in text) and suite_capability_error(a)
               for a in PQ_ALGS)


@pytest.mark.parametrize("c", CASES, ids=[c["name"] for c in CASES])
def test_matches_the_reference(c):
    if _uses_unavailable_pq(c):
        pytest.skip("PQ suite unavailable on this host")
    try:
        got = FNS[c["fn"]](_copy(c["args"]))
    except Exception as e:  # noqa: BLE001
        got = "THREW %r" % e
    g = canonicalize(got)
    if "unsupported_suite" in g and any(a in g and suite_capability_error(a) for a in PQ_ALGS):
        pytest.skip("PQ suite unavailable on this host")
    assert g == canonicalize(c["out"])
