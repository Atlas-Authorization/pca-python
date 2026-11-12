"""The Intent Layer v2 state vectors (packages/pca/conformance/intent-state-vectors.json): accumulator and monitor
declarations, values and pre-states, the session-history window and fold, sequencer key sets and reservation receipts.
Every case is run through this verifier's implementation and compared (as canonical JSON) to the reference output."""
import json
import os

import pytest

from atlas_pca.intent_history import HistoryError, acc_key_of, acc_post, acc_pre_state, in_window, monitor_state, monitor_step
from atlas_pca.intent_v2 import suite_capability_error
from atlas_pca.pca import canonicalize
from test_k042_intentacc_diff import FNS as ACC_FNS, PQ_ALGS, _copy

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")
with open(os.path.join(DIR, "intent-state-vectors.json"), encoding="utf-8") as fh:
    DOC = json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))
CASES = DOC["cases"]


def _try(f):
    try:
        return f()
    except HistoryError:
        return {"throws": True}


def _pre(a):
    cand = a[2]
    return _try(lambda: acc_pre_state(a[0], a[1], cand["params"], cand["t"], a[3]))


def _post(a):
    cand = a[2]
    return _try(lambda: acc_post(a[0], a[1], cand["verb"], cand["params"], cand["t"], a[3]))


HISTORY_FNS = {
    "inWindow": lambda a: in_window(a[0], a[1], a[2]),
    "accKeyOf": lambda a: acc_key_of(a[0], a[1]),
    "accPreState": _pre,
    "accPost": _post,
    "monitorStep": lambda a: monitor_step(a[0], a[1], a[2]),
    "monitorState": lambda a: monitor_state(a[0], a[1]),
}
FNS = {**ACC_FNS, **HISTORY_FNS}


def test_the_corpus_file_is_fully_run():
    assert (DOC["format"], DOC["ver"]) == ("pca-intent-state-vectors", 1)
    assert len(CASES) > 3000
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
    assert canonicalize(got) == canonicalize(c["out"]), c["name"]
