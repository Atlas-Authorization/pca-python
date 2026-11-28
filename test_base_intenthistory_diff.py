"""Differential replay of session histories (windows, keys, pre-states, post values, monitor folds) against the TypeScript
reference: testdata/base-intenthistory.json.gz, every case. Where the reference throws (a corrupt history, a null entry or
window, an unusable candidate) the port raises; where the reference's window test has no answer (an unknown window kind) the
port answers False; a monitor of an unknown kind has no next state (None) in both."""
import pytest

from atlas_pca import intent_history as H
from base_oracle import canon, load, run

COUNT, CASES = load("intenthistory")

MAP = {
    "inWindow": H.in_window,
    "accKeyOf": H.acc_key_of,
    "accPreState": lambda a, h, cand, schema: H.acc_pre_state(a, h, cand["params"], cand["t"], schema),
    "accPost": lambda a, h, cand, schema: H.acc_post(a, h, cand["verb"], cand["params"], cand["t"], schema),
    "monitorStep": H.monitor_step,
    "monitorState": H.monitor_state,
}
TOTALS = {"inWindow": 1848, "accKeyOf": 104, "accPreState": 11340, "accPost": 14784, "monitorStep": 1003, "monitorState": 100}


def _in_window_equal(got, out, _case):
    return isinstance(got, bool) and got == (False if out is None else out)


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS and COUNT == 29179
    throws = sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"])
    assert throws == 16284  # the rest are values: a replay that only refuses cannot pass


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, skipped = run(CASES[fn], MAP[fn], compare=_in_window_equal if fn == "inWindow" else None)
    assert (ran, skipped) == (TOTALS[fn], 0)


def test_values_are_json_plain():
    assert canon(H.acc_pre_state({"agg": "distinct", "val": "action.params.item", "sel": {"verbs": ["v"]}, "win": {"kind": "task"}, "key": None},
                                 [], {"item": "a"}, 0)) == '{"values":[]}'
