"""Replays the TS-reference oracle of the frontier signals (testdata/ref-frontier-signals.json.gz, 690 cases): the three signal typings and
the risk-input tightening, signed zeros included. Every fn has a handler and the totals are asserted; a reference refusal (a null baseline
or objective) needs a native exception."""
import math
import os

import pytest

from atlas_pca import frontier_signals as F
from base_oracle import HERE, load, run

COUNT, CASES = load("frontier-signals", os.path.join(HERE, "testdata", "ref-frontier-signals.json.gz"))
HANDLERS = {"semanticSignal": F.semantic_signal, "progressSignal": F.progress_signal, "objectiveSignal": F.objective_signal, "tightenRiskInputs": F.tighten_risk_inputs}
TOTALS = {"semanticSignal": 39, "progressSignal": 129, "objectiveSignal": 182, "tightenRiskInputs": 340}


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _same(got, out, _case):
    """Equal by value, with the sign of a zero compared explicitly (min(0, -0) is -0, max(-0, 0) is 0)."""
    def z(x):
        return math.copysign(1, x) if isinstance(x, (int, float)) and not isinstance(x, bool) and x == 0 else None
    if isinstance(out, dict) and isinstance(got, dict):
        return set(out) == set(got) and all(_same(got[k], out[k], None) for k in out)
    return got == out and z(got) == z(out) and isinstance(got, bool) == isinstance(out, bool)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 690 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 2


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_frontier_signals_replay(fn):
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same) == (TOTALS[fn], 0)
