"""Replays the TS-reference oracle of the budget forecaster (testdata/ref-budget-forecast.json.gz, 326 cases): forecast over a compiled
policy (the simulator underneath, with the default catalog, a custom one and an empty one), recommendPolicy and autonomyBoundOf.
Every fn has a handler and the total is asserted. A spec is {permissions, limits?, budgetModel?, riskPolicy?, now}, compiled with
compile_policy; null in an optional position is "not given"; numbers are compared as IEEE doubles (their shortest JSON form)."""
import math
import os

import pytest

from atlas_pca import budget_forecast as B
from atlas_pca import catalog as C
from atlas_pca.facade import compile_policy
from base_oracle import HERE, canon, load

COUNT, CASES = load("budget-forecast", os.path.join(HERE, "testdata", "ref-budget-forecast.json.gz"))


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def compiled(spec):
    return compile_policy(spec["permissions"], limits=spec.get("limits"), budget_model=spec.get("budgetModel"),
                          risk_policy=spec.get("riskPolicy"), now=spec.get("now"))


def _forecast(spec, plan, start, actions):
    cat = None if actions is None else C.build_catalog([C.define_action(a) for a in actions])
    return B.forecast(compiled(spec), plan, start=start, catalog=cat)


HANDLERS = {
    "forecast": _forecast,
    "recommendPolicy": B.recommend_policy,
    "autonomyBoundOf": B.autonomy_bound_of,
}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 326 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == {"forecast": 150, "recommendPolicy": 166, "autonomyBoundOf": 10}


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_budget_forecast_replay(fn):
    bad = []
    for c in CASES[fn]:
        out = c["out"]
        threw = isinstance(out, dict) and "$throws" in out
        try:
            got = HANDLERS[fn](*_dec(c["args"]))
        except Exception as e:  # noqa: BLE001 - a native refusal, compared against the reference
            if not threw:
                bad.append("%s\n    native raised %s: %s\n    ref:    %s" % (c["name"], type(e).__name__, e, canon(out)[:300]))
            continue
        if threw or canon(got) != canon(out):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:600], canon(out)[:600]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))
