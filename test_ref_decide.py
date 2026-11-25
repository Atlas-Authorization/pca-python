"""Replays the TS-reference oracles of the Policy VM: testdata/ref-decide-java.json.gz (decide, 226 cases) and
testdata/ref-decide-derive.json.gz (deriveDecideInput and derive-then-decide, 120 cases each). Results are compared by JSON value with
null members counted as absent (the reference leaves an option it was not given undefined; this port carries None). A refusal with a
code must carry the same code."""
import os

import pytest

from atlas_pca.policy_vm import decide, derive_decide_input
from base_oracle import HERE, canon, load, run

D_COUNT, D_CASES = load("decide", os.path.join(HERE, "testdata", "ref-decide-java.json.gz"))
R_COUNT, R_CASES = load("decide-derive", os.path.join(HERE, "testdata", "ref-decide-derive.json.gz"))
_KW = {"grant": "grant", "plan": "plan", "params": "params", "risk": "risk", "budget": "budget", "chain": "chain", "now": "now", "pqPins": "pq_pins",
       "goalNodeId": "goal_node_id", "subject": "subject", "env": "env", "caveatContext": "caveat_context", "ageHorizonMs": "age_horizon_ms"}


def _nums(v):
    """The corpus spells a non-finite number {"$num": "NaN" | "Infinity" | "-Infinity"}."""
    if isinstance(v, dict):
        if len(v) == 1 and "$num" in v:
            return float(v["$num"].replace("Infinity", "inf"))
        return {k: _nums(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_nums(x) for x in v]
    return v


def _present(v):
    if isinstance(v, dict):
        return {k: _present(x) for k, x in v.items() if x is not None}
    if isinstance(v, list):
        return [_present(x) for x in v]
    return v


def _same(got, out, _case):
    return canon(_present(got)) == canon(_present(out))


def _derive(p, ctx):
    return derive_decide_input(_nums(p), **{_KW[k]: _nums(v) for k, v in ctx.items()})


def _derive_then_decide(p, ctx):
    inp = _derive(p, ctx)
    return {"input": inp, "decision": decide(inp)}


def test_corpora_are_complete():
    assert D_COUNT == 226 and set(D_CASES) == {"decide"}
    assert R_COUNT == 240 and set(R_CASES) == {"deriveDecideInput", "deriveThenDecide"}


def test_decide_matches_the_reference():
    ran, skipped = run(D_CASES["decide"], lambda inp: decide(_nums(inp)), compare=_same)
    assert ran == 226 and skipped == 0


@pytest.mark.parametrize("fn,call", [("deriveDecideInput", _derive), ("deriveThenDecide", _derive_then_decide)])
def test_derive_matches_the_reference(fn, call):
    ran, skipped = run(R_CASES[fn], call, compare=_same)
    assert ran == 120 and skipped == 0
