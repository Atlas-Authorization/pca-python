"""Replays the TS-reference oracle of the policy debugger (testdata/ref-policy-debug.json.gz, 553 cases): explainRisk, explainDecision
over Policy VM decide inputs, applyDelta, counterfactual and auditPCActn (the core verifier's report with the explanation).
Every fn has a handler and the total is asserted. Results are compared by JSON value with null members counted as absent (the reference
leaves an option it was not given undefined; this port carries None); in an optional position null is "not given", except the audit's
audience, where an explicit null is the opt-out and an absent member is "not given"."""
import math
import os

import pytest

from atlas_pca import policy_debug as P
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("policy-debug", os.path.join(HERE, "testdata", "ref-policy-debug.json.gz"))
TOTALS = {"explainRisk": 315, "explainDecision": 140, "applyDelta": 63, "counterfactual": 26, "auditPCActn": 9}


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _present(v):
    if isinstance(v, dict):
        return {k: _present(x) for k, x in v.items() if x is not None}
    return [_present(x) for x in v] if isinstance(v, list) else v


def _same(got, out, _case):
    return canon(_present(got)) == canon(_present(out))


def _audit(p, inp, opts):
    kw = {"now_epoch": opts.get("nowEpoch"), "insecure_skip_plan_root_check": opts.get("insecureSkipPlanRootCheck") is True}
    if "audience" in opts:
        kw["audience"] = opts["audience"]
    return P.audit_pcactn(p, inp, opts["grant"], **kw)


HANDLERS = {
    "explainRisk": lambda inputs, weights, floor: P.explain_risk(inputs, weights) if floor is None else P.explain_risk(inputs, weights, floor),
    "explainDecision": P.explain_decision,
    "applyDelta": P.apply_delta,
    "counterfactual": P.counterfactual,
    "auditPCActn": _audit,
}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 553 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_policy_debug_replay(fn):
    ran, skipped = run(CASES[fn], lambda *args: HANDLERS[fn](*_dec(list(args))), compare=_same)
    assert (ran, skipped) == (TOTALS[fn], 0)
