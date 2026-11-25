"""Replays the TS-reference oracle of the intent runtime's routing and conformance (testdata/ref-intent-routing.json.gz, 849 cases): the optimistic bond sizing
(the intent runtime's and the settlement module's implementations, over the same cases), the score quantiser, the judge verdict check, the conformal
threshold and empirical false-allow rate, the k-of-n semantic threshold, and the learner-bound scenarios (route per outcome, the route after runtime vetoes,
the conformance attestation with its tampered forms and the panel check, the just-in-time consent record). Every fn has a handler and the totals are
asserted; an infinite threshold is compared as the string "inf"; a reference refusal needs a native exception."""
import copy
import decimal
import math
import os

import pytest

from atlas_pca import bond_settlement as BS
from atlas_pca import intent_mapkit as MK
from atlas_pca import intent_runtime as RT
from atlas_pca import semantic_threshold as ST
from base_oracle import HERE, load, run

COUNT, CASES = load("intent-routing", os.path.join(HERE, "testdata", "ref-intent-routing.json.gz"))


def _js_number(v):
    """A JS Number as the corpus carries it: integral values below 1e21 as the shortest-digits integer, larger ones as a float."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return v
    f = float(v)
    if f != f or f in (float("inf"), float("-inf")):
        return f
    return int(decimal.Decimal(repr(f))) if f.is_integer() and abs(f) < 1e21 else f


def _bond(bond_amount):
    return lambda p, e: _js_number(bond_amount(p, e))


def _inf(x):
    return x if isinstance(x, float) and math.isfinite(x) or not isinstance(x, float) else "inf"


def _learner(omega, map_opts, observations):
    l = MK.create_learner(omega, map_opts)
    for x in observations:
        l.observe({"verb": x["verb"], "values": x["values"]}, x["y"], x["source"])
    return l


def _threshold(verdicts, opts):
    r = ST.verify_semantic_threshold(verdicts, opts)
    return dict(r, cutoff=_inf(r["cutoff"])) if r.get("cutoff") is not None else r


def _route(omega, map_opts, observations, outcomes, opts):
    l = _learner(omega, map_opts, observations)
    return [RT.route_action(l, o, opts) for o in outcomes]


def _route_veto(omega, map_opts, observations, outcomes, opts):
    l = _learner(omega, map_opts, observations)
    for o in outcomes:
        l.observe(o, 0, "runtime")
    return [RT.route_action(l, o, opts) for o in outcomes]


def _verify(verdicts, vo):
    return ST.verify_semantic_threshold(verdicts, vo)


def _mutations():
    def tog(a):
        a["ok"] = not a["ok"]
        return a

    def bump(a):
        a["aggregate_score_ppm"] += 1
        return a

    def pop(a):
        if a["verdict_digests"]:  # [].pop() is a no-op in JS
            a["verdict_digests"].pop()
        return a

    def kk(a):
        a["k"] += 1
        return a

    def why(a):
        a["reason"] = "x"
        return a
    return [lambda a: a, tog, bump, pop, kk, why]


class _Panel:
    def __init__(self, verdicts):
        self._v = verdicts

    def verdicts(self, _input):
        return self._v


def _conformance(omega, map_opts, observations, outcome, ctx, verdicts, copts):
    l = _learner(omega, map_opts, observations)
    inp = RT.judge_input_of(l, outcome, ctx)
    att = RT.intent_conformance_attestation(inp, verdicts, copts, _verify)
    tampered = [RT.verify_ic_att(f(copy.deepcopy(att)), inp, verdicts, copts, _verify) for f in _mutations()]
    tampered.append(RT.verify_ic_att(att, inp, verdicts[1:], copts, _verify))
    return {"input": inp, "att": att, "digest": RT.ic_att_digest(att), "verify": RT.verify_ic_att(att, inp, verdicts, copts, _verify), "tampered": tampered,
            "check": RT.check_intent_conformance(_Panel(verdicts), inp, copts, _verify)}


def _jit(omega, map_opts, observations, outcome, decision, ctx):
    l = _learner(omega, map_opts, observations)
    req = RT.jit_consent_request(l, outcome, {"intentRef": ctx["intentRef"], "mapDigest": ctx["mapDigest"]})
    return {"req": req, "digest": RT.jit_consent_digest(req), "result": RT.record_jit_decision(l, req, decision), "metrics": l.metrics(),
            "route": RT.route_action(l, outcome, {})}


HANDLERS = {
    "bondAmount": _bond(RT.bond_amount), "quantizeScore": ST.quantize_score,
    "verifyJudgeVerdict": ST.verify_judge_verdict,
    "conformalThreshold": lambda c: _inf(ST.conformal_threshold(c)),
    "empiricalFalseAllowRate": ST.empirical_false_allow_rate, "verifySemanticThreshold": _threshold,
    "routeScenario": _route, "routeVetoScenario": _route_veto, "conformanceScenario": _conformance, "jitScenario": _jit,
}
TOTALS = {"bondAmount": 270, "quantizeScore": 15, "verifyJudgeVerdict": 74, "conformalThreshold": 18, "empiricalFalseAllowRate": 36, "verifySemanticThreshold": 345,
          "routeScenario": 49, "routeVetoScenario": 1, "conformanceScenario": 28, "jitScenario": 13}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 849 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_intent_routing_replay(fn):
    assert run(CASES[fn], HANDLERS[fn]) == (TOTALS[fn], 0)


def test_the_settlement_module_sizes_bonds_the_same_way():
    assert run(CASES["bondAmount"], _bond(BS.bond_amount)) == (270, 0)
