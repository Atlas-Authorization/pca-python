"""Differential replay of cut refinement, partial answers and adaptive elicitation against vectors generated from the TypeScript
reference (@atlasauth/pca-intent). Every number is compared exactly (the learner it drives uses
the deterministic math of atlas_pca.detmath, not libm)."""
import math

from atlas_pca import intent_mapkit as M, intent_omega as O, intent_policy as P, intent_refine as R
from base_oracle import canon, load_ref, norm, run

COUNT, CASES = load_ref("intent-refine")


def _close(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_close(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_close(x, y) for x, y in zip(a, b))
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if isinstance(a, int) and isinstance(b, int):
            return a == b
        return math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-15)
    return canon(a) == canon(b)


def cmp(got, out, case=None):
    return canon(norm(got)) == canon(out)


def mk(omega, mo, obs):
    l = M.create_learner(omega, mo)
    for x in obs:
        l.observe({"verb": x["verb"], "values": x["values"]}, x["y"], x["source"], x.get("region"))
    return l


def cells_of(l):
    return [{"verb": c["verb"], "cell": c["cell"], "p": c["p"]} for c in l.cells()]


def regions_of(omega, mo, obs, empty):
    l = mk(omega, mo, obs)
    return [R.region_of_observation({**omega, "verbs": []} if empty else l.omega, x) for x in l.observations]


def refine_scenario(omega, mo, obs, rr):
    l = mk(omega, mo, obs)
    nl = R.refine_learner(l, rr)
    return {"omega": nl.omega, "observations": nl.observations, "metrics": nl.metrics(), "cells": cells_of(nl)}


def partial_scenario(omega, mo, obs, q, pa):
    l = mk(omega, mo, obs)
    svs = next((v for v in omega["verbs"] if v["verb"] == q["verb"]), None)
    if svs is None:
        oc, p = {"verb": q["verb"], "values": {}}, 0.5
    else:
        oc = O.cell_rep(svs, q["cell"])
        p = l.acceptance(oc)
    r = R.answer_partial(l, {"verb": q["verb"], "cell": q["cell"], "outcome": oc, "p": p, "score": 0}, pa)
    return {"omega": r["learner"].omega, "added": r["added"], "observations": r["learner"].observations, "metrics": r["learner"].metrics(),
            "synth": r["learner"].synthesize()}


def adaptive_scenario(omega, mo, policy, ps, ev, oo):
    k, pi = [0], [0]
    adm = P.admitter(policy)

    def ans(q, l):
        k[0] += 1
        if k[0] % ev == 0 and pi[0] < len(ps) and q["verb"] == "stripe.refund":
            x = ps[pi[0]]
            pi[0] += 1
            return x
        vs = next(v for v in l.omega["verbs"] if v["verb"] == q["verb"])
        return 1 if adm.admits(vs, q["outcome"]) else 0
    r = R.elicit_adaptive(M.create_learner(omega, mo), ans, {"epsRisk": 0.001, "epsBurden": 0.01, "maxQuestions": 25, **oo})
    return {"stop": r["stop"], "questions": r["questions"], "auditQuestions": r["auditQuestions"], "seedQuestions": r["seedQuestions"],
            "refinements": r["refinements"], "asked": [{k2: q[k2] for k2 in ("verb", "cell", "outcome", "p", "score")} for q in r["asked"]],
            "omega": r["learner"].omega, "metrics": r["learner"].metrics(), "observations": r["learner"].observations}


MAP = {
    "refineOmega": R.refine_omega,
    "regionsOf": regions_of,
    "refineScenario": refine_scenario,
    "partialScenario": partial_scenario,
    "adaptiveScenario": adaptive_scenario,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn], compare=cmp)
