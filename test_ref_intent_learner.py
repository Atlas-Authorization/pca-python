"""Differential replay of the intent learner (posterior over box / union / decision-list hypothesis classes, questions, audit round,
synthesis into predicates) against vectors generated from the TypeScript reference (@atlasauth/pca-intent). Doubles from
transcendental functions are compared to 1e-12 relative; counts, ppm-like integers, strings and structure exactly."""
import math

from atlas_pca import intent_learner as L, intent_policy as P
from base_oracle import canon, load_ref, norm, run

COUNT, CASES = load_ref("intent-learner")


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
    return _close(norm(got), out)


def mk_opts(opts):
    x = dict(opts)
    if x.get("nullMassFn") == "byRev":
        x["nullMass"] = lambda vs: 0.1 if vs["reversibility"] == "reversible" else 0.3
        del x["nullMassFn"]
    if x.get("priorMix"):
        kind = x["priorMix"]["weight"]
        if kind == "size":
            wt = lambda _vs, has: 1 + sum(1 for c in range(64) if has(c))  # noqa: E731
        elif kind == "neg":
            wt = lambda _vs, _has: -1  # noqa: E731
        else:
            wt = lambda _vs, _has: 0  # noqa: E731
        x["priorMix"] = {"beta": x["priorMix"]["beta"], "weight": wt}
    return x


def jq(q):
    return None if q is None else {k: q[k] for k in ("verb", "cell", "outcome", "p", "score")}


def scenario(omega, opts, ops):
    lopts = mk_opts(opts)
    l = L.IntentLearner(omega, lopts)
    out = []
    for op in ops:
        k = op["op"]
        if k == "observe":
            out.append(l.observe({"verb": op["verb"], "values": op["values"]}, op["y"], op.get("source") or "elicitation", op.get("region")))
        elif k == "probe":
            oc = {"verb": op["verb"], "values": op["values"]}
            out.append([l.acceptance(oc), l.admits_outcome(oc), l.is_vetoed(oc)])
        elif k == "next":
            out.append(jq(l.next_question()))
        elif k == "metrics":
            out.append(l.metrics())
        elif k == "cells":
            out.append(l.cells())
        elif k == "unconfirmed":
            out.append(l.unconfirmed_grant_cells())
        elif k == "synth":
            out.append(l.synthesize())
        elif k == "vetoed":
            out.append(l.vetoed_cells())
        elif k == "observations":
            out.append(l.observations)
        elif k == "replay":
            out.append(L.IntentLearner.replay(omega, lopts, l.observations).metrics())
        elif k == "elicit":
            adm = P.admitter(op["policy"])
            count = [0]

            def ans(q, adm=adm, op=op, count=count):
                vs = next(v for v in omega["verbs"] if v["verb"] == q["verb"])
                y = 1 if adm.admits(vs, q["outcome"]) else 0
                count[0] += 1
                return 1 - y if op.get("flipEvery") and count[0] % op["flipEvery"] == 0 else y
            r = L.elicit(l, ans, {"epsRisk": op["epsRisk"], "epsBurden": op["epsBurden"], "maxQuestions": op["maxQuestions"], "audit": op.get("audit"), "seed": op.get("seed")})
            out.append({"stop": r["stop"], "questions": r["questions"], "auditQuestions": r["auditQuestions"], "seedQuestions": r["seedQuestions"],
                        "asked": [jq(q) for q in r["asked"]], "metrics": l.metrics()})
        else:
            raise ValueError("bad op")
    return out


def hypothesis_cell_sets(vs, hc, caps=None, *rest):
    r = L.hypothesis_cell_sets(vs, hc, caps)
    if caps is not None or hc is None:
        return len(r["sets"])
    return {"sets": [list(s) for s in r["sets"]], "complexity": r["complexity"]}


MAP = {
    "scenario": scenario,
    "hypothesisCellSets": hypothesis_cell_sets,
    "hypothesisClassName": L.hypothesis_class_name,
    "boxesToPredicates": lambda vs, allowed: L.boxes_to_predicates(vs, bytes(allowed)),
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn], compare=cmp)
