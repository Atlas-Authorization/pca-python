"""Differential replay of multi-principal aggregation over Intent Maps (rules, joint grant, recompute verification, lifting onto a
common refinement, cross-organisation aggregation) against vectors generated from the TypeScript reference (@atlasauth/pca-intent).
Doubles from transcendental functions are compared to 1e-12 relative; ppm integers, strings and structure exactly. A verification
problem's language-specific text ("replay failed: ...", a recompute error that is not a reference message) is compared by its prefix."""
import copy
import math
import re

from atlas_pca import intent_mapkit as M, intent_multi_agg as A
from base_oracle import canon, load_ref, norm, run

COUNT, CASES = load_ref("intent-multi-agg")
_REF_PREFIX = re.compile(r"^(aggregateIntentMaps|ruleOf|liftIntentMap|crossOrgAggregate|commonRefinement|pca-intent|refineOmega)")


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


def norm_problem(p):
    q = re.sub(r"replay failed: [^;]*", "replay failed", p)
    m = re.match(r"recompute failed: (.*)\Z", q, re.S)
    if m and not _REF_PREFIX.match(m.group(1)):
        return "recompute failed: error"
    if not m and not re.match(r"(input |aggregate does not|recompute failed)", q) and not q.startswith("replay failed"):
        return q if _REF_PREFIX.match(q) else "error"
    return q


def nrm(r):
    return {"ok": r["ok"], "problems": [norm_problem(p) for p in r["problems"]]}


def build_map(omega, map_opts, observations, ref):
    l = M.create_learner(omega, map_opts)
    for x in observations:
        l.observe({"verb": x["verb"], "values": x["values"]}, x["y"], x["source"], x.get("region"))
    return M.emit_intent_map(l, ref)


def _set(f):
    def mut(m):
        f(m)
        return m
    return mut


MUTS = [
    lambda m: m,
    _set(lambda m: m["metrics"].__setitem__("residual_risk_ppm", m["metrics"]["residual_risk_ppm"] + 7)),
    _set(lambda m: m["cells"][0].__setitem__("in_grant", not m["cells"][0]["in_grant"])),
    _set(lambda m: m.__setitem__("aggregation", None)),
    _set(lambda m: m["aggregation"].update({"rule": "quorum", "k": 1})),
    _set(lambda m: m["aggregation"].__setitem__("vetoers", [])),
]


def aggregate_scenario(omega, principals, rule, orgs, map_opts):
    # the reference passes the orgs object as the options argument, so no org label is ever applied
    opts = orgs if orgs is not None else {}
    maps = [build_map(omega, map_opts, p["observations"], p["ref"]) for p in principals]
    agg = A.aggregate_intent_maps(maps, rule, opts)
    tampered = [nrm(A.verify_aggregate(f(copy.deepcopy(agg)), maps, opts)) for f in MUTS]
    return {"aggregate": agg, "digest": M.intent_map_digest(agg), "rule": A.rule_of(agg), "verify": nrm(A.verify_aggregate(agg, maps, opts)),
            "tampered": tampered, "wrongInputs": nrm(A.verify_aggregate(agg, maps[:-1], opts)),
            "combined": A.combine_intent_maps(maps, opts) if rule["kind"] == "unanimity" and "vetoers" not in rule else None}


def aggregate_two_omegas(o1, o2, ps, rule):
    return A.aggregate_intent_maps([build_map(o1, {}, ps[0]["observations"], ps[0]["ref"]), build_map(o2, {}, [], ps[1]["ref"])], rule)


def aggregate_of_aggregate(omega, ps, rule):
    maps = [build_map(omega, {}, p["observations"], p["ref"]) for p in ps]
    agg = A.aggregate_intent_maps(maps, rule)
    return A.aggregate_intent_maps([agg, maps[0]], rule)


def lift_of_aggregate(omega, ps, rule):
    maps = [build_map(omega, {}, p["observations"], p["ref"]) for p in ps]
    return A.lift_intent_map(A.aggregate_intent_maps(maps[:1], rule), omega)


_NONE = object()


def cross_scenario(specs, rule, orgs=_NONE):
    if orgs is _NONE:  # the variant that corrupts the first map's metrics, which crossOrgAggregate must refuse
        maps = [build_map(s["omega"], {}, s["observations"], s["ref"]) for s in specs]
        maps[0]["metrics"]["residual_risk_ppm"] += 9
        return A.cross_org_aggregate(maps, rule)
    opts = orgs if orgs is not None else {}
    maps = [build_map(s["omega"], s.get("mapOpts") or {}, s["observations"], s["ref"]) for s in specs]
    r = A.cross_org_aggregate(maps, rule, opts)
    tampered = [nrm(A.verify_cross_org_aggregate(f(copy.deepcopy(r["aggregate"])), maps, opts)) for f in MUTS]
    return {"aggregate": r["aggregate"], "lifted": r["lifted"], "omega": r["omega"], "digest": M.intent_map_digest(r["aggregate"]),
            "verify": nrm(A.verify_cross_org_aggregate(r["aggregate"], maps, opts)), "tampered": tampered,
            "wrong": nrm(A.verify_cross_org_aggregate(r["aggregate"], maps[1:], opts))}


def lift_scenario(omega, mo, obs, ref, target):
    return A.lift_intent_map(build_map(omega, mo, obs, ref), target)


MAP = {
    "aggregateScenario": aggregate_scenario,
    "aggregateTwoOmegas": aggregate_two_omegas,
    "aggregateOfAggregate": aggregate_of_aggregate,
    "liftOfAggregate": lift_of_aggregate,
    "crossScenario": cross_scenario,
    "liftScenario": lift_scenario,
    "omegaKey": A.omega_key,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn], compare=cmp)
