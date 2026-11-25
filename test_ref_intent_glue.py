"""Differential replay of the learner feedback glue against vectors generated from the TypeScript reference (@atlasauth/pca-intent):
outcome verification (a violated postcondition vetoes the cell), frame reports, org layers learned from maps, delta grants (the cells a
new answer adds, their predicates, the minted principal-signed delta grant) and just-in-time consent decisions. Doubles from
transcendental functions are compared to 1e-12 relative; ppm integers, signatures, strings and structure exactly."""
import math

from atlas_pca import (intent_effects as EF, intent_frames as FR, intent_jit as J, intent_layers_wallet as LW, intent_mapkit as M,
                       intent_runtime as RT)
from atlas_pca.agent import keypair_from_seed
from base_oracle import canon, load_ref, norm, run

GLUE = load_ref("intent-glue-py")[1]
JIT = load_ref("intent-jit")[1]
ROUTING = load_ref("intent-routing")[1]


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


def mk(omega, mo, obs):
    l = M.create_learner(omega, mo)
    for x in obs:
        l.observe({"verb": x["verb"], "values": x["values"]}, x["y"], x["source"], x.get("region"))
    return l


def tail(l):
    return {"vetoed": l.vetoed_cells(), "metrics": l.metrics(), "observations": l.observations}


def verify_scenario(omega, mo, obs, oc, effect, pcs=None):
    l = mk(omega, mo, obs)
    return l, EF.verify_outcome(l, oc, effect, pcs)


def verify_case(*args):
    if len(args) == 5:  # the variant that answers "yes" after the violation: the veto must hold
        omega, mo, obs, oc, effect = args
        l, r = verify_scenario(omega, mo, obs, oc, effect)
        l.observe(oc, 1, "elicitation")
        return {"r": r, **tail(l), "again": l.admits_outcome(oc)}
    l, r = verify_scenario(*args)
    return {"result": r, **tail(l)}


def frame_scenario(omega, mo, obs, oc, report):
    l = mk(omega, mo, obs)
    r = FR.apply_frame_report(l, oc, report)
    return {"result": r, **tail(l)}


def org_scenario(omega, principals, rule, mo):
    maps = [M.emit_intent_map(mk(omega, mo, p["observations"]), p["ref"]) for p in principals]
    return LW.org_layer_from_maps(maps, rule)


def delta_scenario(omega, mo, a, b):
    prev, nxt = mk(omega, mo, a), mk(omega, mo, a + b)
    d = J.delta_cells(prev, nxt)
    return {"cells": d, "predicates": J.delta_predicates(nxt.omega, d)}


def mint_scenario(omega, mo, a, b, args, princ_seed):
    prev, nxt = mk(omega, mo, a), mk(omega, mo, a + b)
    kw = {}
    if args.get("mapForm") is not None:
        kw["map_form"] = args["mapForm"]
    if "caveats" in args:
        kw["caveats"] = args["caveats"]
    r = J.mint_delta(prev, nxt, args["prevGrant"], keypair_from_seed(princ_seed, True), args["holder"], args["session"], args["seq"], args["root"],
                     args["mapDigest"], prev_id=args.get("prev"), salt=args.get("salt"), **kw)
    return None if r is None else {"grant": r["grant"], "goalSalt": r["goal_salt"], "cells": r["cells"]}


def jit_scenario(omega, mo, obs, oc, decision, ctx):
    l = mk(omega, mo, obs)
    req = RT.jit_consent_request(l, oc, {"intentRef": ctx["intentRef"], "mapDigest": ctx["mapDigest"]})
    return {"req": req, "digest": RT.jit_consent_digest(req), "result": RT.record_jit_decision(l, req, decision), "metrics": l.metrics(),
            "route": RT.route_action(l, oc, {})}


# the other functions of these corpora (visit decision, coordinates, signed notices, routing, bonds, judges) are not replayed from them here
JIT_OTHER = {"visitScenario", "cellFromCoords", "requiredScenario", "cellCoords", "walletScenario"}
ROUTING_OTHER = {"verifySemanticThreshold", "bondAmount", "verifyJudgeVerdict", "routeScenario", "empiricalFalseAllowRate", "conformanceScenario",
                 "conformalThreshold", "quantizeScore", "routeVetoScenario"}


def test_corpora_are_fully_covered():
    assert set(GLUE) == {"verifyScenario", "frameScenario", "orgScenario"}
    assert set(JIT) == {"deltaScenario", "mintScenario"} | JIT_OTHER
    assert set(ROUTING) == {"jitScenario"} | ROUTING_OTHER


def test_glue_matches_the_reference():
    run(GLUE["verifyScenario"], verify_case, compare=cmp)
    run(GLUE["frameScenario"], frame_scenario, compare=cmp)
    run(GLUE["orgScenario"], org_scenario, compare=cmp)


def test_delta_grants_match_the_reference():
    run(JIT["deltaScenario"], delta_scenario, compare=cmp)
    run(JIT["mintScenario"], mint_scenario, compare=cmp)


def test_jit_decisions_match_the_reference():
    run(ROUTING["jitScenario"], jit_scenario, compare=cmp)
