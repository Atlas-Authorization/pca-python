"""Differential replay of the wallet over an intent learner (the grant view of a learner with an optional ceiling, and the mass a
released population prior admits beyond the base prior) against vectors generated from the TypeScript reference (@atlasauth/pca-wallet).
Doubles from transcendental functions are compared to 1e-12 relative; integers, strings and structure exactly."""
import math

from atlas_pca import intent_mapkit as M, intent_omega as O, wallet_channel as CH, wallet_population as PO
from base_oracle import canon, load_ref, norm, run

COUNT, CASES = load_ref("wallet-learner-py")


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
        l.observe({"verb": x["verb"], "values": x["values"]}, x["y"], x["source"])
    return l


CEILINGS = {"all": lambda v, idx: True, "idx0": lambda v, idx: idx[0] == 0, "never": lambda v, idx: False}


def view_scenario(omega, mo, obs, ceiling, probes):
    view = CH.learner_view(mk(omega, mo, obs), {} if ceiling == "none" else {"insideCeiling": CEILINGS[ceiling]})
    return {"probes": [[view["p"](p["verb"], p["idx"]), view["vetoed"](p["verb"], p["idx"]), view["outsideCeiling"](p["verb"], p["idx"])] for p in probes],
            "confirmed": view["confirmed"]()}


def prior_scenario(omega, base, obs, beta, schema, q_of, hi=False):
    cells = {}
    for vs in omega["verbs"]:
        for c in range(O.verb_cell_count(vs)):
            q = 0.98 - 0.04 * (c % q_of) if hi else 0.05 + 0.04 * (c % q_of)
            cells[PO.population_cell_key(schema, vs, O.decode_cell(vs, c))] = {"q": min(0.98, max(0.02, q)), "n": 50}
    rel = {"v": 1, "kind": "pca-intent-population-prior", "schema": schema, "period": 1, "epsilon": 0.9, "delta": 1e-5, "sigma": 1, "sensitivity": 8, "cells": cells}
    return PO.prior_admitted_ppm(omega, base, obs, PO.population_prior(rel, beta))


MAP = {
    "viewScenario": view_scenario,
    "viewUnknownVerb": lambda omega, verb, idx: CH.learner_view(mk(omega, {}, []))["p"](verb, idx),
    "priorScenario": prior_scenario,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn], compare=cmp)
