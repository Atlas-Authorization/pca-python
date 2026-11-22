"""Differential replay of the policy analyzer (atlas_pca.analyzer) against vectors generated from the TypeScript reference
(@atlasauth/pca-analyzer): caveat / interval / probe engines, the bounded decision engine, reachability and relations, exposure,
residuals and filters, narrowing, coverage, minimal-flip counterfactuals, schema validation and the policy test runner.

Keys are labels: the Ed25519 seed of a label is sha256("atlas-pca-conformance/" + label), and "$key:LABEL" stands for its public key."""
import hashlib

import pytest

from atlas_pca import analyzer as A
from atlas_pca import ed25519
from atlas_pca.pca import b64u
from base_oracle import load_ref, run

COUNT, CASES = load_ref("analyzer")


def _seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()


def _pub(label):
    return b64u(ed25519.public_key(_seed(label)))


def _keyed(v):
    return _pub(v[5:]) if isinstance(v, str) and v.startswith("$key:") else v


def _revive(v):
    """{"$num": "Infinity"} back to the number."""
    if isinstance(v, list):
        return [_revive(x) for x in v]
    if isinstance(v, dict):
        if len(v) == 1 and isinstance(v.get("$num"), str):
            return float(v["$num"].replace("Infinity", "inf"))
        return {k: _revive(x) for k, x in v.items()}
    return v


def _probes_json(inp):
    p = A.collect_probes(inp)
    return dict(p, fields=[{"path": f["path"], "values": [{"$absent": True} if x is A.ABSENT else x for x in f["values"]]} for f in p["fields"]])


def _reps(inp):
    p = A.collect_probes(inp)
    if A.product_size(p) > 400:
        raise ValueError("grid too large for the corpus")
    out = []
    for r in A.representatives(p):
        o = {"verb": r["verb"], "resource": r["resource"], "assignments": dict(r["assignments"]), "action": A.rep_to_action(r)}
        if r["revClass"] is not None:
            o["revClass"] = r["revClass"]
        out.append(o)
    return out


def _veto_applies(veto, x):
    a = dict(x)
    if x.get("params") is None:
        a["params"] = {}
    return A.veto_applies(veto, {"action": a, "subject": x.get("subject") if x.get("subject") is not None else {},
                                 "env": x.get("env") if x.get("env") is not None else {}})


def _find(q, spec):
    return A.find_with_backend({"name": spec["name"], "find": lambda _q: spec["result"]}, q)


FULL = A.FULL_INTERVAL

MAP = {
    "analyzeCaveats": A.analyze_caveats,
    "numericConjunctionSatisfiable": A.numeric_conjunction_satisfiable,
    "predicateNumericSatisfiable": A.predicate_numeric_satisfiable,
    "tightenInterval": lambda iv, op, v: A.tighten_interval(FULL if iv is None else iv, op, v),
    "intervalEmpty": lambda iv: A.interval_empty(FULL if iv is None else iv),
    "fieldProbes": A.field_probes,
    "vetoesFromConstitution": A.vetoes_from_constitution,
    "toModel": A.to_model,
    "collectProbes": _probes_json,
    "representatives": _reps,
    "decideAction": lambda p, a: A.decide_action(A.to_model(p), a),
    "witnessOf": lambda p, a: A.witness_of(A.to_model(p), a),
    "admitsConcrete": A.admits_concrete,
    "vetoApplies": _veto_applies,
    "reachable": lambda p, a, o=None: A.reachable(p, a, o),
    "alwaysDenies": lambda p, v=None, o=None: A.always_denies(p, v, o),
    "alwaysAllows": lambda p, v, o=None: A.always_allows(p, v, o),
    "subsumes": lambda a, b, o=None: A.subsumes(a, b, o),
    "disjoint": lambda a, b, o=None: A.disjoint(a, b, o),
    "equivalent": lambda a, b, o=None: A.equivalent(a, b, o),
    "intentConformance": lambda p, i, o=None: A.intent_conformance(p, i, o),
    "thresholdsOf": lambda p, path: A.thresholds_of(A.to_model(p), path),
    "maxExposure": A.max_exposure,
    "escalationSurface": lambda p, o=None: A.escalation_surface(p, o),
    "delegationEnvelope": lambda c, o=None: A.delegation_envelope(c, o),
    "diffPolicies": lambda a, b, o=None: A.diff_policies(a, b, o),
    "diffGate": lambda d, al=None: A.diff_gate(_revive(d), al),
    "findWithBackend": _find,
    "dagExposure": A.dag_exposure,
    "residual": lambda p, k, o=None: A.residual(p, k, o),
    "residualPolicy": A.residual_policy,
    "evaluateResidual": A.evaluate_residual,
    "whatMayIDo": lambda p, v, k=None, o=None: A.what_may_i_do(p, v, k, o),
    "toFilter": lambda p, k, ro, f: A.to_filter(A.residual(p, k, ro), f),
    "toUcast": A.to_ucast,
    "evalFilter": A.eval_filter,
    "evalUcast": A.eval_ucast,
    "suggestNarrowing": lambda p, ob, o=None: A.suggest_narrowing(p, ob, o),
    "signAccessRequest": lambda r, label: A.sign_access_request(r, _seed(label), _pub(label)),
    "verifyAccessRequest": lambda x, e=None: A.verify_access_request(x, None if e is None else _keyed(e)),
    "coverage": lambda p, t, o=None: A.coverage(p, t, o),
    "coverageGate": lambda r, m=None: A.coverage_gate(r, m),
    "minimalFlip": A.minimal_flip,
    "verbShapes": A.verb_shapes,
    "verbShapesFromActionDefs": A.verb_shapes_from_action_defs,
    "validatePolicyAgainstSchema": lambda p, s, o=None: A.validate_policy_against_schema(p, s, o),
    "policyTestsDoc": A.policy_tests_doc,
    "runPolicyTests": lambda p, d, o=None: A.run_policy_tests(p, d, o),
    "generateBoundaryTests": lambda p, o=None: A.generate_boundary_tests(p, o),
    "decideAll": A.decide_all,
    "signPolicyTests": lambda d, label: A.sign_policy_tests(d, _seed(label), _pub(label)),
    "verifyPolicyTests": lambda s, e: A.verify_policy_tests(s, _keyed(e)),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 6309 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(set(MAP) - {"vetoApplies"}))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_veto_applies_matches_the_reference():
    cases = CASES["vetoApplies"]
    run([c for c in cases if c["name"] != "unless-object"], _veto_applies)
    # the one case that hands the action over as is: `unless` is not an array, so the reference throws
    run([c for c in cases if c["name"] == "unless-object"], lambda veto, x: A.veto_applies(veto, {"action": x, "subject": {}, "env": {}}))
