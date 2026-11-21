"""Replays the TS-reference oracle of the objective risk functional (testdata/ref-objective-risk.json.gz, 4052 cases): canonical action, the
inverse registry and reversibility, the resource graph and blast radius, native and BYO embedders, goal commitment and distance, split-conformal
calibration, harm currency, the composition and the dispute-game oracle. Every fn has a handler and the totals are asserted; a reference
refusal needs a native exception. A reference reason that starts with "Cannot read properties" is a JavaScript engine message: only a non-empty
reason is required there."""
import math
import os

import pytest

from atlas_pca import objective_risk as O
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("objective-risk", os.path.join(HERE, "testdata", "ref-objective-risk.json.gz"))


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _registry(s):
    r = O.InMemoryInverseRegistry(s.get("trusted") or [])
    for verb, e in s.get("entries") or []:
        r.register(verb, e)
    return r


def _graph(s):
    g = O.ResourceGraph()
    for n in s.get("nodes") or []:
        g.add_node(n)
    for e in s.get("edges") or []:
        g.add_edge(e)
    return g


def _infer_of(i, dims_default):
    def infer(j):
        if i.get("throws"):
            raise RuntimeError("infer boom")
        if i.get("notArray"):
            return "x"
        if i.get("byLen"):
            n = len(j.encode("utf-16-be", "surrogatepass")) // 2  # a JavaScript string length
            return [n + k for k in range(i.get("dims", dims_default))]
        return i.get("vector")
    return infer


def _byo(d, claimed, infer):
    return O.byo_embedder(d, _infer_of(dict(infer, dims=d.get("dims")) if infer.get("byLen") else infer, 4), claimed)


def _embedder(s):
    if s["scheme"] == "native":
        return O.native_hash_embedder(s["config"])
    if s["scheme"] == "fixed":
        return O.Embedder(s["modelId"], s["config"], s["dims"], lambda a: s["vector"])
    return _byo(s["descriptor"], s.get("claimedModelId"), s["infer"])


def _ctx(c):
    ctx = {"registry": _registry(c["registry"]), "authorizedKinds": set(c["authorizedKinds"]), "graph": _graph(c["graph"]),
           "embedder": _embedder(c["embedder"]), "goal": c["goal"], "commitments": c["commitments"], "denominations": c["denominations"],
           "weights": c["weights"], "taint": c.get("taint"), "age": c.get("age")}
    for k in ("scope", "attestedUncertainty", "calibration"):
        if c.get(k) is not None:
            ctx[k] = c[k]
    return ctx


def _registry_ops(trusted, ops):
    r, out = O.InMemoryInverseRegistry(trusted), []
    for op, *a in ops:
        if op == "register":
            r.register(a[0], a[1])
            out.append(None)
        elif op == "lookup":
            out.append(r.lookup(a[0]))
        elif op == "trustedVerifiers":
            out.append(r.trusted_verifiers())
        else:
            out.append(r.digest())
    return out


def _native_embed(cfg, a):
    e = O.native_hash_embedder(cfg)
    return {"modelId": e.model_id, "dims": e.dims, "config": e.config, "vector": e.embed(a)}


def _byo_embed(d, claimed, infer, a):
    e = _byo(d, claimed, infer)
    return {"modelId": e.model_id, "dims": e.dims, "vector": e.embed(a)}


def _graph_build(s):
    g = _graph(s)
    return {"size": g.size, "digest": g.digest()}


HANDLERS = {
    "constants": lambda: {"METRIC": O.METRIC, "DEFAULT_EPSILON": O.DEFAULT_EPSILON, "NATIVE_SCHEME": O.NATIVE_SCHEME,
                          "DEFAULT_MAX_PARAM_LEAVES": O.DEFAULT_MAX_PARAM_LEAVES, "DEFAULT_NATIVE_CONFIG": O.DEFAULT_NATIVE_CONFIG},
    "canonicalAction": O.canonical_action, "canonicalActionJson": O.canonical_action_json, "canonicalActionDigest": O.canonical_action_digest,
    "registryOps": _registry_ops, "registryDigest": lambda s: _registry(s).digest(),
    "reversibility": lambda a, s, kinds: O.reversibility(a, _registry(s), set(kinds)),
    "graphBuild": _graph_build, "graphReachable": lambda s, start, scope: _graph(s).reachable(start, scope),
    "graphNode": lambda s, i: _graph(s).node(i), "blastRadius": lambda a, s, scope: O.blast_radius(a, _graph(s), scope),
    "nativeEmbed": _native_embed, "byoModelId": O.byo_model_id, "byoEmbed": _byo_embed, "validateVector": O.validate_vector,
    "conformanceCheck": lambda es, cases: O.conformance_check(_embedder(es), cases),
    "commitGoal": lambda es, a, eps: O.commit_goal(_embedder(es), a, eps),
    "verifyGoalCommitment": lambda g, es: O.verify_goal_commitment(g, _embedder(es)),
    "vectorDistance": O.vector_distance,
    "committedDistanceChecked": lambda c, g, es: O.committed_distance_checked(c, g, _embedder(es)),
    "committedDistance": lambda a, g, es: O.committed_distance(a, g, _embedder(es)),
    "calibrate": O.calibrate, "conformalThreshold": O.conformal_threshold, "calibrationDigest": O.calibration_digest,
    "harmReport": O.harm_report, "objectiveRisk": lambda a, c: O.objective_risk(a, _ctx(c)),
    "objectiveRiskOracle": lambda c, i, snap: O.objective_risk_oracle(_ctx(c)).resolve(i, snap),
}
TOTALS = {"graphReachable": 1190, "blastRadius": 1190, "reversibility": 224, "objectiveRisk": 178, "vectorDistance": 168, "calibrate": 154,
          "conformalThreshold": 121, "harmReport": 108, "objectiveRiskOracle": 104, "graphNode": 102, "nativeEmbed": 98, "verifyGoalCommitment": 88,
          "committedDistanceChecked": 40, "committedDistance": 40, "canonicalAction": 39, "byoEmbed": 39, "commitGoal": 36, "canonicalActionJson": 23,
          "canonicalActionDigest": 23, "byoModelId": 18, "graphBuild": 17, "validateVector": 17, "calibrationDigest": 13, "conformanceCheck": 10,
          "registryDigest": 8, "registryOps": 3, "constants": 1}
ENGINE = "Cannot read properties"


def _same(got, out, _case):
    if isinstance(out, str) and out.startswith(ENGINE):
        return isinstance(got, str) and got != ""
    if isinstance(out, dict) and isinstance(got, dict):
        return set(out) == set(got) and all(_same(got[k], out[k], None) for k in out)
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 4052 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 407


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_objective_risk_replay(fn):
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same) == (TOTALS[fn], 0)
