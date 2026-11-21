"""Differential replay of the Intent Map (emit, digest, replay verification, tamper detection, learner options, the committed form
and runtime divergence) against vectors generated from the TypeScript reference (@atlasauth/pca-intent). Doubles from transcendental
functions are compared to 1e-12 relative; ppm integers, strings and structure exactly. A "replay failed: <text>" problem is compared
as "replay failed" (the text is the language's own)."""
import copy
import math

from atlas_pca import intent_map_commit as MC, intent_mapkit as M, intent_omega as O
from base_oracle import canon, load_ref, norm, run

COUNT, CASES = load_ref("intent-map")


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


def sec(seed):
    return bytes((seed + 7 * i) & 255 for i in range(32))


def norm_problems(r):
    return {"ok": r["ok"], "problems": ["replay failed" if p.startswith("replay failed") else p for p in r["problems"]]}


def _set(f):
    def mut(m):
        f(m)
        return m
    return mut


def _pop(lst):
    if lst:
        lst.pop()


MUTS = [
    lambda m: m,
    _set(lambda m: m["metrics"].__setitem__("residual_risk_ppm", m["metrics"]["residual_risk_ppm"] + 5)),
    _set(lambda m: m["cells"][0].__setitem__("p_ppm", m["cells"][0]["p_ppm"] + 3)),
    _set(lambda m: m["cells"][0].__setitem__("in_grant", not m["cells"][0]["in_grant"])),
    _set(lambda m: m.__setitem__("grant_digest", "AAAA")),
    _set(lambda m: _pop(m["observations"])),
    _set(lambda m: m.__setitem__("kind", "x")),
    _set(lambda m: m.__setitem__("principals", ["a", "b"])),
    _set(lambda m: m.__setitem__("aggregation", {"rule": "unanimity"})),
    _set(lambda m: m["metrics"].pop("log2_vs_mbits", None)),
    _set(lambda m: m["learner"].__setitem__("eta_ppm", m["learner"]["eta_ppm"] + 100000)),
    _set(lambda m: m["metrics"].__setitem__("questions", m["metrics"]["questions"] + 1)),
    _set(lambda m: _pop(m["cells"])),
    _set(lambda m: m["omega"]["verbs"][0].__setitem__("w", 5)),
    _set(lambda m: m["metrics"].__setitem__("log2_vs_mbits", None)),
    _set(lambda m: m["cells"][0].__setitem__("p_ppm", m["cells"][0]["p_ppm"] + 2)),
    _set(lambda m: m["cells"][0].__setitem__("p_ppm", m["cells"][0]["p_ppm"] + 1)),
]


def disclosures(omega, cm):
    out = []
    for vs in omega["verbs"]:
        t = O.verb_cell_count(vs)
        for f in (0, t // 2, t - 1):
            oc = O.cell_rep(vs, O.decode_cell(vs, f))
            params, resource = {}, None
            for k, v in oc["values"].items():
                if k == "action.resource":
                    resource = v
                else:
                    params[k[len("action.params."):]] = v
            out.append(cm["disclose"](vs["verb"], resource, params))
    return out


def map_scenario(omega, map_opts, observations, intent_ref, secret_seed):
    l = M.create_learner(omega, map_opts)
    for x in observations:
        l.observe({"verb": x["verb"], "values": x["values"]}, x["y"], x["source"], x.get("region"))
    m = M.emit_intent_map(l, intent_ref)
    tampered = [norm_problems(M.verify_intent_map(f(copy.deepcopy(m)))) for f in MUTS]
    tampered.append(norm_problems(M.verify_intent_map(None)))
    tampered.append(norm_problems(M.verify_intent_map({"v": 2})))
    try:
        cm = MC.commit_intent_map(m, sec(secret_seed))
        commit = {"map_commit": cm["map_commit"], "size": cm["size"], "leaves": cm["leaves"], "disclosures": disclosures(omega, cm)}
    except Exception:  # noqa: BLE001
        commit = {"error": True}
    return {"map": m, "digest": M.intent_map_digest(m), "grantDigest": M.grant_digest(m["grant"]), "verify": norm_problems(M.verify_intent_map(m)),
            "tampered": tampered, "options": M.map_learner_options(m), "omegaRoundtrip": M.omega_to_json(M.omega_from_json(m["omega"])), "commit": commit}


def commit_intent_map(m):
    cm = MC.commit_intent_map(m, sec(3))
    return {"map_commit": cm["map_commit"], "size": cm["size"], "leaves": cm["leaves"]}


def divergence(omega, mo, obs, ds):
    l = M.create_learner(omega, mo)
    for x in obs:
        l.observe({"verb": x["verb"], "values": x["values"]}, x["y"], x["source"])
    return [M.apply_divergence(l, d["outcome"], d["y"]) for d in ds]


MAP = {
    "mapScenario": map_scenario,
    "commitIntentMap": commit_intent_map,
    "grantDigest": M.grant_digest,
    "intentMapDigest": M.intent_map_digest,
    "omegaToJSON": M.omega_to_json,
    "omegaFromJSON": M.omega_from_json,
    "divergence": divergence,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn], compare=cmp)
