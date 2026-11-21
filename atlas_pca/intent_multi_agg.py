"""Multi-principal aggregation over Intent Maps: the joint grant under a unanimity / quorum / weighted rule (every number
recomputable from the inputs), lifting a map onto a common refinement, and cross-organisation aggregation. Native port of the
TypeScript reference (@atlasauth/pca-intent, multi.ts; the rule and refinement primitives are in `intent_multi`)."""
from __future__ import annotations

from ._fin import fin
import json
import math
from typing import Any, Dict, List, Optional

from .intent_learner import boxes_to_predicates
from .intent_mapkit import (
    PPM, create_learner, emit_intent_map, grant_digest, intent_map_digest, map_learner_options, omega_from_json, omega_to_json, ppm,
    verify_intent_map,
)
from .intent_multi import common_refinement, joint_acceptance, normalize_rule, rule_admits
from .intent_omega import DEFAULT_HARM, cell_of, cell_stats, decode_cell, rep_value, verb_cell_count
from .intent_region import region_of_cell

_ORDER = ["reversible", "rate_limited", "irreversible"]


def _stringify(x: Any) -> str:
    """JSON.stringify of a JSON value (key order kept; an integral double prints as an integer)."""
    def fix(v: Any) -> Any:
        if isinstance(v, float) and fin(v) and v == math.floor(v) and abs(v) < 1e21:
            return int(v)
        if isinstance(v, dict):
            return {k: fix(e) for k, e in v.items()}
        if isinstance(v, list):
            return [fix(e) for e in v]
        return v
    return json.dumps(fix(x), separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def aggregate_intent_maps(maps: List[dict], rule: dict, opts: Optional[dict] = None) -> dict:
    """Aggregate single-principal maps over a SHARED omega under a rule; the result has `aggregation` set."""
    orgs = (opts or {}).get("orgs")
    if len(maps) == 0:
        raise ValueError("aggregateIntentMaps: no maps")
    om = _stringify(maps[0]["omega"])
    if any(_stringify(m["omega"]) != om for m in maps):
        raise ValueError("aggregateIntentMaps: maps must share Ω (lift them with crossOrgAggregate)")
    if any(m.get("aggregation") is not None or len(m["principals"]) != 1 or not isinstance(m.get("intent_ref"), str) for m in maps):
        raise ValueError("aggregateIntentMaps: every input must be a single-principal map with an intent_ref")
    refs = [m["intent_ref"] for m in maps]
    if len(set(refs)) != len(refs):
        raise ValueError("aggregateIntentMaps: duplicate principal")
    n = normalize_rule(rule, refs)
    omega = omega_from_json(maps[0]["omega"])
    stats: List[dict] = []
    for vs in omega["verbs"]:
        for c in range(verb_cell_count(vs)):
            stats.append(cell_stats(vs, decode_cell(vs, c), DEFAULT_HARM))
    cells = []
    for i, c in enumerate(maps[0]["cells"]):
        cells.append({
            "verb": c["verb"], "cell": c["cell"],
            "p_ppm": ppm(joint_acceptance(n, [m["cells"][i]["p_ppm"] / PPM for m in maps])),
            "in_grant": rule_admits(n, [m["cells"][i]["in_grant"] for m in maps]),
        })
    predicates: List[dict] = []
    worst = -1
    off = 0
    for vs in omega["verbs"]:
        nc = verb_cell_count(vs)
        allowed = bytearray(nc)
        any_ = False
        for c in range(nc):
            if cells[off + c]["in_grant"]:
                allowed[c] = 1
                any_ = True
        off += nc
        if not any_:
            continue
        worst = max(worst, _ORDER.index(vs["reversibility"]) if vs["reversibility"] in _ORDER else -1)
        predicates.extend(boxes_to_predicates(vs, allowed))
    grant = {"predicates": predicates, "caveats": [{"type": "reversibility_max", "class": _ORDER[worst]}] if worst >= 0 else []}
    # each principal's own posterior estimate of the JOINT grant
    per = []
    for i, m in enumerate(maps):
        R = B = Rmax = 0.0
        for j, c in enumerate(m["cells"]):
            p = c["p_ppm"] / PPM
            mass, harm = stats[j]["mass"], stats[j]["harm"]
            Rmax += mass * (1 - p) * harm
            if cells[j]["in_grant"]:
                R += mass * (1 - p) * harm
            else:
                B += mass * p
        e: Dict[str, Any] = {"intent_ref": refs[i]}
        if orgs and orgs.get(refs[i]):
            e["org"] = orgs[refs[i]]
        e["R"], e["B"], e["F"] = R, B, (1 - R / Rmax if Rmax > 0 else 1)
        per.append(e)

    def worst_metric(k: str, f: Any) -> Any:
        return f([(m["metrics"].get(k) if m["metrics"].get(k) is not None else 0) for m in maps])

    kind = rule["kind"]
    aggregation: Dict[str, Any] = {"rule": kind}
    if kind == "quorum":
        aggregation["k"] = rule["k"]
    if kind == "weighted":
        aggregation["weights"] = {r: n["weights"][i] for i, r in enumerate(refs)}
        aggregation["threshold"] = rule["threshold"]
    aggregation["vetoers"] = [r for i, r in enumerate(refs) if n["veto"][i]]
    aggregation["per_principal"] = []
    for x in per:
        pp: Dict[str, Any] = {"intent_ref": x["intent_ref"]}
        if x.get("org"):
            pp["org"] = x["org"]
        pp["residual_risk_ppm"] = ppm(x["R"])
        pp["burden_ppm"] = ppm(x["B"])
        aggregation["per_principal"].append(pp)
    return {
        "v": 1,
        "kind": "pca-intent-map",
        "intent_ref": None,
        "principals": refs,
        "omega": maps[0]["omega"],
        "learner": maps[0]["learner"],
        "observations": [o for m in maps for o in m["observations"]],
        "cells": cells,
        "grant": grant,
        "grant_digest": grant_digest(grant),
        "metrics": {
            # every principal's own posterior estimate of the joint grant; the map reports the worst of them
            "residual_risk_ppm": max(x["residual_risk_ppm"] for x in aggregation["per_principal"]),
            "burden_ppm": max(x["burden_ppm"] for x in aggregation["per_principal"]),
            "uncertainty_ppm": worst_metric("uncertainty_ppm", max),
            "disagreement_ppm": worst_metric("disagreement_ppm", max),
            "mean_harm_ppm": maps[0]["metrics"]["mean_harm_ppm"],
            "fidelity_est_ppm": ppm(min(x["F"] for x in per)),
            "entropy_mbits": worst_metric("entropy_mbits", sum),
            "log2_vs_mbits": None if any(m["metrics"].get("log2_vs_mbits") is None for m in maps) else worst_metric("log2_vs_mbits", sum),
            "questions": worst_metric("questions", sum),
            "conflicts": worst_metric("conflicts", sum),
        },
        "aggregation": aggregation,
    }


def combine_intent_maps(maps: List[dict], opts: Optional[dict] = None) -> dict:
    """The unanimity rule: the joint grant is the intersection of the principals' conservative grants."""
    return aggregate_intent_maps(maps, {"kind": "unanimity"}, opts)


def rule_of(agg: dict) -> dict:
    """The rule an aggregated map records."""
    a = agg.get("aggregation")
    if not a:
        raise ValueError("ruleOf: not an aggregated map")
    if a["rule"] == "unanimity":
        return {"kind": "unanimity", "vetoers": a["vetoers"]}
    if a["rule"] == "quorum":
        return {"kind": "quorum", "k": a.get("k"), "vetoers": a["vetoers"]}
    return {"kind": "weighted", "weights": a.get("weights"), "threshold": a.get("threshold"), "vetoers": a["vetoers"]}


def verify_aggregate(agg: dict, inputs: List[dict], opts: Optional[dict] = None) -> Dict[str, Any]:
    """Replay-verify every input map, then recompute the aggregate and compare digests (inputs share the omega)."""
    problems: List[str] = []
    try:
        for i, m in enumerate(inputs):
            r = verify_intent_map(m)
            if not r["ok"]:
                problems.append("input %d: %s" % (i, "; ".join(r["problems"])))
        if problems:
            return {"ok": False, "problems": problems}
        again = aggregate_intent_maps(inputs, rule_of(agg), opts)
        if intent_map_digest(again) != intent_map_digest(agg):
            problems.append("aggregate does not match its recomputation")
    except Exception as e:  # noqa: BLE001 - the reference reports any recompute error as a problem
        problems.append("recompute failed: %s" % e)
    return {"ok": len(problems) == 0, "problems": problems}


def lift_intent_map(m: dict, target: dict) -> dict:
    """Re-express a single-principal map on a refinement of its omega: observations re-applied as value-space regions and
    prior mass 1 on the empty hypothesis for every verb the map did not cover."""
    if m.get("aggregation") is not None or len(m["principals"]) > 1:
        raise ValueError("liftIntentMap: lift single-principal maps, then aggregate")
    src = omega_from_json(m["omega"])
    o = map_learner_options(m)
    known = {v["verb"] for v in src["verbs"]}
    src_mass = o.get("nullMass")
    null_mass: Dict[str, Any] = {}
    for vs in target["verbs"]:
        if vs["verb"] in known:
            own = src_mass.get(vs["verb"]) if isinstance(src_mass, dict) else None
            null_mass[vs["verb"]] = 0.2 if own is None else own
        else:
            null_mass[vs["verb"]] = 1
    l = create_learner(target, {**o, "nullMass": null_mass})
    for ob in m["observations"]:
        svs = next((v for v in src["verbs"] if v["verb"] == ob["verb"]), None)
        tvs = next((v for v in target["verbs"] if v["verb"] == ob["verb"]), None)
        if svs is None or tvs is None:
            raise ValueError("liftIntentMap: verb %s missing from Ω" % ob["verb"])
        values = dict(ob["values"])
        for d in tvs["dims"]:
            if d["path"] not in values:
                values[d["path"]] = rep_value(d, 0)
        own_cell = cell_of(svs, {"verb": ob["verb"], "values": ob["values"]})
        if own_cell is None:
            raise ValueError("liftIntentMap: an observation of %s lies outside the map's own Ω" % ob["verb"])
        region = ob.get("region")
        if region is None:
            region = region_of_cell(svs, own_cell)
        l.observe({"verb": ob["verb"], "values": values}, ob["y"], ob["source"], region)
    return emit_intent_map(l, m["intent_ref"])


def cross_org_aggregate(maps: List[dict], rule: dict, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Replay-verify every map, lift all of them onto the common refinement of their omegas, then aggregate."""
    for i, m in enumerate(maps):
        r = verify_intent_map(m)
        if not r["ok"]:
            raise ValueError("crossOrgAggregate: map %d does not verify: %s" % (i, "; ".join(r["problems"])))
    omega = common_refinement([omega_from_json(m["omega"]) for m in maps])
    lifted = [lift_intent_map(m, omega) for m in maps]
    return {"aggregate": aggregate_intent_maps(lifted, rule, opts), "lifted": lifted, "omega": omega}


def verify_cross_org_aggregate(agg: dict, maps: List[dict], opts: Optional[dict] = None) -> Dict[str, Any]:
    """Verify a cross-org aggregate by recomputing it from the ORIGINAL maps."""
    try:
        again = cross_org_aggregate(maps, rule_of(agg), opts)["aggregate"]
        if intent_map_digest(again) == intent_map_digest(agg):
            return {"ok": True, "problems": []}
        return {"ok": False, "problems": ["aggregate does not match its recomputation"]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "problems": [str(e)]}


def omega_key(o: dict) -> str:
    """The omega of an aggregated or single map as JSON (a comparison key)."""
    return _stringify(omega_to_json(o))
