"""The Intent Map: a content-addressed, replayable artifact holding the outcome space, the learner parameters, every answer,
the learned cells, the conservative grant and the quantified fidelity (all probabilities and metrics are integer ppm so the
digest is language-portable). Native port of the TypeScript reference (@atlasauth/pca-intent, map.ts). Maps, omegas and
learner options are plain dicts with the reference's field names. (`intent_map` holds the committed-map verifier.)"""
from __future__ import annotations

from ._fin import fin
import math
from typing import Any, Dict, List, Optional

from .intent_learner import IntentLearner, hypothesis_class_name
from .intent_omega import js_log
from .intent_v2 import _UNDEF, _js_string
from .pca import hash_canonical

INTENT_MAP_DOMAIN = "atlas-pca/intent-map/v1"
PPM = 1000000


def js_round(x: float) -> int:
    """JS Math.round: the nearest integer, ties toward +infinity."""
    f = math.floor(x)
    return f + 1 if x - f >= 0.5 else f


def ppm(x: float) -> int:
    return js_round(x * PPM)


def _qz(x: float) -> float:
    return js_round(x * PPM) / PPM


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _opt(o: Any, k: str, default: Any = None) -> Any:
    v = o.get(k) if isinstance(o, dict) else None
    return default if v is None else v


def omega_to_json(o: dict) -> dict:
    ws = [v["weight"] for v in o["verbs"]]
    equal = all(abs(w - ws[0]) < 1e-15 for w in ws)
    verbs = []
    for v in o["verbs"]:
        dims = []
        for d in v["dims"]:
            if d["kind"] == "num":
                nd = {"kind": "num", "path": d["path"], "lo": d["lo"], "hi": d["hi"], "cuts": list(d["cuts"])}
                if "dist" in d:
                    nd["dist"] = d["dist"]
                dims.append(nd)
            else:
                dims.append({"kind": "cat", "path": d["path"], "values": [dict(x) for x in d["values"]]})
        verbs.append({"verb": v["verb"], "reversibility": v["reversibility"], "w": 1 if equal else max(1, js_round(v["weight"] * PPM)), "dims": dims})
    return {"verbs": verbs, "approximate": list(o["approximate"])}


def omega_from_json(j: dict) -> dict:
    tot = 0
    for v in j["verbs"]:
        tot += v["w"]
    verbs = []
    for v in j["verbs"]:
        dims = []
        for d in v["dims"]:
            if d["kind"] == "num":
                dims.append({"kind": "num", "path": d["path"], "lo": d["lo"], "hi": d["hi"], "cuts": list(_opt(d, "cuts", [])), "dist": _opt(d, "dist", "uniform")})
            else:
                dims.append({"kind": "cat", "path": d["path"], "values": [dict(x) for x in _opt(d, "values", [])]})
        verbs.append({"verb": v["verb"], "reversibility": v["reversibility"], "weight": v["w"] / tot, "dims": dims})
    return {"v": 1, "approximate": list(j["approximate"]), "verbs": verbs}


def grant_digest(g: dict) -> str:
    inner: Dict[str, Any] = {}
    if g.get("predicates") is not None:
        inner["predicates"] = g["predicates"]
    inner["caveats"] = g["caveats"] if "caveats" in g else []
    return hash_canonical({"d": "atlas-pca/intent-grant/v1", "g": inner})


def _json_plain(v: Any) -> Any:
    """JSON.parse(JSON.stringify(v)): -0 becomes 0, a non-finite number null."""
    if isinstance(v, dict):
        return {k: _json_plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_json_plain(x) for x in v]
    if isinstance(v, float):
        return None if not fin(v) else 0 if v == 0 else v
    return v


def intent_map_digest(m: Any) -> str:
    """Content address of an Intent Map (the core definition, so the server and relying parties agree). The map is taken in its JSON
    form, as the reference does: a negative zero member hashes as 0 and a non-finite one as null."""
    return hash_canonical({"d": INTENT_MAP_DOMAIN, "m": _json_plain(m)})


def _metrics_of(l: IntentLearner) -> Dict[str, Any]:
    m = l.metrics()
    rmax = 0.0
    for c in l.cells():
        rmax += c["mass"] * (1 - c["p"]) * c["harm"]
    return {
        "residual_risk_ppm": ppm(m["residualRisk"]),
        "burden_ppm": ppm(m["burden"]),
        "uncertainty_ppm": ppm(m["uncertainty"]),
        "disagreement_ppm": ppm(m["disagreementMass"]),
        "mean_harm_ppm": ppm(m["meanHarm"]),
        "fidelity_est_ppm": ppm(1 - m["residualRisk"] / rmax if rmax > 0 else 1),
        "entropy_mbits": js_round(m["entropyBits"] * 1000),
        "log2_vs_mbits": None if m["log2VersionSpace"] is None else js_round(m["log2VersionSpace"] * 1000),
        "questions": m["questions"],
        "conflicts": m["conflicts"],
    }


def _is_safe_integer(x: Any) -> bool:
    return _is_num(x) and fin(x) and x == math.floor(x) and abs(x) <= 9007199254740991


def _prior_mix_of(pm: dict) -> dict:
    """The learner's priorMix function for a data-form population prior (ppm-quantised like every map number)."""
    by_verb: Dict[str, List[dict]] = {}
    for c in pm["cells"]:
        q = _qz(c["q"])
        if not (q >= 0 and q <= 1) or not _is_safe_integer(c["cell"]) or c["cell"] < 0:
            raise ValueError("pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0")
        by_verb.setdefault(c["verb"], []).append({"cell": c["cell"], "lq": js_log(q), "lnq": js_log(1 - q)})

    def weight(vs: dict, contains: Any) -> float:
        lw = 0.0
        for t in by_verb.get(vs["verb"], []):
            lw += t["lq"] if contains(t["cell"]) else t["lnq"]
        return math.exp(lw)

    return {"beta": _qz(pm["beta"]), "weight": weight}


def _anchor_opt(a: dict) -> dict:
    return {"policy": {"predicates": a["policy"]["predicates"], "caveats": _opt(a["policy"], "caveats", [])}, "lambda": js_round(a["lambda"] * 1000) / 1000}


def _anchor_json(a: dict) -> dict:
    return {"policy": {"predicates": a["policy"]["predicates"], "caveats": _opt(a["policy"], "caveats", [])}, "lambda_milli": js_round(a["lambda"] * 1000)}


def _quantize_class(h: Optional[dict]) -> dict:
    if not h or h.get("kind") == "box":
        return {"kind": "box"}
    decay = _qz(_opt(h, "decay", 0.25))
    if h["kind"] == "union":
        return {"kind": "union", "k": h.get("k"), "decay": decay}
    return {"kind": "decision-list", "maxRules": h.get("maxRules"), "decay": decay, "conditions": _opt(h, "conditions", "box")}


def _null_mass_of(o: dict, verb: str) -> float:
    nm = o.get("nullMass")
    if _is_num(nm):
        return nm
    own = nm.get(verb) if isinstance(nm, dict) else None  # own entries only: a verb named like an Object member is an ordinary key
    if own is not None:
        return own
    return _opt(o, "defaultNullMass", 0.2)


def create_learner(omega: dict, o: Optional[dict] = None) -> IntentLearner:
    """Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised)."""
    o = o if o is not None else {}
    eta0 = _opt(o, "eta", 0)
    opts: Dict[str, Any] = {
        "eta": _qz(eta0),
        "tau": _qz(_opt(o, "tau", 1 if eta0 == 0 else 0.95)),
        "strategy": _opt(o, "strategy", "disagreement"),
        "nullMass": lambda vs: _qz(_null_mass_of(o, vs["verb"])),
        "hypothesisClass": _quantize_class(o.get("hypothesisClass")),
    }
    if "agnosticSlack" in o:
        opts["agnosticSlack"] = o["agnosticSlack"]
    if o.get("anchor"):
        opts["anchor"] = _anchor_opt(o["anchor"])
    if o.get("anchors"):
        opts["anchors"] = [_anchor_opt(a) for a in o["anchors"]]
    if o.get("monotone"):
        opts["monotone"] = {"paths": list(o["monotone"]["paths"]), "offMass": _qz(_opt(o["monotone"], "offMass", 0))}
    if "etaPos" in o:
        opts["etaPos"] = _qz(o["etaPos"])
    if "etaNeg" in o:
        opts["etaNeg"] = _qz(o["etaNeg"])
    if o.get("priorMix"):
        opts["priorMix"] = _prior_mix_of(o["priorMix"])
    l = IntentLearner(omega, opts)
    l._map_params = o  # type: ignore[attr-defined]
    return l


def learner_options_of(l: IntentLearner) -> dict:
    """The serialisable parameters a learner was built with (create_learner only)."""
    o = getattr(l, "_map_params", None)
    if o is None:
        raise ValueError("pca-intent: build the learner with createLearner() so its parameters are serialisable")
    return o


def emit_intent_map(l: IntentLearner, intent_ref_value: Optional[str] = None) -> dict:
    o = learner_options_of(l)
    null_mass_ppm = {vs["verb"]: ppm(_null_mass_of(o, vs["verb"])) for vs in l.omega["verbs"]}
    grant = l.synthesize()
    hc = l.hypothesis_class
    learner: Dict[str, Any] = {"hypothesis_class": hypothesis_class_name(hc)}
    if hc["kind"] == "union":
        learner["class_params"] = {"k": hc["k"], "decay_ppm": ppm(_opt(hc, "decay", 0.25))}
    if hc["kind"] == "decision-list":
        learner["class_params"] = {"max_rules": hc["maxRules"], "decay_ppm": ppm(_opt(hc, "decay", 0.25))}
    if l.agnostic_slack is not None:
        learner["agnostic_slack"] = l.agnostic_slack
    learner["eta_ppm"] = ppm(l.eta)
    learner["tau_ppm"] = ppm(l.tau)
    learner["strategy"] = l.strategy
    learner["null_mass_ppm"] = null_mass_ppm
    if o.get("anchor"):
        learner["anchor"] = _anchor_json(o["anchor"])
    if o.get("anchors"):
        learner["anchors"] = [_anchor_json(a) for a in o["anchors"]]
    if o.get("monotone"):
        learner["monotone"] = {"paths": list(o["monotone"]["paths"]), "off_ppm": ppm(_opt(o["monotone"], "offMass", 0))}
    if "etaPos" in o or "etaNeg" in o:
        learner["noise"] = {"eta_pos_ppm": ppm(l.eta_pos), "eta_neg_ppm": ppm(l.eta_neg)}
    if o.get("priorMix"):
        pm = o["priorMix"]
        learner["prior_mix"] = {"beta_ppm": ppm(pm["beta"]), "cells": [{"verb": c["verb"], "cell": c["cell"], "q_ppm": ppm(c["q"])} for c in pm["cells"]]}
    observations = []
    for x in l.observations:
        ob = {"verb": x["verb"], "values": dict(x["values"]), "y": x["y"], "source": x["source"]}
        if x.get("region") is not None:
            ob["region"] = x["region"]
        observations.append(ob)
    return {
        "v": 1,
        "kind": "pca-intent-map",
        "intent_ref": intent_ref_value,
        "principals": [intent_ref_value] if intent_ref_value else [],
        "omega": omega_to_json(l.omega),
        "learner": learner,
        "observations": observations,
        "cells": [{"verb": c["verb"], "cell": c["cell"], "p_ppm": ppm(c["p"]), "in_grant": c["inGrant"]} for c in l.cells()],
        "grant": grant,
        "grant_digest": grant_digest(grant),
        "metrics": _metrics_of(l),
    }


def map_learner_options(m: dict) -> dict:
    """The learner parameters a map records (inverse of what emit_intent_map writes)."""
    lr = m["learner"]
    null_mass = {k: v / PPM for k, v in lr["null_mass_ppm"].items()}
    cp = lr.get("class_params")
    hcn = lr["hypothesis_class"]
    if hcn == "per-verb-union/v1":
        hc = {"kind": "union", "k": _opt(cp, "k", 2), "decay": _opt(cp, "decay_ppm", 250000) / PPM}
    elif hcn in ("per-verb-decision-list/v1", "per-verb-decision-list/v2"):
        hc = {"kind": "decision-list", "maxRules": _opt(cp, "max_rules", 2), "decay": _opt(cp, "decay_ppm", 250000) / PPM,
              "conditions": "atomic" if hcn == "per-verb-decision-list/v1" else "box"}
    else:
        hc = {"kind": "box"}
    out: Dict[str, Any] = {"eta": lr["eta_ppm"] / PPM, "tau": lr["tau_ppm"] / PPM, "strategy": lr["strategy"], "nullMass": null_mass, "hypothesisClass": hc}
    if lr.get("agnostic_slack") is not None:
        out["agnosticSlack"] = lr["agnostic_slack"]
    if lr.get("anchor"):
        out["anchor"] = {"policy": lr["anchor"]["policy"], "lambda": lr["anchor"]["lambda_milli"] / 1000}
    if lr.get("anchors"):
        out["anchors"] = [{"policy": a["policy"], "lambda": a["lambda_milli"] / 1000} for a in lr["anchors"]]
    if lr.get("monotone"):
        out["monotone"] = {"paths": list(lr["monotone"]["paths"]), "offMass": lr["monotone"]["off_ppm"] / PPM}
    if lr.get("noise"):
        out["etaPos"] = lr["noise"]["eta_pos_ppm"] / PPM
        out["etaNeg"] = lr["noise"]["eta_neg_ppm"] / PPM
    if lr.get("prior_mix"):
        pm = lr["prior_mix"]
        out["priorMix"] = {"beta": pm["beta_ppm"] / PPM, "cells": [{"verb": c["verb"], "cell": c["cell"], "q": c["q_ppm"] / PPM} for c in pm["cells"]]}
    return out


def learner_from_map(m: dict) -> IntentLearner:
    """Rebuild the learner a map describes (omega + prior + observations)."""
    l = create_learner(omega_from_json(m["omega"]), map_learner_options(m))
    for o in m["observations"]:
        l.observe({"verb": o["verb"], "values": o["values"]}, o["y"], o["source"], o.get("region"))
    return l


def _is_one(v: Any) -> bool:
    return _is_num(v) and v == 1


def verify_intent_map(m: Any) -> Dict[str, Any]:
    """Replay a single-principal map and check every number, every cell and the grant."""
    problems: List[str] = []
    try:
        if not (isinstance(m, dict) and _is_one(m.get("v")) and m.get("kind") == "pca-intent-map"):
            return {"ok": False, "problems": ["not an intent map v1"]}
        if len(m["principals"]) > 1 or m.get("aggregation") is not None:
            return {"ok": False, "problems": ["combined map: verify each principal map and recombine with verifyAggregate"]}
        r = emit_intent_map(learner_from_map(m), m["intent_ref"])
        if r["grant_digest"] != m["grant_digest"] or grant_digest(m["grant"]) != m["grant_digest"]:
            problems.append("grant does not match the replayed posterior")
        if len(r["cells"]) != len(m["cells"]):
            problems.append("cell count differs")
        else:
            for i, c in enumerate(r["cells"]):
                x = m["cells"][i]
                if c["verb"] != x["verb"] or c["in_grant"] != x["in_grant"] or _gt2(c["p_ppm"], x["p_ppm"]):
                    problems.append("cell %d differs" % i)
        for k, a in r["metrics"].items():
            b = m["metrics"].get(k, _UNDEF) if isinstance(m["metrics"], dict) else _UNDEF
            if a is None or b is None:
                bad = a is not b
            else:
                bad = _gt2(a, b)
            if bad:
                problems.append("metric %s differs (%s claimed, %s replayed)" % (k, _js_string(b), _js_string(a)))
    except Exception as e:  # noqa: BLE001 - the reference reports any replay error as a problem
        problems.append("replay failed: %s" % e)
    return {"ok": len(problems) == 0, "problems": problems}


def _gt2(a: Any, b: Any) -> bool:
    """Math.abs(a - b) > 2 with JS coercion limits: a non-number side makes the difference NaN, which is never > 2."""
    return _is_num(a) and _is_num(b) and abs(a - b) > 2


def apply_divergence(l: IntentLearner, outcome: dict, y: int) -> Dict[str, Any]:
    """A runtime divergence is one more labelled observation; a NEGATIVE one also vetoes the outcome's cell for good."""
    def count() -> int:
        return sum(1 for c in l.cells() if c["inGrant"])
    before = count()
    l.observe(outcome, y, "runtime")
    return {"before": before, "after": count(), "grant": l.synthesize()}
