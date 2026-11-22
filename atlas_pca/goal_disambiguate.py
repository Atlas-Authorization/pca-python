"""Questions over the symmetric difference of competing readings and active disambiguation by version-space halving (the TypeScript
reference is @atlasauth/pca-goal `disambiguate`). A reading is `{id, family, deterministic, goal, notes}`; the question options are
`{ont, riskOf?, massOf?, budget?}`. The reference's asynchronous `ask` is a plain callable returning 'allow' or 'deny'."""
import math
from functools import cmp_to_key
from typing import Any, Callable, Dict, List, Optional, Sequence

from .analyzer_js import js_json, u16key
from .goal_examples import boundary_examples, build_space, cells, decide_case, replay
from .goal_fmt import fmt_act
from .goal_nversion import meet  # noqa: F401  (re-exported for callers that import it from here, as the reference's module does)

__all__ = ["DEFAULT_RISK", "allows_witness", "questions", "disagreement_mass", "disambiguate"]

DEFAULT_RISK = {"read": 1, "reversible": 2, "external_send": 8, "irreversible": 10}


def _h2(p: float) -> float:
    return 0 if p <= 0 or p >= 1 else -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def allows_witness(g: Any, ont: Any, w: Dict[str, Any]) -> bool:
    hist = replay(g, ont, w["prior"], w["rels"])
    return decide_case(g, ont, {"act": w["act"], "hist": hist, "rels": w["rels"]})["decision"] == "allow"


def _allow_set(r: Any, w: dict, ont: Any) -> bool:
    return allows_witness(r["goal"], ont, w)


def _witnesses(readings: Sequence[Any], ont: Any) -> List[Dict[str, Any]]:
    """Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences."""
    goals = [r["goal"] for r in readings]
    out = [{"act": c["act"], "prior": [], "rels": c["rels"]} for c in cells(build_space(goals))["cases"]]
    for r in readings:
        for e in boundary_examples(r["goal"], {"ont": ont, "extra": goals})["examples"]:
            if e["kind"] == "cap_sequence":
                out.append({"act": e["act"], "prior": [a["act"] for a in e["hist"]["adms"]], "rels": e["rels"]})
    return out


def questions(readings: Sequence[Any], opts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Questions ranked by H2(vote) x risk x mass (best first)."""
    ont = opts["ont"]
    k = len(readings)
    cls = {v["verb"]: v["cls"] for v in ont["verbs"]}
    risk_of = opts.get("riskOf") or (lambda a: DEFAULT_RISK.get(cls.get(a["verb"], ""), 10))
    mass_of = opts.get("massOf")
    out: List[Dict[str, Any]] = []
    seen = set()
    for w in _witnesses(readings, ont):
        yes = [r["id"] for r in readings if _allow_set(r, w, ont)]
        if len(yes) == 0 or len(yes) == k:
            continue
        qid = js_json([w["act"], len(w["prior"])])
        if qid in seen:
            continue
        seen.add(qid)
        n = len(w["prior"])
        out.append({
            "id": qid, "act": w["act"], "prior": w["prior"], "rels": w["rels"], "allow": yes, "notAllow": [r["id"] for r in readings if r["id"] not in yes],
            "text": "Should this be allowed: %s%s?" % (fmt_act(w["act"]), " (after %d earlier identical action(s))" % n if n else ""),
            "score": _h2(len(yes) / k) * risk_of(w["act"]) * (mass_of(w["act"]) if mass_of else 1)})

    def cmp(a: dict, b: dict) -> int:
        d = b["score"] - a["score"]
        if d:
            return -1 if d < 0 else 1
        return -1 if u16key(a["id"]) < u16key(b["id"]) else 1
    return sorted(out, key=cmp_to_key(cmp))


def disagreement_mass(readings: Sequence[Any], ont: Any) -> float:
    """Fraction of witness cells on which the readings do not all agree on Allow."""
    w = _witnesses(readings, ont)
    if len(w) == 0:
        return 0
    split = 0
    for x in w:
        n = len([r for r in readings if _allow_set(r, x, ont)])
        if 0 < n < len(readings):
            split += 1
    return split / len(w)


def disambiguate(readings: Sequence[Any], ask: Callable[[Dict[str, Any]], str], opts: Dict[str, Any]) -> Dict[str, Any]:
    """Active disambiguation by version-space halving over the finite class of readings: every question strictly shrinks the class,
    so at most k-1 questions. Realizability (assumption): the principal's intent is one of the readings."""
    ont = opts["ont"]
    budget = opts.get("budget")
    budget = len(readings) if budget is None else budget
    active = list(readings)
    asked: List[dict] = []
    while len(active) > 1 and len(asked) < budget:
        qs = questions(active, opts)
        if not qs:
            break  # the survivors agree on every witness cell
        q = qs[0]
        asked.append(q)
        ans = ask(q)
        active = [r for r in active if _allow_set(r, q, ont) == (ans == "allow")]
    mass = disagreement_mass(active, ont)
    g = meet([r["goal"] for r in active])
    if mass > 0:
        hole = {"hid": "budget", "q": "Question budget exhausted with disagreement left.", "domain": [], "affects": [], "global": True}
        holes = sorted(list(g["holes"]) + [hole], key=lambda h: u16key(h["hid"]))
        return {"status": "budget_exhausted", "goal": dict(g, holes=holes), "asked": asked, "residualMass": mass, "remaining": [r["id"] for r in active]}
    return {"status": "resolved", "goal": g, "asked": asked, "residualMass": 0, "remaining": [r["id"] for r in active]}
