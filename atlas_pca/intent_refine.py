"""Cut refinement and partial answers: a "partly" answer inserts the stated cuts / values (or adds a whole dimension) to the
outcome space, re-enumerates the hypotheses and replays every earlier observation as a value-space region. Native port of the
TypeScript reference (@atlasauth/pca-intent, refine.ts). Refinements, partial answers and questions are plain dicts."""
from __future__ import annotations

from ._fin import fin
import copy
import math
from typing import Any, Callable, Dict, List, Optional

from .intent_learner import IntentLearner, audit_round  # noqa: F401  (audit_round kept for callers of the reference's pair)
from .intent_mapkit import create_learner, learner_options_of
from .intent_omega import OTHER, cat_cell_of, cell_rep, num_cells, rep_value, u16key
from .intent_region import region_of_cell, restrict_region


def _is_integer(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x) and x == math.floor(x)


def _uniq(xs: List[Any]) -> List[Any]:
    out: List[Any] = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out


def _sorted_cat(values: List[dict]) -> List[dict]:
    ex = sorted(set(v["value"] for v in values if v["kind"] == "exact"), key=u16key)
    pre = sorted(set(v["value"] for v in values if v["kind"] == "prefix"), key=u16key)
    return [{"kind": "exact", "value": v} for v in ex] + [{"kind": "prefix", "value": v} for v in pre] + [{"kind": "other", "value": OTHER}]


def refine_omega(omega: dict, r: dict) -> dict:
    """Omega with one verb's dimension refined (a deep copy; other verbs and the weights are unchanged)."""
    out = copy.deepcopy(omega)
    vs = next((v for v in out["verbs"] if v["verb"] == r["verb"]), None)
    if vs is None:
        raise ValueError("refineOmega: no verb %s in Ω" % r["verb"])
    i = next((k for k, d in enumerate(vs["dims"]) if d["path"] == r["path"]), -1)
    if r.get("newDim"):
        if i >= 0:
            raise ValueError("refineOmega: %s is already a dimension of %s" % (r["path"], r["verb"]))
        if r["newDim"]["path"] != r["path"]:
            raise ValueError("refineOmega: newDim.path must equal path")
        d = copy.deepcopy(r["newDim"])
        if d["kind"] == "cat":
            d["values"] = _sorted_cat(d["values"])
        else:
            d["cuts"] = sorted(c for c in _uniq(list(d["cuts"])) if c >= d["lo"] and c <= d["hi"])
        vs["dims"].append(d)
        vs["dims"].sort(key=lambda x: u16key(x["path"]))
        return out
    if i < 0:
        raise ValueError("refineOmega: %s has no dimension %s (pass newDim to add it)" % (r["verb"], r["path"]))
    d = vs["dims"][i]
    if d["kind"] == "num":
        if r.get("values") or r.get("prefixes"):
            raise ValueError("refineOmega: %s is numeric" % r["path"])
        cuts = [c for c in (r.get("cuts") or []) if _is_integer(c)]
        d["cuts"] = sorted(c for c in _uniq(list(d["cuts"]) + cuts) if c >= d["lo"] and c <= d["hi"])
    else:
        if r.get("cuts"):
            raise ValueError("refineOmega: %s is categorical" % r["path"])
        d["values"] = _sorted_cat(list(d["values"]) + [{"kind": "exact", "value": v} for v in (r.get("values") or [])]
                                  + [{"kind": "prefix", "value": v} for v in (r.get("prefixes") or [])])
        if len(d["values"]) > 20:
            raise ValueError("refineOmega: %s would have more than 20 values" % r["path"])
    return out


def region_of_observation(omega: dict, o: dict) -> dict:
    """The value-space region an observation was about, in the omega it was recorded in."""
    if o.get("region"):
        return o["region"]
    vs = next((v for v in omega["verbs"] if v["verb"] == o["verb"]), None)
    if vs is None:
        raise ValueError("regionOfObservation: no verb %s" % o["verb"])
    return region_of_cell(vs, o["cell"])


def refine_learner(l: IntentLearner, r: dict, rescope: Optional[Callable[[dict, dict], dict]] = None) -> IntentLearner:
    """Rebuild a learner over a refined omega and replay every observation as a region (rescope may rewrite a region)."""
    omega = refine_omega(l.omega, r)
    nxt = create_learner(omega, learner_options_of(l))
    for o in l.observations:
        region = region_of_observation(l.omega, o)
        if rescope is not None:
            region = rescope(o, region)
        vs = next(v for v in omega["verbs"] if v["verb"] == o["verb"])
        values = dict(o["values"])
        for d in vs["dims"]:
            if d["path"] not in values:
                values[d["path"]] = rep_value(d, 0)
        nxt.observe({"verb": o["verb"], "values": values}, o["y"], o["source"], region)
    return nxt


def _part_label(d: dict, j: int, parts: List[dict]) -> Optional[int]:
    x = rep_value(d, j)
    for p in parts:
        if "lo" in p:
            if d["kind"] != "num":
                continue
            c = num_cells(d)[j]
            if c["lo"] >= p["lo"] and c["hi"] <= p["hi"]:
                return p["y"]
        elif "values" in p:
            if d["kind"] == "cat" and d["values"][j]["kind"] == "exact" and str(x) in p["values"]:
                return p["y"]
        elif d["kind"] == "cat" and d["values"][j]["kind"] != "exact":
            return p["y"]
    return None


def _sub_cells(d: dict, region: dict) -> List[int]:
    """Sub-cells of dimension d (in the refined omega) that lie inside the questioned region's dimension."""
    n = len(num_cells(d)) if d["kind"] == "num" else len(d["values"])
    rd = region["dims"].get(d["path"])
    out: List[int] = []
    for j in range(n):
        if not rd:
            out.append(j)
        elif d["kind"] == "num" and rd["kind"] == "num":
            c = num_cells(d)[j]
            if c["lo"] >= rd["lo"] and c["hi"] <= rd["hi"]:
                out.append(j)
        elif d["kind"] == "cat" and rd["kind"] == "cat":
            cell = cat_cell_of({"kind": "cat", "path": d["path"], "values": rd["values"]}, rep_value(d, j))
            if cell in rd["cells"]:
                out.append(j)
    return out


def answer_partial(l: IntentLearner, q: dict, a: dict) -> Dict[str, Any]:
    """Apply a partial answer to question q: a NEW learner over the refined omega and the observations the answer added."""
    old_vs = next((v for v in l.omega["verbs"] if v["verb"] == q["verb"]), None)
    if old_vs is None:
        raise ValueError("answerPartial: no verb %s" % q["verb"])
    q_region = region_of_cell(old_vs, q["cell"])
    r: Dict[str, Any] = {"verb": q["verb"], "path": a["path"]}
    for k in ("cuts", "values", "newDim"):
        if a.get(k):
            r[k] = a[k]
    refined = refine_omega(l.omega, r)
    nvs = next(v for v in refined["verbs"] if v["verb"] == q["verb"])
    d = next(x for x in nvs["dims"] if x["path"] == a["path"])
    rescope: Optional[Callable[[dict, dict], dict]] = None
    if a.get("newDim"):
        n_d = len(num_cells(d)) if d["kind"] == "num" else len(d["values"])
        yes_cells = [j for j in range(n_d) if _part_label(d, j, a["parts"]) == 1]

        def rescope(o: dict, region: dict) -> dict:  # noqa: F811
            if o["verb"] != q["verb"] or o["y"] != 1:
                return region
            if d["kind"] == "cat":
                return restrict_region(region, d, {"cells": yes_cells})
            # numeric: restrict to the contiguous accepted span (the "typical" range the earlier yes was about)
            if len(yes_cells) == 0:
                return restrict_region(region, d, {"lo": d["hi"] + 1, "hi": d["hi"] + 1})
            cells = num_cells(d)
            return restrict_region(region, d, {"lo": cells[yes_cells[0]]["lo"], "hi": cells[yes_cells[-1]]["hi"]})
    nxt = refine_learner(l, r, rescope)
    added: List[dict] = []
    for j in _sub_cells(d, q_region):
        y = _part_label(d, j, a["parts"])
        if y is None:
            continue
        if d["kind"] == "num":
            c = num_cells(d)[j]
            region = restrict_region(q_region, d, {"lo": c["lo"], "hi": c["hi"]})
        else:
            region = restrict_region(q_region, d, {"cells": [j]})
        values = dict(q["outcome"]["values"])
        values[d["path"]] = rep_value(d, j)
        for x in nvs["dims"]:
            if x["path"] not in values:
                values[x["path"]] = rep_value(x, 0)
        ob = nxt.observe({"verb": q["verb"], "values": values}, y, "elicitation", region)
        if ob:
            added.append(ob)
    return {"learner": nxt, "added": added}


def elicit_adaptive(learner: IntentLearner, answer: Callable[[dict, IntentLearner], Any], o: dict) -> Dict[str, Any]:
    """Elicitation that accepts "yes", "no" and "partly": the stop rule and audit of `elicit`, a partial answer counts as one
    question and swaps in the refined learner; after maxRefinements partial answers a further one is treated as "no"."""
    l = learner
    asked: List[dict] = []
    refinements = 0
    max_ref = o.get("maxRefinements")
    max_ref = 8 if max_ref is None else max_ref

    def apply(q: dict) -> None:
        nonlocal l, refinements
        a = answer(q, l)
        asked.append(q)
        if isinstance(a, dict) or a is None:
            if refinements < max_ref:
                l = answer_partial(l, q, a)["learner"]
                refinements += 1
            else:
                l.observe(q["outcome"], 0, "elicitation")
        else:
            l.observe(q["outcome"], a, "elicitation")

    seed_questions = 0
    for s in o.get("seed") or []:
        if len(asked) >= o["maxQuestions"]:
            break
        vs = next((v for v in l.omega["verbs"] if v["verb"] == s["verb"]), None)
        if vs is None or len(s["cell"]) != len(vs["dims"]):
            continue
        outcome = {"verb": s["verb"], "values": {d["path"]: rep_value(d, s["cell"][k]) for k, d in enumerate(vs["dims"])}}
        p = l.acceptance(outcome)
        if p <= 1e-9 or p >= 1 - 1e-9 or l.is_vetoed(outcome):
            continue
        apply({"verb": s["verb"], "cell": list(s["cell"]), "outcome": outcome, "p": p, "score": 0})
        seed_questions += 1
    stop: Optional[str] = None
    while stop is None:
        m = l.metrics()
        if m["residualRisk"] <= o["epsRisk"] and m["burden"] <= o["epsBurden"]:
            stop = "converged"
        elif len(asked) >= o["maxQuestions"]:
            stop = "budget"
        else:
            q = l.next_question()
            if q is None:
                stop = "no-disagreement"
            else:
                apply(q)
    audit_questions = 0
    if o.get("audit"):
        while True:
            pending = l.unconfirmed_grant_cells()
            total = 0.0
            for x in pending:
                total += x["weight"]
            if len(pending) == 0 or total <= o["epsRisk"]:
                break
            if len(asked) >= o["maxQuestions"]:
                stop = "budget"
                break
            top = pending[0]
            vs = next(v for v in l.omega["verbs"] if v["verb"] == top["verb"])
            outcome = cell_rep(vs, top["cell"])
            apply({"verb": top["verb"], "cell": top["cell"], "outcome": outcome, "p": l.acceptance(outcome), "score": top["weight"]})
            audit_questions += 1
    return {"stop": stop, "questions": len(asked), "auditQuestions": audit_questions, "seedQuestions": seed_questions, "asked": asked,
            "learner": l, "refinements": refinements}
