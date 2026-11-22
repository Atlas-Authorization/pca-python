"""Outcome verification: postconditions on observed effects, evaluated by the one predicate evaluator. Three-valued: ok,
violated, pending. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .intent_omega import u16key
from .intent_policy import outcome_to_action
from .intent_v2 import _UNDEF
from .predicates import evaluate_predicates, is_group_condition, is_leaf_condition


def _eff(field: str) -> str:
    return "env.effect." + field


def _pc(id_: str, verb: str, description: str, where: List[dict]) -> dict:
    return {"id": id_, "verb": verb, "description": description, "where": where}


_AMT = [{"field": _eff("amount"), "op": "lte", "ref": "action.params.amount"}, {"field": _eff("amount"), "op": "gte", "value": 0}]

DEFAULT_POSTCONDITIONS: List[dict] = [
    _pc("stripe.refund.amount", "stripe.refund", "the refunded amount is at most the requested amount", [dict(c) for c in _AMT]),
    _pc("stripe.refund.recipient", "stripe.refund", "the refund went to the requested recipient", [{"field": _eff("recipient"), "op": "eq", "ref": "action.params.recipient"}]),
    _pc("stripe.charge.amount", "stripe.charge", "the charged amount is at most the requested amount", [dict(c) for c in _AMT]),
    _pc("stripe.payout.amount", "stripe.payout", "the paid-out amount is at most the requested amount", [dict(c) for c in _AMT]),
    _pc("stripe.payout.recipient", "stripe.payout", "the payout went to the requested recipient", [{"field": _eff("recipient"), "op": "eq", "ref": "action.params.recipient"}]),
    _pc("gmail.send.to", "gmail.send", "the mail went only to the requested address", [{"field": _eff("to"), "op": "eq", "ref": "action.params.to"}]),
    _pc("slack.post_message.channel", "slack.post_message", "the message was posted in the requested channel", [{"field": _eff("channel"), "op": "eq", "ref": "action.params.channel"}]),
    _pc("files.write.path", "files.write", "the written path is the requested resource", [{"field": _eff("path"), "op": "eq", "ref": "action.resource"}]),
    _pc("files.delete.path", "files.delete", "the deleted path is the requested resource", [{"field": _eff("path"), "op": "eq", "ref": "action.resource"}]),
    _pc("github.merge_pr.repo", "github.merge_pr", "the merge landed in the requested repository", [{"field": _eff("repo"), "op": "eq", "ref": "action.resource"}]),
    _pc("calendar.create_event.hour", "calendar.create_event", "the event starts at the requested hour", [{"field": _eff("hour"), "op": "eq", "ref": "env.hour"}]),
]


def _leaves(c: Any, out: List[dict]) -> None:
    if c is None or not isinstance(c, dict):
        return
    if is_group_condition(c):
        if "all_of" in c and isinstance(c["all_of"], list):
            for x in c["all_of"]:
                _leaves(x, out)
        elif "any_of" in c and isinstance(c["any_of"], list):
            for x in c["any_of"]:
                _leaves(x, out)
        elif "not" in c:
            _leaves(c["not"], out)
        return
    if is_leaf_condition(c):
        d = {"field": c["field"]}
        if isinstance(c.get("ref"), str):
            d["ref"] = c["ref"]
        out.append(d)


def _get(root: Any, path: str) -> Any:
    cur = root
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        elif isinstance(cur, list) and k.isascii() and k.isdigit() and str(int(k)) == k and int(k) < len(cur):
            cur = cur[int(k)]
        else:
            return _UNDEF
    return cur


def effect_context(vs: dict, o: dict, effect: Any) -> dict:
    """The evaluator's context for an action plus its observed effect."""
    a = outcome_to_action(vs, o)
    ctx: Dict[str, Any] = {"action": {"verb": a["verb"], "resource": a["resource"], "params": a["params"], "reversibility_class": vs.get("reversibility")}}
    if a.get("subject"):
        ctx["subject"] = a["subject"]
    ctx["env"] = {**(a.get("env") or {}), "effect": effect}
    return ctx


def check_postconditions(vs: dict, o: dict, effect: Any, pcs: Optional[List[dict]] = None) -> dict:
    if pcs is None:
        pcs = DEFAULT_POSTCONDITIONS
    ctx = effect_context(vs, o, effect)
    rep: Dict[str, Any] = {"status": "ok", "violated": [], "missing": [], "checked": [], "notApplicable": []}
    for pc in pcs:
        if pc["verb"] != o["verb"]:
            continue
        ls: List[dict] = []
        for c in pc["where"]:
            _leaves(c, ls)
        if any("ref" in l and not l["ref"].startswith("env.effect.") and _get(ctx, l["ref"]) is _UNDEF for l in ls):
            rep["notApplicable"].append(pc["id"])
            continue
        need: Dict[str, None] = {}
        for l in ls:
            for f in [l["field"]] + ([l["ref"]] if l.get("ref") else []):
                if f.startswith("env.effect."):
                    need[f] = None
        lacking = [f for f in need if _get(ctx, f) is _UNDEF]
        if lacking:
            rep["missing"].extend(lacking)
            continue
        rep["checked"].append(pc["id"])
        r = evaluate_predicates([{"verb": o["verb"], "resource": "*", "where": pc["where"]}], ctx)
        if not r["allowed"]:
            rep["violated"].append(pc["id"])
    rep["missing"] = sorted(set(rep["missing"]), key=u16key)
    rep["status"] = "violated" if rep["violated"] else "pending" if rep["missing"] else "ok"
    return rep


def verify_outcome(l: Any, o: dict, effect: Any, pcs: Optional[List[dict]] = None) -> Dict[str, Any]:
    """Check an executed action's effect and feed the result back: a violation is a negative runtime observation that vetoes
    the action's cell. `ok` and `pending` change nothing (a met postcondition is not the principal's endorsement)."""
    from .intent_mapkit import apply_divergence
    vs = next((v for v in l.omega["verbs"] if v["verb"] == o["verb"]), None)
    if vs is None:
        raise ValueError("verifyOutcome: no verb %s in Ω" % o["verb"])
    report = check_postconditions(vs, o, effect, pcs)
    if report["status"] != "violated":
        return {"report": report}
    return {"report": report, "divergence": apply_divergence(l, o, 0)}
