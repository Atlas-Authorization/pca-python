"""`lift_legacy`: the total, conservative lift of the facade's `{permissions, limits}` input to a Goal + Ontology (the TypeScript
reference is @atlasauth/pca-goal `legacy`). Corrected semantics of the four facade bugs: `$200/day` is a SLIDING 86 400 000 ms sum
bound (explicit window), not a per-call ceiling plus a one-day grant lifetime; a `$` limit on a verb with no amount field is an error;
every limit is its own bound, so adding a limit only narrows (co-sign tiers are not part of the goal); money parameters are integers in
MINOR units of USD (cents), the explicit unit the old facade left implicit."""
import math
import re
from functools import cmp_to_key
from typing import Any, Dict, List

from .analyzer_js import UNDEF, u16key
from .facade import compile_policy, parse_limit

__all__ = ["lift_legacy"]

_USD = {"k": "money", "ccy": "USD"}
_MAX_SAFE = 9007199254740991
_UNEXPRESSIBLE = re.compile("[*?]|^re:")


def _by_code(a: str, b: str) -> int:
    x, y = u16key(a), u16key(b)
    return -1 if x < y else (1 if x > y else 0)


def _js_round(x: float) -> int:
    """Math.round: ties toward +Infinity, exact for large values."""
    r = math.floor(x)
    return r + 1 if x - r >= 0.5 else r


def _is_safe(n: Any) -> bool:
    return isinstance(n, (int, float)) and not isinstance(n, bool) and float(n).is_integer() and abs(n) <= _MAX_SAFE


def lift_legacy(o: Dict[str, Any]) -> Dict[str, Any]:
    """`o`: `{permissions, limits?, catalog?, principal, notAfter?, notBefore?, nlDigest?}` (the money epoch `notAfter` defaults to the
    largest safe integer). Returns `{goal, ontology}`."""
    raw = o.get("limits")
    raw = {} if raw is None else raw

    def own(k: Any) -> Any:
        return raw[k] if isinstance(raw, dict) and isinstance(k, str) and k in raw else UNDEF

    # the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
    cat = o.get("catalog")
    specs = compile_policy(o["permissions"], None, cat)["actions"]
    grants: List[Dict[str, Any]] = []
    bounds: List[Dict[str, Any]] = []
    verbs: List[Dict[str, Any]] = []
    for s in specs:
        gid = "g:%s" % s["verb"]
        amount_path = s.get("amountField")
        verbs.append({"verb": s["verb"], "cls": s["reversibility"], "params": [{"path": amount_path, "ty": {"k": "q", "u": _USD}}] if amount_path else []})
        resource = s["resource"] if s.get("resource") is not None else "*"
        if _UNEXPRESSIBLE.search(resource) and resource != "*":
            raise ValueError("liftLegacy: resource pattern '%s' of %s is not expressible; name exact resources or acknowledge a wildcard" % (resource, s["verb"]))
        raw_limit = own(s["verb"])
        if raw_limit is UNDEF or raw_limit is None:  # `??`: a JSON null is no limit here
            raw_limit = own(s.get("action"))
        cond: Dict[str, Any] = {"k": "true"}
        if raw_limit is not UNDEF:
            lim = parse_limit(raw_limit)
            if lim["unit"] == "usd":
                if not amount_path:
                    raise ValueError("liftLegacy: '$' limit on '%s' but the catalog gives that verb no amount field, so the limit could not be enforced" % s["verb"])
                minor = _js_round(lim["amount"] * 100)
                if not _is_safe(minor):
                    raise ValueError("liftLegacy: limit for %s is out of range" % s["verb"])
                amt = {"k": "param", "path": amount_path, "ty": {"k": "q", "u": _USD}}
                cond = {"k": "and", "a": {"k": "cmp", "op": "gte", "l": amt, "r": {"k": "lit", "v": {"k": "q", "q": {"u": _USD, "n": 0}}}},
                        "b": {"k": "cmp", "op": "lte", "l": amt, "r": {"k": "lit", "v": {"k": "q", "q": {"u": _USD, "n": minor}}}}}
                if lim.get("periodMs") is not None:
                    bounds.append({"bid": "b:%s" % s["verb"], "sel": {"k": "gids", "gids": [gid]}, "agg": "sum", "value": amt, "key": "",
                                   "window": {"k": "sliding", "ms": lim["periodMs"]}, "scope": {"k": "session"}, "cap": {"u": _USD, "n": minor}, "onExceed": "deny"})
            else:
                if not _is_safe(lim["amount"]):
                    raise ValueError("liftLegacy: count limit for %s must be a whole number" % s["verb"])
                bounds.append({"bid": "b:%s" % s["verb"], "sel": {"k": "gids", "gids": [gid]}, "agg": "count",
                               "value": {"k": "lit", "v": {"k": "q", "q": {"u": {"k": "count"}, "n": 1}}}, "key": "",
                               "window": {"k": "sliding", "ms": lim["periodMs"]} if lim.get("periodMs") is not None else {"k": "lifetime"},
                               "scope": {"k": "session"}, "cap": {"u": {"k": "count"}, "n": int(lim["amount"])}, "onExceed": "deny"})
        grants.append({"gid": gid, "verb": s["verb"], "res": {"k": "any", "reason": "legacy default: no resource scope given"} if resource == "*" else {"k": "exact", "id": resource},
                       "cond": cond})
    grants.sort(key=cmp_to_key(lambda a, b: _by_code(a["gid"], b["gid"])))
    bounds.sort(key=cmp_to_key(lambda a, b: _by_code(a["bid"], b["bid"])))
    for i in range(1, len(grants)):
        if grants[i]["gid"] == grants[i - 1]["gid"]:
            raise ValueError("liftLegacy: duplicate grant %s" % grants[i]["gid"])
    nb, na, nl = o.get("notBefore"), o.get("notAfter"), o.get("nlDigest")
    goal = {
        "v": 1, "principal": o["principal"], "ontDigest": "legacy-catalog", "nlDigest": "" if nl is None else nl, "sources": [],
        "grants": grants, "prohibits": [], "bounds": bounds,
        "validity": {"notBefore": 0 if nb is None else nb, "notAfter": _MAX_SAFE if na is None else na, "maxIdle": 0},
        "deleg": {"maxDepth": 16, "narrowOnly": True, "mayTouch": [g["gid"] for g in grants]},
        "escalateOn": [], "wildcardAck": [g["gid"] for g in grants if g["res"]["k"] == "any"], "holes": []}
    verbs.sort(key=cmp_to_key(lambda a, b: _by_code(a["verb"], b["verb"])))
    ontology = {"verbs": [v for i, v in enumerate(verbs) if i == 0 or verbs[i - 1]["verb"] != v["verb"]], "rels": []}
    return {"goal": goal, "ontology": ontology}
