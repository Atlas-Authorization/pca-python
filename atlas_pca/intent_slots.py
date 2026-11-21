"""Structured intent slots: the machine-readable half of an intent statement, compiled into the policy they literally
describe. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from typing import Any, Dict, List


def _slot_conds(sc: dict) -> List[dict]:
    out: List[dict] = []
    p = sc["path"]
    if sc.get("min") is not None:
        out.append({"field": p, "op": "gte", "value": sc["min"]})
    if sc.get("max") is not None:
        out.append({"field": p, "op": "lte", "value": sc["max"]})
    any_of: List[dict] = []
    if sc.get("oneOf"):
        any_of.append({"field": p, "op": "in", "value": list(sc["oneOf"])})
    for x in sc.get("prefixOneOf") or []:
        any_of.append({"field": p, "op": "prefix", "value": x})
    if len(any_of) == 1:
        out.append(any_of[0])
    elif len(any_of) > 1:
        out.append({"any_of": any_of})
    if sc.get("noneOf"):
        out.append({"field": p, "op": "nin", "value": list(sc["noneOf"])})
    return out


def slots_to_policy(slots: dict) -> Dict[str, Any]:
    """One predicate per slot verb."""
    preds = []
    for verb in slots["verbs"]:
        where: List[dict] = []
        for c in slots["constraints"]:
            if c.get("verb") is None or c.get("verb") == verb:
                where.extend(_slot_conds(c))
        pr: Dict[str, Any] = {"verb": verb, "resource": "*"}
        if where:
            pr["where"] = where
        preds.append(pr)
    return {"predicates": preds, "caveats": []}
