"""Data-flow governance, DLP for agents: declare data classes (a resource matcher plus the maximum taint that may flow to them
autonomously) and evaluate an action's provenance taint against them. Pure and offline. An ADVISORY HEURISTIC: taint levels are labels
something upstream attached; this checks them against ceilings and never tracks data through a program, so it is never the only control
over an exfiltration path. Taint 0 is clean, higher is more untrusted or sensitive. Mirrors the TypeScript reference (``dlp.ts``).

A policy is ``{"classes": [{"name", "resource", "verbs"?, "maxTaintForAuto", "hardDenyAbove"?}], "defaultMaxTaintForAuto"?}``; a context is
``{"verb", "resource", "taint", "trustedRefs"?}``; a result is ``{"outcome": "allow" | "step_up" | "deny", "class"?, "reason"?}``.
Fails closed: a malformed policy or ceiling is a deny, and a taint that is not a finite number counts as maximally tainted.
"""
from __future__ import annotations

import math
from ._fin import fin
from typing import Any, Dict, List, Optional

from .predicates import _UNDEF, _js_number_string, _js_string

_INF = math.inf


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _truthy(v: Any) -> bool:
    if v is None or v is False or v == "" or v is _UNDEF:
        return False
    if _is_num(v):
        return not (v == 0 or v != v)
    return True


def _get(o: Any, key: str) -> Any:
    """Own-property read ``o[key]`` of a decoded JSON value (a missing member or a non-object is undefined)."""
    return o.get(key, _UNDEF) if isinstance(o, dict) else _UNDEF


def _is_number(v: Any) -> bool:
    """A number that is not NaN (the reference's ``isNum``)."""
    return _is_num(v) and not (isinstance(v, float) and math.isnan(v))


def _finite(v: Any) -> bool:
    return _is_num(v) and fin(v)


def _same_value_zero(a: Any, b: Any) -> bool:
    """Array.prototype.includes equality for decoded JSON values (a bool is never a number)."""
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if a is None or b is None or a is _UNDEF or b is _UNDEF:
        return a is b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b


def _matches(pattern: Any, resource: Any) -> bool:
    if pattern == "*" and isinstance(pattern, str):
        return True
    if not isinstance(pattern, str):
        raise TypeError("pattern.endsWith is not a function")
    if pattern.endswith("*"):
        if not isinstance(resource, str):
            raise TypeError("resource.startsWith is not a function")
        return resource.startswith(pattern[:-1])
    return isinstance(resource, str) and pattern == resource


def _specificity(pattern: str) -> float:
    if pattern == "*":
        return 0
    if pattern.endswith("*"):
        return len(pattern.encode("utf-16-le", "surrogatepass")) // 2 - 1
    return len(pattern.encode("utf-16-le", "surrogatepass")) // 2 + 1000  # exact beats any prefix


def _strictness(c: Dict[str, Any]) -> float:
    """A malformed ceiling sorts first, so the policy then denies instead of picking a lenient sibling; an absent ceiling (unconstrained)
    is the most lenient and sorts last."""
    m = _get(c, "maxTaintForAuto")
    if m is _UNDEF:
        return _INF
    return float(m) if _is_number(m) else -_INF


def _verb_ok(c: Dict[str, Any], verb: Any) -> bool:
    vs = _get(c, "verbs")
    if not _truthy(vs):
        return True
    if isinstance(vs, list):
        return any(_same_value_zero(x, verb) for x in vs)
    if isinstance(vs, str):
        return _js_string(verb) in vs
    raise TypeError("c.verbs.includes is not a function")


def _class_for(classes: List[Any], ctx: Any) -> Optional[Dict[str, Any]]:
    """The most specific matching class (longest non-wildcard prefix wins, exact beats prefix); of equally specific ones the STRICTEST
    wins, then the first listed."""
    resource, verb = _get(ctx, "resource"), _get(ctx, "verb")
    applicable = []
    for c in classes:
        if not isinstance(c, dict):
            raise TypeError("Cannot read properties of a non-object class")
        if _matches(c.get("resource", _UNDEF), resource) and _verb_ok(c, verb):
            applicable.append(c)
    best: Optional[Dict[str, Any]] = None
    for c in applicable:
        if best is None:
            best = c
            continue
        order = _specificity(best["resource"]) - _specificity(c["resource"])  # the comparator `spec(b) - spec(a) || strict(a) - strict(b)`
        if order == 0:
            order = _strictness(c) - _strictness(best)
        if order < 0:  # a NaN difference (inf - inf) reads as equal: the earlier class stays
            best = c
    return best


def _malformed(policy: Dict[str, Any], cls: Optional[Dict[str, Any]]) -> bool:
    """A ceiling that is present but not a number (or NaN) would make every ``>`` false and allow everything."""
    if cls is not None:
        m, h = _get(cls, "maxTaintForAuto"), _get(cls, "hardDenyAbove")
        return (m is not _UNDEF and not _is_number(m)) or (h is not _UNDEF and not _is_number(h))
    d = _get(policy, "defaultMaxTaintForAuto")
    return d is not _UNDEF and not _is_number(d)


def _result(outcome: str, cls: Optional[Dict[str, Any]], reason: Optional[str]) -> Dict[str, Any]:
    r: Dict[str, Any] = {"outcome": outcome}
    if cls is not None and "name" in cls:
        r["class"] = cls["name"]
    if reason is not None:
        r["reason"] = reason
    return r


def evaluate_dlp(policy: Any, ctx: Any) -> Dict[str, Any]:
    """Evaluate an action's data flow against the DLP policy. Raises TypeError where the reference throws (a class that is not an object,
    a class resource that is not a string)."""
    if not isinstance(policy, dict) or not isinstance(policy.get("classes"), list):
        return _result("deny", None, "malformed DLP policy")
    if ctx is None:
        raise TypeError("Cannot read properties of null")
    cls = _class_for(policy["classes"], ctx)
    if _malformed(policy, cls):
        return _result("deny", cls, "malformed DLP policy: ceilings must be numbers")
    mx = _get(cls, "maxTaintForAuto") if cls is not None else _get(policy, "defaultMaxTaintForAuto")
    t = _get(ctx, "taint")
    bad = not _finite(t)
    taint = _INF if bad else float(t)  # fail closed: a non-finite or non-number taint is maximally tainted, even under an unbounded ceiling
    if mx is _UNDEF:
        return _result("allow", cls, None)  # no ceiling at all: nothing to compare against
    name = _get(cls, "name") if cls is not None else _UNDEF
    label = "<default>" if name is _UNDEF or name is None else _js_string(name)
    hard = _get(cls, "hardDenyAbove") if cls is not None else _UNDEF
    if hard is not _UNDEF and (bad or taint > hard):
        return _result("deny", cls, "taint %s exceeds hard ceiling %s for '%s'" % (_js_number_string(taint), _js_number_string(float(hard)), label))
    if bad or taint > mx:
        return _result("step_up", cls, "taint %s > %s for '%s' — needs human review" % (_js_number_string(taint), _js_number_string(float(mx)), label))
    return _result("allow", cls, None)


def default_dlp_policy(opts: Any = _UNDEF) -> Dict[str, Any]:
    """Preset: PII resources accept only clean (taint 0) autonomously; secrets hard-deny any taint. ``opts``: ``{"piiResource"?,
    "secretsResource"?}`` (no options: no classes; an explicit None is refused, as the reference refuses null)."""
    o = {} if opts is _UNDEF else opts
    if not isinstance(o, dict):
        raise TypeError("defaultDlpPolicy: opts must be an object")
    classes: List[Dict[str, Any]] = []
    if _truthy(o.get("piiResource", _UNDEF)):
        classes.append({"name": "pii", "resource": o["piiResource"], "maxTaintForAuto": 0, "hardDenyAbove": 2})
    if _truthy(o.get("secretsResource", _UNDEF)):
        classes.append({"name": "secrets", "resource": o["secretsResource"], "maxTaintForAuto": 0, "hardDenyAbove": 0})
    return {"classes": classes}
