"""LAYERED INTENT, the verifier side (Intent Layer v2 s2.4, s3.5, s5 check `layers`; milestone V5; T18). Port of
packages/pca/src/intent-layers.ts (the TypeScript is authoritative).

Layers are predicate sets: G^org (org / operator ceiling), G^site (the site's own policy), G^std (the principal's standing
profile rules) and G^task (G^task_0 and the principal-signed deltas D_1 ... D_k). DENY ANYWHERE WINS: an action outside a
ceiling is denied with reason `ceiling` and is NEVER a question. Every layer is evaluated by the ONE predicate evaluator
(`predicates.evaluate_predicates`) with the same action context as the admitting root's predicates.

ABSENT VS NULL: an ABSENT layer is no constraint; a layer PRESENT with JSON null or any value that is not
`{"predicates": [...]}` is MALFORMED and fails closed (never read as "no constraint").
"""
from typing import Any

from .predicates import evaluate_predicates

__all__ = ["LAYER_CEILINGS", "is_layer_policy", "decide_layer_ceilings", "decide_layers"]

LAYER_CEILINGS = ("org", "site", "std")

_ABSENT = object()


def _is_arr(x: Any) -> bool:
    return isinstance(x, (list, tuple))


def _closed_to(o: dict, allowed) -> bool:
    """Every own key of `o` is in `allowed` (closed member set)."""
    return all(k in allowed for k in o)


_GRANT_MEMBERS = LAYER_CEILINGS + ("task", "denied")


def is_layer_policy(l: Any) -> bool:
    """A well-formed layer: a plain object with exactly one member, `predicates`, an array (closed member set)."""
    return isinstance(l, dict) and _closed_to(l, ("predicates",)) and "predicates" in l and _is_arr(l["predicates"])


def _layer_admits(l: dict, ctx: Any) -> bool:
    return evaluate_predicates(l["predicates"], ctx)["allowed"]


def _own(o: dict, k: str) -> Any:
    return o[k] if k in o else _ABSENT


def decide_layer_ceilings(layers: Any, ctx: Any) -> dict:
    """The `layers` check: the action must be inside G^org, then G^site, then G^std (absent = no constraint). `layers` must
    be a plain object; a ceiling present with null or any value other than {"predicates": [...]} fails (named), as does an
    empty predicate list (it admits nothing). Returns {"status": "pass"} or {"status": "fail", "layer": k, "reason": str}.
    Never raises. An unknown member of the layers object fails, reported as `org`."""
    if isinstance(layers, dict) and not _closed_to(layers, LAYER_CEILINGS):
        return {"status": "fail", "layer": "org", "reason": "layers: unknown member (the layers object is {org?, site?, std?})"}
    return _ceilings_of(layers, ctx)


def _ceilings_of(layers: Any, ctx: Any) -> dict:
    try:
        if not isinstance(layers, dict):
            return {"status": "fail", "layer": "org", "reason": "layers: the layers member is malformed (not an object)"}
        for k in LAYER_CEILINGS:
            layer = _own(layers, k)
            if layer is _ABSENT:
                continue
            if not is_layer_policy(layer):
                return {"status": "fail", "layer": k,
                        "reason": "layers: the %s ceiling is malformed (null or not {predicates: [...]})" % k}
            if not _layer_admits(layer, ctx):
                return {"status": "fail", "layer": k,
                        "reason": "layers: the action is outside the %s ceiling (a ceiling is never a question)" % k}
        return {"status": "pass"}
    except Exception as e:  # noqa: BLE001 - total: fail closed
        return {"status": "fail", "layer": "org", "reason": "layers: evaluation error (fail closed): %s" % e}


def decide_layers(g: Any, ctx: Any) -> dict:
    """The full layer decision for one action, in order:
      1. outside (or a malformed) G^org, then G^site, then G^std -> {"decision": "ceiling", "layer": k};
      2. inside a denied region (veto, p = 0) -> {"decision": "intent_denied"};
      3. inside G^task_0 or some delta -> {"decision": "admit", "by": i} (0 for G^task_0, k for D_k);
      4. otherwise -> {"decision": "intent_required"}.
    A `denied` present but not an array, a `task` that is not an array (it is required), or any of their entries that is
    not {"predicates": [...]}, yields intent_denied. Absent `denied` = []. A grant member other than org / site / std /
    task / denied is malformed: intent_denied (checked first). Never raises."""
    try:
        if isinstance(g, dict) and not _closed_to(g, _GRANT_MEMBERS):
            return {"decision": "intent_denied"}
        c = _ceilings_of(g, ctx)
        if c["status"] == "fail":
            return {"decision": "ceiling", "layer": c["layer"]}
        denied_in = _own(g, "denied")
        denied = [] if denied_in is _ABSENT else denied_in
        task = _own(g, "task")
        if (not _is_arr(denied) or not all(is_layer_policy(d) for d in denied)
                or not _is_arr(task) or not all(is_layer_policy(t) for t in task)):
            return {"decision": "intent_denied"}
        for d in denied:
            if _layer_admits(d, ctx):
                return {"decision": "intent_denied"}
        for i, t in enumerate(task):
            if _layer_admits(t, ctx):
                return {"decision": "admit", "by": i}
        return {"decision": "intent_required"}
    except Exception:  # noqa: BLE001 - total: fail closed
        return {"decision": "intent_denied"}
