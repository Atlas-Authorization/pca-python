"""Typing of the intent-frontier results as ``ok`` | ``escalate`` | ``deny`` (a signal can only LOWER a decision; ``ok`` is neutral) and the
risk-input tightening that lets the objective path only RAISE risk. Total functions: anything that is not a result is ``deny``."""
from ._fin import fin
import math
from typing import Any, Dict

__all__ = ["semantic_signal", "progress_signal", "objective_signal", "tighten_risk_inputs"]

_PROGRESS_ESCALATE = ("exploration-exhausted", "budget-exceeded")


def _is_obj(x: Any) -> bool:
    return isinstance(x, dict)


def _fin(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)


def semantic_signal(result: Any) -> str:
    """``ok`` / ``escalate`` for a result whose ``ok`` is a real boolean, else ``deny``."""
    if not _is_obj(result) or not isinstance(result.get("ok"), bool):
        return "deny"
    return "ok" if result["ok"] else "escalate"


def progress_signal(result: Any) -> str:
    """``ok`` iff the step verified; running out of exploration budget escalates; every other denial denies."""
    if not _is_obj(result) or not isinstance(result.get("ok"), bool):
        return "deny"
    if result["ok"]:
        return "ok"
    return "escalate" if result.get("reason") in _PROGRESS_ESCALATE and isinstance(result.get("reason"), str) else "deny"


def objective_signal(res: Any) -> str:
    """Nothing committed (``none``) or a reproduced result (``objective``) is neutral; a mismatch is neutral only under ``onMismatch: heuristic``."""
    if not _is_obj(res):
        return "deny"
    mode = res.get("mode")
    if mode == "none" or mode == "objective":
        return "ok"
    if mode == "mismatch":
        return "ok" if res.get("onMismatch") == "heuristic" else "deny"
    return "deny"


def _get(o: Any, k: str) -> Any:
    if o is None:
        raise TypeError("cannot read properties of null (reading '%s')" % k)
    return o.get(k) if isinstance(o, dict) else None


def _ieee_min(a: Any, b: Any) -> Any:
    return -0.0 if a == 0 == b and (math.copysign(1, a) < 0 or math.copysign(1, b) < 0) else min(a, b)


def _ieee_max(a: Any, b: Any) -> Any:
    return 0.0 if a == 0 == b and (math.copysign(1, a) > 0 or math.copysign(1, b) > 0) else max(a, b)


def tighten_risk_inputs(baseline: Any, objective: Any) -> Dict[str, Any]:
    """Reversibility is the lower of the two, blast radius the higher, and a non-finite value on either side makes both the worst case
    (0 and 1); the semantic distance is the objective's when finite, else 1. A null baseline or objective raises."""
    br, bb, orv, ob = _get(baseline, "reversibility"), _get(baseline, "blastRadius"), _get(objective, "reversibility"), _get(objective, "blastRadius")
    ok = _fin(br) and _fin(orv) and _fin(bb) and _fin(ob)
    sd = _get(objective, "semanticDistance")
    return {"reversibility": _ieee_min(br, orv) if ok else 0, "blastRadius": _ieee_max(bb, ob) if ok else 1, "semanticDistance": sd if _fin(sd) else 1}
