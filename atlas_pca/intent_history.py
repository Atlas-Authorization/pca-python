"""Session histories (Intent Layer v2 section 2.1; packages/pca/src/intent-history.ts): the host side of accumulators and
monitors. The verifier receives the PRE-STATE of the action's group from its own store; these functions compute it from the
session's event history (window, key, selection and counted statuses applied) and fold a monitor over it. They are pure: the
store, its lock and the reservation are the host's. A function that the reference reports as throwing (a corrupt history)
raises `HistoryError`."""
import math
from typing import Any, List, Optional

from .intent_v2 import _UNDEF, _UTF8_ORDER, acc_selects, acc_value_of, combine_acc, distinct_key, pre_value
from .pca import _is_safe_int
from .predicates import predicate_matches

__all__ = ["HistoryError", "in_window", "acc_key_of", "acc_pre_state", "acc_post", "monitor_step", "monitor_state"]


class HistoryError(Exception):
    """The session history is corrupt (or the candidate unusable): the caller fails closed."""


def _is_time(x: Any) -> bool:
    """A safe integer that is not -0 (the reference `isSafeInt`)."""
    return _is_safe_int(x) and not (isinstance(x, float) and x == 0 and math.copysign(1.0, x) < 0)


def _counted(status: Any) -> bool:
    return status == "reserved" or status == "committed"


def in_window(win: dict, ti: Any, t: Any) -> bool:
    """Does the counted event stamped ti still count at t? task: always; sliding(ms): (t - ms, t]; period(ms, t0): the period
    containing t; and every event stamped AFTER t (it has not left any window). A time that is not a safe integer is in no
    window (fail closed)."""
    if not _is_time(ti) or not _is_time(t):
        return False
    if ti > t:
        return True
    kind = win.get("kind")
    if kind == "task":
        return True
    if kind == "sliding":
        return ti > t - win["ms"]
    if kind == "period":
        return math.floor((ti - win["t0"]) / win["ms"]) == math.floor((t - win["t0"]) / win["ms"])
    return False


def acc_key_of(a: dict, params: dict) -> Optional[str]:
    """The canonical key of the grouping parameter, '•' when ungrouped, None when the parameter is missing."""
    if a["key"] is None:
        return "•"
    name = a["key"][len("action.params."):]
    return distinct_key(params[name]) if name in params else None


def _empty_pre(agg: str) -> dict:
    return {"sum": 0} if agg == "sum" else {"count": 0} if agg == "count" else {"max": 0} if agg == "max" else {"values": []}


def acc_pre_state(a: dict, history: List[dict], cand_params: dict, cand_t: Any, schema: Any = None) -> dict:
    """The pre-state of the accumulator for a candidate action; raises HistoryError on a corrupt history."""
    key = acc_key_of(a, cand_params)
    if key is None:
        raise HistoryError("the key parameter %s is missing" % a["key"])
    if not _is_time(cand_t):
        raise HistoryError("the candidate time is not a safe integer")
    total, count, mx = 0, 0, 0
    vals: List[str] = []
    for e in history:
        counted = _counted(e.get("status"))
        if counted and not _is_time(e.get("t")):
            raise HistoryError("event %s: the time is not a safe integer" % e.get("id"))
        if not counted or not in_window(a["win"], e["t"], cand_t) or not acc_selects(a, e["verb"], schema) or acc_key_of(a, e["params"]) != key:
            continue
        v = acc_value_of(a, e["verb"], e["params"], schema)
        if not v["ok"]:
            raise HistoryError("event %s: %s" % (e.get("id"), v["reason"]))
        total += v["val"]
        count += 1
        mx = max(mx, v["val"])
        if "key" in v:
            vals.append(v["key"])
    if a["agg"] == "sum":
        if not _is_safe_int(total):
            raise HistoryError("sum exceeds 2^53-1")
        return {"sum": total}
    if a["agg"] == "count":
        return {"count": count}
    if a["agg"] == "max":
        return {"max": mx}
    return {"values": sorted(set(vals), key=_UTF8_ORDER)}


def acc_post(a: dict, history: List[dict], verb: str, params: dict, t: Any, schema: Any = None) -> Any:
    """post(history, omega, t): the pre-state combined with omega when omega is selected, else the pre-state's value."""
    pre = _empty_pre(a["agg"]) if a["key"] is not None and acc_key_of(a, params) is None else acc_pre_state(a, history, params, t, schema)
    if not acc_selects(a, verb, schema):
        return pre_value(a, pre)
    v = acc_value_of(a, verb, params, schema)
    if not v["ok"]:
        raise HistoryError(v["reason"])
    post = combine_acc(a, pre, v)
    if post is None:
        raise HistoryError("overflow")
    return post


def _initial(m: dict) -> str:
    k = m["kind"]
    return "unmet" if k in ("requires_prior", "precedes") else "clean" if k == "never" else "ok" if k == "always" else "idle"


def monitor_step(m: dict, q: str, e: dict) -> str:
    """One monitor step on one event; statuses that do not count leave the state unchanged."""
    counts = e.get("status") == "committed" if m.get("status", "admitted") == "committed" else _counted(e.get("status"))
    if not counts:
        return q
    ctx = {"action": {"verb": e["verb"], "resource": e["resource"], "params": e["params"]}}
    kind = m["kind"]
    if kind in ("requires_prior", "precedes"):
        return "met" if q == "met" or predicate_matches(m["p"], ctx) else "unmet"
    if kind == "never":
        return "seen" if q == "seen" or predicate_matches(m["p"], ctx) else "clean"
    if kind == "always":
        return "broken" if q == "broken" or not predicate_matches(m["p"], ctx) else "ok"
    if kind == "responds_within":
        if q == "missed":
            return "missed"
        w = m["within"]
        pending = None
        if q.startswith("pending:"):
            try:
                pending = float(q[len("pending:"):])
            except ValueError:
                pending = math.nan
        if pending is not None:
            if predicate_matches(m["q"], ctx):
                pending = None
            elif pending - 1 <= 0:
                return "missed"
            else:
                pending -= 1
        if predicate_matches(m["p"], ctx):
            pending = w if pending is None else min(pending, w)
        if pending is None:
            return "idle"
        return "pending:%d" % pending
    return q


def monitor_state(m: dict, history: List[dict]) -> str:
    """The fold of the monitor over the history (admission order, current statuses)."""
    q = _initial(m)
    for e in history:
        q = monitor_step(m, q, e)
    return q
