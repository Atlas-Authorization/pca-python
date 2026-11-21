"""Session histories (Intent Layer v2 section 2.1; packages/pca/src/intent-history.ts): the host side of accumulators and
monitors. The verifier receives the PRE-STATE of the action's group from its own store; these functions compute it from the
session's event history (window, key, selection and counted statuses applied) and fold a monitor over it. They are pure: the
store, its lock and the reservation are the host's. A function that the reference reports as throwing (a corrupt history)
raises `HistoryError`."""
import math
from typing import Any, List, Optional

from .attest_common import js_number
from .intent_v2 import _UNDEF, _UTF8_ORDER, acc_selects, acc_value_of, combine_acc, distinct_key, monitor_initial_state, pre_value
from .pca import _is_safe_int
from .predicates import _js_number_string, predicate_matches

__all__ = ["HistoryError", "EVENT_STATUSES", "COUNTED_STATUSES", "is_counted", "in_window", "acc_key_of", "acc_pre_state", "acc_post", "monitor_step",
           "monitor_state", "acc_context_for", "admit_intent_action", "settle_intent_event"]

EVENT_STATUSES = ("reserved", "committed", "released", "reverted")
COUNTED_STATUSES = ("reserved", "committed")


def is_counted(status: Any) -> bool:
    """A reserved or committed event counts toward a cap; a released or reverted one does not."""
    return status == "reserved" or status == "committed"



class HistoryError(Exception):
    """The session history is corrupt (or the candidate unusable): the caller fails closed."""


def _is_time(x: Any) -> bool:
    """A safe integer that is not -0 (the reference `isSafeInt`)."""
    return _is_safe_int(x) and not (isinstance(x, float) and x == 0 and math.copysign(1.0, x) < 0)


def _counted(status: Any) -> bool:
    return status == "reserved" or status == "committed"


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _status(e: Any) -> Any:
    """The status of a history entry as the reference reads it: a null entry is a corrupt history, any other non-object has none."""
    if e is None:
        raise HistoryError("a history entry is null")
    return e.get("status") if isinstance(e, dict) else None


def in_window(win: dict, ti: Any, t: Any) -> bool:
    """Does the counted event stamped ti still count at t? task: always; sliding(ms): (t - ms, t]; period(ms, t0): the period
    containing t; and every event stamped AFTER t (it has not left any window). A time that is not a safe integer is in no
    window (fail closed)."""
    if not _is_time(ti) or not _is_time(t):
        return False
    if ti > t:
        return True
    if win is None:
        raise HistoryError("the window is missing")
    if not isinstance(win, dict):
        return False
    kind, ms, t0 = win.get("kind"), win.get("ms"), win.get("t0")
    if kind == "task":
        return True
    if kind == "sliding":
        return _is_num(ms) and ti > t - ms  # an absent bound compares false in the reference (NaN)
    if kind == "period":
        if not (_is_num(ms) and _is_num(t0)):
            return False
        if ms == 0:  # the reference divides: both quotients are infinities of one sign, or one is NaN
            return (ti - t0) * (t - t0) > 0
        return math.floor((ti - t0) / ms) == math.floor((t - t0) / ms)
    return False


def acc_key_of(a: dict, params: dict) -> Optional[str]:
    """The canonical key of the grouping parameter, '•' when ungrouped, None when the parameter is missing."""
    if a["key"] is None:
        return "•"
    name = a["key"][len("action.params."):]
    return distinct_key(params[name]) if isinstance(params, dict) and name in params else None


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
        counted = _counted(_status(e))
        if counted and not _is_time(e.get("t")):
            raise HistoryError("event %s: the time is not a safe integer" % e.get("id"))
        if not counted or not in_window(a.get("win"), e["t"], cand_t) or not acc_selects(a, e.get("verb"), schema) or acc_key_of(a, e.get("params")) != key:
            continue
        v = acc_value_of(a, e.get("verb"), e.get("params"), schema)
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
    # first, as the reference (TS 80ad8c7ff): a host-built declaration is not validated elsewhere, and an unknown agg would
    # read as distinct in the pre-state
    if not isinstance(a.get("agg"), str) or a["agg"] not in ("sum", "count", "max", "distinct"):
        raise HistoryError("accPost: unknown agg")
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


_initial = monitor_initial_state


def monitor_step(m: dict, q: str, e: dict) -> Optional[str]:
    """One monitor step on one event; statuses that do not count leave the state unchanged. A monitor of an unknown kind has
    no next state on a counted event (None, as the reference)."""
    st = _status(e)
    counts = st == "committed" if m.get("status") == "committed" else _counted(st)
    if not counts:
        return q
    ctx = {"action": {"verb": e.get("verb"), "resource": e.get("resource"), "params": e.get("params")}}
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
        pending = js_number(q[len("pending:"):]) if q.startswith("pending:") else None
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
        return "pending:" + _js_number_string(float(pending))
    return None


def monitor_state(m: dict, history: List[dict]) -> Optional[str]:
    """The fold of the monitor over the history (admission order, current statuses)."""
    q = _initial(m)
    for e in history:
        q = monitor_step(m, q, e)
    return q


def acc_context_for(S: dict, history: List[dict], cand: dict, schema: Any = None) -> dict:
    """The verifier context (``intentV2.acc``) for a candidate action ``cand`` = {"params", "t"}: the pre-states of the site-local accumulators (one that
    keys on a parameter the candidate lacks is left to the verifier, which fails the claim) and the state of every monitor. Raises HistoryError on a
    corrupt history."""
    state: dict = {}
    for a in S["accumulators"]:
        if a["holder"]["kind"] != "site_local":
            continue
        if a["key"] is not None and acc_key_of(a, cand["params"]) is None:
            continue
        state[a["id"]] = acc_pre_state(a, history, cand["params"], cand["t"], schema)
    return {"state": state, "monitors": {m["id"]: monitor_state(m, history) for m in S["monitors"]}}


def admit_intent_action(store: Any, args: dict) -> Any:
    """Admit one action atomically against the session's accumulators: under the session lock (``store.with_session(session, fn)`` calls ``fn(tx)``,
    ``tx`` = events() / append(event) / set_status(id, status)), compute the pre-states and monitor states, run ``args["verify"](acc)`` and, on
    ``{"allow": True}``, append the event as ``reserved``. ``args`` = {session, root, event, verify, schema?, requireDurable? (default True)}. A store
    whose ``durable`` is not exactly True is refused (a restart would reset every cap) unless ``requireDurable`` is False."""
    if args.get("requireDurable") is not False and getattr(store, "durable", None) is not True:
        raise HistoryError("admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore")

    def run(tx: Any) -> Any:
        acc = acc_context_for(args["root"], tx.events(), args["event"], args.get("schema"))
        v = args["verify"](acc)
        if v["allow"]:
            tx.append(dict(args["event"], status="reserved"))
        return v

    return store.with_session(args["session"], run)


def settle_intent_event(store: Any, session: str, event_id: str, status: str) -> bool:
    """Move an admitted event to committed / released / reverted: whether the event was found."""
    return store.with_session(session, lambda tx: tx.set_status(event_id, status))
