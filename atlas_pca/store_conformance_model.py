"""The pure logic of the store conformance kit (port of the TypeScript reference, @atlasauth/pca-store-conformance): the sequential
register specification both store operations share, the verdict-preserving reductions, the budgeted linearizability search, the
per-key checker with minimal counterexamples, the recorder history parser and the workload PRNG.

ONE MODEL FOR BOTH OPERATIONS. An operation is a dict ``{client, kind, key, lo, w, call, ret, res}``: ``kind`` is ``consume`` or
``advance``; each carries a threshold ``lo`` and a write value ``w`` (consume: ``lo`` = now, ``w`` = retainUntil; advance:
``lo = w`` = the counter); ``call`` / ``ret`` bound the interval (``ret`` is ``math.inf`` when the outcome is unknown); ``res`` is
``true``, ``false`` or ``unknown``. The register starts at ``-inf``. A TRUE answer is legal iff ``s < lo`` and then ``s = max(s, w)``;
a FALSE answer is legal iff ``s >= lo`` and leaves ``s``; an UNKNOWN outcome may or may not have taken effect. Operation identity
matters (``deletion`` removes the very object it is given).

A PASS is evidence, not proof; a violation is a recorded history no sequential order explains."""
from __future__ import annotations

from ._fin import fin
import json
import math
from decimal import ROUND_HALF_UP, Decimal, localcontext
from typing import Any, Callable, Dict, List, Optional, Tuple

DEFAULT_SEARCH_BUDGET = 200_000
_INF = math.inf
_M32 = 0xFFFFFFFF


# ---- the register model -------------------------------------------------------------------------------------------------

def step(s: float, op: dict) -> List[float]:
    """The register's successor states after ``op`` from ``s`` (empty: the answer is impossible from ``s``)."""
    fresh = s < op["lo"]
    if op["res"] == "true":
        return [max(s, op["w"])] if fresh else []
    if op["res"] == "false":
        return [] if fresh else [s]
    return [s, max(s, op["w"])] if fresh else [s]


def _definite_true(o: dict) -> bool:
    return o["res"] == "true"


def overlapping_trues(ops: List[dict]) -> Optional[List[dict]]:
    """Two definite TRUE answers whose ``[lo, w]`` intervals overlap can never both linearize: the minimal counterexample, or None."""
    ts = sorted((o for o in ops if _definite_true(o)), key=lambda o: o["lo"])
    for i in range(1, len(ts)):
        if ts[i - 1]["w"] >= ts[i]["lo"]:
            return [ts[i - 1], ts[i]]
    return None


def prune(ops: List[dict]) -> List[dict]:
    """Drop every definite FALSE that a definite TRUE explains (a TRUE with ``w >= lo`` that returned before the FALSE was invoked)."""
    ts = sorted((o for o in ops if _definite_true(o)), key=lambda o: o["ret"])
    pm: List[float] = []
    for t in ts:
        pm.append(max(t["w"], pm[-1] if pm else -_INF))
    out = []
    for o in ops:
        if o["res"] != "false":
            out.append(o)
            continue
        n = 0
        while n < len(ts) and ts[n]["ret"] < o["call"]:
            n += 1
        if not (n > 0 and pm[n - 1] >= o["lo"]):
            out.append(o)
    return out


def fast_check(ops: List[dict]) -> Optional[bool]:
    """EXACT decision for a history with no unknown operation, in O(n log n); None when one is unknown."""
    if any(o["res"] == "unknown" for o in ops):
        return None
    ts = sorted((o for o in ops if _definite_true(o)), key=lambda o: o["lo"])
    t: List[float] = []
    prev = -_INF
    for i, o in enumerate(ts):
        if i > 0 and ts[i - 1]["w"] >= o["lo"]:
            return False
        ti = max(o["call"], prev)
        if ti > o["ret"]:
            return False
        t.append(ti)
        prev = ti
    for f in ops:
        if f["res"] != "false":
            continue
        j = next((k for k, x in enumerate(ts) if x["w"] >= f["lo"]), -1)
        if j < 0 or t[j] > f["ret"]:
            return False
    return True


# ---- the linearizability search ----------------------------------------------------------------------------------------------

def search_linearizable(ops: List[dict], budget: int = DEFAULT_SEARCH_BUDGET) -> str:
    """Wing-Gong / Lowe search for ONE key's history: ``ok``, ``violation`` or ``unresolved`` (a key over the budget is never a pass)."""
    order = sorted(ops, key=lambda o: o["call"])
    n = len(order)
    bits = [1 << i for i in range(n)]
    all_done = (1 << n) - 1
    seen = set()
    stack: List[Tuple[int, float]] = [(0, -_INF)]
    while stack:
        done, s = stack.pop()
        if done == all_done:
            return "ok"
        ident = (done, s)
        if ident in seen:
            continue
        if len(seen) >= budget:
            return "unresolved"
        seen.add(ident)
        min_ret = _INF
        for i in range(n):
            if (done & bits[i]) == 0:
                min_ret = min(min_ret, order[i]["ret"])
        i = 0
        # sorted by invocation: once one starts after the earliest pending return, all later ones do too
        while i < n and order[i]["call"] <= min_ret:
            if (done & bits[i]) == 0:
                for s2 in step(s, order[i]):
                    stack.append((done | bits[i], s2))
            i += 1
    return "violation"


# ---- the per-key checker ----------------------------------------------------------------------------------------------------

def decide_key(ops: List[dict], budget: int = DEFAULT_SEARCH_BUDGET) -> dict:
    """Decide one key's history: overlap, then prune, then the exact check, then the budgeted search. ``{verdict, method, kept}``."""
    if overlapping_trues(ops):
        return {"verdict": "violation", "method": "overlap", "kept": list(ops)}
    kept = prune(ops)
    exact = fast_check(kept)
    if exact is not None:
        return {"verdict": "ok" if exact else "violation", "method": "exact", "kept": kept}
    return {"verdict": search_linearizable(kept, budget), "method": "search", "kept": kept}


def deletion(ops: List[dict], op: dict) -> List[dict]:
    """The SOUND deletion step for ``op``: deleting a FALSE never helps it; deleting a writer also removes the FALSEs it may have explained."""
    if op["res"] == "false":
        return [o for o in ops if o is not op]
    return [o for o in ops if o is not op and not (o["res"] == "false" and o["lo"] <= op["w"])]


def minimize(ops: List[dict], budget: int = DEFAULT_SEARCH_BUDGET) -> List[dict]:
    """Greedy sound deletion to a 1-minimal violating history."""
    cur = list(ops)
    changed = True
    while changed:
        changed = False
        for op in cur:
            nxt = deletion(cur, op)
            if decide_key(nxt, budget)["verdict"] == "violation":
                cur = nxt
                changed = True
                break
    return cur


def check_key(ops: List[dict], opts: Optional[dict] = None) -> dict:
    """Check one key's history (all operations share ``kind`` and ``key``). ``opts`` (reference spelling): ``budget``, ``minimize``
    (default true) and ``minimizeLimit`` (default 200)."""
    opts = opts or {}
    budget = opts["budget"] if opts.get("budget") is not None else DEFAULT_SEARCH_BUDGET
    first = ops[0]
    d = decide_key(ops, budget)
    kept = d["kept"]
    r: Dict[str, Any] = {"key": first["key"], "kind": first["kind"], "ops": len(ops), "searched": len(kept), "verdict": d["verdict"], "method": d["method"]}
    if d["verdict"] != "violation":
        return r
    pair = overlapping_trues(ops)
    limit = opts["minimizeLimit"] if opts.get("minimizeLimit") is not None else 200
    if pair:
        r["counterexample"] = sorted(pair, key=lambda o: o["call"])
        r["minimized"] = True
    elif opts.get("minimize") is not False and len(kept) <= limit:
        r["counterexample"] = minimize(kept, budget)
        r["minimized"] = True
    else:
        r["counterexample"] = kept
        r["minimized"] = False
    return r


def check_history(ops: List[dict], opts: Optional[dict] = None) -> dict:
    """Split a history by (kind, key) and check every key (P-compositionality)."""
    by_key: Dict[Tuple[str, str], List[dict]] = {}
    outcomes = {"true": 0, "false": 0, "unknown": 0}
    for o in ops:
        outcomes[o["res"]] += 1
        by_key.setdefault((o["kind"], o["key"]), []).append(o)
    violations: List[dict] = []
    unresolved: List[dict] = []
    for lst in by_key.values():
        r = check_key(lst, opts)
        if r["verdict"] == "violation":
            violations.append(r)
        elif r["verdict"] == "unresolved":
            unresolved.append(r)
    return {"ops": len(ops), "keys": len(by_key), "ok": not violations and not unresolved, "outcomes": outcomes,
            "violations": violations, "unresolved": unresolved}


# ---- formatting ----------------------------------------------------------------------------------------------------------------

def js_number_str(x: Any) -> str:
    """``String(number)`` for the values a history carries: integers without a fraction, otherwise the shortest round-trip form."""
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        return str(x)
    if isinstance(x, float):
        if x != x:
            return "NaN"
        if x in (_INF, -_INF):
            return "Infinity" if x > 0 else "-Infinity"
        if x == int(x) and abs(x) < 1e21:
            return str(int(x))
        return repr(x)
    return str(x)


def _to_fixed3(x: float) -> str:
    """JavaScript ``toFixed(3)``: exact binary value, ties away from zero."""
    with localcontext() as c:
        c.prec = 400
        return str(Decimal(x).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP))


def _fmt_t(t: float, base: float) -> str:
    return "open" if t == _INF else "+%sms" % _to_fixed3(t - base)


def _res(r: str) -> str:
    return "TRUE" if r == "true" else "false" if r == "false" else "unknown"


def format_ops(ops: List[dict]) -> List[str]:
    """One line per operation, times relative to the first invocation."""
    base = min((o["call"] for o in ops), default=_INF)
    out = []
    for o in sorted(ops, key=lambda x: x["call"]):
        what = "consumeOnce(now=%s, retainUntil=%s)" % (js_number_str(o["lo"]), js_number_str(o["w"])) if o["kind"] == "consume" \
            else "advance(%s)" % js_number_str(o["lo"])
        out.append("%s: %s [%s .. %s] -> %s" % (o["client"], what, _fmt_t(o["call"], base), _fmt_t(o["ret"], base), _res(o["res"])))
    return out


def overall(tests: List[dict]) -> str:
    """Fold test statuses: ``fail`` beats ``unresolved`` beats ``pass`` (a skip counts for nothing)."""
    if any(t["status"] == "fail" for t in tests):
        return "fail"
    if any(t["status"] == "unresolved" for t in tests):
        return "unresolved"
    return "pass"


_OP_NAME = {"consume": "consumeOnce", "advance": "advance"}


def format_report(r: dict, max_keys: int = 3) -> str:
    """Human-readable report: one line per test, then each violating key's minimal counterexample (at most ``max_keys`` per test)."""
    out = ["pca-store-conformance: %s -> %s" % (r["adapter"], r["status"].upper())]
    for t in r["tests"]:
        name = ("%s/%s" % (t["test"], _OP_NAME[t["kind"]])).ljust(24)
        stats = "" if t["status"] == "skip" else "%s ops, %s keys, %s errors/timeouts" % (js_number_str(t["ops"]), js_number_str(t["keys"]), js_number_str(t["errors"]))
        extra = "; ".join(x for x in (
            "%d NON-LINEARIZABLE key(s)" % len(t["violations"]) if t["violations"] else "",
            "%s unresolved key(s) (over the search budget)" % js_number_str(t["unresolved"]) if t["unresolved"] else "",
            t.get("note") or "") if x)
        out.append("  [%s] %s %s" % (t["status"].upper(), name, "; ".join(x for x in (stats, extra) if x)))
        for v in t["violations"][: max(0, max_keys)]:
            out.append("      key %s (%s ops, decided by %s): %s:" % (v["key"], js_number_str(v["ops"]), v["method"],
                                                                   "minimal counterexample" if v.get("minimized") else "violating history (not shrunk)"))
            for line in format_ops(v.get("counterexample") or []):
                out.append("        " + line)
    return "\n".join(out)


def _finite_or_none(v: Any) -> Any:
    if isinstance(v, float) and not fin(v):
        return None
    if isinstance(v, dict):
        return {k: _finite_or_none(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_finite_or_none(x) for x in v]
    return v


def report_json(r: dict) -> str:
    """JSON-safe form of a report (a non-finite number becomes null), two-space indented."""
    return json.dumps(_finite_or_none(r), indent=2, ensure_ascii=False)


# ---- the recorder's history parser and the PRNG ------------------------------------------------------------------------------------

def _js_str(x: Any) -> str:
    """JavaScript ``String(x)`` for a JSON value."""
    if x is None:
        return "null"
    if isinstance(x, (bool, int, float)):
        return js_number_str(x)
    if isinstance(x, str):
        return x
    if isinstance(x, list):
        return ",".join("" if v is None else _js_str(v) for v in x)
    return "[object Object]"


def _js_num(x: Any) -> float:
    """JavaScript ``Number(x)`` for a JSON value."""
    if x is None:
        return 0
    if isinstance(x, bool):
        return 1 if x else 0
    if isinstance(x, (int, float)):
        return x
    if isinstance(x, str):
        t = x.strip(" \t\n\r\v\f   ﻿")
        if t == "":
            return 0
        try:
            if t.lower().lstrip("+-") in ("nan", "inf", "infinity") and t.lstrip("+-") != "Infinity":
                return math.nan
            if "_" in t:
                return math.nan
            v = float(t)
            return int(v) if v == int(v) and abs(v) < 1e21 and "." not in t and "e" not in t.lower() else v
        except (ValueError, OverflowError):
            return math.nan
    if isinstance(x, list):
        return 0 if len(x) == 0 else _js_num(x[0]) if len(x) == 1 and not isinstance(x[0], (list, dict)) else math.nan
    return math.nan


def _no_const(name: str) -> Any:
    raise ValueError(name)


def parse_history(text: str) -> dict:
    """Rebuild the operations from recorder lines (any number of files concatenated). An invocation without a response is pending
    (unknown, open-ended); an ``unknown`` response stays open-ended too. Lines that do not parse are counted as torn.
    Returns ``{ops, torn, pending}``."""
    open_ops: Dict[str, dict] = {}
    ops: List[dict] = []
    torn = 0
    for line in text.split("\n"):
        if line == "":
            continue
        try:
            e = json.loads(line, parse_constant=_no_const)
        except Exception:  # noqa: BLE001
            torn += 1
            continue
        if not isinstance(e, list):
            torn += 1
            continue
        ident = "%s/%s" % (_js_str(e[1]) if len(e) > 1 else "undefined", _js_str(e[2]) if len(e) > 2 else "undefined")
        if len(e) == 9 and e[0] == "i":
            op = {"client": _js_str(e[4]), "kind": e[5], "key": _js_str(e[6]), "lo": _js_num(e[7]), "w": _js_num(e[8]), "call": _js_num(e[3]),
                  "ret": _INF, "res": "unknown"}
            open_ops[ident] = op
            ops.append(op)
        elif len(e) == 5 and e[0] == "r" and ident in open_ops:
            op = open_ops.pop(ident)
            if e[4] != "unknown":
                op["ret"] = _js_num(e[3])
                op["res"] = "true" if e[4] == "true" else "false"
        else:
            torn += 1
    return {"ops": ops, "torn": torn, "pending": len(open_ops)}


def prng(seed: Any) -> Callable[[Any], int]:
    """Deterministic PRNG (mulberry32): ``rand(n)`` is an integer in ``[0, n)``."""
    a = [int(seed) & _M32 if isinstance(seed, (int, float)) and fin(seed) else 0]

    def rand(n: Any) -> int:
        a[0] = (a[0] + 0x6D2B79F5) & _M32
        t = a[0]
        t = ((t ^ (t >> 15)) * (t | 1)) & _M32
        t = (t ^ ((t + (((t ^ (t >> 7)) * (t | 61)) & _M32)) & _M32)) & _M32
        return int(math.floor((((t ^ (t >> 14)) & _M32) / 4294967296) * n))

    return rand
