"""An independent reading of the goal semantics D_G (the TypeScript reference is @atlasauth/pca-goal `refsem`): a second,
hand-written implementation used to cross-check a compiled policy. NOT the trusted decision function. Decisions are 0 deny,
1 escalate, 2 allow; condition truth is 0 false, 1 unknown, 2 true."""
from ._fin import fin
import math
from typing import Any, Dict, List, Optional

from .analyzer_js import UNDEF, includes, jget, js_gt, js_json, js_lt, req_list, strict_eq, to_number, truthy

__all__ = ["ref_decide", "ref_explain"]


def _b2t(b: Any) -> int:
    return 2 if truthy(b) else 0


def _same_unit(a: Any, b: Any) -> bool:
    if a is UNDEF or b is UNDEF:
        return a is b
    return js_json(a) == js_json(b)


def _has(o: Any, k: Any) -> bool:
    if o is None or o is UNDEF:
        raise TypeError("cannot convert undefined or null to object")
    return isinstance(o, dict) and isinstance(k, str) and k in o


def _val(t: Any, a: Any, h: Any) -> Any:
    k = jget(t, "k")
    if k == "param":
        params = jget(a, "params")
        path = jget(t, "path")
        return params[path] if _has(params, path) else UNDEF
    if k == "lit":
        return jget(t, "v")
    aggs = jget(h, "aggs")
    bid = jget(t, "bid")
    return {"k": "q", "q": aggs[bid]} if _has(aggs, bid) else UNDEF


def _eq(x: Any, y: Any) -> int:
    if jget(x, "k") == "q" and jget(y, "k") == "q":
        xq, yq = jget(x, "q"), jget(y, "q")
        return _b2t(strict_eq(jget(xq, "n"), jget(yq, "n"))) if _same_unit(jget(xq, "u"), jget(yq, "u")) else 1
    if jget(x, "k") == "s" and jget(y, "k") == "s":
        return _b2t(strict_eq(jget(x, "s"), jget(y, "s")))
    return 1


def _lt(x: Any, y: Any) -> int:
    if jget(x, "k") == "q" and jget(y, "k") == "q" and _same_unit(jget(jget(x, "q"), "u"), jget(jget(y, "q"), "u")):
        return _b2t(js_lt(jget(jget(x, "q"), "n"), jget(jget(y, "q"), "n")))
    return 1


def _in_set(x: Any, y: Any) -> int:
    if jget(y, "k") != "set":
        return 1
    acc = 0
    for it in req_list(jget(y, "items")):
        acc = max(acc, _eq(x, it))
    return acc


def _cmp(op: Any, x: Any, y: Any) -> int:
    if not truthy(x) or not truthy(y):
        return 1
    if op == "eq":
        return _eq(x, y)
    if op == "ne":
        return 2 - _eq(x, y)
    if op == "lt":
        return _lt(x, y)
    if op == "gte":
        return 2 - _lt(x, y)
    if op == "gt":
        return _lt(y, x)
    if op == "lte":
        return 2 - _lt(y, x)
    if op == "in":
        return _in_set(x, y)
    return 2 - _in_set(x, y)


def _eval_c(c: Any, a: Any, h: Any) -> int:
    k = jget(c, "k")
    if k == "true":
        return 2
    if k == "cmp":
        return _cmp(jget(c, "op"), _val(jget(c, "l"), a, h), _val(jget(c, "r"), a, h))
    if k == "and":
        return min(_eval_c(jget(c, "a"), a, h), _eval_c(jget(c, "b"), a, h))
    if k == "or":
        return max(_eval_c(jget(c, "a"), a, h), _eval_c(jget(c, "b"), a, h))
    if k == "not":
        return 2 - _eval_c(jget(c, "c"), a, h)
    raise ValueError("unknown condition")  # the reference yields NaN here; refuse instead


def _res_ok(s: Any, ont: Any, r: Any) -> bool:
    k = jget(s, "k")
    if k == "any":
        return True
    if k == "exact":
        return strict_eq(r, jget(s, "id"))
    if k == "oneof":
        return includes(jget(s, "ids"), r)
    if k == "related":
        members: Any = []
        for x in req_list(jget(ont, "rels")):
            if strict_eq(jget(x, "rel"), jget(s, "rel")) and strict_eq(jget(x, "anchor"), jget(s, "anchor")):
                m = jget(x, "members")
                members = [] if m is None or m is UNDEF else m
                break
        return includes(members, r)
    if k == "all_of":
        return all(_res_ok(p, ont, r) for p in req_list(jget(s, "parts")))
    return False


def _verbs_of(ont: Any, cls: Any) -> List[Any]:
    return [jget(v, "verb") for v in req_list(jget(ont, "verbs")) if strict_eq(jget(v, "cls"), cls)]


def _in_scope(sc: Any, a: Any, x: Any) -> bool:
    k = jget(sc, "k")
    if k == "session":
        return strict_eq(jget(a, "sess"), jget(x, "sess"))
    if k == "principal":
        return strict_eq(jget(a, "prin"), jget(x, "prin"))
    if k == "org":
        return strict_eq(jget(a, "org"), jget(x, "org"))
    if k == "fleet":
        return includes(jget(sc, "agents"), jget(a, "agent")) and includes(jget(sc, "agents"), jget(x, "agent"))
    return False


def _floor(v: float) -> float:
    return math.floor(v) if fin(v) else v


def _in_win(w: Any, a: Any, x: Any) -> bool:
    k = jget(w, "k")
    if k == "task" or k == "lifetime":
        return True
    if k == "sliding":
        at, xt, ms = to_number(jget(a, "t")), to_number(jget(x, "t")), to_number(jget(w, "ms"))
        return js_gt(jget(x, "t"), at - ms) and xt <= at
    if k == "period":
        ms = jget(w, "ms")
        if not js_gt(ms, 0):
            return False
        m, t0 = to_number(ms), to_number(jget(w, "t0"))
        return _floor((to_number(jget(a, "t")) - t0) / m) == _floor((to_number(jget(x, "t")) - t0) / m)
    return False


def _fsum(xs: List[Any]) -> Any:
    s: Any = 0.0
    for x in xs:
        s = s + x if isinstance(s, float) and isinstance(x, (int, float)) and not isinstance(x, bool) else _concat(s, x)
    return s


def _concat(a: Any, b: Any) -> str:
    from .analyzer_js import js_str
    return js_str(a) + js_str(b)


def ref_decide(g: Any, ont: Any, a: Any, h: Any) -> int:
    return ref_explain(g, ont, a, h)["d"]


def ref_explain(g: Any, ont: Any, a: Any, h: Any) -> Dict[str, Any]:
    """`{d, witness, prohibit}`: the decision, the first grant (goal order) whose own decision is Allow (null unless d = 2), and
    the meet over the prohibitions alone (0 one fires, 1 one is unknown, 2 none applies)."""
    d = 2
    prohibit = 2
    witness: Optional[str] = None
    v = jget(g, "validity")
    t = jget(a, "t")
    deleg = jget(g, "deleg")
    last = jget(h, "last")
    depth = jget(a, "depth")
    if js_lt(t, jget(v, "notBefore")) or js_gt(t, jget(v, "notAfter")):
        d = min(d, 0)
    elif js_gt(jget(v, "maxIdle"), 0) and not js_lt(last, 0) and to_number(last) == to_number(last) and js_gt(to_number(t) - to_number(last), jget(v, "maxIdle")):
        d = min(d, 0)
    elif js_lt(depth, 0) or js_gt(depth, jget(deleg, "maxDepth")):
        d = min(d, 0)
    for p in req_list(jget(g, "prohibits")):
        tg = jget(p, "target")
        verbs = [jget(tg, "verb")] if jget(tg, "k") == "verb" else _verbs_of(ont, jget(tg, "cls"))
        m = min(_b2t(includes(verbs, jget(a, "verb"))), min(_b2t(_res_ok(jget(p, "res"), ont, jget(a, "res"))), _eval_c(jget(p, "cond"), a, h)))
        pd = 0 if m == 2 else (1 if m == 1 else 2)
        d = min(d, pd)
        prohibit = min(prohibit, pd)
    for c in req_list(jget(g, "escalateOn")):
        d = min(d, 2 if _eval_c(c, a, h) == 0 else 1)
    best = 0
    for gr in req_list(jget(g, "grants")):
        verb_ok = strict_eq(jget(a, "verb"), jget(gr, "verb")) and (strict_eq(depth, 0) or includes(jget(deleg, "mayTouch"), jget(gr, "gid")))
        m = min(_b2t(verb_ok), min(_b2t(_res_ok(jget(gr, "res"), ont, jget(a, "res"))), _eval_c(jget(gr, "cond"), a, h)))
        gd = m
        for b in req_list(jget(g, "bounds")):
            sel = jget(b, "sel")
            gids = jget(sel, "gids") if jget(sel, "k") == "gids" else []
            verbs = _verbs_of(ont, jget(sel, "cls")) if jget(sel, "k") == "effect" else []
            if not (includes(gids, jget(gr, "gid")) or includes(verbs, jget(a, "verb"))):
                continue
            items: List[Any] = []
            for x in req_list(jget(h, "adms")):
                xa = jget(x, "act")
                if ((includes(gids, jget(x, "gid")) or includes(verbs, jget(xa, "verb"))) and _in_scope(jget(b, "scope"), a, xa)
                        and _in_win(jget(b, "window"), a, xa)):
                    items.append(xa)
            items.append(a)
            cap = jget(b, "cap")
            agg = jget(b, "agg")
            if agg == "count":
                ex = _b2t(js_gt(len(items), jget(cap, "n")))
            elif agg == "sum" or agg == "max":
                xs: List[Any] = []
                ok = True
                for it in items:
                    val = _val(jget(b, "value"), it, h)
                    if not truthy(val) or jget(val, "k") != "q" or not _same_unit(jget(jget(val, "q"), "u"), jget(cap, "u")):
                        ok = False
                        break
                    xs.append(jget(jget(val, "q"), "n"))
                if not ok:
                    ex = 1
                elif agg == "sum":
                    ex = _b2t(js_gt(_fsum(xs), jget(cap, "n")))
                elif len(xs) == 0:
                    ex = 1
                else:
                    ns = [to_number(x) for x in xs]
                    ex = _b2t(js_gt(math.nan if any(n != n for n in ns) else max(ns), jget(cap, "n")))
            else:
                ks: List[str] = []
                ok = True
                key = jget(b, "key")
                for it in items:
                    ip = jget(it, "params")
                    if not _has(ip, key):
                        ok = False
                        break
                    ks.append(js_json(ip[key]))
                ex = _b2t(js_gt(len(set(ks)), jget(cap, "n"))) if ok else 1
            gd = min(gd, (0 if jget(b, "onExceed") == "deny" else 1) if ex == 2 else (1 if ex == 1 else 2))
        if gd == 2 and witness is None:
            witness = jget(gr, "gid")
        best = max(best, gd)
    d = min(d, best)
    return {"d": d, "witness": witness if d == 2 else None, "prohibit": prohibit}
