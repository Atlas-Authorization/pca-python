"""The human-readable PolicyCard text: a fixed phrase table over the IR, every clause with its exact numbers (the TypeScript
reference is @atlasauth/pca-goal `card`). Two different goals never print the same card."""
from typing import Any, Dict, List

from .analyzer_js import UNDEF, includes, jget, js_gt, js_str, req_list
from .goal_normalize import jq

__all__ = ["q", "unit", "quantity", "value", "term", "cond", "res", "win", "scope", "grant_line", "prohibit_line", "bound_line",
           "validity_line", "delegation_line", "escalate_line", "hole_line", "render_card"]

_OPW = {"eq": "=", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "in": "is one of", "nin": "is none of"}


def q(x: Any) -> str:
    return "undefined" if x is UNDEF else jq(x)


def unit(u: Any) -> str:
    return "%s minor units" % js_str(jget(u, "ccy")) if jget(u, "k") == "money" else js_str(jget(u, "k"))


def quantity(x: Any) -> str:
    return "%s %s" % (js_str(jget(x, "n")), unit(jget(x, "u")))


def value(v: Any) -> str:
    k = jget(v, "k")
    if k == "q":
        return quantity(jget(v, "q"))
    if k == "s":
        return q(jget(v, "s"))
    return "{" + ", ".join(value(i) for i in req_list(jget(v, "items"))) + "}"


def term(t: Any) -> str:
    k = jget(t, "k")
    if k == "param":
        ty = jget(t, "ty")
        return "param %s (%s)" % (q(jget(t, "path")), unit(jget(ty, "u")) if jget(ty, "k") == "q" else "text")
    if k == "lit":
        return value(jget(t, "v"))
    return "running total of bound %s (%s)" % (q(jget(t, "bid")), unit(jget(t, "u")))


def cond(c: Any) -> str:
    k = jget(c, "k")
    if k == "true":
        return "always"
    if k == "cmp":
        op = jget(c, "op")
        return "%s %s %s" % (term(jget(c, "l")), _OPW[op] if isinstance(op, str) and op in _OPW else "undefined", term(jget(c, "r")))
    if k == "and":
        return "(%s) AND (%s)" % (cond(jget(c, "a")), cond(jget(c, "b")))
    if k == "or":
        return "(%s) OR (%s)" % (cond(jget(c, "a")), cond(jget(c, "b")))
    if k == "not":
        return "NOT (%s)" % cond(jget(c, "c"))
    return "undefined"  # the reference switch has no default


def res(s: Any) -> str:
    k = jget(s, "k")
    if k == "exact":
        return "exactly %s" % q(jget(s, "id"))
    if k == "oneof":
        return "one of [%s]" % ", ".join(q(i) for i in req_list(jget(s, "ids")))
    if k == "related":
        return "%s of %s" % (js_str(jget(s, "rel")), q(jget(s, "anchor")))
    if k == "all_of":
        return "ALL OF (%s)" % " AND ".join(res(p) for p in req_list(jget(s, "parts")))
    return "ANY RESOURCE (reason: %s)" % q(jget(s, "reason"))


def win(w: Any) -> str:
    k = jget(w, "k")
    if k == "task":
        return "per task"
    if k == "lifetime":
        return "over the lifetime"
    if k == "sliding":
        return "in any %s ms window" % js_str(jget(w, "ms"))
    return "per %s ms period starting at %s" % (js_str(jget(w, "ms")), js_str(jget(w, "t0")))


def scope(s: Any) -> str:
    if jget(s, "k") == "fleet":
        return "fleet [%s]" % ", ".join(q(a) for a in req_list(jget(s, "agents")))
    return js_str(jget(s, "k"))


def grant_line(x: Any) -> str:
    return "ALLOW %s: verb %s on %s when %s" % (q(jget(x, "gid")), q(jget(x, "verb")), res(jget(x, "res")), cond(jget(x, "cond")))


def prohibit_line(x: Any) -> str:
    t = jget(x, "target")
    tgt = "verb %s" % q(jget(t, "verb")) if jget(t, "k") == "verb" else "every verb of effect class %s" % q(jget(t, "cls"))
    return "NEVER %s: %s on %s when %s" % (q(jget(x, "pid")), tgt, res(jget(x, "res")), cond(jget(x, "cond")))


def bound_line(b: Any) -> str:
    sel = jget(b, "sel")
    over = ("grants [%s]" % ", ".join(q(g) for g in req_list(jget(sel, "gids")))) if jget(sel, "k") == "gids" else "effect class %s" % q(jget(sel, "cls"))
    agg = jget(b, "agg")
    mid = "" if agg == "count" else (" of %s" % q(jget(b, "key")) if agg == "distinct" else " of %s" % term(jget(b, "value")))
    exc = "deny" if jget(b, "onExceed") == "deny" else "ask the principal"
    return "LIMIT %s: %s%s over %s, %s, scope %s, at most %s; beyond that: %s" % (
        q(jget(b, "bid")), js_str(agg), mid, over, win(jget(b, "window")), scope(jget(b, "scope")), quantity(jget(b, "cap")), exc)


def validity_line(v: Any) -> str:
    mi = jget(v, "maxIdle")
    return "VALID from %s to %s; idle limit %s" % (js_str(jget(v, "notBefore")), js_str(jget(v, "notAfter")),
                                                    "%s ms" % js_str(mi) if js_gt(mi, 0) else "none")


def delegation_line(d: Any) -> str:
    return "DELEGATION depth at most %s, narrow only %s, delegates may use grants [%s]" % (
        js_str(jget(d, "maxDepth")), js_str(jget(d, "narrowOnly")), ", ".join(q(g) for g in req_list(jget(d, "mayTouch"))))


def escalate_line(c: Any) -> str:
    return "ASK THE PRINCIPAL when %s" % cond(c)


def hole_line(h: Any) -> str:
    from .analyzer_js import truthy
    aff = "everything" if truthy(jget(h, "global")) else "[%s]" % ", ".join(q(a) for a in req_list(jget(h, "affects")))
    return "UNRESOLVED %s: %s options [%s] affects %s" % (q(jget(h, "hid")), q(jget(h, "q")), ", ".join(q(d) for d in req_list(jget(h, "domain"))), aff)


def render_card(g: Any) -> Dict[str, List[str]]:
    """One line per clause, in the goal's canonical order; `warnings` lists what the principal must look at twice."""
    lines: List[str] = ["Goal v%s for principal %s; ontology %s; request text digest %s" % (
        js_str(jget(g, "v")), q(jget(g, "principal")), q(jget(g, "ontDigest")), q(jget(g, "nlDigest")))]
    warnings: List[str] = []
    for s in req_list(jget(g, "sources")):
        lines.append("Source %s" % q(s))
    for x in req_list(jget(g, "grants")):
        lines.append(grant_line(x))
        if jget(jget(x, "res"), "k") == "any":
            ack = includes(jget(g, "wildcardAck"), jget(x, "gid"))
            warnings.append("grant %s applies to every resource%s" % (q(jget(x, "gid")), " (acknowledged)" if ack else " (NOT acknowledged)"))
    for x in req_list(jget(g, "prohibits")):
        lines.append(prohibit_line(x))
    for b in req_list(jget(g, "bounds")):
        lines.append(bound_line(b))
    lines.append(validity_line(jget(g, "validity")))
    lines.append(delegation_line(jget(g, "deleg")))
    for c in req_list(jget(g, "escalateOn")):
        lines.append(escalate_line(c))
    for a in req_list(jget(g, "wildcardAck")):
        lines.append("Wildcard acknowledged for %s" % q(a))
    for h in req_list(jget(g, "holes")):
        lines.append(hole_line(h))
    if len(req_list(jget(g, "holes"))) > 0:
        warnings.append("this goal has unresolved questions and cannot be signed")
    return {"lines": lines, "warnings": warnings}
