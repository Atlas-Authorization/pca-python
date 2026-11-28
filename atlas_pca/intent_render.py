"""Deterministic plain-language rendering and the back-translation diff. Every sentence is a fixed template over the
grant's own data (no language model anywhere); anything the templates do not know is rendered as an explicit "not
understood" line. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Sequence

from .intent_omega import cell_rep, decode_cell, num_cells, verb_cell_count
from .intent_policy import admitter, normalize_policy
from .intent_slots import slots_to_policy
from .intent_v2 import _UNDEF, _js_string
from .predicates import is_group_condition, is_leaf_condition


def _cat_get(catalog: Any, verb: str) -> Optional[dict]:
    from .analyzer_exposure import _catalog_get
    return _catalog_get(catalog, verb)


def _g(o: Any, k: str) -> Any:
    """o.k of a JSON value: undefined for a non-object, a TypeError for null (as the reference)."""
    if o is None:
        raise TypeError("cannot read properties of null (reading '%s')" % k)
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def label_of(path: str) -> str:
    if path == "action.resource":
        return "resource"
    return path.split(".")[-1].replace("_", " ")


def _fmt(v: Any) -> str:
    if isinstance(v, str):
        return '"%s"' % v
    if isinstance(v, list):
        return ", ".join(_fmt(x) for x in v)
    return _js_string(v)


def _arr(x: Any) -> List[Any]:
    if x is None or x is _UNDEF:
        return []
    if not isinstance(x, list):
        raise TypeError("map is not a function")
    return x


def render_condition(c: Any) -> str:
    if c is None or not isinstance(c, dict):
        return "an unreadable condition (not understood)"
    if is_group_condition(c):
        if "all_of" in c:
            return "all of: " + " and ".join("(%s)" % render_condition(x) for x in _arr(c["all_of"]))
        if "any_of" in c:
            return "either " + " or ".join("(%s)" % render_condition(x) for x in _arr(c["any_of"]))
        return "it is not the case that " + render_condition(c.get("not", _UNDEF))
    if not is_leaf_condition(c):
        return "an unreadable condition (not understood)"
    L = "the " + label_of(c["field"])
    V = "the " + label_of(c["ref"]) if "ref" in c else _fmt(c.get("value", _UNDEF))
    op = c.get("op", _UNDEF)
    T = {
        "eq": "%s is %s", "ne": "%s is not %s", "in": "%s is one of %s", "nin": "%s is none of %s", "lt": "%s is less than %s",
        "lte": "%s is at most %s", "gt": "%s is more than %s", "gte": "%s is at least %s", "prefix": "%s starts with %s",
        "like": "%s matches the pattern %s", "matches": "%s matches the regular expression %s", "is_a": "%s is of type %s",
        "member_of": "%s belongs to %s",
    }
    if isinstance(op, str) and op in T:
        return T[op] % (L, V)
    if op == "exists":
        return "%s is absent" % L if c.get("value", _UNDEF) is False else "%s is present" % L
    return '%s has an unrecognised test "%s" (not understood)' % (L, _js_string(op))


def _render_resource(r: Any) -> str:
    if r is _UNDEF or r == "*" and isinstance(r, str):
        return "on any resource"
    if not isinstance(r, str):
        return "on an unreadable resource matcher (not understood)"
    if r.startswith("re:"):
        return 'on resources matching the regular expression "%s"' % r[3:]
    if r.endswith("*"):
        return 'on resources under "%s"' % r[:-1]
    return 'only on resource "%s"' % r


def _lower_first(s: str) -> str:
    return s[:1].lower() + s[1:] if s and s[0] != "\n" else s


def _desc(s: dict) -> str:
    d = s["description"]
    return d[:-1] if d.endswith(".") else d


def _render_verb(v: Any, catalog: Any) -> str:
    def one(x: str) -> str:
        if x == "*":
            return "ANY action of any connector"
        s = _cat_get(catalog, x)
        if s:
            return "%s [%s, %s]" % (_lower_first(_desc(s)), x, s["reversibility"].replace("_", "-", 1))
        return '"%s" [uncatalogued: treated as irreversible]' % x
    if isinstance(v, list):
        return "; or ".join(one(_js_string(x)) for x in v)
    return one(_js_string(v))


def _iso(t: Any) -> str:
    """new Date(Number(t)).toISOString(); a RangeError (ValueError) for an invalid date."""
    while isinstance(t, list):  # Number([]) is 0 and Number([x]) is Number(String(x)); longer arrays are NaN
        if len(t) == 0:
            t = 0
        elif len(t) == 1 and not isinstance(t[0], (bool, dict)):
            t = t[0]
        else:
            raise ValueError("Invalid time value")
    if t is None:
        t = 0
    elif t is _UNDEF:
        raise ValueError("Invalid time value")
    elif isinstance(t, bool):
        t = 1 if t else 0
    elif isinstance(t, str):
        if "_" in t:
            raise ValueError("Invalid time value")
        try:
            t = float(t.strip()) if t.strip() else 0.0
        except ValueError:
            raise ValueError("Invalid time value")
    elif not isinstance(t, (int, float)):
        raise ValueError("Invalid time value")
    if t != t or abs(t) > 8.64e15:
        raise ValueError("Invalid time value")
    ms = int(t)  # TimeClip truncates toward zero
    days, rem = divmod(ms, 86400000)
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    if m <= 2:
        y += 1
    ys = "%04d" % y if 0 <= y <= 9999 else ("+" if y > 0 else "-") + "%06d" % abs(y)
    h, rem = divmod(rem, 3600000)
    mi, rem = divmod(rem, 60000)
    s, milli = divmod(rem, 1000)
    return "%s-%02d-%02dT%02d:%02d:%02d.%03dZ" % (ys, m, d, h, mi, s, milli)


def render_caveat(c: Any) -> str:
    t = c.get("type", _UNDEF) if isinstance(c, dict) else _UNDEF
    g = (lambda k: c.get(k, _UNDEF)) if isinstance(c, dict) else (lambda k: _UNDEF)
    if t == "expires":
        return "The grant expires at %s." % _iso(g("at"))
    if t == "not_before":
        return "The grant is not valid before %s." % _iso(g("at"))
    if t == "rate":
        return "At most %s actions in any %s seconds." % (_js_string(g("max")), _js_string(g("per_secs")))
    if t == "max_blast_radius":
        return "No action whose blast radius exceeds %s (on a 0–1 scale)." % _js_string(g("max"))
    if t == "reversibility_max":
        return 'Nothing more severe than "%s" (reversible < rate-limited < irreversible).' % _js_string(g("class")).replace("_", "-", 1)
    if t == "delegation_depth":
        return "It may be re-delegated at most %s level(s) deep." % _js_string(g("max"))
    if t == "budget_alloc":
        return "A trust-budget allocation of %s is carried for sub-delegation." % _js_string(g("limit"))
    return 'An unrecognised constraint of type "%s" (NOT UNDERSTOOD: do not rely on this grant until it is explained).' % _js_string(t)


def render_grant(policy: Any, catalog: Any = None) -> str:
    """Render a grant as numbered plain-language sentences. Deterministic: same grant, same text."""
    n = normalize_policy(policy)
    preds, caveats = n["predicates"], n["caveats"]
    if len(preds) == 0:
        return "This grant allows nothing."
    lines = ["The agent may do the following, and nothing else:"]
    for i, p in enumerate(preds):
        w = _g(p, "where")
        conds = [render_condition(x) for x in _arr(w)]
        lines.append("%d. %s, %s%s." % (i + 1, _render_verb(_g(p, "verb"), catalog), _render_resource(_g(p, "resource")),
                                       ", only when " + ", and ".join(conds) if conds else ""))
    if caveats:
        lines.append("Limits that apply to everything above:")
        for c in caveats:
            lines.append("- " + render_caveat(c))
    return "\n".join(lines)


def _render_dim_cell(d: dict, i: int) -> str:
    L = label_of(d["path"])
    if d["kind"] == "num":
        c = num_cells(d)[i]
        if c["lo"] == c["hi"]:
            return "%s exactly %s" % (L, _js_string(c["lo"]))
        return "any %s from %s to %s (e.g. %s)" % (L, _js_string(c["lo"]), _js_string(c["hi"]), _js_string(c["lo"] if i > 0 else c["hi"]))
    v = d["values"][i]
    if v["kind"] == "exact":
        return '%s "%s"' % (L, v["value"])
    if v["kind"] == "prefix":
        return 'a %s under "%s" (not otherwise named)' % (L, v["value"])
    return "a %s not named anywhere in the grant or your request" % L


def render_question(vs: dict, cell: Sequence[int], catalog: Any = None) -> str:
    s = _cat_get(catalog, vs["verb"])
    what = "%s [%s]" % (_desc(s), vs["verb"]) if s else 'perform "%s"' % vs["verb"]
    parts = [_render_dim_cell(d, cell[k]) for k, d in enumerate(vs["dims"])]
    return "Should the agent be allowed to: %s%s?" % (what, ", with " + ", ".join(parts) if parts else "")


# ---- back-translation diff -----------------------------------------------------------------------------------------

def claims_of(policy: Any, omega: dict) -> List[dict]:
    """The claim IR of a policy over the outcome space: verb by verb and dimension by dimension."""
    a = admitter(policy)
    out = []
    for vs in omega["verbs"]:
        n = verb_cell_count(vs)
        acc: List[List[int]] = []
        for c in range(n):
            idx = decode_cell(vs, c)
            if a.admits(vs, cell_rep(vs, idx)):
                acc.append(idx)
        proj = [set(x[k] for x in acc) for k in range(len(vs["dims"]))]
        box_count = 1
        for s in proj:
            box_count *= len(s)
        dims = []
        for k, d in enumerate(vs["dims"]):
            s = proj[k]
            total = len(num_cells(d)) if d["kind"] == "num" else len(d["values"])
            ids = sorted(s)
            if d["kind"] == "num":
                cells = num_cells(d)
                dc: Dict[str, Any] = {"path": d["path"], "any": len(s) == total}
                if ids:
                    dc["range"] = [cells[ids[0]]["lo"], cells[ids[-1]]["hi"]]
                dims.append(dc)
            else:
                dims.append({"path": d["path"], "any": len(s) == total,
                             "values": [d["values"][i]["value"] + "*" if d["values"][i]["kind"] == "prefix" else d["values"][i]["value"] for i in ids]})
        out.append({"verb": vs["verb"], "allowed": len(acc) > 0, "boxShaped": len(acc) == box_count, "dims": dims})
    return out


def _dim_text(c: Optional[dict]) -> str:
    if not c:
        return "anything"
    if c["any"]:
        return "any value"
    if "range" in c:
        return "%s to %s" % (_js_string(c["range"][0]), _js_string(c["range"][1]))
    return ", ".join(c["values"]) if c.get("values") else "nothing"


def _diff_claims(g: List[dict], s: List[dict], w: dict) -> List[dict]:
    out: List[dict] = []
    for i, gc in enumerate(g):
        sc = s[i]
        if gc["allowed"] and not sc["allowed"]:
            out.append({"verb": gc["verb"], "kind": "extra-verb", "text": w["extra"](gc["verb"])})
            continue
        if not gc["allowed"] and sc["allowed"]:
            out.append({"verb": gc["verb"], "kind": "missing-verb", "text": w["missing"](gc["verb"])})
            continue
        if not gc["allowed"]:
            continue
        if (not gc["boxShaped"] or not sc["boxShaped"]) and gc["boxShaped"] != sc["boxShaped"]:
            out.append({"verb": gc["verb"], "kind": "shape", "text": w["shape"](gc["verb"])})
        for k, gd in enumerate(gc["dims"]):
            sd = sc["dims"][k]
            if gd == sd:
                continue
            kind = "different"
            if "range" in gd and "range" in sd:
                gr, sr = gd["range"], sd["range"]
                kind = "looser" if gr[0] <= sr[0] and gr[1] >= sr[1] else "tighter" if gr[0] >= sr[0] and gr[1] <= sr[1] else "different"
            elif "values" in gd and "values" in sd:
                kind = "looser" if all(v in gd["values"] for v in sd["values"]) else "tighter" if all(v in sd["values"] for v in gd["values"]) else "different"
            elif gd["any"] and not sd["any"]:
                kind = "looser"
            out.append({"verb": gc["verb"], "kind": kind, "path": gd["path"], "text": w["dim"](gc["verb"], gd["path"], _dim_text(gd), _dim_text(sd))})
    return out


def back_translation_diff(grant: Any, slots: dict, omega: dict) -> List[dict]:
    """Render the grant and the intent slots into the same claim IR and list every difference."""
    return _diff_claims(claims_of(grant, omega), claims_of(slots_to_policy(slots), omega), {
        "extra": lambda v: "The grant allows %s, which your request did not mention." % v,
        "missing": lambda v: "Your request mentions %s, but the grant does not allow it." % v,
        "shape": lambda v: "The grant's rule for %s is a combination of cases that your request did not describe." % v,
        "dim": lambda v, path, a, b: "For %s, the grant allows %s %s; your request said %s." % (v, label_of(path), a, b),
    })


def claim_diff(a: Any, b: Any, omega: dict, names: Sequence[str] = ("the first reading", "the second reading")) -> List[dict]:
    """The same claim diff between two grants (two readings); kind is from a's point of view."""
    n0, n1 = names[0], names[1]
    return _diff_claims(claims_of(a, omega), claims_of(b, omega), {
        "extra": lambda v: "%s allows %s; %s does not." % (n0, v, n1),
        "missing": lambda v: "%s allows %s; %s does not." % (n1, v, n0),
        "shape": lambda v: "%s and %s describe %s with differently shaped rules." % (n0, n1, v),
        "dim": lambda v, path, x, y: "For %s, %s allows %s %s; %s allows %s." % (v, n0, label_of(path), x, n1, y),
    })


def render_action(vs: dict, values: dict, catalog: Any = None) -> str:
    """A concrete action in plain language; values are printed verbatim so nothing is hidden."""
    s = _cat_get(catalog, vs["verb"])
    rev = _js_string(vs.get("reversibility", _UNDEF)).replace("_", "-", 1)
    what = "%s [%s, %s]" % (_desc(s), vs["verb"], rev) if s else 'perform "%s" [uncatalogued: treated as irreversible]' % vs["verb"]
    from .intent_omega import u16key
    parts = []
    for k in sorted(values, key=u16key):
        v = values[k]
        parts.append("%s %s" % (label_of(k), '"%s"' % v if isinstance(v, str) else _js_string(v)))
    return "The agent wants to: %s%s." % (what, ", with " + ", ".join(parts) if parts else "")
