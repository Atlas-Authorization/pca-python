"""N-version interpretation: the enforced policy is the semantic meet of the readings (the TypeScript reference is
@atlasauth/pca-goal `nversion`). Allow(meet gs) a implies Allow(g) a for every g in gs. Grants are the cross product of the readings'
grants on equal verbs (a merged grant is named `x&y&z`), resources intersect through `all_of`, conditions conjoin; a bound of one reading
counts the actions admitted by the merged grants derived from the grants that bound selected."""
from typing import Any, Dict, List, Optional, Sequence

from .analyzer_js import UNDEF, includes, jget, js_str, req_list, strict_eq, truthy, u16key
from .goal_normalize import canonicalize_goal, stable

__all__ = ["meet_grants", "meet", "check_panel", "n_version"]


def _parts_of(s: Any) -> list:
    k = jget(s, "k")
    return req_list(jget(s, "parts")) if k == "all_of" else ([] if k == "any" else [s])


def _intersect(a: Any, b: Any) -> Any:
    if jget(a, "k") == "any":
        return b
    if jget(b, "k") == "any":
        return a
    m: Dict[str, Any] = {}
    for p in _parts_of(a) + _parts_of(b):
        m[stable(p)] = p
    uniq = list(m.values())
    return uniq[0] if len(uniq) == 1 else {"k": "all_of", "parts": uniq}


def _conj(a: Any, b: Any) -> Any:
    if jget(a, "k") == "true":
        return b
    return a if jget(b, "k") == "true" else {"k": "and", "a": a, "b": b}


def _cross(a: List[dict], b: List[dict]) -> List[dict]:
    out = []
    for x in a:
        for y in b:
            if strict_eq(jget(x["g"], "verb"), jget(y["g"], "verb")):
                out.append({"g": {"gid": "%s&%s" % (js_str(jget(x["g"], "gid")), js_str(jget(y["g"], "gid"))), "verb": jget(x["g"], "verb"),
                                  "res": _intersect(jget(x["g"], "res"), jget(y["g"], "res")), "cond": _conj(jget(x["g"], "cond"), jget(y["g"], "cond"))},
                            "from": x["from"] + y["from"]})
    return out


def meet_grants(a: Sequence[Any], b: Sequence[Any]) -> List[Any]:
    """Cross product on equal verbs, resource intersection, conjoined conditions."""
    return [t["g"] for t in _cross([{"g": g, "from": [jget(g, "gid")]} for g in req_list(a)], [{"g": g, "from": [jget(g, "gid")]} for g in req_list(b)])]


def _sorted(xs: list) -> list:
    return sorted(xs, key=lambda x: u16key(js_str(x)))


def meet(goals: Sequence[Any]) -> Dict[str, Any]:
    """The semantic meet of readings that share principal, ontology and text."""
    goals = req_list(goals)
    if len(goals) == 0:
        raise ValueError("meet: no goals")
    first = goals[0]
    for g in goals:
        if (not strict_eq(jget(g, "principal"), jget(first, "principal")) or not strict_eq(jget(g, "ontDigest"), jget(first, "ontDigest"))
                or not strict_eq(jget(g, "nlDigest"), jget(first, "nlDigest"))):
            raise ValueError("meet: readings must share principal, ontology and text")
    if len(goals) == 1:
        return first
    tracked = [{"g": g, "from": [jget(g, "gid")]} for g in req_list(jget(first, "grants"))]
    for g in goals[1:]:
        tracked = _cross(tracked, [{"g": x, "from": [jget(x, "gid")]} for x in req_list(jget(g, "grants"))])
    grants = [t["g"] for t in tracked]

    def derived(i: int, gids: Any) -> list:
        return [t["g"]["gid"] for t in tracked if includes(gids, t["from"][i])]

    prohibits: List[Any] = []
    pseen: Dict[str, Any] = {}
    for i, g in enumerate(goals):
        for p in req_list(jget(g, "prohibits")):
            body = stable(dict(p, pid=""))
            if body in pseen:
                continue
            taken = any(strict_eq(v, jget(p, "pid")) for v in pseen.values())
            pseen[body] = jget(p, "pid")
            prohibits.append(dict(p, pid="%s#%d" % (js_str(jget(p, "pid")), i)) if taken else p)
    bounds: List[Any] = []
    bseen: Dict[str, Any] = {}
    for i, g in enumerate(goals):
        for b in req_list(jget(g, "bounds")):
            bsel = jget(b, "sel")
            sel = {"k": "gids", "gids": _sorted(derived(i, jget(bsel, "gids")))} if jget(bsel, "k") == "gids" else bsel
            if jget(sel, "k") == "gids" and len(sel["gids"]) == 0:
                continue  # no merged grant derives from the selected grants: nothing to count
            cap = jget(b, "cap")
            key = stable({"sel": sel, "agg": jget(b, "agg"), "value": jget(b, "value"), "key": jget(b, "key"), "window": jget(b, "window"),
                          "scope": jget(b, "scope"), "unit": jget(cap, "u")})
            prev = bseen.get(key)
            if prev is not None:  # the same aggregate over the same counted grants in several readings: the minimum cap, the stricter exceed action
                if jget(cap, "n") < jget(prev["cap"], "n"):
                    prev["cap"] = cap
                if jget(b, "onExceed") == "deny":
                    prev["onExceed"] = "deny"
                continue
            nb = dict(b, sel=sel, bid="%s#%d" % (js_str(jget(b, "bid")), i) if any(strict_eq(x["bid"], jget(b, "bid")) for x in bounds) else jget(b, "bid"))
            bounds.append(nb)
            bseen[key] = nb
    esc: Dict[str, Any] = {}
    for g in goals:
        for c in req_list(jget(g, "escalateOn")):
            esc[stable(c)] = c
    idle = [jget(jget(g, "validity"), "maxIdle") for g in goals]
    idle = [x for x in idle if x > 0]
    touch = [t["g"]["gid"] for t in tracked if all(includes(jget(jget(g, "deleg"), "mayTouch"), t["from"][i]) for i, g in enumerate(goals))]

    def ack_ok(g: Any, i: int, t: dict) -> bool:
        x = next((x for x in req_list(jget(g, "grants")) if strict_eq(jget(x, "gid"), t["from"][i])), None)
        return (x is None or jget(jget(x, "res"), "k") != "any") or includes(jget(g, "wildcardAck"), t["from"][i])

    ack = [t["g"]["gid"] for t in tracked if jget(t["g"]["res"], "k") == "any" and all(ack_ok(g, i, t) for i, g in enumerate(goals))]
    holes: Dict[Any, Any] = {}
    for i, g in enumerate(goals):
        for h in req_list(jget(g, "holes")):
            prev = holes.get(jget(h, "hid"))
            affects = _sorted(list(dict.fromkeys((jget(prev, "affects") if prev is not None else []) + derived(i, jget(h, "affects")))))
            gl = jget(h, "global")
            holes[jget(h, "hid")] = dict(h, affects=affects, **{"global": gl if truthy(gl) else (jget(prev, "global") if prev is not None else False)})
    sources: List[Any] = []
    for g in goals:
        sources += req_list(jget(g, "sources"))
    vs = [jget(g, "validity") for g in goals]
    return canonicalize_goal(dict(
        first, grants=grants, prohibits=prohibits, bounds=bounds, escalateOn=list(esc.values()), sources=list(dict.fromkeys(sources)),
        validity={"notBefore": max(jget(v, "notBefore") for v in vs), "notAfter": min(jget(v, "notAfter") for v in vs), "maxIdle": min(idle) if idle else 0},
        deleg={"maxDepth": min(jget(jget(g, "deleg"), "maxDepth") for g in goals), "narrowOnly": True, "mayTouch": touch},
        holes=list(holes.values()), wildcardAck=ack))


def check_panel(readings: Sequence[Any]) -> List[Dict[str, str]]:
    """Panel requirements: k >= 3, at least one deterministic non-LLM interpreter, at least two distinct model families."""
    out: List[Dict[str, str]] = []
    if len(readings) < 3:
        out.append({"code": "too_few", "msg": "need at least 3 interpreters"})
    if not any(truthy(jget(r, "deterministic")) for r in readings):
        out.append({"code": "no_deterministic", "msg": "need at least one deterministic template interpreter"})
    if len(set(jget(r, "family") for r in readings if not truthy(jget(r, "deterministic")))) < 2:
        out.append({"code": "no_family_diversity", "msg": "need at least two distinct model families"})
    return out


def n_version(readings: Sequence[Any], opts: Dict[str, Any]) -> Dict[str, Any]:
    """`opts`: the question options plus `massThreshold`. Auto-signable only when the panel is valid and no hole remains."""
    from .goal_disambiguate import disagreement_mass, questions
    merged = meet([r["goal"] for r in readings])
    panel_issues = check_panel(readings)
    verb_sets = [set(g["verb"] for g in r["goal"]["grants"]) for r in readings]
    all_verbs = set(v for s in verb_sets for v in s)
    holes: List[Dict[str, Any]] = []
    for v in sorted(all_verbs, key=u16key):
        if any(v not in s for s in verb_sets):
            holes.append({"hid": "nv:verb:%s" % v, "q": 'Only some readings allow "%s". Should it be allowed at all?' % v, "domain": [], "affects": [], "global": False})
    mass = disagreement_mass(readings, opts["ont"])
    thr = opts.get("massThreshold")
    if mass > (0 if thr is None else thr):
        qs = questions(readings, opts)
        holes.append({"hid": "nv:split", "q": qs[0]["text"] if qs else "The readings disagree.", "domain": [], "affects": [], "global": True})
    all_h = list(merged["holes"]) + holes
    by_hid: Dict[Any, Any] = {}
    for h in all_h:
        by_hid[h["hid"]] = h
    return {"merged": canonicalize_goal(dict(merged, holes=list(by_hid.values()))), "panelIssues": panel_issues, "disagreementHoles": holes, "mass": mass,
            "signable": len(panel_issues) == 0 and len(all_h) == 0}
