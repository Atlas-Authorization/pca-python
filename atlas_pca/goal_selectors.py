"""Trait selectors and role-addressed parameters for the Goal IR (the TypeScript reference is @atlasauth/pca-goal `selectors`). A
selector goal ("SelGoal") names a verb or a trait class in its grants, prohibitions and bounds, and may name a parameter by ROLE; it is
lowered against the PINNED catalog to an ordinary goal (one grant per verb). Fail-closed rules: a grant verb with no unique parameter of
a named role is dropped from the grant (reported); a prohibition whose role term is unresolved for a verb applies to that verb
unconditionally; a bound whose role value cannot be resolved for every selected verb is a type error; an allow selector is positive
(no `none_of`, at least one trait); an unconfirmed verb carries `pca.unreviewed`: a class ALLOW never covers it, a class prohibition or
bound over a trait selector ALWAYS covers it; an unknown trait id is a type error. The typed front door of the proved compiler
(`compileSelGoal`) needs the verified core and is not native."""
import re
from functools import cmp_to_key
from typing import Any, Dict, List, Optional, Sequence

from .actions import CORE_REGISTRY, closure, effective
from .actions_builtin import CORE_PACK_DEFS, DOMAIN_VERBS, domain_roles
from .analyzer_js import UNDEF, includes, jget, js_json, js_str, req_list, strict_eq, u16key
from .goal_card import render_card
from .goal_normalize import jq
from .pca import hash_canonical

__all__ = [
    "sel_catalog_of_defs", "sel_catalog_of_domain", "sel_catalog_digest", "sel_goal_digest", "class_verbs", "UNREVIEWED", "allow_class_verbs",
    "float_class_verbs", "resolve_role", "expand_sel_goal", "SEL_ID_RE", "sel_reasons", "with_role_params", "render_sel_card", "trait_closure",
    "sel_carrier", "encode_sel_catalog", "compile_sel_goal",
]

UNREVIEWED = "pca.unreviewed"
SEL_ID_RE = re.compile("[0-9A-Za-z_]{1,64}")


def _by_str(a: str, b: str) -> int:
    x, y = u16key(a), u16key(b)
    return -1 if x < y else (1 if x > y else 0)


def sel_catalog_of_defs(defs: Sequence[dict], reg: Optional[dict] = None, review: Any = None) -> Dict[str, Any]:
    """The catalog of a pack of defs (verb ids and parameter paths are the defs' own): `{known, verbs}`."""
    reg = CORE_REGISTRY if reg is None else reg
    verbs = []
    for d in defs:
        roles: Dict[str, List[str]] = {}
        for name in sorted(d["params"], key=u16key):
            r = d["params"][name].get("role")
            if r is not None:
                roles.setdefault(r, []).append(name)
        verbs.append({"verb": d["verb"], "traits": effective(d, reg, review)["closure"], "roles": roles})
    verbs.sort(key=cmp_to_key(lambda a, b: _by_str(a["verb"], b["verb"])))
    return {"known": sorted(reg.keys(), key=u16key), "verbs": verbs}


def sel_catalog_of_domain(domain: str, reg: Optional[dict] = None, review: Any = None) -> Dict[str, Any]:
    """The catalog of one domain ontology: the NL short ids and NL parameter names, with the traits of the defs behind them."""
    reg = CORE_REGISTRY if reg is None else reg
    roles = domain_roles(domain)
    verbs = []
    for b in DOMAIN_VERBS[domain]:
        d = next(x for x in CORE_PACK_DEFS if x["verb"] == b["verb"])
        verbs.append({"verb": b["id"], "traits": effective(d, reg, review)["closure"], "roles": roles.get(b["id"], {})})
    verbs.sort(key=cmp_to_key(lambda a, b: _by_str(a["verb"], b["verb"])))
    return {"known": sorted(reg.keys(), key=u16key), "verbs": verbs}


def sel_catalog_digest(c: Any) -> str:
    """Digest of the catalog (what `SelGoal.catDigest` must equal)."""
    return hash_canonical({"d": "atlas-pca/goal-sel-catalog/v1", "catalog": c})


def sel_goal_digest(g: Any) -> str:
    return hash_canonical({"d": "atlas-pca/goal-ir-sel/v1", "goal": g})


# ---- G-A4: the verbs of a Class selector ------------------------------------------------------------------------------------------

def _has_all(ts: Any, req: Any) -> bool:
    return all(includes(ts, t) for t in req_list(req))


def _has_none(ts: Any, ex: Any) -> bool:
    return all(not includes(ts, t) for t in req_list(ex))


def class_verbs(cat: Any, all_of: Any, none_of: Any) -> List[str]:
    """The verbs of the catalog, in catalog order, whose trait closure contains every `all_of` trait and none of the `none_of` traits."""
    return [jget(v, "verb") for v in req_list(jget(cat, "verbs")) if _has_all(jget(v, "traits"), all_of) and _has_none(jget(v, "traits"), none_of)]


def allow_class_verbs(cat: Any, all_of: Any, none_of: Any) -> List[str]:
    """The verbs a class ALLOW covers: the class, minus every unconfirmed verb."""
    return class_verbs(cat, all_of, list(req_list(none_of)) + [UNREVIEWED])


def float_class_verbs(cat: Any, all_of: Any, none_of: Any) -> List[str]:
    """The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says."""
    return [jget(v, "verb") for v in req_list(jget(cat, "verbs"))
            if includes(jget(v, "traits"), UNREVIEWED) or (_has_all(jget(v, "traits"), all_of) and _has_none(jget(v, "traits"), none_of))]


# ---- role resolution --------------------------------------------------------------------------------------------------------------

def _decl_of(ont: Any, verb: Any) -> Any:
    return next((v for v in req_list(jget(ont, "verbs")) if strict_eq(jget(v, "verb"), verb)), None)


def _info_of(cat: Any, verb: Any) -> Any:
    return next((v for v in req_list(jget(cat, "verbs")) if strict_eq(jget(v, "verb"), verb)), None)


def resolve_role(ont: Any, cat: Any, verb: Any, role: Any) -> Optional[Dict[str, Any]]:
    """The one parameter of `verb` carrying `role`, with its declared type; none, several or undeclared: None."""
    info, decl = _info_of(cat, verb), _decl_of(ont, verb)
    if info is None or decl is None:
        return None
    roles = jget(info, "roles")
    paths = roles[role] if isinstance(roles, dict) and isinstance(role, str) and role in roles else []
    if len(paths) != 1:
        return None
    p = next((x for x in req_list(jget(decl, "params")) if strict_eq(jget(x, "path"), paths[0])), None)
    return {"path": jget(p, "path"), "ty": jget(p, "ty")} if p is not None else None


def _resolve_term(ont: Any, cat: Any, verb: Any, t: Any) -> Any:
    k = jget(t, "k")
    if k == "param":
        return {"k": "param", "path": jget(t, "path"), "ty": jget(t, "ty")}
    if k == "lit":
        return {"k": "lit", "v": jget(t, "v")}
    if k == "hist":
        return {"k": "hist", "bid": jget(t, "bid"), "u": jget(t, "u")}
    if k == "role":
        r = resolve_role(ont, cat, verb, jget(t, "role"))
        return {"k": "param", "path": r["path"], "ty": r["ty"]} if r else None
    return None


def _resolve_cond(ont: Any, cat: Any, verb: Any, c: Any) -> Any:
    """None as soon as one role term is unresolved for the verb."""
    k = jget(c, "k")
    if k == "true":
        return {"k": "true"}
    if k == "cmp":
        l, r = _resolve_term(ont, cat, verb, jget(c, "l")), _resolve_term(ont, cat, verb, jget(c, "r"))
        return {"k": "cmp", "op": jget(c, "op"), "l": l, "r": r} if l and r else None
    if k == "and" or k == "or":
        a, b = _resolve_cond(ont, cat, verb, jget(c, "a")), _resolve_cond(ont, cat, verb, jget(c, "b"))
        return {"k": k, "a": a, "b": b} if a and b else None
    if k == "not":
        a = _resolve_cond(ont, cat, verb, jget(c, "c"))
        return {"k": "not", "c": a} if a else None
    return None


# ---- the expansion ------------------------------------------------------------------------------------------------------------------

def _grant_verbs(cat: Any, s: Any) -> List[Any]:
    return [jget(s, "verb")] if jget(s, "k") == "verb" else allow_class_verbs(cat, jget(s, "all_of"), jget(s, "none_of"))


def _expand_grants(ont: Any, cat: Any, gs: Any, report: dict) -> List[dict]:
    out = []
    for gr in req_list(gs):
        sel = jget(gr, "sel")
        verbs = _grant_verbs(cat, sel)
        dropped = []
        for v in verbs:
            c = _resolve_cond(ont, cat, v, jget(gr, "cond"))
            if c is None:
                dropped.append({"verb": v, "reason": "role_unresolved"})
                continue
            out.append({"src": jget(gr, "gid"), "g": {"gid": "%s.%s" % (js_str(jget(gr, "gid")), js_str(v)) if jget(sel, "k") == "class" else jget(gr, "gid"),
                                                       "verb": v, "res": jget(gr, "res"), "cond": c}})
        report["grants"].append({"gid": jget(gr, "gid"), "verbs": verbs, "dropped": dropped})
    return out


def _proh_verbs(ont: Any, cat: Any, t: Any) -> List[Any]:
    k = jget(t, "k")
    if k == "verb":
        return [jget(t, "verb")]
    if k == "effect":
        return [jget(v, "verb") for v in req_list(jget(ont, "verbs")) if strict_eq(jget(v, "cls"), jget(t, "cls"))]
    return float_class_verbs(cat, jget(t, "all_of"), jget(t, "none_of"))


def _expand_prohibits(ont: Any, cat: Any, ps: Any, report: dict) -> List[dict]:
    out = []
    for p in req_list(ps):
        target = jget(p, "target")
        verbs = _proh_verbs(ont, cat, target)
        unconditional = []
        for v in verbs:
            c = _resolve_cond(ont, cat, v, jget(p, "cond"))
            if c is None:
                unconditional.append(v)
            out.append({"pid": jget(p, "pid") if jget(target, "k") == "verb" else "%s.%s" % (js_str(jget(p, "pid")), js_str(v)),
                        "target": {"k": "verb", "verb": v}, "res": jget(p, "res"), "cond": {"k": "true"} if c is None else c})
        report["prohibits"].append({"pid": jget(p, "pid"), "verbs": verbs, "unconditional": unconditional})
    return out


def _ids_of(es: List[dict], srcs: Any) -> list:
    return [e["g"]["gid"] for e in es if includes(srcs, e["src"])]


def _gids_of_verbs(es: List[dict], vs: Any) -> list:
    return [e["g"]["gid"] for e in es if includes(vs, e["g"]["verb"])]


def _verbs_of_gids(es: List[dict], gids: Any) -> list:
    return [e["g"]["verb"] for e in es if includes(gids, e["g"]["gid"])]


def _bound_role_verbs(ont: Any, cat: Any, es: List[dict], s: Any) -> list:
    k = jget(s, "k")
    if k == "gids":
        return _verbs_of_gids(es, _ids_of(es, jget(s, "gids")))
    if k == "effect":
        return [jget(v, "verb") for v in req_list(jget(ont, "verbs")) if strict_eq(jget(v, "cls"), jget(s, "cls"))]
    return _verbs_of_gids(es, _gids_of_verbs(es, float_class_verbs(cat, jget(s, "all_of"), jget(s, "none_of"))))


def _bound_value(ont: Any, cat: Any, vs: Sequence[Any], t: Any) -> Optional[Dict[str, Any]]:
    """One value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` when the paths differ but the type is one."""
    k = jget(t, "k")
    if k == "param":
        return {"term": {"k": "param", "path": jget(t, "path"), "ty": jget(t, "ty")}, "how": "literal"}
    if k == "lit":
        return {"term": {"k": "lit", "v": jget(t, "v")}, "how": "literal"}
    if k == "hist":
        return {"term": {"k": "hist", "bid": jget(t, "bid"), "u": jget(t, "u")}, "how": "literal"}
    if k == "role":
        rs = []
        for v in vs:
            r = resolve_role(ont, cat, v, jget(t, "role"))
            if not r:
                return None
            rs.append(r)
        if len(rs) == 0:
            return None
        same = lambda a, b: js_json(a) == js_json(b)  # noqa: E731
        if all(r["path"] == rs[0]["path"] and same(r["ty"], rs[0]["ty"]) for r in rs):
            return {"term": {"k": "param", "path": rs[0]["path"], "ty": rs[0]["ty"]}, "how": "shared_path"}
        if all(same(r["ty"], rs[0]["ty"]) for r in rs):
            return {"term": {"k": "param", "path": "@%s" % js_str(jget(t, "role")), "ty": rs[0]["ty"]}, "how": "role_key"}
    return None


def _expand_bounds(ont: Any, cat: Any, es: List[dict], bs: Any, report: dict) -> List[dict]:
    out = []
    for b in req_list(bs):
        bsel = jget(b, "sel")
        bv = _bound_value(ont, cat, _bound_role_verbs(ont, cat, es, bsel), jget(b, "value"))
        if bv is None:
            continue  # a type error (sel_reasons), never reached when the goal is well typed

        def mk(sel: dict) -> dict:
            return {"bid": jget(b, "bid"), "sel": sel, "agg": jget(b, "agg"), "value": bv["term"], "key": jget(b, "key"), "window": jget(b, "window"),
                    "scope": jget(b, "scope"), "cap": jget(b, "cap"), "onExceed": jget(b, "onExceed")}
        k = jget(bsel, "k")
        gids = None
        if k == "gids":
            gids = _ids_of(es, jget(bsel, "gids"))
        elif k == "trait":
            gids = _gids_of_verbs(es, float_class_verbs(cat, jget(bsel, "all_of"), jget(bsel, "none_of")))
        if k == "effect":
            out.append(mk({"k": "effect", "cls": jget(bsel, "cls")}))
            report["bounds"].append({"bid": jget(b, "bid"), "gids": [], "dropped": False, "value": bv["how"]})
            continue
        if len(gids) == 0:  # type: ignore[arg-type]
            report["bounds"].append({"bid": jget(b, "bid"), "gids": [], "dropped": True, "value": bv["how"]})
            continue
        out.append(mk({"k": "gids", "gids": gids}))
        report["bounds"].append({"bid": jget(b, "bid"), "gids": gids, "dropped": False, "value": bv["how"]})
    return out


def expand_sel_goal(sg: Any, ont: Any, cat: Any) -> Dict[str, Any]:
    """Lower a selector goal to an ordinary Goal against the PINNED catalog. Pure and total; typing is `sel_reasons` + the core typechecker."""
    report: Dict[str, list] = {"grants": [], "prohibits": [], "bounds": []}
    es = _expand_grants(ont, cat, jget(sg, "grants"), report)
    prohibits = _expand_prohibits(ont, cat, jget(sg, "prohibits"), report)
    bounds = _expand_bounds(ont, cat, es, jget(sg, "bounds"), report)
    deleg = jget(sg, "deleg")
    goal = {
        "v": 1, "principal": jget(sg, "principal"), "ontDigest": jget(sg, "ontDigest"), "nlDigest": jget(sg, "nlDigest"), "sources": jget(sg, "sources"),
        "grants": [e["g"] for e in es], "prohibits": prohibits, "bounds": bounds, "validity": jget(sg, "validity"),
        "deleg": dict(deleg, mayTouch=_ids_of(es, jget(deleg, "mayTouch"))), "escalateOn": jget(sg, "escalateOn"),
        "wildcardAck": _ids_of(es, jget(sg, "wildcardAck")),
        "holes": [dict(h, affects=_ids_of(es, jget(h, "affects"))) for h in req_list(jget(sg, "holes"))]}
    return {"goal": goal, "report": report}


# ---- typing of the selector layer ---------------------------------------------------------------------------------------------------

def _all_known(known: Any, ids: Any) -> bool:
    return all(len(i) > 0 and includes(known, i) for i in req_list(ids))


def _grant_sel_ok(cat: Any, g: Any) -> bool:
    s = jget(g, "sel")
    return jget(s, "k") == "verb" or (len(jget(s, "all_of")) > 0 and len(jget(s, "none_of")) == 0 and _all_known(jget(cat, "known"), jget(s, "all_of")))


def _proh_sel_ok(cat: Any, p: Any) -> bool:
    t = jget(p, "target")
    return jget(t, "k") != "trait" or (_all_known(jget(cat, "known"), jget(t, "all_of")) and _all_known(jget(cat, "known"), jget(t, "none_of")))


def _bound_sel_ok(cat: Any, gs: Any, b: Any) -> bool:
    s = jget(b, "sel")
    k = jget(s, "k")
    if k == "gids":
        return all(any(strict_eq(jget(g, "gid"), i) for g in req_list(gs)) for i in req_list(jget(s, "gids")))
    if k == "effect":
        return True
    return _all_known(jget(cat, "known"), jget(s, "all_of")) and _all_known(jget(cat, "known"), jget(s, "none_of"))


def sel_reasons(sg: Any, ont: Any, cat: Any) -> List[str]:
    """The type reasons of the selector layer, preceded by the wire checks (`catalog_digest_mismatch`, `bad_id`). [] = well typed at this layer."""
    out: List[str] = []
    if not strict_eq(jget(sg, "catDigest"), sel_catalog_digest(cat)):
        out.append("catalog_digest_mismatch")
    ids = ([jget(g, "gid") for g in req_list(jget(sg, "grants"))] + [jget(p, "pid") for p in req_list(jget(sg, "prohibits"))]
           + [jget(b, "bid") for b in req_list(jget(sg, "bounds"))])
    if not all(SEL_ID_RE.fullmatch(js_str(i)) for i in ids):
        out.append("bad_id")
    if not all(_decl_of(ont, jget(v, "verb")) is not None for v in req_list(jget(cat, "verbs"))):
        out.append("catalog_mismatch")
    if not all(_grant_sel_ok(cat, g) for g in req_list(jget(sg, "grants"))):
        out.append("bad_grant_selector")
    if not all(_proh_sel_ok(cat, p) for p in req_list(jget(sg, "prohibits"))):
        out.append("bad_prohibit_selector")
    if not all(_bound_sel_ok(cat, jget(sg, "grants"), b) for b in req_list(jget(sg, "bounds"))):
        out.append("bad_bound_selector")
    es = _expand_grants(ont, cat, jget(sg, "grants"), {"grants": [], "prohibits": [], "bounds": []})
    if not all(_bound_value(ont, cat, _bound_role_verbs(ont, cat, es, jget(b, "sel")), jget(b, "value")) is not None for b in req_list(jget(sg, "bounds"))):
        out.append("unresolved_role_bound")
    return out


def compile_sel_goal(sg: Any, ont: Any, cat: Any, compile_goal: Optional[Any] = None) -> Dict[str, Any]:
    """CompileX: selector reasons first (fail closed), then expansion and the core compiler. The proved compiler is not native: pass
    `compile_goal(goal, ont) -> {ok, policy | reasons}`; with none, a goal that passes the selector layer raises."""
    rs = sel_reasons(sg, ont, cat)
    if len(rs) > 0:
        return {"ok": False, "reasons": rs}
    x = expand_sel_goal(sg, ont, cat)
    if compile_goal is None:
        raise NotImplementedError("compile_sel_goal needs a core compiler (compile_goal)")
    c = compile_goal(x["goal"], ont)
    return {"ok": True, "policy": c["policy"], "goal": x["goal"], "report": x["report"]} if c["ok"] else {"ok": False, "reasons": c["reasons"]}


# ---- acts ---------------------------------------------------------------------------------------------------------------------------

def with_role_params(act: Any, cat: Any) -> Dict[str, Any]:
    """Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
    supplies, `@<role>` is that parameter's value. Any `@` key the caller sent is removed first (a caller cannot forge a role value)."""
    params: Dict[str, Any] = {}
    for k, v in jget(act, "params").items():
        if not k.startswith("@"):
            params[k] = v
    info = _info_of(cat, jget(act, "verb"))
    if info is not None:
        for role, paths in jget(info, "roles").items():
            if len(paths) == 1 and paths[0] in params:
                params["@" + role] = params[paths[0]]
    return dict(act, params=params)


# ---- the policy card ---------------------------------------------------------------------------------------------------------------

def _selector_text(all_: Any, none: Any, reg: dict) -> str:
    def phrase(i: Any) -> str:
        t = reg.get(i) if isinstance(i, str) else None
        return t["card_phrase"] if t is not None and t.get("card_phrase") is not None else js_str(i)
    a = "every action that %s" % " and ".join(phrase(i) for i in req_list(all_)) if len(all_) > 0 else "every action"
    return "%s, except those that %s" % (a, " or ".join(phrase(i) for i in req_list(none))) if len(none) > 0 else a


def render_sel_card(sg: Any, ont: Any, cat: Any, reg: Optional[dict] = None) -> Dict[str, List[str]]:
    """The card of a selector goal: one line per selector clause in the words of the trait phrases (never a model), with the verbs the
    pinned catalog gives it, then the card of the expansion (the exact clauses that run)."""
    reg = CORE_REGISTRY if reg is None else reg
    x = expand_sel_goal(sg, ont, cat)
    goal, report = x["goal"], x["report"]
    lines: List[str] = []
    warnings: List[str] = []
    for i, g in enumerate(req_list(jget(sg, "grants"))):
        r = report["grants"][i]
        s = jget(g, "sel")
        if jget(s, "k") == "class":
            lines.append("ALLOW %s: %s [%d verb(s) in the pinned catalog: %s]" % (
                jq(jget(g, "gid")), _selector_text(jget(s, "all_of"), [], reg), len(r["verbs"]), ", ".join(jq(v) for v in r["verbs"])))
        for d in r["dropped"]:
            warnings.append("grant %s does not cover %s: it has no unique parameter for a role the condition names" % (jq(jget(g, "gid")), jq(d["verb"])))
    for i, p in enumerate(req_list(jget(sg, "prohibits"))):
        r = report["prohibits"][i]
        t = jget(p, "target")
        if jget(t, "k") == "trait":
            lines.append("NEVER %s: %s, today %d verb(s) [%s]; it also covers every verb added to the catalog later" % (
                jq(jget(p, "pid")), _selector_text(jget(t, "all_of"), jget(t, "none_of"), reg), len(r["verbs"]), ", ".join(jq(v) for v in r["verbs"])))
        for v in r["unconditional"]:
            warnings.append("prohibition %s applies to %s without its condition: the verb has no unique parameter for a role the condition names" % (jq(jget(p, "pid")), jq(v)))
    for i, b in enumerate(req_list(jget(sg, "bounds"))):
        r = report["bounds"][i] if i < len(report["bounds"]) else None
        s = jget(b, "sel")
        if jget(s, "k") == "trait" and r:
            lines.append("LIMIT %s: over %s (%d grant(s))" % (jq(jget(b, "bid")), _selector_text(jget(s, "all_of"), jget(s, "none_of"), reg), len(r["gids"])))
        if r and r["dropped"]:
            warnings.append("limit %s selects no grant and bounds nothing" % jq(jget(b, "bid")))
        if r and r["value"] == "role_key":
            warnings.append("limit %s sums a role the verbs carry on different parameters: the action must supply the role key" % jq(jget(b, "bid")))
    core = render_card(goal)
    return {"lines": lines + core["lines"], "warnings": warnings + core["warnings"]}


def trait_closure(ids: Sequence[str], reg: Optional[dict] = None) -> List[str]:
    """The closure of a trait id list under the registry (a selector written with a parent trait covers the children by `implies`)."""
    return closure(CORE_REGISTRY if reg is None else reg, ids)


# ---- the carrier form ---------------------------------------------------------------------------------------------------------------

_ROLE_MARK = "\u0001role:"


def _carry_term(t: Any) -> Dict[str, Any]:
    k = jget(t, "k")
    if k == "role":
        return {"k": "param", "path": _ROLE_MARK + jget(t, "role"), "ty": {"k": "s"}}
    if k == "param":
        return {"k": "param", "path": jget(t, "path"), "ty": jget(t, "ty")}
    if k == "lit":
        return {"k": "lit", "v": jget(t, "v")}
    return {"k": "hist", "bid": jget(t, "bid"), "u": jget(t, "u")}


def _carry_cond(c: Any) -> Dict[str, Any]:
    k = jget(c, "k")
    if k == "true":
        return {"k": "true"}
    if k == "cmp":
        return {"k": "cmp", "op": jget(c, "op"), "l": _carry_term(jget(c, "l")), "r": _carry_term(jget(c, "r"))}
    if k == "and" or k == "or":
        return {"k": k, "a": _carry_cond(jget(c, "a")), "b": _carry_cond(jget(c, "b"))}
    return {"k": "not", "c": _carry_cond(jget(c, "c"))}


def _sel2(all_: Any, none: Any) -> str:
    return "\u0002".join(req_list(all_)) + "\u0001" + "\u0002".join(req_list(none))


def sel_carrier(sg: Any) -> Dict[str, Any]:
    """An ordinary Goal's worth of data carrying a selector goal (selectors ride in strings and role-marked params), so the extracted
    model decodes it with its existing Goal decoder."""
    grants = []
    for g in req_list(jget(sg, "grants")):
        s = jget(g, "sel")
        grants.append({"gid": jget(g, "gid"), "verb": "V\u0001" + jget(s, "verb") if jget(s, "k") == "verb" else "C\u0001" + _sel2(jget(s, "all_of"), jget(s, "none_of")),
                       "res": jget(g, "res"), "cond": _carry_cond(jget(g, "cond"))})
    prohibits = []
    for p in req_list(jget(sg, "prohibits")):
        t = jget(p, "target")
        k = jget(t, "k")
        verb = "V\u0001" + jget(t, "verb") if k == "verb" else ("E\u0001" + jget(t, "cls") if k == "effect" else "T\u0001" + _sel2(jget(t, "all_of"), jget(t, "none_of")))
        prohibits.append({"pid": jget(p, "pid"), "res": jget(p, "res"), "cond": _carry_cond(jget(p, "cond")), "target": {"k": "verb", "verb": verb}})
    bounds = []
    for b in req_list(jget(sg, "bounds")):
        s = jget(b, "sel")
        k = jget(s, "k")
        sel = ({"k": "gids", "gids": jget(s, "gids")} if k == "gids" else ({"k": "effect", "cls": jget(s, "cls")} if k == "effect"
               else {"k": "effect", "cls": "T\u0001" + _sel2(jget(s, "all_of"), jget(s, "none_of"))}))
        bounds.append({"bid": jget(b, "bid"), "key": jget(b, "key"), "window": jget(b, "window"), "scope": jget(b, "scope"), "cap": jget(b, "cap"),
                       "onExceed": jget(b, "onExceed"), "agg": jget(b, "agg"), "value": _carry_term(jget(b, "value")), "sel": sel})
    return {"v": 1, "principal": jget(sg, "principal"), "ontDigest": jget(sg, "ontDigest"), "nlDigest": jget(sg, "nlDigest"), "sources": jget(sg, "sources"),
            "grants": grants, "prohibits": prohibits, "bounds": bounds, "validity": jget(sg, "validity"), "deleg": jget(sg, "deleg"),
            "escalateOn": jget(sg, "escalateOn"), "wildcardAck": jget(sg, "wildcardAck"), "holes": jget(sg, "holes")}


def encode_sel_catalog(c: Any) -> List[list]:
    """The catalog tape the extracted model reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*."""
    def strs(xs: Any) -> list:
        return [["i", len(xs)]] + [["s", x] for x in xs]
    out: List[list] = strs(jget(c, "known")) + [["i", len(jget(c, "verbs"))]]
    for v in jget(c, "verbs"):
        roles = list(jget(v, "roles").items())
        out += [["s", jget(v, "verb")]] + strs(jget(v, "traits")) + [["i", len(roles)]]
        for r, ps in roles:
            out += [["s", r]] + strs(ps)
    return out
