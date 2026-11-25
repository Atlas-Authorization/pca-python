"""Policy coverage (which clauses decided, which never matched, how close traffic came to each threshold, which single-edit mutants
the traffic cannot tell from the policy) and the minimal-change counterfactual search on a deny or escalate. Port of the
TypeScript reference (@atlasauth/pca-analyzer)."""
from ._fin import fin
import math
import re
from typing import Any, Dict, List, Optional

from .analyzer_core import (
    ABSENT, always_denies, bound_of, collect_probes, context_of_action, decide_action, equivalent, probe_set, to_model, veto_applies,
)
from .analyzer_exposure import thresholds_of
from .analyzer_js import (
    UNDEF, is_num, jget, js_gt, js_str, jsnum, key_order, nn, num_str, oget, own, req_list, spread, strict_eq, to_fixed, truthy, uobj,
)
from .analyzer_residual import policy_digest_of
from .pca import evaluate_caveats
from .predicates import evaluate_condition_tri, is_group_condition, is_leaf_condition, predicate_matches


def permit_id(i: int) -> str:
    return "permit[%d]" % i


def _id(x: Any) -> Any:
    return None if x is UNDEF else x


def witness_of(model: Dict[str, Any], action: Any) -> Dict[str, Any]:
    """The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit."""
    decision = decide_action(model, action)
    ctx = context_of_action(action)
    permits = [permit_id(i) for i, p in enumerate(model["predicates"]) if predicate_matches(p, ctx)]
    vetoes = [v for v in model["vetoes"] if veto_applies(v, ctx)]
    tighten = []
    for t in model["tighten"]:
        w = jget(t, "when")
        if evaluate_condition_tri(None if w is UNDEF else w, ctx) != "false":
            tighten.append(t)

    def others(win: Any) -> List[Any]:
        return [i for i in permits + [_id(jget(v, "id")) for v in vetoes] + [_id(jget(t, "id")) for t in tighten] if i != win]

    def done(kind: str, id_: Any) -> Dict[str, Any]:
        return {"decision": decision, "winner": {"kind": kind, "id": _id(id_)}, "also": others(_id(id_))}

    if not model["caveatSat"] or decision == "deny":
        if not model["caveatSat"]:
            return done("caveat", "caveats")
        if not permits:
            return {"decision": decision, "winner": {"kind": "none", "id": None}, "also": others(None)}
        veto = next((v for v in vetoes if jget(v, "kind") == "deny"), None)
        if veto is not None:
            return done("veto", jget(veto, "id"))
        t = next((x for x in tighten if jget(x, "signal") == "deny"), None)
        if t is not None:
            return done("tighten", jget(t, "id"))
        return done("caveat", "caveats")  # reversibility cap or an ancestor of the chain
    if decision == "escalate":
        veto = next((v for v in vetoes if jget(v, "kind") == "approval"), None)
        if veto is not None:
            return done("veto", jget(veto, "id"))
        return done("tighten", jget(tighten[0], "id") if tighten else None)
    return done("permit", permits[0] if permits else None)


# ---- mutation operators ---------------------------------------------------------------------------------------------------------

_FLIP = {"lt": "lte", "lte": "lt", "gt": "gte", "gte": "gt", "eq": "ne", "ne": "eq", "in": "nin", "nin": "in"}


def _variants_of_cond(c: Any, eps: Any) -> List[Dict[str, Any]]:
    if not isinstance(c, (dict, list)):
        return []
    if is_group_condition(c):
        out: List[Dict[str, Any]] = []
        if "not" in c:
            for v in _variants_of_cond(c["not"], eps):
                out.append({"cond": {"not": v["cond"]}, "what": "not(%s)" % v["what"]})
            return out
        is_all = "all_of" in c
        kids = req_list(c["all_of"] if is_all else c.get("any_of", UNDEF))
        for i, k in enumerate(kids):
            for v in _variants_of_cond(k, eps):
                nxt = [v["cond"] if j == i else x for j, x in enumerate(kids)]
                out.append({"cond": {"all_of": nxt} if is_all else {"any_of": nxt},
                            "what": "%s[%d] %s" % ("all_of" if is_all else "any_of", i, v["what"])})
        return out
    if not is_leaf_condition(c) or "ref" in c:
        return []
    out = []
    name = re.sub(r"^action\.params\.", "", c["field"])
    val = c.get("value", UNDEF)
    op = c.get("op", UNDEF)
    if is_num(val) and fin(jsnum(val)) and op in ("lt", "lte", "gt", "gte", "eq"):
        up, dn = val + eps, val - eps
        out.append({"cond": dict(c, value=up), "what": "%s %s %s -> %s" % (name, op, num_str(jsnum(val)), num_str(jsnum(up)))})
        out.append({"cond": dict(c, value=dn), "what": "%s %s %s -> %s" % (name, op, num_str(jsnum(val)), num_str(jsnum(dn)))})
    if isinstance(op, str) and op in _FLIP:
        out.append({"cond": dict(c, op=_FLIP[op]), "what": "%s %s -> %s" % (name, op, _FLIP[op])})
    return out


def _mutants_of(policy: Dict[str, Any], eps: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    def mk(**over: Any) -> Dict[str, Any]:
        return dict({"predicates": policy["predicates"], "caveats": policy["caveats"], "vetoes": policy["vetoes"], "tighten": policy["tighten"]}, **over)

    preds = policy["predicates"]
    for i, p in enumerate(preds):
        out.append({"id": "drop-%s" % permit_id(i), "description": "drop %s" % permit_id(i), "policy": mk(predicates=[x for j, x in enumerate(preds) if j != i])})
        where = req_list(nn(jget(p, "where"), []))
        for j, c in enumerate(where):
            for v in _variants_of_cond(c, eps):
                np_ = dict(spread(p), where=[v["cond"] if k == j else x for k, x in enumerate(where)])
                out.append({"id": "%s.where[%d]:%s" % (permit_id(i), j, v["what"]), "description": "%s: %s" % (permit_id(i), v["what"]),
                            "policy": mk(predicates=[np_ if k == i else x for k, x in enumerate(preds)])})
            rest = [x for k, x in enumerate(where) if k != j]
            out.append({"id": "%s.where[%d]:drop" % (permit_id(i), j), "description": "%s: drop condition %d" % (permit_id(i), j),
                        "policy": mk(predicates=[dict(spread(p), where=rest) if k == i else x for k, x in enumerate(preds)])})
    vetoes = policy["vetoes"]
    for i, v in enumerate(vetoes):
        vid = js_str(jget(v, "id"))
        out.append({"id": "drop-veto:%s" % vid, "description": "drop prohibition %s" % vid, "policy": mk(vetoes=[x for j, x in enumerate(vetoes) if j != i])})
        over = jget(v, "over")
        if truthy(over):
            nv = [dict(spread(x), over=dict(spread(over), threshold=jget(over, "threshold") + eps)) if j == i else x for j, x in enumerate(vetoes)]
            out.append({"id": "veto:%s:threshold+" % vid, "description": "raise the %s threshold by %s" % (vid, num_str(jsnum(eps))), "policy": mk(vetoes=nv)})
    tighten = policy["tighten"]
    for i, t in enumerate(tighten):
        tid = js_str(jget(t, "id"))
        out.append({"id": "drop-tighten:%s" % tid, "description": "drop tighten rule %s" % tid, "policy": mk(tighten=[x for j, x in enumerate(tighten) if j != i])})
    return out


def _reach(model: Dict[str, Any], kind: str, idx: int) -> Any:
    if kind == "permit":
        r = always_denies({"predicates": [model["predicates"][idx]], "caveats": model["caveats"]})
        return "unknown" if r.get("approximate") else not r["alwaysDenies"]
    if kind == "veto":
        r = always_denies({"predicates": [jget(model["vetoes"][idx], "when")]})
        return "unknown" if r.get("approximate") else not r["alwaysDenies"]
    return "unknown"


def coverage(policy: Any, traffic: Any, o: Any = None) -> Dict[str, Any]:
    """Coverage of `policy` by `traffic` (actions): clauses, boundaries, mutants and the 0..1 scores."""
    o = {} if o is None else o
    traffic = req_list(traffic)
    model = to_model(policy)
    eps = nn(jget(o, "epsilon"), 1)
    ids: List[Dict[str, Any]] = (
        [{"id": permit_id(i), "kind": "permit"} for i in range(len(model["predicates"]))]
        + [{"id": _id(jget(v, "id")), "kind": "veto"} for v in model["vetoes"]]
        + [{"id": _id(jget(t, "id")), "kind": "tighten"} for t in model["tighten"]]
    )
    matched: Dict[Any, int] = {}
    decisive: Dict[Any, int] = {}

    def bump(m: Dict[Any, int], k: Any) -> None:
        if k is not None:
            m[k] = m.get(k, 0) + 1

    for a in traffic:
        w = witness_of(model, a)
        bump(decisive, w["winner"]["id"])
        for i in [w["winner"]["id"]] + w["also"]:
            bump(matched, i)
    np_, nv = len(model["predicates"]), len(model["vetoes"])
    clauses: List[Dict[str, Any]] = []
    for n, c in enumerate(ids):
        idx = n if c["kind"] == "permit" else n - np_ if c["kind"] == "veto" else n - np_ - nv
        clauses.append({"id": c["id"], "kind": c["kind"], "matched": matched.get(c["id"], 0), "decisive": decisive.get(c["id"], 0),
                        "reachable": _reach(model, c["kind"], idx)})
    paths: Dict[str, None] = {}

    def walk(c: Any) -> None:
        if not isinstance(c, (dict, list)):
            return
        if is_group_condition(c):
            if "all_of" in c:
                for x in req_list(c["all_of"]):
                    walk(x)
            elif "any_of" in c:
                for x in req_list(c["any_of"]):
                    walk(x)
            else:
                walk(c["not"])
        elif is_leaf_condition(c) and c["field"].startswith("action.params.") and c.get("op") in ("lt", "lte", "gt", "gte", "eq", "in", "nin"):
            paths[c["field"]] = None

    for p in probe_set(model):
        for c in req_list(nn(jget(p, "where"), [])):
            walk(c)
    for v in model["vetoes"]:
        over = jget(v, "over")
        if truthy(over):
            paths[jget(over, "path")] = None
    boundaries: List[Dict[str, Any]] = []
    for path in sorted(paths, key=lambda s: s.encode("utf-16-be", "surrogatepass")):
        name = path[len("action.params."):]
        vals = [x for x in (own(nn(jget(a, "params"), {}), name) for a in traffic) if is_num(x)]
        for t in thresholds_of(model, path):
            boundaries.append({
                "path": path, "threshold": t, "at": any(strict_eq(v, t) for v in vals),
                "below": any(v < t and v >= t - eps for v in vals), "above": any(v > t and v <= t + eps for v in vals),
            })
    survivors: List[Dict[str, Any]] = []
    killed = 0
    equiv = 0
    mm = nn(jget(o, "maxMutants"), 200)
    allm = _mutants_of(model, eps)[0:int(mm)] if mm == mm else []
    base = [decide_action(model, a) for a in traffic]
    for m in allm:
        mmod = to_model(m["policy"])
        if any(decide_action(mmod, a) != base[i] for i, a in enumerate(traffic)):
            killed += 1
            continue
        eq = equivalent(policy, m["policy"])
        if eq["equivalent"]:
            equiv += 1
            continue
        s = {"id": m["id"], "description": m["description"]}
        if truthy(eq.get("counterexample", UNDEF)):
            s["killer"] = eq["counterexample"]
        survivors.append(s)

    def ratio(n: int, d: int) -> float:
        return 1 if d == 0 else n / d

    live = [c for c in clauses if c["reachable"] is not False]
    return {
        "traffic": len(traffic),
        "policyDigest": policy_digest_of(model),
        "clauses": clauses,
        "neverMatched": [c["id"] for c in clauses if c["matched"] == 0],
        "neverDecisive": [c["id"] for c in clauses if c["decisive"] == 0],
        "untested": [c["id"] for c in clauses if c["reachable"] is not False and c["matched"] == 0],
        "unreachable": [c["id"] for c in clauses if c["reachable"] is False],
        "boundaries": boundaries,
        "mutants": {"total": len(allm), "killed": killed, "equivalent": equiv, "survivors": survivors},
        "score": {
            "clauses": ratio(len([c for c in live if c["decisive"] > 0]), len(live)),
            "boundaries": ratio(len([b for b in boundaries if b["at"] and b["below"] and b["above"]]), len(boundaries)),
            "mutation": ratio(killed, len(allm) - equiv),
        },
    }


def coverage_gate(r: Any, minimum: Any = None) -> Dict[str, Any]:
    """A CI gate over a coverage report: {ok, reasons}."""
    mn = {} if minimum is None else minimum
    reasons: List[str] = []
    score = jget(r, "score")
    for key, label, text in (("clauses", "clause coverage", "clauses"), ("boundaries", "boundary coverage", "boundaries"), ("mutation", "mutation score", "mutation")):
        lim = jget(mn, key)
        if jsnum(score[key]) < jsnum(nn(lim, 0)):
            reasons.append("%s %s < %s" % (label, to_fixed(jsnum(score[key]), 2), js_str(lim) if not is_num(lim) else num_str(jsnum(lim))))
    ms = jget(mn, "maxSurvivors")
    if ms is not UNDEF and len(r["mutants"]["survivors"]) > jsnum(ms):
        reasons.append("%d surviving mutants > %s" % (len(r["mutants"]["survivors"]), js_str(ms) if not is_num(ms) else num_str(jsnum(ms))))
    if len(r["unreachable"]) > 0:
        reasons.append("unreachable clauses: %s" % ", ".join(js_str(x) for x in r["unreachable"]))
    return {"ok": len(reasons) == 0, "reasons": reasons}


# ---- minimal flip ---------------------------------------------------------------------------------------------------------------

_RANK = {"deny": 0, "escalate": 1, "allow": 2}


def _cav_ctx(c: Any) -> Any:
    """The reference's camelCase CaveatContext as the context dict `evaluate_caveats` reads."""
    if not isinstance(c, dict):
        return c
    out = {k: v for k, v in c.items()}
    for camel, snake in (("blastRadius", "blast_radius"), ("reversibilityClass", "reversibility_class"), ("delegationDepth", "delegation_depth"),
                         ("recentActionTimes", "recent_action_times")):
        if camel in out:
            out[snake] = out.pop(camel)
    return out


def _jsmax(a: float, b: float) -> float:
    return math.nan if a != a or b != b else max(a, b)


def _wait_time(caveats: Any, ctx: Any) -> Any:
    at: Any = UNDEF
    now = jget(ctx, "now")
    for c in caveats:
        t = jget(c, "type")
        cat = jget(c, "at")
        if t == "not_before" and is_num(cat) and js_gt(cat, now):
            at = _jsmax(0 if at is UNDEF else at, jsnum(cat))
        mx, ps = jget(c, "max"), jget(c, "per_secs")
        if t == "rate" and is_num(mx) and is_num(ps):
            span = jsnum(ps) * 1000
            times = nn(jget(ctx, "recentActionTimes"), [])
            recent = sorted([x for x in req_list(times) if js_gt(x, jsnum(now) - span)], key=jsnum)
            if len(recent) >= jsnum(mx):
                i = len(recent) - jsnum(mx)
                v = jsnum(recent[int(i)]) + span if i == int(i) and 0 <= i < len(recent) else math.nan
                at = _jsmax(0 if at is UNDEF else at, v)
    return at


def _meters(m: Dict[str, Any]) -> bool:
    cs = list(m["caveats"])
    for x in m["meets"]:
        cs.extend(x["caveats"])
    return any(jget(c, "type") in ("rate", "budget_alloc", "max_blast_radius") for c in cs)


def _set_path(o: Dict[str, Any], path: List[str], v: Any) -> Dict[str, Any]:
    if not path:
        return o
    k, rest = path[0], path[1:]
    o[k] = v if not rest else _set_path(spread(nn(o.get(k), {})), rest, v)
    return o


def _decl(shape: Any, name: str) -> Any:
    if shape is UNDEF:
        return UNDEF
    return jget(jget(shape, "params"), name)


def _with_param(action: Any, params: Dict[str, Any], name: str, v: Any) -> Dict[str, Any]:
    a = spread(action)
    p = dict(params)
    p[name] = v
    a["params"] = p
    return a


def _uniq(xs: List[Any]) -> List[Any]:
    seen: Dict[Any, Any] = {}
    for x in xs:
        k = ("n", jsnum(x)) if is_num(x) else ("s", x) if isinstance(x, str) else ("o", id(x))
        seen.setdefault(k, x)
    return list(seen.values())


def minimal_flip(policy: Any, action: Any, o: Any) -> Dict[str, Any]:
    """The smallest verified change that gets `action` to the wanted decision (default allow), ordered by cost: wait, change one
    parameter, change two together, another resource, obtain a fact, split (opt-in), ask a human. Only a repair the real
    decision confirms is returned; shown only to the authenticated holder; critical values are redacted by default."""
    model = to_model(policy)
    cctx = jget(o, "caveatContext")
    caveats_ok = cctx is UNDEF or evaluate_caveats(model["caveats"], _cav_ctx(cctx))[0]
    current = decide_action(model, action) if caveats_ok else "deny"
    want = nn(jget(o, "desired"), "allow")
    rank_want = _RANK.get(want, math.nan) if isinstance(want, str) else math.nan
    res: Dict[str, Any] = {"current": current, "repairs": [], "repairExists": False}
    if not truthy(jget(o, "holderAuthenticated")):
        return dict(res, refused="counterfactuals are shown only to the authenticated holder")
    probe = jget(o, "probe")
    if truthy(probe):
        now = jget(probe, "now")
        recent = [t for t in req_list(jget(probe, "history")) if js_gt(t, jsnum(now) - jsnum(jget(probe, "windowSecs")) * 1000)]
        if len(recent) >= jsnum(jget(probe, "limit")):
            return dict(res, refused="probe budget exhausted", probe={"history": recent})
        res["probe"] = {"history": recent + [now]}
    digest = policy_digest_of(model)
    if _RANK[current] >= rank_want:
        return res

    schema = jget(o, "schema")
    shape: Any = UNDEF
    if schema is not UNDEF and schema is not None:
        shape = next((s for s in req_list(schema) if strict_eq(jget(s, "verb"), jget(action, "verb"))), UNDEF)

    def reaches(a: Any) -> Optional[str]:
        d = decide_action(model, a)
        return d if _RANK[d] >= rank_want else None

    cands: List[Dict[str, Any]] = []

    def push(repair: Dict[str, Any], cost: Any, a: Any) -> None:
        d = reaches(a)
        if d is not None:
            cands.append({"repair": repair, "cost": cost, "decision": d, "action": a})

    pr = collect_probes({"predicateSets": [probe_set(model)], "varyReversibility": "revCap" in model})
    params = spread(nn(jget(action, "params"), {}))
    ch = jget(o, "changeable")
    if ch is not UNDEF and ch is not None:
        names = list(req_list(ch))
    elif shape is not UNDEF:
        names = key_order(jget(shape, "params"))
    else:
        names = key_order(params)

    # 1. wait: a time caveat that is not open yet, or a rate window that will reset
    if not caveats_ok and truthy(cctx):
        at = _wait_time(model["caveats"], cctx)
        d = decide_action(model, action)
        if at is not UNDEF:
            later = dict(spread(cctx), now=at)
            if evaluate_caveats(model["caveats"], _cav_ctx(later))[0] and _RANK[d] >= rank_want:
                cands.append({"repair": {"kind": "wait_until", "at": at, "reason": "a time or rate caveat opens then"}, "cost": 1, "decision": d, "action": action})
    finish = not caveats_ok  # nothing else helps while a caveat is closed

    # 2. one parameter changed: the nearest verified value, per parameter
    for name in [] if finish else names:
        path = "action.params.%s" % name
        decl = _decl(shape, name)
        cur = own(params, name)
        field = next((f for f in pr["fields"] if f["path"] == path), None)
        dvals = oget(decl, "values")
        dmin, dmax = oget(decl, "min"), oget(decl, "max")
        pool = [v for v in (list(field["values"]) if field else []) + (list(dvals) if dvals is not UNDEF else [])
                + ([dmin] if dmin is not UNDEF else []) + ([dmax] if dmax is not UNDEF else []) if v is not ABSENT]
        nums = [v for v in pool if is_num(v) and fin(jsnum(v))]
        T = thresholds_of(model, path)
        integer = oget(decl, "type") == "integer" or (is_num(cur) and float(jsnum(cur)).is_integer())
        ints = [x for t in T for x in (t - 1, t + 1)] if integer else []
        curn = jsnum(cur) if is_num(cur) else 0
        numeric = sorted(
            [v for v in _uniq(nums + ints) if (dmin is UNDEF or v >= dmin) and (dmax is UNDEF or v <= dmax)],
            key=lambda v: (abs(jsnum(v) - curn), jsnum(v)))
        strs = _uniq([v for v in pool if isinstance(v, str) and not v.startswith("\u0000")])
        best: Optional[Dict[str, Any]] = None
        for v in numeric + strs:
            if strict_eq(v, cur):
                continue
            a = _with_param(action, params, name, v)
            d = reaches(a)
            if d is not None:
                extra = min(1, abs(jsnum(v) - jsnum(cur)) / (abs(jsnum(cur)) + 1)) if is_num(v) and is_num(cur) else 0.5
                best = {"repair": uobj({"kind": "set_param", "param": name, "from": cur, "to": v}), "cost": 2 + extra, "decision": d, "action": a}
                break  # the pool is ordered nearest first
        if best is not None:
            cands.append(best)

    # 2b. when no single edit works, the cheapest PAIR of edits
    if not finish and not cands:
        dims: List[Dict[str, Any]] = []

        def param_dim(name: str) -> Dict[str, Any]:
            field = next((f for f in pr["fields"] if f["path"] == "action.params.%s" % name), None)
            decl = _decl(shape, name)
            dv = oget(decl, "values")
            vals = (list(field["values"]) if field else []) + (list(dv) if dv is not UNDEF else [])
            vals = [v for v in vals if (isinstance(v, str) and not v.startswith("\u0000")) or (is_num(v) and not isinstance(v, bool))]
            vals = [v for v in vals if not strict_eq(v, own(params, name))]
            return {
                "cost": 2,
                "make": lambda a, v: _with_param(a, nn(jget(a, "params"), {}) if isinstance(jget(a, "params"), dict) else {}, name, v),
                "step": lambda v: uobj({"kind": "set_param", "param": name, "from": own(params, name), "to": v}),
                "values": _uniq(vals)[:6],
            }

        for name in names:
            dims.append(param_dim(name))
        ares = jget(action, "resource")
        dims.append({
            "cost": 3, "make": lambda a, v: dict(spread(a), resource=v),
            "step": lambda v: uobj({"kind": "set_resource", "from": ares, "to": v}),
            "values": [x for x in pr["resources"] if not x.startswith("\u0000") and x != ares][:6],
        })
        for i in range(len(dims)):
            for j in range(i + 1, len(dims)):
                for x in dims[i]["values"]:
                    for y in dims[j]["values"]:
                        a = dims[j]["make"](dims[i]["make"](action, x), y)
                        d = reaches(a)
                        if d is not None:
                            cands.append({"repair": {"kind": "combine", "steps": [dims[i]["step"](x), dims[j]["step"](y)]},
                                          "cost": dims[i]["cost"] + dims[j]["cost"], "decision": d, "action": a})

    # 3. another allowed resource
    ares = jget(action, "resource")
    for r in [] if finish else [x for x in pr["resources"] if not x.startswith("\u0000") and x != ares]:
        push(uobj({"kind": "set_resource", "from": ares, "to": r}), 3, dict(spread(action), resource=r))

    # 4. a named fact that is missing: a subject or env field the policy reads
    for f in [] if finish else [x for x in pr["fields"] if x["path"].startswith("subject.") or x["path"].startswith("env.")]:
        segs = f["path"].split(".")
        root, rest = segs[0], segs[1:]
        for v in [x for x in f["values"] if x is not ABSENT]:
            cur_root = jget(action, root)
            a = spread(action)
            a[root] = _set_path(spread(nn(cur_root, {})), rest, v)
            before = reaches(action)
            d = reaches(a)
            if d is not None and before is None:
                cands.append({"repair": {"kind": "obtain_fact", "path": f["path"], "value": v}, "cost": 4, "decision": d, "action": a})
                break

    # 5. split (opt-in, and only when nothing meters the total)
    if jget(o, "allowSplit") is True and not _meters(model):
        for name in names:
            cur = own(params, name)
            if not is_num(cur):
                continue
            flipped = next((c for c in cands if c["repair"]["kind"] == "set_param" and c["repair"]["param"] == name and is_num(c["repair"].get("to", UNDEF))), None)
            part = flipped["repair"]["to"] if flipped is not None and flipped["repair"]["kind"] == "set_param" else UNDEF
            if part is UNDEF or part <= 0 or part >= cur:
                continue
            n = math.ceil(jsnum(cur) / jsnum(part))
            if n > 8:
                continue
            parts = [{name: part if i < n - 1 else cur - part * (n - 1)} for i in range(n)]
            if all(reaches(dict(spread(action), params=dict(params, **p))) is not None for p in parts):
                cands.append({"repair": {"kind": "split", "param": name, "parts": parts}, "cost": 3 + n, "decision": want, "action": action})

    cands.sort(key=lambda c: c["cost"])
    mc = nn(jget(o, "maxCandidates"), 8)
    top = cands[0:int(mc)]
    res["repairExists"] = len(top) > 0
    redact = nn(jget(o, "redact"), "critical")

    def hide(c: Dict[str, Any]) -> Dict[str, Any]:
        if redact == "none" or c["repair"]["kind"] != "set_param":
            return c
        sens = oget(_decl(shape, c["repair"]["param"]), "sensitivity")
        if redact == "critical" and sens != "critical":
            return c
        res["redacted"] = True
        return dict(c, repair={"kind": "set_param", "param": c["repair"]["param"], "redacted": True}, action=spread(action))

    if redact == "all":
        res["redacted"] = True
    else:
        res["repairs"] = [hide(c) for c in top]
    free = next((c for c in top if c["decision"] == "allow" and c["repair"]["kind"] != "split"), None)
    if free is not None and current == "escalate":
        res["humanFree"] = hide(free)
    if current == "escalate" or not top:
        res["humanAsk"] = uobj({"verb": jget(action, "verb"), "resource": jget(action, "resource"), "params": dict(params),
                                "kind": "approval" if current == "escalate" else "access-request", "policyDigest": digest})
    return res
