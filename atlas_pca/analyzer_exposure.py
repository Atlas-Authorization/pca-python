"""Quantitative and ternary static queries over a policy (the most that can ever be spent, the actions that need a human, the reach
of a delegation chain, a first-class diff) and the workflow-DAG exposure. Port of the TypeScript reference (@atlasauth/pca-analyzer)."""
from ._fin import fin
import math
from typing import Any, Dict, List, Optional

from .analyzer_core import (
    ABSENT, bound_of, collect, collect_probes, decide, decide_action, probe_set, rep_to_action, search, to_model, vetoes_from_constitution,
)
from .analyzer_js import UNDEF, includes, is_num, jget, js_json, js_str, jsnum, key_order, nn, num_str, req_list, strict_eq, truthy, uobj
from .facade import BUILTIN_ACTIONS
from .predicates import is_group_condition, is_leaf_condition

HUGE = 9007199254740991
_INF = math.inf


def resolve_action(catalog: Any, verb: str) -> Dict[str, Any]:
    """{spec, catalogued}: a catalogued verb's spec, else the fail-closed spec (irreversible, maximum blast radius)."""
    spec = _catalog_get(catalog, verb)
    if spec is not None:
        return {"spec": spec, "catalogued": True}
    parts = verb.split(".")
    return {"spec": {"connector": parts[0], "action": ".".join(parts[1:]) or verb, "verb": verb, "reversibility": "irreversible",
                     "blastRadius": 1, "description": "(uncatalogued) " + verb}, "catalogued": False}


def _catalog_get(catalog: Any, verb: str) -> Optional[Dict[str, Any]]:
    if catalog is None or catalog is UNDEF:
        catalog = BUILTIN_ACTIONS
    if hasattr(catalog, "get") and not isinstance(catalog, dict):
        return catalog.get(verb)
    if isinstance(catalog, dict):
        return catalog.get(verb)
    found = None
    for a in catalog:  # a list of specs: a later spec with the same verb replaces an earlier one
        if isinstance(a, dict) and a.get("verb") == verb:
            found = a
    return found


def _cond_thresholds(c: Any, path: str, into: List[Any]) -> None:
    if not isinstance(c, (dict, list)):
        return
    if is_group_condition(c):
        if "all_of" in c and isinstance(c["all_of"], list):
            for x in c["all_of"]:
                _cond_thresholds(x, path, into)
        elif "any_of" in c and isinstance(c["any_of"], list):
            for x in c["any_of"]:
                _cond_thresholds(x, path, into)
        elif "not" in c:
            _cond_thresholds(c["not"], path, into)
        return
    if not is_leaf_condition(c) or c["field"] != path:
        return
    v = c.get("value", UNDEF)
    if is_num(v) and fin(jsnum(v)):
        into.append(v)
    elif isinstance(v, list):
        for x in v:
            if is_num(x) and fin(jsnum(x)):
                into.append(x)


def thresholds_of(model: Dict[str, Any], path: str) -> List[Any]:
    """Every numeric literal the policy compares `path` against, ascending and de-duplicated."""
    out: List[Any] = []
    for p in probe_set(model):
        w = nn(jget(p, "where"), [])
        for c in req_list(w):
            _cond_thresholds(c, path, out)
    for v in model["vetoes"]:
        over = jget(v, "over")
        if truthy(over) and jget(over, "path") == path and is_num(jget(over, "threshold")):
            out.append(jget(over, "threshold"))
    seen: Dict[float, Any] = {}
    for x in out:
        seen.setdefault(jsnum(x), x)
    return [seen[k] for k in sorted(seen)]


def _pinned(pr: Dict[str, Any], path: str, value: Any, resource: Any) -> Dict[str, Any]:
    fields = [f for f in pr["fields"] if f["path"] != path] + [{"path": path, "values": [value]}]
    return dict(pr, resources=[resource] if resource is not UNDEF else pr["resources"], fields=fields)


def _peak_at(model: Dict[str, Any], o: Any, level: str) -> Dict[str, Any]:
    field = nn(jget(o, "amountField"), "amount")
    fname = js_str(field)
    path = "action.params.%s" % fname
    mx = bound_of(o)
    base = collect_probes({"predicateSets": [probe_set(model)], "varyReversibility": "revCap" in model})
    base["verbs"] = [jget(o, "verb")]
    T = thresholds_of(model, path)
    lo = max(0, jsnum(nn(jget(o, "min"), 0)))
    hi = jsnum(nn(jget(o, "max"), _INF))
    raw: List[float] = []
    for i, t in enumerate(T):
        raw.append(t - 1)
        raw.append(t)
        if i + 1 < len(T):
            raw.append((t + T[i + 1]) / 2)
    raw.append(T[-1] + 1 if T else 0)
    raw.append(HUGE)
    raw.append(lo)
    if fin(hi):
        raw.append(hi)
    uniq: Dict[float, float] = {}
    for c in raw:
        uniq.setdefault(c, c)
    cands = sorted((c for c in uniq if lo <= c <= hi and fin(c)), reverse=True)
    resource = jget(o, "resource")

    def ok(m: Dict[str, Any]):
        return lambda rep: (decide(m, rep) == "allow") if level == "allow" else (decide(m, rep) != "deny")

    overflow = False
    for c in cands:
        out = search(_pinned(base, path, c, resource), ok(model), mx)
        if out["overflow"]:
            overflow = True
            break
        if "hit" not in out:
            continue
        hit = out["hit"]

        def act(v: Any, hit: Dict[str, Any] = hit) -> Dict[str, Any]:
            a = rep_to_action(hit)
            a["params"] = dict(a.get("params") or {}, **{fname: v})
            return a

        def holds(a: Dict[str, Any]) -> bool:
            d = decide_action(model, a)
            return d == "allow" if level == "allow" else d != "deny"

        top = T[-1] if T else -_INF
        if c > top:
            if fin(hi):
                return {"peak": {"admitted": True, "max": hi, "attained": holds(act(hi)), "witness": act(hi)}, "overflow": False}
            return {"peak": {"admitted": True, "max": _INF, "attained": False, "witness": act(HUGE)}, "overflow": False}
        if any(jsnum(t) == c for t in T):
            return {"peak": {"admitted": True, "max": c, "attained": True, "witness": act(c)}, "overflow": False}
        nxt = next(t for t in T if t > c)
        if jget(o, "integer") is True:
            m = math.ceil(nxt) - 1
            if m >= c and holds(act(m)):
                return {"peak": {"admitted": True, "max": m, "attained": True, "witness": act(m)}, "overflow": False}
        return {"peak": {"admitted": True, "max": nxt, "attained": False, "witness": act(c)}, "overflow": False}
    return {"peak": {"admitted": False, "max": 0, "attained": False}, "overflow": overflow}


def _universal(p: Any, verb: Any) -> bool:
    pv = jget(p, "verb")
    verb_ok = strict_eq(pv, "*") or strict_eq(pv, verb) or (isinstance(pv, list) and (includes(pv, "*") or includes(pv, verb)))
    res = jget(p, "resource")
    where = jget(p, "where")
    if where is None:
        raise TypeError("cannot read properties of null (reading 'length')")
    return bool(verb_ok and (res is UNDEF or strict_eq(res, "*")) and (where is UNDEF or len(where) == 0))


def _ceil_div(a: Any, b: Any) -> Any:
    q = jsnum(a) / jsnum(b)
    return math.ceil(q) if fin(q) else q


def _window_bound(model: Dict[str, Any], c: Any, o: Any, peak: Dict[str, Any]) -> Dict[str, Any]:
    W = jget(o, "windowSecs")
    path = "action.params.%s" % js_str(nn(jget(o, "amountField"), "amount"))
    per = peak["max"] if peak["admitted"] else 0
    basis: List[str] = []
    not_applied: List[str] = []
    st = {"maxActions": _INF}

    def limit_actions(n: Any, per_secs: Any, why: str) -> None:
        k = _INF if W is UNDEF else n * _ceil_div(W, per_secs)  # a sliding limit of n per perSecs: at most n per started period
        if k < st["maxActions"]:
            st["maxActions"] = k
            basis.append(why)

    caveats = list(model["caveats"])
    for m in model["meets"]:
        caveats.extend(m["caveats"])
    invs = c.get("invariants", UNDEF) if isinstance(c, dict) else UNDEF
    invs = invs if isinstance(invs, list) else []
    for cv in caveats:
        mx, ps = jget(cv, "max"), jget(cv, "per_secs")
        if jget(cv, "type") == "rate" and is_num(mx) and is_num(ps) and ps > 0:
            limit_actions(mx, ps, "rate caveat %s/%ss" % (num_str(jsnum(mx)), num_str(jsnum(ps))))
    for inv in invs:
        if jget(inv, "kind") != "rate":
            continue
        if _universal(jget(inv, "when"), jget(o, "verb")):
            limit_actions(jget(inv, "max"), jget(inv, "window_secs"), "rate invariant %s" % js_str(jget(inv, "id")))
        else:
            not_applied.append(jget(inv, "id"))
    max_actions = st["maxActions"]
    bound = 0 if per == 0 else (_INF if max_actions == _INF else per * max_actions)
    if fin(jsnum(per)) and per > 0:
        basis.insert(0, "per-action ceiling")
    for cv in caveats:
        lim = jget(cv, "limit")
        if jget(cv, "type") != "budget_alloc" or not is_num(lim):
            continue
        bm = jget(o, "budgetModel")
        kappa = jget(o, "kappa")
        if bm == "dollars":
            if lim < bound:
                bound = lim  # in the dollar model the allocation is a lifetime cap on the total
                basis.append("budget_alloc limit %s" % num_str(jsnum(lim)))
        elif bm == "risk" and is_num(kappa) and kappa > 0:
            r = jget(o, "blastRadius")
            if r is UNDEF or r is None:
                r = resolve_action(None, jget(o, "verb"))["spec"]["blastRadius"]
            cost = jsnum(kappa) * min(1, max(0, jsnum(r)))
            n = math.floor(jsnum(lim) / cost) if cost > 0 else _INF
            if n < max_actions:
                max_actions = n
                st["maxActions"] = n
                bound = 0 if n == 0 else (per * n if fin(jsnum(per)) and per > 0 else bound)
                basis.append("budget_alloc %s / cost %s = %s actions" % (num_str(jsnum(lim)), num_str(cost), num_str(jsnum(n))))
        else:
            not_applied.append("budget_alloc %s (trust-budget units; pass budgetModel and kappa)" % num_str(jsnum(lim)))
    for inv in invs:
        if jget(inv, "kind") != "cap":
            continue
        if not _universal(jget(inv, "when"), jget(o, "verb")) or jget(inv, "amount") != path:
            not_applied.append(jget(inv, "id"))
            continue
        ws = jget(inv, "window_secs")
        if ws is not UNDEF and W is UNDEF:
            continue  # a windowed cap says nothing about a lifetime total
        cap = jget(inv, "max") if (ws is UNDEF or W is UNDEF) else jget(inv, "max") * _ceil_div(W, ws)
        if cap < bound:
            bound = cap
            basis.append("cap invariant %s" % js_str(jget(inv, "id")))
    max_actions = st["maxActions"]
    out: Dict[str, Any] = {"maxActions": max_actions, "bound": bound, "basis": basis, "notApplied": [x for x in not_applied if x is not UNDEF]}
    if W is not UNDEF:
        out["secs"] = W
    w = peak.get("witness")
    if peak["admitted"] and w is not None and fin(jsnum(max_actions)) and fin(jsnum(peak["max"])) and peak["max"] > 0:
        out["sequence"] = {"action": w, "repeat": max_actions}
    return out


_UNBOUNDED = {"admitted": True, "max": _INF, "attained": False}


def max_exposure(policy: Any, given: Any) -> Dict[str, Any]:
    """The most that can ever leave under a policy: the largest single action, the largest autonomous action and the windowed
    total ({verb, amountField, perAction, autonomousPerAction, window, autonomousWindow, unmodeled, approximate?, reason?})."""
    o: Dict[str, Any] = dict(given) if isinstance(given, dict) else {}
    if jget(given, "budgetModel") is UNDEF:
        bmodel = jget(policy, "budgetModel")
        if bmodel in ("dollars", "risk"):
            o["budgetModel"] = bmodel
    if jget(given, "kappa") is UNDEF:
        rp = jget(policy, "riskPolicy")
        pk = jget(rp, "kappa") if (rp is not UNDEF and rp is not None) else UNDEF
        if is_num(pk):
            o["kappa"] = pk
    c = jget(o, "constitution")
    cv = vetoes_from_constitution(c) if c is not UNDEF else None
    base = to_model(policy)
    model = dict(base, vetoes=list(base["vetoes"]) + cv["vetoes"]) if cv is not None else base
    admit = _peak_at(model, o, "admit")
    auto = _peak_at(model, o, "allow")
    approximate = admit["overflow"] or auto["overflow"] or bool(model["undecidable"])
    ap = dict(_UNBOUNDED) if admit["overflow"] else admit["peak"]
    up = dict(_UNBOUNDED) if auto["overflow"] else auto["peak"]
    e = uobj({
        "verb": jget(o, "verb"), "amountField": nn(jget(o, "amountField"), "amount"),
        "perAction": ap, "autonomousPerAction": up,
        "window": _window_bound(model, c, o, ap), "autonomousWindow": _window_bound(model, c, o, up),
        "unmodeled": ["%s: %s" % (js_str(u.get("id", UNDEF)), u["reason"]) for u in (cv["unmodeled"] if cv is not None else []) if u.get("kind") not in ("cap", "rate")],
    })
    if approximate:
        e["approximate"] = True
        e["reason"] = ("representative grid exceeded the bound; exposure reported as unbounded"
                       if admit["overflow"] or auto["overflow"] else "over-approximated (%s)" % "; ".join(model["undecidable"]))
    return e


def escalation_surface(policy: Any, opts: Any = None) -> Dict[str, Any]:
    """The actions that are admitted only with a human: {escalates, witnesses, approximate?, reason?}."""
    opts = {} if opts is None else opts
    model = to_model(policy)
    base = collect_probes({"predicateSets": [probe_set(model)], "varyReversibility": "revCap" in model})
    verb = jget(opts, "verb")
    if verb is not UNDEF:
        base["verbs"] = [verb]
    r = collect(base, lambda rep: decide(model, rep) == "escalate", bound_of(opts), nn(jget(opts, "limit"), 8))
    witnesses = [a for a in (rep_to_action(h) for h in r["hits"]) if decide_action(model, a) == "escalate"]
    out: Dict[str, Any] = {"escalates": len(witnesses) > 0, "witnesses": witnesses}
    if r["overflow"] or model["undecidable"]:
        out["approximate"] = True
        out["reason"] = "representative grid exceeded the bound" if r["overflow"] else "over-approximated (%s)" % "; ".join(model["undecidable"])
    return out


def delegation_envelope(chain: Any, opts: Any = None) -> Dict[str, Any]:
    """The join of everything any holder of the leaf could do, with the remaining delegation depth."""
    chain = req_list(chain)
    leaf = chain[-1] if chain else UNDEF
    if isinstance(leaf, (dict, list)):
        extra = leaf.get("meet", UNDEF) if isinstance(leaf, dict) else UNDEF
        if truthy(extra) and not isinstance(extra, list):
            raise TypeError("meet is not iterable")
        policy: Any = dict(leaf, meet=list(chain[:-1]) + (list(extra) if truthy(extra) else [])) if isinstance(leaf, dict) else {"meet": list(chain[:-1])}
    else:
        policy = {"predicates": []}
    model = to_model(policy)
    base = collect_probes({"predicateSets": [probe_set(model)], "varyReversibility": "revCap" in model})
    verbs: List[Dict[str, Any]] = []
    any_verb = False
    overflow = False
    for verb in base["verbs"]:
        r = collect(dict(base, verbs=[verb]), lambda rep: decide(model, rep) != "deny", bound_of(opts), 1)
        if r["overflow"]:
            overflow = True
            break
        if not r["hits"]:
            continue
        hit = r["hits"][0]
        w = rep_to_action(hit)
        if verb.startswith("\u0000"):
            any_verb = True
        else:
            verbs.append({"verb": verb, "witness": w, "autonomous": decide(model, hit) == "allow"})
    violations: List[int] = []
    for i in range(len(chain) - 1):
        a = to_model(chain[i])
        b = to_model(chain[i + 1])
        pr = collect_probes({"predicateSets": [probe_set(a), probe_set(b)], "varyReversibility": "revCap" in a or "revCap" in b})
        out = search(pr, lambda rep: decide(b, rep) != "deny" and decide(a, rep) == "deny", bound_of(opts))
        if "hit" in out or out["overflow"]:
            violations.append(i + 1)
    depths: List[Any] = []
    for p in chain:
        cvs = p.get("caveats", UNDEF) if isinstance(p, dict) else UNDEF
        for c in (cvs if isinstance(cvs, list) else []):
            if jget(c, "type") == "delegation_depth" and is_num(jget(c, "max")):
                depths.append(c["max"])
    used = max(0, len(chain) - 1)
    depth: Dict[str, Any] = {"used": used}
    if depths:
        allowed = min(depths, key=jsnum)
        depth["allowed"] = allowed
        depth["remaining"] = max(0, jsnum(allowed) - used)
    out2: Dict[str, Any] = {"violations": violations, "verbs": verbs, "anyVerb": any_verb, "depth": depth}
    if overflow or model["undecidable"]:
        out2["approximate"] = True
        out2["reason"] = "representative grid exceeded the bound" if overflow else "over-approximated (%s)" % "; ".join(model["undecidable"])
    return out2


WIDEN = ("deny->allow", "deny->escalate", "escalate->allow")


def _sub(x: Any, y: Any) -> Any:
    return 0 if x == y else x - y  # Infinity - Infinity is no change


def diff_policies(a: Any, b: Any, o: Any = None) -> Dict[str, Any]:
    """`diff(A, B)`: which actions move between allow / escalate / deny, with witnesses; optionally how the max exposure moved."""
    o = {} if o is None else o
    ma, mb = to_model(a), to_model(b)
    pr = collect_probes({"predicateSets": [probe_set(ma), probe_set(mb)], "varyReversibility": "revCap" in ma or "revCap" in mb})
    limit = nn(jget(o, "limit"), 4)
    shifts: Dict[str, List[Dict[str, Any]]] = {}
    counts: Dict[str, int] = {}

    def visit(rep: Dict[str, Any]) -> bool:
        x, y = decide(ma, rep), decide(mb, rep)
        if x == y:
            return False
        k = "%s->%s" % (x, y)
        n = counts.get(k, 0)
        counts[k] = n + 1
        if n < limit:
            shifts.setdefault(k, []).append(rep_to_action(rep))
        return False  # walk the whole grid

    walk = collect(pr, visit, bound_of(o), 1)
    overflow = walk["overflow"]
    kinds = list(shifts)
    widens = any(k in WIDEN for k in kinds)
    narrows = any(k not in WIDEN for k in kinds)
    summary = ["%s: %d+ action(s), e.g. %s %s %s" % (k, len(shifts[k]), shifts[k][0]["verb"], shifts[k][0]["resource"], js_json(shifts[k][0].get("params") or {})) for k in kinds]
    d: Dict[str, Any] = {
        "equivalent": not kinds and not overflow and not ma["undecidable"] and not mb["undecidable"],
        "shifts": shifts, "widens": widens, "narrows": narrows, "summary": summary,
    }
    ex = jget(o, "exposure")
    if ex is not UNDEF:
        before = max_exposure(a, ex)
        after = max_exposure(b, ex)
        e = {
            "before": before, "after": after,
            "perActionDelta": _sub(after["perAction"]["max"], before["perAction"]["max"]),
            "autonomousDelta": _sub(after["autonomousWindow"]["bound"], before["autonomousWindow"]["bound"]),
            "delta": _sub(after["window"]["bound"], before["window"]["bound"]),
        }
        d["exposure"] = e
        worst = max(e["delta"], e["perActionDelta"], e["autonomousDelta"])
        best = min(e["delta"], e["perActionDelta"])
        verb = js_str(jget(ex, "verb"))
        if worst > 0:
            summary.append("max exposure of %s rises by %s" % (verb, num_str(jsnum(worst))))
        elif best < 0:
            summary.append("max exposure of %s falls by %s" % (verb, num_str(jsnum(-best))))
    if overflow or ma["undecidable"] or mb["undecidable"]:
        d["approximate"] = True
        seen: Dict[str, None] = {}
        for r in ma["undecidable"] + mb["undecidable"]:
            seen[r] = None
        d["reason"] = "representative grid exceeded the bound" if overflow else "over-approximated (%s)" % "; ".join(seen)
    return d


def diff_gate(d: Any, allow: Any = None) -> Dict[str, Any]:
    """A CI gate over a diff: fails when the change widens authority beyond what the reviewer allowed."""
    allow = {} if allow is None else allow
    reasons: List[str] = []
    if jget(d, "widens") is True and jget(allow, "widen") is not True:
        reasons.append("widens authority: %s" % "; ".join(s for s in d["summary"] if any(s.startswith(k) for k in WIDEN)))
    ex = jget(d, "exposure")
    rise = max(ex["delta"], ex["perActionDelta"], ex["autonomousDelta"]) if truthy(ex) else 0
    lim = nn(jget(allow, "maxExposureIncrease"), 0)
    if rise > lim:
        reasons.append("max exposure rises by %s" % num_str(jsnum(rise)))
    if truthy(jget(d, "approximate")):
        reasons.append("inconclusive: %s" % js_str(nn(jget(d, "reason"), "approximate")))
    return {"ok": len(reasons) == 0, "reasons": reasons}


def find_with_backend(backend: Any, q: Any) -> Dict[str, Any]:
    """Check what an optional external solver returned: a witness is re-checked by the real evaluator (never trusted); an unsat
    claim is returned labelled as solver-claimed. `backend` has a `name` and a `find(query)` callable returning
    {witness?, unsat?} (a dict {"name", "find"} works too)."""
    find = backend["find"] if isinstance(backend, dict) else backend.find
    name = backend["name"] if isinstance(backend, dict) else backend.name
    r = find(q)
    w = jget(r, "witness")
    if w is not UNDEF:
        ma = to_model(jget(q, "a"))
        qb = jget(q, "b")
        qv = jget(q, "verb")
        if jget(q, "kind") == "reachable":
            ok = decide_action(ma, w) != "deny" and (qv is UNDEF or strict_eq(jget(w, "verb"), qv))
        else:
            ok = qb is not UNDEF and ((decide_action(ma, w) != "deny") != (decide_action(to_model(qb), w) != "deny"))
        return {"witness": w} if ok else {"rejected": True}
    if jget(r, "unsat") is True:
        return {"claimedUnsat": {"by": name, "proof": "solver-claimed, not machine-checked"}}
    return {}


# ---- workflow DAG exposure ----------------------------------------------------------------------------------------------------

PATH_CAP = 1_000_000


def dag_exposure(b: Any) -> Dict[str, Any]:
    """Static exposure of a workflow body (steps, dependency DAG, edges, budget); raises ValueError (the reference's RangeError) on a
    body that is not a DAG."""
    steps = req_list(jget(b, "steps"))
    by_id: Dict[Any, Any] = {}
    for s in steps:
        by_id[jget(s, "id")] = s
    if len(by_id) != len(steps):
        raise ValueError("dagExposure: duplicate step id")
    level: Dict[Any, int] = {}
    anc: Dict[Any, set] = {}
    visiting: set = set()

    def visit(id_: Any) -> None:
        if id_ in level:
            return
        if id_ in visiting:
            raise ValueError("dagExposure: cycle")
        visiting.add(id_)
        if id_ not in by_id:
            raise ValueError("dagExposure: unknown step %s" % js_str(id_))
        s = by_id[id_]
        a: set = set()
        lv = 0
        for d in req_list(jget(s, "deps")):
            visit(d)
            a.add(d)
            a |= anc[d]
            lv = max(lv, level[d] + 1)
        visiting.discard(id_)
        anc[id_] = a
        level[id_] = lv

    for s in steps:
        visit(jget(s, "id"))
    depth = max([0] + list(level.values())) + 1
    widths: Dict[int, int] = {}
    for lv in level.values():
        widths[lv] = widths.get(lv, 0) + 1
    level_width: Any = max(widths.values()) if widths else -_INF

    children: Dict[Any, List[Any]] = {jget(s, "id"): [] for s in steps}
    for s in steps:
        for d in jget(s, "deps"):
            children[d].append(jget(s, "id"))
    memo: Dict[Any, int] = {}
    capped = [False]

    def to_leaves(id_: Any) -> int:
        if id_ in memo:
            return memo[id_]
        kids = children[id_]
        n = 1 if len(kids) == 0 else 0
        for k in kids:
            n += to_leaves(k)
        if n > PATH_CAP:
            n = PATH_CAP
            capped[0] = True
        memo[id_] = n
        return n

    paths = 0
    for s in steps:
        if len(jget(s, "deps")) == 0:
            paths = min(PATH_CAP, paths + to_leaves(jget(s, "id")))

    budget = jget(b, "budget")
    caps = jget(budget, "caps")
    if caps is UNDEF or caps is None or not isinstance(caps, dict):
        raise TypeError("Object.entries requires an object")
    cost: Dict[str, Any] = {}
    for name in key_order(caps):
        cap = caps[name]
        total = 0
        for s in steps:
            sc = jget(s, "cost")
            total = total + (sc[name] if isinstance(sc, dict) and name in sc and sc[name] is not None else 0)
        cost[name] = {"cap": cap, "total": total, "maxSpend": min(cap, total)}
    max_steps = jget(budget, "max_steps")
    never: List[Dict[str, Any]] = []
    for s in steps:
        sc = jget(s, "cost")
        if isinstance(sc, dict) and any(c > nn(caps.get(n), 0) for n, c in sc.items()):
            never.append({"step": jget(s, "id"), "reason": "cost_over_cap"})
        elif len(anc[jget(s, "id")]) + 1 > jsnum(max_steps) if is_num(max_steps) else False:
            never.append({"step": jget(s, "id"), "reason": "needs_more_steps_than_budget"})

    edges = req_list(jget(b, "edges"))
    feeds: Dict[Any, set] = {jget(s, "id"): set() for s in steps}
    for e in edges:
        feeds[jget(jget(e, "to"), "step")].add(jget(jget(e, "from"), "step"))

    def lineage_of(id_: Any, seen: set) -> set:
        for f in feeds[id_]:
            if f not in seen:
                seen.add(f)
                lineage_of(f, seen)
        return seen

    sinks: List[Dict[str, Any]] = []
    for s in steps:
        sk = jget(s, "sink")
        if sk is None:
            continue
        sid = jget(s, "id")
        incoming = [e for e in edges if jget(jget(e, "to"), "step") == sid]
        lineage = sorted(lineage_of(sid, set()), key=lambda x: x.encode("utf-16-be", "surrogatepass"))
        sinks.append(uobj({
            "step": sid, "sink": sk, "lineage": lineage,
            "protected": len(jget(s, "deny_labels")) > 0 or len(jget(s, "escalate_labels")) > 0 or any(len(jget(e, "deny_labels")) > 0 for e in incoming),
        }))
    unprotected = [k["step"] for k in sinks if not k["protected"] and len(k["lineage"]) > 0]
    ordering_only = [jget(s, "id") for s in steps if len(jget(s, "deps")) > 0 and not any(jget(jget(e, "to"), "step") == jget(s, "id") for e in edges)]
    pipelinable = [i for i, e in enumerate(edges) if jget(e, "promise") is not None]
    ms = jsnum(max_steps) if is_num(max_steps) else math.nan
    return {
        "steps": len(steps), "maxSteps": min(len(steps), ms) if ms == ms else None, "depth": depth, "levelWidth": level_width,
        "paths": paths, "pathsCapped": capped[0], "cost": cost, "neverRunnable": never, "sinks": sinks, "unprotectedSinks": unprotected,
        "orderingOnly": ordering_only, "pipelinable": pipelinable,
    }
