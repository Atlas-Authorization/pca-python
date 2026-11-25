"""Static analyzability of authority: the bounded decision engine and its relational queries (reachability, vacuity, totality,
subsumption, disjointness, equivalence, intent conformance). Port of the TypeScript reference (@atlasauth/pca-analyzer).

Policies are plain JSON trees; a model, a probe set, a representative and every result are plain dicts. The engine enumerates a
finite distinguishing grid of representative actions and evaluates the real predicate evaluator at each, so a verdict is exact
over the decided fragment and fails safe (`approximate`) outside it."""
import math
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Tuple

from .analyzer_js import (
    UNDEF, fin, has, includes, is_arr, is_fin, is_num, jget, js_gt, js_lt, js_json, js_str, jsnum, nn, num_str, own, req_list, spread,
    truthy, uobj,
)
from .pca import REVERSIBILITY_ORDER
from .predicates import (
    MAX_RE_RESOURCE_LEN,
    _starts_with,
    evaluate_condition,
    evaluate_condition_tri,
    evaluate_predicates,
    is_group_condition,
    is_leaf_condition,
    is_safe_regex_source,
    resolve_path,
)
from .prohibitions import when_matches
from .safe_regex import safe_regex_full_match, utf16_len

DEFAULT_MAX_COMBINATIONS = 200_000
FRESH_STRING = "\u0000atlas-analyzer::fresh-unmatched\u0000"
FRESH_VERB = "\u0000atlas-analyzer::fresh-verb\u0000"
FRESH_RESOURCE = "\u0000atlas-analyzer::fresh-resource\u0000"


class _Absent:
    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = _Absent()
FULL_INTERVAL = {"lo": -math.inf, "loInclusive": False, "hi": math.inf, "hiInclusive": False}

# ---- caveats ----------------------------------------------------------------------------------------------------------------


def analyze_caveats(caveats: Any) -> Dict[str, Any]:
    """Static satisfiability of an envelope caveat set: {sat, reason?, revCap?} (revCap indexes REVERSIBILITY_ORDER)."""
    if not isinstance(caveats, (list, tuple)):
        return {"sat": False, "reason": "caveats are not an array"}
    not_before_max = -math.inf
    expires_min = math.inf
    rev_cap: Optional[int] = None
    for cv in caveats:
        if not isinstance(cv, dict) or not isinstance(cv.get("type"), str):
            return {"sat": False, "reason": "malformed caveat (not an object with a string type)"}
        t = cv["type"]
        if t == "expires":
            at = fin(cv.get("at", UNDEF))
            if at is None:
                return {"sat": False, "reason": "expires.at is not a finite number"}
            expires_min = min(expires_min, at)
        elif t == "not_before":
            at = fin(cv.get("at", UNDEF))
            if at is None:
                return {"sat": False, "reason": "not_before.at is not a finite number"}
            not_before_max = max(not_before_max, at)
        elif t == "rate":
            mx = fin(cv.get("max", UNDEF))
            per = fin(cv.get("per_secs", UNDEF))
            if mx is None or per is None or per <= 0:
                return {"sat": False, "reason": "rate caveat requires finite max and per_secs > 0"}
            if mx < 1:
                return {"sat": False, "reason": "rate.max %s < 1 forbids every action" % num_str(mx)}
        elif t == "max_blast_radius":
            mx = fin(cv.get("max", UNDEF))
            if mx is None:
                return {"sat": False, "reason": "max_blast_radius.max is not a finite number"}
            if mx < 0:
                return {"sat": False, "reason": "max_blast_radius.max < 0 forbids every action"}
        elif t == "reversibility_max":
            cls = js_str(cv.get("class", UNDEF))
            if cls not in REVERSIBILITY_ORDER:
                return {"sat": False, "reason": "reversibility_max.class '%s' is unknown" % cls}
            idx = REVERSIBILITY_ORDER.index(cls)
            rev_cap = idx if rev_cap is None else min(rev_cap, idx)
        elif t == "delegation_depth":
            mx = fin(cv.get("max", UNDEF))
            if mx is None:
                return {"sat": False, "reason": "delegation_depth.max is not a finite number"}
            if mx < 0:
                return {"sat": False, "reason": "delegation_depth.max < 0 forbids every action"}
        elif t == "budget_alloc":
            lim = fin(cv.get("limit", UNDEF))
            if lim is None or lim < 0:
                return {"sat": False, "reason": "budget_alloc.limit must be a finite number >= 0"}
        else:
            return {"sat": False, "reason": "unknown caveat type '%s' (fail closed)" % t}
    if not_before_max != -math.inf and expires_min != math.inf and not_before_max >= expires_min:
        return {"sat": False, "reason": "not_before (%s) >= expires (%s): the validity window is empty" % (num_str(not_before_max), num_str(expires_min))}
    out: Dict[str, Any] = {"sat": True}
    if rev_cap is not None:
        out["revCap"] = rev_cap
    return out


# ---- constitution -----------------------------------------------------------------------------------------------------------


def vetoes_from_constitution(c: Any) -> Dict[str, Any]:
    """A constitution's stateless invariants as analyzer vetoes; the rest are reported in `unmodeled`."""
    vetoes: List[Dict[str, Any]] = []
    unmodeled: List[Dict[str, Any]] = []
    invs = c.get("invariants", UNDEF) if isinstance(c, dict) else UNDEF
    for inv in invs if isinstance(invs, (list, tuple)) else []:
        kind = jget(inv, "kind")
        iid = jget(inv, "id")
        if kind == "never":
            vetoes.append(uobj({"id": iid, "kind": "deny", "when": jget(inv, "when")}))
        elif kind == "never_unless":
            vetoes.append(uobj({"id": iid, "kind": "deny", "when": jget(inv, "when"), "unless": jget(inv, "unless")}))
        elif kind == "require_approval_over":
            vetoes.append(uobj({
                "id": iid, "kind": "approval", "when": jget(inv, "when"),
                "over": uobj({"path": jget(inv, "amount"), "threshold": jget(inv, "threshold")}), "unless": jget(inv, "approved"),
            }))
        elif kind == "cap" or kind == "rate":
            unmodeled.append(uobj({"id": iid, "kind": kind, "reason": "windowed total: bounded by maxExposure, not by a per-action veto"}))
        else:
            unmodeled.append(uobj({"id": iid, "kind": kind, "reason": "needs action history"}))
    return {"vetoes": vetoes, "unmodeled": unmodeled}


# ---- single-field interval / finite-set engine ------------------------------------------------------------------------------


def _numeric_cell_reps(thresholds: List[float]) -> List[float]:
    seen: Dict[float, None] = {}
    for t in thresholds:
        seen.setdefault(t, None)
    s = sorted(x for x in seen if math.isfinite(x))
    if not s:
        return []
    out = [s[0] - 1]
    for i, ti in enumerate(s):
        out.append(ti)
        if i + 1 < len(s):
            out.append((ti + s[i + 1]) / 2)
    out.append(s[-1] + 1)
    return out


def _value_key(x: Any) -> str:
    if x is FRESH_STRING or (isinstance(x, str) and x == FRESH_STRING):
        return "s:__fresh__"
    t = "number" if is_num(x) else "string" if isinstance(x, str) else "boolean" if isinstance(x, bool) else "undefined" if x is UNDEF else "object"
    return t + ":" + ("undefined" if x is UNDEF else js_json(x))


def field_probes(conditions: Any) -> List[Any]:
    """Representative probe values for one field from the conjunction of `where` conditions on it."""
    literals: List[Any] = []
    thresholds: List[float] = []
    prefixes: List[str] = []
    for c in req_list(conditions):
        if not is_leaf_condition(c) or "ref" in c:
            continue
        v = c.get("value", UNDEF)
        op = c.get("op", UNDEF)
        if op == "eq" or op == "ne":
            literals.append(v)
            if is_fin(v):
                thresholds.append(jsnum(v))
        elif op == "in" or op == "nin":
            if isinstance(v, (list, tuple)):
                for x in v:
                    literals.append(x)
                    if is_fin(x):
                        thresholds.append(jsnum(x))
        elif op in ("lt", "lte", "gt", "gte"):
            if is_fin(v):
                thresholds.append(jsnum(v))
        elif op in ("prefix", "like", "matches", "is_a"):
            if isinstance(v, str):
                literals.append(v)
                if op == "prefix":
                    prefixes.append(v)
        elif op == "member_of":
            if isinstance(v, str):
                literals.append(v)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    if isinstance(x, str):
                        literals.append(x)
    out: List[Any] = []
    seen = set()

    def add(x: Any) -> None:
        k = _value_key(x)
        if k not in seen:
            seen.add(k)
            out.append(x)

    for lit in literals:
        add(lit)
    for n in _numeric_cell_reps(thresholds):
        add(n)
    for p in prefixes:
        add(p)
        add(p + "x")
    add(FRESH_STRING)
    return out


def tighten_interval(iv: Dict[str, Any], op: Any, value: Any) -> Dict[str, Any]:
    """Tighten an interval {lo, loInclusive, hi, hiInclusive} by one numeric condition (a non-numeric operand returns it as is)."""
    if not is_fin(value):
        return iv
    n = dict(iv)
    if op == "eq":
        if value > n["lo"] or (value == n["lo"] and not n["loInclusive"]):
            n["lo"] = value
            n["loInclusive"] = True
        if value < n["hi"] or (value == n["hi"] and not n["hiInclusive"]):
            n["hi"] = value
            n["hiInclusive"] = True
    elif op == "gte":
        if value > n["lo"]:
            n["lo"] = value
            n["loInclusive"] = True
    elif op == "gt":
        if value > n["lo"] or (value == n["lo"] and n["loInclusive"]):
            n["lo"] = value
            n["loInclusive"] = False
    elif op == "lte":
        if value < n["hi"]:
            n["hi"] = value
            n["hiInclusive"] = True
    elif op == "lt":
        if value < n["hi"] or (value == n["hi"] and n["hiInclusive"]):
            n["hi"] = value
            n["hiInclusive"] = False
    return n


def interval_empty(iv: Dict[str, Any]) -> bool:
    if iv["lo"] > iv["hi"]:
        return True
    if iv["lo"] == iv["hi"]:
        return not (iv["loInclusive"] and iv["hiInclusive"])
    return False


def numeric_conjunction_satisfiable(conditions: Any) -> bool:
    """Is the numeric part of a field's `where` conjunction satisfiable (an empty interval is not)?"""
    by_field: Dict[str, Dict[str, Any]] = {}
    for c in req_list(conditions):
        if not is_leaf_condition(c) or "ref" in c:
            continue
        by_field[c["field"]] = tighten_interval(by_field.get(c["field"], FULL_INTERVAL), c.get("op", UNDEF), c.get("value", UNDEF))
    return not any(interval_empty(iv) for iv in by_field.values())


def predicate_numeric_satisfiable(where: Any) -> bool:
    if not isinstance(where, (list, tuple)):
        return True
    return numeric_conjunction_satisfiable(where)


# ---- model ------------------------------------------------------------------------------------------------------------------


def normalize_policy(p: Any) -> Dict[str, Any]:
    """A value that is not a policy is an empty policy (the verifier admits nothing under it)."""
    if not isinstance(p, dict):
        return {"predicates": [], "caveats": [], "vetoes": [], "tighten": []}

    def arr(k: str) -> list:
        v = p.get(k, UNDEF)
        return v if isinstance(v, list) else []
    return {"predicates": arr("predicates"), "caveats": arr("caveats"), "vetoes": arr("vetoes"), "tighten": arr("tighten")}


def probe_set(m: Dict[str, Any]) -> List[Any]:
    """The predicates whose literals shape the grid: the permits plus every veto and tighten trigger."""
    out: List[Any] = list(m["predicates"])
    for v in m["vetoes"]:
        out.append(jget(v, "when"))
        unless = jget(v, "unless")
        if isinstance(unless, list) and len(unless) > 0:
            out.append({"verb": "*", "where": unless})
        over = jget(v, "over")
        if truthy(over):
            out.append({"verb": "*", "where": [{"field": jget(over, "path"), "op": "gt", "value": jget(over, "threshold")}]})
    for t in m["tighten"]:
        out.append({"verb": "*", "where": [jget(t, "when")]})
    for x in m["meets"]:
        out.extend(probe_set(x))
    return out


def _condition_undecidable(c: Any, reasons: Dict[str, None]) -> None:
    if not isinstance(c, (dict, list)):
        return
    if is_group_condition(c):
        if "all_of" in c and isinstance(c["all_of"], list):
            for x in c["all_of"]:
                _condition_undecidable(x, reasons)
        elif "any_of" in c and isinstance(c["any_of"], list):
            for x in c["any_of"]:
                _condition_undecidable(x, reasons)
        elif "not" in c:
            _condition_undecidable(c["not"], reasons)
        return
    if not is_leaf_condition(c):
        return
    if "ref" in c:
        reasons["cross-field `ref` condition — the relation between two fields is not resolved"] = None
    if c["field"] == "action.params":
        reasons["condition on the whole `action.params` object is not enumerated precisely"] = None
    op = c.get("op", UNDEF)
    if op in ("lt", "lte", "gt", "gte") and not is_fin(c.get("value", UNDEF)):
        reasons["`%s` against a non-numeric operand — string ordering is not enumerated exactly" % op] = None
    if op in ("like", "matches", "is_a", "member_of"):
        reasons["`%s` condition — matched by over-approximation, not enumerated exactly" % op] = None


def _detect_undecidable(predicates: Iterable[Any]) -> List[str]:
    reasons: Dict[str, None] = {}
    for p in predicates:
        if not isinstance(p, (dict, list)):
            continue
        r = own(p, "resource")
        if isinstance(r, str) and r.startswith("re:"):
            reasons["re: regex resource matcher — resource dimension cannot be soundly enumerated"] = None
        w = own(p, "where")
        if isinstance(w, list):
            for c in w:
                _condition_undecidable(c, reasons)
    return list(reasons)


def to_model(p: Any) -> Dict[str, Any]:
    """The analyzable model of a policy: {predicates, caveats, vetoes, tighten, meets, caveatSat, caveatReason?, revCap?, undecidable}."""
    n = normalize_policy(p)
    ca = analyze_caveats(n["caveats"])
    meet = p.get("meet", UNDEF) if isinstance(p, dict) else UNDEF
    meets = [to_model(x) for x in meet] if isinstance(meet, list) else []
    if ca["sat"]:
        reason = next((x.get("caveatReason") for x in meets if not x["caveatSat"]), None)
    else:
        reason = ca.get("reason")
    caps = [c for c in [ca.get("revCap")] + [x.get("revCap") for x in meets] if c is not None]
    m: Dict[str, Any] = {
        "predicates": n["predicates"], "caveats": n["caveats"], "vetoes": n["vetoes"], "tighten": n["tighten"], "meets": meets,
        "caveatSat": bool(ca["sat"] and all(x["caveatSat"] for x in meets)),
    }
    if reason is not None:
        m["caveatReason"] = reason
    if caps:
        m["revCap"] = min(caps)
    seen: Dict[str, None] = {}
    for r in _detect_undecidable(probe_set(m)):
        seen[r] = None
    for x in meets:
        for r in x["undecidable"]:
            seen[r] = None
    m["undecidable"] = list(seen)
    return m


# ---- probe collection --------------------------------------------------------------------------------------------------------


def _add_verb_literals(c: Dict[str, Any], into: Dict[str, None]) -> None:
    v = c.get("value", UNDEF)
    op = c.get("op", UNDEF)
    if op in ("eq", "ne", "prefix", "like", "is_a"):
        if isinstance(v, str):
            into[v] = None
    elif op in ("in", "nin") and isinstance(v, (list, tuple)):
        for x in v:
            if isinstance(x, str):
                into[x] = None


def collect_probes(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """The grid dimensions {verbs, resources, revClasses, fields:[{path, values}]} of a set of predicate sets
    ({predicateSets, extraVerbs?, extraResources?, extraFieldConditions?, varyReversibility}); an absent value is ABSENT."""
    verb_literals: Dict[Any, None] = {}
    for v in nn(inputs.get("extraVerbs", UNDEF), []):
        verb_literals[v if not isinstance(v, (list, dict)) else id(v)] = None
    resource_literals: Dict[str, None] = {}
    field_conds: Dict[str, List[Dict[str, Any]]] = {}

    def classify_resource(r: Any) -> None:
        if r is UNDEF or (isinstance(r, str) and r == "*"):
            return
        if not isinstance(r, str):
            raise TypeError("resource matcher is not a string")
        if r.startswith("re:"):
            return
        if r.endswith("*"):
            body = r[:-1]
            resource_literals[body] = None
            resource_literals[body + "x"] = None
            return
        resource_literals[r] = None

    def handle_cond(c: Any) -> None:
        if not isinstance(c, (dict, list)):
            return
        if is_group_condition(c):
            if "all_of" in c and isinstance(c["all_of"], list):
                for x in c["all_of"]:
                    handle_cond(x)
            elif "any_of" in c and isinstance(c["any_of"], list):
                for x in c["any_of"]:
                    handle_cond(x)
            elif "not" in c:
                handle_cond(c["not"])
            return
        if not is_leaf_condition(c):
            return
        field = c["field"]
        if field == "action.verb":
            _add_verb_literals(c, verb_literals)  # type: ignore[arg-type]
            return
        if field == "action.resource":
            v = c.get("value", UNDEF)
            if c.get("op", UNDEF) == "prefix" and isinstance(v, str):
                classify_resource(v + "*")
            elif isinstance(v, str):
                classify_resource(v)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    if isinstance(x, str):
                        classify_resource(x)
            return
        field_conds.setdefault(field, []).append(c)

    for lst in req_list(inputs["predicateSets"]):
        for p in lst:
            if not isinstance(p, (dict, list)):
                continue
            verb = own(p, "verb")
            if isinstance(verb, str):
                if verb != "*":
                    verb_literals[verb] = None
            elif isinstance(verb, (list, tuple)):
                for v in verb:
                    if isinstance(v, str) and v != "*":
                        verb_literals[v] = None
            classify_resource(own(p, "resource"))
            w = own(p, "where")
            if isinstance(w, (list, tuple)):
                for c in w:
                    handle_cond(c)
    for r in nn(inputs.get("extraResources", UNDEF), []):
        classify_resource(r)
    for ec in nn(inputs.get("extraFieldConditions", UNDEF), []):
        handle_cond(dict(ec["cond"], field=ec["path"]))
    fields = [{"path": path, "values": field_probes(conds) + [ABSENT]} for path, conds in field_conds.items()]
    return {
        "verbs": list(verb_literals) + [FRESH_VERB],
        "resources": list(resource_literals) + [FRESH_RESOURCE],
        "revClasses": list(REVERSIBILITY_ORDER) if inputs.get("varyReversibility") else [None],
        "fields": fields,
    }


def product_size(pr: Dict[str, Any]) -> int:
    n = len(pr["verbs"]) * len(pr["resources"]) * len(pr["revClasses"])
    for f in pr["fields"]:
        n *= len(f["values"])
    return n


# ---- representatives --------------------------------------------------------------------------------------------------------


def _enumerate_fields(fields: List[Dict[str, Any]], i: int, acc: Dict[str, Any]) -> Generator[Dict[str, Any], None, None]:
    if i >= len(fields):
        yield dict(acc)
        return
    f = fields[i]
    for v in f["values"]:
        if v is ABSENT:
            acc.pop(f["path"], None)
        else:
            acc[f["path"]] = v
        yield from _enumerate_fields(fields, i + 1, acc)


def representatives(pr: Dict[str, Any]) -> Generator[Dict[str, Any], None, None]:
    """Every grid point as {verb, resource, revClass (None = no class), assignments: {path: value}}."""
    for verb in pr["verbs"]:
        for resource in pr["resources"]:
            for rev in pr["revClasses"]:
                for assignments in _enumerate_fields(pr["fields"], 0, {}):
                    yield {"verb": verb, "resource": resource, "revClass": rev, "assignments": assignments}


class _Leaf:
    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value


def _insert(root: Dict[str, Any], segs: List[str], value: Any) -> None:
    node = root
    for key in segs[:-1]:
        nxt = node.get(key)
        if nxt is None or isinstance(nxt, _Leaf):
            created: Dict[str, Any] = {}
            node[key] = created
            node = created
        else:
            node = nxt
    node[segs[-1]] = _Leaf(value)


def _materialize(node: Dict[str, Any]) -> Dict[str, Any]:
    return {k: (c.value if isinstance(c, _Leaf) else _materialize(c)) for k, c in node.items()}


def _build_roots(rep: Dict[str, Any]) -> Dict[str, Any]:
    roots: Dict[str, Dict[str, Any]] = {"action": {}, "subject": {}, "env": {}}
    for path, value in rep["assignments"].items():
        segs = path.split(".")
        if len(segs) < 2 or segs[0] not in roots:
            continue
        _insert(roots[segs[0]], segs[1:], value)
    action: Dict[str, Any] = {"verb": rep["verb"], "resource": rep["resource"], "params": {}}
    for key, child in roots["action"].items():
        if key == "verb" or key == "resource":
            continue
        if key == "params":
            if not isinstance(child, _Leaf):
                action["params"] = _materialize(child)
        else:
            action[key] = child.value if isinstance(child, _Leaf) else _materialize(child)
    if rep["revClass"] is not None:
        action["reversibility_class"] = rep["revClass"]
    return {"action": action, "subject": _materialize(roots["subject"]), "env": _materialize(roots["env"])}


def _reversibility_ok(model: Dict[str, Any], rev: Any) -> bool:
    if "revCap" not in model:
        return True
    if rev is None or rev is UNDEF:
        return False  # a reversibility_max caveat denies an action with no class
    return isinstance(rev, str) and rev in REVERSIBILITY_ORDER and REVERSIBILITY_ORDER.index(rev) <= model["revCap"]


def veto_applies(v: Any, ctx: Any) -> bool:
    """Does a veto apply at this context? Veto polarity: whatever cannot be decided counts as applying."""
    w = jget(v, "when")
    if not when_matches(None if w is UNDEF else w, ctx):
        return False
    over = jget(v, "over")
    if truthy(over):
        r = resolve_path(ctx, jget(over, "path"))
        val = r.get("value")
        is_over = (not r["found"] or not is_fin(val) or val < 0 or js_gt(val, jget(over, "threshold")))
        if not is_over:
            return False
    unless = jget(v, "unless")
    if jget(v, "kind") != "approval" and truthy(unless):
        if not isinstance(unless, list):
            raise TypeError("unless.every is not a function")
        if all(evaluate_condition(c, ctx) for c in unless):
            return False
    return True


def decision_at_context(model: Dict[str, Any], ctx: Any) -> str:
    """The ternary decision 'allow' | 'escalate' | 'deny' of the permission layer at a concrete context."""
    if not evaluate_predicates(model["predicates"], ctx)["allowed"]:
        return "deny"
    escalate = False
    for v in model["vetoes"]:
        if not veto_applies(v, ctx):
            continue
        if jget(v, "kind") == "deny":
            return "deny"
        escalate = True
    for t in model["tighten"]:
        w = jget(t, "when")
        if evaluate_condition_tri(None if w is UNDEF else w, ctx) == "false":
            continue
        if jget(t, "signal") == "deny":
            return "deny"
        escalate = True
    own_d = "escalate" if escalate else "allow"
    for x in model["meets"]:
        d = decision_at_context(x, ctx)
        if d == "deny":
            return "deny"
        if d == "escalate":
            own_d = "escalate"
    return own_d


def decide(model: Dict[str, Any], rep: Dict[str, Any]) -> str:
    """Ternary decision of a representative (the static caveat gate first)."""
    if not model["caveatSat"]:
        return "deny"
    if not _reversibility_ok(model, rep["revClass"]):
        return "deny"
    return decision_at_context(model, _build_roots(rep))


def admits(model: Dict[str, Any], rep: Dict[str, Any]) -> bool:
    return decide(model, rep) != "deny"


def context_of_action(action: Any) -> Dict[str, Any]:
    act: Dict[str, Any] = {}
    verb = jget(action, "verb")
    resource = jget(action, "resource")
    if verb is not UNDEF:
        act["verb"] = verb
    if resource is not UNDEF:
        act["resource"] = resource
    params = jget(action, "params")
    act["params"] = spread(None if params is UNDEF else params)
    rc = jget(action, "reversibilityClass")
    if rc is not UNDEF:
        act["reversibility_class"] = rc
    subj = jget(action, "subject")
    env = jget(action, "env")
    return {"action": act, "subject": spread(None if subj is UNDEF else subj), "env": spread(None if env is UNDEF else env)}


def decide_action(model: Dict[str, Any], action: Any) -> str:
    """Ternary decision of a fully-specified action."""
    if not model["caveatSat"]:
        return "deny"
    if not _reversibility_ok(model, jget(action, "reversibilityClass")):
        return "deny"
    return decision_at_context(model, context_of_action(action))


def admits_action(model: Dict[str, Any], action: Any) -> bool:
    return decide_action(model, action) != "deny"


def rep_to_action(rep: Dict[str, Any]) -> Dict[str, Any]:
    roots = _build_roots(rep)
    action: Dict[str, Any] = {"verb": rep["verb"], "resource": rep["resource"], "params": dict(roots["action"]["params"])}
    if rep["revClass"] is not None:
        action["reversibilityClass"] = rep["revClass"]
    if roots["subject"]:
        action["subject"] = roots["subject"]
    if roots["env"]:
        action["env"] = roots["env"]
    return action


def search(pr: Dict[str, Any], predicate: Callable[[Dict[str, Any]], bool], mx: Any) -> Dict[str, Any]:
    """Walk the grid to the first representative the predicate accepts: {hit?, overflow}."""
    if product_size(pr) > mx:
        return {"overflow": True}
    for rep in representatives(pr):
        if predicate(rep):
            return {"hit": rep, "overflow": False}
    return {"overflow": False}


def collect(pr: Dict[str, Any], predicate: Callable[[Dict[str, Any]], bool], mx: Any, limit: Any) -> Dict[str, Any]:
    """Like `search`, collecting up to `limit` accepted representatives."""
    if product_size(pr) > mx:
        return {"hits": [], "overflow": True}
    hits: List[Dict[str, Any]] = []
    for rep in representatives(pr):
        if predicate(rep):
            hits.append(rep)
            if len(hits) >= limit:
                break
    return {"hits": hits, "overflow": False}


# ---- queries ----------------------------------------------------------------------------------------------------------------


def bound_of(opts: Any) -> Any:
    """The grid bound; anything but a non-negative finite number falls back to the default."""
    m = opts.get("maxCombinations", UNDEF) if isinstance(opts, dict) else UNDEF
    f = fin(m)
    return m if f is not None and f >= 0 else DEFAULT_MAX_COMBINATIONS


def _merge_witness(witness: Dict[str, Any], provided: Any) -> Dict[str, Any]:
    params = dict(witness.get("params") or {})
    pp = jget(provided, "params")
    params.update(spread(None if pp is UNDEF else pp))
    out: Dict[str, Any] = uobj({"verb": jget(provided, "verb"), "resource": jget(provided, "resource"), "params": params})
    rc = jget(provided, "reversibilityClass")
    if rc is UNDEF or rc is None:
        rc = witness.get("reversibilityClass", UNDEF)
    if rc is not UNDEF:
        out["reversibilityClass"] = rc
    if "subject" in witness:
        out["subject"] = witness["subject"]
    if "env" in witness:
        out["env"] = witness["env"]
    return out


def reachable(policy: Any, action: Any, opts: Any = None) -> Dict[str, Any]:
    """Can any input complete `action` into one the policy admits? {reachable, witness?, approximate?, reason?}."""
    model = to_model(policy)
    mx = bound_of(opts)
    if not model["caveatSat"]:
        return {"reachable": False, "reason": "caveats unsatisfiable: %s" % model.get("caveatReason", "unknown")}
    rc = jget(action, "reversibilityClass")
    if rc is not UNDEF and "revCap" in model:
        idx = REVERSIBILITY_ORDER.index(rc) if isinstance(rc, str) and rc in REVERSIBILITY_ORDER else -1
        if idx < 0 or idx > model["revCap"]:
            return {"reachable": False, "reason": "reversibility class '%s' exceeds the caveat cap" % js_str(rc)}
    if admits_action(model, action):
        return {"reachable": True, "witness": action}
    base = collect_probes({"predicateSets": [probe_set(model)], "varyReversibility": "revCap" in model})
    provided = nn(jget(action, "params"), {})
    fields = []
    for f in base["fields"]:
        if f["path"].startswith("action.params."):
            key = f["path"][len("action.params."):]
            if isinstance(provided, dict) and key in provided:
                fields.append({"path": f["path"], "values": [provided[key]]})
                continue
        fields.append(f)
    if rc is not UNDEF:
        rev_classes: List[Any] = [rc]
    elif "revCap" in model:
        rev_classes = list(REVERSIBILITY_ORDER)
    else:
        rev_classes = [None]
    pr = {"verbs": [jget(action, "verb")], "resources": [jget(action, "resource")], "revClasses": rev_classes, "fields": fields}
    outcome = search(pr, lambda rep: admits(model, rep), mx)
    if "hit" in outcome:
        return {"reachable": True, "witness": _merge_witness(rep_to_action(outcome["hit"]), action)}
    if outcome["overflow"]:
        return {"reachable": True, "approximate": True, "reason": "representative grid exceeded the bound; could not prove unreachable"}
    if model["undecidable"]:
        return {
            "reachable": True, "approximate": True,
            "reason": "over-approximated (%s); could not construct a witness but cannot prove unreachable" % "; ".join(model["undecidable"]),
        }
    return {"reachable": False, "reason": "no predicate admits this action for any input (proven over the decided fragment)"}


def _probes_for(models: List[Dict[str, Any]], verb: Any = None) -> Dict[str, Any]:
    pr = collect_probes({"predicateSets": [probe_set(m) for m in models], "varyReversibility": any("revCap" in m for m in models)})
    if verb is not None and verb is not UNDEF:
        pr["verbs"] = [verb]
    return pr


def always_denies(policy: Any, verb: Any = None, opts: Any = None) -> Dict[str, Any]:
    """Does the policy deny everything (optionally restricted to `verb`)? Proven only over the decided fragment."""
    model = to_model(policy)
    mx = bound_of(opts)
    if not model["caveatSat"]:
        return {"alwaysDenies": True, "reason": "caveats unsatisfiable: %s" % model.get("caveatReason", "unknown")}
    outcome = search(_probes_for([model], verb), lambda rep: admits(model, rep), mx)
    if "hit" in outcome:
        return {"alwaysDenies": False, "witness": rep_to_action(outcome["hit"])}
    if outcome["overflow"]:
        return {"alwaysDenies": False, "approximate": True, "reason": "grid exceeded the bound; cannot prove vacuity"}
    if model["undecidable"]:
        return {"alwaysDenies": False, "approximate": True, "reason": "over-approximated (%s); cannot prove vacuity" % "; ".join(model["undecidable"])}
    return {"alwaysDenies": True}


def always_allows(policy: Any, verb: Any, opts: Any = None) -> Dict[str, Any]:
    """Does the policy admit EVERY action of `verb`? Proven only over the decided fragment."""
    model = to_model(policy)
    mx = bound_of(opts)
    if not model["caveatSat"]:
        return {"alwaysAllows": False, "reason": "caveats unsatisfiable: %s" % model.get("caveatReason", "unknown")}
    outcome = search(_probes_for([model], verb), lambda rep: not admits(model, rep), mx)
    if "hit" in outcome:
        return {"alwaysAllows": False, "counterexample": rep_to_action(outcome["hit"])}
    if outcome["overflow"]:
        return {"alwaysAllows": False, "approximate": True, "reason": "grid exceeded the bound; cannot prove totality"}
    if model["undecidable"]:
        return {"alwaysAllows": False, "approximate": True, "reason": "over-approximated (%s); cannot prove totality" % "; ".join(model["undecidable"])}
    return {"alwaysAllows": True}


def _approx_note(models: List[Dict[str, Any]], overflow: bool) -> Optional[str]:
    if overflow:
        return "representative grid exceeded the bound; cannot prove the relation"
    reasons: Dict[str, None] = {}
    for m in models:
        for r in m["undecidable"]:
            reasons[r] = None
    if reasons:
        return "over-approximated (%s); cannot prove the relation" % "; ".join(reasons)
    return None


def _relation(a: Any, b: Any, opts: Any, pred: Callable[[Dict[str, Any], Dict[str, Any], Dict[str, Any]], bool], key: str, witness_key: str) -> Dict[str, Any]:
    ma, mb = to_model(a), to_model(b)
    mx = bound_of(opts)
    outcome = search(_probes_for([ma, mb]), lambda rep: pred(ma, mb, rep), mx)
    if "hit" in outcome:
        return {key: False, witness_key: rep_to_action(outcome["hit"])}
    note = _approx_note([ma, mb], outcome["overflow"])
    if note is not None:
        return {key: False, "approximate": True, "reason": note}
    return {key: True}


def subsumes(a: Any, b: Any, opts: Any = None) -> Dict[str, Any]:
    """Does `a` permit everything `b` permits? A counterexample is an action `b` admits that `a` denies."""
    return _relation(a, b, opts, lambda ma, mb, r: admits(mb, r) and not admits(ma, r), "subsumes", "counterexample")


def disjoint(a: Any, b: Any, opts: Any = None) -> Dict[str, Any]:
    """Is there no action both policies admit? A witness is one both admit."""
    return _relation(a, b, opts, lambda ma, mb, r: admits(ma, r) and admits(mb, r), "disjoint", "witness")


def equivalent(a: Any, b: Any, opts: Any = None) -> Dict[str, Any]:
    """Do the policies admit exactly the same actions? A counterexample is admitted by exactly one."""
    return _relation(a, b, opts, lambda ma, mb, r: admits(ma, r) != admits(mb, r), "equivalent", "counterexample")


def _scope_matches(scope: Any, resource: Any) -> bool:
    if not isinstance(scope, str):
        raise TypeError("scope.startsWith is not a function")
    if scope == "*":
        return True
    if scope.startswith("re:"):
        src = scope[3:]
        if utf16_len(src) > 200 or utf16_len(resource) > MAX_RE_RESOURCE_LEN or not is_safe_regex_source(src):
            return False
        return safe_regex_full_match(src, resource) is True
    if scope.endswith("*"):
        return _starts_with(resource, scope[:-1])
    return scope == resource


def _intent_violation_kinds(action: Dict[str, Any], intent: Any, amount_field: Any, min_amount: Any) -> List[str]:
    kinds: List[str] = []
    verbs = jget(intent, "verbs")
    if not (includes(verbs, "*") or includes(verbs, action["verb"])):
        kinds.append("off-verb")
    scopes = nn(jget(intent, "resourceScopes"), [])
    req_list(scopes)
    if len(scopes) > 0 and not any(_scope_matches(s, action["resource"]) for s in scopes):
        kinds.append("off-scope")
    max_amount = jget(intent, "maxAmount")
    if max_amount is not UNDEF:
        amt = own(nn(action.get("params", UNDEF), {}), amount_field)
        if is_fin(amt):
            if js_gt(amt, max_amount):
                kinds.append("over-amount")
            elif js_lt(amt, min_amount):
                kinds.append("under-amount")
    return kinds


def intent_conformance(policy: Any, intent: Any, opts: Any = None) -> Dict[str, Any]:
    """Does the policy admit ONLY actions inside the declared intent envelope? {conforms, violations, approximate?, reason?}."""
    model = to_model(policy)
    mx = bound_of(opts)
    amount_field = nn(jget(intent, "amountField"), "amount")
    min_amount = nn(jget(intent, "minAmount"), 0)
    if not model["caveatSat"]:
        return {"conforms": True, "violations": []}
    extra_conds: List[Dict[str, Any]] = []
    max_amount = jget(intent, "maxAmount")
    if max_amount is not UNDEF:
        path = "action.params.%s" % js_str(amount_field)
        extra_conds.append({"path": path, "cond": {"field": path, "op": "lte", "value": max_amount}})
        extra_conds.append({"path": path, "cond": {"field": path, "op": "gte", "value": min_amount}})
    verbs = req_list(jget(intent, "verbs"))
    pr = collect_probes({
        "predicateSets": [probe_set(model)],
        "extraVerbs": [v for v in verbs if v != "*"],
        "extraResources": nn(jget(intent, "resourceScopes"), []),
        "extraFieldConditions": extra_conds,
        "varyReversibility": "revCap" in model,
    })
    fp = 1
    for f in pr["fields"]:
        fp *= len(f["values"])
    if len(pr["verbs"]) * len(pr["resources"]) * len(pr["revClasses"]) * fp > mx:
        return {"conforms": False, "approximate": True, "violations": [], "reason": "grid exceeded the bound; cannot prove conformance"}
    violations: List[Dict[str, Any]] = []
    for rep in representatives(pr):
        if not admits(model, rep):
            continue
        action = rep_to_action(rep)
        kinds = _intent_violation_kinds(action, intent, amount_field, min_amount)
        if kinds:
            violations.append({"action": action, "kinds": kinds})
            if len(violations) >= 16:
                break
    if violations:
        return {"conforms": False, "violations": violations}
    scopes = nn(jget(intent, "resourceScopes"), [])
    intent_regex = any(_scope_starts_re(s) for s in scopes)
    if model["undecidable"] or intent_regex:
        reasons = list(model["undecidable"])
        if intent_regex:
            reasons.append("re: intent resource scope not enumerated soundly")
        return {"conforms": False, "approximate": True, "violations": [], "reason": "over-approximated (%s); cannot prove conformance" % "; ".join(reasons)}
    return {"conforms": True, "violations": []}


def _scope_starts_re(s: Any) -> bool:
    if not isinstance(s, str):
        raise TypeError("s.startsWith is not a function")
    return s.startswith("re:")


def admits_concrete(policy: Any, action: Any) -> bool:
    """Exact admission of a fully-specified action (no existential search)."""
    return admits_action(to_model(policy), action)
