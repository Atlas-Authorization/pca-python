"""Lint a policy against the action schema / ActionDefs it is written for, and the policy-as-code test runner (boundary-test
generation, signed test documents). Port of the TypeScript reference (@atlasauth/pca-analyzer)."""
from ._fin import fin
from typing import Any, Dict, List

from . import ed25519
from .analyzer_core import (
    DEFAULT_MAX_COMBINATIONS, always_denies, collect, collect_probes, context_of_action, decide, decide_action, probe_set, rep_to_action,
    to_model, veto_applies,
)
from .analyzer_coverage import permit_id, witness_of
from .analyzer_exposure import thresholds_of
from .analyzer_js import (
    UNDEF, includes, is_num, jget, js_json, js_str, jsnum, key_order, nn, num_str, oget, own, req_list, spread, strict_eq, truthy, uobj,
)
from .analyzer_residual import policy_digest_of
from .pca import b64u, decode_b64u_strict, hash_canonical, sha256
from .predicates import is_group_condition, is_leaf_condition

POLICY_TESTS_KIND = "pca-policy-tests"
POLICY_TESTS_SIG_DOMAIN = "atlas-pca/policy-tests/v1\0"

_DEF_TYPE = {"string": "string", "integer": "integer", "boolean": "boolean", "date": "date", "set": "set", "array": "array"}


def _def_shape(p: Any) -> Dict[str, Any]:
    t = jget(p, "type")
    out: Dict[str, Any] = {}
    if isinstance(t, str) and t in _DEF_TYPE:
        out["type"] = _DEF_TYPE[t]
    if truthy(jget(p, "role")):
        out["semantic"] = jget(p, "role")
    if truthy(jget(p, "values")):
        out["values"] = jget(p, "values")
    if jget(p, "min") is not UNDEF:
        out["min"] = jget(p, "min")
    if jget(p, "max") is not UNDEF:
        out["max"] = jget(p, "max")
    if truthy(jget(p, "sensitivity")):
        out["sensitivity"] = jget(p, "sensitivity")
    if jget(p, "required") is not UNDEF:
        out["required"] = jget(p, "required")
    return out


def _entries(o: Any) -> List[Any]:
    o = nn(o, {})
    if not isinstance(o, dict):
        raise TypeError("Object.entries requires an object")
    return [(k, o[k]) for k in key_order(o)]


def verb_shapes_from_action_defs(defs: Any) -> List[Dict[str, Any]]:
    """Verb shapes from ActionDefs ({verb, params: {name: {type, role?, required?, values?, min?, max?, sensitivity?}}}). Types the
    policy language cannot compare directly (datetime, duration, object_ref) stay untyped."""
    return [uobj({"verb": jget(d, "verb"), "params": {k: _def_shape(p) for k, p in _entries(jget(d, "params"))}}) for d in req_list(defs)]


def verb_shapes(src: Any) -> List[Dict[str, Any]]:
    """The verbs and parameters of a signed action schema ({verbs: [...]}), a list of shapes, or a list of ActionDefs."""
    if isinstance(src, dict) and "verbs" in src:
        out = []
        for v in req_list(src["verbs"]):
            params: Dict[str, Any] = {}
            for k, d in _entries(jget(v, "params")):
                s: Dict[str, Any] = {"type": jget(d, "type")}
                if truthy(jget(d, "values")):
                    s["values"] = jget(d, "values")
                if jget(d, "min") is not UNDEF:
                    s["min"] = jget(d, "min")
                if jget(d, "max") is not UNDEF:
                    s["max"] = jget(d, "max")
                if truthy(jget(d, "unit")):
                    s["unit"] = jget(d, "unit")
                s["semantic"] = jget(d, "semantic")
                s["sensitivity"] = jget(d, "sensitivity")
                if jget(d, "required") is not UNDEF:
                    s["required"] = jget(d, "required")
                params[k] = uobj(s)
            out.append(uobj({"verb": jget(v, "verb"), "params": params}))
        return out
    lst = req_list(src)
    shapes = []
    for d in lst:
        v = d["verb"] if isinstance(d, dict) and "verb" in d else False
        if not truthy(v):
            v = d["id"] if isinstance(d, dict) and "id" in d else False
        if not truthy(v):
            v = ""
        shapes.append({"verb": v, "params": {k: _def_shape(p) for k, p in _entries(jget(d, "params"))}})
    for i, v in enumerate(shapes):
        orig = nn(jget(lst[i], "params"), {})
        for k in v["params"]:
            if oget(own(orig, k), "semantic") is not UNDEF:
                v["params"][k]["semantic"] = orig[k]["semantic"]
            if oget(own(orig, k), "unit") is not UNDEF:
                v["params"][k]["unit"] = orig[k]["unit"]
    return shapes


_NUMERIC_OPS = ("lt", "lte", "gt", "gte")


def _leaves(c: Any, into: List[Any]) -> List[Any]:
    if not isinstance(c, (dict, list)):
        return into
    if is_group_condition(c):
        if "all_of" in c and isinstance(c["all_of"], list):
            for x in c["all_of"]:
                _leaves(x, into)
        elif "any_of" in c and isinstance(c["any_of"], list):
            for x in c["any_of"]:
                _leaves(x, into)
        elif "not" in c:
            _leaves(c["not"], into)
    else:
        into.append(c)
    return into


def _typeof(x: Any) -> str:
    if isinstance(x, bool):
        return "boolean"
    if is_num(x):
        return "number"
    if isinstance(x, str):
        return "string"
    return "undefined" if x is UNDEF else "object"


def _type_ok(t: Any, v: Any) -> bool:
    if t is UNDEF:
        return True
    if t == "integer":
        return is_num(v) and fin(jsnum(v))
    if t == "boolean":
        return isinstance(v, bool)
    if t == "string" or t == "date":
        return isinstance(v, str)
    return True


def _semantic_money(d: Any) -> bool:
    s = nn(jget(d, "semantic"), "")
    if not isinstance(s, str):
        raise TypeError("startsWith is not a function")
    return s.startswith("money.")


def _grants(p: Any, verb: Any) -> bool:
    pv = jget(p, "verb")
    return bool(strict_eq(pv, "*") or strict_eq(pv, verb) or (isinstance(pv, list) and (includes(pv, "*") or includes(pv, verb))))


def _num(v: Any) -> str:
    return num_str(jsnum(v))


def validate_policy_against_schema(policy: Any, src: Any, o: Any = None) -> Dict[str, Any]:
    """Lint a policy against the schema it is written for: {ok, findings: [{code, severity, where, message}]}; ok is False when a
    finding is an error."""
    o = {} if o is None else o
    shapes = verb_shapes(src)
    by_verb: Dict[Any, Dict[str, Any]] = {}
    for s in shapes:
        by_verb[s.get("verb", UNDEF)] = s
    schema_units = jget(o, "schemaUnits")
    if schema_units is UNDEF or schema_units is None:
        schema_units = src.get("units", UNDEF) if isinstance(src, dict) and "units" in src else UNDEF
    model = to_model(policy)
    findings: List[Dict[str, Any]] = []
    units = jget(o, "units")
    list_ungranted = truthy(jget(o, "listUngranted"))

    def add(code: str, severity: str, where: str, message: str) -> None:
        findings.append({"code": code, "severity": severity, "where": where, "message": message})

    def check(p: Any, where: str, is_veto: bool) -> None:
        pv = jget(p, "verb")
        if strict_eq(pv, "*") or (isinstance(pv, list) and includes(pv, "*")):
            verbs = [s.get("verb", UNDEF) for s in shapes]
        elif isinstance(pv, list):
            verbs = list(pv)
        else:
            verbs = [pv]
        for v in verbs:
            if not _has_verb(by_verb, v):
                add("undeclared-verb", "warn" if is_veto else "error", where, "verb '%s' is not declared by the schema" % js_str(v))
        declared = [by_verb[v] for v in verbs if _has_verb(by_verb, v)]
        if not declared:
            return
        pw = nn(jget(p, "where"), [])
        for wi, w in enumerate(req_list(pw)):
            for c in _leaves(w, []):
                if not is_leaf_condition(c) or not c["field"].startswith("action.params."):
                    continue
                name = c["field"][len("action.params."):].split(".")[0]
                at = "%s.where[%d]" % (where, wi)
                having = [s for s in declared if name in s["params"]]
                if not having:
                    add("undeclared-param", "error", at, "parameter '%s' is declared by none of %s" % (name, ", ".join(js_str(s.get("verb", UNDEF)) for s in declared)))
                    continue
                if len(having) < len(declared):
                    add("undeclared-param", "warn", at, "parameter '%s' is not declared by %s" % (
                        name, ", ".join(js_str(s.get("verb", UNDEF)) for s in declared if not any(s is h for h in having))))
                d = having[0]["params"][name]
                op = c.get("op", UNDEF)
                val = c.get("value", UNDEF)
                vals = val if isinstance(val, list) and (op == "in" or op == "nin") else [val]
                dtype = own(d, "type")
                if "ref" not in c and op in ("eq", "ne", "in", "nin") + _NUMERIC_OPS:
                    for x in vals:
                        if not _type_ok(dtype, x):
                            add("type-mismatch", "error", at, "'%s' is %s but is compared (%s) with %s" % (name, js_str(dtype), op, _typeof(x)))
                if op in _NUMERIC_OPS and dtype is not UNDEF and dtype != "integer":
                    if dtype == "string" or dtype == "date":
                        add("ordering-on-string", "warn", at, "'%s' is %s: ordering follows UTF-8 byte order" % (name, dtype))
                    else:
                        add("type-mismatch", "error", at, "ordering operator %s on %s parameter '%s'" % (op, js_str(dtype), name))
                dvals = own(d, "values")
                if truthy(dvals) and (op == "eq" or op == "in") and isinstance(vals[0] if vals else UNDEF, str):
                    missing = [x for x in vals if isinstance(x, str) and not includes(dvals, x)]
                    if len(missing) == len(vals):
                        add("value-not-in-enum", "error", at, "no value of %s %s is in the schema's set for '%s'" % (op, js_json(vals), name))
                    elif missing:
                        add("value-not-in-enum", "warn", at, "%s are not in the schema's set for '%s'" % (js_json(missing), name))
                dmin, dmax = own(d, "min"), own(d, "max")
                if dtype == "integer" and is_num(val) and "ref" not in c:
                    v = val
                    dead = ((op == "eq" and ((dmax is not UNDEF and v > dmax) or (dmin is not UNDEF and v < dmin)))
                            or (op == "gt" and dmax is not UNDEF and v >= dmax)
                            or (op == "gte" and dmax is not UNDEF and v > dmax)
                            or (op == "lt" and dmin is not UNDEF and v <= dmin)
                            or (op == "lte" and dmin is not UNDEF and v < dmin))
                    lo = "-inf" if dmin is UNDEF or dmin is None else _num(dmin)
                    hi = "inf" if dmax is UNDEF or dmax is None else _num(dmax)
                    if dead:
                        add("out-of-range", "error", at, "'%s' %s %s can never hold: the schema bounds it to [%s, %s]" % (name, op, _num(v), lo, hi))
                    elif (op == "lte" and dmax is not UNDEF and v >= dmax) or (op == "gte" and dmin is not UNDEF and v <= dmin):
                        add("redundant-bound", "info", at, "'%s' %s %s never binds: the schema already bounds it to [%s, %s]" % (name, op, _num(v), lo, hi))
                dunit = own(d, "unit")
                if truthy(dunit) and units is not UNDEF and (op in _NUMERIC_OPS or op == "eq") and not is_veto:
                    tag = own(units, c["field"])
                    if tag is UNDEF or tag is None:
                        tag = own(units, "action.params.%s" % name)
                    sch = schema_units.get(dunit, UNDEF) if isinstance(schema_units, dict) and isinstance(dunit, str) else UNDEF
                    if tag is UNDEF or tag is None:
                        add("unit-missing", "error", at, "'%s' carries unit '%s' but the policy has no unit tag for it (rule 20)" % (name, js_str(dunit)))
                    elif truthy(sch) and (not strict_eq(jget(tag, "kind"), jget(sch, "kind")) or not strict_eq(jget(tag, "currency"), jget(sch, "currency"))
                                          or not strict_eq(jget(tag, "exponent"), jget(sch, "exponent"))):
                        add("unit-mismatch", "error", at, "'%s': policy unit %s differs from the schema's %s (rule 20)" % (name, js_json(tag), js_json(sch)))

    for i, p in enumerate(model["predicates"]):
        if not isinstance(p, (dict, list)):
            continue
        check(p, "predicates[%d]" % i, False)
        r = always_denies({"predicates": [p]})
        if r["alwaysDenies"] and not r.get("approximate"):
            add("unreachable-predicate", "warn", "predicates[%d]" % i, "no action can ever match this predicate")
    for i, v in enumerate(model["vetoes"]):
        check(jget(v, "when"), "vetoes[%d]" % i, True)

    # a money verb with no ceiling in any predicate that grants it
    for s in shapes:
        sverb = s.get("verb", UNDEF)
        money = [name for name in key_order(s["params"]) if _semantic_money(s["params"][name])]
        if not money:
            continue
        granting = [p for p in model["predicates"] if _grants(p, sverb)]
        if not granting:
            if list_ungranted:
                add("verb-not-granted", "info", js_str(sverb), "the schema declares '%s' but no predicate grants it" % js_str(sverb))
            continue
        for name in money:
            path = "action.params.%s" % name

            def bounded(p: Any, path: str = path) -> bool:
                for w in req_list(nn(jget(p, "where"), [])):
                    src_w = {"all_of": w["all_of"] if "all_of" in w else []} if is_group_condition(w) else w
                    if any(is_leaf_condition(c) and c["field"] == path and c.get("op") in ("lt", "lte", "eq", "in") for c in _leaves(src_w, [])):
                        return True
                return False

            if not all(bounded(p) for p in granting):
                add("unbounded-money", "warn", js_str(sverb), "'%s' can move '%s' with no per-action ceiling in at least one granting predicate" % (js_str(sverb), name))
    if list_ungranted:
        for s in shapes:
            if any(_semantic_money(d) for d in s["params"].values()):
                continue
            sverb = s.get("verb", UNDEF)
            if not any(_grants(p, sverb) for p in model["predicates"]):
                add("verb-not-granted", "info", js_str(sverb), "the schema declares '%s' but no predicate grants it" % js_str(sverb))
    return {"ok": all(f["severity"] != "error" for f in findings), "findings": findings}


def _has_verb(by_verb: Dict[Any, Any], v: Any) -> bool:
    try:
        return v in by_verb
    except TypeError:
        return False


# ---- policy-as-code test runner -------------------------------------------------------------------------------------------------


def policy_tests_doc(policy: Any, cases: Any) -> Dict[str, Any]:
    return {"v": 1, "kind": POLICY_TESTS_KIND, "policy_digest": policy_digest_of(to_model(policy)), "cases": cases}


def run_policy_tests(policy: Any, doc: Any, opts: Any = None) -> Dict[str, Any]:
    """Run a test document against a policy: {total, passed, failures, digestMatch, ok}. With `requireDigest` a changed policy fails
    even if every case still passes."""
    opts = {} if opts is None else opts
    model = to_model(policy)
    failures: List[Dict[str, Any]] = []
    cases = req_list(jget(doc, "cases"))
    for c in cases:
        w = witness_of(model, jget(c, "action"))
        decided_by = w["winner"]["id"]
        exp_by = jget(c, "decidedBy")
        if not strict_eq(w["decision"], jget(c, "expect")) or (exp_by is not UNDEF and not strict_eq(exp_by, decided_by)):
            f = uobj({"name": jget(c, "name"), "expected": jget(c, "expect"), "got": w["decision"], "decidedBy": decided_by})
            if exp_by is not UNDEF:
                f["expectedDecidedBy"] = exp_by
            failures.append(f)
    digest_match = strict_eq(jget(doc, "policy_digest"), policy_digest_of(model))
    return {"total": len(cases), "passed": len(cases) - len(failures), "failures": failures, "digestMatch": digest_match,
            "ok": len(failures) == 0 and (jget(opts, "requireDigest") is not True or digest_match)}


def _message(doc: Any) -> bytes:
    return POLICY_TESTS_SIG_DOMAIN.encode("utf-8") + sha256(hash_canonical(doc).encode("utf-8"))


def sign_policy_tests(doc: Any, secret: bytes, signer_public: str) -> Dict[str, Any]:
    """The principal signs the confirmed examples. `secret` is the Ed25519 seed."""
    return {"doc": doc, "signer": signer_public, "sig": b64u(ed25519.sign(secret, _message(doc)))}


def verify_policy_tests(s: Any, expected_signer: Any) -> bool:
    try:
        if not strict_eq(jget(s, "signer"), expected_signer):
            return False
        d = jget(s, "doc")
        if d is UNDEF or d is None or jget(d, "kind") != POLICY_TESTS_KIND:
            return False
        sig = jget(s, "sig")
        if not isinstance(sig, str):
            return False
        pk = decode_b64u_strict(jget(s, "signer"), 32)
        msg = _message(d)
        sg = decode_b64u_strict(sig, 64)
        if pk is None or sg is None:
            return False
        return bool(ed25519.verify(pk, msg, sg))
    except Exception:  # noqa: BLE001 - any failure is a refusal
        return False


def _param_paths(p: Any) -> List[str]:
    out: Dict[str, None] = {}

    def walk(c: Any) -> None:
        if not isinstance(c, (dict, list)):
            return
        o = c if isinstance(c, dict) else {}
        f = o.get("field")
        if isinstance(f, str) and f.startswith("action.params."):
            out[f] = None
        for k in ("all_of", "any_of"):
            if isinstance(o.get(k), list):
                for x in o[k]:
                    walk(x)
        if truthy(o.get("not", UNDEF)):
            walk(o["not"])

    w = jget(p, "where")
    if isinstance(w, list):
        for c in w:
            walk(c)
    return list(out)


def generate_boundary_tests(policy: Any, o: Any = None) -> Dict[str, Any]:
    """Boundary examples for every clause and numeric threshold: one minimal allow per permit, one trigger per prohibition, and the
    points just below, at and just above each threshold. Expectations are the policy's CURRENT behaviour, to be confirmed."""
    o = {} if o is None else o
    eps = nn(jget(o, "epsilon"), 1)
    model = to_model(policy)
    cases: List[Dict[str, Any]] = []
    seen = set()

    def add(name: str, action: Dict[str, Any]) -> None:
        key = js_json(action)
        if key in seen:
            return
        seen.add(key)
        w = witness_of(model, action)
        c: Dict[str, Any] = {"name": name, "action": action, "expect": w["decision"]}
        if w["winner"]["id"] is not None:
            c["decidedBy"] = w["winner"]["id"]
        cases.append(c)

    for i, p in enumerate(model["predicates"]):
        r = always_denies({"predicates": [p], "caveats": model["caveats"], "vetoes": model["vetoes"], "tighten": model["tighten"]})
        base = r.get("witness")
        if base is None:
            base = always_denies({"predicates": [p], "caveats": model["caveats"]}).get("witness")
        if not base:
            continue
        add("%s: minimal admitted action" % permit_id(i), base)
        for path in _param_paths(p):
            name = path[len("action.params."):]
            for t in thresholds_of(to_model({"predicates": [p]}), path):
                for tag, v in (("below", t - eps), ("at", t), ("above", t + eps)):
                    a = dict(base)
                    a["params"] = dict(base.get("params") or {}, **{name: v})
                    add("%s: %s %s %s" % (permit_id(i), name, tag, _num(t)), a)
        add("%s: unmentioned resource" % permit_id(i), dict(base, resource=base["resource"] + "/__other__"))
    # a trigger per prohibition: an action some permit would allow and this prohibition stops
    permit_only = dict(model, vetoes=[], tighten=[])
    pr = collect_probes({"predicateSets": [probe_set(model)], "varyReversibility": "revCap" in model})
    for v in model["vetoes"]:
        hits = collect(pr, lambda rep, v=v: decide(permit_only, rep) != "deny" and veto_applies(v, context_of_action(rep_to_action(rep))),
                       DEFAULT_MAX_COMBINATIONS, 1)["hits"]
        if hits:
            add("%s: trigger" % js_str(jget(v, "id")), rep_to_action(hits[0]))
    return policy_tests_doc(policy, cases)


def decide_all(policy: Any, doc: Any) -> List[str]:
    """Decision of every case of a test document under `policy`."""
    model = to_model(policy)
    return [decide_action(model, jget(c, "action")) for c in req_list(jget(doc, "cases"))]
