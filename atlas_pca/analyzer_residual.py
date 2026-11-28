"""Partial evaluation, residual policies, "what may I do?" discovery and data filters (SQL / UCAST). Port of the TypeScript
reference (@atlasauth/pca-analyzer). Everything here is advisory: the verifier stays authoritative."""
import functools
import math
import re
from typing import Any, Dict, List, Optional

from .analyzer_core import (
    DEFAULT_MAX_COMBINATIONS, collect_probes, decide, decide_action, probe_set, product_size, rep_to_action, representatives, to_model,
)
from .analyzer_exposure import thresholds_of
from .analyzer_js import (
    UNDEF, fin, is_num, jget, js_gt, js_json, js_str, jsnum, key_order, nn, req_list, spread, strict_eq, truthy, uobj,
)
from .pca import REVERSIBILITY_ORDER, hash_canonical
from .predicates import (
    evaluate_condition_tri, is_group_condition, is_leaf_condition, predicate_matches, resolve_path,
)

_UNKNOWN_VERB = "\u0000unknown-verb\u0000"
_UNKNOWN_RESOURCE = "\u0000unknown-resource\u0000"


def _is_unknown_path(path: Any, unknown: Any) -> bool:
    """A path is symbolic when it is an unknown path, below one, or an ancestor of one."""
    return isinstance(path, str) and any(path == u or path.startswith(u + ".") or u.startswith(path + ".") for u in unknown)


def _const(v: str, src: Any) -> Dict[str, Any]:
    return {"t": "const", "v": v, "src": src}


def _pe(c: Any, ctx: Any, unk: Any) -> Dict[str, Any]:
    if not isinstance(c, (dict, list)):
        return _const("unknown", c)
    if is_group_condition(c):
        if "all_of" in c:
            a = c["all_of"]
            if not isinstance(a, list) or len(a) == 0:
                return _const("unknown", c)
            rs = [_pe(x, ctx, unk) for x in a]
            if any(r["t"] == "const" and r["v"] == "false" for r in rs):
                return _const("false", c)
            kept = [r for r in rs if not (r["t"] == "const" and r["v"] == "true")]
            if not kept:
                return _const("true", c)
            if all(r["t"] == "const" for r in kept):
                return _const("unknown", c)
            cs = [r["src"] if r["t"] == "const" else r["c"] for r in kept]
            return {"t": "cond", "c": cs[0] if len(cs) == 1 else {"all_of": cs}}
        if "any_of" in c:
            a = c["any_of"]
            if not isinstance(a, list) or len(a) == 0:
                return _const("unknown", c)
            rs = [_pe(x, ctx, unk) for x in a]
            if any(r["t"] == "const" and r["v"] == "true" for r in rs):
                return _const("true", c)
            kept = [r for r in rs if not (r["t"] == "const" and r["v"] == "false")]
            if not kept:
                return _const("false", c)
            if all(r["t"] == "const" for r in kept):
                return _const("unknown", c)
            cs = [r["src"] if r["t"] == "const" else r["c"] for r in kept]
            return {"t": "cond", "c": cs[0] if len(cs) == 1 else {"any_of": cs}}
        r = _pe(c["not"], ctx, unk)
        if r["t"] == "cond":
            return {"t": "cond", "c": {"not": r["c"]}}
        return _const("false" if r["v"] == "true" else "true" if r["v"] == "false" else "unknown", c)
    if is_leaf_condition(c) and (_is_unknown_path(c["field"], unk) or _is_unknown_path(c.get("ref"), unk) or _is_unknown_path(c.get("collection"), unk)):
        return {"t": "cond", "c": c}
    return _const(evaluate_condition_tri(c, ctx), c)


def _pe_all(where: Any, ctx: Any, unk: Any) -> Any:
    """AND of a `where` list: ('v', 'true'|'false'|'unknown') or ('cs', [symbolic conditions])."""
    if where is UNDEF:
        return ("v", "true")
    if not isinstance(where, list):
        return ("v", "unknown")
    rs = [_pe(w, ctx, unk) for w in where]
    if any(r["t"] == "const" and r["v"] == "false" for r in rs):
        return ("v", "false")
    kept = [r for r in rs if not (r["t"] == "const" and r["v"] == "true")]
    if not kept:
        return ("v", "true")
    if all(r["t"] == "const" for r in kept):
        return ("v", "unknown")
    return ("cs", [r["src"] if r["t"] == "const" else r["c"] for r in kept])


def _context_of(k: Any) -> Dict[str, Any]:
    verb, resource = jget(k, "verb"), jget(k, "resource")
    params, subj, env, rc = jget(k, "params"), jget(k, "subject"), jget(k, "env"), jget(k, "reversibilityClass")
    action: Dict[str, Any] = {
        "verb": _UNKNOWN_VERB if verb is UNDEF or verb is None else verb,
        "resource": _UNKNOWN_RESOURCE if resource is UNDEF or resource is None else resource,
        "params": spread(None if params is UNDEF else params),
    }
    if rc is not UNDEF:
        action["reversibility_class"] = rc
    return {"action": action, "subject": spread(None if subj is UNDEF else subj), "env": spread(None if env is UNDEF else env)}


def policy_digest_of(model: Dict[str, Any]) -> str:
    """hashCanonical of the policy a residual was planned against."""
    return hash_canonical({
        "predicates": model["predicates"], "caveats": model["caveats"], "vetoes": model["vetoes"], "tighten": model["tighten"],
        "meet": [policy_digest_of(m) for m in model["meets"]],
    })


def _flatten(m: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = [m]
    for x in m["meets"]:
        out.extend(_flatten(x))
    return out


def _pm(pat: Dict[str, Any], ctx: Any) -> bool:
    return predicate_matches(pat, ctx)


def _residual_part(part: Dict[str, Any], ctx: Any, unk: Any, verb_known: bool, res_known: bool) -> Dict[str, Any]:
    predicates: List[Any] = []
    for p in part["predicates"]:
        if not isinstance(p, (dict, list)):
            continue
        pv, pr = jget(p, "verb"), jget(p, "resource")
        if verb_known and not _pm({"verb": pv, "resource": "*"}, ctx):
            continue
        if res_known and not _pm({"verb": "*", "resource": pr}, ctx):
            continue
        w = _pe_all(jget(p, "where"), ctx, unk)
        if w[0] == "v" and w[1] != "true":
            continue  # false and unknown both fail closed for a permit
        item: Dict[str, Any] = uobj({"verb": "*" if verb_known else pv})
        if not res_known and pr is not UNDEF:
            item["resource"] = pr
        if w[0] == "cs":
            item["where"] = w[1]
        predicates.append(item)
    vetoes = [v for v in (_pe_veto(v, ctx, unk, verb_known, res_known) for v in part["vetoes"]) if v is not None]
    tighten: List[Any] = []
    for t in part["tighten"]:
        tw = jget(t, "when")
        r = _pe(None if tw is UNDEF else tw, ctx, unk)
        if r["t"] == "const" and r["v"] == "false":
            continue  # a veto-polarity rule that cleanly cannot hold
        nt = spread(t)
        nt["when"] = r["c"] if r["t"] == "cond" else tw
        tighten.append(uobj(nt))
    return {"predicates": predicates, "caveats": part["caveats"], "vetoes": vetoes, "tighten": tighten}


def _pe_veto(v: Any, ctx: Any, unk: Any, verb_known: bool, res_known: bool) -> Optional[Dict[str, Any]]:
    when = jget(v, "when")
    wv = jget(when, "verb")
    if verb_known and not _pm({"verb": wv, "resource": "*"}, ctx):
        return None
    wr = jget(when, "resource")
    if res_known and wr is not UNDEF and not _pm({"verb": "*", "resource": wr}, ctx):
        return None
    w = _pe_all(jget(when, "where"), ctx, unk)
    if w[0] == "v" and w[1] == "false":
        return None  # veto polarity: a clean false removes the veto; true and unknown mean it applies
    keep = w[1] if w[0] == "cs" else None
    nw: Dict[str, Any] = uobj({"verb": "*" if verb_known else wv})
    if not res_known and wr is not UNDEF:
        nw["resource"] = wr
    if keep is not None:
        nw["where"] = keep
    out: Dict[str, Any] = uobj({"id": jget(v, "id"), "kind": jget(v, "kind"), "when": nw})
    over = jget(v, "over")
    if truthy(over):
        if _is_unknown_path(jget(over, "path"), unk):
            out["over"] = over
        else:
            r = resolve_path(ctx, jget(over, "path"))
            val = r.get("value")
            is_over = not r["found"] or fin(val) is None or val < 0 or js_gt(val, jget(over, "threshold"))
            if not is_over:
                return None
    unless = jget(v, "unless")
    if truthy(unless) and jget(v, "kind") == "approval":
        out["unless"] = unless  # the evidence of approval: carried, never used to drop the veto
    elif truthy(unless):
        u = _pe_all(unless, ctx, unk)
        if u[0] == "cs":
            out["unless"] = u[1]
        elif u[1] == "true":
            return None  # the exception certainly holds: the veto never applies
    return out


def residual(policy: Any, known: Any, opts: Any = None) -> Dict[str, Any]:
    """Specialise `policy` to `known` ({verb?, resource?, params?, subject?, env?, reversibilityClass?}); everything under
    `opts.unknown` stays symbolic. Returns {decision: 'never'|'always'|'conditional', reason?, policy, policyDigest}."""
    opts = {} if opts is None else opts
    model = to_model(policy)
    digest = policy_digest_of(model)
    verb_known = jget(known, "verb") is not UNDEF
    res_known = jget(known, "resource") is not UNDEF and jget(opts, "resourceUnknown") is not True
    unknown = nn(jget(opts, "unknown"), ["action.params"])
    unk = list(req_list(unknown)) + ([] if verb_known else ["action.verb"]) + ([] if res_known else ["action.resource"])
    ctx = _context_of(known)
    empty = {"predicates": [], "caveats": [], "vetoes": [], "tighten": []}

    def never(reason: str) -> Dict[str, Any]:
        return {"decision": "never", "reason": reason, "policy": empty, "policyDigest": digest}

    if not model["caveatSat"]:
        return never("caveats unsatisfiable: %s" % model.get("caveatReason", "unknown"))
    rc = jget(known, "reversibilityClass")
    if rc is not UNDEF and "revCap" in model:
        idx = REVERSIBILITY_ORDER.index(rc) if isinstance(rc, str) and rc in REVERSIBILITY_ORDER else -1
        if idx < 0 or idx > model["revCap"]:
            return never("reversibility class exceeds the caveat cap")
    parts = [_residual_part(m, ctx, unk, verb_known, res_known) for m in _flatten(model)]
    own, rest = parts[0], parts[1:]
    pol = dict(own)
    if rest:
        pol["meet"] = rest
    res: Dict[str, Any] = {"decision": "conditional", "policy": pol, "policyDigest": digest}
    if any(len(p["predicates"]) == 0 for p in parts):
        return never("no permit survives the known facts")
    for p in parts:
        for v in p["vetoes"]:
            w = v["when"]
            if (v.get("kind") == "deny" and ("resource" not in w or w["resource"] == "*") and ("where" not in w or len(w["where"]) == 0)
                    and "unless" not in v and "over" not in v):
                return never("veto %s applies to every completion" % js_str(v.get("id", UNDEF)))
    if all(any("where" not in x for x in p["predicates"]) and len(p["vetoes"]) == 0 and len(p["tighten"]) == 0 for p in parts):
        res["decision"] = "always"
    return res


def residual_policy(r: Any) -> Dict[str, Any]:
    """The residual as a policy the analyzer and the real evaluator both understand."""
    pol = jget(r, "policy")
    own = {k: v for k, v in pol.items() if k != "meet"}
    meet = pol.get("meet")
    if truthy(meet):
        own["meet"] = [dict(m) for m in meet]
    return own


def evaluate_residual(r: Any, ctx: Any) -> str:
    """Ternary decision of a residual once the unknown fields are bound."""
    if jget(r, "decision") == "never":
        return "deny"
    a = jget(ctx, "action")
    action: Dict[str, Any] = uobj({"verb": jget(a, "verb"), "resource": jget(a, "resource")})
    if truthy(jget(a, "params")):
        action["params"] = jget(a, "params")
    if truthy(jget(ctx, "subject")):
        action["subject"] = jget(ctx, "subject")
    if truthy(jget(ctx, "env")):
        action["env"] = jget(ctx, "env")
    if truthy(jget(a, "reversibility_class")):
        action["reversibilityClass"] = jget(a, "reversibility_class")
    return decide_action(to_model(residual_policy(r)), action)


# ---- "what may I do?" ---------------------------------------------------------------------------------------------------------

def _merge_ranges(rs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def lo(r: Dict[str, Any]) -> float:
        return jsnum(r["lo"]) if "lo" in r else -math.inf

    def cmp(a: Dict[str, Any], b: Dict[str, Any]) -> float:
        d = lo(a) - lo(b) if not (lo(a) == lo(b) and math.isinf(lo(a))) else math.nan
        if d != d or d == 0:  # NaN and 0 are falsy: fall through to the inclusive tie-break
            return int(bool(b.get("loInclusive"))) - int(bool(a.get("loInclusive")))
        return d

    out: List[Dict[str, Any]] = []
    for r in sorted(rs, key=functools.cmp_to_key(cmp)):
        last = out[-1] if out else None
        rlo = jsnum(r["lo"]) if "lo" in r else -math.inf
        rhi = jsnum(r["hi"]) if "hi" in r else math.inf
        if last is not None:
            lhi = jsnum(last["hi"]) if "hi" in last else math.inf
        if last is not None and lhi >= rlo and not (lhi == rlo and not last.get("hiInclusive") and not r.get("loInclusive")):
            if rhi > lhi or (rhi == lhi and r.get("hiInclusive")):
                if "hi" not in r:
                    last.pop("hi", None)
                else:
                    last["hi"] = r["hi"]
                if r.get("hiInclusive"):
                    last["hiInclusive"] = True
                else:
                    last.pop("hiInclusive", None)
        else:
            out.append(dict(r))
    return out


def _cell_range(value: Any, T: List[Any]) -> Dict[str, Any]:
    if any(jsnum(t) == jsnum(value) for t in T):
        return {"lo": value, "hi": value, "loInclusive": True, "hiInclusive": True}
    below = next((t for t in reversed(T) if t < value), UNDEF)
    above = next((t for t in T if t > value), UNDEF)
    out: Dict[str, Any] = {}
    if below is not UNDEF:
        out["lo"] = below
    if above is not UNDEF:
        out["hi"] = above
    return out


def _u16(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def what_may_i_do(policy: Any, verbs: Any, known: Any = None, o: Any = None) -> List[Dict[str, Any]]:
    """Per verb shape ({verb, params}): autonomous / approval-only / denied for the known principal, and which parameter values
    and resources are still allowed. Advisory; sound on the decided fragment, otherwise `approximate`."""
    known = {} if known is None else known
    o = {} if o is None else o
    out: List[Dict[str, Any]] = []
    mc = jget(o, "maxCombinations")
    mx = mc if is_num(mc) else DEFAULT_MAX_COMBINATIONS
    for shape in req_list(verbs):
        sverb = jget(shape, "verb")
        kn = spread(known)
        kn["verb"] = sverb
        res = residual(policy, uobj(kn))
        env: Dict[str, Any] = uobj({
            "verb": sverb, "status": "denied", "params": {}, "resources": {"autonomous": [], "withApproval": [], "other": False},
            "policyDigest": res["policyDigest"], "advisory": True,
        })
        rem = jget(o, "remaining")
        if truthy(rem):
            env["remaining"] = spread(rem)
        md = jget(o, "missingDischarges")
        if truthy(md):
            env["missingDischarges"] = list(md)
        if res["decision"] == "never":
            if "reason" in res:
                env["reason"] = res["reason"]
            out.append(env)
            continue
        rp = to_model(residual_policy(res))
        sparams = jget(shape, "params")
        if not isinstance(sparams, dict):
            raise TypeError("Object.entries requires an object")
        names = key_order(sparams)
        extra: List[Dict[str, Any]] = []
        for name in names:
            d = sparams[name]
            if jget(d, "values") is not UNDEF:
                extra.append({"path": "action.params.%s" % name, "cond": {"field": "action.params.%s" % name, "op": "in", "value": d["values"]}})
        extra_num: List[Dict[str, Any]] = []
        for name in names:
            d = sparams[name]
            if jget(d, "min") is not UNDEF:
                extra_num.append({"path": "action.params.%s" % name, "cond": {"field": "action.params.%s" % name, "op": "gte", "value": d["min"]}})
            if jget(d, "max") is not UNDEF:
                extra_num.append({"path": "action.params.%s" % name, "cond": {"field": "action.params.%s" % name, "op": "lte", "value": d["max"]}})
        pr = collect_probes({"predicateSets": [probe_set(rp)], "extraFieldConditions": extra + extra_num, "varyReversibility": "revCap" in rp})
        pr["verbs"] = [sverb]
        declared = names
        if product_size(pr) > mx:
            env["status"] = "needs-approval"
            env["approximate"] = True
            env["reason"] = "representative grid exceeded the bound; no domain is claimed"
            out.append(env)
            continue
        kres = jget(known, "resource")
        if kres is not UNDEF:
            pr["resources"] = [kres]
        seen: Dict[str, Dict[str, Dict[str, Any]]] = {}
        res_seen: Dict[str, Dict[str, bool]] = {}
        any_allow = False
        any_escalate = False
        fresh_res = False
        for rep in representatives(pr):
            d = decide(rp, rep)
            if d == "deny":
                continue
            if d == "allow":
                any_allow = True
            else:
                any_escalate = True
            act = rep_to_action(rep)
            params = act.get("params") or {}
            for name in declared:
                v = params.get(name, UNDEF)
                m = seen.setdefault(name, {})
                k = "\u0000absent" if v is UNDEF else js_json(v)
                cur = m.get(k)
                if cur is None:
                    cur = {"value": v, "allow": False, "escalate": False}
                    m[k] = cur
                if d == "allow":
                    cur["allow"] = True
                else:
                    cur["escalate"] = True
            rr = res_seen.setdefault(act["resource"], {"allow": False, "escalate": False})
            if d == "allow":
                rr["allow"] = True
            else:
                rr["escalate"] = True
            if act["resource"].startswith("\u0000"):
                fresh_res = True
        env["status"] = "autonomous" if any_allow else "needs-approval" if any_escalate else "denied"
        for name in declared:
            decl = sparams[name]
            path = "action.params.%s" % name
            T = thresholds_of(rp, path)
            vals = list(seen.get(name, {}).values())
            dmin, dmax = jget(decl, "min"), jget(decl, "max")
            nums = [x for x in vals if is_num(x["value"]) and (dmin is UNDEF or x["value"] >= dmin) and (dmax is UNDEF or x["value"] <= dmax)]
            strs = [x for x in vals if isinstance(x["value"], str)]
            dvalues = jget(decl, "values")
            if jget(decl, "type") == "integer" or nums:
                def clip(r: Dict[str, Any]) -> Dict[str, Any]:
                    n = dict(r)
                    if dmin is not UNDEF and ("lo" not in r or r["lo"] < dmin):
                        n["lo"] = dmin
                        n["loInclusive"] = True
                    if dmax is not UNDEF and ("hi" not in r or r["hi"] > dmax):
                        n["hi"] = dmax
                        n["hiInclusive"] = True
                    return n

                def ranges(pick: Any, nums: List[Dict[str, Any]] = nums, T: List[Any] = T) -> List[Dict[str, Any]]:
                    return _merge_ranges([clip(_cell_range(x["value"], T)) for x in nums if pick(x)])

                env["params"][name] = {"kind": "numeric", "autonomous": ranges(lambda x: x["allow"]), "withApproval": ranges(lambda x: x["escalate"] and not x["allow"])}
            elif dvalues is not UNDEF or strs:
                def pick_list(f: Any, strs: List[Dict[str, Any]] = strs) -> List[str]:
                    return sorted((x["value"] for x in strs if f(x) and not x["value"].startswith("\u0000")), key=_u16)

                fresh = next((x for x in strs if x["value"].startswith("\u0000")), None)
                env["params"][name] = {
                    "kind": "enum",
                    "autonomous": pick_list(lambda x: x["allow"]),
                    "withApproval": pick_list(lambda x: x["escalate"] and not x["allow"]),
                    "otherAutonomous": dvalues is UNDEF and fresh is not None and fresh["allow"] is True,
                    "otherWithApproval": dvalues is UNDEF and fresh is not None and fresh["escalate"] and not fresh["allow"],
                }
            else:
                env["params"][name] = {"kind": "unconstrained"}
        rnames = [(r, v) for r, v in res_seen.items() if not r.startswith("\u0000")]
        env["resources"] = {
            "autonomous": sorted((r for r, v in rnames if v["allow"]), key=_u16),
            "withApproval": sorted((r for r, v in rnames if v["escalate"] and not v["allow"]), key=_u16),
            "other": fresh_res,
        }
        if rp["undecidable"]:
            env["approximate"] = True
            env["reason"] = "over-approximated (%s)" % "; ".join(rp["undecidable"])
        out.append(env)
    return out


# ---- data filters ---------------------------------------------------------------------------------------------------------------


class Unsupported(Exception):
    """An expression the filter cannot express exactly (the caller falls back to per-row authorization)."""


_COL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62})?")


def _scalar(v: Any) -> bool:
    return isinstance(v, bool) or isinstance(v, str) or (is_num(v) and fin(v) is not None)


def _col_of(path: Any, cols: Any) -> str:
    if not isinstance(cols, dict):
        raise TypeError("columns is not an object")
    c = cols[path] if isinstance(path, str) and path in cols else UNDEF
    if c is UNDEF or not isinstance(c, str) or not _COL_RE.fullmatch(c):
        raise Unsupported("field '%s' has no usable column" % js_str(path))
    return c


def _and(xs: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"t": "true"} if not xs else xs[0] if len(xs) == 1 else {"t": "and", "xs": xs}


def _or(xs: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"t": "false"} if not xs else xs[0] if len(xs) == 1 else {"t": "or", "xs": xs}


def _cond(c: Any, cols: Any) -> Dict[str, Any]:
    if not isinstance(c, (dict, list)):
        raise Unsupported("malformed condition")
    if is_group_condition(c):
        if "all_of" in c and isinstance(c["all_of"], list) and len(c["all_of"]) > 0:
            return _and([_cond(x, cols) for x in c["all_of"]])
        if "any_of" in c and isinstance(c["any_of"], list) and len(c["any_of"]) > 0:
            return _or([_cond(x, cols) for x in c["any_of"]])
        if "not" in c:
            return {"t": "not", "x": _cond(c["not"], cols)}
        raise Unsupported("empty condition group")
    if not is_leaf_condition(c):
        raise Unsupported("malformed condition")
    if "ref" in c:
        raise Unsupported("cross-field ref")
    col = _col_of(c["field"], cols)
    v = c.get("value", UNDEF)
    op = c.get("op", UNDEF)
    if op == "eq" or op == "ne":
        if not _scalar(v):
            raise Unsupported("%s against a non-scalar" % op)
        return {"t": "cmp", "col": col, "op": op, "v": v}
    if op in ("lt", "lte", "gt", "gte"):
        if not is_num(v) or fin(v) is None:
            raise Unsupported("string ordering follows UTF-8 byte order, which SQL collations do not guarantee")
        return {"t": "cmp", "col": col, "op": op, "v": v}
    if op == "in" or op == "nin":
        if not isinstance(v, list) or len(v) == 0 or not all(_scalar(x) for x in v):
            raise Unsupported("%s needs a non-empty list of scalars" % op)
        return {"t": "in", "col": col, "vs": v, "neg": op == "nin"}
    if op == "prefix":
        if not isinstance(v, str):
            raise Unsupported("prefix needs a string")
        return {"t": "prefix", "col": col, "prefix": v}
    if op == "exists":
        return {"t": "null", "col": col, "isNull": v is False}
    raise Unsupported("operator '%s' has no exact SQL form" % js_str(op))


def _resource_expr(p: Any, cols: Any) -> Dict[str, Any]:
    r = jget(p, "resource")
    if r is UNDEF or strict_eq(r, "*"):
        return {"t": "true"}
    col = _col_of("action.resource", cols)
    if not isinstance(r, str):
        raise TypeError("resource.startsWith is not a function")
    if r.startswith("re:"):
        raise Unsupported("regex resource matcher")
    if r.endswith("*"):
        return {"t": "prefix", "col": col, "prefix": r[:-1]}
    return {"t": "cmp", "col": col, "op": "eq", "v": r}


def _veto_expr(v: Any, cols: Any) -> Dict[str, Any]:
    wh = jget(v, "when")
    xs: List[Dict[str, Any]] = []
    if jget(wh, "resource") is not UNDEF:
        xs.append({"t": "coalesce", "x": _resource_expr(wh, cols), "def": True})
    where = nn(jget(wh, "where"), [])
    for c in req_list(where):
        xs.append({"t": "coalesce", "x": _cond(c, cols), "def": True})
    parts = [_and(xs)]
    over = jget(v, "over")
    if truthy(over):
        col = _col_of(jget(over, "path"), cols)
        parts.append(_or([{"t": "null", "col": col, "isNull": True}, {"t": "cmp", "col": col, "op": "lt", "v": 0},
                          {"t": "cmp", "col": col, "op": "gt", "v": jget(over, "threshold")}]))
    unless = jget(v, "unless")
    if jget(v, "kind") != "approval" and truthy(unless) and len(unless) > 0:
        parts.append({"t": "not", "x": _and([{"t": "coalesce", "x": _cond(c, cols), "def": False} for c in unless])})
    return _and(parts)


def _part_expr(p: Any, cols: Any, include: Any) -> Dict[str, Any]:
    permits = []
    for x in jget(p, "predicates"):
        permits.append(_and([_resource_expr(x, cols)] + [_cond(c, cols) for c in req_list(nn(jget(x, "where"), []))]))
    gates = [_or(permits)]
    for v in jget(p, "vetoes"):
        e = _veto_expr(v, cols)
        # an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
        if jget(v, "kind") == "deny" or include == "autonomous":
            gates.append({"t": "not", "x": e})
    if include == "autonomous":
        for t in jget(p, "tighten"):
            gates.append({"t": "not", "x": {"t": "coalesce", "x": _cond(jget(t, "when"), cols), "def": True}})
    else:
        for t in jget(p, "tighten"):
            if jget(t, "signal") == "deny":
                gates.append({"t": "not", "x": {"t": "coalesce", "x": _cond(jget(t, "when"), cols), "def": True}})
    return _and(gates)


_SQL_OPS = {"eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}


def _render(e: Dict[str, Any], dialect: Any, params: List[Any]) -> str:
    def ph(v: Any) -> str:
        params.append(v)
        return "$%d" % len(params) if dialect == "postgres" else "?"

    def R(x: Dict[str, Any]) -> str:
        t = x["t"]
        if t == "true":
            return "TRUE"
        if t == "false":
            return "FALSE"
        if t == "cmp":
            return "%s %s %s" % (x["col"], _SQL_OPS[x["op"]], ph(x["v"]))
        if t == "in":
            return "%s %s (%s)" % (x["col"], "NOT IN" if x["neg"] else "IN", ", ".join([ph(v) for v in x["vs"]]))
        if t == "prefix":
            return "%s LIKE %s ESCAPE '!'" % (x["col"], ph(re.sub(r"[!%_]", lambda m: "!" + m.group(0), x["prefix"]) + "%"))
        if t == "null":
            return "%s IS %sNULL" % (x["col"], "" if x["isNull"] else "NOT ")
        if t == "and":
            return "(%s)" % " AND ".join([R(y) for y in x["xs"]])
        if t == "or":
            return "(%s)" % " OR ".join([R(y) for y in x["xs"]])
        if t == "not":
            return "NOT (%s)" % R(x["x"])
        return "COALESCE(%s, %s)" % (R(x["x"]), "TRUE" if x["def"] else "FALSE")

    return R(e)


def to_filter(res: Any, o: Any) -> Dict[str, Any]:
    """Compile a residual to a parameterized SQL filter ({ok, expr, sql, params, ucast}), or {ok: False, reason} when it cannot be
    done exactly (the caller then falls back to per-row authorization)."""
    try:
        if jget(res, "decision") == "never":
            return {"ok": True, "expr": {"t": "false"}, "sql": "FALSE", "params": [], "ucast": to_ucast({"t": "false"})}
        include = nn(jget(o, "include"), "autonomous")
        pol = jget(res, "policy")
        own = {k: v for k, v in pol.items() if k != "meet"}
        meet = pol.get("meet")
        cols = jget(o, "columns")
        expr = _and([_part_expr(p, cols, include) for p in [own] + list(nn(meet, []))])
        params: List[Any] = []
        sql = _render(expr, nn(jget(o, "dialect"), "postgres"), params)
        return {"ok": True, "expr": expr, "sql": sql, "params": params, "ucast": to_ucast(expr)}
    except Unsupported as e:
        return {"ok": False, "reason": str(e)}
    except Exception:  # noqa: BLE001 - any other failure is a compile error, never a looser filter
        return {"ok": False, "reason": "filter compilation error"}


def _typeof(x: Any) -> str:
    if isinstance(x, bool):
        return "boolean"
    if is_num(x):
        return "number"
    if isinstance(x, str):
        return "string"
    return "undefined" if x is UNDEF else "object"


def _row_get(row: Any, c: str) -> Any:
    return row[c] if isinstance(row, dict) and c in row else None


def eval_filter(e: Dict[str, Any], row: Any) -> Optional[bool]:
    """Evaluate a filter expression over one row with SQL's three-valued (Kleene) logic: True, False or None (NULL)."""
    def K(x: Dict[str, Any]) -> Optional[bool]:
        t = x["t"]
        if t == "true":
            return True
        if t == "false":
            return False
        if t == "cmp":
            a = _row_get(row, x["col"])
            b = x["v"]
            if a is None or _typeof(a) != _typeof(b):
                return None
            op = x["op"]
            if op == "eq":
                return strict_eq(a, b)
            if op == "ne":
                return not strict_eq(a, b)
            if _typeof(a) == "object":
                return False
            a, b = (jsnum(a), jsnum(b)) if _typeof(a) == "number" else (a, b)
            return a < b if op == "lt" else a <= b if op == "lte" else a > b if op == "gt" else a >= b
        if t == "in":
            a = _row_get(row, x["col"])
            if a is None:
                return None
            hit = any(strict_eq(v, a) for v in x["vs"])
            return (not hit) if x["neg"] else hit
        if t == "prefix":
            a = _row_get(row, x["col"])
            return a.startswith(x["prefix"]) if isinstance(a, str) else None
        if t == "null":
            return (_row_get(row, x["col"]) is None) == x["isNull"]
        if t == "and":
            unk = False
            for y in x["xs"]:
                v = K(y)
                if v is False:
                    return False
                if v is None:
                    unk = True
            return None if unk else True
        if t == "or":
            unk = False
            for y in x["xs"]:
                v = K(y)
                if v is True:
                    return True
                if v is None:
                    unk = True
            return None if unk else False
        if t == "not":
            v = K(x["x"])
            return None if v is None else not v
        v = K(x["x"])
        return x["def"] if v is None else v

    return K(e)


# ---- UCAST -------------------------------------------------------------------------------------------------------------------


def _is_empty(u: Dict[str, Any], op: str) -> bool:
    return u["type"] == "compound" and u["operator"] == op and len(u["value"]) == 0


def _join(op: str, xs: List[Dict[str, Any]]) -> Dict[str, Any]:
    other = "or" if op == "and" else "and"
    flat: List[Dict[str, Any]] = []
    for x in xs:
        if x["type"] == "compound" and x["operator"] == op:
            flat.extend(x["value"])
        else:
            flat.append(x)
    if any(_is_empty(x, other) for x in flat):
        return {"type": "compound", "operator": other, "value": []}
    kept = [x for x in flat if not _is_empty(x, op)]
    if len(kept) == 1:
        return kept[0]
    return {"type": "compound", "operator": op, "value": kept}


def _and2(xs: List[Dict[str, Any]]) -> Dict[str, Any]:
    return _join("and", xs)


def _or2(xs: List[Dict[str, Any]]) -> Dict[str, Any]:
    return _join("or", xs)


def _not2(x: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": "compound", "operator": "not", "value": [x]}


def _f(field: str, operator: str, value: Any) -> Dict[str, Any]:
    return {"type": "field", "field": field, "operator": operator, "value": value}


def _not_null(c: str) -> Dict[str, Any]:
    return _f(c, "ne", None)


_INV = {"eq": "ne", "ne": "eq", "lt": "gte", "lte": "gt", "gt": "lte", "gte": "lt"}


def _T(x: Dict[str, Any]) -> Dict[str, Any]:
    t = x["t"]
    if t == "true":
        return _and2([])
    if t == "false":
        return _or2([])
    if t == "cmp":
        return _and2([_not_null(x["col"]), _f(x["col"], "ne", x["v"])]) if x["op"] == "ne" else _f(x["col"], x["op"], x["v"])
    if t == "in":
        return _and2([_not_null(x["col"]), _f(x["col"], "nin", x["vs"])]) if x["neg"] else _f(x["col"], "in", x["vs"])
    if t == "prefix":
        return _f(x["col"], "startswith", x["prefix"])
    if t == "null":
        return _f(x["col"], "eq", None) if x["isNull"] else _not_null(x["col"])
    if t == "and":
        return _and2([_T(y) for y in x["xs"]])
    if t == "or":
        return _or2([_T(y) for y in x["xs"]])
    if t == "not":
        return _F(x["x"])
    return _not2(_F(x["x"])) if x["def"] else _T(x["x"])


def _F(x: Dict[str, Any]) -> Dict[str, Any]:
    t = x["t"]
    if t == "true":
        return _or2([])
    if t == "false":
        return _and2([])
    if t == "cmp":
        return _and2([_not_null(x["col"]), _f(x["col"], _INV[x["op"]], x["v"])])
    if t == "in":
        return _f(x["col"], "in", x["vs"]) if x["neg"] else _and2([_not_null(x["col"]), _f(x["col"], "nin", x["vs"])])
    if t == "prefix":
        return _and2([_not_null(x["col"]), _not2(_f(x["col"], "startswith", x["prefix"]))])
    if t == "null":
        return _not_null(x["col"]) if x["isNull"] else _f(x["col"], "eq", None)
    if t == "and":
        return _or2([_F(y) for y in x["xs"]])
    if t == "or":
        return _and2([_F(y) for y in x["xs"]])
    if t == "not":
        return _T(x["x"])
    return _F(x["x"]) if x["def"] else _not2(_T(x["x"]))  # coalesce(x, FALSE) is false exactly when x is not definitely true


def to_ucast(e: Dict[str, Any]) -> Dict[str, Any]:
    """The filter as a UCAST tree whose rows are exactly those the SQL form selects."""
    return _T(e)


def eval_ucast(u: Dict[str, Any], row: Any) -> bool:
    """Evaluate a UCAST tree over one row (two-valued; a comparison with NULL is false)."""
    if u["type"] == "compound":
        if u["operator"] == "and":
            return all(eval_ucast(c, row) for c in u["value"])
        if u["operator"] == "or":
            return any(eval_ucast(c, row) for c in u["value"])
        return not eval_ucast(u["value"][0], row)
    a = _row_get(row, u["field"])
    v = u["value"]
    op = u["operator"]
    if op == "eq" and v is None:
        return a is None
    if op == "ne" and v is None:
        return a is not None
    if a is None:
        return False
    if op == "eq":
        return strict_eq(a, v)
    if op in ("ne", "lt", "lte", "gt", "gte"):
        if _typeof(a) != _typeof(v):
            return False
        if op == "ne":
            return not strict_eq(a, v)
        if _typeof(a) == "object":
            return False
        x, y = (jsnum(a), jsnum(v)) if _typeof(a) == "number" else (a, v)
        return x < y if op == "lt" else x <= y if op == "lte" else x > y if op == "gt" else x >= y
    if op == "in":
        return any(strict_eq(e, a) for e in v)
    if op == "nin":
        return not any(strict_eq(e, a) for e in v)
    if op == "startswith":
        return isinstance(a, str) and a.startswith(v)
    return False
