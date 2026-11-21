"""The policy-safety CI gate. Port of the TypeScript reference (@atlasauth/pca-policy-ci).

It drives the real static analyzer (atlas_pca.analyzer) over a PCA envelope, grant, compiled policy, bare `{predicates, caveats}` or a
delegation chain and reports findings; five toggleable rules plus schema mismatch. SOUNDNESS: a hard `error` is emitted only from a
PROVEN analyzer verdict; any undecidable feature fails safe to a `warn` / `info` that says so. Also the authoring gates (`diff`,
`test`, `coverage`) and the command line (`run`, `parse_args`, `main`). Findings and results are plain dicts."""
from ._fin import fin
import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional

from .analyzer_core import always_allows, always_denies, predicate_numeric_satisfiable, reachable, subsumes
from .analyzer_core import FULL_INTERVAL, interval_empty, tighten_interval
from .analyzer_coverage import coverage, coverage_gate
from .analyzer_exposure import diff_gate, diff_policies
from .analyzer_js import UNDEF, includes, is_num, jget, js_json, js_str, jsnum, nn, num_str, req_list, to_fixed, truthy
from .analyzer_validate import run_policy_tests, validate_policy_against_schema
from .authorize import ENVELOPE_CAVEAT, read_envelope
from .pca import hash_canonical
from .predicates import is_leaf_condition

# ---- types and configuration -------------------------------------------------------------------------------------------------------

DEFAULT_DANGEROUS_VERBS = ("delete", "destroy", "drop", "remove", "purge", "transfer", "payout", "wire", "withdraw", "admin", "grant",
                           "revoke", "deploy", "shutdown", "rotate")
SEVERITY_RANK = {"info": 1, "warn": 2, "error": 3}
SCOPE_NARROWING_CAVEATS = ("max_blast_radius", "rate", "reversibility_max", "budget_alloc", "delegation_depth")
BUDGET_GATE_CAVEATS = ("max_blast_radius", "rate", "budget_alloc")
ENVELOPE_CAVEAT_TYPE = ENVELOPE_CAVEAT

_JS_WS = "\t\n\u000b\f\r                  　﻿"


def _trim(s: str) -> str:
    return s.strip(_JS_WS)


def _is_record(x: Any) -> bool:
    return isinstance(x, dict)


def _verbs_of(verb: Any) -> List[str]:
    if isinstance(verb, str):
        return [verb]
    if isinstance(verb, list):
        return [x for x in verb if isinstance(x, str)]
    return []


def _num(x: Any) -> Any:
    """A finite number, else UNDEF."""
    if is_num(x) and fin(jsnum(x)):
        return x
    return UNDEF


def _is_dangerous_verb(verb: str, dangerous: Any) -> bool:
    v = verb.lower()
    return any(kw.lower() in v for kw in dangerous)  # the verb contains a dangerous keyword (reference: v.includes(kw))


def _is_wildcard_resource(resource: Any) -> bool:
    return resource is UNDEF or (isinstance(resource, str) and resource == "*")


def _has_caveat_of_type(caveats: Any, types: Any) -> bool:
    return any(isinstance(c, dict) and isinstance(c.get("type"), str) and c["type"] in types for c in caveats)


def _describe_action(a: Any) -> str:
    parts = [js_str(jget(a, "verb")), js_str(jget(a, "resource"))]
    params = jget(a, "params")
    if truthy(params) and isinstance(params, dict) and len(params) > 0:
        parts.append(js_json(params))
    rc = jget(a, "reversibilityClass")
    if rc is not UNDEF:
        parts.append("[%s]" % js_str(rc))
    return " ".join(parts)


def _uniq(xs: List[str]) -> List[str]:
    return list(dict.fromkeys(xs))


def _find(rule: str, severity: str, message: str, where: Optional[str] = None) -> Dict[str, Any]:
    f = {"rule": rule, "severity": severity, "message": message}
    if where is not None:
        f["where"] = where
    return f


# ---- normalization -----------------------------------------------------------------------------------------------------------------


def is_capability(x: Any) -> bool:
    """A minted grant / delegation hop: the content-addressed, signed shape of a capability."""
    return (_is_record(x) and isinstance(x.get("id"), str) and isinstance(x.get("issuer"), str) and isinstance(x.get("holder"), str)
            and isinstance(x.get("body_digest"), str) and isinstance(x.get("sig"), str) and isinstance(x.get("caveats"), list))


def is_envelope(x: Any) -> bool:
    """A signed policy envelope (the root intent grant payload)."""
    return (_is_record(x) and isinstance(x.get("goal_commit"), str) and isinstance(x.get("predicates"), list)
            and isinstance(x.get("caveats"), list) and _is_record(x.get("agent_binding")) and _is_record(x.get("risk_policy")))


def _is_compiled(x: Any) -> bool:
    return (_is_record(x) and isinstance(x.get("predicates"), list) and isinstance(x.get("caveats"), list)
            and _is_record(x.get("riskPolicy")) and isinstance(x.get("actions"), list))


def _runtime_caveats(caveats: List[Any]) -> List[Any]:
    """Drop the envelope-carrying caveat; keep the runtime gate caveats (and any appended attenuation)."""
    return [c for c in caveats if isinstance(c, (dict, list)) and not (isinstance(c, dict) and c.get("type") == ENVELOPE_CAVEAT_TYPE)]


def _from_grant(grant: Any) -> Dict[str, Any]:
    env = read_envelope(grant)
    if env is None:
        return {"ok": False, "reason": "grant has no readable `envelope` caveat (malformed or unsigned payload)"}
    cs = grant.get("caveats")
    appended = _runtime_caveats(cs if isinstance(cs, list) else [])
    return {"ok": True, "policy": {"predicates": env["predicates"], "caveats": list(env["caveats"]) + appended, "riskPolicy": env.get("risk_policy"), "kind": "grant"}}


def normalize_policy_input(input_: Any) -> Dict[str, Any]:
    """Reduce any single-policy input to its effective authority: {ok: True, policy: {predicates, caveats, riskPolicy?, kind}} or
    {ok: False, reason}."""
    if is_capability(input_):
        return _from_grant(input_)
    if is_envelope(input_):
        return {"ok": True, "policy": {"predicates": input_["predicates"], "caveats": input_["caveats"], "riskPolicy": input_["risk_policy"], "kind": "envelope"}}
    if _is_compiled(input_):
        return {"ok": True, "policy": {"predicates": input_["predicates"], "caveats": input_["caveats"], "riskPolicy": input_["riskPolicy"], "kind": "compiled"}}
    if _is_record(input_) and isinstance(input_.get("predicates"), list):
        c = input_.get("caveats")
        return {"ok": True, "policy": {"predicates": input_["predicates"], "caveats": c if isinstance(c, list) else [], "kind": "bare"}}
    return {"ok": False, "reason": "unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })"}


def normalize_chain(chain: Any) -> Dict[str, Any]:
    """Normalize a delegation chain (root to leaf) to one effective policy per hop: {ok: True, hops} or {ok: False, reason}."""
    chain = req_list(chain)
    if len(chain) == 0:
        return {"ok": False, "reason": "empty chain"}
    if all(is_capability(c) for c in chain):
        env = read_envelope(chain[0])
        if env is None:
            return {"ok": False, "reason": "root grant has no readable `envelope` caveat"}
        hops = []
        for cap in chain:
            cs = cap.get("caveats")
            hops.append({"predicates": env["predicates"], "caveats": list(env["caveats"]) + _runtime_caveats(cs if isinstance(cs, list) else []),
                         "riskPolicy": env.get("risk_policy"), "kind": "chain-hop"})
        return {"ok": True, "hops": hops}
    hops = []
    for i, c in enumerate(chain):
        r = normalize_policy_input(c)
        if not r["ok"]:
            return {"ok": False, "reason": "hop %d: %s" % (i, r["reason"])}
        hops.append(dict(r["policy"], kind="chain-hop"))
    return {"ok": True, "hops": hops}


# ---- rules -------------------------------------------------------------------------------------------------------------------------


def _analyzer_input(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"predicates": p["predicates"], "caveats": p["caveats"]}


def _declared_verbs(predicates: List[Any]) -> List[str]:
    concrete: List[str] = []
    for p in predicates:
        if not isinstance(p, (dict, list)):
            continue
        for v in _verbs_of(p.get("verb") if isinstance(p, dict) else None):
            if v != "*":
                concrete.append(v)
    return _uniq(concrete)


def _gate_description(policy: Dict[str, Any]) -> Optional[str]:
    gates: List[str] = []
    if _has_caveat_of_type(policy["caveats"], BUDGET_GATE_CAVEATS):
        gates.append("/".join(js_str(jget(c, "type")) for c in policy["caveats"] if includes(list(BUDGET_GATE_CAVEATS), jget(c, "type"))))
    rp = policy.get("riskPolicy")
    if rp is not None and rp is not UNDEF:
        t2 = rp.get("theta2", UNDEF) if isinstance(rp, dict) else UNDEF
        if is_num(t2) and fin(jsnum(t2)) and t2 < 1:
            gates.append("risk step-up (theta2 < 1)")
    return ", ".join(gates) if gates else None


def rule_over_broad_grant(policy: Dict[str, Any], dangerous: Any, opts: Any) -> List[Dict[str, Any]]:
    """A wildcard verb or resource, a dangerous verb with no narrowing, or a proven always-allow."""
    out: List[Dict[str, Any]] = []
    inp = _analyzer_input(policy)
    has_scope_narrowing = _has_caveat_of_type(policy["caveats"], SCOPE_NARROWING_CAVEATS)
    for i, p in enumerate(policy["predicates"]):
        if not isinstance(p, (dict, list)):
            continue
        d = p if isinstance(p, dict) else {}
        verbs = _verbs_of(d.get("verb"))
        where = "predicates[%d]" % i
        w = d.get("where")
        has_where = isinstance(w, list) and len(w) > 0
        if "*" in verbs:
            out.append(_find("over-broad-grant", "error", "predicate grants a WILDCARD verb '*' — authority over any action", where))
        if _is_wildcard_resource(d.get("resource", UNDEF)):
            dv = [v for v in verbs if _is_dangerous_verb(v, dangerous)]
            if dv:
                out.append(_find("over-broad-grant", "error", "dangerous verb(s) %s granted on a WILDCARD resource ('*')" % js_json(dv), where))
            elif "*" not in verbs:
                out.append(_find("over-broad-grant", "warn", "predicate matches ANY resource ('*') — consider a resource prefix", where))
        for v in verbs:
            if v != "*" and _is_dangerous_verb(v, dangerous) and not has_where and not has_scope_narrowing:
                out.append(_find("over-broad-grant", "error",
                                 "dangerous verb '%s' is granted with NO narrowing `where` and no scope-narrowing caveat (%s)" % (v, "/".join(SCOPE_NARROWING_CAVEATS)), where))
    for v in _declared_verbs(policy["predicates"]):
        aa = always_allows(inp, v, opts)
        if aa["alwaysAllows"] and aa.get("approximate") is not True:
            out.append(_find("over-broad-grant", "error", "grants EVERY action of '%s' — the authority has no effective constraint (always-allow)" % v))
    return out


def rule_privilege_escalation(hops: List[Dict[str, Any]], opts: Any) -> List[Dict[str, Any]]:
    """A delegation hop whose effective authority is not a subset of its parent's."""
    out: List[Dict[str, Any]] = []
    for i in range(1, len(hops)):
        s = subsumes(_analyzer_input(hops[i - 1]), _analyzer_input(hops[i]), opts)
        where = "hop[%d]" % i
        if s["subsumes"]:
            continue
        if s.get("approximate") is True:
            reason = s.get("reason")
            out.append(_find("privilege-escalation", "warn", "could not prove hop %d attenuation (undecidable%s) — attenuation not verified" % (i, ": %s" % reason if reason else ""), where))
        else:
            ce = s.get("counterexample")
            ex = " — child admits '%s' which its parent denies" % _describe_action(ce) if ce is not None else ""
            out.append(_find("privilege-escalation", "error",
                             "delegation hop %d ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)%s" % (i, ex), where))
    return out


# which numeric field carries a caveat's bound, and whether the STRICTEST (binding) one is the min or the max
_ORDERED_CAVEATS = (("expires", "at", "min"), ("not_before", "at", "max"), ("max_blast_radius", "max", "min"), ("delegation_depth", "max", "min"),
                    ("budget_alloc", "limit", "min"))
_NUMERIC_OPS = ("lt", "lte", "gt", "gte", "eq")


def _caveat_key(cv: Any) -> str:
    return js_json(cv)


def _interval_eq(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return a["lo"] == b["lo"] and a["loInclusive"] == b["loInclusive"] and a["hi"] == b["hi"] and a["hiInclusive"] == b["hiInclusive"]


def _non_binding_conditions(where: List[Any], pred_index: int) -> List[Dict[str, Any]]:
    by_field: Dict[str, List[Any]] = {}
    for i, c in enumerate(where):
        if not is_leaf_condition(c) or "ref" in c:
            continue
        if not isinstance(c.get("op"), str) or c["op"] not in _NUMERIC_OPS:
            continue
        if _num(c.get("value", UNDEF)) is UNDEF:
            continue
        by_field.setdefault(c["field"], []).append((c, i))
    out: List[Dict[str, Any]] = []
    for field, conds in by_field.items():
        if len(conds) < 2:
            continue
        full = FULL_INTERVAL
        for c, _i in conds:
            full = tighten_interval(full, c["op"], c["value"])
        if interval_empty(full):
            continue  # the whole-predicate unsat case is reported separately
        for e in conds:
            without = FULL_INTERVAL
            for x in conds:
                if x is not e:
                    without = tighten_interval(without, x[0]["op"], x[0]["value"])
            if _interval_eq(without, full):
                out.append(_find("redundant-caveat", "info",
                                 "condition on '%s' (%s %s) does not tighten the authority — redundant with the other bounds on this field" % (
                                     field, e[0]["op"], js_str(e[0]["value"])), "predicates[%d].where[%d]" % (pred_index, e[1])))
    return out


def rule_redundant_caveat(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """A caveat or condition that can never bite: a duplicate, one subsumed by a stricter one, an unsatisfiable predicate, a
    non-binding bound."""
    out: List[Dict[str, Any]] = []
    caveats = policy["caveats"]
    seen: Dict[str, int] = {}
    for i, cv in enumerate(caveats):
        if not isinstance(cv, (dict, list)):
            continue
        k = _caveat_key(cv)
        if k in seen:
            out.append(_find("redundant-caveat", "warn", "caveat %d ('%s') is an exact duplicate of caveat %d — dead policy" % (i, js_str(jget(cv, "type")), seen[k]), "caveats[%d]" % i))
        else:
            seen[k] = i
    for typ, field, keep in _ORDERED_CAVEATS:
        vals = []
        for i, cv in enumerate(caveats):
            if isinstance(cv, dict) and cv.get("type") == typ:
                v = _num(cv.get(field, UNDEF))
                if v is not UNDEF:
                    vals.append((i, v))
        if len(vals) < 2:
            continue
        binding = min((v for _i, v in vals), key=jsnum) if keep == "min" else max((v for _i, v in vals), key=jsnum)
        for i, v in vals:
            if jsnum(v) != jsnum(binding):
                out.append(_find("redundant-caveat", "warn", "caveat %d ('%s' %s=%s) is subsumed by a stricter '%s' (%s=%s) — it can never bite" % (
                    i, typ, field, num_str(jsnum(v)), typ, field, num_str(jsnum(binding))), "caveats[%d]" % i))
    for i, p in enumerate(policy["predicates"]):
        w = p.get("where", UNDEF) if isinstance(p, dict) else UNDEF
        if not isinstance(p, (dict, list)) or not isinstance(w, list):
            continue
        if not predicate_numeric_satisfiable(w):
            out.append(_find("redundant-caveat", "warn", "predicate %d can never match — its numeric `where` constraints are unsatisfiable (dead policy)" % i, "predicates[%d]" % i))
        else:
            out.extend(_non_binding_conditions(w, i))
    return out


def rule_dangerous_reachability(policy: Dict[str, Any], dangerous: Any, extra_targets: Any, opts: Any) -> List[Dict[str, Any]]:
    """A dangerous (verb, resource) the analyzer PROVES reachable, with no budget / rate / step-up gate (error) or with one (info)."""
    out: List[Dict[str, Any]] = []
    inp = _analyzer_input(policy)
    derived = [{"verb": v} for v in _declared_verbs(policy["predicates"]) if _is_dangerous_verb(v, dangerous)]
    targets = derived + list(extra_targets)
    gate = _gate_description(policy)
    for t in targets:
        verb = jget(t, "verb")
        resource = jget(t, "resource")
        if resource is not UNDEF:
            r = reachable(inp, {"verb": verb, "resource": resource}, opts)
            proven = bool(r["reachable"]) and r.get("approximate") is not True
            approximate = r.get("approximate") is True
            reason = r.get("reason")
            witness = "%s %s" % (js_str(verb), js_str(resource))
        else:
            ad = always_denies(inp, verb, opts)
            proven = ad["alwaysDenies"] is False and ad.get("approximate") is not True
            approximate = ad.get("approximate") is True
            reason = ad.get("reason")
            witness = _describe_action(ad["witness"]) if "witness" in ad else js_str(verb)
        if approximate:
            out.append(_find("dangerous-reachability", "warn", "could not decide reachability of dangerous verb '%s' (undecidable%s)" % (js_str(verb), ": %s" % reason if reason else "")))
        elif proven:
            if gate is None:
                out.append(_find("dangerous-reachability", "error", "dangerous action '%s' is REACHABLE with no budget / rate / step-up gate" % witness))
            else:
                out.append(_find("dangerous-reachability", "info", "dangerous action '%s' is reachable but gated by %s" % (witness, gate)))
    return out


def _is_non_trivial(policy: Dict[str, Any], dangerous: Any) -> bool:
    for p in policy["predicates"]:
        if not isinstance(p, (dict, list)):
            continue
        d = p if isinstance(p, dict) else {}
        verbs = _verbs_of(d.get("verb"))
        w = d.get("where")
        has_where = isinstance(w, list) and len(w) > 0
        if "*" in verbs or any(_is_dangerous_verb(v, dangerous) for v in verbs) or _is_wildcard_resource(d.get("resource", UNDEF)) or not has_where:
            return True
    return False


def rule_missing_safety_floor(policy: Dict[str, Any], cfg: Dict[str, Any], dangerous: Any) -> List[Dict[str, Any]]:
    """No `expires` caveat, or no blast-radius / rate / budget gate on a non-trivial grant."""
    out: List[Dict[str, Any]] = []
    if len(policy["predicates"]) == 0:
        return out  # nothing is granted; default-deny needs no floor
    if cfg["requireExpiry"] and not _has_caveat_of_type(policy["caveats"], ("expires",)):
        out.append(_find("missing-safety-floor", "warn", "grant has no `expires` caveat — the authority never expires"))
    if cfg["requireScopeGate"] and _is_non_trivial(policy, dangerous) and not _has_caveat_of_type(policy["caveats"], BUDGET_GATE_CAVEATS):
        out.append(_find("missing-safety-floor", "warn", "non-trivial grant has no blast-radius / rate / budget gate (%s)" % "/".join(BUDGET_GATE_CAVEATS)))
    return out


def rule_schema_mismatch(policy: Dict[str, Any], schema: Any, options: Any = None) -> List[Dict[str, Any]]:
    """The policy compared with the action schema it is written for."""
    r = validate_policy_against_schema({"predicates": policy["predicates"], "caveats": policy["caveats"]}, schema, options)
    return [{"rule": "schema-mismatch", "severity": f["severity"], "message": "%s: %s" % (f["code"], f["message"]), "where": f["where"]} for f in r["findings"]]


# ---- lint ----------------------------------------------------------------------------------------------------------------------------


def _guarded(rule: str, run_: Callable[[], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """A rule that throws is a finding, not a crash and not silence: a gate must not pass a policy it could not finish checking."""
    try:
        return run_()
    except Exception as e:  # noqa: BLE001
        return [{"rule": "internal-error", "severity": "error", "message": "rule %s could not run: %s" % (rule, e)}]


def _resolve_rules(rules: Any) -> Dict[str, Any]:
    r = {} if rules is UNDEF or rules is None else rules
    ob, dr, sf = jget(r, "overBroadGrant"), jget(r, "dangerousReachability"), jget(r, "missingSafetyFloor")

    def verbs(o: Any) -> Any:
        if isinstance(o, (dict, list)) and truthy(jget(o, "dangerousVerbs")):
            return jget(o, "dangerousVerbs")
        return DEFAULT_DANGEROUS_VERBS

    return {
        "overBroadGrant": {"enabled": ob is not False, "dangerousVerbs": verbs(ob)},
        "privilegeEscalation": jget(r, "privilegeEscalation") is not False,
        "redundantCaveat": jget(r, "redundantCaveat") is not False,
        "dangerousReachability": {"enabled": dr is not False, "dangerousVerbs": verbs(dr),
                                  "targets": jget(dr, "targets") if isinstance(dr, (dict, list)) and truthy(jget(dr, "targets")) else []},
        "missingSafetyFloor": {"enabled": sf is not False,
                               "requireExpiry": jget(sf, "requireExpiry") is not False if isinstance(sf, (dict, list)) else True,
                               "requireScopeGate": jget(sf, "requireScopeGate") is not False if isinstance(sf, (dict, list)) else True},
    }


def _analyzer_opts(opts: Any) -> Dict[str, Any]:
    mc = jget(opts, "maxCombinations") if isinstance(opts, dict) else UNDEF
    return {"maxCombinations": mc} if mc is not UNDEF else {}


def _single_rules(cfg: Dict[str, Any], policy: Dict[str, Any], ao: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if cfg["overBroadGrant"]["enabled"]:
        out.extend(_guarded("over-broad-grant", lambda: rule_over_broad_grant(policy, cfg["overBroadGrant"]["dangerousVerbs"], ao)))
    if cfg["redundantCaveat"]:
        out.extend(_guarded("redundant-caveat", lambda: rule_redundant_caveat(policy)))
    if cfg["dangerousReachability"]["enabled"]:
        dr = cfg["dangerousReachability"]
        out.extend(_guarded("dangerous-reachability", lambda: rule_dangerous_reachability(policy, dr["dangerousVerbs"], dr["targets"], ao)))
    if cfg["missingSafetyFloor"]["enabled"]:
        out.extend(_guarded("missing-safety-floor", lambda: rule_missing_safety_floor(policy, cfg["missingSafetyFloor"], cfg["overBroadGrant"]["dangerousVerbs"])))
    return out


def lint_policy(input_: Any, opts: Any = None) -> List[Dict[str, Any]]:
    """Lint a single PCA policy (an envelope, a minted grant, a compiled policy or a bare `{predicates, caveats?}`). All findings
    (empty = clean). `opts`: {rules?, schema?, schemaOptions?, maxCombinations?}."""
    opts = {} if opts is None else opts
    norm = normalize_policy_input(input_)
    if not norm["ok"]:
        return [{"rule": "malformed-policy", "severity": "error", "message": norm["reason"]}]
    cfg = _resolve_rules(jget(opts, "rules"))
    ao = _analyzer_opts(opts)
    policy = norm["policy"]
    out = _single_rules(cfg, policy, ao)
    schema = jget(opts, "schema")
    if schema is not UNDEF:
        out.extend(_guarded("schema-mismatch", lambda: rule_schema_mismatch(policy, schema, jget(opts, "schemaOptions") if jget(opts, "schemaOptions") is not UNDEF else None)))
    return out


def lint_chain(chain: Any, opts: Any = None) -> List[Dict[str, Any]]:
    """Lint a delegation chain (root to leaf): privilege escalation across every consecutive pair, then the single-policy rules on
    the acting LEAF's effective authority."""
    opts = {} if opts is None else opts
    norm = normalize_chain(chain)
    if not norm["ok"]:
        return [{"rule": "malformed-policy", "severity": "error", "message": norm["reason"]}]
    cfg = _resolve_rules(jget(opts, "rules"))
    ao = _analyzer_opts(opts)
    hops = norm["hops"]
    out: List[Dict[str, Any]] = []
    if cfg["privilegeEscalation"]:
        out.extend(_guarded("privilege-escalation", lambda: rule_privilege_escalation(hops, ao)))
    if hops:
        out.extend(_single_rules(cfg, hops[-1], ao))
    return out


def lint(input_: Any, opts: Any = None) -> List[Dict[str, Any]]:
    """An array input is a delegation chain; anything else is a single policy."""
    return lint_chain(input_, opts) if isinstance(input_, list) else lint_policy(input_, opts)


def _rank_key(k: Any) -> Optional[str]:
    """The own severity key a value names (a property key is coerced the way JavaScript coerces it), else None."""
    s = js_str(k)
    return s if s in SEVERITY_RANK else None


def summarize(results: Any, opts: Any = None) -> Dict[str, Any]:
    """Roll labeled findings into counts and an exit code (0 ok, 1 a finding reaches the threshold, 2 nothing was linted)."""
    opts = {} if opts is None else opts
    max_severity = nn(jget(opts, "maxSeverity"), "error")
    mk = _rank_key(max_severity)
    if mk is None:  # an unknown threshold would make every comparison false and pass everything
        raise ValueError("summarize: maxSeverity must be one of %s" % ", ".join(SEVERITY_RANK))
    counts = {"error": 0, "warn": 0, "info": 0}
    if not isinstance(results, list) or len(results) == 0:
        return {"results": [], "counts": counts, "maxSeverity": max_severity, "ok": False, "exitCode": 2, "reason": "no policies were linted"}
    failing = 0
    threshold = SEVERITY_RANK[mk]
    for r in results:
        for f in req_list(jget(r, "findings")):
            sev = _rank_key(jget(f, "severity")) or "error"  # a severity that is not one of the three counts as an error
            counts[sev] += 1
            if SEVERITY_RANK[sev] >= threshold:
                failing += 1
    ok = failing == 0
    return {"results": results, "counts": counts, "maxSeverity": max_severity, "ok": ok, "exitCode": 0 if ok else 1}


def lint_policies(items: Any, opts: Any = None) -> Dict[str, Any]:
    """Lint a list of labeled policies (or chains) and roll the findings into a summary."""
    opts = {} if opts is None else opts
    results = []
    for i, item in enumerate(req_list(items)):
        label = nn(jget(item, "label"), "policy[%d]" % i)
        results.append({"label": label, "findings": lint(jget(item, "policy"), opts)})
    return summarize(results, opts)


# ---- pinned lint rule list --------------------------------------------------------------------------------------------------------------

LINT_RULES_DIGEST_DOMAIN = "atlas-pca/action-lint-rules/v1"
_LINT_RULES = (
    ("LD-001", "error", "a destroy-like verb whose effects do not delete"),
    ("LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format"),
    ("LD-003", "error", "a numeric parameter without min and max"),
    ("LD-004", "error", "a money-moving action without idempotency"),
    ("LD-005", "error", "personal data can leave without the matching effect"),
    ("LD-006", "error", "a declared reversibility or blast below the effective floor"),
    ("LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait"),
    ("LD-008", "error", "resource id '*' with scope one"),
    ("LD-009", "error", "a duplicate verb or alias collision"),
    ("LD-010", "error", "a write marked reversible with no compensating action in the pack"),
    ("LD-011", "error", "review state confirmed without a valid attestation for this digest"),
    ("LD-012", "error", "a structural param rule that the effective traits require is violated"),
    ("LD-013", "error", "a read-only action that can mutate or handles credentials"),
    ("LD-014", "error", "one binding in two defs"),
    ("LW-001", "warning", "description missing or too long, or title not imperative"),
    ("LW-002", "warning", "a string parameter without max_len"),
    ("LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag"),
    ("LW-004", "warning", "an unreviewed def in a stable pack"),
    ("LW-005", "warning", "a dismissed suggested trait without a reason"),
    ("LW-006", "warning", "an array parameter without max_items"),
    ("LW-007", "warning", "a critical parameter without provenance_min"),
    ("LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace"),
    ("LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example"),
    ("LW-010", "warning", "since is missing"),
)


def lint_rules_digest() -> str:
    """The digest the CI gate pins: the ordered (id, severity, title) list of the action-kit lint rules."""
    return hash_canonical({"d": LINT_RULES_DIGEST_DOMAIN, "rules": [{"id": i, "severity": s, "title": t} for i, s, t in _LINT_RULES]})


_DIGEST_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def check_lint_rules_pin(pin_text: str, actual: Optional[str] = None) -> Dict[str, Any]:
    """Enforce the pinned digest of the lint rule list: `pin_text` is the content of the pin file (one digest, surrounding whitespace
    ignored). Adding, removing or rewording a rule fails here until the pin is updated in the same change."""
    actual = lint_rules_digest() if actual is None else actual
    pinned = _trim(pin_text)
    if not _DIGEST_RE.fullmatch(pinned):
        return {"ok": False, "message": "the lint rules pin is not a digest (expected 43 base64url characters)"}
    if pinned == actual:
        return {"ok": True, "message": "lint rules digest %s matches the pin" % actual}
    return {"ok": False, "message": "lint rules digest %s differs from the pin %s: the rule list changed; review it and update the pin" % (actual, pinned)}


# ---- authoring gates ---------------------------------------------------------------------------------------------------------------------


def _bad(line: str) -> Dict[str, Any]:
    return {"ok": False, "exitCode": 2, "lines": [line]}


def to_analyzer_policy(doc: Any) -> Dict[str, Any]:
    """A policy document as the analyzer reads it: any shape `lint` accepts, plus optional `vetoes` and `tighten` members."""
    n = normalize_policy_input(doc)
    if not n["ok"]:
        return n
    policy: Dict[str, Any] = {"predicates": n["policy"]["predicates"], "caveats": n["policy"]["caveats"]}
    if _is_record(doc):
        if isinstance(doc.get("vetoes"), list):
            policy["vetoes"] = doc["vetoes"]
        if isinstance(doc.get("tighten"), list):
            policy["tighten"] = doc["tighten"]
    return {"ok": True, "policy": policy}


def diff_command(old_doc: Any, new_doc: Any, o: Any = None) -> Dict[str, Any]:
    """`diff`: does this change widen authority, or raise the most that can leave? {ok, exitCode (0 ok, 1 gate failed, 2 unusable
    input), lines}."""
    o = {} if o is None else o
    a, b = to_analyzer_policy(old_doc), to_analyzer_policy(new_doc)
    if not a["ok"]:
        return _bad("old policy: %s" % a["reason"])
    if not b["ok"]:
        return _bad("new policy: %s" % b["reason"])
    verb = jget(o, "verb")
    opts: Dict[str, Any] = {}
    if verb is not UNDEF:
        ex: Dict[str, Any] = {"verb": verb}
        if truthy(jget(o, "amountField")):
            ex["amountField"] = jget(o, "amountField")
        if truthy(jget(o, "integer")):
            ex["integer"] = True
        if jget(o, "windowSecs") is not UNDEF:
            ex["windowSecs"] = jget(o, "windowSecs")
        opts = {"exposure": ex}
    d = diff_policies(a["policy"], b["policy"], opts)
    allow: Dict[str, Any] = {"widen": jget(o, "allowWiden") is True}
    if jget(o, "maxExposureIncrease") is not UNDEF:
        allow["maxExposureIncrease"] = jget(o, "maxExposureIncrease")
    gate = diff_gate(d, allow)
    lines = ["no change in what is admitted"] if d["equivalent"] else list(d["summary"]) if d["summary"] else ["no witness found"]
    if not gate["ok"]:
        lines.extend("FAIL: %s" % r for r in gate["reasons"])
    lines.append("PASS" if gate["ok"] else "FAIL")
    return {"ok": gate["ok"], "exitCode": 0 if gate["ok"] else 1, "lines": lines}


def test_command(policy_doc: Any, tests_doc: Any, o: Any = None) -> Dict[str, Any]:
    """`test`: a policy test document against a policy, pinned by digest with `requireDigest`."""
    o = {} if o is None else o
    p = to_analyzer_policy(policy_doc)
    if not p["ok"]:
        return _bad("policy: %s" % p["reason"])
    if not _is_record(tests_doc) or tests_doc.get("kind") != "pca-policy-tests" or not isinstance(tests_doc.get("cases"), list):
        return _bad("tests: not a pca-policy-tests document")
    rd = jget(o, "requireDigest")
    r = run_policy_tests(p["policy"], tests_doc, {"requireDigest": rd} if rd is not UNDEF else {})
    lines = []
    for f in r["failures"]:
        eb = f.get("expectedDecidedBy")
        by = f.get("decidedBy")
        lines.append("FAIL %s: expected %s%s, got %s by %s" % (js_str(f.get("name", UNDEF)), js_str(f.get("expected", UNDEF)), " by %s" % js_str(eb) if truthy(eb) else "",
                                                                  js_str(f["got"]), "no clause" if by is None else js_str(by)))
    if not r["digestMatch"]:
        lines.append("%s: the policy differs from the one the examples were confirmed against" % ("FAIL" if truthy(rd) else "note"))
    lines.append("%d/%d examples %s" % (r["passed"], r["total"], "PASS" if r["ok"] else "FAIL"))
    return {"ok": r["ok"], "exitCode": 0 if r["ok"] else 1, "lines": lines}


def coverage_command(policy_doc: Any, traffic_doc: Any, o: Any = None) -> Dict[str, Any]:
    """`coverage`: which clauses and thresholds the tests or traffic never exercise, and which mutations they cannot tell apart."""
    o = {} if o is None else o
    p = to_analyzer_policy(policy_doc)
    if not p["ok"]:
        return _bad("policy: %s" % p["reason"])
    actions: Any = None
    if isinstance(traffic_doc, list):
        actions = traffic_doc
    elif _is_record(traffic_doc) and isinstance(traffic_doc.get("cases"), list):
        actions = [c.get("action", UNDEF) if _is_record(c) else c for c in traffic_doc["cases"]]
    if actions is None or any(not _is_record(a) or not isinstance(a.get("verb"), str) or not isinstance(a.get("resource"), str) for a in actions):
        return _bad("traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document")
    r = coverage(p["policy"], actions)
    mn: Dict[str, Any] = {}
    for src, dst in (("minClauses", "clauses"), ("minBoundaries", "boundaries"), ("minMutation", "mutation"), ("maxSurvivors", "maxSurvivors")):
        if jget(o, src) is not UNDEF:
            mn[dst] = jget(o, src)
    gate = coverage_gate(r, mn)
    sc = r["score"]
    lines = ["clauses decisive %s%%, boundaries covered %s%%, mutants killed %s%% (%d/%d)" % (
        to_fixed(sc["clauses"] * 100, 0), to_fixed(sc["boundaries"] * 100, 0), to_fixed(sc["mutation"] * 100, 0), r["mutants"]["killed"], r["mutants"]["total"] - r["mutants"]["equivalent"])]
    lines += ["untested: %s" % i for i in r["untested"]]
    lines += ["survives: %s%s" % (m["description"], " (kill with %s)" % js_json(m["killer"]) if m.get("killer") else "") for m in r["mutants"]["survivors"]]
    lines += ["FAIL: %s" % x for x in gate["reasons"]]
    lines.append("PASS" if gate["ok"] else "FAIL")
    return {"ok": gate["ok"], "exitCode": 0 if gate["ok"] else 1, "lines": lines}


# ---- command line ------------------------------------------------------------------------------------------------------------------------

_SEVERITIES = ("error", "warn", "info")

HELP = """pca-policy-ci — statically catch unsafe PCA policies before they ship.

Usage:
  pca-policy-ci <files...> [options]
  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
  pca-policy-ci test <policy.json> <tests.json> [--require-digest]
  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]

Options:
  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)
  --format <text|github>            Output format (default: text; 'github' = workflow annotations)
  --schema <file>                   Also check each policy against this signed action schema (JSON)
  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>
  --quiet, -q                       Only print findings and the summary line
  --help, -h                        Show this help

Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array
treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity."""


def parse_args(argv: Any) -> Dict[str, Any]:
    """The command line as {args: {files, maxSeverity, format, quiet, help, schema?, lintRulesPin?}} or {error}."""
    files: List[str] = []
    max_severity = "error"
    fmt = "text"
    quiet = False
    help_ = False
    schema: Optional[str] = None
    pin: Optional[str] = None
    argv = list(argv)
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--help" or a == "-h":
            help_ = True
        elif a == "--quiet" or a == "-q":
            quiet = True
        elif a == "--lint-rules-pin":
            i += 1
            v = argv[i] if i < len(argv) else None
            if v is None or v.startswith("-"):
                return {"error": "--lint-rules-pin expects a file"}
            pin = v
        elif a == "--max-severity":
            i += 1
            v = argv[i] if i < len(argv) else None
            if v is None or v not in _SEVERITIES:
                return {"error": "--max-severity expects one of %s" % "|".join(_SEVERITIES)}
            max_severity = v
        elif a.startswith("--max-severity="):
            v = a[len("--max-severity="):]
            if v not in _SEVERITIES:
                return {"error": "--max-severity expects one of %s" % "|".join(_SEVERITIES)}
            max_severity = v
        elif a == "--schema":
            i += 1
            v = argv[i] if i < len(argv) else None
            if v is None:
                return {"error": "--schema expects a file"}
            schema = v
        elif a.startswith("--schema="):
            schema = a[len("--schema="):]
        elif a == "--format":
            i += 1
            v = argv[i] if i < len(argv) else None
            if v != "text" and v != "github":
                return {"error": "--format expects 'text' or 'github'"}
            fmt = v
        elif a.startswith("--format="):
            v = a[len("--format="):]
            if v != "text" and v != "github":
                return {"error": "--format expects 'text' or 'github'"}
            fmt = v
        elif a.startswith("-"):
            return {"error": "unknown option '%s'" % a}
        else:
            files.append(a)
        i += 1
    args: Dict[str, Any] = {"files": files, "maxSeverity": max_severity, "format": fmt, "quiet": quiet, "help": help_}
    if schema is not None:
        args["schema"] = schema
    if pin is not None:
        args["lintRulesPin"] = pin
    return {"args": args}


_ERRNO_TEXT = {2: ("ENOENT", "no such file or directory"), 13: ("EACCES", "permission denied"), 21: ("EISDIR", "illegal operation on a directory")}


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            return fh.read()
    except OSError as e:
        code, text = _ERRNO_TEXT.get(e.errno or 0, ("E%s" % (e.errno,), (e.strerror or "").lower()))
        raise OSError("%s: %s, %s '%s'" % (code, text, "read" if e.errno == 21 else "open", path)) from None


def _lint_file(path: str, schema: Any = UNDEF) -> List[Dict[str, Any]]:
    try:
        text = _read_text(path)
    except OSError as e:
        return [{"rule": "malformed-policy", "severity": "error", "message": "cannot read file: %s" % e}]
    try:
        doc = json.loads(text)
    except ValueError as e:
        return [{"rule": "malformed-policy", "severity": "error", "message": "invalid JSON: %s" % e}]
    return lint(doc, {"schema": schema} if schema is not UNDEF else {})


_GH_LEVEL = {"error": "error", "warn": "warning", "info": "notice"}
_TEXT_TAG = {"error": "ERROR", "warn": "WARN", "info": "INFO"}


def _print_text(results: List[Dict[str, Any]], quiet: bool, write: Callable[[str], Any]) -> None:
    for r in results:
        if not quiet:
            write("\n%s:" % r["label"])
        if not r["findings"]:
            if not quiet:
                write("  (clean)")
            continue
        for f in r["findings"]:
            loc = " [%s]" % f["where"] if f.get("where") is not None else ""
            write("  %s %s%s: %s" % (_TEXT_TAG[f["severity"]].ljust(5), f["rule"], loc, f["message"]))


def _escape_gh(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_gh_prop(s: str) -> str:
    """Workflow-command PROPERTY values must also escape `:` and `,`, or a file name can add properties or end the command."""
    return _escape_gh(s).replace(":", "%3A").replace(",", "%2C")


def _print_github(results: List[Dict[str, Any]], write: Callable[[str], Any]) -> None:
    for r in results:
        for f in r["findings"]:
            props = "file=%s,title=%s" % (_escape_gh_prop(r["label"]), _escape_gh_prop(f["rule"]))
            loc = "%s: " % f["where"] if f.get("where") is not None else ""
            write("::%s %s::%s" % (_GH_LEVEL[f["severity"]], props, _escape_gh("%s%s" % (loc, f["message"]))))


def _read_json(path: str) -> Dict[str, Any]:
    try:
        return {"ok": True, "doc": json.loads(_read_text(path))}
    except (OSError, ValueError) as e:
        return {"ok": False, "reason": "%s: %s" % (path, e)}


_JS_NUMBER = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")


def _flag_number(flags: Dict[str, Any], k: str) -> Any:
    """`Number(v)` of a flag value when it is a non-blank finite number, else UNDEF."""
    v = flags.get(k)
    if not isinstance(v, str) or _trim(v) == "":
        return UNDEF
    t = _trim(v)
    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", t):
            n = float(int(t, 16))
        elif re.fullmatch(r"0[oO][0-7]+", t):
            n = float(int(t[2:], 8))
        elif re.fullmatch(r"0[bB][01]+", t):
            n = float(int(t[2:], 2))
        elif _JS_NUMBER.fullmatch(t):
            n = float(t)
        else:
            return UNDEF
    except (ValueError, OverflowError):
        return UNDEF
    if not fin(n):
        return UNDEF
    return int(n) if n.is_integer() and abs(n) < 2 ** 53 else n


_VALUED = ("--verb", "--amount-field", "--window-secs", "--max-exposure-increase", "--min-clauses", "--min-boundaries", "--min-mutation", "--max-survivors")
_BOOLS = ("--allow-widen", "--integer", "--require-digest")


def _run_authoring(cmd: str, rest: List[str], write: Callable[[str], Any]) -> int:
    files: List[str] = []
    flags: Dict[str, Any] = {}
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in _VALUED:
            i += 1
            if i >= len(rest):
                write("%s expects a value" % a)
                return 2
            flags[a] = rest[i]
        elif a in _BOOLS:
            flags[a] = True
        elif a.startswith("-"):
            write("unknown option '%s'" % a)
            return 2
        else:
            files.append(a)
        i += 1
    for k, v in flags.items():
        if k in _VALUED and k != "--verb" and k != "--amount-field" and _flag_number(flags, k) is UNDEF:
            write("%s expects a number, got '%s'" % (k, v))
            return 2
    if len(files) != 2:
        write("error: %s takes exactly two files" % cmd)
        write(HELP)
        return 2
    docs = [_read_json(f) for f in files]
    failed = next((d for d in docs if not d["ok"]), None)
    if failed is not None:
        write(failed["reason"])
        return 2
    a_doc, b_doc = docs[0]["doc"], docs[1]["doc"]

    def opt(flag: str, key: str, out: Dict[str, Any]) -> None:
        n = _flag_number(flags, flag)
        if n is not UNDEF:
            out[key] = n

    if cmd == "diff":
        o: Dict[str, Any] = {"allowWiden": "--allow-widen" in flags}
        if isinstance(flags.get("--verb"), str):
            o["verb"] = flags["--verb"]
        if isinstance(flags.get("--amount-field"), str):
            o["amountField"] = flags["--amount-field"]
        o["integer"] = "--integer" in flags
        opt("--window-secs", "windowSecs", o)
        opt("--max-exposure-increase", "maxExposureIncrease", o)
        r = diff_command(a_doc, b_doc, o)
    elif cmd == "test":
        r = test_command(a_doc, b_doc, {"requireDigest": "--require-digest" in flags})
    else:
        o = {}
        opt("--min-clauses", "minClauses", o)
        opt("--min-boundaries", "minBoundaries", o)
        opt("--min-mutation", "minMutation", o)
        opt("--max-survivors", "maxSurvivors", o)
        r = coverage_command(a_doc, b_doc, o)
    for line in r["lines"]:
        write(line)
    return r["exitCode"]


def run(argv: Any, write: Optional[Callable[[str], Any]] = None) -> int:
    """Run the command line (`<files...>`, `diff`, `test`, `coverage`); `write` receives each output line (default: stdout).
    Returns the exit code: 0 ok, 1 a gate failed, 2 unusable input."""
    if write is None:
        def write(s: str) -> None:  # noqa: F811
            sys.stdout.write(s + "\n")
    argv = list(argv)
    if argv and argv[0] in ("diff", "test", "coverage"):
        return _run_authoring(argv[0], argv[1:], write)
    parsed = parse_args(argv)
    if "error" in parsed:
        write(parsed["error"])
        write(HELP)
        return 2
    args = parsed["args"]
    if args["help"]:
        write(HELP)
        return 0
    pin_failed = False
    if "lintRulesPin" in args:
        try:
            r = check_lint_rules_pin(_read_text(args["lintRulesPin"]))
        except OSError as e:
            r = {"ok": False, "message": "cannot read the lint rules pin: %s" % e}
        write("%s — %s" % ("PASS" if r["ok"] else "FAIL", r["message"]))
        pin_failed = not r["ok"]
        if not args["files"]:
            return 1 if pin_failed else 0
    if not args["files"]:
        write("error: no policy files given")
        write(HELP)
        return 2
    schema: Any = UNDEF
    if "schema" in args:
        s = _read_json(args["schema"])
        if not s["ok"]:
            write(s["reason"])
            return 2
        schema = s["doc"]
    results = [{"label": f, "findings": _lint_file(f, schema)} for f in args["files"]]
    summary = summarize(results, {"maxSeverity": args["maxSeverity"]})
    if args["format"] == "github":
        _print_github(results, write)
    else:
        _print_text(results, args["quiet"], write)
    if summary.get("reason"):
        write("error: %s" % summary["reason"])
    c = summary["counts"]
    write("\n%s — %d error(s), %d warning(s), %d info across %d policy/policies (fail threshold: %s)" % (
        "PASS" if summary["ok"] else "FAIL", c["error"], c["warn"], c["info"], len(results), summary["maxSeverity"]))
    return max(1, summary["exitCode"]) if pin_failed else summary["exitCode"]


def main(argv: Optional[List[str]] = None) -> None:
    sys.exit(run(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":  # pragma: no cover
    main()
