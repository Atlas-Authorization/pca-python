"""PCA behind the OpenID AuthZEN Authorization API 1.0: a Policy Decision Point (Access Evaluation, Access Evaluations boxcar,
the COAZ MCP-tool profile, the AARP approval-required step-up), a framework-agnostic handler over ``{"path", "body"}`` dicts and
the three Search APIs (subject / resource / action). Port of the TypeScript reference (@atlasauth/pca-authzen).

Everything fails closed: an unresolved policy, a malformed PCActn, a verifier rejection, a policy denial or any raised error is
``decision: False``. The Policy-VM (``decide`` / ``derive_decide_input``) is injected through the config (keys of the same names); a PDP
without it fails closed on the path that needs it. ``admits_concrete`` defaults to the native analyzer (config may override). Injected ``decide``
returns the TypeScript-shaped dict (``releaseGuardianShare``, ``admit``, ``r``, ``requiredThreshold``, ``reasons``)."""
from ._fin import fin
import json
import math
import time
from typing import Any, Callable, Dict, List, Optional

from .authorize import read_envelope
from .pca import ARTIFACT_SIZE_REASON, artifact_too_large, hash_canonical, params_digest, strict_parse, verify_pcactn_core

PCA_APPROVAL_KEY = "pca_approval"
PCA_ACTION_KEY = "pca_action"
PCA_PROVENANCE_KEY = "pca_provenance"
DEFAULT_MAX_EVALUATIONS = 100
EVALUATION_PATH = "/access/v1/evaluation"
EVALUATIONS_PATH = "/access/v1/evaluations"
COAZ_TOOL_PATH = "/access/v1/mcp/tool/evaluation"
SEARCH_SUBJECT_PATH = "/access/v1/search/subject"
SEARCH_RESOURCE_PATH = "/access/v1/search/resource"
SEARCH_ACTION_PATH = "/access/v1/search/action"
MAX_SEARCH_LIMIT = 1000

_UNDEF = object()  # a JSON member that is absent (TypeScript `undefined`), distinct from null


def _is_rec(x: Any) -> bool:
    return isinstance(x, dict)


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)


def _truthy(v: Any) -> bool:
    """JavaScript truthiness: {} and [] are truthy, unlike Python."""
    if v is None or v is False or v is _UNDEF:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return not (v == 0 or v != v)
    return v != ""


def _prop(x: Any, k: str) -> Any:
    """x.k in JavaScript: null/undefined throw, a primitive or array has no such member."""
    if x is None or x is _UNDEF:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if x is None else "undefined", k))
    return x.get(k, _UNDEF) if isinstance(x, dict) else _UNDEF


def _js(v: Any) -> str:
    """A JavaScript template-literal rendering of a JSON value."""
    if v is _UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    if isinstance(v, (int, float, str)):
        return str(v)
    if isinstance(v, list):
        return ",".join("" if x is None else _js(x) for x in v)
    return "[object Object]"


def _err(e: BaseException) -> str:
    return str(e) if str(e) else "unknown"


# ---- guards -----------------------------------------------------------------------------------------------------------------

def is_authzen_subject(x: Any) -> bool:
    return _is_rec(x) and isinstance(x.get("type"), str) and isinstance(x.get("id"), str)


def is_authzen_action(x: Any) -> bool:
    return _is_rec(x) and isinstance(x.get("name"), str)


def is_authzen_resource(x: Any) -> bool:
    return _is_rec(x) and isinstance(x.get("type"), str) and isinstance(x.get("id"), str)


def is_access_evaluation_request(x: Any) -> bool:
    return (_is_rec(x) and is_authzen_subject(x.get("subject")) and is_authzen_action(x.get("action"))
            and is_authzen_resource(x.get("resource")) and ("context" not in x or _is_rec(x["context"])))


def is_access_evaluations_request(x: Any) -> bool:
    return _is_rec(x) and isinstance(x.get("evaluations"), list)


def is_coaz_tool_authorization_request(x: Any) -> bool:
    return (_is_rec(x) and is_authzen_subject(x.get("subject")) and _is_rec(x.get("tool"))
            and isinstance(x["tool"].get("name"), str))


def _is_required_threshold(x: Any) -> bool:
    return (_is_rec(x) and _is_num(x.get("t")) and x["t"] in (1, 2, 3) and isinstance(x.get("proof"), str)
            and isinstance(x.get("optimisticAllowed"), bool))


# ---- AARP -------------------------------------------------------------------------------------------------------------------

def approval_of(resp: Any) -> Optional[Dict[str, Any]]:
    """The AARP pending-approval reference of a decision, or None."""
    ctx = _prop(resp, "context")
    if ctx is _UNDEF:
        return None
    p = _prop(ctx, PCA_APPROVAL_KEY)
    if _is_rec(p) and p.get("approval_required") is True and isinstance(p.get("auth_req_id"), str):
        tier = 3 if _is_num(p.get("tier")) and p["tier"] == 3 else 2
        rt = p.get("required_threshold")
        return {
            "approval_required": True,
            "auth_req_id": p["auth_req_id"],
            "tier": tier,
            "required_threshold": rt if _is_required_threshold(rt) else {"t": tier, "proof": "strong" if tier == 3 else "standard", "optimisticAllowed": False},
            "goal_commit": p["goal_commit"] if isinstance(p.get("goal_commit"), str) else "",
            "risk": p["risk"] if _is_num(p.get("risk")) else 1,
            "reason": p["reason"] if isinstance(p.get("reason"), str) else "approval required",
            "requested_at": p["requested_at"] if _is_num(p.get("requested_at")) else 0,
        }
    return None


def is_approval_required(resp: Any) -> bool:
    return approval_of(resp) is not None


# ---- mapping ----------------------------------------------------------------------------------------------------------------

def _deny(reason: str, id: Optional[str] = None, status: Optional[int] = None) -> Dict[str, Any]:
    context: Dict[str, Any] = {"reason_admin": {"denied": True, "reason": reason}, "reason_user": {"message": reason}}
    if status is not None:
        context["error"] = {"status": status, "message": reason}
    if id is not None:
        context["id"] = id
    return {"decision": False, "context": context}


def _permit(reason: str) -> Dict[str, Any]:
    return {"decision": True, "context": {"reason_admin": {"reason": reason}}}


def _pick_reversibility(req: dict) -> Optional[str]:
    from_action = req["action"].get("properties")
    if _is_rec(from_action) and isinstance(from_action.get("reversibility_class"), str):
        return from_action["reversibility_class"]
    from_ctx = req.get("context")
    if _is_rec(from_ctx) and isinstance(from_ctx.get("reversibility_class"), str):
        return from_ctx["reversibility_class"]
    return None


def _env_from_context(context: Any) -> Optional[Dict[str, Any]]:
    if not _is_rec(context):
        return None
    out = {k: v for k, v in context.items() if k not in (PCA_ACTION_KEY, PCA_APPROVAL_KEY)}
    return out if out else None


def default_to_action(req: dict) -> Dict[str, Any]:
    """verb = action.name; resource = "type:id" (just the type when id is empty); params = resource.properties overlaid by
    action.properties; subject = subject.properties; env = context minus the PCA keys."""
    res, act = req["resource"], req["action"]
    resource = "%s:%s" % (res["type"], res["id"]) if len(res["id"]) > 0 else res["type"]
    params: Dict[str, Any] = {}
    if _is_rec(res.get("properties")):
        params.update(res["properties"])
    if _is_rec(act.get("properties")):
        params.update(act["properties"])
    out: Dict[str, Any] = {"verb": act["name"], "resource": resource, "params": params}
    rc = _pick_reversibility(req)
    if rc is not None:
        out["reversibilityClass"] = rc
    if _is_rec(req["subject"].get("properties")):
        out["subject"] = req["subject"]["properties"]
    env = _env_from_context(req.get("context"))
    if env is not None:
        out["env"] = env
    return out


def _pcactn_from_context(context: Any) -> Any:
    """The forwarded PCActn dict, None when absent, or the string "malformed"."""
    if not _is_rec(context):
        return None
    raw = context.get(PCA_ACTION_KEY)
    if raw is None:
        return None
    if not isinstance(raw, str):
        return "malformed"
    try:
        if artifact_too_large(raw):
            raise ValueError(ARTIFACT_SIZE_REASON)
        v = strict_parse(raw)
        if not isinstance(v, dict):
            raise TypeError("decodePCActn: not an object")
        return v
    except Exception:  # noqa: BLE001 - any decode failure is a refusal
        return "malformed"


def _params_of(action: dict) -> dict:
    return action["params"] if _is_rec(action.get("params")) else {}


def _fresh_budget(grant: Any, now: Any) -> Dict[str, Any]:
    env = read_envelope(grant)
    b_max = env["risk_policy"].get("bMax") if env else None
    return {"B": b_max if _is_num(b_max) else 0, "tau": now, "asOf": now}


def _approval_required(p: dict, decision: dict, grant: Any, now: Any) -> Dict[str, Any]:
    tier = 3 if decision["requiredThreshold"]["t"] >= 3 else 2
    reasons = decision.get("reasons")
    reason = reasons[0] if reasons else "requires tier-%d co-sign" % tier
    act = p["action"]
    body: Dict[str, Any] = {"d": "atlas-pca/authzen/aarp/v1", "verb": act["verb"], "resource": act["resource"],
                            "params_digest": act["params_digest"], "at": now}
    if "counter" in p:
        body["counter"] = p["counter"]
    auth_req_id = hash_canonical(body)
    env = read_envelope(grant)
    pending = {
        "approval_required": True,
        "auth_req_id": auth_req_id,
        "tier": tier,
        "required_threshold": decision["requiredThreshold"],
        "goal_commit": env["goal_commit"] if env else "",
        "risk": decision["r"],
        "reason": reason,
        "requested_at": now,
    }
    return {"decision": False, "context": {
        "id": auth_req_id,
        "reason_admin": {"stage": "step_up", "risk": decision["r"], "threshold": decision["requiredThreshold"], "reasons": reasons},
        "reason_user": {"message": "approval required before this action can proceed"},
        PCA_APPROVAL_KEY: pending,
    }}


def _merge_evaluation(defaults: dict, item: Any) -> Optional[dict]:
    if item is None:
        raise TypeError("Cannot read properties of null (reading 'subject')")
    it = item if isinstance(item, dict) else {}

    def pick(k: str) -> Any:
        v = it.get(k)
        return v if v is not None else defaults.get(k)

    subject, action, resource = pick("subject"), pick("action"), pick("resource")
    if not is_authzen_subject(subject) or not is_authzen_action(action) or not is_authzen_resource(resource):
        return None
    out = {"subject": subject, "action": action, "resource": resource}
    if it.get("context") is not None:
        out["context"] = it["context"]
    elif "context" in defaults:
        out["context"] = defaults["context"]
    return out


# ---- the PDP ----------------------------------------------------------------------------------------------------------------

def _need(config: dict, name: str) -> Callable:
    fn = config.get(name)
    if fn is None and name == "admits_concrete":  # the reference imports the analyzer's admitsConcrete; so does the native one
        from .analyzer_core import admits_concrete
        return admits_concrete
    if fn is None:
        raise RuntimeError("authzen: config.%s is not provided (fail closed)" % name)
    return fn


class AuthzenPdp:
    """``config`` keys: resolve(req) -> ctx|None (required); audience (absent = fail closed, None = accept any, str = exact);
    authorized_plan_roots; insecure_skip_plan_root_check; now() -> epoch ms; tool_capability(name); require_proof (default True);
    authorizer(input) -> {allow, reason}; require_authorizer (default True); max_evaluations; decide; derive_decide_input;
    admits_concrete. A ``ctx`` is ``{grant, chain?, policy, plan?, risk?, budget?, enforce?, to_action?}``."""

    def __init__(self, config: dict):
        self.config = config
        self._clock = config.get("now") or (lambda: int(time.time() * 1000))
        self._tool_capability = config.get("tool_capability") or (lambda name: name)

    def evaluate(self, req: Any) -> Dict[str, Any]:
        c = self.config
        now = self._clock()
        try:
            ctx = c["resolve"](req)
            if ctx is None:
                return _deny("no PCA authority resolved for this request")
            mapped = (ctx["to_action"] if ctx.get("to_action") is not None else default_to_action)(req)
            carried = _pcactn_from_context(req.get("context"))
            if carried == "malformed":
                return _deny("context carries a malformed PCActn")

            if carried is None:
                if c.get("require_proof") is not False:
                    return _deny("a signed PCActn is required (requireProof)")
                admissible = _need(c, "admits_concrete")(ctx["policy"], mapped)
                return _permit("statically admissible under the declared authority") if admissible \
                    else _deny("action is not admissible under the declared authority")

            p = carried
            if c.get("require_authorizer") is not False and c.get("authorizer") is None:
                return _deny("no replay/revocation authorizer is configured (requireAuthorizer)")

            # the proof must be FOR this request: verb + resource, and the attributes must hash to the signed params_digest
            act = p.get("action")
            if act is None:
                raise TypeError("Cannot read properties of undefined (reading 'verb')")
            if not isinstance(act, dict):
                act = {}
            verb, resource = act.get("verb", _UNDEF), act.get("resource", _UNDEF)
            if verb != mapped["verb"] or resource != mapped["resource"]:
                return _deny("the PCActn authorizes %s on %s, not the requested %s on %s" % (_js(verb), _js(resource), _js(mapped["verb"]), _js(mapped["resource"])))
            req_params = _params_of(mapped)
            if params_digest(req_params) != act.get("params_digest", _UNDEF):
                return _deny("the request attributes do not match the PCActn's signed params_digest")

            audience = c.get("audience")
            if "audience" in c and audience is None and isinstance(p.get("aud"), str) and p["aud"]:
                audience = p["aud"]  # explicit opt-out: accept any audience
            enforce = ctx["enforce"] if ctx.get("enforce") is not None else {}
            if enforce.get("attestation") is not None:
                raise RuntimeError("authzen: enforce.attestation is not supported by this verifier (fail closed)")
            verify = verify_pcactn_core(
                p, ctx["grant"], now=now, audience=audience,
                authorized_plan_roots=c.get("authorized_plan_roots"),
                insecure_skip_plan_root_check=bool(c.get("insecure_skip_plan_root_check")),
                enforce_freshness=enforce.get("freshness"), enforce_taint=enforce.get("taint"))
            if not verify.allow:
                return {"decision": False, "context": {
                    "reason_admin": {"denied": True, "stage": "verify", "checks": verify.checks, "reason": verify.reason if verify.reason is not None else "PCActn verification failed"},
                    "reason_user": {"message": "the proof-carrying action did not verify"}}}

            budget = ctx["budget"] if ctx.get("budget") is not None else _fresh_budget(ctx["grant"], now)
            dctx: Dict[str, Any] = {"grant": ctx["grant"], "chain": ctx["chain"] if ctx.get("chain") is not None else p.get("cap_chain"),
                                    "params": req_params, "risk": ctx["risk"] if ctx.get("risk") is not None else {}, "budget": budget, "now": now}
            if ctx.get("plan") is not None:
                dctx["plan"] = ctx["plan"]
            if mapped.get("subject") is not None:
                dctx["subject"] = mapped["subject"]
            if mapped.get("env") is not None:
                dctx["env"] = mapped["env"]
            decision = _need(c, "decide")(_need(c, "derive_decide_input")(p, dctx))

            if not _truthy(decision["releaseGuardianShare"]):
                return {"decision": False, "context": {
                    "reason_admin": {"denied": True, "stage": "policy", "reasons": decision.get("reasons"), "risk": decision["r"]},
                    "reason_user": {"message": "the policy does not permit this action"}}}

            if _truthy(decision.get("admit")):
                if c.get("authorizer") is not None:
                    ain: Dict[str, Any] = {"operation": {"verb": mapped["verb"], "resource": mapped["resource"], "params": req_params}, "pcactn": p}
                    if _is_rec(req.get("context")) and PCA_PROVENANCE_KEY in req["context"]:
                        ain["provenance"] = req["context"][PCA_PROVENANCE_KEY]
                    az = c["authorizer"](ain)
                    allow = az["allow"] if isinstance(az, dict) else az.allow
                    if not _truthy(allow):
                        reason = az.get("reason") if isinstance(az, dict) else getattr(az, "reason", None)
                        return {"decision": False, "context": {
                            "reason_admin": {"denied": True, "stage": "authorize", "reason": reason},
                            "reason_user": {"message": "the proof-carrying action was not authorized"}}}
                return {"decision": True, "context": {"reason_admin": {"stage": "policy", "risk": decision["r"], "threshold": decision["requiredThreshold"]}}}

            return _approval_required(p, decision, ctx["grant"], now)
        except Exception as e:  # noqa: BLE001 - fail closed
            return _deny("evaluation error (fail closed): %s" % _err(e), None, 500)

    def evaluations(self, req: Any) -> Dict[str, Any]:
        items = _prop(req, "evaluations")
        if not isinstance(items, list):
            return {"evaluations": []}
        opts = _prop(req, "options")
        semantic = opts.get("evaluations_semantic") if isinstance(opts, dict) else None
        if semantic is None:
            semantic = "execute_all"

        def refuse(reason: str) -> Dict[str, Any]:
            return {"evaluations": [_deny(reason, None, 400) for _ in items]}

        if semantic not in ("execute_all", "deny_on_first_deny", "permit_on_first_permit") or not isinstance(semantic, str):
            return refuse("unsupported evaluations_semantic")
        mx = self.config.get("max_evaluations")
        mx = DEFAULT_MAX_EVALUATIONS if mx is None else mx
        if len(items) > mx:
            return refuse("too many evaluations (limit %s)" % _js(mx if mx != math.inf else "Infinity"))
        merged = [_merge_evaluation(req, it) for it in items]
        out: List[Dict[str, Any]] = []
        for m in merged:
            r = _deny("incomplete evaluation (missing subject/action/resource)", None, 400) if m is None else self.evaluate(m)
            out.append(r)
            if semantic == "deny_on_first_deny" and r["decision"] is False:
                break
            if semantic == "permit_on_first_permit" and r["decision"] is True:
                break
        return {"evaluations": out}

    def evaluate_tool(self, req: dict) -> Dict[str, Any]:
        tool = req["tool"]
        try:
            capability = self._tool_capability(tool["name"])
        except Exception as e:  # noqa: BLE001 - fail closed
            r = _deny("evaluation error (fail closed): %s" % _err(e), None, 500)
            return {"decision": False, "tool": tool["name"], "required_capability": "", "context": r["context"]}
        action: Dict[str, Any] = {"name": capability}
        if "arguments" in tool:
            action["properties"] = tool["arguments"]
        mapped: Dict[str, Any] = {"subject": req["subject"], "action": action, "resource": {"type": "mcp_tool", "id": tool["name"]}}
        if "context" in req:
            mapped["context"] = req["context"]
        resp = self.evaluate(mapped)
        out: Dict[str, Any] = {"decision": resp["decision"], "tool": tool["name"], "required_capability": capability}
        if "context" in resp:
            out["context"] = resp["context"]
        return out


def authzen_pdp(config: dict) -> AuthzenPdp:
    return AuthzenPdp(config)


# ---- handler ----------------------------------------------------------------------------------------------------------------

def authzen_handler(pdp: AuthzenPdp) -> Callable[[dict], Dict[str, Any]]:
    """``handler({"path", "body"}) -> {"status", "body"}``. A malformed body is a 400 (a PEP enforces it as a deny); any raised
    error is a 500 with no detail."""

    def route(req: dict) -> Dict[str, Any]:
        path, body = req.get("path", _UNDEF), req.get("body")
        if path == EVALUATION_PATH:
            if not is_access_evaluation_request(body):
                return {"status": 400, "body": {"error": "invalid AuthZEN Access Evaluation request"}}
            return {"status": 200, "body": pdp.evaluate(body)}
        if path == EVALUATIONS_PATH:
            # an absent or empty `evaluations` array is a plain single Access Evaluation
            if _is_rec(body) and ("evaluations" not in body or (isinstance(body["evaluations"], list) and len(body["evaluations"]) == 0)):
                if not is_access_evaluation_request(body):
                    return {"status": 400, "body": {"error": "invalid AuthZEN Access Evaluations request"}}
                return {"status": 200, "body": pdp.evaluate(body)}
            if not is_access_evaluations_request(body):
                return {"status": 400, "body": {"error": "invalid AuthZEN Access Evaluations request"}}
            return {"status": 200, "body": pdp.evaluations(body)}
        if path == COAZ_TOOL_PATH:
            if not is_coaz_tool_authorization_request(body):
                return {"status": 400, "body": {"error": "invalid COAZ MCP-tool authorization request"}}
            return {"status": 200, "body": pdp.evaluate_tool(body)}
        return {"status": 404, "body": {"error": "unknown AuthZEN path: %s" % _js(path)}}

    def handle(req: dict) -> Dict[str, Any]:
        try:
            return route(req)
        except Exception:  # noqa: BLE001 - a PEP treats non-200 as a deny; never leak internals
            return {"status": 500, "body": {"error": "internal error"}}

    return handle


# ---- search -----------------------------------------------------------------------------------------------------------------

def _str(x: Any) -> bool:
    return isinstance(x, str) and len(x) > 0


def _entity(x: Any, need_id: bool) -> bool:
    return _is_rec(x) and _str(x.get("type")) and (_str(x.get("id")) if need_id else True) and ("properties" not in x or _is_rec(x["properties"]))


def _action(x: Any) -> bool:
    return _is_rec(x) and _str(x.get("name")) and ("properties" not in x or _is_rec(x["properties"]))


def _safe_nonneg_int(v: Any) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, float) and (not fin(v) or not v.is_integer() or math.copysign(1.0, v) < 0):
        return False
    return 0 <= v <= 2 ** 53 - 1


def _page_ok(p: Any) -> bool:
    if p is _UNDEF:
        return True
    if not _is_rec(p):
        return False
    if "token" in p and not isinstance(p["token"], str):
        return False
    if "limit" in p and not _safe_nonneg_int(p["limit"]):
        return False
    return "properties" not in p or _is_rec(p["properties"])


def _base(b: dict) -> bool:
    return ("context" not in b or _is_rec(b["context"])) and _page_ok(b.get("page", _UNDEF))


def is_subject_search(b: Any) -> bool:
    return _is_rec(b) and _base(b) and _entity(b.get("subject"), False) and _action(b.get("action")) and _entity(b.get("resource"), True)


def is_resource_search(b: Any) -> bool:
    return _is_rec(b) and _base(b) and _entity(b.get("subject"), True) and _action(b.get("action")) and _entity(b.get("resource"), False)


def is_action_search(b: Any) -> bool:
    return _is_rec(b) and _base(b) and "action" not in b and _entity(b.get("subject"), True) and _entity(b.get("resource"), True)


def _provider_fn(p: Any, name: str) -> Optional[Callable]:
    fn = p.get(name) if isinstance(p, dict) else getattr(p, name, None)
    return fn if callable(fn) else None


def search_metadata(base: str, p: Any) -> Dict[str, str]:
    """Fragment for /.well-known/authzen-configuration; a missing endpoint means that search is unsupported."""
    out: Dict[str, str] = {}
    if _provider_fn(p, "search_subject"):
        out["search_subject_endpoint"] = base + SEARCH_SUBJECT_PATH
    if _provider_fn(p, "search_resource"):
        out["search_resource_endpoint"] = base + SEARCH_RESOURCE_PATH
    if _provider_fn(p, "search_action"):
        out["search_action_endpoint"] = base + SEARCH_ACTION_PATH
    return out


def _strip_id(req: dict, key: str) -> dict:
    e = dict(req[key])
    e.pop("id", None)
    out = dict(req)
    out[key] = e
    return out


def _json_key(t: Any) -> str:
    """JSON.stringify: insertion order kept, an integral float prints as an integer."""
    def fix(v: Any) -> Any:
        if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
            return int(v)
        if isinstance(v, dict):
            return {k: fix(x) for k, x in v.items()}
        if isinstance(v, list):
            return [fix(x) for x in v]
        return v
    return json.dumps(fix(t), ensure_ascii=False, separators=(",", ":"))


def _shape(r: Any, limit: Any, type_ok: Callable[[Any], bool]) -> Dict[str, Any]:
    results_in = _prop(r, "results")
    if not isinstance(results_in, list):
        raise TypeError("results.filter is not a function")
    seen = set()
    results = []
    for t in results_in:
        k = _json_key(t)
        if not type_ok(t) or k in seen:
            continue
        seen.add(k)
        results.append(t)
    capped = results[:int(limit)] if limit is not _UNDEF and limit > 0 else results
    # a provider that ignores the limit would hide results behind a page marker we cannot resume: fail closed
    if len(capped) < len(results):
        raise ValueError("provider returned more than the page limit")
    out: Dict[str, Any] = {}
    pg = r.get("page", _UNDEF)
    if _truthy(pg):
        page: Dict[str, Any] = {}
        if "next_token" in pg:
            page["next_token"] = pg["next_token"]
        page["count"] = len(capped)
        if "total" in pg:
            page["total"] = pg["total"]
        if _truthy(pg.get("properties")):
            page["properties"] = pg["properties"]
        out["page"] = page
    if _truthy(r.get("context")):
        out["context"] = r["context"]
    out["results"] = capped
    return out


def _entity_type_ok(type_: str) -> Callable[[Any], bool]:
    def ok(e: Any) -> bool:
        return _prop(e, "type") == type_
    return ok


def authzen_search_handler(p: Any) -> Callable[[dict], Optional[Dict[str, Any]]]:
    """Returns None for a path that is not a search path, so it can be chained after ``authzen_handler``'s result."""

    def route(req: dict) -> Optional[Dict[str, Any]]:
        path, body = req.get("path", _UNDEF), req.get("body")
        if path == SEARCH_SUBJECT_PATH:
            fn = _provider_fn(p, "search_subject")
            if not fn:
                return {"status": 404, "body": {"error": "subject search is not supported"}}
            if not is_subject_search(body):
                return {"status": 400, "body": {"error": "invalid AuthZEN subject search request"}}
            lim = body["page"].get("limit", _UNDEF) if "page" in body else _UNDEF
            return {"status": 200, "body": _shape(fn(_strip_id(body, "subject")), lim, _entity_type_ok(body["subject"]["type"]))}
        if path == SEARCH_RESOURCE_PATH:
            fn = _provider_fn(p, "search_resource")
            if not fn:
                return {"status": 404, "body": {"error": "resource search is not supported"}}
            if not is_resource_search(body):
                return {"status": 400, "body": {"error": "invalid AuthZEN resource search request"}}
            lim = body["page"].get("limit", _UNDEF) if "page" in body else _UNDEF
            return {"status": 200, "body": _shape(fn(_strip_id(body, "resource")), lim, _entity_type_ok(body["resource"]["type"]))}
        if path == SEARCH_ACTION_PATH:
            fn = _provider_fn(p, "search_action")
            if not fn:
                return {"status": 404, "body": {"error": "action search is not supported"}}
            if not is_action_search(body):
                return {"status": 400, "body": {"error": "invalid AuthZEN action search request"}}
            lim = body["page"].get("limit", _UNDEF) if "page" in body else _UNDEF
            return {"status": 200, "body": _shape(fn(body), lim, lambda _t: True)}
        return None

    def handle(req: dict) -> Optional[Dict[str, Any]]:
        try:
            return route(req)
        except Exception:  # noqa: BLE001
            return {"status": 500, "body": {"error": "internal error"}}

    return handle
