"""Server-side and authoring public surface (the TypeScript ``server/authorize``, ``server/require-pca``, ``server/verify``,
``server/authorize-execution``, ``workflow``, ``policy-templates`` and ``policy-link``) under the Python names of this SDK: the state stores
are :class:`atlas_pca.authorize.MemoryStateStore` / :class:`SqliteStateStore`, the build-once authorizer is :class:`atlas_pca.authorize.AuthorizeOptions`
and the request guard is :func:`atlas_pca.server.require_pca`; this module adds the thin entry points and helpers that were still missing."""
import copy
from typing import Any, Callable, Dict, List, Optional, Sequence

from .authorize import AuthorizeOptions, MemoryStateStore, SqliteStateStore
from .caveat_lang import evaluate_k1  # noqa: F401  (kept for callers importing the surface from one place)
from .facade import create_agent
from .k3 import verify_body
from .pca_surface import EXECUTION_REQUIRED_CHECKS, STATEFUL_REQUIRED_CHECKS  # noqa: F401
from .policy_link import instantiate_template, template_digest
from .pca import hash_canonical
from .workflow import WORKFLOW_DOMAIN, _receipt_error, dag_error, valid_workflow_body, workflow_digest  # noqa: F401

__all__ = ["memory_pca_store", "atomic_memory_pca_store", "is_atomic_pca_state_store", "durable_pca_state_store", "create_authorizer",
           "require_authorized", "authorize_execution", "PolicyBuilder", "policy", "decision_of_result", "missing_execution_components", "enforce_required", "workflow_commitment_error",
           "workflow_receipt_error", "slots_digest", "create_link", "list_templates", "from_template", "TEMPLATES", "PcaAgentError"]


def memory_pca_store() -> MemoryStateStore:
    """A single-process replay and budget store (``scope == "process"``)."""
    return MemoryStateStore()


atomic_memory_pca_store = memory_pca_store  # the Python memory store is atomic (one lock around the claim)


def is_atomic_pca_state_store(s: Any) -> bool:
    """True iff `s` has the atomic ``claim`` and ``raise_pin`` of a state store (the pair the authorize pipeline needs)."""
    return s is not None and callable(getattr(s, "claim", None)) and callable(getattr(s, "raise_pin", getattr(s, "pin", None)))


def durable_pca_state_store(path: str) -> SqliteStateStore:
    """A durable, multi-process state store on a SQLite file (the claim is one atomic statement)."""
    return SqliteStateStore(path)


def create_authorizer(options: AuthorizeOptions) -> Callable[..., Any]:
    """Build the authorizer once: ``authorizer(pcactn, operation=..., audience=..., resolve_grant=..., now=...)`` returns an
    :class:`AuthorizeResult`. A missing component refuses every call (fail closed), as ``authorize`` does."""
    def authorizer(pcactn: Any, **call: Any) -> Any:
        return options.run(pcactn, **call)
    return authorizer


def require_authorized(operation: Callable[[Any, Any], Optional[dict]], *, audience: str, resolve_grant: Callable, options: AuthorizeOptions,
                       **kw: Any) -> Callable[..., Any]:
    """A request guard over ``authorize``: ``guard(headers, body)`` maps the request to its operation with ``operation(headers, body)`` (a refusal
    when it cannot) and returns the :class:`atlas_pca.server.PCAResult`."""
    from .server import require_pca
    inner = require_pca(audience=audience, resolve_grant=resolve_grant, authorize=options, **kw)

    def guard(headers: Any, body: Any = None) -> Any:
        try:
            op = operation(headers, body)
        except Exception:  # noqa: BLE001 - no operation: refused below
            op = None
        return inner(headers, body, operation=op)
    return guard


def decision_of_result(r: Any) -> str:
    """``allow`` for an ok guard result, ``escalate`` for an escalated refusal, else ``deny``."""
    ok = r.get("ok") if isinstance(r, dict) else getattr(r, "ok", None)
    dec = r.get("decision") if isinstance(r, dict) else getattr(r, "decision", None)
    return "allow" if ok is True else "escalate" if dec == "escalate" else "deny"


def missing_execution_components(opts: Any) -> List[str]:
    """The required components of an executor that are absent: ``audience``, ``grant or resolveGrant``, ``state`` (``get`` / ``put``) and
    ``isRevoked``."""
    o = opts if isinstance(opts, dict) else {}
    missing: List[str] = []
    if not isinstance(o.get("audience"), str) or o["audience"] == "":
        missing.append("audience")
    if o.get("grant") is None and not callable(o.get("resolveGrant")):
        missing.append("grant or resolveGrant")
    st = o.get("state")
    if st is None or not callable(getattr(st, "get", None)) or not callable(getattr(st, "put", None)):
        missing.append("state")
    if not callable(o.get("isRevoked")):
        missing.append("isRevoked")
    return missing


def enforce_required(v: dict, required: Sequence[str]) -> dict:
    """Default-deny of the required checks: every name in `required` whose status is not ``pass`` makes the verdict a refusal and is reported
    (``unsupported`` stays ``unsupported``; anything else becomes ``fail``). Mutates and returns `v` (``allow``, ``checks``, ``reasons``)."""
    for name in required:
        st = v["checks"].get(name)
        if st == "pass":
            continue
        v["allow"] = False
        v["reasons"].append("%s: required check is %s (default-deny: not enforced by this resource server)"
                            % (name, "unsupported" if st == "unsupported" else (st if st is not None else "absent")))
        if st != "unsupported":
            v["checks"][name] = "fail"
    return v


def workflow_commitment_error(workflow: Any, principal: Any, now: Any) -> Optional[str]:
    """Why a signed workflow cannot be admitted (``bad_workflow``, ``bad_dag``, ``bad_signature``, ``not_yet`` or ``expired``), or None. Used by
    issuers of step receipts, which must not sign for a workflow they would refuse."""
    from .workflow import is_b32, is_uint, only_keys
    if not isinstance(workflow, dict) or not only_keys(workflow, ["body", "sig"]) or not valid_workflow_body(workflow.get("body")) \
            or not is_b32(principal) or not is_uint(now):
        return "bad_workflow"
    body = workflow["body"]
    if dag_error(body) is not None:
        return "bad_dag"
    if body.get("principal") != principal or not verify_body(WORKFLOW_DOMAIN, body, principal, workflow.get("sig")):
        return "bad_signature"
    if now < body["issued_at"]:
        return "not_yet"
    if now >= body["expires_at"]:
        return "expired"
    return None


def workflow_receipt_error(w: dict, rs_signer: str, receipts: list, now: int) -> Optional[Dict[str, int]]:
    """Check a receipt chain against the workflow: ``{"at": index}`` of the offending receipt, or None."""
    i = _receipt_error(w, rs_signer, receipts, now)
    return None if i is None else {"at": i}


# ---- policy links and templates ------------------------------------------------------------------------------------------

def slots_digest(slots: dict) -> str:
    """The digest a ``bind_params_digest`` reference cites: the canonical hash of the slot object."""
    return hash_canonical(slots)


def create_link(definition: dict, slots: dict, bind_params: bool = False) -> dict:
    """A template reference for `definition` filled with `slots` (raises ``TypeError`` when the slots do not instantiate it). With `bind_params`
    the reference carries the slots' digest instead of the slots."""
    r = instantiate_template(definition, slots)
    if not r.get("ok"):
        raise TypeError("createLink: %s" % r.get("reason"))
    if bind_params:
        return {"template_id": definition["id"], "version_digest": template_digest(definition), "bind_params_digest": slots_digest(slots)}
    return {"template_id": definition["id"], "version_digest": template_digest(definition), "slots": copy.deepcopy(slots)}


TEMPLATES: Dict[str, dict] = {
    "read-only": {"name": "read-only", "description": "Read access only — no side effects anywhere.",
                  "permissions": {"github": ["read"], "slack": ["read"], "files": ["read"], "http": ["get"]}},
    "support-agent": {"name": "support-agent", "description": "Draft + send customer email and post to Slack, rate-limited.",
                      "permissions": {"gmail": ["draft", "send"], "slack": ["post_message"]}, "limits": {"send": "50/day", "post_message": "100/day"}},
    "finance-bot": {"name": "finance-bot", "description": "Issue reversible refunds within a daily cap; no payouts.",
                    "permissions": {"stripe": ["refund"]}, "limits": {"refund": "$500/day"}},
    "dev-assistant": {"name": "dev-assistant", "description": "Read repos, open PRs and comment — never merge or delete.",
                      "permissions": {"github": ["read", "create_pr", "comment"]}, "limits": {"create_pr": "20/day"}},
}


def list_templates() -> List[dict]:
    """The built-in role templates: conservative starting points, meant to be narrowed, not widened."""
    return list(TEMPLATES.values())


def from_template(name: str, principal: Any, goal: str, aud: Optional[str] = None, holder: Any = None, now: Optional[int] = None,
                  overrides: Optional[dict] = None) -> Any:
    """Mint an agent handle from a named template (`overrides`: ``permissions``, ``limits``, ``risk_policy``, ``agent_binding``,
    ``budget_model``). Raises on an unknown template."""
    t = TEMPLATES.get(name) if isinstance(name, str) else None
    if t is None:
        raise ValueError("fromTemplate: unknown template '%s' (have: %s)" % (name, ", ".join(TEMPLATES)))
    o = overrides or {}
    return create_agent(principal, goal, o.get("permissions") or t["permissions"], o.get("limits") or t.get("limits"), holder=holder,
                        agent_binding=o.get("agent_binding"), risk_policy=o.get("risk_policy") or t.get("riskPolicy"),
                        budget_model=o.get("budget_model"), aud=aud, now=now)


class PcaAgentError(Exception):
    """A failure of the agent client: ``code`` is one of no_plan, unknown_node, no_secret, network, bad_response, build_failed."""

    def __init__(self, code: str, message: str, http_status: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def authorize_execution(pcactn: Any, operation: Dict[str, Any], authorize: AuthorizeOptions, *, audience: Any, resolve_grant: Any = None,
                        grant: Any = None, now: Any = None) -> Dict[str, Any]:
    """The full-policy check for one local execution (an agent framework tool call, a gateway request) by a verifier that has the PCActn in
    hand: configuration, binding to the operation, then the full ``authorize`` pipeline (``authorize`` is the built :class:`AuthorizeOptions`).

    `operation` is ``{"verb", "resource"?, "params", "provenance"?}``: the PCActn's signed verb (and resource, when given) must be this
    operation, checked before any state is read or written. `grant` or `resolve_grant(grant_ref)` supplies the grant (never take it
    from the call). Returns ``{"allow": True, "pcactn", "grant", "checks", "result"}`` or ``{"allow": False, "kind", "status", "reason", "checks"?,
    "result"?}`` with kind one of config / binding / authn / policy / replay / revoked. Never raises; every failure denies."""
    from .adapters import js_string
    from .authorize import missing_authorize_components
    if grant is not None and resolve_grant is None:
        resolve_grant = lambda _ref: grant  # noqa: E731
    missing = missing_authorize_components(audience=audience, resolve_grant=resolve_grant, state_store=getattr(authorize, "state_store", None),
                                           is_revoked=getattr(authorize, "is_revoked", None),
                                           escalation_principals=getattr(authorize, "escalation_principals", None))
    if not callable(getattr(authorize, "run", None)):
        missing.append("authorize.run")
    if not isinstance(operation, dict) or not isinstance(operation.get("verb"), str):
        missing.append("operation")
    if missing:
        return {"allow": False, "kind": "config", "status": 403, "reason": "full policy mode is missing %s (fail closed)" % ", ".join(missing)}
    try:
        a = pcactn.get("action") if isinstance(pcactn, dict) else None
        a = a if isinstance(a, dict) else {}
        verb, res = a.get("verb"), a.get("resource")
        if verb != operation["verb"] or (operation.get("resource") is not None and res != operation["resource"]):
            want = operation["verb"] if operation.get("resource") is None else "%s on %s" % (operation["verb"], operation["resource"])
            return {"allow": False, "kind": "binding", "status": 403,
                    "reason": "the proof is for %s on %s, but this call is %s" % (js_string(verb), js_string(res), want)}
        g = grant if grant is not None else resolve_grant(pcactn.get("grant_ref"))
        if not g:
            return {"allow": False, "kind": "authn", "status": 401, "reason": "unknown grant_ref"}
        r = authorize.run(pcactn, operation={k: v for k, v in operation.items() if k != "provenance"}, audience=audience,
                          resolve_grant=lambda _ref: g, now=now() if callable(now) else now, provenance=operation.get("provenance"))
        checks = dict(getattr(r, "checks", None) or {})
        if r.allow:
            return {"allow": True, "pcactn": getattr(r, "pcactn", None) or pcactn, "grant": g, "checks": checks, "result": r}
        if getattr(r, "missing", None):
            kind = "config"
        elif r.status == 401:
            kind = "authn"
        elif checks.get("revocation") == "fail":
            kind = "revoked"
        elif checks.get("replay") == "fail":
            kind = "replay"
        else:
            kind = "policy"
        return {"allow": False, "kind": kind, "status": r.status, "reason": r.reason or "denied", "checks": checks, "result": r}
    except Exception as e:  # noqa: BLE001 - fail closed
        return {"allow": False, "kind": "policy", "status": 403, "reason": "authorization error (fail closed): %s" % type(e).__name__}


class PolicyBuilder:
    """A chainable policy builder: ``policy().allow("stripe", ["refund"]).limit("refund", "$500/day").build()``."""

    def __init__(self) -> None:
        self._perms: Dict[str, List[str]] = {}
        self._lims: Dict[str, str] = {}
        self._risk: Optional[dict] = None

    @classmethod
    def from_template(cls, name: str) -> "PolicyBuilder":
        """Start from a named template (its permissions, limits and risk seed the builder)."""
        t = TEMPLATES.get(name) if isinstance(name, str) else None
        if t is None:
            raise ValueError("PolicyBuilder.from: unknown template '%s'" % (name,))
        b = cls()
        for c, acts in t["permissions"].items():
            b.allow(c, acts)
        for k, v in (t.get("limits") or {}).items():
            b.limit(k, v)
        if t.get("riskPolicy"):
            b.risk(t["riskPolicy"])
        return b

    def allow(self, connector: str, actions: Sequence[str]) -> "PolicyBuilder":
        cur = self._perms.get(connector, [])
        self._perms[connector] = list(dict.fromkeys([*cur, *actions]))
        return self

    def limit(self, verb_or_action: str, spec: str) -> "PolicyBuilder":
        self._lims[verb_or_action] = spec
        return self

    def risk(self, partial: dict) -> "PolicyBuilder":
        self._risk = {**(self._risk or {}), **partial}
        return self

    def build(self) -> Dict[str, Any]:
        if not self._perms:
            raise ValueError("PolicyBuilder: no permissions added")
        out: Dict[str, Any] = {"permissions": copy.deepcopy(self._perms), "limits": dict(self._lims)}
        if self._risk:
            out["riskPolicy"] = dict(self._risk)
        return out

    def agent(self, principal: Any, goal: str, aud: Optional[str] = None, holder: Any = None, now: Optional[int] = None) -> Any:
        """Mint an agent directly from the built policy."""
        b = self.build()
        return create_agent(principal, goal, b["permissions"], b["limits"], holder=holder, risk_policy=b.get("riskPolicy"), aud=aud, now=now)


def policy() -> PolicyBuilder:
    """Entry point for the fluent builder."""
    return PolicyBuilder()
