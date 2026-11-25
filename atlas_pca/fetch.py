"""Runtime-neutral request guard for Proof-Carrying Authority, shaped like the Web Fetch guard of the TypeScript reference
(@atlasauth/pca-fetch): wrap a handler so the inbound PCActn is verified first; on success the handler runs with the verdict
and PCActn, otherwise a 401 / 403 response dict with a WWW-Authenticate challenge is returned. It adds no verification of its
own: it joins :func:`atlas_pca.server.require_pca` (default-deny, the full ``authorize`` pipeline unless ``signature_only``)
to a request-like dict ``{"method", "url"?, "headers", "body"?}`` and a response dict ``{"status", "headers", "body"}``.

The agent-side signed fetch is :meth:`atlas_pca.agent.Agent.fetch`.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional

from .sdjwt_jws import js_json
from .server import PCAResult, require_pca

PcaFetchHandler = Callable[[Mapping[str, Any], Dict[str, Any]], Any]


def _guard(options: Dict[str, Any]) -> Callable[[Mapping[str, Any]], PCAResult]:
    if not options.get("audience"):
        raise TypeError("pca-fetch: `audience` (this resource server's id) is required")
    # 0.5: a proof must be bound to the operation the request will execute (or use `authorize`); the unbound form is an explicit opt-in
    unbound = options.pop("insecure_allow_unbound_operation", False) is True
    if options.get("operation") is None and options.get("authorize") is None and not unbound and options.get("signature_only") is not True:
        raise TypeError("pca-fetch: `operation` is required (0.5): map each request to the operation it will execute so the proof is bound "
                        "to it, or use `authorize`; set insecure_allow_unbound_operation only to migrate")
    if unbound and options.get("operation") is None:
        options.setdefault("signature_only", True)
    guard = require_pca(**options)

    def run(req: Mapping[str, Any]) -> PCAResult:
        return guard(req.get("headers") or {}, req.get("body"))

    return run


def create_pca_fetch_guard(**options: Any) -> Callable[[Mapping[str, Any]], PCAResult]:
    """A verifier over a request-like dict returning the full guard result, so you can compose it yourself. Raises TypeError
    when the configuration is unsafe (no audience, no operation mapping)."""
    return _guard(options)


def deny_response(result: PCAResult, deny_body: Optional[Callable[[PCAResult], Any]] = None) -> Dict[str, Any]:
    """The 401 / 403 response for a refusal: JSON body ``{error, verdict, decision, escalation?}`` (or ``deny_body(result)``),
    ``content-type: application/json`` and the ``WWW-Authenticate`` challenge."""
    if deny_body is not None:
        body = deny_body(result)
    else:
        az = result.authorization
        v = result.verdict
        if az is not None:
            verdict: Dict[str, Any] = {"allow": False, "checks": dict(az.checks or {}), "reasons": list(az.reasons or [])}
        elif v is not None:
            verdict = {"allow": bool(v.allow), "checks": dict(v.checks), "reasons": list(v.reasons) or ([v.reason] if v.reason else [])}
        else:
            verdict = {"allow": False, "checks": {}, "reasons": [result.error] if result.error else []}
        body = {"error": verdict["reasons"][0] if verdict["reasons"] else "forbidden", "verdict": verdict,
                "decision": result.decision or "deny"}
        if result.escalation:
            body["escalation"] = result.escalation
    headers = {"content-type": "application/json"}
    if result.www_authenticate:
        headers["WWW-Authenticate"] = result.www_authenticate
    return {"status": result.status, "headers": headers, "body": js_json(body)}


def with_pca(handler: PcaFetchHandler, deny_body: Optional[Callable[[PCAResult], Any]] = None, **options: Any) -> Callable[[Mapping[str, Any]], Any]:
    """Wrap `handler(request, {"pca": {"verdict", "pcactn", "operation"?}})` so the inbound PCActn is verified first.
    `options` are the keyword arguments of :func:`atlas_pca.server.require_pca` (``audience``, ``resolve_grant``, ``operation``,
    ``authorize``, ``signature_only``, ...) plus ``insecure_allow_unbound_operation``."""
    guard = _guard(options)

    def wrapped(req: Mapping[str, Any]) -> Any:
        result = guard(req)
        if result.ok:
            pca: Dict[str, Any] = {"verdict": result.verdict, "pcactn": result.pcactn}
            if result.authorization is not None and result.authorization.operation is not None:
                pca["operation"] = result.authorization.operation
            return handler(req, {"pca": pca})
        return deny_response(result, deny_body)

    return wrapped
