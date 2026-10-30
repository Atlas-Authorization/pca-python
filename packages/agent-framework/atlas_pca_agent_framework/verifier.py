"""Turn a carried proof + a tool's required capability into an allow/deny decision.

This sits ON TOP of ``atlas_pca.verify_pcactn_core`` (the eight offline CORE checks: wire, version,
audience, validity, chain, plan_inclusion, leaf_signature, counter_format). No crypto lives here. It adds the
two things a Microsoft Agent Framework tool guard needs beyond the core checks:

* **resource-server correctness** — the proof's signed ``aud`` must equal this guard's ``audience``
  (RFC 8707 resource). A proof minted for another resource server is rejected; the core check enforces
  this when ``audience`` is passed, and omitting ``audience`` fails closed.
* **capability sufficiency** — the proof's committed ``action`` (``verb``/``resource``) must match what
  the tool declares it requires. A perfectly valid proof for ``read:db/orders`` does not authorize a
  tool that requires ``write:db/orders``. Passing ``verb``/``resource`` as ``None`` skips this check —
  the proof then needs only to be valid for this audience (used by the function-invocation middleware
  for tools that carry no explicit capability requirement).

Every failure is fail-closed: a missing proof, an unknown grant, any failed core check, or an
insufficient capability all deny.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol

from atlas_pca.pca import Verdict, verify_pcactn_core

from ._proof import coerce_pcactn, current_provenance

#: ``(grant_ref) -> grant | None`` — resolves the PCActn's ``grant_ref`` to its root grant object.
GrantResolver = Callable[[Optional[str]], Optional[Dict[str, Any]]]


def _capability(verb: Optional[str], resource: Optional[str]) -> Optional[str]:
    """``"verb:resource"`` when both are given, else ``None`` (no specific capability required)."""
    if verb is None and resource is None:
        return None
    return "%s:%s" % (verb, resource)


@dataclass
class ToolDecision:
    """Outcome of guarding one tool call. ``ok`` is the one thing a caller must branch on.

    Mirrors ``atlas_pca.server.PCAResult`` in spirit: ``ok`` + ``reason`` + the underlying ``verdict``
    (present whenever the core verifier ran) + the verified ``pcactn``. Dict-style access is provided
    so callers may treat it as ``{"ok": ..., "reason": ...}``.
    """

    ok: bool
    reason: Optional[str] = None
    verdict: Optional[Verdict] = None
    pcactn: Optional[Dict[str, Any]] = None
    required: Optional[str] = None
    #: the full ``atlas_pca.AuthorizeResult`` when an :class:`AuthorizeVerifier` decided (checks, bound operation)
    authorization: Any = None

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class Verifier(Protocol):
    """What the Agent Framework guards call to decide a tool invocation.

    A custom verifier (e.g. one that also checks a revocation list or a replay cache) implements this
    one method; :class:`CoreVerifier` is the default, offline, crypto-complete implementation. ``verb``
    and ``resource`` are ``None`` when the caller requires only a valid proof (no capability gate).
    """

    def verify(self, pcactn: Optional[Dict[str, Any]], *, verb: Optional[str], resource: Optional[str],
               audience: str) -> ToolDecision:
        ...


class CoreVerifier:
    """Default verifier: the reference CORE checks plus resource-server + capability gating.

    ``resolve_grant`` maps a PCActn's ``grant_ref`` to its root grant; ``now`` fixes the clock for the
    validity window (epoch milliseconds, default wall-clock at check time, as in the reference verifier).
    """

    def __init__(self, resolve_grant: GrantResolver, *, now: Optional[int] = None) -> None:
        self._resolve_grant = resolve_grant
        self._now = now

    def verify(self, pcactn: Optional[Dict[str, Any]], *, verb: Optional[str], resource: Optional[str],
               audience: str) -> ToolDecision:
        required = _capability(verb, resource)
        if pcactn is None:
            return ToolDecision(ok=False, reason="no proof-carrying action presented", required=required)

        grant_ref = pcactn.get("grant_ref") if isinstance(pcactn, dict) else None
        grant = self._resolve_grant(grant_ref)
        if not isinstance(grant, dict):
            return ToolDecision(ok=False, pcactn=pcactn, required=required,
                                reason="grant_ref does not resolve to a known grant")

        # The eight CORE checks. Passing `audience` makes the proof resource-server-correct: a proof
        # whose signed `aud` is not this guard's audience fails the `audience` check (and omitting it
        # fails closed inside the reference verifier).
        verdict = verify_pcactn_core(pcactn, grant, now=self._now, audience=audience)
        if not verdict.allow:
            return ToolDecision(ok=False, verdict=verdict, pcactn=pcactn, required=required,
                                reason=verdict.reason or "proof-carrying authority is insufficient")

        # Capability sufficiency: the committed action must be exactly what this tool requires. Skipped
        # when no capability was requested (verb/resource both None) — a valid proof then suffices.
        if required is not None:
            action = pcactn.get("action")
            action = action if isinstance(action, dict) else {}
            got = "%s:%s" % (action.get("verb"), action.get("resource"))
            if action.get("verb") != verb or action.get("resource") != resource:
                return ToolDecision(
                    ok=False, verdict=verdict, pcactn=pcactn, required=required,
                    reason="insufficient capability: proof authorizes %s, tool requires %s" % (got, required),
                )

        return ToolDecision(ok=True, verdict=verdict, pcactn=pcactn, required=required)


class AuthorizeVerifier:
    """Opt-in full pipeline (0.5): each tool call goes through ``atlas_pca.authorize``.

    The operation is the capability the tool requires (``verb``/``resource``) with the tool-call arguments as its
    params, so the proof must be for exactly this call. On top of the core checks it enforces the grant's envelope
    predicates, root and delegated caveats (``max_spend``, ``predicates``, ``tool_schema``, ...), revocation
    (``options.is_revoked``) and the replay counter (``options.state_store``, consumed only when everything else
    passes). A missing component, a tool without a capability or arguments that cannot be bound deny. ``options`` is an
    ``atlas_pca.AuthorizeOptions`` or a dict of its fields.
    """

    #: the guard passes the tool-call arguments as ``params=`` to a verifier that sets this
    binds_params = True

    def __init__(self, resolve_grant: GrantResolver, options: Any, *, now: Optional[int] = None,
                 provenance: Optional[Callable[[Dict[str, Any]], Any]] = None, recorder: Any = None) -> None:
        from atlas_pca.authorize import AuthorizeOptions  # atlas-pca 0.5+

        self._options = AuthorizeOptions(**dict(options)) if isinstance(options, dict) else options
        self._resolve_grant = resolve_grant
        self._now = now
        self._provenance = provenance
        #: the agent session's ``atlas_pca.ProvenanceRecorder`` (or None): it builds the bundle for a call that presents none,
        #: and the guards record each allowed tool's result in it as UNTRUSTED tool output
        self.recorder = recorder

    def bundle(self, verb: Optional[str], resource: Optional[str], params: Optional[Dict[str, Any]]) -> Any:
        """The provenance bundle for this call (provenance by default): ``provenance(operation)`` when configured, else the
        bundle bound with :func:`pca_context`, else ``recorder.for_action(operation)``. None = unlabelled: a sensitive call
        then escalates."""
        if not isinstance(verb, str) or not isinstance(resource, str) or params is None:
            return None  # no bindable operation: authorize_tool_call refuses the call before the gate
        op = {"verb": verb, "resource": resource, "params": dict(params)}
        raw = self._provenance(op) if self._provenance is not None else current_provenance()
        if raw is not None:
            return coerce_pcactn(raw)  # a bundle travels in a proof's encodings (object, JSON, base64url JSON)
        return self.recorder.for_action(op) if self.recorder is not None else None

    def verify(self, pcactn: Optional[Dict[str, Any]], *, verb: Optional[str], resource: Optional[str],
               audience: str, params: Optional[Dict[str, Any]] = None) -> ToolDecision:
        from atlas_pca.authorize import authorize_tool_call

        required = _capability(verb, resource)
        if pcactn is None:
            return ToolDecision(ok=False, reason="no proof-carrying action presented", required=required)
        try:
            bundle = self.bundle(verb, resource, params)
        except Exception:  # noqa: BLE001  (fail closed: a bundle source or recorder that fails never lets the call through)
            return ToolDecision(ok=False, pcactn=pcactn, required=required,
                                reason="provenance_flow: the provenance bundle could not be read or recorded (fail closed)")
        r = authorize_tool_call(self._options, pcactn, verb=verb, resource=resource, params=params,
                                audience=audience, resolve_grant=self._resolve_grant, now=self._now, provenance=bundle)
        return ToolDecision(ok=r.allow, reason=None if r.allow else r.reason, verdict=r.verdict, pcactn=pcactn,
                            required=required, authorization=r)


def verify_call(verifier: Any, pcactn: Optional[Dict[str, Any]], *, verb: Optional[str], resource: Optional[str],
                audience: str, params: Optional[Dict[str, Any]]) -> ToolDecision:
    """Call ``verifier.verify``, handing it the tool-call arguments only when it binds them (``binds_params``)."""
    if getattr(verifier, "binds_params", False):
        return verifier.verify(pcactn, verb=verb, resource=resource, audience=audience, params=params)
    return verifier.verify(pcactn, verb=verb, resource=resource, audience=audience)


def record_output(verifier: Any, source: Optional[str], output: Any) -> None:
    """Provenance by default: record an allowed tool's result in the verifier's recorder (when it has one) as UNTRUSTED tool
    output, so a later sensitive call whose choice or arguments come from it escalates."""
    rec = getattr(verifier, "recorder", None)
    if rec is not None:
        rec.tool(source or "tool", output)
