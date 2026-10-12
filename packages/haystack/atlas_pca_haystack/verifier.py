"""Turn a carried proof + a tool's required capability into an allow/deny decision.

This sits ON TOP of ``atlas_pca.verify_pcactn_core`` (the eight offline CORE checks: wire, version,
audience, validity, chain, plan_inclusion, leaf_signature, counter). No crypto lives here. It adds the
two things a tool guard needs beyond the core checks:

* **resource-server correctness** — the proof's signed ``aud`` must equal this guard's ``audience``
  (RFC 8707 resource). A proof minted for another resource server is rejected; the core check enforces
  this when ``audience`` is passed, and omitting ``audience`` fails closed.
* **capability sufficiency** — the proof's committed ``action`` (``verb``/``resource``) must match what
  the tool declares it requires. A perfectly valid proof for ``read:db/orders`` does not authorize a
  tool that requires ``write:db/orders``.

Every failure is fail-closed: a missing proof, an unknown grant, any failed core check, or an
insufficient capability all deny.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol

from atlas_pca.pca import Verdict, verify_pcactn_core

#: ``(grant_ref) -> grant | None`` — resolves the PCActn's ``grant_ref`` to its root grant object.
GrantResolver = Callable[[Optional[str]], Optional[Dict[str, Any]]]


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

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class Verifier(Protocol):
    """What :func:`atlas_pca_haystack.pca_tool` calls to decide a tool invocation.

    A custom verifier (e.g. one that also checks a revocation list or a replay cache) implements this
    one method; :class:`CoreVerifier` is the default, offline, crypto-complete implementation.
    """

    def verify(self, pcactn: Optional[Dict[str, Any]], *, verb: str, resource: str,
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

    def verify(self, pcactn: Optional[Dict[str, Any]], *, verb: str, resource: str,
               audience: str) -> ToolDecision:
        required = "%s:%s" % (verb, resource)
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

        # Capability sufficiency: the committed action must be exactly what this tool requires.
        action = pcactn.get("action")
        action = action if isinstance(action, dict) else {}
        got = "%s:%s" % (action.get("verb"), action.get("resource"))
        if action.get("verb") != verb or action.get("resource") != resource:
            return ToolDecision(
                ok=False, verdict=verdict, pcactn=pcactn, required=required,
                reason="insufficient capability: proof authorizes %s, tool requires %s" % (got, required),
            )

        return ToolDecision(ok=True, verdict=verdict, pcactn=pcactn, required=required)
