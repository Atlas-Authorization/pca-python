"""``pca_guard_node`` — a graph node that verifies the pending tool call and steps up a risky one.

Place this node *before* the tool node on a risky path. It reads the pending tool call(s) off the last
message, verifies a proof-carrying action for each, and:

* **all pass** -> returns a routing marker ``{route_key: {"ok": True, ...}}`` and the (verified) proof
  under the state key, so a conditional edge sends the graph on to the tool node; or
* **any fails** (missing / invalid / wrong-audience / insufficient-capability proof) -> maps to a
  **step-up**: when ``langgraph`` is installed it calls ``langgraph.types.interrupt(payload)`` to pause
  the graph for human-in-the-loop approval — the PCA analogue of a FROST threshold co-sign or a CIBA
  out-of-band approval. The host collects a *stepped-up* proof-carrying action (one carrying the extra
  threshold/approval evidence) and resumes the graph with it (``Command(resume=<proof>)``); the node
  re-verifies that proof and either passes or stays denied. When ``langgraph`` is **not** installed the
  node cannot pause, so it instead returns ``{route_key: {"ok": False, "stepup": True, ...}}`` and a
  conditional edge (see :func:`pca_route`) routes to a step-up subgraph.

Fail-closed throughout: an unverifiable action never routes to the tool node.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from ._proof import (
    PCA_CONFIG_KEY,
    PCA_STATE_KEY,
    ProofInput,
    coerce_pcactn,
    resolve_proof,
)
from .node import _tool_calls_of, _ToolCall
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: How each pending tool call's required capability is chosen. A callable is passed the tool *name*.
RequireSpec = Union[str, Mapping[str, str], Callable[[Optional[str]], Optional[str]]]

#: A LangGraph node: ``(state[, config]) -> state-update dict``.
GuardNode = Callable[..., Dict[str, Any]]

DEFAULT_MESSAGES_KEY = "messages"
DEFAULT_ROUTE_KEY = "pca"

#: Routing labels a conditional edge maps to.
ROUTE_APPROVED = "approved"
ROUTE_STEPUP = "stepup"

_NO_INTERRUPT: Any = object()


def _require_for(name: Optional[str], require: RequireSpec) -> Optional[str]:
    if callable(require) and not isinstance(require, Mapping):
        return require(name)
    if isinstance(require, Mapping):
        return require.get(name) if name is not None else None
    return require


def _split_require(spec: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if spec is None:
        return None, None
    if not isinstance(spec, str) or ":" not in spec:
        raise ValueError("require entry must be a 'verb:resource' string, got %r" % (spec,))
    verb, resource = spec.split(":", 1)
    if not verb or not resource:
        raise ValueError("require entry must be a non-empty 'verb:resource' string, got %r" % (spec,))
    return verb, resource


def _try_interrupt(payload: Dict[str, Any]) -> Any:
    """``langgraph.types.interrupt(payload)`` when LangGraph is installed, else :data:`_NO_INTERRUPT`.

    When present, ``interrupt`` pauses the graph and (on resume) returns the host-supplied resume value;
    when absent there is nothing to pause, so the caller falls back to edge-based routing.
    """
    try:
        from langgraph.types import interrupt
    except Exception:
        return _NO_INTERRUPT
    return interrupt(payload)


def _resume_proof(resumed: Any) -> ProofInput:
    """The stepped-up proof out of a resume value: the value itself, or its ``pca_action`` field."""
    if isinstance(resumed, Mapping):
        for key in ("pca_action", "pcactn", PCA_STATE_KEY):
            if key in resumed:
                return resumed[key]
        # No wrapper key: a bare PCActn object resumed directly is itself the stepped-up proof.
        return dict(resumed)
    return resumed


def _verify_all(verifier: Verifier, proof: Optional[Dict[str, Any]], calls: List[_ToolCall],
                require: RequireSpec, audience: str) -> List[Tuple[_ToolCall, ToolDecision]]:
    """Verify ``proof`` against every pending call; return the ``(call, decision)`` pairs that denied."""
    denials: List[Tuple[_ToolCall, ToolDecision]] = []
    for call in calls:
        verb, resource = _split_require(_require_for(call.name, require))
        decision = verifier.verify(proof, verb=verb, resource=resource, audience=audience)
        if not decision.ok:
            denials.append((call, decision))
    return denials


def _stepup_payload(audience: str, denials: List[Tuple[_ToolCall, ToolDecision]],
                    prompt: Optional[str]) -> Dict[str, Any]:
    first = denials[0][1]
    return {
        "type": "pca_step_up",
        "audience": audience,
        "reason": first.reason,
        "required": first.required,
        "actions": [{"tool": c.name, "id": c.id, "required": d.required, "reason": d.reason}
                    for c, d in denials],
        "prompt": prompt or "A proof-carrying action with step-up (FROST threshold / CIBA approval) is "
                            "required to run this risky step.",
    }


def pca_guard_node(*, audience: str, require: RequireSpec,
                   resolve_grant: Optional[GrantResolver] = None, verifier: Optional[Verifier] = None,
                   now: Optional[int] = None, messages_key: str = DEFAULT_MESSAGES_KEY,
                   route_key: str = DEFAULT_ROUTE_KEY, state_key: str = PCA_STATE_KEY,
                   config_key: str = PCA_CONFIG_KEY, stepup_prompt: Optional[str] = None) -> GuardNode:
    """Build a LangGraph node that proof-checks the pending tool call and steps up a risky one.

    ``audience``       — this node's RFC 8707 resource id; a proof for another audience is rejected.
    ``require``        — a :data:`RequireSpec` choosing each pending call's capability (callable gets the tool *name*).
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required unless ``verifier`` is supplied.
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``now``            — epoch-ms validity clock (default: wall clock); used only for the default verifier.
    ``route_key``      — the state key the routing marker is written under (read by :func:`pca_route`).
    ``stepup_prompt``  — the human-facing prompt carried in the ``interrupt`` payload.

    The returned node takes ``(state[, config])`` and returns a state update. Wire it with a conditional
    edge::

        graph.add_node("pca", pca_guard_node(audience="rs-orders", require="write:db/orders",
                                             resolve_grant=resolve))
        graph.add_conditional_edges("pca", pca_route, {"approved": "tools", "stepup": "human_review"})
    """
    if not audience:
        raise ValueError("pca_guard_node requires a non-empty `audience`")
    if verifier is None:
        if resolve_grant is None:
            raise ValueError("pca_guard_node requires either `verifier=` or `resolve_grant=`")
        verifier = CoreVerifier(resolve_grant, now=now)
    elif resolve_grant is not None:
        raise ValueError("pass either `verifier=` or `resolve_grant=`, not both")
    the_verifier: Verifier = verifier

    def node(state: Any, config: Any = None) -> Dict[str, Any]:
        proof = resolve_proof(state=state, config=config, state_key=state_key, config_key=config_key)
        calls = _tool_calls_of(state, messages_key)
        denials = _verify_all(the_verifier, proof, calls, require, audience)
        if not denials:
            update: Dict[str, Any] = {route_key: {"ok": True, "stepup": False, "reason": None}}
            if proof is not None:
                update[state_key] = proof
            return update

        # Risky / insufficient: step up. When LangGraph is present, pause for human-in-the-loop
        # approval (FROST/CIBA); otherwise expose the decision so a conditional edge routes to step-up.
        resumed = _try_interrupt(_stepup_payload(audience, denials, stepup_prompt))
        if resumed is _NO_INTERRUPT:
            first = denials[0][1]
            return {route_key: {"ok": False, "stepup": True, "reason": first.reason,
                                "required": first.required,
                                "pending": [c.name for c, _ in denials]}}

        # Resumed with a stepped-up proof: re-verify every pending call against it (fail-closed).
        stepped = coerce_pcactn(_resume_proof(resumed))
        redenials = _verify_all(the_verifier, stepped, calls, require, audience)
        if redenials:
            first = redenials[0][1]
            return {route_key: {"ok": False, "stepup": True, "reason": first.reason,
                                "required": first.required,
                                "pending": [c.name for c, _ in redenials]}}
        update = {route_key: {"ok": True, "stepup": True, "reason": None}}
        if stepped is not None:
            update[state_key] = stepped
        return update

    _annotate_config(node)
    return node


def _annotate_config(node: GuardNode) -> None:
    """Type the node's ``config`` parameter as ``RunnableConfig`` when LangGraph is installed, so the
    framework injects the run config without warning about an untyped parameter."""
    try:
        from langchain_core.runnables import RunnableConfig
    except Exception:
        return
    node.__annotations__["config"] = RunnableConfig


def pca_route(state: Any, *, route_key: str = DEFAULT_ROUTE_KEY, approved: str = ROUTE_APPROVED,
              stepup: str = ROUTE_STEPUP) -> str:
    """Conditional-edge selector reading :func:`pca_guard_node`'s marker: ``approved`` or ``stepup``.

    Fail-closed: anything other than an explicit ``ok == True`` routes to ``stepup``.
    """
    if isinstance(state, Mapping):
        marker = state.get(route_key)
    else:
        marker = getattr(state, route_key, None)
    if isinstance(marker, Mapping) and marker.get("ok") is True:
        return approved
    return stepup
