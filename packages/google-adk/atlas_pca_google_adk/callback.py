"""``pca_before_tool_callback`` — gate *every* tool on a Google ADK agent in one line.

ADK's ``LlmAgent`` takes a ``before_tool_callback(tool, args, tool_context)`` hook that runs before any
tool executes; returning a ``dict`` short-circuits the tool and hands that dict back to the model as
the tool result, while returning ``None`` lets the tool run. :func:`pca_before_tool_callback` builds
such a hook that verifies a proof-carrying action for each call and fails closed:

* no proof, or an undecodable one                        -> deny (the tool never runs)
* a proof that does not verify under the core verifier   -> deny (bad signature / chain / validity /
  wrong audience / unknown grant / replay counter)
* a valid proof whose authorized action does not satisfy the tool's required capability -> deny
* otherwise                                              -> allow (return ``None``, the tool runs)

The proof is read per the ``PCA-Action`` convention: the inline ``pca_action`` key in ``args`` (which
is removed before the tool runs), else the ``PCA-Action`` key in the ``tool_context`` session state,
else the context var. ``audience`` is this agent's RFC 8707 resource identifier, so a proof minted for
another resource server is rejected.

``require`` selects each tool's required capability:

* a ``"verb:resource"`` string applied to every tool;
* a mapping ``{tool_name: "verb:resource"}`` — a tool absent from the map needs only a *valid* proof
  (resource-server-correct), with no specific capability; or
* a callable ``(tool) -> "verb:resource" | None`` — ``None`` likewise means "valid proof, no capability".

Every tool is gated (a valid proof is always required); ``require`` only decides the *capability*.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional, Union

from ._proof import PCA_ARG, PCA_STATE_KEY, coerce_pcactn, current_proof, proof_from_tool_context
from .tool import PcaToolDenied
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: How each tool's required capability is chosen. See the module docstring.
RequireSpec = Union[str, Mapping[str, str], Callable[[Any], Optional[str]]]

#: An ADK ``before_tool_callback``: ``(tool, args, tool_context) -> dict | None``. A dict denies
#: (becomes the tool result); ``None`` allows the tool to run.
BeforeToolCallback = Callable[[Any, Dict[str, Any], Any], Optional[Dict[str, Any]]]


def _tool_name(tool: Any) -> Optional[str]:
    name = getattr(tool, "name", None) or getattr(tool, "__name__", None)
    return str(name) if name is not None else None


def _require_for(tool: Any, require: RequireSpec) -> Optional[str]:
    if callable(require) and not isinstance(require, Mapping):
        return require(tool)
    if isinstance(require, Mapping):
        name = _tool_name(tool)
        return require.get(name) if name is not None else None
    return require


def _split_require(spec: Optional[str]) -> "tuple[Optional[str], Optional[str]]":
    if spec is None:
        return None, None
    if not isinstance(spec, str) or ":" not in spec:
        raise ValueError("require entry must be a 'verb:resource' string, got %r" % (spec,))
    verb, resource = spec.split(":", 1)
    if not verb or not resource:
        raise ValueError("require entry must be a non-empty 'verb:resource' string, got %r" % (spec,))
    return verb, resource


def _deny_result(decision: ToolDecision) -> Dict[str, Any]:
    """The tool-result dict ADK hands back to the model when a call is denied."""
    return {
        "error": decision.reason or "proof-carrying authority required",
        "pca": {"allowed": False, "required": decision.required},
    }


def _read_proof(args: Optional[Dict[str, Any]], tool_context: Any, *, arg_name: str,
                state_key: str) -> Optional[Dict[str, Any]]:
    """Resolve the proof for one call and strip the inline key from ``args`` so the tool never sees it."""
    inline = None
    if isinstance(args, dict) and arg_name in args:
        inline = args.pop(arg_name)
    if inline is not None:
        return coerce_pcactn(inline)
    from_state = proof_from_tool_context(tool_context, state_key=state_key)
    if from_state is not None:
        return coerce_pcactn(from_state)
    return coerce_pcactn(current_proof())


def pca_before_tool_callback(*, audience: str, require: RequireSpec,
                             resolve_grant: Optional[GrantResolver] = None,
                             verifier: Optional[Verifier] = None, now: Optional[int] = None,
                             raise_on_deny: bool = False, arg_name: str = PCA_ARG,
                             state_key: str = PCA_STATE_KEY) -> BeforeToolCallback:
    """Build an ADK ``before_tool_callback`` that gates every tool on an agent with PCA.

    ``audience``       — this agent's RFC 8707 resource id; a proof for another audience is rejected.
    ``require``        — a :data:`RequireSpec` choosing each tool's capability (see the module docstring).
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required unless ``verifier`` is supplied.
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``now``            — epoch-ms validity clock (default: wall clock); used only for the default verifier.
    ``raise_on_deny``  — raise :class:`PcaToolDenied` instead of returning a deny result dict.
    ``arg_name``       — the inline proof key in ``args`` (default ``"pca_action"``), stripped before the tool runs.
    ``state_key``      — the ``tool_context`` session-state key the proof travels under (default ``"PCA-Action"``).

    Wire it in one line::

        from atlas_pca_google_adk import pca_before_tool_callback

        agent = LlmAgent(
            ...,
            before_tool_callback=pca_before_tool_callback(
                audience="rs-orders",
                require={"place_order": "write:db/orders"},
                resolve_grant=resolve,
            ),
        )
    """
    if not audience:
        raise ValueError("pca_before_tool_callback requires a non-empty `audience`")
    if verifier is None:
        if resolve_grant is None:
            raise ValueError("pca_before_tool_callback requires either `verifier=` or `resolve_grant=`")
        verifier = CoreVerifier(resolve_grant, now=now)
    elif resolve_grant is not None:
        raise ValueError("pass either `verifier=` or `resolve_grant=`, not both")
    the_verifier: Verifier = verifier

    def before_tool_callback(tool: Any, args: Dict[str, Any],
                             tool_context: Any = None) -> Optional[Dict[str, Any]]:
        verb, resource = _split_require(_require_for(tool, require))
        pcactn = _read_proof(args, tool_context, arg_name=arg_name, state_key=state_key)
        decision = the_verifier.verify(pcactn, verb=verb, resource=resource, audience=audience)
        if decision.ok:
            return None  # proceed: ADK runs the tool
        if raise_on_deny:
            raise PcaToolDenied(decision)
        return _deny_result(decision)

    return before_tool_callback
