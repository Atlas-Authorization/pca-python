"""``pca_tool`` — wrap a single Google ADK tool so every call is proof-carrying and policy-gated.

``pca_tool(require="verb:resource", audience=..., resolve_grant=...)`` returns a decorator over an ADK
``FunctionTool`` (or the plain callable behind one). Before the underlying function fires, it resolves
the carried proof (the inline ``pca_action`` call argument, else the ``PCA-Action`` key in the ADK
``tool_context`` session state, else the context var from :mod:`atlas_pca_google_adk._proof`), verifies
it with the reference verifier for this tool's required capability and this resource server's audience,
and only then runs the tool. A denial raises :class:`PcaToolDenied` — ADK catches an exception raised
inside a tool and routes it back to the model as the tool's (error) result — and the underlying tool
never executes.

The wrapper is **duck-typed**: it accepts a ``google.adk.tools.FunctionTool`` / ``BaseTool`` instance
or a plain callable, and it does not import ``google.adk`` at module load. When ``google.adk`` *is*
installed, :func:`pca_tool` returns a real ``FunctionTool`` (built from a guarded function whose
signature mirrors the original, so ADK still injects ``tool_context`` and builds the right function
declaration); otherwise it returns a structurally-identical :class:`GuardedTool` so tests (and
non-ADK callers) need nothing installed.
"""
from __future__ import annotations

import functools
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from ._proof import (
    PCA_ARG,
    PCA_STATE_KEY,
    ProofInput,
    coerce_pcactn,
    current_proof,
    proof_from_tool_context,
)
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: A tool's work function, or a guarded wrapper over it. Tool I/O is arbitrary by nature.
ToolFn = Callable[..., Any]

_UNSET = object()


class PcaToolDenied(RuntimeError):
    """Raised in place of running a tool when the proof is missing, invalid, or insufficient.

    Carries the full :class:`ToolDecision` on ``.decision`` so a caller (or an ADK error handler) can
    inspect ``reason`` / ``verdict`` / ``required`` while still getting a plain string message. ADK
    surfaces an exception raised inside a tool back to the model as the tool's error result.
    """

    def __init__(self, decision: ToolDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason or "proof-carrying authority required")


@dataclass
class _Meta:
    name: str
    description: str
    inner: ToolFn
    forward_tool_context: bool


def _parse_require(require: str) -> Tuple[str, str]:
    if not isinstance(require, str) or ":" not in require:
        raise ValueError("require must be a 'verb:resource' string, got %r" % (require,))
    verb, resource = require.split(":", 1)
    if not verb or not resource:
        raise ValueError("require must be a non-empty 'verb:resource' string, got %r" % (require,))
    return verb, resource


def _accepts_tool_context(func: ToolFn) -> bool:
    """Whether ``func`` wants an ADK ``tool_context`` (a named param or ``**kwargs``)."""
    try:
        params = inspect.signature(func).parameters.values()
    except (TypeError, ValueError):
        return False
    for p in params:
        if p.name == "tool_context" and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY):
            return True
        if p.kind is p.VAR_KEYWORD:
            return True
    return False


def _meta_of(target: Any) -> _Meta:
    """Resolve the work function and display metadata from an ADK ``FunctionTool`` / ``BaseTool``
    instance or a plain callable — structurally, without importing ``google.adk``."""
    func = getattr(target, "func", None)
    if callable(func):
        inner: ToolFn = func
    elif callable(target):
        inner = target
    else:
        raise TypeError("pca_tool expected an ADK FunctionTool or a callable, got %r" % (target,))

    name = getattr(target, "name", None) or getattr(inner, "__name__", None) or "pca_guarded_tool"
    description = getattr(target, "description", None) or (getattr(inner, "__doc__", None) or "")
    return _Meta(name=str(name), description=str(description), inner=inner,
                 forward_tool_context=_accepts_tool_context(inner))


def _resolve_proof(inline: ProofInput, tool_context: Any) -> Optional[Dict[str, Any]]:
    """The proof for this call: an explicit inline ``pca_action`` wins, else the ``tool_context``
    session state, else the context var. Normalized through the strict profile; ``None`` fails closed.
    """
    if inline is not None:
        return coerce_pcactn(inline)
    from_state = proof_from_tool_context(tool_context)
    if from_state is not None:
        return coerce_pcactn(from_state)
    return coerce_pcactn(current_proof())


class GuardedTool:
    """A duck-typed ADK tool: ``name`` / ``description`` / ``func`` plus ADK's ``run_async`` entry.

    Returned by :func:`pca_tool` when ``google.adk`` is not importable. It exposes the surface ADK
    calls (``async run_async(*, args, tool_context)`` dispatching to the guarded function), and is also
    directly callable / has a sync ``run`` for convenience, so the guard is fully exercisable without
    the framework installed.
    """

    def __init__(self, *, name: str, description: str, guarded: ToolFn, required: str,
                 is_long_running: bool = False) -> None:
        self.name = name
        self.description = description
        self.func = guarded
        self.pca_required = required
        self.is_long_running = is_long_running
        self._guarded = guarded

    async def run_async(self, *, args: Optional[Dict[str, Any]] = None, tool_context: Any = None) -> Any:
        call_args = dict(args or {})
        return self._guarded(tool_context=tool_context, **call_args)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded(*args, **kwargs)


def _import_function_tool() -> Optional[type]:
    """The ``google.adk`` ``FunctionTool`` class, or ``None`` when ADK is not installed."""
    try:
        from google.adk.tools import FunctionTool as _FunctionTool
    except Exception:
        try:
            from google.adk.tools.function_tool import FunctionTool as _FunctionTool
        except Exception:
            return None
    return _FunctionTool


def _expose_tool_context(guarded: ToolFn) -> None:
    """Declare a ``tool_context`` parameter on ``guarded`` so ADK injects the run's ``ToolContext``
    (where the session-state proof lives). ADK only injects it when the function's signature names it,
    and it is left out of the tool declaration the model sees."""
    from google.adk.tools.tool_context import ToolContext

    sig = inspect.signature(guarded)
    params = [p for p in sig.parameters.values() if p.name != "tool_context" and p.kind is not p.VAR_KEYWORD]
    params.append(inspect.Parameter("tool_context", inspect.Parameter.KEYWORD_ONLY, default=None,
                                    annotation=ToolContext))
    guarded.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]
    guarded.__annotations__ = {**getattr(guarded, "__annotations__", {}), "tool_context": ToolContext}


def pca_tool(require: str, *, audience: str, verifier: Optional[Verifier] = None,
             resolve_grant: Optional[GrantResolver] = None, now: Optional[int] = None,
             arg_name: str = PCA_ARG, state_key: str = PCA_STATE_KEY) -> Callable[[Any], Any]:
    """Decorator making an ADK tool require a valid proof-carrying action before it runs.

    ``require``        — the capability this tool demands, as ``"verb:resource"`` (e.g. ``"write:db/orders"``).
    ``audience``       — this resource server's own id; the proof's signed ``aud`` must equal it (RFC 8707).
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required when ``verifier`` is not supplied.
    ``now``            — epoch-ms clock for the validity window (default: wall clock); used only for the default verifier.
    ``arg_name``       — the tool-call argument that carries the proof inline (default ``"pca_action"``).
    ``state_key``      — the ``tool_context`` session-state key the proof travels under (default ``"PCA-Action"``).

    Usage::

        from google.adk.tools import FunctionTool
        from atlas_pca_google_adk import pca_tool

        @pca_tool("write:db/orders", audience="rs-orders", resolve_grant=resolve)
        def place_order(sku: str, qty: int, tool_context) -> str:
            ...

        agent = LlmAgent(..., tools=[place_order])  # `place_order` is now a guarded FunctionTool
    """
    verb, resource = _parse_require(require)
    if verifier is None:
        if resolve_grant is None:
            raise ValueError("pca_tool requires either `verifier=` or `resolve_grant=`")
        verifier = CoreVerifier(resolve_grant, now=now)
    the_verifier: Verifier = verifier

    def decorator(target: Any) -> Any:
        meta = _meta_of(target)

        @functools.wraps(meta.inner)
        def guarded(*args: Any, tool_context: Any = _UNSET, **kwargs: Any) -> Any:
            inline = kwargs.pop(arg_name, None)
            ctx = None if tool_context is _UNSET else tool_context
            pcactn = _resolve_proof(inline, ctx)
            decision = the_verifier.verify(pcactn, verb=verb, resource=resource, audience=audience)
            if not decision.ok:
                raise PcaToolDenied(decision)
            if meta.forward_tool_context and ctx is not None:
                kwargs["tool_context"] = ctx
            return meta.inner(*args, **kwargs)

        # Preserve the tool's display name/description (functools.wraps copied the inner function's).
        guarded.__name__ = meta.name
        guarded.__doc__ = meta.description
        setattr(guarded, "pca_required", require)

        function_tool = _import_function_tool()
        if function_tool is not None:
            if not meta.forward_tool_context:
                _expose_tool_context(guarded)
            return function_tool(guarded)
        return GuardedTool(name=meta.name, description=meta.description, guarded=guarded, required=require)

    return decorator
