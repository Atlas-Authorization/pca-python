"""``pca_tool`` — wrap a single Haystack tool so every call is proof-carrying and policy-gated.

``pca_tool(require="verb:resource", audience=..., verifier=...)`` returns a decorator over a Haystack
tool. Before the underlying ``function`` fires, it resolves the carried proof (the ``pca_action``
``invoke`` keyword, else the context var from :mod:`atlas_pca_haystack._proof`), verifies it with the
reference verifier for this tool's required capability and this resource server's audience, and only
then runs the tool. A denial raises :class:`PcaToolDenied` before any work happens, and the underlying
tool never executes. When a :class:`ToolInvoker` runs a guarded tool, that exception is the invocation
error Haystack surfaces (propagated with ``raise_on_failure=True``, or turned into an error tool
message otherwise), so the model sees a denial rather than a result.

The wrapper is **duck-typed**: it accepts a ``haystack.tools.Tool`` instance, a ``@tool``-decorated
object, or a plain callable, and it does not import ``haystack`` at module load. When ``haystack`` *is*
installed, :func:`pca_tool` returns a real ``Tool`` (same ``name`` / ``description`` / ``parameters``,
its ``function`` replaced by the guarded wrapper) so the guarded tool drops into a pipeline or a
``ToolInvoker`` unchanged; otherwise it returns a structurally-identical :class:`GuardedTool` so tests
(and non-Haystack callers) need nothing installed.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from ._proof import PCA_ARG, ProofInput, coerce_pcactn, current_proof
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: A tool's work function, or a guarded wrapper over it. Tool I/O is arbitrary by nature.
ToolFn = Callable[..., Any]

#: A permissive JSON-Schema for a real Haystack ``Tool`` built from a source without its own schema.
_EMPTY_PARAMETERS: Dict[str, Any] = {"type": "object", "properties": {}}


class PcaToolDenied(RuntimeError):
    """Raised in place of running a tool when the proof is missing, invalid, or insufficient.

    Carries the full :class:`ToolDecision` on ``.decision`` so a caller (or a Haystack error handler)
    can inspect ``reason`` / ``verdict`` / ``required`` while still getting a plain string message.
    """

    def __init__(self, decision: ToolDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason or "proof-carrying authority required")


@dataclass
class _Meta:
    name: str
    description: str
    parameters: Dict[str, Any]
    inner: ToolFn


def _parse_require(require: str) -> Tuple[str, str]:
    if not isinstance(require, str) or ":" not in require:
        raise ValueError("require must be a 'verb:resource' string, got %r" % (require,))
    verb, resource = require.split(":", 1)
    if not verb or not resource:
        raise ValueError("require must be a non-empty 'verb:resource' string, got %r" % (require,))
    return verb, resource


def _meta_of(target: Any) -> _Meta:
    """Resolve the work function and display metadata from a ``Tool`` instance, a ``@tool`` object,
    or a plain callable — structurally, without importing haystack.

    A Haystack ``Tool`` exposes its work callable on ``.function`` plus ``.name`` / ``.description`` /
    ``.parameters``; a plain callable falls back to ``__name__`` / ``__doc__`` and an empty schema.
    """
    func = getattr(target, "function", None)
    if callable(func):
        inner: ToolFn = func
    elif callable(target):
        inner = target
    else:
        raise TypeError("pca_tool expected a Haystack Tool or a callable, got %r" % (target,))

    name = getattr(target, "name", None) or getattr(target, "__name__", None) or "pca_guarded_tool"
    description = getattr(target, "description", None) or (getattr(target, "__doc__", None) or "")
    parameters = getattr(target, "parameters", None)
    if not isinstance(parameters, dict):
        parameters = dict(_EMPTY_PARAMETERS)
    return _Meta(name=str(name), description=str(description), parameters=parameters, inner=inner)


def _pop_proof(kwargs: Dict[str, Any], arg_name: str) -> Optional[Dict[str, Any]]:
    """The proof for this call: the explicit ``arg_name`` keyword wins, else the context var."""
    raw: ProofInput
    if arg_name in kwargs:
        raw = kwargs.pop(arg_name)
    else:
        raw = current_proof()
    return coerce_pcactn(raw)


class GuardedTool:
    """A duck-typed Haystack tool: ``name`` / ``description`` / ``parameters`` / ``function`` / ``invoke``.

    Returned by :func:`pca_tool` when ``haystack`` is not importable. It exposes the same surface a
    ``ToolInvoker`` calls (``invoke(**kwargs)`` delegates to the guarded wrapper, and the object is also
    directly callable), so the guard is fully exercisable without the framework installed.
    """

    def __init__(self, *, name: str, description: str, parameters: Dict[str, Any],
                 guarded: ToolFn, required: str) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters
        self.function: ToolFn = guarded
        self.pca_required = required

    def invoke(self, **kwargs: Any) -> Any:
        # Haystack's Tool.invoke is keyword-only; match that for drop-in use by a ToolInvoker.
        return self.function(**kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.function(*args, **kwargs)


def _import_tool_cls() -> Optional[type]:
    """The ``haystack`` ``Tool`` class, or ``None`` when haystack is not installed."""
    try:
        from haystack.tools import Tool as _Tool
    except Exception:
        return None
    tool_cls: type = _Tool
    return tool_cls


def _build_haystack_tool(tool_cls: type, target: Any, meta: _Meta, guarded: ToolFn, required: str,
                         guarded_async: Optional[ToolFn] = None) -> Any:
    """A real ``Tool`` whose ``function`` (and ``async_function``, when the tool has one) is guarded.

    When ``target`` is already a Haystack ``Tool`` it is shallow-copied and only its callables are
    swapped, so every other field (``outputs_to_string``, ``inputs_from_state``, ``outputs_to_state``,
    ...) and any ``Tool`` subclass survive; a plain callable gets a fresh ``Tool`` built from ``meta``.
    """
    if isinstance(target, tool_cls):
        tool = copy.copy(target)
        tool.function = guarded
        if guarded_async is not None:
            tool.async_function = guarded_async
    else:
        tool = tool_cls(
            name=meta.name,
            description=meta.description or meta.name,
            parameters=meta.parameters,
            function=guarded,
        )
    # Non-breaking marker for introspection; ignored by Haystack's own machinery.
    try:
        tool.pca_required = required
    except Exception:
        pass
    return tool


def pca_tool(require: str, *, audience: str, verifier: Optional[Verifier] = None,
             resolve_grant: Optional[GrantResolver] = None, now: Optional[int] = None,
             arg_name: str = PCA_ARG) -> Callable[[Any], Any]:
    """Decorator making a Haystack tool require a valid proof-carrying action before it runs.

    ``require``        — the capability this tool demands, as ``"verb:resource"`` (e.g. ``"write:db/orders"``).
    ``audience``       — this resource server's own id; the proof's signed ``aud`` must equal it (RFC 8707).
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required when ``verifier`` is not supplied.
    ``now``            — epoch-ms clock for the validity window (default: wall clock); used only for the default verifier.
    ``arg_name``       — the ``invoke`` keyword that carries the proof inline (default ``"pca_action"``).

    Usage::

        from haystack.tools import tool
        from atlas_pca_haystack import pca_tool

        @pca_tool("write:db/orders", audience="rs-orders", resolve_grant=resolve)
        @tool
        def place_order(sku: str, qty: int) -> str:
            ...
    """
    verb, resource = _parse_require(require)
    if verifier is None:
        if resolve_grant is None:
            raise ValueError("pca_tool requires either `verifier=` or `resolve_grant=`")
        verifier = CoreVerifier(resolve_grant, now=now)
    the_verifier: Verifier = verifier

    def decorator(target: Any) -> Any:
        meta = _meta_of(target)

        def guarded(*args: Any, **kwargs: Any) -> Any:
            pcactn = _pop_proof(kwargs, arg_name)
            decision = the_verifier.verify(pcactn, verb=verb, resource=resource, audience=audience)
            if not decision.ok:
                raise PcaToolDenied(decision)
            return meta.inner(*args, **kwargs)

        guarded_async: Optional[ToolFn] = None
        inner_async = getattr(target, "async_function", None)
        if callable(inner_async):
            async def guarded_async_fn(*args: Any, **kwargs: Any) -> Any:
                pcactn = _pop_proof(kwargs, arg_name)
                decision = the_verifier.verify(pcactn, verb=verb, resource=resource, audience=audience)
                if not decision.ok:
                    raise PcaToolDenied(decision)
                return await inner_async(*args, **kwargs)

            guarded_async = guarded_async_fn

        tool_cls = _import_tool_cls()
        if tool_cls is not None:
            return _build_haystack_tool(tool_cls, target, meta, guarded, require, guarded_async)
        return GuardedTool(name=meta.name, description=meta.description, parameters=meta.parameters,
                           guarded=guarded, required=require)

    return decorator
