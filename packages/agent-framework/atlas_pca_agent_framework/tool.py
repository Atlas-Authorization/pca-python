"""``pca_tool`` — wrap a single Microsoft Agent Framework tool so every call is proof-carrying.

``pca_tool(require="verb:resource", audience=..., resolve_grant=...)`` returns a decorator over an
``@ai_function``-decorated ``AIFunction`` (or the plain callable behind one). Before the underlying
function fires, it resolves the carried proof (the context var from :mod:`atlas_pca_agent_framework._proof`,
or an inline ``pca_action`` argument), verifies it with the reference verifier for this tool's required
capability and this resource server's audience, and only then runs the tool. A denial raises
:class:`PcaToolDenied` — the Agent Framework surfaces an exception raised inside a tool back to the
model as the tool's (error) result — and the underlying function never executes.

The wrapper is **duck-typed**: it accepts an ``agent_framework`` ``AIFunction`` instance or a plain
callable, and it does not import ``agent_framework`` at module load. When ``agent_framework`` *is*
installed, :func:`pca_tool` returns a real ``AIFunction`` (rebuilt by ``ai_function`` from a guarded
function whose signature mirrors the original, so the model still sees the right parameter schema);
otherwise it returns a structurally-identical :class:`GuardedFunction` so tests (and callers without
the framework) need nothing installed. Both synchronous and ``async def`` tools are supported — the
guarded wrapper preserves the inner function's coroutine-ness.
"""
from __future__ import annotations

import copy
import functools
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from ._proof import PCA_ARG, ProofInput, coerce_pcactn, current_proof
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: A tool's work function, or a guarded wrapper over it. Tool I/O is arbitrary by nature.
ToolFn = Callable[..., Any]


class PcaToolDenied(RuntimeError):
    """Raised in place of running a tool when the proof is missing, invalid, or insufficient.

    Carries the full :class:`ToolDecision` on ``.decision`` so a caller (or an Agent Framework error
    handler) can inspect ``reason`` / ``verdict`` / ``required`` while still getting a plain string
    message. The framework surfaces an exception raised inside a tool back to the model as the tool's
    error result.
    """

    def __init__(self, decision: ToolDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason or "proof-carrying authority required")


@dataclass
class _Meta:
    name: str
    description: str
    inner: ToolFn
    is_async: bool


def _parse_require(require: str) -> Tuple[str, str]:
    if not isinstance(require, str) or ":" not in require:
        raise ValueError("require must be a 'verb:resource' string, got %r" % (require,))
    verb, resource = require.split(":", 1)
    if not verb or not resource:
        raise ValueError("require must be a non-empty 'verb:resource' string, got %r" % (require,))
    return verb, resource


def _inner_callable(target: Any) -> ToolFn:
    """The raw work function behind an ``AIFunction`` / ``@ai_function`` object, or ``target`` itself.

    Structural, no ``agent_framework`` import: Agent Framework stores the wrapped callable on the
    ``AIFunction`` (observed as ``func`` / ``_func``, and ``functools.wraps`` leaves ``__wrapped__``).
    Trying those first keeps the original signature so a rebuilt ``AIFunction`` derives the right schema.
    """
    for attr in ("func", "_func", "__wrapped__"):
        candidate = getattr(target, attr, None)
        if callable(candidate):
            return candidate
    if callable(target):
        return target
    raise TypeError("pca_tool expected an agent_framework AIFunction or a callable, got %r" % (target,))


def _meta_of(target: Any) -> _Meta:
    """Resolve the work function and display metadata from an ``AIFunction`` or a plain callable."""
    inner = _inner_callable(target)
    name = getattr(target, "name", None) or getattr(inner, "__name__", None) or "pca_guarded_tool"
    description = getattr(target, "description", None) or (getattr(inner, "__doc__", None) or "")
    return _Meta(name=str(name), description=str(description), inner=inner,
                 is_async=inspect.iscoroutinefunction(inner))


def _resolve_proof(inline: ProofInput) -> Optional[Dict[str, Any]]:
    """The proof for this call: an explicit inline ``pca_action`` wins, else the context var.

    Normalized through the strict profile; ``None`` (absent/undecodable) fails closed.
    """
    if inline is not None:
        return coerce_pcactn(inline)
    return coerce_pcactn(current_proof())


class GuardedFunction:
    """A duck-typed Agent Framework tool: ``name`` / ``description`` plus an ``async invoke`` entry.

    Returned by :func:`pca_tool` when ``agent_framework`` is not importable. It exposes the surface the
    framework calls on an ``AIFunction`` (``async invoke(*, arguments=None, **kwargs)``) and is also
    directly callable (returning the inner's value, or a coroutine for an ``async def`` tool), so the
    guard is fully exercisable without the framework installed.
    """

    def __init__(self, *, name: str, description: str, guarded: ToolFn, required: str,
                 is_async: bool) -> None:
        self.name = name
        self.description = description
        self.pca_required = required
        self.is_async = is_async
        self._guarded = guarded

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded(*args, **kwargs)

    async def invoke(self, *, arguments: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Any:
        """Invoke the guarded tool the way the framework does: merged ``arguments`` + keyword args."""
        merged: Dict[str, Any] = dict(arguments or {})
        merged.update(kwargs)
        result = self._guarded(**merged)
        if inspect.isawaitable(result):
            return await result
        return result


def _import_function_tool() -> Optional[type]:
    """The ``agent_framework`` ``FunctionTool`` class, or ``None`` when it is not installed."""
    try:
        from agent_framework import FunctionTool as _FunctionTool
    except Exception:
        return None
    tool_cls: type = _FunctionTool
    return tool_cls


def _import_tool_decorator() -> Optional[Callable[[ToolFn], Any]]:
    """The framework's function-to-tool decorator: ``tool`` (current) or ``ai_function`` (earlier
    releases), or ``None`` when ``agent_framework`` is not installed."""
    try:
        import agent_framework as _af
    except Exception:
        return None
    for attr in ("tool", "ai_function"):
        decorator = getattr(_af, attr, None)
        if callable(decorator):
            found: Callable[[ToolFn], Any] = decorator
            return found
    return None


def _make_guarded(meta: _Meta, the_verifier: Verifier, *, verb: str, resource: str, audience: str,
                  arg_name: str) -> ToolFn:
    """Build the signature-preserving guarded wrapper, async iff the inner tool is ``async def``."""
    if meta.is_async:
        @functools.wraps(meta.inner)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            inline = kwargs.pop(arg_name, None)
            pcactn = _resolve_proof(inline)
            decision = the_verifier.verify(pcactn, verb=verb, resource=resource, audience=audience)
            if not decision.ok:
                raise PcaToolDenied(decision)
            return await meta.inner(*args, **kwargs)
    else:
        @functools.wraps(meta.inner)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            inline = kwargs.pop(arg_name, None)
            pcactn = _resolve_proof(inline)
            decision = the_verifier.verify(pcactn, verb=verb, resource=resource, audience=audience)
            if not decision.ok:
                raise PcaToolDenied(decision)
            return meta.inner(*args, **kwargs)

    # Preserve the tool's display name/description (functools.wraps copied the inner function's).
    guarded.__name__ = meta.name
    guarded.__doc__ = meta.description
    setattr(guarded, "pca_required", "%s:%s" % (verb, resource))
    return guarded


def pca_tool(require: str, *, audience: str, verifier: Optional[Verifier] = None,
             resolve_grant: Optional[GrantResolver] = None, now: Optional[int] = None,
             arg_name: str = PCA_ARG) -> Callable[[Any], Any]:
    """Decorator making an Agent Framework tool require a valid proof-carrying action before it runs.

    ``require``        — the capability this tool demands, as ``"verb:resource"`` (e.g. ``"write:db/orders"``).
    ``audience``       — this resource server's own id; the proof's signed ``aud`` must equal it (RFC 8707).
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required when ``verifier`` is not supplied.
    ``now``            — epoch-ms clock for the validity window (default: wall clock); used only for the default verifier.
    ``arg_name``       — the inline proof key in ``arguments`` (default ``"pca_action"``), stripped before the tool runs.

    Usage::

        from agent_framework import ai_function, ChatAgent
        from atlas_pca_agent_framework import pca_tool, pca_context

        @pca_tool("write:db/orders", audience="rs-orders", resolve_grant=resolve)
        @ai_function
        async def place_order(sku: str, qty: int) -> str:
            ...

        agent = ChatAgent(chat_client=client, tools=[place_order])
        with pca_context(my_pcactn):
            await agent.run("order two widgets")   # place_order runs only under a valid proof
    """
    verb, resource = _parse_require(require)
    if verifier is None:
        if resolve_grant is None:
            raise ValueError("pca_tool requires either `verifier=` or `resolve_grant=`")
        verifier = CoreVerifier(resolve_grant, now=now)
    elif resolve_grant is not None:
        raise ValueError("pass either `verifier=` or `resolve_grant=`, not both")
    the_verifier: Verifier = verifier

    def decorator(target: Any) -> Any:
        meta = _meta_of(target)
        guarded = _make_guarded(meta, the_verifier, verb=verb, resource=resource, audience=audience,
                                arg_name=arg_name)

        function_tool = _import_function_tool()
        if function_tool is not None and isinstance(target, function_tool):
            # Already a real FunctionTool: keep every setting it carries (approval mode, invocation
            # limits, result parser, custom schema, ...) and swap only the callable it runs.
            clone = copy.copy(target)
            clone.func = guarded
            return clone
        decorator_fn = _import_tool_decorator()
        if decorator_fn is not None:
            return decorator_fn(guarded)
        return GuardedFunction(name=meta.name, description=meta.description, guarded=guarded,
                               required=require, is_async=meta.is_async)

    return decorator
