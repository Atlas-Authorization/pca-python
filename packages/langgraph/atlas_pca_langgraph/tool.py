"""``pca_tool`` — wrap a single LangGraph/LangChain tool so every call is proof-carrying and gated.

``pca_tool("verb:resource", audience=..., resolve_grant=...)`` returns a decorator over a ``@tool``-
decorated function, a LangChain ``BaseTool``/``StructuredTool`` instance, or a plain callable. Before
the underlying function fires, it resolves the carried proof (the inline ``pca_action`` argument, else
the ``PCA-Action`` key in the ``RunnableConfig`` ``configurable``, else the context var), verifies it
with the reference verifier for this tool's required capability and this resource server's audience,
and only then runs the tool. A denial raises :class:`PcaToolDenied` and the underlying tool never runs.

``require`` may be ``None`` to require only a *valid* proof for this audience (no capability gate) —
used by :class:`~atlas_pca_langgraph.node.PcaToolNode` for tools that carry no explicit capability.

The wrapper is **duck-typed**: it does not import ``langchain_core`` at module load. When
``langchain_core`` *is* installed, :func:`pca_tool` returns a real ``StructuredTool`` (so the tool keeps
its name/description/args-schema and drops into a ``ToolNode`` or ``create_react_agent``); otherwise it
returns a structurally-identical :class:`GuardedTool` so tests (and non-LangChain callers) need nothing
installed.
"""
from __future__ import annotations

import functools
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from ._proof import (
    PCA_ARG,
    PCA_CONFIG_KEY,
    ProofInput,
    coerce_pcactn,
    current_proof,
    proof_from_config,
)
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: A tool's work function, or a guarded wrapper over it. Tool I/O is arbitrary by nature.
ToolFn = Callable[..., Any]

_UNSET: Any = object()


class PcaToolDenied(RuntimeError):
    """Raised in place of running a tool when the proof is missing, invalid, or insufficient.

    Carries the full :class:`ToolDecision` on ``.decision`` so a caller (or a LangGraph error handler)
    can inspect ``reason`` / ``verdict`` / ``required`` while still getting a plain string message.
    """

    def __init__(self, decision: ToolDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason or "proof-carrying authority required")


@dataclass
class _Meta:
    name: str
    description: str
    inner: ToolFn
    forward_config: bool


def _parse_require(require: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """``"verb:resource"`` -> ``(verb, resource)``; ``None`` -> ``(None, None)`` (valid-proof only)."""
    if require is None:
        return None, None
    if not isinstance(require, str) or ":" not in require:
        raise ValueError("require must be a 'verb:resource' string or None, got %r" % (require,))
    verb, resource = require.split(":", 1)
    if not verb or not resource:
        raise ValueError("require must be a non-empty 'verb:resource' string, got %r" % (require,))
    return verb, resource


def _accepts_param(func: ToolFn, name: str) -> bool:
    """Whether ``func`` declares a keyword param ``name`` (or accepts ``**kwargs``)."""
    try:
        params = inspect.signature(func).parameters.values()
    except (TypeError, ValueError):
        return False
    for p in params:
        if p.name == name and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY):
            return True
        if p.kind is p.VAR_KEYWORD:
            return True
    return False


def _meta_of(target: Any) -> _Meta:
    """Resolve the work function and display metadata from a LangChain ``BaseTool``/``StructuredTool``
    instance or a plain callable — structurally, without importing ``langchain_core``."""
    func = getattr(target, "func", None)
    if callable(func):
        inner: ToolFn = func
    elif callable(target):
        inner = target
    else:
        raise TypeError("pca_tool expected a LangChain tool or a callable, got %r" % (target,))

    name = getattr(target, "name", None) or getattr(inner, "__name__", None) or "pca_guarded_tool"
    description = getattr(target, "description", None) or (getattr(inner, "__doc__", None) or "")
    return _Meta(name=str(name), description=str(description), inner=inner,
                 forward_config=_accepts_param(inner, "config"))


def _resolve_proof(inline: ProofInput, config: Any) -> Optional[Dict[str, Any]]:
    """The proof for this call: an explicit inline ``pca_action`` wins, else the ``RunnableConfig``
    ``configurable``, else the context var. Normalized through the strict profile; ``None`` fails closed.
    """
    if inline is not None:
        got = coerce_pcactn(inline)
        if got is not None:
            return got
    from_config = proof_from_config(config)
    if from_config is not None:
        got = coerce_pcactn(from_config)
        if got is not None:
            return got
    return coerce_pcactn(current_proof())


class GuardedTool:
    """A duck-typed LangChain tool: ``name`` / ``description`` / ``func`` plus the ``invoke`` entry.

    Returned by :func:`pca_tool` when ``langchain_core`` is not importable. It exposes the surface a
    ``ToolNode`` calls (``invoke(input, config)`` / ``ainvoke``), is directly callable, and has a sync
    ``run`` for convenience, so the guard is fully exercisable without the framework installed. The
    inline ``pca_action`` key in an ``invoke`` input dict is honored and stripped before the inner tool
    runs.
    """

    def __init__(self, *, name: str, description: str, guarded: ToolFn, required: Optional[str]) -> None:
        self.name = name
        self.description = description
        self.func = guarded
        self.pca_required = required
        self._guarded = guarded

    def invoke(self, input: Any = None, config: Any = None, **kwargs: Any) -> Any:
        call_args: Dict[str, Any] = {}
        if isinstance(input, dict):
            call_args.update(input)
        call_args.update(kwargs)
        if config is not None and "config" not in call_args:
            call_args["config"] = config
        return self._guarded(**call_args)

    async def ainvoke(self, input: Any = None, config: Any = None, **kwargs: Any) -> Any:
        return self.invoke(input, config, **kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded(*args, **kwargs)


def _import_structured_tool() -> Optional[type]:
    """The ``langchain_core`` ``StructuredTool`` class, or ``None`` when it is not installed."""
    try:
        from langchain_core.tools import StructuredTool as _StructuredTool
    except Exception:
        return None
    return _StructuredTool


def pca_tool(require: Optional[str], *, audience: str, verifier: Optional[Verifier] = None,
             resolve_grant: Optional[GrantResolver] = None, now: Optional[int] = None,
             arg_name: str = PCA_ARG, config_key: str = PCA_CONFIG_KEY) -> Callable[[Any], Any]:
    """Decorator making a LangGraph/LangChain tool require a valid proof-carrying action before it runs.

    ``require``        — the capability this tool demands, as ``"verb:resource"`` (e.g. ``"write:db/orders"``),
                         or ``None`` to require only a valid proof for this audience (no capability gate).
    ``audience``       — this resource server's own id; the proof's signed ``aud`` must equal it (RFC 8707).
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required when ``verifier`` is not supplied.
    ``now``            — epoch-ms clock for the validity window (default: wall clock); used only for the default verifier.
    ``arg_name``       — the tool-call argument that carries the proof inline (default ``"pca_action"``).
    ``config_key``     — the ``RunnableConfig.configurable`` key the proof travels under (default ``"PCA-Action"``).

    Usage::

        from langchain_core.tools import tool
        from atlas_pca_langgraph import pca_tool

        @pca_tool("write:db/orders", audience="rs-orders", resolve_grant=resolve)
        @tool
        def place_order(sku: str, qty: int) -> str:
            ...

        graph = StateGraph(...).add_node("tools", ToolNode([place_order]))
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

        @functools.wraps(meta.inner)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            inline = kwargs.pop(arg_name, None)
            config = kwargs.get("config", _UNSET)
            config_val = None if config is _UNSET else config
            pcactn = _resolve_proof(inline, config_val)
            decision = the_verifier.verify(pcactn, verb=verb, resource=resource, audience=audience)
            if not decision.ok:
                raise PcaToolDenied(decision)
            # Strip `config` unless the inner tool actually declares it (as LangChain does for its own
            # injected RunnableConfig): we only read it to locate the proof.
            if config is not _UNSET and not meta.forward_config:
                kwargs.pop("config", None)
            return meta.inner(*args, **kwargs)

        # Preserve the tool's display name/description (functools.wraps copied the inner function's).
        guarded.__name__ = meta.name
        guarded.__doc__ = meta.description
        setattr(guarded, "pca_required", require)

        structured_tool = _import_structured_tool()
        if structured_tool is not None:
            built = structured_tool.from_function(func=guarded, name=meta.name,
                                                  description=meta.description)
            setattr(built, "pca_required", require)
            return built
        return GuardedTool(name=meta.name, description=meta.description, guarded=guarded, required=require)

    return decorator
