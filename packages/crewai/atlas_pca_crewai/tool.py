"""``pca_tool`` — wrap a single CrewAI tool so every call is proof-carrying and policy-gated.

``pca_tool(require="verb:resource", audience=..., verifier=...)`` returns a decorator over a CrewAI
tool. Before the underlying ``_run`` fires, it resolves the carried proof (the ``pca_action`` call
keyword, else the context var from :mod:`atlas_pca_crewai._proof`), verifies it with the reference
verifier for this tool's required capability and this resource server's audience, and only then runs
the tool. A denial raises :class:`PcaToolDenied` — a tool error CrewAI routes back to the agent as an
observation — and the underlying tool never executes.

The wrapper is **duck-typed**: it accepts a ``crewai.tools.BaseTool`` instance, a ``@tool``-decorated
object, or a plain callable, and it does not import ``crewai`` at module load. When ``crewai`` *is*
installed, :func:`pca_tool` returns a real ``BaseTool`` subclass so the guarded tool drops into a crew
unchanged; otherwise it returns a structurally-identical :class:`GuardedTool` so tests (and non-CrewAI
callers) need nothing installed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, ClassVar, Dict, Optional, Tuple

from ._proof import PCA_ARG, ProofInput, coerce_pcactn, current_proof, pca_context
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: A tool's work function, or a guarded wrapper over it. Tool I/O is arbitrary by nature.
ToolFn = Callable[..., Any]


class PcaToolDenied(RuntimeError):
    """Raised in place of running a tool when the proof is missing, invalid, or insufficient.

    Carries the full :class:`ToolDecision` on ``.decision`` so a caller (or a CrewAI error handler)
    can inspect ``reason`` / ``verdict`` / ``required`` while still getting a plain string message.
    """

    def __init__(self, decision: ToolDecision) -> None:
        self.decision = decision
        super().__init__(decision.reason or "proof-carrying authority required")


@dataclass
class _Meta:
    name: str
    description: str
    args_schema: Optional[type]
    inner: ToolFn


def _parse_require(require: str) -> Tuple[str, str]:
    if not isinstance(require, str) or ":" not in require:
        raise ValueError("require must be a 'verb:resource' string, got %r" % (require,))
    verb, resource = require.split(":", 1)
    if not verb or not resource:
        raise ValueError("require must be a non-empty 'verb:resource' string, got %r" % (require,))
    return verb, resource


def _meta_of(target: Any) -> _Meta:
    """Resolve the work function and display metadata from a BaseTool instance, a ``@tool`` object,
    or a plain callable — structurally, without importing crewai."""
    run = getattr(target, "_run", None)
    if callable(run):
        inner: ToolFn = run
    else:
        func = getattr(target, "func", None)
        if callable(func):
            inner = func
        elif callable(target):
            inner = target
        else:
            raise TypeError("pca_tool expected a CrewAI tool or a callable, got %r" % (target,))

    name = getattr(target, "name", None) or getattr(target, "__name__", None) or "pca_guarded_tool"
    description = getattr(target, "description", None) or (getattr(target, "__doc__", None) or "")
    args_schema = getattr(target, "args_schema", None)
    return _Meta(name=str(name), description=str(description), args_schema=args_schema, inner=inner)


def _pop_proof(kwargs: Dict[str, Any], arg_name: str) -> Optional[Dict[str, Any]]:
    """The proof for this call: the explicit ``arg_name`` keyword wins, else the context var."""
    raw: ProofInput
    if arg_name in kwargs:
        raw = kwargs.pop(arg_name)
    else:
        raw = current_proof()
    return coerce_pcactn(raw)


class GuardedTool:
    """A duck-typed CrewAI tool: ``name`` / ``description`` / ``args_schema`` / ``run`` / ``_run``.

    Returned by :func:`pca_tool` when ``crewai`` is not importable. It exposes the same surface CrewAI
    calls (``run`` delegates to ``_run``; the object is also directly callable), so the guard is fully
    exercisable without the framework installed.
    """

    def __init__(self, *, name: str, description: str, args_schema: Optional[type],
                 guarded: ToolFn, required: str) -> None:
        self.name = name
        self.description = description
        self.args_schema = args_schema
        self.pca_required = required
        self._guarded = guarded

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded(*args, **kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded(*args, **kwargs)


def _import_base_tool() -> Optional[type]:
    """The ``crewai`` ``BaseTool`` class, or ``None`` when crewai is not installed."""
    try:
        from crewai.tools import BaseTool as _BaseTool
    except Exception:
        try:
            from crewai_tools import BaseTool as _BaseTool
        except Exception:
            return None
    return _BaseTool


def _build_crewai_tool(base: type, meta: _Meta, guarded: ToolFn, required: str,
                       arg_name: str = PCA_ARG) -> Any:
    """Construct a real ``BaseTool`` subclass whose ``_run`` is the guarded wrapper."""
    def _run(self: Any, *args: Any, **kwargs: Any) -> Any:
        return guarded(*args, **kwargs)

    def run(self: Any, *args: Any, **kwargs: Any) -> Any:
        # ``BaseTool.run`` validates keywords against the tool's args schema and would drop the inline
        # proof before ``_run`` sees it, so lift it out here and bind it for the duration of the call.
        if arg_name in kwargs:
            with pca_context(kwargs.pop(arg_name)):
                return base.run(self, *args, **kwargs)  # type: ignore[attr-defined]
        return base.run(self, *args, **kwargs)  # type: ignore[attr-defined]

    # BaseTool is a pydantic model: a plain class attribute must be declared a ClassVar, not a field.
    cls = type("PcaGuardedTool", (base,), {"_run": _run, "run": run, "pca_required": required,
                                           "__annotations__": {"pca_required": ClassVar[str]}})
    fields: Dict[str, Any] = {"name": meta.name, "description": meta.description or meta.name}
    if meta.args_schema is not None:
        fields["args_schema"] = meta.args_schema
    return cls(**fields)


def pca_tool(require: str, *, audience: str, verifier: Optional[Verifier] = None,
             resolve_grant: Optional[GrantResolver] = None, now: Optional[int] = None,
             arg_name: str = PCA_ARG) -> Callable[[Any], Any]:
    """Decorator making a CrewAI tool require a valid proof-carrying action before it runs.

    ``require``        — the capability this tool demands, as ``"verb:resource"`` (e.g. ``"write:db/orders"``).
    ``audience``       — this resource server's own id; the proof's signed ``aud`` must equal it (RFC 8707).
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required when ``verifier`` is not supplied.
    ``now``            — epoch-ms clock for the validity window (default: wall clock); used only for the default verifier.
    ``arg_name``       — the tool-call keyword that carries the proof inline (default ``"pca_action"``).

    Usage::

        from crewai.tools import tool
        from atlas_pca_crewai import pca_tool

        @pca_tool("write:db/orders", audience="rs-orders", resolve_grant=resolve)
        @tool("place_order")
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

        base = _import_base_tool()
        if base is not None:
            return _build_crewai_tool(base, meta, guarded, require, arg_name)
        return GuardedTool(name=meta.name, description=meta.description, args_schema=meta.args_schema,
                           guarded=guarded, required=require)

    return decorator
