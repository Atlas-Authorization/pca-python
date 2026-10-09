"""Gate every tool a Haystack ``ToolInvoker`` (and therefore a whole pipeline) can invoke, in one call.

A Haystack agent runs tools through a :class:`ToolInvoker` component: it holds a list of tools and,
for each tool call an LLM emits, looks the tool up by name and calls ``tool.invoke(**arguments)``.
Guarding the invoker therefore guards every tool the pipeline can reach.

* :func:`guard_tools` maps a list of tools to their guarded equivalents (each via :func:`pca_tool`);
* :func:`guard_tool_invoker` replaces a ``ToolInvoker``'s tools in place with guarded ones (and
  rebuilds its name lookup), so the invoker is gated with no change to the pipeline wiring.

Because an LLM — not the caller — supplies a tool call's arguments, a proof cannot ride in those
arguments; bind it with :func:`atlas_pca_haystack.pca_context` around the ``ToolInvoker.run`` /
``Pipeline.run`` instead.

Each tool's required capability comes from ``require``, which is one of:

* a ``"verb:resource"`` string applied to every tool (handy for a single-capability invoker);
* a mapping ``{tool_name: "verb:resource"}`` — tools absent from the map are left ungated; or
* a callable ``(tool) -> "verb:resource" | None`` — returning ``None`` leaves that tool ungated.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Union

from .tool import pca_tool
from .verifier import GrantResolver, Verifier

#: How each tool's required capability is chosen. See the module docstring.
RequireSpec = Union[str, Mapping[str, str], Callable[[Any], Optional[str]]]


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


def guard_tools(tools: List[Any], *, audience: str, require: RequireSpec,
                verifier: Optional[Verifier] = None, resolve_grant: Optional[GrantResolver] = None,
                now: Optional[int] = None) -> List[Any]:
    """Return a new list where every tool with a resolved ``require`` is wrapped by :func:`pca_tool`.

    Tools whose ``require`` resolves to ``None`` are passed through unchanged.
    """
    guarded: List[Any] = []
    for tool in tools:
        req = _require_for(tool, require)
        if req is None:
            guarded.append(tool)
            continue
        guarded.append(
            pca_tool(req, audience=audience, verifier=verifier, resolve_grant=resolve_grant, now=now)(tool)
        )
    return guarded


def guard_tool_invoker(invoker: Any, *, audience: str, require: RequireSpec,
                       verifier: Optional[Verifier] = None,
                       resolve_grant: Optional[GrantResolver] = None,
                       now: Optional[int] = None) -> Any:
    """Guard every tool a ``ToolInvoker`` can call, replacing its tool list in place.

    Call it once before the invoker runs (``guard_tool_invoker(invoker, ...)``); returns the same
    ``invoker`` for chaining. The invoker's ``tools`` are swapped for guarded equivalents and its
    private name lookup (``_tools_with_names``, when present) is rebuilt so dispatch finds the guarded
    tool by the same name. Tools whose ``require`` resolves to ``None`` are left ungated.
    """
    tools = getattr(invoker, "tools", None)
    if tools:
        guarded = guard_tools(list(tools), audience=audience, require=require,
                              verifier=verifier, resolve_grant=resolve_grant, now=now)
        invoker.tools = guarded
        if isinstance(getattr(invoker, "_tools_with_names", None), dict):
            rebuilt: Dict[str, Any] = {}
            for tool in guarded:
                name = _tool_name(tool)
                if name is not None:
                    rebuilt[name] = tool
            invoker._tools_with_names = rebuilt
    return invoker
