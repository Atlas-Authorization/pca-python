"""Wrap every tool a whole crew can reach, in one call.

:func:`guard_tools` maps a list of tools to their guarded equivalents; :func:`guard_crew` is the
``before_kickoff``-style guard that walks a crew's agents (and tasks) and replaces each tool in place;
:class:`PcaToolGuard` is a mixin a crew class can inherit so a single ``before_kickoff`` hook guards
everything the crew owns.

Each tool's required capability comes from ``require``, which is one of:

* a ``"verb:resource"`` string applied to every tool (rare, but handy for a single-capability crew);
* a mapping ``{tool_name: "verb:resource"}`` — tools absent from the map are left ungated; or
* a callable ``(tool) -> "verb:resource" | None`` — returning ``None`` leaves that tool ungated.
"""
from __future__ import annotations

from typing import Any, Callable, List, Mapping, Optional, Union

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


def _guard_holder(holder: Any, *, audience: str, require: RequireSpec,
                  verifier: Optional[Verifier], resolve_grant: Optional[GrantResolver],
                  now: Optional[int]) -> None:
    """Replace ``holder.tools`` in place with guarded tools, if the holder has a non-empty list."""
    tools = getattr(holder, "tools", None)
    if tools:
        holder.tools = guard_tools(list(tools), audience=audience, require=require,
                                   verifier=verifier, resolve_grant=resolve_grant, now=now)


def guard_crew(crew: Any, *, audience: str, require: RequireSpec,
               verifier: Optional[Verifier] = None, resolve_grant: Optional[GrantResolver] = None,
               now: Optional[int] = None) -> Any:
    """Guard every tool reachable from ``crew`` (its agents, its tasks, and any crew-level tools).

    Call it once before ``crew.kickoff(...)``. Returns the same ``crew`` for chaining.
    """
    for agent in getattr(crew, "agents", None) or []:
        _guard_holder(agent, audience=audience, require=require, verifier=verifier,
                      resolve_grant=resolve_grant, now=now)
    for task in getattr(crew, "tasks", None) or []:
        _guard_holder(task, audience=audience, require=require, verifier=verifier,
                      resolve_grant=resolve_grant, now=now)
    _guard_holder(crew, audience=audience, require=require, verifier=verifier,
                  resolve_grant=resolve_grant, now=now)
    return crew


class PcaToolGuard:
    """Mixin for a crew class: a single hook guards every tool the crew owns.

    Set the class attributes (or instance attributes) and register :meth:`pca_guard_tools` as a
    ``before_kickoff`` hook::

        class MyCrew(PcaToolGuard):
            pca_audience = "rs-orders"
            pca_require = {"place_order": "write:db/orders"}
            pca_resolve_grant = staticmethod(resolve)

            @before_kickoff
            def _guard(self, inputs):
                return self.pca_guard_tools(inputs)

    ``pca_require`` is a :data:`RequireSpec`. Provide either ``pca_verifier`` or ``pca_resolve_grant``.
    """

    pca_audience: str = ""
    pca_require: RequireSpec = {}
    pca_verifier: Optional[Verifier] = None
    pca_resolve_grant: Optional[GrantResolver] = None
    pca_now: Optional[int] = None

    def pca_guard_tools(self, inputs: Any = None) -> Any:
        """Guard every tool on this crew, then return ``inputs`` unchanged (so it chains as a hook)."""
        if not self.pca_audience:
            raise ValueError("PcaToolGuard requires a non-empty `pca_audience`")
        guard_crew(self, audience=self.pca_audience, require=self.pca_require,
                   verifier=self.pca_verifier, resolve_grant=self.pca_resolve_grant, now=self.pca_now)
        return inputs
