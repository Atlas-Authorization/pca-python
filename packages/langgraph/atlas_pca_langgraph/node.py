"""Node-level PCA gating for LangGraph's ``ToolNode``.

:class:`PcaToolNode` is a drop-in replacement for ``langgraph.prebuilt.ToolNode``: a graph node
(callable) that reads the pending tool calls off the last message, requires a valid proof-carrying
action for *every* tool it would execute, and only then runs it — a denied call never touches the
underlying tool and comes back as an error ``ToolMessage`` (fail-closed), exactly as ``ToolNode``
surfaces a tool error to the model. :func:`guard_tool_node` wraps an existing ``ToolNode`` the same way.

Each tool's required capability comes from ``require``, which is one of:

* a ``"verb:resource"`` string applied to every tool;
* a mapping ``{tool_name: "verb:resource"}`` — a tool absent from the map needs only a *valid* proof
  (resource-server-correct), with no specific capability; or
* a callable ``(tool) -> "verb:resource" | None`` — ``None`` likewise means "valid proof, no capability".

Every tool is gated (a valid proof is always required); ``require`` only decides the *capability*.

The node is **duck-typed**: it reproduces the ``ToolNode`` contract itself (read ``state[messages_key]``
-> last message ``tool_calls`` -> run each tool -> return ``{messages_key: [ToolMessage, ...]}``) and
does not import ``langgraph``. It emits a real ``langchain_core`` ``ToolMessage`` when that package is
installed, else a structurally-identical duck-typed message, so tests need nothing installed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from ._proof import (
    PCA_ARG,
    PCA_CONFIG_KEY,
    PCA_STATE_KEY,
    resolve_proof,
)
from .tool import GuardedTool, PcaToolDenied, _parse_require, pca_tool
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: How each tool's required capability is chosen. See the module docstring.
RequireSpec = Union[str, Mapping[str, str], Callable[[Any], Optional[str]]]

#: Default state key LangGraph's ``ToolNode`` reads/writes (``MessagesState``'s ``messages``).
DEFAULT_MESSAGES_KEY = "messages"


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


def _tc_get(tc: Any, key: str) -> Any:
    if isinstance(tc, Mapping):
        return tc.get(key)
    return getattr(tc, key, None)


@dataclass
class _ToolCall:
    name: Optional[str]
    args: Dict[str, Any]
    id: Optional[str]


def _tool_calls_of(state: Any, messages_key: str) -> List[_ToolCall]:
    """The pending tool calls on the last message of ``state[messages_key]`` (duck-typed, never raises)."""
    if isinstance(state, Mapping):
        messages = state.get(messages_key)
    else:
        messages = getattr(state, messages_key, None)
    if not messages:
        return []
    try:
        last = messages[-1]
    except (TypeError, IndexError, KeyError):
        return []
    raw = getattr(last, "tool_calls", None)
    if raw is None and isinstance(last, Mapping):
        raw = last.get("tool_calls")
    if not raw:
        return []
    calls: List[_ToolCall] = []
    for tc in raw:
        args = _tc_get(tc, "args")
        calls.append(_ToolCall(name=_tc_get(tc, "name"),
                               args=dict(args) if isinstance(args, Mapping) else {},
                               id=_tc_get(tc, "id")))
    return calls


@dataclass
class ToolMessageLike:
    """A duck-typed ``langchain_core`` ``ToolMessage`` (used when ``langchain_core`` is not installed)."""

    content: Any
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    status: str = "success"
    type: str = "tool"
    additional_kwargs: Dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


def _make_tool_message(content: Any, *, name: Optional[str], tool_call_id: Optional[str],
                       status: str) -> Any:
    """A real ``ToolMessage`` when ``langchain_core`` is present, else a :class:`ToolMessageLike`."""
    try:
        from langchain_core.messages import ToolMessage
    except Exception:
        return ToolMessageLike(content=content, name=name, tool_call_id=tool_call_id, status=status)
    msg_content = content if isinstance(content, (str, list)) else repr(content)
    msg_status = "error" if status == "error" else "success"
    return ToolMessage(content=msg_content, name=name or "", tool_call_id=tool_call_id or "",
                       status=msg_status)


class PcaToolNode:
    """A ``ToolNode``-shaped graph node that requires a valid proof-carrying action for every tool call.

    Construct it from the same tool list a ``ToolNode`` takes. Calling it with the graph state runs the
    pending tool calls — each gated by the reference verifier for this node's ``audience`` and the
    tool's resolved capability — and returns ``{messages_key: [ToolMessage, ...]}``. A denied call does
    not run the tool; its ``ToolMessage`` carries the denial reason with ``status="error"``.

    ``audience``       — this node's RFC 8707 resource id; a proof minted for another audience is rejected.
    ``require``        — a :data:`RequireSpec` choosing each tool's capability (see the module docstring).
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required unless ``verifier`` is supplied.
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``now``            — epoch-ms validity clock (default: wall clock); used only for the default verifier.
    ``messages_key``   — the state key the pending calls are read from and the results written to.
    """

    def __init__(self, tools: List[Any], *, audience: str, require: RequireSpec,
                 resolve_grant: Optional[GrantResolver] = None, verifier: Optional[Verifier] = None,
                 now: Optional[int] = None, messages_key: str = DEFAULT_MESSAGES_KEY,
                 arg_name: str = PCA_ARG, state_key: str = PCA_STATE_KEY,
                 config_key: str = PCA_CONFIG_KEY) -> None:
        if not audience:
            raise ValueError("PcaToolNode requires a non-empty `audience`")
        if verifier is None:
            if resolve_grant is None:
                raise ValueError("PcaToolNode requires either `verifier=` or `resolve_grant=`")
            verifier = CoreVerifier(resolve_grant, now=now)
        elif resolve_grant is not None:
            raise ValueError("pass either `verifier=` or `resolve_grant=`, not both")

        self.audience = audience
        self.messages_key = messages_key
        self._arg_name = arg_name
        self._state_key = state_key
        self._config_key = config_key
        self._verifier: Verifier = verifier
        # Wrap every tool with pca_tool so gating runs through the single CoreVerifier path. Each tool's
        # required capability is fixed at wrap time from `require`; `_parse_require` validates it eagerly.
        self.guarded_by_name: Dict[str, GuardedTool] = {}
        self._required_by_name: Dict[str, Optional[str]] = {}
        for tool in tools:
            name = _tool_name(tool)
            if name is None:
                raise ValueError("every tool must have a `name`; got %r" % (tool,))
            req = _require_for(tool, require)
            _parse_require(req)  # eager validation of a bad 'verb:resource' entry
            guarded = pca_tool(req, audience=audience, verifier=verifier)(tool)
            self.guarded_by_name[name] = guarded if isinstance(guarded, GuardedTool) else GuardedTool(
                name=name, description=getattr(guarded, "description", "") or "",
                guarded=getattr(guarded, "func"), required=req)
            self._required_by_name[name] = req

    def invoke(self, state: Any, config: Any = None) -> Dict[str, Any]:
        return self.__call__(state, config)

    async def ainvoke(self, state: Any, config: Any = None) -> Dict[str, Any]:
        return self.__call__(state, config)

    def __call__(self, state: Any, config: Any = None) -> Dict[str, Any]:
        proof = resolve_proof(state=state, config=config, state_key=self._state_key,
                              config_key=self._config_key)
        out: List[Any] = []
        for call in _tool_calls_of(state, self.messages_key):
            name = call.name
            guarded = self.guarded_by_name.get(name) if name is not None else None
            if guarded is None:
                out.append(_make_tool_message(
                    "no such guarded tool: %r" % (name,), name=name, tool_call_id=call.id,
                    status="error"))
                continue
            try:
                # Carry the node-scoped proof to the gated tool inline; the wrapper re-verifies it for
                # this tool's capability and fails closed (raising) before the inner tool can run.
                result = guarded.run(pca_action=proof, **call.args)
            except PcaToolDenied as denied:
                out.append(_make_tool_message(
                    denied.decision.reason or "proof-carrying authority required",
                    name=name, tool_call_id=call.id, status="error"))
                continue
            out.append(_make_tool_message(result, name=name, tool_call_id=call.id, status="success"))
        return {self.messages_key: out}


try:  # type the injected ``config`` so a real LangGraph does not warn about an untyped parameter
    from langchain_core.runnables import RunnableConfig as _RunnableConfig

    PcaToolNode.__call__.__annotations__["config"] = _RunnableConfig
except Exception:  # langchain-core is optional
    pass


def _tools_of(tool_node: Any) -> List[Any]:
    """Extract the tool objects from a ``ToolNode`` (``.tools_by_name``), or a plain list of tools."""
    by_name = getattr(tool_node, "tools_by_name", None)
    if isinstance(by_name, Mapping):
        return list(by_name.values())
    tools = getattr(tool_node, "tools", None)
    if isinstance(tools, (list, tuple)):
        return list(tools)
    if isinstance(tool_node, (list, tuple)):
        return list(tool_node)
    raise TypeError("guard_tool_node expected a ToolNode or a list of tools, got %r" % (tool_node,))


def guard_tool_node(tool_node: Any, *, audience: str, require: RequireSpec,
                    resolve_grant: Optional[GrantResolver] = None, verifier: Optional[Verifier] = None,
                    now: Optional[int] = None, messages_key: str = DEFAULT_MESSAGES_KEY,
                    arg_name: str = PCA_ARG, state_key: str = PCA_STATE_KEY,
                    config_key: str = PCA_CONFIG_KEY) -> PcaToolNode:
    """Gate every tool an existing ``ToolNode`` would execute, returning a :class:`PcaToolNode`.

    Pull the tools out of ``tool_node`` (its ``tools_by_name``) and rebuild the node with PCA gating on
    each one::

        base = ToolNode([place_order, cancel_order])
        guarded = guard_tool_node(base, audience="rs-orders",
                                  require={"place_order": "write:db/orders"},
                                  resolve_grant=resolve)
        graph.add_node("tools", guarded)
    """
    return PcaToolNode(_tools_of(tool_node), audience=audience, require=require,
                       resolve_grant=resolve_grant, verifier=verifier, now=now,
                       messages_key=messages_key, arg_name=arg_name, state_key=state_key,
                       config_key=config_key)
