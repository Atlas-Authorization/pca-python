"""OpenAI adapter: turn a chat `tool_call` into a PCActn, run your handler with the proof, return the `tool` message.

Duck-typed: tool calls may be dicts or SDK objects (`.id`, `.function.name`, `.function.arguments`); the `openai` package is never
imported. Does not authorize; the resource server's verifier decides (the TypeScript reference, @atlasauth/pca-openai).
"""
import inspect
import json
from typing import Any, Callable, Dict, List, Optional

from atlas_pca.adapters import (PcaCall, bridge_tool_call, js_json, provenance_headers, record_input, record_messages, record_principal,
                                record_tool_result)

__all__ = ["dispatch_tool_call", "dispatch_tool_calls", "with_pca_completions", "PcaCall", "provenance_headers", "record_input",
           "record_messages", "record_principal"]


def _get(o: Any, k: str) -> Any:
    return o.get(k) if isinstance(o, dict) else getattr(o, k, None)


def _parse_arguments(raw: Any) -> Dict[str, Any]:
    if raw is None or (isinstance(raw, str) and raw.strip() == ""):
        return {}
    parsed = json.loads(raw.strip() if isinstance(raw, str) else raw)
    if not isinstance(parsed, dict):
        raise ValueError("dispatchToolCall: tool_call arguments must be a JSON object")
    return parsed


async def dispatch_tool_call(agent: Any, call: Any, mapping: Callable[[Dict[str, Any]], Optional[Dict[str, str]]],
                             handlers: Dict[str, Callable[..., Any]]) -> Dict[str, str]:
    """Build + sign a PCActn for one tool call, run `handlers[name](args, pca)` (sync or async) and return the `tool` message.
    Raises ValueError when `mapping` declines the tool: no tool runs without a proof."""
    fn = _get(call, "function")
    name = _get(fn, "name")
    args = _parse_arguments(_get(fn, "arguments"))
    pca = bridge_tool_call(agent, {"name": name, "arguments": args}, mapping)
    if pca is None:
        raise ValueError('dispatchToolCall: no PCActn for unmapped tool "%s" (the mapping declined)' % name)
    handler = handlers.get(name)
    result = handler(args, pca) if handler else None
    if inspect.isawaitable(result):
        result = await result
    content = js_json({"pca": pca.encoded} if result is None else result)
    record_tool_result(agent, name, content)  # the tool message re-enters the model's context: untrusted from here on
    return {"role": "tool", "tool_call_id": _get(call, "id"), "content": content}


async def dispatch_tool_calls(agent: Any, calls: List[Any], mapping: Callable[[Dict[str, Any]], Optional[Dict[str, str]]],
                              handlers: Dict[str, Callable[..., Any]]) -> List[Dict[str, str]]:
    """Dispatch a model turn's tool calls sequentially (each PCActn takes the next counter)."""
    return [await dispatch_tool_call(agent, c, mapping, handlers) for c in calls]


def with_pca_completions(agent: Any, create: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap `client.chat.completions.create` (or any call taking `messages=`) so every model turn first records the conversation's new
    messages (`user` turns are the principal, `tool` turns untrusted). Works for sync and async `create`."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        msgs = kwargs.get("messages")
        if msgs is None and args and isinstance(args[0], dict):
            msgs = args[0].get("messages")
        record_messages(agent, msgs)
        return create(*args, **kwargs)
    return wrapper
