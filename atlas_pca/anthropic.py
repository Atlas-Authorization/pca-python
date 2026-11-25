"""Anthropic (Claude) adapter: turn a `tool_use` block into a PCActn, run your handler, return the `tool_result` block.

Duck-typed: blocks may be dicts or SDK objects (`.type`, `.id`, `.name`, `.input`); the `anthropic` package is never imported.
A declined tool, a missing handler or a raising handler yields an `is_error` result, as the TypeScript reference
(@atlasauth/pca-anthropic) does. Does not authorize; the resource server's verifier decides.
"""
import asyncio
import inspect
from typing import Any, Callable, Dict, List, Optional

from atlas_pca.adapters import (PcaCall, bridge_tool_call, js_json, provenance_headers, record_input, record_messages, record_principal,
                                record_tool_result)

__all__ = ["handle_tool_use", "handle_tool_uses", "extract_tool_uses", "with_pca_messages", "PcaCall", "provenance_headers",
           "record_input", "record_messages", "record_principal"]


def _get(o: Any, k: str) -> Any:
    return o.get(k) if isinstance(o, dict) else getattr(o, k, None)


def _err(block_id: Any, content: str) -> Dict[str, Any]:
    return {"type": "tool_result", "tool_use_id": block_id, "content": content, "is_error": True}


async def handle_tool_use(agent: Any, block: Any, mapping: Callable[[Dict[str, Any]], Optional[Dict[str, str]]],
                          handlers: Dict[str, Callable[..., Any]]) -> Dict[str, Any]:
    """Build the PCActn for one `tool_use` block, run `handlers[name](input, pca)` (sync or async), return the `tool_result`.
    `content` is the compact JSON of the result, or `{"pca": <encoded>}` when the handler returns None."""
    name, bid, inp = _get(block, "name"), _get(block, "id"), _get(block, "input")
    pca = bridge_tool_call(agent, {"name": name, "arguments": inp}, mapping)
    if pca is None:
        return _err(bid, 'No proof-carrying authority is mapped for tool "%s".' % name)
    handler = handlers.get(name)
    if not handler:
        return _err(bid, 'No handler registered for tool "%s".' % name)
    try:
        result = handler(inp, pca)
        if inspect.isawaitable(result):
            result = await result
        content = js_json({"pca": pca.encoded} if result is None else result)
        record_tool_result(agent, name, content)  # the tool_result re-enters Claude's context: untrusted from here on
        return {"type": "tool_result", "tool_use_id": bid, "content": content}
    except Exception as e:  # noqa: BLE001 - the model sees the refusal text
        record_tool_result(agent, name, str(e))  # a tool's error text reaches Claude too, and a tool can put anything in it
        return _err(bid, str(e))


async def handle_tool_uses(agent: Any, blocks: List[Any], mapping: Callable[[Dict[str, Any]], Optional[Dict[str, str]]],
                           handlers: Dict[str, Callable[..., Any]]) -> List[Dict[str, Any]]:
    """Handle every `tool_use` block concurrently, preserving order (other block types are ignored)."""
    return list(await asyncio.gather(*[handle_tool_use(agent, b, mapping, handlers) for b in extract_tool_uses(blocks)]))


def extract_tool_uses(content: List[Any]) -> List[Any]:
    """The `tool_use` blocks of an assistant message's content."""
    return [b for b in content if _get(b, "type") == "tool_use"]


def with_pca_messages(agent: Any, create: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap `client.messages.create` (or any call taking `messages=`) so every model turn first records the conversation's new messages
    (user text is the principal; `tool_result` blocks are untrusted). Works for sync and async `create`."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        msgs = kwargs.get("messages")
        if msgs is None and args and isinstance(args[0], dict):
            msgs = args[0].get("messages")
        record_messages(agent, msgs)
        return create(*args, **kwargs)
    return wrapper
