"""MCP `tools/list` to drafts (native port of import/mcp.ts of the TypeScript reference @atlasauth/pca-actions). The annotations are HINTS from
the tool's own server and are untrusted: they can only add restriction (destructive, network egress); every output is `unreviewed`."""
from typing import Any

from .actions import ActionKitError
from .actions_import_common import add_todo, clip, emit_def, finish, flatten_object, is_obj, is_str, new_budget, new_ctx, resolve_schema, with_trait
from .intent_wb import _UNDEF, _utf16_len


def import_mcp(source: Any, opts: dict) -> dict:
    """`source` is a `tools/list` result {"tools": [...]} or the tool array itself."""
    c = new_ctx("mcp", source, opts)
    tools = source if isinstance(source, list) else source["tools"] if is_obj(source) and isinstance(source.get("tools"), list) else None
    if tools is None:
        raise ActionKitError("bad_source", "an MCP source is a tool array or a tools/list result {tools: [...]}")
    seen: set = set()
    for t in tools:
        if not is_obj(t) or not is_str(t.get("name")) or _utf16_len(t["name"]) == 0 or _utf16_len(t["name"]) > 256:
            add_todo(c, "(tool)", "skipped_op", "an entry without a usable name is skipped")
            continue
        name = t["name"]
        if name in seen:
            add_todo(c, name, "duplicate_tool", "a tool name listed twice; the first is kept")
            continue
        seen.add(name)
        c.root = t.get("inputSchema")
        bud = new_budget(c)
        inp = resolve_schema(t.get("inputSchema"), c, bud, "%s: inputSchema" % name)
        params: dict = {}
        flatten_object(inp, c, bud, name, params)
        a = t["annotations"] if is_obj(t.get("annotations")) else {}
        read = a.get("readOnlyHint") is True and a.get("destructiveHint") is not True
        effects = ["read"] if read else ["update", "delete"] if a.get("destructiveHint") is True else ["update"]
        emit_def(
            c, name, effects, "one", params, {"mcp": {"tool": clip(name, 256)}},
            title=a["title"] if is_str(a.get("title")) and len(a["title"]) > 0 else t.get("title", _UNDEF),
            description=t.get("description"),
            idempotency={"mode": "natural"} if a.get("idempotentHint") is True else None,
            traits=with_trait(None, "pca.network_egress") if a.get("openWorldHint") is True else None,
        )
    return finish(c)
