"""AsyncAPI 2.x / 3.x to drafts (native port of import/asyncapi.ts of the TypeScript reference @atlasauth/pca-actions). Sending to a channel is
effect `send`, receiving is `read`; the message payload becomes the params. A broker publish leaves the trust domain, so it stays `send`
unless the channel carries the allow-listed `x-pca-internal: true`."""
import re
from typing import Any, List, Optional

from .actions import ActionKitError
from .actions_import_common import (
    UTF8_ORDER, add_todo, clip, emit_def, finish, flatten_object, g, is_obj, is_str, new_budget, new_ctx, param_seg, pointer, resolve_schema, verb_of,
)
from .intent_wb import _UNDEF


def _deref(c, x: Any, where: str, depth: int = 0) -> Optional[dict]:
    if not is_obj(x):
        return None
    if not is_str(x.get("$ref")):
        return x
    if depth > c.lim["max_ref_depth"]:
        add_todo(c, where, "ref_depth", "a reference chain is too deep")
        return None
    t = pointer(c.root, x["$ref"])
    if t is None:
        add_todo(c, where, "unresolved_ref", "reference '%s' does not resolve locally" % clip(x["$ref"], 120))
        return None
    return _deref(c, t, where, depth + 1)


def _payload_params(c, msgs: List[Any], where: str, params: dict, bud) -> None:
    resolved = [m for m in (_deref(c, m, where) for m in msgs) if m is not None]
    if not resolved:
        return
    if len(resolved) > 1:
        add_todo(c, where, "message_variants", "%d message variants: only the first is declared" % len(resolved))
    payload = resolved[0].get("payload", _UNDEF)
    if payload is _UNDEF:
        return
    s = resolve_schema(payload, c, bud, "%s: payload" % where)
    if s.get("type") == "object" or is_obj(s.get("properties")):
        flatten_object(s, c, bud, where, params)
    else:
        add_todo(c, where, "payload_shape", "the message payload is not an object schema; it is not declared")


def _channel_params(c, ch: dict, where: str, params: dict) -> None:
    ps = _deref(c, ch.get("parameters"), where)
    if ps is None:
        return
    for name in sorted(ps, key=UTF8_ORDER):
        s = param_seg(name)
        if s in params:
            continue
        params[s] = {"type": "string", "max_len": 256}


def import_asyncapi(source: Any, opts: dict) -> dict:
    c = new_ctx("asyncapi", source, opts)
    if not is_obj(source) or not is_str(source.get("asyncapi")) or re.match(r"[23]\.", source["asyncapi"]) is None:
        raise ActionKitError("bad_source", "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')")
    v3 = source["asyncapi"].startswith("3")
    channels = source["channels"] if is_obj(source.get("channels")) else {}

    def internal(ch: dict) -> bool:
        return "x-pca-internal" in c.ext and ch.get("x-pca-internal") is True

    def emit(op_name: Optional[str], ch_name: str, ch: dict, action: str, op: dict, msgs: list) -> None:
        where = "%s %s" % (action, clip(ch_name, 100))
        bud = new_budget(c)
        c.root = source
        params: dict = {}
        _channel_params(c, ch, where, params)
        _payload_params(c, msgs, where, params, bud)
        effects = ["read"] if action == "receive" else ["create"] if internal(ch) else ["send"]
        emit_def(
            c, op_name if op_name is not None else where, effects, "one", params, {"asyncapi": {"channel": clip(ch_name, 250), "op": action}},
            verb=verb_of(opts["ns"], "%s %s" % (ch_name, action)) if op_name is None else None, no_alias=op_name is None,
            title=op["summary"] if is_str(op.get("summary")) else None, description=op["description"] if is_str(op.get("description")) else None,
        )

    if v3:
        ops = source["operations"] if is_obj(source.get("operations")) else {}
        for oid in sorted(ops, key=UTF8_ORDER):
            op = _deref(c, ops[oid], oid)
            if op is None or op.get("action") not in ("send", "receive") or not is_str(op.get("action")):
                add_todo(c, oid, "skipped_op", "an operation without action send|receive is skipped")
                continue
            ch_ref = _deref(c, op.get("channel"), oid)
            if ch_ref is None:
                continue
            chan = op.get("channel")
            ch_name = ch_ref["address"] if is_str(ch_ref.get("address")) else (chan["$ref"].split("/")[-1] if is_obj(chan) and is_str(chan.get("$ref")) else oid)
            if isinstance(op.get("messages"), list) and len(op["messages"]) > 0:
                msgs = op["messages"]
            elif is_obj(ch_ref.get("messages")):
                msgs = [ch_ref["messages"][k] for k in sorted(ch_ref["messages"], key=UTF8_ORDER)]
            else:
                msgs = []
            emit(oid, ch_name, ch_ref, op["action"], op, msgs)
    else:
        for ch_name in sorted(channels, key=UTF8_ORDER):
            ch = _deref(c, channels[ch_name], ch_name)
            if ch is None:
                continue
            for key, action in (("publish", "send"), ("subscribe", "receive")):
                op = _deref(c, ch.get(key), ch_name)
                if op is None:
                    continue
                m = _deref(c, op.get("message"), ch_name)
                msgs = m["oneOf"] if m is not None and isinstance(m.get("oneOf"), list) else [m] if m is not None else []
                oid = op.get("operationId")
                emit(oid if is_str(oid) and len(oid) > 0 else None, ch_name, ch, action, op, msgs)
    return finish(c)
