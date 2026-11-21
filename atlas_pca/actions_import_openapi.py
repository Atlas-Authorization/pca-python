"""OpenAPI 3.x and Swagger 2 to drafts (native port of import/openapi.ts of the TypeScript reference @atlasauth/pca-actions): one def per
operation, parameters from path / query / body (nested bodies flattened to dotted names), the method giving the initial effects. `x-`
extensions are ignored unless allow-listed. Every draft is `unreviewed`."""
import re
from functools import cmp_to_key
from typing import Any, List, Optional

from .actions import _JS_WS as _WS, ActionKitError, _jtruthy
from .actions_import_common import (
    UTF8_ORDER, add_todo, clip, emit_def, finish, flatten_object, g, is_obj, is_str, leaf_param, new_budget, new_ctx, param_seg, pointer,
    resolve_schema, spread_obj, tokens_of, verb_of,
)
from .intent_v2 import compare_utf8
from .intent_wb import _UNDEF, _utf16_len

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
EFFECT_OF = {"get": ["read"], "head": ["read"], "options": ["read"], "trace": ["read"], "post": ["create"], "put": ["update"], "patch": ["update"], "delete": ["delete"]}
NATURAL = ("get", "head", "options", "trace", "put", "delete")
BODY_TYPES = ("application/json", "application/x-www-form-urlencoded", "multipart/form-data")
_VERSIONISH = re.compile(r"(v[0-9]+(\.[0-9]+)?|api|rest|public|latest)", re.I | re.A)
_PARAM_SEG = re.compile("\\{[^\n\r\u2028\u2029]+\\}")
_VERB_EXT = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}")
_JSON_PLUS = re.compile(r"application/[^;]*\+json(;|\Z)", re.I | re.A)
_IDEM = re.compile(r"idempotency-key", re.I | re.A)


def _deref(c, x: Any, where: str) -> Any:
    """The object a `$ref` chain ends at (an array is possible: callers read members through g()); None when it does not resolve."""
    if not is_obj(x):
        return None
    if not is_str(x.get("$ref")):
        return x
    seen: list = []
    cur: Any = x
    while is_obj(cur) and is_str(cur.get("$ref")):
        if cur["$ref"] in seen or len(seen) > c.lim["max_ref_depth"]:
            add_todo(c, where, "cyclic_ref", "a reference chain is cyclic or too deep")
            return None
        seen.append(cur["$ref"])
        t = pointer(c.root, cur["$ref"])
        if t is None:
            add_todo(c, where, "unresolved_ref", "reference '%s' does not resolve locally" % clip(cur["$ref"], 120))
            return None
        cur = t
    return cur


def _path_facts(path: str):
    segs = [s for s in path.split("/") if len(s) > 0]
    ends = len(segs) > 0 and _PARAM_SEG.fullmatch(segs[-1]) is not None
    nouns = [t for s in segs if "{" not in s and "}" not in s and _VERSIONISH.fullmatch(s) is None for t in tokens_of(s)]
    return nouns, ends


def _swagger2_param(p: dict) -> dict:
    if "schema" in p or p.get("in") == "body":
        return p
    skip = ("name", "in", "required", "description")
    out = {k: p[k] for k in skip if k in p}
    out["schema"] = {k: v for k, v in p.items() if k not in skip}
    return out


def _body_schema(c, op: dict, params: List[dict], swagger: bool, where: str) -> Any:
    if swagger:
        for q in params:
            if q.get("in") == "body":
                return q.get("schema", _UNDEF)
        return _UNDEF
    rb = _deref(c, op.get("requestBody", _UNDEF), where)
    content = g(rb, "content")
    if not is_obj(content):
        return _UNDEF
    keys = sorted(content, key=UTF8_ORDER)
    pick = None
    for t in BODY_TYPES:
        pick = next((k for k in keys if k.lower().split(";")[0].strip(_WS) == t), None)
        if pick is not None:
            break
    if pick is None:
        pick = next((k for k in keys if _JSON_PLUS.match(k)), None)
    if pick is None:
        if len(keys) > 0:
            add_todo(c, where, "body_type", "request body media types (%s) are not form or JSON; the body is not declared" % ", ".join(clip(k, 40) for k in keys[:3]))
        return _UNDEF
    return g(content[pick], "schema")



def import_openapi(source: Any, opts: dict) -> dict:
    c = new_ctx("openapi", source, opts)
    if not is_obj(source):
        raise ActionKitError("bad_source", "an OpenAPI document must be an object")
    swagger = is_str(source.get("swagger")) and source["swagger"].startswith("2")
    v3 = is_str(source.get("openapi")) and source["openapi"].startswith("3.")
    if not swagger and not v3:
        raise ActionKitError("bad_source", "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')")
    paths = source["paths"] if is_obj(source.get("paths")) else {}
    global_security = source["security"] if isinstance(source.get("security"), list) else None
    for path in sorted(paths, key=UTF8_ORDER):
        item0 = _deref(c, paths[path], path)
        if item0 is None:
            continue
        shared = g(item0, "parameters")
        shared = shared if isinstance(shared, list) else []
        for method in METHODS:
            op = g(item0, method)
            if not is_obj(op):
                continue
            where = "%s %s" % (method.upper(), clip(path, 120))
            oid = op.get("operationId")
            operation_id = oid if is_str(oid) and 0 < _utf16_len(oid) <= 200 else None
            nouns, ends = _path_facts(path)
            name_raw = op.get("x-pca-verb") if is_str(op.get("x-pca-verb")) and "x-pca-verb" in c.ext else None
            if name_raw is not None and _VERB_EXT.fullmatch(name_raw) and name_raw.startswith(opts["ns"] + "."):
                verb = name_raw
            elif operation_id is not None:
                verb = verb_of(opts["ns"], operation_id)
            else:
                verb = verb_of(opts["ns"], " ".join([*nouns[-2:], "list" if method == "get" and not ends else method]))
            c.root = source
            bud = new_budget(c)
            merged: dict = {}
            own_params = op.get("parameters")
            for raw in [*shared, *(own_params if isinstance(own_params, list) else [])]:
                q0 = _deref(c, raw, where)
                if not is_obj(q0) or not is_str(q0.get("name")) or not is_str(q0.get("in")):
                    continue
                q = _swagger2_param(q0) if swagger else q0
                merged["%s:%s" % (q["in"], q["name"])] = q
            allp = list(merged.values())
            params: dict = {}
            idem_param: Optional[str] = None
            body = _body_schema(c, op, allp, swagger, where)
            if body is not _UNDEF:
                b = resolve_schema(body, c, bud, "%s: request body" % where)
                if b.get("type") == "object" or is_obj(b.get("properties")):
                    flatten_object(b, c, bud, where, params)
                else:
                    add_todo(c, where, "body_shape", "the request body is not an object schema; it is not declared")
            for q in sorted(allp, key=cmp_to_key(lambda a, b: compare_utf8("%s:%s" % (a["in"], a["name"]), "%s:%s" % (b["in"], b["name"])))):
                name = q["name"]
                if q["in"] == "header" and _IDEM.fullmatch(name):
                    idem_param = "idempotency_key"
                    continue
                if q["in"] == "body":
                    continue
                if q["in"] not in ("path", "query", "formData"):
                    add_todo(c, where, "param_location", "%s parameter '%s' is not an action parameter (path, query and body only)" % (clip(q["in"], 12), clip(name, 60)))
                    continue
                sname = param_seg(name)
                if sname != name:
                    add_todo(c, "%s: %s" % (where, name), "renamed_param", "parameter '%s' is declared as '%s'" % (clip(name, 80), sname))
                if sname in params or any(k.startswith(sname + ".") for k in params):
                    add_todo(c, "%s: %s" % (where, name), "skipped_param", "'%s' is declared by the body and by a %s parameter; kept the body's" % (sname, q["in"]))
                    continue
                if len(params) >= 64:
                    add_todo(c, where, "too_many_params", "more than 64 parameters; the rest are dropped")
                    break
                sq = q.get("schema")
                sq = {} if sq is None else sq
                qd = q.get("description", _UNDEF)
                extra = {"description": qd} if _jtruthy(qd) and not _jtruthy(g(sq, "description")) else {}
                sch = resolve_schema({**spread_obj(sq), **extra}, c, bud, "%s: %s" % (where, name))
                params[sname] = leaf_param(sch, q["in"] == "path" or q.get("required") is True, c, bud, "%s: %s" % (where, name))
            if idem_param is not None and idem_param not in params:
                params[idem_param] = {"type": "string", "required": False, "max_len": 255}
            else:
                idem_param = None
            scope = "one" if ends or method == "post" else "set"
            sec = op["security"] if isinstance(op.get("security"), list) else global_security
            scopes = sorted({x for r in (sec or []) if is_obj(r) for v in r.values() if isinstance(v, list) for x in v if is_str(x)}, key=UTF8_ORDER)
            if scopes:
                add_todo(c, where, "required_scope", "requires scope: %s" % ", ".join(clip(s, 60) for s in scopes[:12]))
            if op.get("deprecated") is True:
                add_todo(c, where, "deprecated", "the operation is marked deprecated")
            for k in op:
                if k.startswith("x-") and k not in c.ext:
                    add_todo(c, where, "extension_ignored", "extension '%s' is ignored (not allow-listed)" % clip(k, 60))
                    break
            summary = op.get("summary")
            desc = op.get("description")
            emit_def(
                c, operation_id if operation_id is not None else where, list(EFFECT_OF[method]), scope, params,
                {"openapi": {"operationId": operation_id if operation_id is not None else clip("%s_%s" % (method, path), 200), "method": method.upper(), "path": clip(path, 240)}},
                verb=verb, no_alias=operation_id is None,
                title=summary if is_str(summary) and len(summary) > 0 else operation_id,
                description=desc if is_str(desc) else summary if is_str(summary) else None,
                idempotency={"mode": "key_param", "param": idem_param} if idem_param is not None else {"mode": "natural"} if method in NATURAL else None,
            )
    return finish(c)
