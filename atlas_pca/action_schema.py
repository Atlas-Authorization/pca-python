"""The site-signed action schema surface that completes the TypeScript reference's ``action-schema`` module: the signing and key helpers, the value-dependent
reversibility class, the wallet floor test, and the v1 drafting importers that turn an MCP ``tools/list`` or an OpenAPI document into a DRAFT schema with a
todo list of the decisions the developer must make (semantic types, sensitivities, units, reversibility). The vocabulary constants, the shape, signature and
conformance checks live in :mod:`atlas_pca.intent_v2` and are re-exported here. The importers are pure over JSON, fail closed (every write verb is drafted
irreversible, every sensitivity ``material``, an unrepresentable shape a ``string`` placeholder flagged in ``todo``) and mirror the reference's JSON Schema
flattening ($ref / allOf / anyOf / oneOf, with reference-depth and expansion bounds)."""
from __future__ import annotations

from ._fin import fin
import functools
import math
import re
from typing import Any, Dict, List, Optional

from .agent import KeyPair, PqKeyPair, sign_with_suite
from .intent_schema import WALLET_FLOOR_EXACT, WALLET_FLOOR_PREFIXES, _floor_applies, effective_sensitivity, verb_reversibility, wallet_floor_overrides
from .intent_v2 import (ACTION_SCHEMA_DOMAIN, ACTION_SCHEMA_KIND, ACTION_SCHEMA_REF_DOMAIN, DEFAULT_MAX_ITEMS, DEFAULT_MAX_LEN, MAX_SCHEMA_PARAMS,
                        MAX_SCHEMA_VALUES, MAX_SCHEMA_VERBS, PARAM_PATH_RE, PARAM_PATH_RE_V2, PARAM_TYPES, PARAM_TYPES_V2, SCHEMA_REVERSIBILITY,
                        SCHEMA_V2_CAVEATS, SCHEMA_V2_CONTEXT, SCHEMA_V2_EFFECTS, SCHEMA_V2_PROVENANCE, SCHEMA_V2_PRULES, SCHEMA_V2_TAGS, SENSITIVITIES,
                        UNIT_ID_RE, _UNDEF, _js_string, _schema_message, accumulation_params, action_schema_digest, action_schema_shape_error,
                        compare_utf8, conform_action, schema_verb, verify_action_schema)
from .pca import _SIG_SUITES, b64u, canonical_bytes_strict  # noqa: F401

__all__ = ["WELL_KNOWN_PCA_ACTIONS_PATH", "sign_action_schema", "action_schema_key_of", "reversibility_of", "floor_applies", "reversibility_from_mcp_hints",
           "draft_schema_from_mcp_tools", "draft_schema_from_openapi"]

WELL_KNOWN_PCA_ACTIONS_PATH = "/.well-known/pca-actions.json"
floor_applies = _floor_applies
_UTF8 = functools.cmp_to_key(compare_utf8)
_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
_MAX_REF_DEPTH = 8
_MAX_REF_NODES = 20_000


# ---- signing ----

def _kid_ok(kid: Any) -> bool:
    """A non-empty string of at most 128 UTF-8 bytes without a lone surrogate (what the verifier accepts as a kid)."""
    if not isinstance(kid, str) or kid == "":
        return False
    try:
        return len(kid.encode("utf-8")) <= 128
    except UnicodeEncodeError:
        return False


def sign_action_schema(doc: dict, kid: str, site_secret: bytes, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """Sign an unsigned schema as the site: ``kid`` names the discovery key entry, ``alg`` / ``pq`` select the suite (default Ed25519). Raises for a
    shape-invalid document or an unusable suite. Returns the document with ``sig`` = {alg, kid, value, pq_value?}."""
    bad = action_schema_shape_error(doc, signed=False)
    if bad:
        raise ValueError("signActionSchema: %s" % bad)
    if not _kid_ok(kid):
        raise ValueError("signActionSchema: sig.kid must be a non-empty string")
    parts = sign_with_suite(alg, KeyPair(bytes(site_secret), allow_insecure_signer=True), pq, _schema_message(doc))
    sig: Dict[str, Any] = {"alg": alg or "ed25519", "kid": kid, "value": parts["sig"]}
    if "pq_sig" in parts:
        sig["pq_value"] = parts["pq_sig"]
    return dict(doc, sig=sig)


def action_schema_key_of(kid: str, site_secret: bytes, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """The discovery key entry of a signer: ``{"kid", "alg", "pk", "pq_pk"?}`` (``pq_pk`` for the suites that carry one). Raises for an unknown suite."""
    if not _kid_ok(kid):
        raise ValueError("actionSchemaKeyOf: kid must be a non-empty string")
    suite = _SIG_SUITES.get(alg or "ed25519")
    if suite is None:
        raise ValueError("unknown signature alg '%s'" % alg)
    key: Dict[str, Any] = {"kid": kid, "alg": alg or "ed25519", "pk": KeyPair(bytes(site_secret), allow_insecure_signer=True).public}
    if suite[1] and pq is not None:
        key["pq_pk"] = pq.public
    return key


# ---- value-dependent reversibility ----

def _key_of_value(x: Any) -> Optional[str]:
    if isinstance(x, str):
        return x
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, (int, float)) and not (isinstance(x, float) and (not fin(x) or (x == 0 and math.copysign(1, x) < 0))):
        if x == int(x) and abs(x) <= 9007199254740991:
            return str(int(x))
    return None


def reversibility_of(v: dict, params: dict) -> str:
    """rev(v, omega): the value-dependent class. An unmapped or absent value gives the declared ``default``, else irreversible (fail closed); only own
    members of the map match."""
    rb = v.get("reversibility_by")
    if rb:
        name = rb["param"][len("action.params."):]
        k = _key_of_value(params.get(name)) if name in params else None
        if k is not None and k in rb["map"]:
            return rb["map"][k]
        return rb["default"] if rb.get("default") is not None else "irreversible"
    r = v.get("reversibility")
    return r if r is not None else ("reversible" if v.get("kind") == "read" else "irreversible")


# ---- importers ----

def reversibility_from_mcp_hints(a: Any) -> Dict[str, str]:
    """MCP annotations are HINTS: they only give a lower bound on reversibility."""
    a = a if isinstance(a, dict) else {}
    if a.get("readOnlyHint") is True:
        return {"kind": "read", "atLeast": "reversible"}
    if a.get("destructiveHint") is True:
        return {"kind": "write", "atLeast": "rate_limited"}
    return {"kind": "write", "atLeast": "reversible"}


def _u16(s: str, n: int) -> str:
    """s.slice(0, n) by UTF-16 code units."""
    b = s.encode("utf-16-le", "surrogatepass")
    return s if len(b) <= 2 * n else b[:2 * n].decode("utf-16-le", "surrogatepass")


def _truthy(x: Any) -> bool:
    return not (x is None or x is _UNDEF or x is False or x == 0 or x == "" or (isinstance(x, float) and x != x))


def _safe_int(x: Any) -> bool:
    return not isinstance(x, bool) and isinstance(x, (int, float)) and fin(x) and x == int(x) and abs(x) <= 9007199254740991


def _pointer(root: Any, ref: str) -> Any:
    """Follow a local ``#/a/b`` JSON pointer; None when absent, not local, or not an object / array."""
    if not ref.startswith("#/"):
        return None
    cur = root
    for raw in ref[2:].split("/"):
        seg = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.isdigit() and str(int(seg)) == seg and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return None
    return cur if isinstance(cur, (dict, list)) else None


class _Ctx:
    def __init__(self, root: Any, todo: List[str]) -> None:
        self.root, self.todo, self.left = root, todo, None


def _is_null_type(m: dict) -> bool:
    t = m.get("type")
    return t == "null" or (isinstance(t, list) and all(x == "null" for x in t))


def _all_of(members: list) -> dict:
    acc: Dict[str, Any] = {}
    for m in members:
        props = dict(acc.get("properties") or {})
        props.update(m.get("properties") or {})
        req = list(acc.get("required") or []) + list(m.get("required") or [])
        acc = dict(acc, **m)
        acc["properties"], acc["required"] = props, req
    return acc


def _flatten(s: Any, c: _Ctx, where: str, depth: int = 0) -> dict:
    """Follow local $refs, merge allOf and collapse anyOf / oneOf to the single non-null variant (or the union of string constants); what stays
    unrepresentable is flagged in ``todo`` and left as an empty schema (declared string by the caller)."""
    if not isinstance(s, dict):
        return {}
    c.left = (_MAX_REF_NODES if c.left is None else c.left) - 1
    if c.left < 0:
        if c.left == -1:
            c.todo.append("%s: schema expansion stopped after %d nodes (declared string; refine or drop)" % (where, _MAX_REF_NODES))
        return {}
    if depth > _MAX_REF_DEPTH:
        c.todo.append("%s: schema nesting or reference chain deeper than %d (declared string; refine or drop)" % (where, _MAX_REF_DEPTH))
        return {}
    cur = s
    if isinstance(s.get("$ref"), str):
        target = _pointer(c.root, s["$ref"])
        if target is None:
            c.todo.append("%s: reference '%s' is not a local reference that resolves (declared string; refine or drop)" % (where, _u16(s["$ref"], 120)))
            return {}
        siblings = {k: v for k, v in s.items() if k != "$ref"}
        cur = dict(_flatten(target, c, where, depth + 1), **siblings)
    if isinstance(cur.get("allOf"), list):
        rest = {k: v for k, v in cur.items() if k != "allOf"}
        cur = dict(_all_of([_flatten(m, c, where, depth + 1) for m in cur["allOf"]]), **rest)
    alts = cur.get("anyOf") if cur.get("anyOf") is not None else cur.get("oneOf")
    if isinstance(alts, list):
        rest = {k: v for k, v in cur.items() if k not in ("anyOf", "oneOf")}
        live = [m for m in (_flatten(m, c, where, depth + 1) for m in alts) if not _is_null_type(m)]
        if len(live) == 1:
            return dict(live[0], **rest)
        consts: List[Optional[list]] = []
        for m in live:
            if isinstance(m.get("const"), str):
                consts.append([m["const"]])
            elif isinstance(m.get("enum"), list) and all(isinstance(x, str) for x in m["enum"]):
                consts.append(m["enum"])
            else:
                consts.append(None)
        if len(live) > 1 and all(x is not None for x in consts):
            return dict(rest, type="string", enum=list(dict.fromkeys(x for xs in consts for x in xs)))  # type: ignore[union-attr]
        c.todo.append("%s: a union of %d schemas has no schema representation (declared string; refine or drop)" % (where, len(live)))
        return rest
    if "const" in cur and "enum" not in cur and isinstance(cur["const"], str):
        cur = dict(cur, enum=[cur["const"]])
    return cur


def _enum_strings(v: Any) -> Optional[list]:
    return v if isinstance(v, list) and all(isinstance(x, str) for x in v) else None


def _decl(name: str, schema: Any, required: bool, c: _Ctx) -> dict:
    """JSON Schema property -> parameter declaration. Sensitivity defaults to ``material`` (the importer never marks anything free); unrepresentable
    shapes become ``string`` placeholders flagged in ``todo``."""
    todo = c.todo
    s = _flatten(schema, c, "action.params.%s" % name)
    t = s.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), None)
    base: Dict[str, Any] = {"semantic": s["x-pca-semantic"] if s.get("x-pca-semantic") is not None else "unknown",
                            "sensitivity": s["x-pca-sensitivity"] if s.get("x-pca-sensitivity") is not None else "material"}
    if not required:
        base["required"] = False
    if _truthy(s.get("description")):
        base["description"] = _u16(s["description"], 1024)
    if not _truthy(s.get("x-pca-semantic")):
        todo.append("action.params.%s: semantic type" % name)
    enum_strings = _enum_strings(s.get("enum"))
    if t == "integer":
        out: Dict[str, Any] = dict(type="integer", **base)
        if _safe_int(s.get("minimum")):
            out["min"] = s["minimum"]
        elif _safe_int(s.get("exclusiveMinimum")):
            out["min"] = s["exclusiveMinimum"] + 1
        if _safe_int(s.get("maximum")):
            out["max"] = s["maximum"]
        elif _safe_int(s.get("exclusiveMaximum")):
            out["max"] = s["exclusiveMaximum"] - 1
        if _truthy(s.get("x-pca-unit")):
            out["unit"] = s["x-pca-unit"]
        if _truthy(s.get("x-pca-accumulates-into")):
            out["accumulates_into"] = s["x-pca-accumulates-into"]
        return out
    if t == "boolean":
        return dict(type="boolean", **base)
    if t == "string" and s.get("format") == "date":
        return dict(type="date", **base)
    if t == "string":
        out = dict(type="string", **base)
        if enum_strings is not None:
            out["values"] = enum_strings
        if _safe_int(s.get("maxLength")) and s["maxLength"] > 0:
            out["max_len"] = s["maxLength"]
        return out
    if t == "array":
        it = _flatten(s.get("items"), c, "action.params.%s[]" % name)
        it_enum = _enum_strings(it.get("enum"))
        if _truthy(s.get("uniqueItems")) and it_enum is not None:
            out = dict(type="set", **base, values=it_enum)
            if _safe_int(s.get("minItems")):
                out["min_items"] = s["minItems"]
            if _safe_int(s.get("maxItems")):
                out["max_items"] = s["maxItems"]
            return out
        it_t = it.get("type")
        if isinstance(it_t, list):
            it_t = it_t[0] if it_t else None
        out = dict(type="array", **base)
        if it_t == "integer":
            out["items"] = "integer"
        if _safe_int(s.get("maxItems")):
            out["max_items"] = s["maxItems"]
        if _safe_int(s.get("minItems")):
            out["min_items"] = s["minItems"]
        return out
    todo.append("action.params.%s: type '%s' has no schema representation (declared string; refine or drop)" % (name, _js_string(t if t is not None else _UNDEF)))
    return dict(type="string", **base)


def _draft(site: dict, verbs: list) -> dict:
    verbs.sort(key=lambda v: _UTF8(v["verb"]))
    return {"v": 1, "kind": ACTION_SCHEMA_KIND, "site": site.get("site"), "aud": site.get("aud"), "version": site.get("version"), "verbs": verbs}


def draft_schema_from_mcp_tools(tools: list, site: dict) -> Dict[str, Any]:
    """A DRAFT schema from an MCP ``tools/list`` (``site`` = {site, aud, version, verbPrefix?}): ``{"schema": unsigned schema, "todo": [...]}``. Verb =
    prefix + tool name; every write verb is drafted irreversible (a destructive hint can only keep it at least rate_limited). Raises on a null tool."""
    todo: List[str] = []
    verbs: List[dict] = []
    for t in tools:
        if t is None:
            raise TypeError("Cannot read properties of null (reading 'inputSchema')")
        t = t if isinstance(t, dict) else {}
        schema_in = t.get("inputSchema")
        c = _Ctx(schema_in, todo)
        name_t = _js_string(t.get("name", _UNDEF))
        inp = _flatten(schema_in, c, "%s: inputSchema" % name_t)
        props = inp.get("properties") if isinstance(inp.get("properties"), dict) else {}
        req = set(inp["required"]) if isinstance(inp.get("required"), list) else set()
        params: Dict[str, dict] = {}
        for name in sorted(props, key=_UTF8):
            if _NAME.fullmatch(name) is None:
                todo.append("%s: parameter '%s' is not a schema name ([A-Za-z0-9_]{1,64}); rename it" % (name_t, name))
                continue
            params["action.params." + name] = _decl(name, props[name], name in req, c)
        h = reversibility_from_mcp_hints(t.get("annotations"))
        verb = (site["verbPrefix"] if site.get("verbPrefix") is not None else "") + name_t
        if h["kind"] == "write":
            todo.append("%s: reversibility (drafted irreversible)" % verb)
        v = {"verb": verb, "kind": h["kind"], "params": params, "reversibility": "reversible" if h["kind"] == "read" else "irreversible",
             "mcp": {"tool": t["name"]} if "name" in t else {}}
        if _truthy(t.get("description")):
            v["description"] = _u16(t["description"], 1024)
        verbs.append(v)
    return {"schema": _draft(site, verbs), "todo": todo}


def _json_body_schema(b: Any) -> Any:
    content = b.get("content") if isinstance(b, dict) else None
    if not isinstance(content, dict):
        return None
    keys = sorted(content, key=_UTF8)
    key = next((k for k in keys if k.lower() == "application/json"), None)
    if key is None:
        key = next((k for k in keys if re.match(r"application/[^;]*\+json(;|$)", k, re.I)), None)
    if key is None:
        return None
    entry = content[key]
    return entry.get("schema") if isinstance(entry, dict) else None


def draft_schema_from_openapi(doc: dict, site: dict) -> Dict[str, Any]:
    """A DRAFT schema from an OpenAPI document (``site`` = {site, aud, version}): one verb per operation that has an ``operationId`` (``x-pca-verb``
    names it otherwise). The parameters are the path and query parameters (path-item parameters included, the operation's own winning) plus the
    properties of the JSON request body (which wins a name clash); local $refs are followed; header and cookie parameters are flagged in ``todo``."""
    todo: List[str] = []
    verbs: List[dict] = []
    c = _Ctx(doc, todo)

    def deref(x: Any) -> Any:
        if not isinstance(x, (dict, list)):
            return None
        if not isinstance(x, dict) or not isinstance(x.get("$ref"), str):
            return x
        t = _pointer(doc, x["$ref"])
        if t is None:
            todo.append("reference '%s' is not a local reference that resolves" % _u16(x["$ref"], 120))
        return t

    seen = set()
    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    for path in sorted(paths, key=_UTF8):
        ops = paths[path]
        if not isinstance(ops, dict):
            continue
        shared = ops["parameters"] if isinstance(ops.get("parameters"), list) else []
        for method in sorted(ops, key=_UTF8):
            op = ops[method]
            if not isinstance(op, dict) or not _truthy(op.get("operationId")):
                continue
            op_id = op["operationId"]
            c.left = _MAX_REF_NODES
            kind_hint = op.get("x-pca-kind")
            read = (kind_hint == "read") if _truthy(kind_hint) else method.lower() in ("get", "head")
            verb = op["x-pca-verb"] if op.get("x-pca-verb") is not None else op_id
            if verb in seen:
                todo.append("%s: declared by more than one operation; give each a distinct x-pca-verb" % _js_string(verb))
            seen.add(verb)
            params: Dict[str, dict] = {}

            def add_name(name: str, sch: Any, required: bool, source: str) -> None:
                if _NAME.fullmatch(name) is None:
                    todo.append("%s: parameter '%s' is not a schema name; rename it" % (_js_string(op_id), name))
                    return
                key = "action.params." + name
                if key in params:
                    todo.append("%s: '%s' is declared by both the %s and another source; kept the first" % (_js_string(op_id), name, source))
                    return
                params[key] = _decl(name, sch, required, c)

            # the request body first (it wins a name clash), then the operation's own parameters over the path item's
            body = _flatten(_json_body_schema(deref(op.get("requestBody"))), c, "%s: request body" % _js_string(op_id))
            bprops = body.get("properties") if isinstance(body.get("properties"), dict) else {}
            breq = set(body["required"]) if isinstance(body.get("required"), list) else set()
            for name in sorted(bprops, key=_UTF8):
                add_name(name, bprops[name], name in breq, "request body")
            merged: Dict[str, dict] = {}
            for raw in shared + (op["parameters"] if isinstance(op.get("parameters"), list) else []):
                q = deref(raw)
                if not isinstance(q, dict) or not isinstance(q.get("name"), str) or not isinstance(q.get("in"), str):
                    continue
                merged["%s:%s" % (q["in"], q["name"])] = q
            for key in sorted(merged, key=_UTF8):
                q = merged[key]
                if q["in"] not in ("path", "query"):
                    todo.append("%s: %s parameter '%s' is not an action parameter (the schema sees path, query and body parameters only)"
                                % (_js_string(op_id), q["in"], q["name"]))
                    continue
                qs = q.get("schema") if isinstance(q.get("schema"), dict) else {}
                sch = dict(qs)
                if _truthy(q.get("description")) and not _truthy(qs.get("description")):
                    sch["description"] = q["description"]
                add_name(q["name"], sch, q["in"] == "path" or q.get("required") is True, "%s parameters" % q["in"])
            rev_hint = op.get("x-pca-reversibility")
            rev = rev_hint if rev_hint is not None else ("reversible" if read else "irreversible")
            if not read and not _truthy(rev_hint):
                todo.append("%s: reversibility (drafted irreversible)" % _js_string(verb))
            v = {"verb": verb, "kind": "read" if read else "write", "params": params, "reversibility": rev, "openapi": {"operationId": op_id}}
            if _truthy(op.get("description")):
                v["description"] = _u16(op["description"], 1024)
            verbs.append(v)
    return {"schema": _draft(site, verbs), "todo": todo}
