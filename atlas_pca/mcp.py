"""Model Context Protocol adapter for Proof-Carrying Authority (the TypeScript reference, @atlasauth/pca-mcp).

- ``with_pca`` wraps a tool handler so each call builds a PCActn first (fast-fail on the local dry run), then runs the handler.
- ``guard_tool_result`` carries the encoded PCActn in a tool result's ``_meta``.
- ``parse_challenges`` / ``plan_step_up`` / ``check_authorization_response_iss``: the client half of MCP authorization step-up,
  with the ``pca_need`` extension (advisory, never approves anything).
- ``draft_action_schema_from_mcp`` / ``apply_schema_decisions`` / ``verb_of_tool`` / ``conform_tool_call``: MCP tools to the site's
  signed action schema and the closed-world check of a tool call.
- ``pca_fetch``: the agent's per-call proof for an MCP client transport, over an injected fetch callable.

``import_action_defs_from_mcp`` / ``import_action_defs_from_mcp_async``: an MCP tool list to action kit defs (``atlas_pca.actions_import_*``).
``with_pca(aud=...)`` signs and dry-runs the call for that audience instead of the agent's own.
The ``pca_need`` decoder is private here: only the step-up planner needs it.
"""
from ._fin import fin
import copy
import functools
import inspect
import json
import math
import re
from typing import Any, Callable, Dict, List, Optional

from .adapters import PcaDenied, PcaCall, bridge_tool_call, guard, record_tool_result
from .intent_v2 import ACTION_SCHEMA_KIND, _UNDEF, _is_num, _js_str, _js_strict_eq, _prop, _u16len, compare_utf8, conform_action
from .pca import decode_b64u_strict, strict_parse

__all__ = ["with_pca", "guard_tool_result", "parse_challenges", "plan_step_up", "pca_need_problem", "check_authorization_response_iss",
           "MCP_CLIENT_REVISIONS", "MCP_AUTH_CLIENT_ROWS", "draft_action_schema_from_mcp", "draft_action_schema_from_mcp_async",
           "draft_schema_from_mcp_tools", "reversibility_from_mcp_hints", "apply_schema_decisions", "verb_of_tool", "conform_tool_call",
           "tool_call_of", "pca_fetch", "import_action_defs_from_mcp", "import_action_defs_from_mcp_async"]

_UTF8_ORDER = functools.cmp_to_key(compare_utf8)
_UTF16_ORDER = lambda s: s.encode("utf-16-be", "surrogatepass")  # noqa: E731 - JS default sort order
# JS `\s` (WhiteSpace + LineTerminator), which differs from Python's
_JS_WS = "\t\n\v\f\r    -     　﻿"


# ---- withPCA / guardToolResult ----------------------------------------------------------------------------------------------

def with_pca(agent: Any, verb: str, resource: Any, handler: Callable[..., Any], fail_fast: bool = True,
             on_proof: Optional[Callable[[PcaCall, Any], Any]] = None, aud: Optional[str] = None) -> Callable[..., Any]:
    """Wrap an MCP tool handler `handler(args, extra=None)`: build a PCActn (dry run first unless `fail_fast=False`), hand it to
    `on_proof(pca, args)`, then run the handler. A local denial returns the MCP error result instead of raising. A coroutine
    handler gives a coroutine wrapper."""
    def denied(err: Exception) -> dict:
        return {"content": [{"type": "text", "text": str(err)}], "isError": True}

    if inspect.iscoroutinefunction(handler):
        async def awrapper(args: Any, extra: Any = None) -> Any:
            async def arun(a: Any, pca: PcaCall) -> Any:
                if on_proof is not None:
                    on_proof(pca, a)
                return await handler(a, extra)
            try:
                return await guard(agent, verb, resource, arun, fail_fast, aud)(args)
            except PcaDenied as err:
                return denied(err)
        return awrapper

    def wrapper(args: Any, extra: Any = None) -> Any:
        def run(a: Any, pca: PcaCall) -> Any:
            if on_proof is not None:
                on_proof(pca, a)
            return handler(a, extra)
        try:
            return guard(agent, verb, resource, run, fail_fast, aud)(args)
        except PcaDenied as err:
            return denied(err)
    return wrapper


def _spread(x: Any) -> dict:
    """JS object spread `{...x}` of a JSON value."""
    if isinstance(x, dict):
        return dict(x)
    if isinstance(x, list):
        return {str(i): v for i, v in enumerate(x)}
    if isinstance(x, str):
        return {str(i): c for i, c in enumerate(x)}
    return {}


def guard_tool_result(pca: Any, result: Any) -> dict:
    """Attach the encoded PCActn to a tool result's `_meta`, keeping `content`, `isError` and existing `_meta` keys."""
    if result is None:
        raise TypeError("guard_tool_result: result must not be null")
    meta = result.get("_meta") if isinstance(result, dict) else None
    prev = _spread(meta) if meta and isinstance(meta, (dict, list)) else {}
    if pca is None:
        raise TypeError("Cannot read properties of null (reading 'encoded')")
    encoded = pca.get("encoded", _UNDEF) if isinstance(pca, dict) else getattr(pca, "encoded", _UNDEF)
    new_meta = dict(prev)
    if encoded is not _UNDEF:
        new_meta["x-pca-action"] = encoded
    else:
        new_meta.pop("x-pca-action", None)
    out = _spread(result)
    out["_meta"] = new_meta
    return out


# ---- the client half of step-up ---------------------------------------------------------------------------------------------

def parse_challenges(header: Any) -> List[dict]:
    """Parse a `WWW-Authenticate` value (RFC 9110 section 11) into [{"scheme", "params"}]. Never raises on garbage."""
    out: List[dict] = []
    if not isinstance(header, str):
        return out
    n = len(header)
    i = 0

    def ws() -> None:
        nonlocal i
        while i < n and header[i] in " \t,":
            i += 1

    def token() -> str:
        nonlocal i
        s = i
        while i < n and header[i] not in ' \t,="':
            i += 1
        return header[s:i]

    cur: Optional[dict] = None
    ws()
    while i < n:
        name = token()
        if name == "":
            i += 1  # a stray quote or equals sign: skip it
            continue
        while i < n and header[i] in " \t":
            i += 1
        if i < n and header[i] == "=":
            i += 1
            while i < n and header[i] in " \t":
                i += 1
            val = ""
            if i < n and header[i] == '"':
                i += 1
                while i < n and header[i] != '"':
                    if header[i] == "\\" and i + 1 < n:
                        i += 1
                    val += header[i]
                    i += 1
                i += 1  # closing quote
            else:
                val = token()
            key = name.lower()
            # the reference tests `key in params` on a plain object, so these two inherited names are never stored
            if cur is not None and key not in cur["params"] and key not in ("constructor", "__proto__"):
                cur["params"][key] = val
        else:
            cur = {"scheme": name.lower(), "params": {}}
            out.append(cur)
        ws()
    return out


def _split_scopes(s: Any) -> List[str]:
    return [] if s is None else [x for x in s.split(" ") if len(x) > 0]


def _iter(x: Any) -> List[Any]:
    """JS iteration (`[...x]`, `new Set(x)`) of a JSON value: arrays and strings only."""
    if isinstance(x, (list, tuple)):
        return list(x)
    if isinstance(x, str):
        return list(x)
    raise TypeError("not iterable")


def plan_step_up(status: Any, www_authenticate: Any, state: dict) -> dict:
    """Decide the next step for a response; `state` = {"requested", "attempts", "maxAttempts"?, "pcaAware"?}. Only `403` with
    `error="insufficient_scope"` on a Bearer challenge is a step-up. The scope list is the sorted union of what was requested
    and what the challenge names; an unchanged union without a usable `pca_need` gives up instead of looping."""
    mx = state.get("maxAttempts")
    if mx is None:
        mx = 3
    bearer = None
    if _js_strict_eq(status, 403):
        bearer = next((c for c in parse_challenges(www_authenticate) if c["scheme"] == "bearer"), None)
    if bearer is None or bearer["params"].get("error") != "insufficient_scope":
        return {"action": "give_up", "reason": "not_insufficient_scope"}
    if state["attempts"] >= mx:
        return {"action": "give_up", "reason": "retry_limit"}
    requested = _iter(state.get("requested"))
    had = set(requested)
    union = sorted(dict.fromkeys(requested + _split_scopes(bearer["params"].get("scope"))), key=_UTF16_ORDER)
    attempts = state["attempts"] + 1
    if state.get("pcaAware") is True:
        r = _pca_need_from_challenge(www_authenticate) if isinstance(www_authenticate, str) else None
        if r is not None and r["ok"]:
            return {"action": "pca", "need": r["need"], "fallbackScopes": union, "attempts": attempts}
        # a missing or malformed pca_need is not an error: fall through to the stock behaviour
    if all(s in had for s in union):
        return {"action": "give_up", "reason": "no_new_scope"}
    return {"action": "scope", "scopes": union, "attempts": attempts}


def pca_need_problem(www_authenticate: Any) -> Optional[str]:
    """The reason a present-but-unusable `pca_need` was ignored, for client logs."""
    r = _pca_need_from_challenge(www_authenticate)
    return r["code"] if r is not None and not r["ok"] else None


def check_authorization_response_iss(a: dict) -> dict:
    """RFC 9207 section 2.4 as tabulated in the MCP authorization specification: `a` = {"recordedIssuer", "issParameterSupported",
    "iss"}. Simple string comparison (no normalization); an absent `iss` is refused only when the server advertised support."""
    rec = a.get("recordedIssuer")
    if not isinstance(rec, str) or len(rec) == 0:
        return {"proceed": False, "reason": "no_recorded_issuer"}
    iss = a.get("iss", _UNDEF)
    if iss is _UNDEF:
        return {"proceed": False, "reason": "iss_missing"} if a.get("issParameterSupported") is True else {"proceed": True}
    return {"proceed": True} if iss == rec and isinstance(iss, str) else {"proceed": False, "reason": "iss_mismatch"}


# ---- the pca_need challenge parameter (decode side) -------------------------------------------------------------------------

_PCA_NEED_MAX_ENCODED = 2048
_NEED_KINDS = ("scope", "grant", "discharge", "escalate")
_NEED_MEMBERS = frozenset(("v", "kind", "verb", "resource", "scopes", "grant_ref", "limits", "discharges", "tier", "policy_digest"))
_MAX_LIST = 16
_WS_RE = re.compile("[" + _JS_WS + "]")
_NEED_PARAM_RE = re.compile('(?:^|[' + _JS_WS + ',])pca_need="([^"\\\\]*)"')


def _is_str(x: Any, mx: int) -> bool:
    return isinstance(x, str) and 0 < _u16len(x) <= mx


def _bad(code: str) -> dict:
    return {"ok": False, "code": code}


def _validate_pca_need(x: Any) -> dict:
    if not isinstance(x, dict):
        return _bad("bad_shape")
    for k in x:
        if k not in _NEED_MEMBERS:
            return _bad("unknown_member")
    if not _js_strict_eq(x.get("v", _UNDEF), 1):
        return _bad("bad_version")
    kind = x.get("kind", _UNDEF)
    if not isinstance(kind, str) or kind not in _NEED_KINDS:
        return _bad("bad_kind")
    if not _is_str(x.get("verb"), 128) or not _is_str(x.get("resource"), 512):
        return _bad("bad_field")
    sc = x.get("scopes", _UNDEF)
    if sc is not _UNDEF and not (isinstance(sc, list) and len(sc) <= _MAX_LIST and all(_is_str(s, 128) and _WS_RE.search(s) is None for s in sc)):
        return _bad("bad_field")
    if x.get("grant_ref", _UNDEF) is not _UNDEF and not _is_str(x["grant_ref"], 128):
        return _bad("bad_field")
    if x.get("policy_digest", _UNDEF) is not _UNDEF and not _is_str(x["policy_digest"], 128):
        return _bad("bad_field")
    tier = x.get("tier", _UNDEF)
    if tier is not _UNDEF and not _js_strict_eq(tier, 2) and not _js_strict_eq(tier, 3):
        return _bad("bad_field")
    lim = x.get("limits", _UNDEF)
    if lim is not _UNDEF:
        if not isinstance(lim, dict) or len(lim) > _MAX_LIST:
            return _bad("bad_field")
        for k, v in lim.items():
            if not _is_str(k, 64) or not _is_num(v) or not fin(v) or v < 0:
                return _bad("bad_field")
    dis = x.get("discharges", _UNDEF)
    if dis is not _UNDEF:
        if not isinstance(dis, list) or len(dis) > _MAX_LIST:
            return _bad("bad_field")
        for d in dis:
            if not isinstance(d, dict) or any(k not in ("issuer", "claim") for k in d) or not _is_str(d.get("issuer"), 512) or not _is_str(d.get("claim"), 256):
                return _bad("bad_field")
    if tier is not _UNDEF and kind != "escalate":
        return _bad("bad_field")
    if kind == "escalate" and tier is _UNDEF:
        return _bad("bad_field")
    return {"ok": True, "need": x}


def _decode_pca_need(value: Any) -> dict:
    if not isinstance(value, str) or len(value) == 0:
        return _bad("bad_base64")
    if _u16len(value) > _PCA_NEED_MAX_ENCODED:
        return _bad("too_long")
    raw = decode_b64u_strict(value)
    if raw is None:
        return _bad("bad_base64")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]  # TextDecoder drops a leading BOM
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _bad("bad_utf8")
    try:
        parsed = strict_parse(text)
    except Exception:  # noqa: BLE001 - any parse failure is bad_json
        return _bad("bad_json")
    return _validate_pca_need(parsed)


def _pca_need_from_challenge(header: Any) -> Optional[dict]:
    if not isinstance(header, str):
        return None
    m = _NEED_PARAM_RE.search(header)
    if m is None:
        return None
    return _decode_pca_need(m.group(1))


# ---- conformance matrix -----------------------------------------------------------------------------------------------------

MCP_CLIENT_REVISIONS = ("2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "draft")


def _levels(a: str, b: str, c: str, d: str, e: str) -> Dict[str, str]:
    return dict(zip(MCP_CLIENT_REVISIONS, (a, b, c, d, e)))


MCP_AUTH_CLIENT_ROWS = [
    {"id": "parse-www-authenticate", "requirement": "Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.", "levels": _levels("n/a", "MUST", "MUST", "MUST", "MUST"), "section": "Protected Resource Metadata Discovery Requirements"},
    {"id": "step-up-on-insufficient-scope", "requirement": "Respond to 403 insufficient_scope by re-authorizing with an increased scope set.", "levels": _levels("n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"), "section": "Step-Up Authorization Flow"},
    {"id": "scope-union", "requirement": "The new scope set is the union of the previously requested set and the challenge scopes.", "levels": _levels("n/a", "n/a", "n/a", "SHOULD", "SHOULD"), "section": "Step-Up Authorization Flow, step 2"},
    {"id": "retry-limit", "requirement": "Retry no more than a few times and track upgrade attempts per resource and operation.", "levels": _levels("n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"), "section": "Step-Up Authorization Flow, step 4"},
    {"id": "iss-validation-table", "requirement": "Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.", "levels": _levels("n/a", "n/a", "n/a", "MUST", "MUST"), "section": "Authorization Response Validation"},
    {"id": "pca-need-ignored-by-stock-client", "requirement": "A client that does not know pca_need behaves exactly as without it.", "levels": _levels("EXT", "EXT", "EXT", "EXT", "EXT"), "section": "RFC 9110 section 11.2 (unknown auth-params are ignored)"},
]


# ---- MCP tools -> the site's action schema ----------------------------------------------------------------------------------

_MAX_REF_DEPTH = 8
_MAX_REF_NODES = 20000
_NAME_RE = re.compile("[A-Za-z0-9_]{1,64}")


def _truthy(x: Any) -> bool:
    if x is _UNDEF or x is None or x is False:
        return False
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        return x == x and x != 0
    return x != ""


def _slice1024(x: Any) -> Any:
    """`x.slice(0, 1024)` of a truthy JSON value: strings by UTF-16 units, arrays by items, anything else throws."""
    if isinstance(x, str):
        b = x.encode("utf-16-le", "surrogatepass")
        return x if len(b) <= 2048 else b[:2048].decode("utf-16-le", "surrogatepass")
    if isinstance(x, list):
        return x[:1024]
    raise TypeError("slice is not a function")


def _safe_int(v: Any) -> bool:
    """Number.isSafeInteger."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, float) and not (fin(v) and v == math.trunc(v)):
        return False
    return abs(int(v)) <= 2 ** 53 - 1


def _own(o: Any, k: str) -> Any:
    return o[k] if isinstance(o, dict) and k in o else _UNDEF


def _nullish(x: Any) -> bool:
    return x is None or x is _UNDEF


def _pointer(root: Any, ref: str) -> Any:
    if not ref.startswith("#/"):
        return _UNDEF
    cur = root
    for raw in ref[2:].split("/"):
        seg = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            if seg not in cur:
                return _UNDEF
            cur = cur[seg]
        elif isinstance(cur, list):
            if re.fullmatch(r"0|[1-9][0-9]*", seg) is None or int(seg) >= len(cur):
                return _UNDEF
            cur = cur[int(seg)]
        else:
            return _UNDEF
    return cur if isinstance(cur, (dict, list)) else _UNDEF


def _is_null_type(m: dict) -> bool:
    t = m.get("type", _UNDEF)
    return t == "null" or (isinstance(t, list) and all(x == "null" for x in t))


def _flatten_schema(s: Any, c: dict, where: str, depth: int = 0) -> dict:
    """Follow local `$ref`s, merge `allOf`, collapse `anyOf` / `oneOf` to its single non-null variant (or a union of string
    constants); whatever cannot be represented is flagged in `c["todo"]` and left empty (the caller declares it `string`)."""
    if not isinstance(s, (dict, list)):
        return {}
    if isinstance(s, list):
        s = {}  # a bare array has no schema members
    c["left"] = c.get("left", _MAX_REF_NODES) - 1
    if c["left"] < 0:
        if c["left"] == -1:
            c["todo"].append("%s: schema expansion stopped after %d nodes (declared string; refine or drop)" % (where, _MAX_REF_NODES))
        return {}
    if depth > _MAX_REF_DEPTH:
        c["todo"].append("%s: schema nesting or reference chain deeper than %d (declared string; refine or drop)" % (where, _MAX_REF_DEPTH))
        return {}
    cur = s
    ref = cur.get("$ref")
    if isinstance(ref, str):
        target = _pointer(c["root"], ref)
        if target is _UNDEF:
            c["todo"].append("%s: reference '%s' is not a local reference that resolves (declared string; refine or drop)" % (where, _slice_u16(ref, 120)))
            return {}
        siblings = {k: v for k, v in s.items() if k != "$ref"}
        merged = dict(_flatten_schema(target, c, where, depth + 1))
        merged.update(siblings)
        cur = merged
    if isinstance(cur.get("allOf"), list):
        rest = {k: v for k, v in cur.items() if k != "allOf"}
        acc: dict = {}
        for m in [_flatten_schema(x, c, where, depth + 1) for x in cur["allOf"]]:
            nxt = dict(acc)
            nxt.update(m)
            props = _spread(acc.get("properties"))
            props.update(_spread(m.get("properties")))
            nxt["properties"] = props
            nxt["required"] = (_iter(acc["required"]) if not _nullish(acc.get("required")) else []) + (_iter(m["required"]) if not _nullish(m.get("required")) else [])
            acc = nxt
        cur = dict(acc)
        cur.update(rest)
    alts = cur.get("anyOf")
    if _nullish(alts):
        alts = cur.get("oneOf")
    if isinstance(alts, list):
        rest = {k: v for k, v in cur.items() if k not in ("anyOf", "oneOf")}
        live = [m for m in (_flatten_schema(x, c, where, depth + 1) for x in alts) if not _is_null_type(m)]
        if len(live) == 1:
            out = dict(live[0])
            out.update(rest)
            return out
        consts = []
        for m in live:
            k = m.get("const", _UNDEF)
            e = m.get("enum", _UNDEF)
            if isinstance(k, str):
                consts.append([k])
            elif isinstance(e, list) and all(isinstance(x, str) for x in e):
                consts.append(e)
            else:
                consts.append(None)
        if len(live) > 1 and all(x is not None for x in consts):
            out = dict(rest)
            out["type"] = "string"
            out["enum"] = list(dict.fromkeys(v for x in consts for v in x))
            return out
        c["todo"].append("%s: a union of %d schemas has no schema representation (declared string; refine or drop)" % (where, len(live)))
        return rest
    if cur.get("const", _UNDEF) is not _UNDEF and cur.get("enum", _UNDEF) is _UNDEF and isinstance(cur["const"], str):
        cur = dict(cur)
        cur["enum"] = [cur["const"]]
    return cur


def _slice_u16(s: str, n: int) -> str:
    b = s.encode("utf-16-le", "surrogatepass")
    return s if len(b) <= 2 * n else b[:2 * n].decode("utf-16-le", "surrogatepass")


def _enum_strings(x: Any) -> Optional[list]:
    return x if isinstance(x, list) and all(isinstance(e, str) for e in x) else None


def _decl_of_json_schema(name: str, schema: Any, required: bool, c: dict) -> dict:
    """JSON Schema property -> parameter declaration. Sensitivity defaults to `material`; unrepresentable shapes become `string`
    placeholders flagged in `todo`."""
    todo = c["todo"]
    s = _flatten_schema(schema, c, "action.params." + name)
    t = s.get("type", _UNDEF)
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), _UNDEF)
    sem = s.get("x-pca-semantic", _UNDEF)
    sen = s.get("x-pca-sensitivity", _UNDEF)
    base = {"semantic": "unknown" if _nullish(sem) else sem, "sensitivity": "material" if _nullish(sen) else sen}
    if not required:
        base["required"] = False
    if _truthy(s.get("description", _UNDEF)):
        base["description"] = _slice1024(s["description"])
    if not _truthy(sem):
        todo.append("action.params.%s: semantic type" % name)
    enum_strings = _enum_strings(s.get("enum", _UNDEF))
    if t == "integer":
        out = {"type": "integer"}
        out.update(base)
        mn, mnx = s.get("minimum", _UNDEF), s.get("exclusiveMinimum", _UNDEF)
        mx, mxx = s.get("maximum", _UNDEF), s.get("exclusiveMaximum", _UNDEF)
        if _safe_int(mn):
            out["min"] = mn
        elif _safe_int(mnx):
            out["min"] = mnx + 1
        if _safe_int(mx):
            out["max"] = mx
        elif _safe_int(mxx):
            out["max"] = mxx - 1
        if _truthy(s.get("x-pca-unit", _UNDEF)):
            out["unit"] = s["x-pca-unit"]
        if _truthy(s.get("x-pca-accumulates-into", _UNDEF)):
            out["accumulates_into"] = s["x-pca-accumulates-into"]
        return out
    if t == "boolean":
        return dict(base, type="boolean")
    if t == "string" and s.get("format", _UNDEF) == "date":
        return dict(base, type="date")
    if t == "string":
        out = dict(base, type="string")
        if enum_strings is not None:
            out["values"] = enum_strings
        ml = s.get("maxLength", _UNDEF)
        if _safe_int(ml) and ml > 0:
            out["max_len"] = ml
        return out
    if t == "array":
        it = _flatten_schema(s.get("items", _UNDEF), c, "action.params.%s[]" % name)
        it_enum = _enum_strings(it.get("enum", _UNDEF))
        mi, mx = s.get("minItems", _UNDEF), s.get("maxItems", _UNDEF)
        if _truthy(s.get("uniqueItems", _UNDEF)) and it_enum is not None:
            out = dict(base, type="set", values=it_enum)
            if _safe_int(mi):
                out["min_items"] = mi
            if _safe_int(mx):
                out["max_items"] = mx
            return out
        it_t = it.get("type", _UNDEF)
        if isinstance(it_t, list):
            it_t = it_t[0] if it_t else _UNDEF
        out = dict(base, type="array")
        if it_t == "integer":
            out["items"] = "integer"
        if _safe_int(mx):
            out["max_items"] = mx
        if _safe_int(mi):
            out["min_items"] = mi
        return out
    todo.append("action.params.%s: type '%s' has no schema representation (declared string; refine or drop)" % (name, _js_str(t)))
    return dict(base, type="string")


def reversibility_from_mcp_hints(a: Any) -> dict:
    """MCP annotations give a LOWER bound on reversibility only (hints never lower a classification)."""
    if _own(a, "readOnlyHint") is True:
        return {"kind": "read", "atLeast": "reversible"}
    if _own(a, "destructiveHint") is True:
        return {"kind": "write", "atLeast": "rate_limited"}
    return {"kind": "write", "atLeast": "reversible"}


def _keys(o: Any) -> List[str]:
    """Object.keys of a JSON value (own enumerable string keys)."""
    if isinstance(o, dict):
        return list(o.keys())
    if isinstance(o, (list, str)):
        return [str(i) for i in range(len(o))]
    return []


def _get(o: Any, k: str) -> Any:
    """`o[k]` for a JSON value and an own key from `_keys`."""
    if isinstance(o, dict):
        return o[k]
    return o[int(k)]


def draft_schema_from_mcp_tools(tools: Any, site: dict) -> dict:
    """Draft action schema from an MCP `tools/list`: verb = `<verbPrefix><tool.name>`; every write verb is drafted `irreversible`
    (the fail-closed default). Returns {"schema", "todo"}: the decisions the developer must make before signing."""
    todo: List[str] = []
    verbs: List[dict] = []
    for t in _iter(tools):
        if t is None:
            raise TypeError("a tool must not be null")
        c = {"root": _own(t, "inputSchema"), "todo": todo}
        if c["root"] is _UNDEF:
            c["root"] = None
        name_s = _js_str(_own(t, "name"))
        inp = _flatten_schema(_own(t, "inputSchema"), c, "%s: inputSchema" % name_s)
        props = inp.get("properties")
        if _nullish(props):
            props = {}
        req_v = inp.get("required")
        req = {x for x in _iter([] if _nullish(req_v) else req_v) if isinstance(x, str)}
        params: Dict[str, Any] = {}
        for pname in sorted(_keys(props), key=_UTF8_ORDER):
            if _NAME_RE.fullmatch(pname) is None:
                todo.append("%s: parameter '%s' is not a schema name ([A-Za-z0-9_]{1,64}); rename it" % (name_s, pname))
                continue
            params["action.params." + pname] = _decl_of_json_schema(pname, _get(props, pname), pname in req, c)
        h = reversibility_from_mcp_hints(_own(t, "annotations"))
        prefix = site.get("verbPrefix")
        verb = ("" if _nullish(prefix) else _js_str(prefix)) + name_s
        if h["kind"] == "write":
            todo.append("%s: reversibility (drafted irreversible)" % verb)
        entry = {"verb": verb, "kind": h["kind"], "params": params, "reversibility": "reversible" if h["kind"] == "read" else "irreversible",
                 "mcp": {} if _own(t, "name") is _UNDEF else {"tool": t["name"]}}
        if _truthy(_own(t, "description")):
            entry["description"] = _slice1024(t["description"])
        verbs.append(entry)
    verbs.sort(key=lambda v: _UTF8_ORDER(v["verb"]))
    schema = {"v": 1, "kind": ACTION_SCHEMA_KIND, "verbs": verbs}
    for k in ("site", "aud", "version"):
        if site.get(k, _UNDEF) is not _UNDEF:
            schema[k] = site[k]
    return {"schema": schema, "todo": todo}


def _tools_of(source: Any) -> Any:
    if isinstance(source, (list, tuple)):
        return list(source)
    r = source.list_tools()
    return r


def draft_action_schema_from_mcp(source: Any, site: dict) -> dict:
    """Draft an action schema from a tool list, or from anything with a synchronous `list_tools()` returning {"tools": [...]}."""
    tools = _tools_of(source)
    if not isinstance(source, (list, tuple)):
        tools = tools["tools"]
    return draft_schema_from_mcp_tools(tools, site)


async def draft_action_schema_from_mcp_async(source: Any, site: dict) -> dict:
    """`draft_action_schema_from_mcp` for a source whose `list_tools()` is a coroutine function."""
    tools = _tools_of(source)
    if not isinstance(source, (list, tuple)):
        if inspect.isawaitable(tools):
            tools = await tools
        tools = tools["tools"]
    return draft_schema_from_mcp_tools(tools, site)


def _import_defs(tools: Any, opts: dict) -> dict:
    from .actions_import_mcp import import_mcp
    from .actions_import_pipeline import suggest_defs
    rest = {k: v for k, v in opts.items() if k != "suggest"}
    r = import_mcp({"tools": tools}, rest)
    return {"defs": suggest_defs(r["defs"], {"mode": opts.get("suggest") or "rules"})["defs"], "todo": r["todo"], "source": r["source"]}


def import_action_defs_from_mcp(source: Any, opts: dict) -> dict:
    """Import an MCP tool list (or anything with a synchronous `list_tools()` returning {"tools": [...]}) as action kit defs: typed
    params with roles, nested bodies flattened, annotations kept as untrusted hints, every def `unreviewed` until a pinned reviewer
    signs it. `opts`: `ns` (required), `uri`, `licence`, `now`, `suggest` (`"rules"` default, or `"none"`). Returns
    {"defs", "todo", "source"}."""
    tools = _tools_of(source)
    if not isinstance(source, (list, tuple)):
        tools = tools["tools"]
    return _import_defs(tools, opts)


async def import_action_defs_from_mcp_async(source: Any, opts: dict) -> dict:
    """`import_action_defs_from_mcp` for a source whose `list_tools()` is a coroutine function."""
    tools = _tools_of(source)
    if not isinstance(source, (list, tuple)):
        if inspect.isawaitable(tools):
            tools = await tools
        tools = tools["tools"]
    return _import_defs(tools, opts)


def _entries(o: Any) -> List[Any]:
    """Object.entries of a JSON value; null / undefined throw."""
    if o is None or o is _UNDEF:
        raise TypeError("cannot convert undefined or null to object")
    return [(k, _get(o, k)) for k in _keys(o)]


def apply_schema_decisions(draft: Any, d: dict) -> dict:
    """Record the developer's decisions on a draft (a new object). A decision about a verb or parameter the draft does not have
    raises: the schema is closed, so a typo must not silently publish a looser schema."""
    out = copy.deepcopy(draft)  # a non-object draft is returned as is when no decision touches it (a decision then raises)
    if not isinstance(out, dict) and (d.get("units") or d.get("verbs")):
        raise TypeError("the draft must be an object")
    units = d.get("units")
    if _truthy(units if units is not None else _UNDEF):
        merged = _spread(out.get("units") if not _nullish(out.get("units")) else {})
        merged.update(_spread(units))
        out["units"] = merged
    for verb, dv in _entries(d.get("verbs", _UNDEF)):
        vs = out.get("verbs")
        if not isinstance(vs, list):
            raise TypeError("the draft has no verbs list")
        v = None
        for x in vs:
            if x is None:
                raise TypeError("a verb entry must not be null")
            if isinstance(x, dict) and x.get("verb", _UNDEF) == verb:
                v = x
                break
        if v is None:
            raise ValueError("applySchemaDecisions: the draft has no verb '%s'" % verb)
        if dv is None or dv is _UNDEF:
            raise TypeError("a decision must not be null")
        if _truthy(_own(dv, "reversibility")):
            v["reversibility"] = dv["reversibility"]
        dp_all = _own(dv, "params")
        for path, dp in _entries({} if _nullish(dp_all) else dp_all):
            vp = v.get("params", _UNDEF)
            if _nullish(vp):
                raise TypeError("the verb has no params")
            p = _own(vp, path)
            if not _truthy(p):
                raise ValueError("applySchemaDecisions: verb '%s' has no parameter '%s'" % (verb, path))
            if isinstance(p, dict):
                p.update(_spread(dp))
            # a non-object declaration cannot take members; Object.assign would only ever change a throwaway copy
    return out


def _verb_of_tool(schema: Any, tool_name: Any) -> Any:
    verbs = _own(schema, "verbs")
    if schema is None or not isinstance(verbs, list):
        raise TypeError("schema.verbs is not an array")
    for v in verbs:
        if v is None:
            raise TypeError("a verb entry must not be null")
        if _js_strict_eq(_prop(_prop(v, "mcp"), "tool"), tool_name):
            return _prop(v, "verb")
    return _UNDEF


def verb_of_tool(schema: Any, tool_name: Any) -> Any:
    """The schema verb an MCP tool maps to (by `mcp.tool`), or None."""
    v = _verb_of_tool(schema, tool_name)
    return None if v is _UNDEF else v


def conform_tool_call(schema: Any, tool_name: Any, args: Any) -> dict:
    """Closed-world check of a tool call against the site schema (an unmapped tool is an unknown verb)."""
    verb = _verb_of_tool(schema, tool_name)
    if verb is _UNDEF:
        return {"ok": False, "code": "unknown_verb", "reason": "MCP tool '%s' is not declared by the site schema" % _js_str(tool_name)}
    return conform_action(schema, verb, args)


# ---- pcaFetch ---------------------------------------------------------------------------------------------------------------

def _reject_constant(_c: str) -> Any:
    raise ValueError("not JSON")


def tool_call_of(body: Any) -> Optional[dict]:
    """The `{"name", "arguments"}` of a JSON-RPC `tools/call` request body, or None for anything else."""
    if not isinstance(body, str):
        return None
    try:
        msg = json.loads(body, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return None
    if not isinstance(msg, dict) or msg.get("method") != "tools/call" or not isinstance(msg.get("method"), str):
        return None
    params = msg.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    args = params.get("arguments") if isinstance(params, dict) else None
    if not isinstance(name, str):
        return None
    return {"name": name, "arguments": args if isinstance(args, dict) else {}}


def pca_fetch(agent: Any, tool_action: Callable[[str, dict], Optional[dict]], fetch: Callable[[Any, Optional[dict]], Any],
              aud: Optional[str] = None) -> Callable[[Any, Optional[dict]], Any]:
    """A fetch for an MCP client transport that attaches a fresh, signed `PCA-Action` header to every `tools/call`. `fetch(url, init)`
    is the wrapped callable (`init` = {"body", "headers", ...}); `tool_action(name, arguments)` returns {"verb", "resource"} or None
    to send the call without a proof. The response is recorded in the agent's chain as UNTRUSTED tool output before it is returned:
    `aud` signs the proofs for that audience instead of the agent's own. A response exposing `text()` is recorded by its body, an event stream (or an unreadable body) by its origin."""

    def wrapped(url: Any, init: Optional[dict] = None) -> Any:
        call = tool_call_of((init or {}).get("body"))
        if call is not None:
            proof = bridge_tool_call(agent, call, lambda c: tool_action(c["name"], c["arguments"]), aud)
            if proof is not None:
                headers = dict((init or {}).get("headers") or {})
                headers.update(proof.headers)
                res = fetch(url, dict(init or {}, headers=headers))
                ct = ""
                try:
                    h = getattr(res, "headers", None)
                    ct = (h.get("content-type") or h.get("Content-Type") or "") if h is not None else ""
                except Exception:  # noqa: BLE001
                    ct = ""
                content: Any = {"tool": call["name"], "stream": str(url)}
                if re.search("event-stream", ct, re.I) is None and callable(getattr(res, "text", None)):
                    try:
                        content = res.text()
                    except Exception:  # noqa: BLE001 - unreadable: keep the origin-only record
                        pass
                record_tool_result(agent, call["name"], content)
                return res
        return fetch(url, init)
    return wrapped
