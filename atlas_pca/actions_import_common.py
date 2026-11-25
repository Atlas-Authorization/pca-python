"""What every action importer shares (native port of import/limits.ts and import/common.ts of the TypeScript reference
@atlasauth/pca-actions): the input bounds, result shapes, text hygiene, verb naming, the bounded `$ref` resolver, the JSON Schema to
ParamDef flattening and the single place a draft ActionDef is assembled (always `unreviewed`). Sources are parsed JSON values (dict /
list / str / int / float / bool / None); an importer returns {"defs", "todo", "source"}. The reference's JavaScript string semantics
(UTF-16 lengths, lone surrogates, property reads on any value) are reproduced where an output depends on them."""
from ._fin import fin
import hashlib
import math
import re
import unicodedata
from functools import cmp_to_key
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from .actions import (
    _ALIAS_RE, _CUSTOM_ROLE_RE, _ID_ROLE_RE, _JS_WS, _VERB_RE, CORE_ROLES, MAX_DEF_PARAMS, MAX_DESCRIPTION_BYTES, MAX_TITLE_BYTES, ActionKitError,
    validate_def,
)
from .actions_derive import MAX_PARAM_PATH_DEPTH
from .intent_v2 import compare_utf8
from .intent_wb import _UNDEF, _js_str, _utf16_len
from .pca import b64u
from .sdjwt_jws import js_num

UTF8_ORDER = cmp_to_key(compare_utf8)

# ---- limits ---------------------------------------------------------------------------------------------------------------

DEFAULT_IMPORT_LIMITS = {"max_bytes": 64 * 1024 * 1024, "max_ops": 20_000, "max_json_depth": 64, "max_nodes": 6_000_000, "max_ref_nodes": 20_000, "max_ref_depth": 8}
HARD_IMPORT_LIMITS = {"max_bytes": 256 * 1024 * 1024, "max_ops": 50_000, "max_json_depth": 128, "max_nodes": 20_000_000, "max_ref_nodes": 200_000, "max_ref_depth": 16}


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def is_safe_integer(v: Any) -> bool:
    """Number.isSafeInteger over a JSON value."""
    if not _num(v):
        return False
    if isinstance(v, float):
        if not fin(v) or not v.is_integer():
            return False
    return abs(v) <= 2 ** 53 - 1


def resolve_limits(over: Any = None) -> dict:
    out = dict(DEFAULT_IMPORT_LIMITS)
    for k in list(out):
        v = over.get(k, _UNDEF) if isinstance(over, dict) else _UNDEF
        if v is _UNDEF:
            continue
        if not is_safe_integer(v) or v < 1:
            raise ActionKitError("bad_limit", "limit %s must be a positive safe integer" % k)
        out[k] = min(int(v), HARD_IMPORT_LIMITS[k])
    return out


def text_size_check(text: Any, lim: dict) -> None:
    if not isinstance(text, str):
        raise ActionKitError("bad_source", "the source must be text")
    if _utf16_len(text) * 3 > lim["max_bytes"] and len(_utf8(text)) > lim["max_bytes"]:
        raise ActionKitError("import_limit", "the source is larger than %d bytes" % lim["max_bytes"])


def check_parsed(root: Any, lim: dict) -> int:
    """Walk a parsed source iteratively; refuse anything that is not plain JSON data, is too deep or large. Returns the node count."""
    nodes = 0
    size = 0
    stack = [(root, 0)]
    while stack:
        v, d = stack.pop()
        nodes += 1
        if nodes > lim["max_nodes"]:
            raise ActionKitError("import_limit", "the source has more than %d nodes" % lim["max_nodes"])
        if d > lim["max_json_depth"]:
            raise ActionKitError("import_limit", "the source nests deeper than %d" % lim["max_json_depth"])
        if v is None or isinstance(v, bool):
            size += 4
        elif _num(v):
            if isinstance(v, float) and not fin(v):
                raise ActionKitError("bad_source", "the source holds a non-finite number")
            size += 8
        elif isinstance(v, str):
            size += _utf16_len(v)
        elif isinstance(v, list):
            size += 2 + len(v)
            for x in v:
                stack.append((x, d + 1))
        elif isinstance(v, dict):
            for k, x in v.items():
                size += _utf16_len(k) + 4
                stack.append((x, d + 1))
        else:
            raise ActionKitError("bad_source", "the source holds a %s" % type(v).__name__)
        if size > lim["max_bytes"]:
            raise ActionKitError("import_limit", "the source is larger than %d bytes" % lim["max_bytes"])
    return nodes


# ---- result types and context ----------------------------------------------------------------------------------------------

IMPORT_KINDS = ("openapi", "mcp", "graphql", "grpc", "asyncapi", "jsonschema")
DEFAULT_EXTENSIONS = ("x-pca-verb", "x-pca-role", "x-pca-internal")
_NS_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")


class Ctx:
    def __init__(self, ns, kind, lim, source, ext, root):
        self.ns = ns
        self.kind = kind
        self.lim = lim
        self.todo: List[dict] = []
        self.source = source
        self.ext = ext
        self.root = root
        self.verbs: set = set()
        self.aliases: Dict[str, str] = {}
        self.defs: List[dict] = []


def _fffd(s: str) -> str:
    return "".join("�" if 0xD800 <= ord(c) <= 0xDFFF else c for c in s)


def _utf8(s: str) -> bytes:
    """TextEncoder.encode: a lone surrogate becomes U+FFFD."""
    return _fffd(s).encode("utf-8")


_JSON_ESC = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x0C: "\\f", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}


def _json_str(s: str) -> str:
    """JSON.stringify of a string (well-formed: a lone surrogate is written as a \\uXXXX escape)."""
    out = []
    for ch in s:
        o = ord(ch)
        out.append(_JSON_ESC[o] if o in _JSON_ESC else "\\u%04x" % o if o < 0x20 or 0xD800 <= o <= 0xDFFF else ch)
    return '"' + "".join(out) + '"'


def _lenient(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _json_str(v)
    if _num(v):
        if isinstance(v, float) and not fin(v):
            raise TypeError("canonicalize: non-finite number")
        return js_num(v)
    if isinstance(v, list):
        return "[" + ",".join(_lenient(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(_json_str(k) + ":" + _lenient(v[k]) for k in sorted(v, key=UTF8_ORDER)) + "}"
    raise TypeError("canonicalize: unsupported type %s" % type(v).__name__)


def hash_canonical_lenient(v: Any) -> str:
    """base64url(sha256(lenient canonical JSON)): keys by UTF-8 order, numbers as ECMAScript prints them."""
    return b64u(hashlib.sha256(_utf8(_lenient(v))).digest())


def new_ctx(kind: str, source: Any, opts: Any) -> Ctx:
    o = opts if isinstance(opts, dict) else {}
    ns = o.get("ns")
    if not isinstance(ns, str) or _NS_RE.fullmatch(ns) is None:
        raise ActionKitError("bad_ns", "ns must match [a-z][a-z0-9_]{0,31}")
    lim = resolve_limits(o.get("limits"))
    if isinstance(source, str):
        text_size_check(source, lim)
        digest = b64u(hashlib.sha256(_utf8(source)).digest())
    elif isinstance(source, (bytes, bytearray)):
        if len(source) > lim["max_bytes"]:
            raise ActionKitError("import_limit", "the source is larger than %d bytes" % lim["max_bytes"])
        digest = b64u(hashlib.sha256(bytes(source)).digest())
    else:
        check_parsed(source, lim)
        digest = hash_canonical_lenient(source)
    now = o.get("now")
    now = 0 if now is None else now
    if not is_safe_integer(now) or now < 0:
        raise ActionKitError("bad_opts", "now must be a non-negative integer")
    uri = o.get("uri")
    licence = o.get("licence")
    ext = o.get("allowExtensions")
    if ext is None:
        ext = DEFAULT_EXTENSIONS
    elif isinstance(ext, str):
        ext = list(ext)
    elif not isinstance(ext, list):
        raise TypeError("allowExtensions is not iterable")
    src = {"kind": kind, "uri": clip("source:" + kind if uri is None else uri, 2048), "spec_digest": digest,
           "licence": clip("unknown" if licence is None else licence, 128), "imported_at": int(now)}
    return Ctx(ns, kind, lim, src, set(ext), source)


def add_todo(c: Ctx, where: str, code: str, message: str) -> None:
    # a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
    n = len(c.todo)
    if n < 5000:
        c.todo.append({"where": clip(where, 200), "code": code, "message": clip(message, 400)})
    elif n == 5000:
        c.todo.append({"where": "*", "code": "todo_truncated", "message": "further notes omitted"})


def finish(c: Ctx) -> dict:
    return {"defs": c.defs, "todo": c.todo, "source": c.source}


# ---- text hygiene ------------------------------------------------------------------------------------------------------------

_LONE = re.compile("[\ud800-\udfff]")
_CTRL = re.compile("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f  ‪-‮⁦-⁩]")
_WS = re.compile("[" + _JS_WS + "]+")


def u8(s: str) -> int:
    return len(_utf8(s))


def clip(s: Any, max_bytes: int) -> str:
    """NFC, no lone surrogates, no control or bidi-override characters, whitespace collapsed, cut to `max_bytes` at a code point."""
    if not isinstance(s, str):
        return ""
    t = _LONE.sub("", s)
    t = _CTRL.sub(" ", t)
    t = unicodedata.normalize("NFC", t)
    t = _WS.sub(" ", t).strip(_JS_WS)
    if u8(t) <= max_bytes:
        return t
    out: List[str] = []
    n = 0
    for ch in t:
        w = u8(ch)
        if n + w > max_bytes:
            break
        out.append(ch)
        n += w
    return "".join(out).strip(_JS_WS)


def first_text(mx: int, *xs: Any) -> str:
    for x in xs:
        t = clip(x, mx)
        if len(t) > 0:
            return t
    return ""


# ---- tokens and verbs --------------------------------------------------------------------------------------------------------

_MARK = re.compile("[̀-ͯ]")
_CAMEL1 = re.compile("([a-z0-9])([A-Z])")
_CAMEL2 = re.compile("([A-Z]+)([A-Z][a-z])")
_NONALNUM = re.compile("[^a-z0-9]+")


def tokens_of(name: Any) -> List[str]:
    s = _MARK.sub("", unicodedata.normalize("NFKD", _js_str(name)))
    s = _CAMEL2.sub(r"\1 \2", _CAMEL1.sub(r"\1 \2", s)).lower()
    return [t for t in _NONALNUM.split(s) if t]


ACTION_WORDS = frozenset((
    "get", "list", "read", "fetch", "find", "search", "query", "show", "describe", "create", "add", "new", "make", "insert", "post", "put", "set", "update", "patch", "edit", "modify",
    "delete", "remove", "destroy", "drop", "send", "notify", "publish", "invite", "cancel", "refund", "charge", "pay", "run", "exec", "execute", "invoke", "start", "stop",
    "enable", "disable", "approve", "reject", "close", "open", "merge", "export", "import", "upload", "download", "subscribe", "unsubscribe", "revoke", "grant", "transfer",
))


def _seg(toks: List[str]) -> str:
    s = "_".join(toks)
    if len(s) <= 32:
        return s
    h = re.sub("[^a-z0-9]", "", b64u(hashlib.sha256(s.encode("utf-8")).digest()), flags=re.I).lower()[:4].ljust(4, "0")
    return "%s_%s" % (s[:27], h)


_VERB_SPLIT = re.compile("[./:" + _JS_WS + "]+")


def verb_of(ns: str, raw: Any) -> str:
    parts = [t for t in (tokens_of(p) for p in _VERB_SPLIT.split(_js_str(raw))) if t]
    if len(parts) >= 2:
        segs = [_seg(p) for p in parts]
    else:
        t = parts[0] if parts else ["op"]
        if len(t) >= 2 and t[0] in ACTION_WORDS:
            segs = [_seg(t[1:]), _seg([t[0]])]
        elif len(t) >= 2 and t[-1] in ACTION_WORDS:
            segs = [_seg(t[:-1]), _seg([t[-1]])]
        else:
            segs = [_seg(t)]
    if len(segs) > 5:
        segs = segs[:2] + segs[-3:]
    v = "%s.%s" % (ns, ".".join(segs))
    if _VERB_RE.fullmatch(v) is None or u8(v) > 128:
        return "%s.op" % ns
    return v


def alias_of(raw: Any, verb: str) -> Optional[str]:
    a = "_".join(tokens_of(raw))
    return a if 0 < len(a) <= 64 and _ALIAS_RE.fullmatch(a) is not None and a != verb else None


def humanize(name: Any) -> str:
    t = tokens_of(name)
    return "" if not t else " ".join([t[0][:1].upper() + t[0][1:]] + t[1:])


def unique_verb(c: Ctx, verb: str, where: str) -> str:
    if verb not in c.verbs:
        return verb
    for n in range(2, 100_000):
        sfx = "_%d" % n
        dot = verb.rfind(".")
        last = verb[dot + 1:]
        cand = "%s%s%s" % (verb[:dot + 1], last[:32 - len(sfx)], sfx)
        if cand not in c.verbs and _VERB_RE.fullmatch(cand) is not None:
            add_todo(c, where, "duplicate_verb", "verb '%s' is taken by an earlier operation; this one is '%s'" % (verb, cand))
            return cand
    raise ActionKitError("import_limit", "too many operations map to one verb")


# ---- JSON value helpers ------------------------------------------------------------------------------------------------------

def is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def own(o: Any, k: str) -> bool:
    return isinstance(o, dict) and k in o


def g(o: Any, k: str) -> Any:
    """o[k] for a JSON value: an own member of an object, else undefined (an array or scalar has no such member here)."""
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def is_str(v: Any) -> bool:
    return isinstance(v, str)


def spread_obj(v: Any) -> dict:
    """{...v}: an object's members, an array's / string's indexed members, nothing for a scalar."""
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, list):
        return {str(i): x for i, x in enumerate(v)}
    if isinstance(v, str):
        u = v.encode("utf-16-le", "surrogatepass")
        return {str(i): u[2 * i:2 * i + 2].decode("utf-16-le", "surrogatepass") for i in range(len(u) // 2)}
    return {}


def spread_arr(v: Any) -> list:
    """[...v]: an array or a string (by code point); anything else is not iterable."""
    if isinstance(v, list):
        return list(v)
    if isinstance(v, str):
        return list(v)
    raise TypeError("value is not iterable")


def _decode_uri(s: str) -> str:
    """decodeURIComponent, or the raw segment when the escape is malformed."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", s):
        return s
    try:
        return unquote(s, errors="strict")
    except UnicodeDecodeError:
        return s


def pointer(root: Any, ref: Any) -> Any:
    """Follow a local `#/a/b` JSON pointer in `root`; None when absent, not local, or not an object or array."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    cur = root
    for raw in ref[2:].split("/"):
        seg = _decode_uri(raw.replace("~1", "/").replace("~0", "~"))
        if isinstance(cur, dict):
            if seg not in cur:
                return None
            cur = cur[seg]
        elif isinstance(cur, list):
            if re.fullmatch(r"0|[1-9][0-9]*", seg) is not None and int(seg) < len(cur):
                cur = cur[int(seg)]
            else:
                return None  # (`length` is an own member of an array but never an object)
        else:
            return None
    return cur if isinstance(cur, (dict, list)) else None


class Budget:
    def __init__(self, left: int):
        self.left = left
        self.exhausted = False


def new_budget(c: Ctx) -> Budget:
    return Budget(c.lim["max_ref_nodes"])


def _merge_all(a: dict, m: dict) -> dict:
    out = dict(a)
    out.update(m)
    out["properties"] = {**spread_obj(a.get("properties")), **spread_obj(m.get("properties"))}
    out["required"] = [*spread_arr(_nn(a.get("required"))), *spread_arr(_nn(m.get("required")))]
    return out


def _nn(v: Any) -> Any:
    """`v ?? []`."""
    return [] if v is None else v


def _is_null_type(m: dict) -> bool:
    t = m.get("type", _UNDEF)
    return t == "null" and isinstance(t, str) or (isinstance(t, list) and len(t) > 0 and all(x == "null" and isinstance(x, str) for x in t))


def resolve_schema(s: Any, c: Ctx, bud: Budget, where: str, chain: tuple = (), depth: int = 0) -> dict:
    """Follow local `$ref`s, merge `allOf`, collapse `anyOf`/`oneOf` to the single non-null variant or to a union of string constants.
    What stays unrepresentable is noted and left as `{}` (declared `string`, which fails closed). Bounded by `max_ref_depth` per chain and
    one budget of nodes per operation."""
    if not isinstance(s, dict):
        return {}
    if bud.left <= 0:
        if not bud.exhausted:
            bud.exhausted = True
            add_todo(c, where, "ref_budget", "schema expansion stopped after %d nodes (declared string; refine or drop)" % c.lim["max_ref_nodes"])
        return {}
    bud.left -= 1
    if depth > c.lim["max_ref_depth"]:
        add_todo(c, where, "ref_depth", "schema nesting or reference chain deeper than %d (declared string; refine or drop)" % c.lim["max_ref_depth"])
        return {}
    cur = s
    if isinstance(cur.get("$ref"), str):
        ref = cur["$ref"]
        if ref in chain:
            add_todo(c, where, "cyclic_ref", "reference '%s' is cyclic (declared string; refine or drop)" % clip(ref, 120))
            return {}
        target = pointer(c.root, ref)
        if target is None:
            add_todo(c, where, "unresolved_ref", "reference '%s' is not a local reference that resolves (declared string; refine or drop)" % clip(ref, 120))
            return {}
        siblings = {k: v for k, v in cur.items() if k != "$ref"}
        cur = {**resolve_schema(target, c, bud, where, chain + (ref,), depth + 1), **siblings}
    if isinstance(cur.get("allOf"), list):
        rest = {k: v for k, v in cur.items() if k != "allOf"}
        merged: dict = {}
        for m in [resolve_schema(m, c, bud, where, chain, depth + 1) for m in cur["allOf"]]:
            merged = _merge_all(merged, m)
        cur = {**merged, **rest}
    alts = cur.get("anyOf") if isinstance(cur.get("anyOf"), list) else cur.get("oneOf") if isinstance(cur.get("oneOf"), list) else None
    if alts is not None:
        rest = {k: v for k, v in cur.items() if k not in ("anyOf", "oneOf")}
        live = [m for m in (resolve_schema(m, c, bud, where, chain, depth + 1) for m in alts) if not _is_null_type(m)]
        if len(live) == 1:
            return {**live[0], **rest}
        consts = []
        for m in live:
            if isinstance(m.get("const"), str):
                consts.append([m["const"]])
            elif isinstance(m.get("enum"), list) and all(isinstance(x, str) for x in m["enum"]):
                consts.append(m["enum"])
            else:
                consts.append(None)
        if len(live) > 1 and all(x is not None for x in consts):
            return {**rest, "type": "string", "enum": list(dict.fromkeys(x for xs in consts for x in xs))}
        add_todo(c, where, "union", "a union of %d schemas has no representation (declared string; refine or drop)" % len(live))
        return rest
    if "const" in cur and "enum" not in cur and isinstance(cur["const"], str):
        cur = {**cur, "enum": [cur["const"]]}
    return cur


# ---- JSON Schema -> params ---------------------------------------------------------------------------------------------------

def param_seg(raw: str) -> str:
    """`[A-Za-z0-9_]{1,64}`; anything else is replaced by `_` (an astral character is two UTF-16 units, so two)."""
    s = "".join(ch if re.fullmatch("[A-Za-z0-9_]", ch) else "_" * (2 if ord(ch) > 0xFFFF else 1) for ch in raw)
    if re.fullmatch("_+", s):
        s = ""
    s = s[:64]
    return s if len(s) > 0 else "p"


FORMATS = {"email": "email", "uuid": "uuid", "uri": "url", "url": "url", "idn-email": "email", "semver": "semver"}
RESERVED = ("__proto__", "constructor", "prototype")
_INT_ROLES = ("money.amount", "money.fee", "count.limit", "bytes.size")


def _is_role_ok(r: str) -> bool:
    return r in CORE_ROLES or _ID_ROLE_RE.fullmatch(r) is not None or _CUSTOM_ROLE_RE.fullmatch(r) is not None


def _int_num(n: Any) -> bool:
    return is_safe_integer(n) and not (isinstance(n, float) and n == 0 and math.copysign(1.0, n) < 0)


def _enum_strs(e: Any) -> Optional[list]:
    ok = (isinstance(e, list) and 0 < len(e) <= 256 and all(
        isinstance(x, str) and len(x) > 0 and u8(x) <= 256 and x == unicodedata.normalize("NFC", x) and _LONE.search(x) is None for x in e))
    return list(dict.fromkeys(e)) if ok else None


def _first_non_null(t: Any) -> Any:
    """`Array.isArray(t) ? t.find(x => x !== 'null') : t` (undefined when none)."""
    if isinstance(t, list):
        for x in t:
            if not (isinstance(x, str) and x == "null"):
                return x
        return _UNDEF
    return t


def leaf_param(s: dict, required: bool, c: Ctx, bud: Budget, where: str) -> dict:
    t0 = _first_non_null(s.get("type", _UNDEF))
    enum_str = _enum_strs(s.get("enum"))
    items = s.get("items")
    t = t0 if t0 is not _UNDEF and t0 is not None else ("string" if enum_str else "array" if isinstance(items, (list, dict)) else _UNDEF)
    base: dict = {"type": "string"}
    if not required:
        base["required"] = False
    desc = clip(s.get("description"), 280)
    if len(desc) > 0:
        base["description"] = desc
    role_ext = s.get("x-pca-role") if "x-pca-role" in c.ext and isinstance(s.get("x-pca-role"), str) else None

    def with_role(p: dict) -> dict:
        if role_ext is None:
            return p
        if not _is_role_ok(role_ext) or (role_ext in _INT_ROLES and p["type"] != "integer"):
            add_todo(c, where, "role_ignored", "x-pca-role '%s' is not valid for a %s parameter" % (clip(role_ext, 64), p["type"]))
            return p
        return {**p, "role": role_ext}

    fmt = s.get("format")
    if t == "integer" or (t == "number" and fmt in ("int32", "int64") and isinstance(fmt, str)):
        p = {**base, "type": "integer"}
        mn, mx = s.get("minimum"), s.get("maximum")
        ex_min, ex_max = s.get("exclusiveMinimum"), s.get("exclusiveMaximum")
        if _int_num(mn) and ex_min is not True:
            p["min"] = int(mn)
        elif _int_num(ex_min):
            p["min"] = int(ex_min) + 1
        elif _int_num(mn) and ex_min is True:
            p["min"] = int(mn) + 1
        if _int_num(mx) and ex_max is not True:
            p["max"] = int(mx)
        elif _int_num(ex_max):
            p["max"] = int(ex_max) - 1
        elif _int_num(mx) and ex_max is True:
            p["max"] = int(mx) - 1
        if "min" in p and "max" in p and p["min"] > p["max"]:
            del p["min"]
            del p["max"]
        return with_role(p)
    if t == "boolean":
        return with_role({**base, "type": "boolean"})
    if t == "string":
        f = fmt if isinstance(fmt, str) else ""
        if f == "date":
            return with_role({**base, "type": "date"})
        if f == "date-time":
            return with_role({**base, "type": "datetime"})
        p = {**base, "type": "string"}
        if enum_str:
            p["values"] = enum_str
        elif isinstance(s.get("enum"), list) and len(s["enum"]) > 0:
            add_todo(c, where, "enum_dropped", "enum values are not 1..256 plain strings (declared as a free string; refine)")
        if f in FORMATS:
            p["format"] = FORMATS[f]
        ml = s.get("maxLength")
        if _int_num(ml) and 0 < ml <= 16_777_216:
            p["max_len"] = int(ml)
        return with_role(p)
    if t == "array":
        it = resolve_schema(items, c, bud, where + "[]")
        it_enum = _enum_strs(it.get("enum"))
        lim: dict = {}
        if _int_num(s.get("maxItems")) and s["maxItems"] >= 0:
            lim["max_items"] = int(s["maxItems"])
        if _int_num(s.get("minItems")) and s["minItems"] >= 0:
            lim["min_items"] = int(s["minItems"])
        if "min_items" in lim and "max_items" in lim and lim["min_items"] > lim["max_items"]:
            del lim["min_items"]
            del lim["max_items"]
        if s.get("uniqueItems") is True and it_enum:
            return with_role({**base, "type": "set", "values": it_enum, **lim})
        it_t = _first_non_null(it.get("type", _UNDEF))
        item = it_t if isinstance(it_t, str) and it_t in ("integer", "string", "boolean") else None
        if item is None and it_t is not _UNDEF:
            add_todo(c, where, "array_items", "array items of type '%s' are not declared (items left open)" % clip(_js_str(it_t), 40))
        return with_role({**base, "type": "array", **({"items": item} if item else {}), **lim})
    shown = _js_str("none" if t is _UNDEF or t is None else t)
    if t == "number":
        add_todo(c, where, "unsupported_type", "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)")
    else:
        add_todo(c, where, "unsupported_type", "type '%s' has no representation (declared string; refine or drop)" % clip(shown, 40))
    return with_role({**base, "type": "string"})


def flatten_object(schema: dict, c: Ctx, bud: Budget, where: str, out: dict, prefix: tuple = (), parent_required: bool = True, force_required: Any = ()) -> None:
    """Nested objects become dotted names up to MAX_PARAM_PATH_DEPTH segments; an object below that (or without properties) is a `string`
    placeholder; a child of an optional parent is optional. At most MAX_DEF_PARAMS params; the rest are dropped, noted."""
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    r = schema.get("required")
    req = {x for x in r if isinstance(x, str)} if isinstance(r, list) else set()
    for name in sorted(props, key=UTF8_ORDER):
        if name in RESERVED:
            add_todo(c, "%s: %s" % (where, name), "skipped_param", "parameter name '%s' is reserved; dropped" % name)
            continue
        child = resolve_schema(props[name], c, bud, "%s: %s" % (where, name))
        if child.get("readOnly") is True:
            continue  # response-only; not an input
        sname = param_seg(name)
        if sname != name:
            add_todo(c, "%s: %s" % (where, name), "renamed_param", "parameter '%s' is declared as '%s'" % (clip(name, 80), sname))
        path = (*prefix, sname)
        full = ".".join(path)
        required = parent_required and (name in req or name in force_required)
        is_object = child.get("type", _UNDEF) == "object" or ("type" not in child and isinstance(child.get("properties"), dict))
        if is_object and isinstance(child.get("properties"), dict) and len(child["properties"]) > 0 and len(path) < MAX_PARAM_PATH_DEPTH:
            flatten_object(child, c, bud, "%s: %s" % (where, full), out, path, required)
            continue
        if len(out) >= MAX_DEF_PARAMS:
            add_todo(c, where, "too_many_params", "more than %d parameters; '%s' and the rest are dropped" % (MAX_DEF_PARAMS, full))
            return
        if full in out or any(k.startswith(full + ".") or full.startswith(k + ".") for k in out):
            add_todo(c, "%s: %s" % (where, full), "skipped_param", "parameter '%s' collides with another; kept the first" % full)
            continue
        out[full] = _placeholder_object(child, required, c, "%s: %s" % (where, full)) if is_object else leaf_param(child, required, c, bud, "%s: %s" % (where, full))


def _placeholder_object(s: dict, required: bool, c: Ctx, where: str) -> dict:
    add_todo(c, where, "object_leaf", "an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)")
    p: dict = {"type": "string"}
    if not required:
        p["required"] = False
    d = clip(s.get("description"), 280)
    if len(d) > 0:
        p["description"] = d
    return p


# ---- assembling a draft def --------------------------------------------------------------------------------------------------

_RTYPE_RE = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}")


def emit_def(c: Ctx, name: str, effects: list, scope: str, params: dict, bindings: dict, verb: Optional[str] = None, title: Any = None,
             description: Any = None, idempotency: Optional[dict] = None, traits: Optional[list] = None, no_alias: bool = False) -> Optional[dict]:
    """Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted)."""
    if len(c.defs) >= c.lim["max_ops"]:
        raise ActionKitError("import_limit", "more than %d operations" % c.lim["max_ops"])
    raw_verb = verb if verb is not None else verb_of(c.ns, name)
    verb = unique_verb(c, raw_verb if _VERB_RE.fullmatch(raw_verb) else verb_of(c.ns, name), name)
    segs = verb.split(".")
    rtype = ".".join(segs[:-1]) if len(segs) > 2 else segs[0]
    ttl = first_text(MAX_TITLE_BYTES, title, humanize(name), verb)
    desc = clip(description, min(MAX_DESCRIPTION_BYTES, 600))
    alias = None if no_alias else alias_of(name, verb)
    d: dict = {"v": 1, "kind": "pca-action-def", "verb": verb}
    if alias is not None and alias not in c.aliases and alias not in c.verbs:
        d["aliases"] = [alias]
    d["title"] = ttl if len(ttl) > 0 else verb
    if len(desc) > 0:
        d["description"] = desc
    d["effects"] = sorted(set(effects))
    d["resource"] = {"type": rtype if _RTYPE_RE.fullmatch(rtype) else segs[0], "id": {"prefix": "", "class": "any_safe", "len": [1, 128]}, "scope": scope}
    d["params"] = params
    if idempotency:
        d["idempotency"] = idempotency
    if traits:
        d["traits"] = sorted(set(traits))
    d["bindings"] = bindings
    d["review"] = {"state": "unreviewed"}
    d["source"] = {k: c.source[k] for k in ("kind", "uri", "spec_digest", "licence", "imported_at")}
    bad = validate_def(d)
    if bad is not None:
        add_todo(c, name, "invalid_def", "not emitted: %s" % bad)
        return None
    c.verbs.add(verb)
    if "aliases" in d:
        c.aliases[d["aliases"][0]] = verb
    c.defs.append(d)
    return d


def with_trait(traits: Optional[list], t: str) -> list:
    return list(dict.fromkeys([*(traits or []), t]))
