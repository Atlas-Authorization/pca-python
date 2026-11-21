"""Authoring forms of an ActionDef (native port of author.ts of the TypeScript reference @atlasauth/pca-actions): the param and resource
shorthands, the entry expansion and the document loader over an already parsed value. One action has one digest whichever way it was
written; every expanded def is checked by validate_def. The typed builder `p` is the class `P`. The YAML text loader is not ported (load_actions_text
reads JSON; parse YAML with the caller's parser and pass the value to load_actions_value): YAML 1.2 core semantics with the reference's error positions
cannot be reproduced by a subset parser without silently reading some documents differently, and no YAML library may be added."""
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from .actions import ACTION_DEF_KIND, BLAST_RADII, ID_CLASSES, PROVENANCE_LEVELS, RESOURCE_SCOPES, ActionKitError, json_profile_error, validate_def, _JS_WS
from .actions_rules import business_rules_error

MAX_AUTHOR_BYTES = 1 << 20
IDEMPOTENCY_PARAM = "idempotency_key"
AUTO_IDEMPOTENT_EFFECTS = ("send", "pay", "create", "provision", "publish")
_DEFAULT_ID_LEN = (8, 32)
_NL = "\n\r  "
_SHORTHAND_RE = re.compile(r"([a-z_]+(?::[a-z0-9_]+(?:\.[a-z0-9_]+){0,3})?)(?:\(([^%s]*)\))?(\?)?" % _NL)
_INT_ARG_RE = re.compile(r"-?[0-9]{1,15}")
_INT_RANGE_RE = re.compile(r"(-?[0-9]{1,15})\.\.(-?[0-9]{1,15})")
_AT_RE = re.compile(r".*@([a-z]+)\Z", re.S)
_ID_REST_RE = re.compile(r"\{([a-z_]+),([0-9]{1,3})\.\.([0-9]{1,3})\}")
_NS_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_ENTRY_KEYS = frozenset(("v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects",
                         "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since"))
_FILE_KEYS = ("ns", "since", "actions")


def _trim(s: str) -> str:
    return s.strip(_JS_WS)


def _split_args(s: str) -> Tuple[List[str], Dict[str, str]]:
    pos: List[str] = []
    named: Dict[str, str] = {}
    for raw in s.split(","):
        a = _trim(raw)
        if a == "":
            continue
        eq = a.find("=")
        if eq > 0:
            named[_trim(a[:eq])] = _trim(a[eq + 1:])
        else:
            pos.append(a)
    return pos, named


def _int_arg(s: Optional[str], what: str) -> Optional[int]:
    if s is None:
        return None
    if _INT_ARG_RE.fullmatch(s) is None:
        raise ActionKitError("bad_shorthand", "%s must be an integer, got '%s'" % (what, s))
    return int(s)


def _only(pos: List[str], named: Dict[str, str], n: int, names: List[str], shorthand: str) -> None:
    if len(pos) > n:
        raise ActionKitError("bad_shorthand", "'%s' takes at most %d positional argument(s)" % (shorthand, n))
    for k in named:
        if k not in names:
            raise ActionKitError("bad_shorthand", "'%s' has no option '%s'" % (shorthand, k))


def _list_arg(s: str, shorthand: str) -> List[str]:
    xs = [_trim(x) for x in s.split("|")]
    if len(xs) == 0 or any(x == "" for x in xs):
        raise ActionKitError("bad_shorthand", "'%s' needs values separated by |" % shorthand)
    return xs


def parse_param_shorthand(src: str) -> dict:
    """Expand one param shorthand (email phone url uuid ccy country secret bool date datetime duration text(N) string(N) message(N)
    int(MIN..MAX) count(MAX) money(CCY|@param, max=, min=, exp=, provenance=) id:<type> enum(a|b) set(a|b) array(items, max=, min=)); a trailing `?` makes it optional."""
    m = _SHORTHAND_RE.fullmatch(_trim(src))
    if not m:
        raise ActionKitError("bad_shorthand", "unknown param shorthand '%s'" % src)
    name, inner, optional = m.group(1), m.group(2), m.group(3) == "?"
    pos, named = _split_args(inner if inner is not None else "")

    def bare() -> None:
        if inner is not None:
            raise ActionKitError("bad_shorthand", "'%s' takes no arguments" % name)

    p: Dict[str, Any]
    if name == "email":
        bare(); p = {"type": "string", "role": "contact.email", "format": "email", "tags": ["pii"], "max_len": 254}
    elif name == "phone":
        bare(); p = {"type": "string", "role": "contact.phone", "format": "phone_e164", "tags": ["pii"], "max_len": 16}
    elif name == "url":
        bare(); p = {"type": "string", "role": "url.target", "format": "url", "max_len": 2048}
    elif name == "uuid":
        bare(); p = {"type": "string", "format": "uuid", "max_len": 36}
    elif name == "ccy":
        bare(); p = {"type": "string", "role": "money.currency", "format": "iso_currency", "max_len": 3}
    elif name == "country":
        bare(); p = {"type": "string", "format": "iso_country", "max_len": 2}
    elif name == "secret":
        bare(); p = {"type": "string", "role": "credential.secret", "tags": ["secret"], "max_len": 512}
    elif name == "bool":
        bare(); p = {"type": "boolean"}
    elif name == "date":
        bare(); p = {"type": "date"}
    elif name == "datetime":
        bare(); p = {"type": "datetime"}
    elif name == "duration":
        _only(pos, named, 1, [], "duration")
        mx = _int_arg(pos[0] if pos else None, "duration max (ms)")
        p = {"type": "duration"}
        if mx is not None:
            p.update({"min": 0, "max": mx})
    elif name in ("text", "string"):
        _only(pos, named, 1, [], name)
        n = _int_arg(pos[0] if pos else None, "%s length" % name)
        p = {"type": "string"}
        if n is not None:
            p["max_len"] = n
    elif name == "message":
        _only(pos, named, 1, [], "message")
        ml = _int_arg(pos[0] if pos else None, "message length")
        p = {"type": "string", "role": "text.message", "tags": ["free_text_outbound"], "max_len": ml if ml is not None else 1024}
    elif name == "int":
        _only(pos, named, 1, [], "int")
        r = None if not pos else _INT_RANGE_RE.fullmatch(pos[0])
        if pos and r is None:
            raise ActionKitError("bad_shorthand", "int takes MIN..MAX, for example int(0..100)")
        p = {"type": "integer"}
        if r:
            p.update({"min": int(r.group(1)), "max": int(r.group(2))})
    elif name == "count":
        _only(pos, named, 1, [], "count")
        mx = _int_arg(pos[0] if pos else None, "count max")
        p = {"type": "integer", "role": "count.limit", "min": 1}
        if mx is not None:
            p["max"] = mx
        p["unit"] = {"kind": "count"}
    elif name == "money":
        _only(pos, named, 1, ["max", "min", "exp", "provenance"], "money")
        c = pos[0] if pos else None
        if c is None:
            raise ActionKitError("bad_shorthand", "money needs a currency: money(USD) or money(@currency_param)")
        ccy: Any = {"from": c[1:]} if c.startswith("@") else c
        mx = _int_arg(named.get("max"), "money max")
        prov = named.get("provenance", "first_party")  # an amount defaults to provenance first_party
        if prov not in PROVENANCE_LEVELS:
            raise ActionKitError("bad_shorthand", "money provenance must be one of %s" % ", ".join(PROVENANCE_LEVELS))
        mn = _int_arg(named.get("min"), "money min")
        ex = _int_arg(named.get("exp"), "money exp")
        p = {"type": "integer", "role": "money.amount", "min": mn if mn is not None else 1}
        if mx is not None:
            p["max"] = mx
        p.update({"unit": {"kind": "money", "ccy": ccy, "exp": ex if ex is not None else 2}, "provenance_min": prov})
    elif name in ("enum", "set"):
        if inner is None:
            raise ActionKitError("bad_shorthand", "%s needs values: %s(a|b|c)" % (name, name))
        p = {"type": "string" if name == "enum" else "set", "values": _list_arg(inner, name)}
    elif name == "array":
        _only(pos, named, 1, ["max", "min"], "array")
        items = pos[0] if pos else None
        if items not in ("string", "integer"):
            raise ActionKitError("bad_shorthand", "array(items): items is string or integer")
        mx = _int_arg(named.get("max"), "array max")
        mn = _int_arg(named.get("min"), "array min")
        p = {"type": "array", "items": items}
        if mn is not None:
            p["min_items"] = mn
        if mx is not None:
            p["max_items"] = mx
    elif name.startswith("id:"):
        bare(); p = {"type": "string", "role": "id." + name[3:], "max_len": 64}
    else:
        raise ActionKitError("bad_shorthand", "unknown param shorthand '%s'" % name)
    return {**p, "required": False} if optional else p


def parse_resource_shorthand(src: str) -> dict:
    """`type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an optional `@one|set|tenant|global`."""
    s = _trim(src)
    scope = None
    at = _AT_RE.fullmatch(s)
    if at:
        name = at.group(1)
        if name not in RESOURCE_SCOPES:
            raise ActionKitError("bad_shorthand", "unknown resource scope '@%s'" % name)
        scope = name
        s = s[: at.start(1) - 1]
    colon = s.find(":")
    if colon < 0:
        return {"type": s, "id": "*", "scope": scope or "tenant"}
    typ, idsrc = s[:colon], s[colon + 1:]
    if idsrc == "*":
        return {"type": typ, "id": "*", "scope": scope or "set"}
    star = idsrc.find("*")
    if star < 0:
        return {"type": typ, "id": {"exact": idsrc}, "scope": scope or "one"}
    prefix, rest = idsrc[:star], idsrc[star + 1:]
    cls, ln = "alnum", list(_DEFAULT_ID_LEN)
    if rest != "":
        r = _ID_REST_RE.fullmatch(rest)
        if not r or r.group(1) not in ID_CLASSES:
            raise ActionKitError("bad_shorthand", "resource id '%s': expected prefix*{class,min..max}" % idsrc)
        cls, ln = r.group(1), [int(r.group(2)), int(r.group(3))]
    return {"type": typ, "id": {"prefix": prefix, "class": cls, "len": ln}, "scope": scope or "one"}


def default_title(verb: str) -> str:
    """The title an action gets when it names none: "acme.invoice.send" -> "Send invoice"."""
    seg = verb.split(".")[1:]
    act = seg[-1] if seg else verb
    t = " ".join([act] + seg[:-1]).replace("_", " ")
    return t[:1].upper() + t[1:]


def _as_list(v: Any) -> Any:
    return [v] if isinstance(v, str) else v


def expand_action(entry: Any, since: Optional[str] = None) -> dict:
    """Expand one authoring entry (shorthands or full def members) to {def, notes}. Raises bad_action / bad_shorthand for a malformed entry."""
    if not isinstance(entry, dict):
        raise ActionKitError("bad_action", "an action must be an object")
    for k in entry:
        if k not in _ENTRY_KEYS:
            raise ActionKitError("bad_action", "unknown member '%s'" % k)
    if "v" in entry and not (entry["v"] == 1 and not isinstance(entry["v"], bool)):
        raise ActionKitError("bad_action", "unsupported def version")
    if "kind" in entry and entry["kind"] != ACTION_DEF_KIND:
        raise ActionKitError("bad_action", "kind must be '%s'" % ACTION_DEF_KIND)
    verb = entry.get("verb")
    if not isinstance(verb, str):
        raise ActionKitError("bad_action", "verb is required")
    notes: List[dict] = []
    if "kind" in entry:
        full = {"v": 1, **entry}  # the full form is taken exactly as written: validate_def decides
        je0 = json_profile_error(full)
        if je0:
            raise ActionKitError("bad_action", "not strict JSON: %s" % je0)
        return {"def": full, "notes": notes}
    out: Dict[str, Any] = {"v": 1, "kind": ACTION_DEF_KIND, "verb": verb}
    if "aliases" in entry:
        out["aliases"] = _as_list(entry["aliases"])
    out["title"] = entry["title"] if entry.get("title") is not None else default_title(verb)
    if "description" in entry:
        out["description"] = entry["description"]
    if "effects" in entry:
        out["effects"] = _as_list(entry["effects"])
    if "resource" in entry:
        res = entry["resource"]
        out["resource"] = parse_resource_shorthand(res) if isinstance(res, str) else res
    params: Dict[str, Any] = {}
    if "params" in entry:
        if not isinstance(entry["params"], dict):
            raise ActionKitError("bad_action", "params must be an object")
        for k, v in entry["params"].items():
            params[k] = parse_param_shorthand(v) if isinstance(v, str) else v
    if "reversibility" in entry:
        out["reversibility"] = entry["reversibility"]
    if "blast" in entry:
        out["blast"] = {"radius": entry["blast"]} if isinstance(entry["blast"], str) else entry["blast"]
    if isinstance(entry.get("blast"), str) and entry["blast"] not in BLAST_RADII:
        raise ActionKitError("bad_action", "unknown blast radius '%s'" % entry["blast"])
    if "side_effects" in entry:
        out["side_effects"] = entry["side_effects"]
    effects = out["effects"] if isinstance(out.get("effects"), list) else []
    idem: Any = entry.get("idempotency", _NONE)
    if isinstance(idem, str):
        idem = {"mode": "key_param", "param": IDEMPOTENCY_PARAM} if idem == "key_param" else {"mode": idem}
    if idem is _NONE and any(e in AUTO_IDEMPOTENT_EFFECTS for e in effects):
        idem = {"mode": "key_param", "param": IDEMPOTENCY_PARAM}
        notes.append({"verb": verb, "message": "%s auto-added" % IDEMPOTENCY_PARAM})
    if isinstance(idem, dict) and idem.get("mode") == "key_param" and idem.get("param") == IDEMPOTENCY_PARAM and IDEMPOTENCY_PARAM not in params:
        params[IDEMPOTENCY_PARAM] = {"type": "string", "max_len": 64}
    if idem is not _NONE:
        out["idempotency"] = idem
    out["params"] = params
    for k in ("context", "traits"):
        if k in entry:
            out[k] = _as_list(entry[k])
    for k in ("audience", "compensates", "bindings", "examples", "source"):
        if k in entry:
            out[k] = entry[k]
    out["review"] = entry["review"] if entry.get("review") is not None else {"state": "authored"}
    sn = entry["since"] if entry.get("since") is not None else since
    if sn is not None:
        out["since"] = sn
    je = json_profile_error(out)
    if je is None and ("effects" not in entry or "resource" not in entry):
        je = "only JSON values are allowed"  # the reference always sets effects and resource: an absent one is an undefined member
    if je:
        raise ActionKitError("bad_action", "not strict JSON: %s" % je)
    return {"def": out, "notes": notes}


_NONE = object()


def _has_proto_key(v: Any, depth: int = 0) -> bool:
    if depth > 40 or not isinstance(v, (dict, list)):
        return depth > 40
    if isinstance(v, list):
        return any(_has_proto_key(x, depth + 1) for x in v)
    return any(k == "__proto__" or _has_proto_key(x, depth + 1) for k, x in v.items())


def load_actions_value(doc: Any) -> dict:
    """Expand an already parsed document ({ns, since?, actions: [...]}, or one raw def) to {defs, notes, errors, locs, rules[, ns]}. Never raises."""
    res: Dict[str, Any] = {"defs": [], "notes": [], "errors": [], "locs": {}, "rules": {}}

    def fail(msg: str) -> dict:
        return {**res, "errors": [{"message": msg}]}

    if _has_proto_key(doc):
        return fail("the document contains a '__proto__' member or nests deeper than 40")
    if not isinstance(doc, dict):
        return fail("the document must be an object")
    since = None
    if doc.get("kind") == ACTION_DEF_KIND:
        entries = [doc]
    else:
        for k in doc:
            if k not in _FILE_KEYS:
                return fail("unknown top-level member '%s' (expected ns, since, actions)" % k)
        if not isinstance(doc.get("ns"), str) or _NS_RE.fullmatch(doc["ns"]) is None:
            return fail("ns must be a lowercase identifier")
        res["ns"] = doc["ns"]
        if isinstance(doc.get("since"), str):
            since = doc["since"]
        elif "since" in doc:
            return fail("since must be a string")
        if not isinstance(doc.get("actions"), list):
            return fail("actions must be a list")
        entries = doc["actions"]
    for index, e in enumerate(entries):
        verb = e["verb"] if isinstance(e, dict) and isinstance(e.get("verb"), str) else None

        def err(message: str) -> None:
            x: Dict[str, Any] = {"index": index}
            if verb:
                x["verb"] = verb
            x["message"] = message
            res["errors"].append(x)

        try:
            rules = _NONE
            entry = e
            if isinstance(e, dict) and "rules" in e:
                rules = e["rules"]
                entry = {k: v for k, v in e.items() if k != "rules"}
            ex = expand_action(entry, since)
            d = ex["def"]
            bad = validate_def(d)
            if bad:
                err(bad)
                continue
            if rules is not _NONE:
                re_ = business_rules_error(d, rules)
                if re_:
                    err(re_)
                    continue
                res["rules"][d["verb"]] = rules
            res["defs"].append(d)
            res["notes"].extend(ex["notes"])
        except Exception as x:  # noqa: BLE001
            err(str(x) if isinstance(x, ActionKitError) else "malformed action: %s" % x)
    return res


def load_actions_text(text: str, fmt: str = "yaml") -> dict:
    """Load an authoring file (YAML 1.2 core or JSON) with source positions. YAML needs the optional ruamel.yaml (`yaml` extra) for the
    syntax layer; see atlas_pca.actions_yaml_load for what it refuses beyond the reference. Input above MAX_AUTHOR_BYTES is refused.
    Never raises (a missing ruamel.yaml is reported as a load error, not a silent fallback)."""
    from . import actions_yaml_load as _y

    def fail(message: str, line: int = 1, column: int = 1) -> dict:
        return {"defs": [], "notes": [], "errors": [{"message": message, "line": line, "column": column}], "locs": {}, "rules": {}}

    def no_const(name: str) -> Any:
        raise ValueError("invalid JSON constant %s" % name)

    if len(text.encode("utf-8", "surrogatepass")) > MAX_AUTHOR_BYTES:
        return fail("the file is larger than %d bytes" % MAX_AUTHOR_BYTES)
    positions = None
    if fmt == "json":
        try:
            value = json.loads(text, parse_constant=no_const)
        except ValueError as e:
            return fail("not JSON: %s" % e)
        try:  # JSON is YAML: only the positions come from the YAML parse, the value from the JSON parse
            positions = _y.positions_of(_y.parse_document(text, strict=False))
        except Exception:  # noqa: BLE001
            positions = None
    else:
        try:
            root = _y.parse_document(text)
            value = _y.to_value(root)
            positions = _y.positions_of(root)
        except _y.YamlError as e:
            return fail("not YAML: %s" % e.message, e.line, e.column)
        except RuntimeError as e:
            return fail(str(e))
    res = load_actions_value(value)
    if positions is not None:
        _y.attach_positions(res, positions)
    return res


def action(verb: str, spec: dict) -> dict:
    """The typed constructor over the JSON form: the same expansion as the loader (so the same digest); raises bad_action on a malformed spec."""
    d = expand_action({"verb": verb, **spec})["def"]
    bad = validate_def(d)
    if bad:
        raise ActionKitError("bad_action", "%s: %s" % (verb, bad))
    return d


# ---- the typed builder ---------------------------------------------------------------------------------------------------------

def _with_extra(p: dict, x: Optional[dict] = None) -> dict:
    return {**p, **x} if x else p


class P:
    """Typed param constructors; each returns the same param the matching shorthand expands to. A trailing `x` adds or overrides members."""

    email = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("email"), x))
    phone = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("phone"), x))
    url = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("url"), x))
    uuid = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("uuid"), x))
    ccy = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("ccy"), x))
    country = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("country"), x))
    secret = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("secret"), x))
    bool_ = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("bool"), x))
    date = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("date"), x))
    datetime = staticmethod(lambda x=None: _with_extra(parse_param_shorthand("datetime"), x))

    @staticmethod
    def duration(max_ms: Optional[int] = None, x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("duration" if max_ms is None else "duration(%d)" % max_ms), x)

    @staticmethod
    def message(max_len: Optional[int] = None, x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("message" if max_len is None else "message(%d)" % max_len), x)

    @staticmethod
    def text(max_len: Optional[int] = None, x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("text" if max_len is None else "text(%d)" % max_len), x)

    @staticmethod
    def int_(min: Optional[int] = None, max: Optional[int] = None, x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("int" if min is None or max is None else "int(%d..%d)" % (min, max)), x)

    @staticmethod
    def count(max: Optional[int] = None, x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("count" if max is None else "count(%d)" % max), x)

    @staticmethod
    def money(ccy: Any, o: Optional[dict] = None, x: Optional[dict] = None) -> dict:
        """`ccy` is a literal ISO code, or {"from": "param"} naming the currency param."""
        o = o or {}
        c = ccy if isinstance(ccy, str) else "@%s" % ccy["from"]
        opts = "".join(", %s=%d" % (k, o[k]) for k in ("max", "min", "exp") if o.get(k) is not None)
        return _with_extra(parse_param_shorthand("money(%s%s)" % (c, opts)), x)

    @staticmethod
    def id_(type: str, x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("id:%s" % type), x)

    @staticmethod
    def enum_(values: List[str], x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("enum(%s)" % "|".join(values)), x)

    @staticmethod
    def set_(values: List[str], x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("set(%s)" % "|".join(values)), x)

    @staticmethod
    def array(items: str, max: Optional[int] = None, x: Optional[dict] = None) -> dict:
        return _with_extra(parse_param_shorthand("array(%s)" % items if max is None else "array(%s, max=%d)" % (items, max)), x)

    @staticmethod
    def optional(d: dict) -> dict:
        return {**d, "required": False}
