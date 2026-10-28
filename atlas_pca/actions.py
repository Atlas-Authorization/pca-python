"""Action kit (native port of the small deterministic core of packages/pca-actions): strict ActionDef parse, normalize and
canonical digest, the trait registry and its closure/floor algebra, rule 22 (FloorDecision and the schema floor integrity
check), the pack Merkle root and inclusion proof, and T(d)/eff(d). Integers and sets only; every function is pure.

The shared vectors (packages/pca-conformance/vectors/actions) pin every output byte for byte. ActionSchema v2 parsing and
the v2 parameter types/formats of conform_action live in intent_v2.py (the schema module); this module does not grow it."""
import re
import unicodedata
from typing import Any, Dict, List, Optional

from .intent_v2 import schema_floors_error  # noqa: F401  (re-exported: the v2 `floors` shape check)
from .pca import _verify_b64u, b64u, decode_b64u_strict, hash_canonical, merkle_root, sha256, canonical_bytes_strict, _is_safe_int, _node_hash, _split

ACTION_DEF_KIND = "pca-action-def"
DEF_DIGEST_DOMAIN = "atlas-pca/action-def/v1"
TRAITS_DIGEST_DOMAIN = "atlas-pca/action-traits/v1"
ROLES_DIGEST_DOMAIN = "atlas-pca/action-roles/v1"
PACK_DIGEST_DOMAIN = "atlas-pca/action-pack/v1"

MAX_VERB_BYTES = 128
MAX_TITLE_BYTES = 120
MAX_DESCRIPTION_BYTES = 1024
MAX_DEF_PARAMS = 64
MAX_DEF_ALIASES = 16
MAX_DEF_TRAITS = 32
MAX_DEF_CONTEXT = 16
MAX_DEF_SIDE_EFFECTS = 16
MAX_TRAIT_IMPLIES_DEPTH = 8
MAX_REGISTRY_TRAITS = 512
PPM_MAX = 1_000_000

EFFECTS = ("read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign")
REVERSIBILITY = ("reversible", "rate_limited", "irreversible")
REV_RANK = {"reversible": 0, "rate_limited": 1, "irreversible": 2}
BLAST_RADII = ("one", "bounded", "tenant", "global")
BLAST_PPM = {"one": 50_000, "bounded": 300_000, "tenant": 700_000, "global": 1_000_000}
RESOURCE_SCOPES = ("one", "set", "tenant", "global")
SCOPE_BLAST = {"one": "one", "set": "bounded", "tenant": "tenant", "global": "global"}
PARAM_TYPES = ("string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref")
SENSITIVITY_RANK = {"free": 0, "material": 1, "critical": 2}
PROVENANCE_LEVELS = ("first_party", "tool", "agent")
CORE_ROLES = (
    "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
    "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
    "credential.secret", "credential.token", "credential.key",
    "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
    "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
)
PARAM_TAGS = ("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql")
PARAM_FORMATS = ("email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256")
UNIT_KINDS = ("money", "count", "bytes", "duration", "ratio")
CAVEAT_KINDS = ("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap")
CONTEXT_KEYS = ("approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested")
PARAM_RULE_IDS = ("array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
                  "pay_has_idempotency", "recipient_param_declared", "secret_not_logged")
IDEMPOTENCY_MODES = ("key_param", "natural", "none")
REVIEW_STATES = ("authored", "unreviewed", "suggested", "confirmed")
BINDING_KINDS = ("mcp", "openapi", "http", "graphql", "grpc", "asyncapi")
ID_CLASSES = ("digits", "hex", "alnum", "slug", "uuid", "any_safe")

_ID_ROLE_RE = re.compile(r"id\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}")
_CUSTOM_ROLE_RE = re.compile(r"x\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}")
_ID_FORMAT_RE = re.compile(r"id:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}")
_TAINT_RE = re.compile(r"session_taint_max:[a-z_]{1,16}")
_VERB_RE = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}")
_ALIAS_RE = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,5}")
_PARAM_NAME_RE = re.compile(r"[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}")
_TRAIT_ID_RE = re.compile(r"[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}")
_RESOURCE_TYPE_RE = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}")
_UNIT_ID_RE = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)*")
_CCY_RE = re.compile(r"[A-Z]{3}")
_RESERVED = ("__proto__", "constructor", "prototype")
_INT_ROLES = ("money.amount", "money.fee", "count.limit", "bytes.size")
_PARAM_KEYS = frozenset((
    "type", "role", "required", "values", "min", "max", "max_len", "items", "min_items", "max_items", "format", "unit", "tags",
    "provenance_min", "sensitivity", "accumulates", "default", "principal_neutral_default", "description"))
_DEF_KEYS = frozenset((
    "v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects",
    "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since"))


class ActionKitError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---- small helpers ----------------------------------------------------------------------------------------------------------

def _u8(s: str) -> int:
    return len(s.encode("utf-8", "surrogatepass"))


def _u16key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _has_lone_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _is_int(v: Any) -> bool:
    return _is_safe_int(v)


def _is_nonneg(v: Any) -> bool:
    return _is_int(v) and v >= 0


def _is_str(v: Any, mx: int = 256) -> bool:
    return isinstance(v, str) and len(v) > 0 and _u8(v) <= mx


def _in(x: Any, options) -> bool:
    return isinstance(x, str) and x in options


def _sort_uniq(xs) -> list:
    return sorted(set(xs or []))


def _is_context_key(k: Any) -> bool:
    return isinstance(k, str) and (k in CONTEXT_KEYS or _TAINT_RE.fullmatch(k) is not None)


def _str_list(v: Any, mx: int, ok) -> bool:
    return isinstance(v, list) and len(v) <= mx and all(isinstance(x, str) and ok(x) for x in v) and len(set(v)) == len(v)


# ---- strict JSON profile + ActionDef validation -----------------------------------------------------------------------------

def json_profile_error(v: Any, depth: int = 0) -> Optional[str]:
    """Strict JSON profile: plain objects/arrays, NFC strings without lone surrogates, safe integers only, depth <= 32."""
    if depth > 32:
        return "nesting deeper than 32"
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return None if _is_int(v) else "numbers must be safe integers (no floats, no -0)"
    if isinstance(v, str):
        if _has_lone_surrogate(v):
            return "string has a lone surrogate"
        return None if unicodedata.normalize("NFC", v) == v else "string is not NFC"
    if isinstance(v, list):
        for x in v:
            e = json_profile_error(x, depth + 1)
            if e:
                return e
        return None
    if isinstance(v, dict):
        for k, x in v.items():
            if _has_lone_surrogate(k) or unicodedata.normalize("NFC", k) != k:
                return "member name is not NFC / has a lone surrogate"
            e = json_profile_error(x, depth + 1)
            if e:
                return e
        return None
    return "only JSON values are allowed"


def is_role(r: Any) -> bool:
    return isinstance(r, str) and (r in CORE_ROLES or _ID_ROLE_RE.fullmatch(r) is not None or _CUSTOM_ROLE_RE.fullmatch(r) is not None)


def is_format(f: Any) -> bool:
    return isinstance(f, str) and (f in PARAM_FORMATS or _ID_FORMAT_RE.fullmatch(f) is not None)


def _id_class_chars(c: str) -> str:
    digits = "0123456789"
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = lower.upper()
    return {
        "digits": digits, "hex": digits + "abcdef", "alnum": digits + lower + upper, "slug": digits + lower + "-_",
        "uuid": digits + "abcdef-", "any_safe": digits + lower + upper + "._-:/",
    }[c]


def _in_class(s: str, c: str) -> bool:
    chars = _id_class_chars(c)
    return all(ch in chars for ch in s)


def id_pattern_error(p: Any) -> Optional[str]:
    if p == "*" and isinstance(p, str):
        return None
    if not isinstance(p, dict):
        return "resource.id must be '*', {exact} or {prefix, class, len}"
    keys = ",".join(sorted(p.keys()))
    if keys == "exact":
        e = p["exact"]
        return None if isinstance(e, str) and 1 <= len(e) <= 128 and _in_class(e, "any_safe") else "resource.id.exact must be 1..128 safe characters"
    if keys != "class,len,prefix":
        return "resource.id must be '*', {exact} or {prefix, class, len}"
    if not isinstance(p["prefix"], str) or len(p["prefix"]) > 32 or not _in_class(p["prefix"], "any_safe"):
        return "resource.id.prefix must be up to 32 safe characters"
    if not _in(p["class"], ID_CLASSES):
        return "resource.id.class is not an id class"
    ln = p["len"]
    if not isinstance(ln, list) or len(ln) != 2 or not all(_is_int(n) and 1 <= n <= 128 for n in ln):
        return "resource.id.len must be [min, max] in 1..128"
    if ln[0] > ln[1]:
        return "resource.id.len: min > max"
    if p["class"] == "uuid" and (p["prefix"] != "" or ln[0] != 36 or ln[1] != 36):
        return "a uuid id has no prefix and length exactly [36, 36]"
    return None


def param_name_error(name: str) -> Optional[str]:
    if _PARAM_NAME_RE.fullmatch(name) is None:
        return "param name '%s' is malformed" % name
    if any(seg in _RESERVED for seg in name.split(".")):
        return "param name '%s' is reserved" % name
    return None


def _param_error(name: str, p: Any, names) -> Optional[str]:
    if not isinstance(p, dict):
        return "%s: declaration must be an object" % name
    for k in p:
        if k not in _PARAM_KEYS:
            return "%s: unknown member '%s'" % (name, k)
    if not _in(p.get("type"), PARAM_TYPES):
        return "%s: unknown type" % name
    t = p["type"]
    if "role" in p and not is_role(p["role"]):
        return "%s: unknown role" % name
    if isinstance(p.get("role"), str) and p["role"] in _INT_ROLES and t != "integer":
        return "%s: role requires an integer parameter" % name
    if "required" in p and not isinstance(p["required"], bool):
        return "%s: required must be a boolean" % name
    if "values" in p:
        vs = p["values"]
        if not isinstance(vs, list) or len(vs) == 0 or len(vs) > 256 or not all(_is_str(x) for x in vs):
            return "%s: values must be 1..256 non-empty strings" % name
        if len(set(vs)) != len(vs):
            return "%s: values must be distinct" % name
        if t not in ("string", "set"):
            return "%s: values apply to string and set only" % name
    if t == "set" and "values" not in p:
        return "%s: a set needs values" % name
    int_like = t in ("integer", "duration") or (t == "array" and p.get("items") == "integer")
    for k in ("min", "max"):
        if k in p and (not _is_int(p[k]) or not int_like):
            return "%s: %s must be a safe integer on an integer parameter" % (name, k)
    if _is_int(p.get("min")) and _is_int(p.get("max")) and p["min"] > p["max"]:
        return "%s: min > max" % name
    if "max_len" in p and (not _is_int(p["max_len"]) or p["max_len"] < 1 or p["max_len"] > 16_777_216 or t not in ("string", "array", "object_ref")):
        return "%s: max_len must be 1..16777216 on a string or array" % name
    if "items" in p and (t != "array" or not _is_str(p["items"], 64)):
        return "%s: items applies to array only" % name
    for k in ("min_items", "max_items"):
        if k in p and (not _is_nonneg(p[k]) or t not in ("set", "array")):
            return "%s: %s must be a non-negative integer on a set or array" % (name, k)
    if _is_int(p.get("min_items")) and _is_int(p.get("max_items")) and p["min_items"] > p["max_items"]:
        return "%s: min_items > max_items" % name
    if "format" in p and (not is_format(p["format"]) or t not in ("string", "object_ref")):
        return "%s: format must be a known format on a string parameter" % name
    if "unit" in p:
        u = p["unit"]
        if t != "integer":
            return "%s: unit applies to integer parameters only" % name
        if not isinstance(u, dict) or not _in(u.get("kind"), UNIT_KINDS):
            return "%s: unit.kind is not a known kind" % name
        if u["kind"] == "money":
            if any(k not in ("kind", "ccy", "exp") for k in u):
                return "%s: unit has unknown members" % name
            if not _is_int(u.get("exp")) or u["exp"] < 0 or u["exp"] > 18:
                return "%s: unit.exp must be an integer in 0..18" % name
            c = u.get("ccy")
            if isinstance(c, str):
                if _CCY_RE.fullmatch(c) is None:
                    return "%s: unit.ccy must be an ISO 4217 style code" % name
            elif not isinstance(c, dict) or ",".join(c.keys()) != "from" or not isinstance(c["from"], str) or c["from"] not in names:
                return "%s: unit.ccy.from must name a declared parameter" % name
        elif ",".join(u.keys()) != "kind":
            return "%s: unit has unknown members" % name
    if "tags" in p:
        tg = p["tags"]
        if not isinstance(tg, list) or len(tg) > len(PARAM_TAGS) or not all(_in(x, PARAM_TAGS) for x in tg) or len(set(tg)) != len(tg):
            return "%s: tags must be distinct known tags" % name
    if "provenance_min" in p and not _in(p["provenance_min"], PROVENANCE_LEVELS):
        return "%s: unknown provenance_min" % name
    if "sensitivity" in p and not _in(p["sensitivity"], tuple(SENSITIVITY_RANK)):
        return "%s: unknown sensitivity" % name
    if "accumulates" in p:
        a = p["accumulates"]
        if t != "integer":
            return "%s: accumulates applies to integer parameters only" % name
        if not isinstance(a, list) or len(a) == 0 or len(a) > 8 or not all(isinstance(x, str) and len(x) <= 64 and _UNIT_ID_RE.fullmatch(x) for x in a) or len(set(a)) != len(a):
            return "%s: accumulates must be 1..8 distinct unit ids" % name
    if "default" in p and p["default"] is None:
        return "%s: default must not be null (absent = no default)" % name
    if "principal_neutral_default" in p and not isinstance(p["principal_neutral_default"], bool):
        return "%s: principal_neutral_default must be a boolean" % name
    if p.get("principal_neutral_default") is True and "default" not in p:
        return "%s: principal_neutral_default needs a default" % name
    if "description" in p and not _is_str(p["description"], MAX_DESCRIPTION_BYTES):
        return "%s: description must be a string up to %d bytes" % (name, MAX_DESCRIPTION_BYTES)
    return None


def _bindings_error(b: Any) -> Optional[str]:
    if not isinstance(b, dict):
        return "bindings must be an object"
    shapes = {"mcp": (["tool"], []), "openapi": (["operationId"], ["method", "path"]), "http": (["method", "path"], []),
              "graphql": (["op", "field"], []), "grpc": (["service", "method"], []), "asyncapi": (["channel", "op"], [])}
    for k, v in b.items():
        if k not in BINDING_KINDS:
            return "bindings: unknown kind '%s'" % k
        req, opt = shapes[k]
        if not isinstance(v, dict):
            return "bindings.%s must be an object" % k
        for m in v:
            if m not in req + opt:
                return "bindings.%s: unknown member '%s'" % (k, m)
        for m in req:
            if not _is_str(v.get(m), 256):
                return "bindings.%s.%s must be a non-empty string" % (k, m)
        for m in opt:
            if m in v and not _is_str(v[m], 256):
                return "bindings.%s.%s must be a non-empty string" % (k, m)
    if "graphql" in b and b["graphql"]["op"] not in ("query", "mutation", "subscription"):
        return "bindings.graphql.op is not a GraphQL operation kind"
    if "asyncapi" in b and b["asyncapi"]["op"] not in ("send", "receive"):
        return "bindings.asyncapi.op must be send or receive"
    return None


def _review_error(r: Any) -> Optional[str]:
    if not isinstance(r, dict):
        return "review must be an object"
    for k in r:
        if k not in ("state", "attestation", "suggested_by"):
            return "review: unknown member '%s'" % k
    if not _in(r.get("state"), REVIEW_STATES):
        return "review.state is not a review state"
    if "attestation" in r:
        a = r["attestation"]
        if not isinstance(a, dict):
            return "review.attestation must be an object"
        for k in a:
            if k not in ("def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig"):
                return "review.attestation: unknown member '%s'" % k
        if not _is_str(a.get("def_digest"), 64) or not _is_str(a.get("traits_digest"), 64) or not _is_str(a.get("facts_digest"), 64) or not _is_str(a.get("reviewer_kid"), 128) or not _is_nonneg(a.get("ts")):
            return "review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required"
        if not _str_list(a.get("final_traits"), MAX_DEF_TRAITS, lambda s: _TRAIT_ID_RE.fullmatch(s) is not None):
            return "review.attestation.final_traits must be distinct trait ids"
        d = a.get("dismissed")
        if not isinstance(d, list) or len(d) > MAX_DEF_TRAITS or not all(
                isinstance(x, dict) and ",".join(sorted(x.keys())) == "reason,trait" and isinstance(x["trait"], str)
                and _TRAIT_ID_RE.fullmatch(x["trait"]) and _is_str(x["reason"], 256) for x in d):
            return "review.attestation.dismissed must be {trait, reason} entries"
        if "sig" in a and not _is_str(a["sig"], 4096):
            return "review.attestation.sig must be a string"
    return None


def validate_def(x: Any) -> Optional[str]:
    """None if `x` is a well-formed ActionDef (structure only: registry, prules and lint checks are separate). Never raises."""
    try:
        je = json_profile_error(x)
        if je:
            return "not strict JSON: " + je
        if not isinstance(x, dict):
            return "def must be an object"
        for k in x:
            if k not in _DEF_KEYS:
                return "unknown member '%s'" % k
        if x.get("v") != 1 or isinstance(x.get("v"), bool):
            return "unsupported def version"
        if x.get("kind") != ACTION_DEF_KIND:
            return "kind must be '%s'" % ACTION_DEF_KIND
        verb = x.get("verb")
        if not isinstance(verb, str) or _VERB_RE.fullmatch(verb) is None or _u8(verb) > MAX_VERB_BYTES:
            return "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)"
        if "aliases" in x and (not _str_list(x["aliases"], MAX_DEF_ALIASES, lambda s: _ALIAS_RE.fullmatch(s) is not None and _u8(s) <= MAX_VERB_BYTES) or verb in x["aliases"]):
            return "aliases must be distinct verb-shaped names other than the verb"
        if not _is_str(x.get("title"), MAX_TITLE_BYTES):
            return "title must be a non-empty string up to %d bytes" % MAX_TITLE_BYTES
        if "description" in x and not _is_str(x["description"], MAX_DESCRIPTION_BYTES):
            return "description must be a string"
        if not _str_list(x.get("effects"), len(EFFECTS), lambda s: s in EFFECTS) or len(x["effects"]) == 0:
            return "effects must be 1..12 distinct known effects"
        r = x.get("resource")
        if not isinstance(r, dict) or ",".join(sorted(r.keys())) != "id,scope,type":
            return "resource must be {type, id, scope}"
        if not isinstance(r["type"], str) or _RESOURCE_TYPE_RE.fullmatch(r["type"]) is None or len(r["type"]) > 128:
            return "resource.type is malformed"
        ide = id_pattern_error(r["id"])
        if ide:
            return ide
        if not _in(r["scope"], RESOURCE_SCOPES):
            return "resource.scope is not a scope"
        params = x.get("params")
        if not isinstance(params, dict):
            return "params must be an object"
        names = list(params.keys())
        if len(names) > MAX_DEF_PARAMS:
            return "more than %d parameters" % MAX_DEF_PARAMS
        name_set = set(names)
        for n in names:
            ne = param_name_error(n)
            if ne:
                return ne
            for m in names:
                if m != n and m.startswith(n + "."):
                    return "param '%s' is both a value and the parent of '%s'" % (n, m)
        for n in names:
            e = _param_error(n, params[n], name_set)
            if e:
                return e
        rv = x.get("reversibility")
        if "reversibility" in x and not isinstance(rv, str):
            if not isinstance(rv, dict) or any(k not in ("by", "map", "default") for k in rv):
                return "reversibility must be a class or {by, map, default?}"
            if not isinstance(rv.get("by"), str) or rv["by"] not in name_set:
                return "reversibility.by must name a declared parameter"
            m = rv.get("map")
            if not isinstance(m, dict) or len(m) == 0 or len(m) > 256 or not all(_is_str(k, 128) and _in(v, REVERSIBILITY) for k, v in m.items()):
                return "reversibility.map must map values to reversibility classes"
            if "default" in rv and not _in(rv["default"], REVERSIBILITY):
                return "reversibility.default is not a class"
        elif "reversibility" in x and rv not in REVERSIBILITY:
            return "unknown reversibility class"
        if "blast" in x:
            b = x["blast"]
            if not isinstance(b, dict) or any(k not in ("radius", "ppm") for k in b) or not _in(b.get("radius"), BLAST_RADII):
                return "blast must be {radius, ppm?}"
            if "ppm" in b and not (_is_int(b["ppm"]) and 0 <= b["ppm"] <= PPM_MAX):
                return "blast.ppm must be an integer in 0..1000000"
        if "side_effects" in x:
            s = x["side_effects"]
            if not isinstance(s, list) or len(s) > MAX_DEF_SIDE_EFFECTS or not all(
                    isinstance(e, dict) and ",".join(sorted(e.keys())) == "kind,target" and _is_str(e["target"], 128) and _in(e["kind"], EFFECTS) for e in s):
                return "side_effects must be {target, kind} entries"
        if "idempotency" in x:
            i = x["idempotency"]
            if not isinstance(i, dict) or any(k not in ("mode", "param") for k in i) or not _in(i.get("mode"), IDEMPOTENCY_MODES):
                return "idempotency must be {mode, param?}"
            bad = (not isinstance(i.get("param"), str) or i["param"] not in name_set) if i["mode"] == "key_param" else "param" in i
            if bad:
                return "idempotency.param is required for key_param (a declared parameter) and forbidden otherwise"
        if "context" in x and not _str_list(x["context"], MAX_DEF_CONTEXT, _is_context_key):
            return "context must be distinct known context keys"
        if "traits" in x and not _str_list(x["traits"], MAX_DEF_TRAITS, lambda s: _TRAIT_ID_RE.fullmatch(s) is not None):
            return "traits must be distinct trait ids"
        if "audience" in x and x["audience"] != "resource":
            return "audience must be 'resource'"
        if "compensates" in x and (not isinstance(x["compensates"], str) or _VERB_RE.fullmatch(x["compensates"]) is None):
            return "compensates must be a verb"
        if "bindings" in x:
            be = _bindings_error(x["bindings"])
            if be:
                return be
        if "examples" in x:
            ex = x["examples"]
            if not isinstance(ex, list) or len(ex) > 32:
                return "examples must be an array of up to 32 entries"
            for e in ex:
                if not isinstance(e, dict) or any(k not in ("params", "under", "expect") for k in e) or not isinstance(e.get("params"), dict) or e.get("expect") not in ("allow", "escalate", "deny"):
                    return "example must be {params, under?, expect}"
        re_ = _review_error(x.get("review"))
        if re_:
            return re_
        if "source" in x:
            s = x["source"]
            if (not isinstance(s, dict) or any(k not in ("kind", "uri", "spec_digest", "licence", "imported_at") for k in s) or not _is_str(s.get("kind"), 64)
                    or not _is_str(s.get("uri"), 2048) or not _is_str(s.get("spec_digest"), 128) or not _is_str(s.get("licence"), 128)
                    or ("imported_at" in s and not _is_nonneg(s["imported_at"]))):
                return "source must be {kind, uri, spec_digest, licence, imported_at?}"
        if "since" in x and not _is_str(x["since"], 64):
            return "since must be a string"
        return None
    except Exception as e:  # noqa: BLE001 - total
        return "malformed def: %s" % e


# ---- profile lattice + trait registry ---------------------------------------------------------------------------------------

def profile(p: Optional[dict] = None) -> dict:
    p = p or {}
    return {"risk": p.get("risk", 0), "rev": p.get("rev", "reversible"), "blast_ppm": p.get("blast_ppm", 0), "esc": p.get("esc", 0),
            "caveats": _sort_uniq(p.get("caveats")), "context": _sort_uniq(p.get("context")), "prules": _sort_uniq(p.get("prules"))}


BOTTOM = profile()


def _int_in(x: Any, lo: int, hi: int) -> bool:
    return _is_int(x) and lo <= x <= hi


def profile_error(p: Any) -> Optional[str]:
    if not isinstance(p, dict):
        return "profile must be an object"
    for k in p:
        if k not in ("risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"):
            return "profile: unknown member '%s'" % k
    if not _int_in(p.get("risk"), 0, 3):
        return "profile.risk must be an integer in 0..3"
    if not _in(p.get("rev"), REVERSIBILITY):
        return "profile.rev is not a reversibility class"
    if not _int_in(p.get("blast_ppm"), 0, PPM_MAX):
        return "profile.blast_ppm must be an integer in 0..1000000"
    if not _int_in(p.get("esc"), 0, 3):
        return "profile.esc must be an integer in 0..3"
    for name, ok in (("caveats", lambda x: _in(x, CAVEAT_KINDS)), ("context", _is_context_key), ("prules", lambda x: _in(x, PARAM_RULE_IDS))):
        a = p.get(name)
        if not isinstance(a, list) or len(a) > 64 or not all(ok(x) for x in a):
            return "profile.%s must be an array of known %s entries" % (name, name)
        for i in range(1, len(a)):
            if not (a[i - 1] < a[i]):
                return "profile.%s must be sorted and distinct" % name
    return None


def join(p: dict, q: dict) -> dict:
    return {"risk": max(p["risk"], q["risk"]), "rev": p["rev"] if REV_RANK[p["rev"]] >= REV_RANK[q["rev"]] else q["rev"],
            "blast_ppm": max(p["blast_ppm"], q["blast_ppm"]), "esc": max(p["esc"], q["esc"]),
            "caveats": _sort_uniq(p["caveats"] + q["caveats"]), "context": _sort_uniq(p["context"] + q["context"]),
            "prules": _sort_uniq(p["prules"] + q["prules"])}


def join_all(ps) -> dict:
    out = BOTTOM
    for p in ps:
        out = join(out, p)
    return out


def _subset(a, b) -> bool:
    return all(x in b for x in a)


def leq(p: dict, q: dict) -> bool:
    return (p["risk"] <= q["risk"] and REV_RANK[p["rev"]] <= REV_RANK[q["rev"]] and p["blast_ppm"] <= q["blast_ppm"] and p["esc"] <= q["esc"]
            and _subset(p["caveats"], q["caveats"]) and _subset(p["context"], q["context"]) and _subset(p["prules"], q["prules"]))


def registry_error(defs, core: bool = False) -> Optional[str]:
    """Null if `defs` form a valid registry, else the first reason (ids, distinct, pca. reserved, implies resolve, T5, no cycle, depth <= 8)."""
    if not isinstance(defs, list) or len(defs) > MAX_REGISTRY_TRAITS:
        return "a registry holds at most %d traits" % MAX_REGISTRY_TRAITS
    by: Dict[str, dict] = {}
    for t in defs:
        if not isinstance(t, dict):
            return "trait must be an object"
        tid = t.get("id")
        if not isinstance(tid, str) or _TRAIT_ID_RE.fullmatch(tid) is None:
            return "trait id '%s' is malformed" % tid
        if tid.startswith("pca.") and not core:
            return "trait '%s': the pca. namespace is reserved for core traits" % tid
        if tid in by:
            return "trait '%s' is defined twice" % tid
        im = t.get("implies")
        if not isinstance(im, list) or len(im) > 8 or len(set(map(str, im))) != len(im) or any(not isinstance(u, str) for u in im):
            return "trait '%s': implies must be up to 8 distinct trait ids" % tid
        pe = profile_error(t.get("floor"))
        if pe:
            return "trait '%s': %s" % (tid, pe)
        cp = t.get("card_phrase")
        if not isinstance(cp, str) or len(cp.encode("utf-16-le", "surrogatepass")) // 2 == 0 or len(cp.encode("utf-16-le", "surrogatepass")) // 2 > 120:
            return "trait '%s': card_phrase must be a non-empty string up to 120 characters" % tid
        by[tid] = t
    for t in defs:
        for u in t["implies"]:
            ud = by.get(u)
            if ud is None:
                return "trait '%s' implies unknown trait '%s'" % (t["id"], u)
            if not leq(ud["floor"], t["floor"]):
                return "trait '%s': floor is below the floor of implied '%s' (a trait may only extend what it implies)" % (t["id"], u)
    depth: Dict[str, int] = {}
    visiting = set()

    def walk(i: str) -> int:
        if i in depth:
            return depth[i]
        if i in visiting:
            return -1
        visiting.add(i)
        d = 1
        for u in by[i]["implies"]:
            du = walk(u)
            if du < 0:
                return -1
            d = max(d, du + 1)
        visiting.discard(i)
        depth[i] = d
        return d

    for t in defs:
        d = walk(t["id"])
        if d < 0:
            return "trait '%s': implies cycle" % t["id"]
        if d > MAX_TRAIT_IMPLIES_DEPTH:
            return "trait '%s': implies depth %d exceeds %d" % (t["id"], d, MAX_TRAIT_IMPLIES_DEPTH)
    return None


def build_registry(defs, core: bool = False) -> Dict[str, dict]:
    e = registry_error(defs, core)
    if e:
        raise ActionKitError("bad_registry", e)
    return {t["id"]: t for t in defs}


def extend_registry(base: Dict[str, dict], custom) -> Dict[str, dict]:
    """Core registry extended with custom traits (which must not use `pca.` and must extend what they imply)."""
    for c in custom:
        if not isinstance(c, dict) or not isinstance(c.get("id"), str) or c["id"] in base or c["id"].startswith("pca."):
            raise ActionKitError("bad_registry", "custom trait may not redefine a core trait")
    return build_registry(list(base.values()) + list(custom), core=True)


def closure(reg: Dict[str, dict], ids) -> List[str]:
    seen = set()
    stack = list(ids)
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        t = reg.get(i) if isinstance(i, str) else None
        if t is None:
            raise ActionKitError("unknown_trait", "unknown trait '%s'" % i)
        seen.add(i)
        stack.extend(t["implies"])
    return sorted(seen)


def floor_of(reg: Dict[str, dict], ids) -> dict:
    return join_all(reg[i]["floor"] for i in closure(reg, ids))


def floor_decision(g: dict, call: dict, rho: dict) -> str:
    """FloorDecision(G, call, rho): deny if rho.esc > G.max_esc; escalate if a caveat/context is missing or rho.esc > G.preauth_esc; else allow."""
    if rho["esc"] > g["max_esc"]:
        return "deny"
    if not _subset(rho["caveats"], g["caveats"]) or not _subset(rho["context"], call["context"]) or rho["esc"] > g["preauth_esc"]:
        return "escalate"
    return "allow"


# [id, implies, own floor, card phrase] - the 22 core traits
_TABLE = [
    ("money_moving", [], dict(risk=3, rev="rate_limited", blast_ppm=700_000, esc=2, caveats=["amount_cap", "count_cap", "window"], context=["idempotency"], prules=["money_has_currency", "money_amount_bounded", "pay_has_idempotency"]), "moves money"),
    ("destructive", [], dict(risk=2, rev="rate_limited", esc=1, caveats=["resource_scope"], prules=["id_not_wildcard"]), "deletes or destroys data"),
    ("irreversible", [], dict(risk=2, rev="irreversible", esc=1, context=["fresh_revocation"]), "cannot be undone"),
    ("external_communication", [], dict(risk=2, rev="irreversible", caveats=["recipient_scope", "rate_cap"], prules=["recipient_param_declared"]), "sends to people outside your organisation"),
    ("data_export", [], dict(risk=2, caveats=["resource_scope", "count_cap"], prules=["export_bounded"]), "exports data"),
    ("privilege_change", [], dict(risk=3, esc=3, caveats=["resource_scope", "short_expiry"]), "changes who can do what"),
    ("code_execution", [], dict(risk=3, rev="irreversible", esc=2, caveats=["resource_scope"], context=["sandbox_attested"]), "runs code or commands"),
    ("credential_access", [], dict(risk=3, esc=3, prules=["secret_not_logged"]), "reads or handles credentials"),
    ("bulk", [], dict(risk=2, caveats=["count_cap"], prules=["array_bounded"]), "acts on many items at once"),
    ("pii_access", [], dict(risk=1, caveats=["resource_scope"]), "touches personal data"),
    ("public_exposure", [], dict(risk=2, rev="irreversible", esc=1), "makes content public"),
    ("persistence", [], dict(risk=2, caveats=["short_expiry"], context=["revocable"]), "creates standing access or infrastructure"),
    ("infra_mutation", [], dict(risk=2, rev="rate_limited", caveats=["resource_scope"]), "changes infrastructure"),
    ("cost_incurring", [], dict(risk=1, caveats=["amount_cap"]), "incurs cost"),
    ("legal_binding", [], dict(risk=3, rev="irreversible", esc=3), "legally or cryptographically binds you"),
    ("impersonation", ["external_communication"], dict(risk=2, esc=1), "acts as a person"),
    ("network_egress", [], dict(risk=1, caveats=["recipient_scope"]), "reaches out to the network"),
    ("financial_data_read", [], dict(risk=1, caveats=["resource_scope"]), "reads financial data"),
    ("regulated_data", [], dict(risk=2, esc=1), "handles regulated data"),
    ("scheduled", [], dict(risk=2, caveats=["short_expiry", "count_cap"]), "runs later or repeatedly"),
    ("unreviewed", [], dict(risk=3, rev="irreversible", blast_ppm=1_000_000, esc=2, caveats=["approval_ref", "resource_scope"], context=["dry_run_first"]), "has not been reviewed yet"),
    ("agent_spawning", [], dict(risk=2, caveats=["count_cap"]), "starts another agent"),
]


def _core_defs() -> List[dict]:
    floors: Dict[str, dict] = {}
    out = []
    for name, implies, own, phrase in _TABLE:
        tid = "pca." + name
        imp = ["pca." + n for n in implies]
        fl = profile(own)
        for u in imp:
            fl = join(fl, floors[u])
        floors[tid] = fl
        out.append({"id": tid, "implies": imp, "floor": fl, "card_phrase": phrase})
    return out


CORE_TRAIT_DEFS = _core_defs()
CORE_REGISTRY = build_registry(CORE_TRAIT_DEFS, core=True)

EFFECT_TRAITS = {
    "read": [], "create": [], "update": [], "delete": ["pca.destructive"], "send": ["pca.external_communication"], "pay": ["pca.money_moving"],
    "exec": ["pca.code_execution"], "privilege": ["pca.privilege_change"], "export": ["pca.data_export"], "publish": ["pca.public_exposure"],
    "provision": ["pca.persistence", "pca.scheduled"], "sign": ["pca.legal_binding"],
}
TAG_TRAITS = {
    "pii": ["pca.pii_access"], "phi": ["pca.pii_access", "pca.regulated_data"], "pci": ["pca.regulated_data"],
    "secret": ["pca.credential_access"], "credential": ["pca.credential_access"],
}
ROLE_TRAITS = {
    "credential.secret": ["pca.credential_access"], "credential.token": ["pca.credential_access"], "credential.key": ["pca.credential_access"],
    "url.target": ["pca.network_egress"],
}
ROLE_SENSITIVITY_FLOOR = {
    "money.amount": "critical", "money.currency": "material", "money.fee": "material", "party.payee": "critical", "party.payer": "material",
    "contact.email": "material", "contact.phone": "material", "contact.address": "material", "person.name": "material", "person.dob": "material",
    "person.national_id": "critical", "credential.secret": "critical", "credential.token": "critical", "credential.key": "critical",
    "code.command": "critical", "query.sql": "critical", "text.message": "material",
}
TAG_SENSITIVITY_FLOOR = {
    "pii": "material", "phi": "material", "pci": "material", "secret": "critical", "credential": "critical",
    "free_text_outbound": "material", "code": "material", "path": "material", "sql": "material",
}


def traits_digest(reg: Dict[str, dict]) -> str:
    """Digest of a trait registry (sorted by id): what a pack pins as `traits_digest`."""
    ts = [{"id": t["id"], "implies": sorted(t["implies"]), "floor": t["floor"], "card_phrase": t["card_phrase"]} for t in sorted(reg.values(), key=lambda t: t["id"])]
    return hash_canonical({"d": TRAITS_DIGEST_DOMAIN, "traits": ts})


def tables_digest() -> str:
    return hash_canonical({"d": ROLES_DIGEST_DOMAIN, "roles": list(CORE_ROLES), "effect_traits": EFFECT_TRAITS, "role_traits": ROLE_TRAITS,
                           "tag_traits": TAG_TRAITS, "role_sensitivity": ROLE_SENSITIVITY_FLOOR, "tag_sensitivity": TAG_SENSITIVITY_FLOOR})


# ---- normalize + digest -----------------------------------------------------------------------------------------------------

def is_read_only(effects) -> bool:
    return len(effects) > 0 and all(e == "read" for e in effects)


def _max_sens(a: str, b: str) -> str:
    return a if SENSITIVITY_RANK[a] >= SENSITIVITY_RANK[b] else b


def sensitivity_floor(p: dict) -> str:
    f = "free"
    if p.get("role") in ROLE_SENSITIVITY_FLOOR:
        f = _max_sens(f, ROLE_SENSITIVITY_FLOOR[p["role"]])
    for t in p.get("tags") or []:
        if t in TAG_SENSITIVITY_FLOOR:
            f = _max_sens(f, TAG_SENSITIVITY_FLOOR[t])
    return f


def effective_param_sensitivity(p: dict) -> str:
    return _max_sens(p.get("sensitivity", "free"), sensitivity_floor(p))


def declared_reversibility(d: dict):
    return d["reversibility"] if "reversibility" in d else ("reversible" if is_read_only(d["effects"]) else "irreversible")


def _max_rev(xs) -> str:
    out = "reversible"
    for b in xs:
        if b in REV_RANK and REV_RANK[b] > REV_RANK[out]:
            out = b
    return out


def worst_reversibility(r, params: dict) -> str:
    """Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have."""
    if isinstance(r, str):
        return r
    d = params.get(r["by"])
    mapped = list(r["map"].values())
    domain = None
    if d is not None:
        if d.get("type") == "boolean":
            domain = ["true", "false"]
        elif d.get("type") == "string" and d.get("values") is not None:
            domain = d["values"]
    covered = domain is not None and all(x in r["map"] for x in domain)
    return _max_rev(mapped if covered else mapped + [r.get("default", "irreversible")])


def _normalize_param(p: dict) -> dict:
    out = dict(p)
    out["required"] = p.get("required", True)
    if "tags" in p:
        out["tags"] = _sort_uniq(p["tags"])
    if "values" in p:
        out["values"] = list(p["values"])
    out["sensitivity"] = effective_param_sensitivity(p)
    if "accumulates" in p:
        out["accumulates"] = _sort_uniq(p["accumulates"])
    else:
        u = p.get("unit")
        if p.get("role") == "money.amount" and isinstance(u, dict) and u.get("kind") == "money" and isinstance(u.get("ccy"), str):
            out["accumulates"] = ["money." + u["ccy"].lower()]
    return out


def normalize(d: dict) -> dict:
    """The authoring-independent form of a def (assumes validate_def passed): defaults filled, sets sorted, review/examples/source/since removed."""
    rev = declared_reversibility(d)
    radius = d["blast"]["radius"] if "blast" in d else SCOPE_BLAST[d["resource"]["scope"]]
    params = {k: _normalize_param(d["params"][k]) for k in sorted(d["params"])}
    if isinstance(rev, str):
        nrev = rev
    else:
        nrev = {"by": rev["by"], "map": dict(rev["map"])}
        if "default" in rev:
            nrev["default"] = rev["default"]
    idem = {"mode": d["idempotency"]["mode"] if "idempotency" in d else "none"}
    if "idempotency" in d and "param" in d["idempotency"]:
        idem["param"] = d["idempotency"]["param"]
    out = {
        "v": 1, "kind": d["kind"], "verb": d["verb"], "aliases": _sort_uniq(d.get("aliases")), "title": d["title"],
        "effects": _sort_uniq(d["effects"]),
        "resource": {"type": d["resource"]["type"], "id": d["resource"]["id"], "scope": d["resource"]["scope"]},
        "params": params, "reversibility": nrev,
        "blast": {"radius": radius, "ppm": max(BLAST_PPM[radius], d["blast"].get("ppm", 0) if "blast" in d else 0)},
        "side_effects": sorted(({"target": s["target"], "kind": s["kind"]} for s in d.get("side_effects", [])),
                               key=lambda s: (_u16key(s["target"]), s["kind"])),
        "idempotency": idem, "context": _sort_uniq(d.get("context")), "traits": _sort_uniq(d.get("traits")),
        "bindings": _json_copy(d.get("bindings", {})),
    }
    if "description" in d:
        out["description"] = d["description"]
    if "audience" in d:
        out["audience"] = d["audience"]
    if "compensates" in d:
        out["compensates"] = d["compensates"]
    return out


def _json_copy(v):
    if isinstance(v, dict):
        return {k: _json_copy(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_json_copy(x) for x in v]
    return v


def def_digest(d: dict) -> str:
    """b64u(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it."""
    return hash_canonical({"d": DEF_DIGEST_DOMAIN, "def": normalize(d)})


# ---- pack Merkle root + inclusion proof --------------------------------------------------------------------------------------

def _leaf(digest: str) -> dict:
    return {"d": PACK_DIGEST_DOMAIN, "def": digest}


def _sorted_digests(digests) -> List[str]:
    s = sorted(set(digests))
    if len(s) != len(digests):
        raise ActionKitError("duplicate_def", "a pack lists a def digest twice")
    if not s:
        raise ActionKitError("empty_pack", "a pack has at least one def")
    return s


def pack_root(digests) -> str:
    return merkle_root([_leaf(x) for x in _sorted_digests(digests)])


def _subroot(hs: List[bytes]) -> bytes:
    if len(hs) == 1:
        return hs[0]
    k = _split(len(hs))
    return _node_hash(_subroot(hs[:k]), _subroot(hs[k:]))


def pack_proof(digests, digest: str) -> dict:
    """RFC 6962 inclusion proof of `digest` in the pack made of `digests`: {index, size, path: [{side, hash}]} bottom-up."""
    s = _sorted_digests(digests)
    if digest not in s:
        raise ActionKitError("not_in_pack", "the digest is not in the pack")
    i = s.index(digest)
    hs = [sha256(b"\x00" + canonical_bytes_strict(_leaf(x))) for x in s]
    path, lo, n, idx = [], 0, len(hs), i
    seg = hs
    while len(seg) > 1:
        k = _split(len(seg))
        if idx < k:
            path.append({"side": "R", "hash": b64u(_subroot(seg[k:]))})
            seg = seg[:k]
        else:
            path.append({"side": "L", "hash": b64u(_subroot(seg[:k]))})
            seg = seg[k:]
            idx -= k
    path.reverse()
    return {"index": i, "size": len(s), "path": path}


# ---- T(d), decl(d), eff(d) --------------------------------------------------------------------------------------------------

def implied_from_facts(effects, params, scope: Optional[str], worst_rev: str) -> List[str]:
    """Traits implied by effects, roles, tags, scope and reversibility. params: dicts with type/role/tags/max_items."""
    out: List[str] = []
    for e in effects:
        out.extend(EFFECT_TRAITS[e])  # KeyError on an unknown effect (callers treat it as a forged document)
    ro = is_read_only(effects)
    for p in params:
        r = p.get("role")
        if r is not None:
            if r in ROLE_TRAITS:
                out.extend(ROLE_TRAITS[r])
            if ro and r.startswith("money."):
                out.append("pca.financial_data_read")
        for t in p.get("tags") or []:
            if t in TAG_TRAITS:
                out.extend(TAG_TRAITS[t])
        if p.get("type") == "array" and p.get("max_items") is None:
            out.append("pca.bulk")
    if scope is not None and scope != "one":
        out.append("pca.bulk")
    if worst_rev == "irreversible":
        out.append("pca.irreversible")
    return _sort_uniq(out)


# ---- the signed human confirmation: the ONLY thing that sets traits below the top of the registry ----------------------------

REVIEW_DOMAIN = "atlas-pca/action-review/v2"
VERB_FACTS_DOMAIN = "atlas-pca/action-verb-facts/v1"
KEY_ROLES = ("reviewer", "importer", "model", "publisher")
_JS_WS = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"


def reviewer_pins_error(p: Any) -> Optional[str]:
    """None if the pin set is sound: distinct kids, canonical keys, known roles, no key that is both a reviewer and a machine."""
    if not isinstance(p, dict) or not isinstance(p.get("keys"), list):
        return "pins must be {keys: [...]}"
    kids, machine = set(), set()
    for k in p["keys"]:
        kid = k.get("kid") if isinstance(k, dict) else None
        if not isinstance(kid, str) or len(kid) == 0 or len(_u16key(kid)) > 256:
            return "a pinned key needs a kid"
        if kid in kids:
            return "kid '%s' is pinned twice" % kid
        kids.add(kid)
        if decode_b64u_strict(k.get("pk"), 32) is None:
            return "key '%s': pk is not canonical base64url (32 bytes)" % kid
        r = k.get("roles")
        if not isinstance(r, list) or not r or not all(isinstance(x, str) and x in KEY_ROLES for x in r) or len(set(r)) != len(r):
            return "key '%s': roles must be distinct known roles" % kid
        if "reviewer" in r and ("importer" in r or "model" in r):
            return "key '%s': an importer or model key cannot hold the reviewer role" % kid
        for t in ("not_before", "not_after"):
            if t in k and not _is_nonneg(k[t]):
                return "key '%s': %s must be a non-negative integer" % (kid, t)
        if "importer" in r or "model" in r:
            machine.add(k["pk"])
    for k in p["keys"]:
        if "reviewer" in k["roles"] and k["pk"] in machine:
            return "key '%s': the same key material is pinned as an importer or model key" % k["kid"]
    return None


def facts_digest(v: dict) -> str:
    """b64u(sha256(strictCanonical({d, verb: the verb without traits, floors, confirmation, def}))): the facts the reviewer saw."""
    return hash_canonical({"d": VERB_FACTS_DOMAIN, "verb": {k: x for k, x in v.items() if k not in ("traits", "floors", "confirmation", "def")}})


def review_message(b: dict) -> bytes:
    """REVIEW_DOMAIN \\0 strictCanonical({def_digest, traits_digest, facts_digest, final_traits (sorted), dismissed (by trait), reviewer_kid, ts})."""
    body = {"def_digest": b["def_digest"], "traits_digest": b["traits_digest"], "facts_digest": b["facts_digest"],
            "final_traits": _sort_uniq(b["final_traits"]),
            "dismissed": [{"trait": d["trait"], "reason": d["reason"]} for d in sorted(b["dismissed"], key=lambda d: _u16key(d["trait"]))],
            "reviewer_kid": b["reviewer_kid"], "ts": b["ts"]}
    return (REVIEW_DOMAIN + "\0").encode("utf-8") + canonical_bytes_strict(body)


def _attestation_error(a: dict, reg: Dict[str, dict], pins: dict) -> Optional[str]:
    """Registry digest and attestation member types, shared by def-level and verb-level confirmation. Reason or None."""
    if a["traits_digest"] not in {traits_digest(reg), *(pins.get("traits_digests") or [])}:
        return "made against a different trait registry"
    if not isinstance(a["reviewer_kid"], str) or not _is_int(a["ts"]) or not isinstance(a["final_traits"], list) or not isinstance(a["dismissed"], list):
        return "malformed"
    return None


def _signed_by_reviewer(a: dict, pins: dict) -> Optional[str]:
    fin = set(a["final_traits"])
    if any(d["trait"] in fin or len(d["reason"].strip(_JS_WS)) == 0 for d in a["dismissed"]):
        return "a dismissed trait is also final, or has no reason"
    key = next((k for k in pins["keys"] if k["kid"] == a["reviewer_kid"]), None)
    if key is None:
        return "no pinned key '%s'" % a["reviewer_kid"]
    if "reviewer" not in key["roles"]:
        return "key '%s' does not hold the reviewer role" % key["kid"]
    if ("not_before" in key and a["ts"] < key["not_before"]) or ("not_after" in key and a["ts"] > key["not_after"]):
        return "the time is outside the key validity"
    body = {k: v for k, v in a.items() if k != "sig"}
    return None if _verify_b64u(key["pk"], review_message(body), a["sig"]) else "the signature is invalid"


def verify_attestation(d: Any, reg: Dict[str, dict], pins: Any) -> bool:
    """True iff the def carries a valid human confirmation: state confirmed, an attestation bound to this def digest and the
    declared traits, against an accepted registry digest, signed by a key pinned with the reviewer role. Never raises."""
    try:
        if reviewer_pins_error(pins) is not None or d["review"]["state"] != "confirmed":
            return False
        a = d["review"].get("attestation")
        if not isinstance(a, dict) or not isinstance(a.get("sig"), str) or a["def_digest"] != def_digest(d):
            return False
        if _attestation_error(a, reg, pins) is not None or _sort_uniq(a["final_traits"]) != _sort_uniq(d.get("traits")):
            return False
        return _signed_by_reviewer(a, pins) is None
    except Exception:  # noqa: BLE001
        return False


def verb_confirmation_error(v: Any, reg: Dict[str, dict], pins: Any) -> Optional[str]:
    """None iff this schema verb carries a VALID human confirmation (see verify_attestation); else the reason. Never raises."""
    try:
        if pins is None:
            return "no reviewer keys are pinned"
        pe = reviewer_pins_error(pins)
        if pe:
            return "bad pins: " + pe
        a = v.get("confirmation")
        if not isinstance(a, dict) or not isinstance(a.get("sig"), str):
            return "no valid confirmation"
        if not isinstance(v.get("def"), str) or a["def_digest"] != v["def"]:
            return "the confirmation covers a different def digest"
        e = _attestation_error(a, reg, pins)
        if e:
            return e
        if not isinstance(a.get("facts_digest"), str) or a["facts_digest"] != facts_digest(v):
            return "the confirmation covers different verb facts"
        carried = set(v.get("traits") or [])
        if any(not isinstance(t, str) or t not in carried for t in a["final_traits"]):
            return "the verb does not carry every trait the reviewer signed"
        return _signed_by_reviewer(a, pins)
    except Exception as e:  # noqa: BLE001
        return "malformed confirmation: %s" % e


def top_traits(reg: Dict[str, dict]) -> List[str]:
    return sorted(reg)


def hint_traits(d: dict) -> List[str]:
    """Declared + implied-by-its-own-facts: what the def would have if a reviewer signed it as it stands. Never enforcement."""
    n = normalize(d)
    return _sort_uniq(list(n["traits"]) + implied_from_facts(n["effects"], list(n["params"].values()), n["resource"]["scope"], worst_reversibility(n["reversibility"], n["params"])))


def traits_of(d: dict, reg: Dict[str, dict], pins: Any = None) -> List[str]:
    """T(d): unconfirmed means maximally dangerous (every trait of the registry); a valid signed confirmation sets the hint traits."""
    return hint_traits(d) if verify_attestation(d, reg, pins) else top_traits(reg)


def decl_profile(d: dict) -> dict:
    n = normalize(d)
    critical = any(SENSITIVITY_RANK[effective_param_sensitivity(p)] >= SENSITIVITY_RANK["critical"] for p in n["params"].values())
    return profile({"risk": 2 if critical else (0 if is_read_only(n["effects"]) else 1), "rev": worst_reversibility(n["reversibility"], n["params"]),
                    "blast_ppm": n["blast"]["ppm"], "context": n["context"]})


def effective(d: dict, reg: Dict[str, dict], pins: Any = None) -> dict:
    """{confirmed, traits, closure, floor, decl, eff}: eff = decl join F(T(d)); `pins` = the verifier's pinned reviewer keys."""
    confirmed = verify_attestation(d, reg, pins)
    tr = hint_traits(d) if confirmed else top_traits(reg)
    fl = floor_of(reg, tr)
    dp = decl_profile(d)
    return {"confirmed": confirmed, "traits": tr, "closure": closure(reg, tr), "floor": fl, "decl": dp, "eff": join(dp, fl)}


# ---- rule 22: whole-document integrity of the carried traits and floors ------------------------------------------------------

_PFX = "action.params."


def schema_verb_floor_error(v: Any, reg: Dict[str, dict], pins: Any = None) -> Optional[str]:
    """Recompute from the verb's own visible facts that its `traits` contain every implied trait and that its `floors` are at least the
    floor of the traits' closure and of the declared reversibility. None = consistent; else `<code>: <reason>`. Never raises."""
    try:
        if not isinstance(v.get("effects"), list) or not isinstance(v.get("traits"), list) or "floors" not in v:
            return "schema_floor_forged: not a v2 verb"
        ps = [(path[len(_PFX):], p) for path, p in v["params"].items()]
        by_name = {}
        for name, p in ps:
            e = {"type": p.get("type")}
            if "values" in p:
                e["values"] = p["values"]
            by_name[name] = e
        if v.get("reversibility_by"):
            rb = v["reversibility_by"]
            decl: Any = {"by": rb["param"][len(_PFX):], "map": rb["map"]}
            if "default" in rb:
                decl["default"] = rb["default"]
        else:
            decl = v["reversibility"] if "reversibility" in v else ("reversible" if v.get("kind") == "read" else "irreversible")
        worst = worst_reversibility(decl, by_name)
        implied = implied_from_facts(v["effects"], [p for _, p in ps], None, worst)
        for t in implied:
            if t not in v["traits"]:
                return "schema_traits_forged: missing implied trait %s" % t
        if verb_confirmation_error(v, reg, pins) is not None:  # unconfirmed: the verb must carry the top of the registry
            for t in top_traits(reg):
                if t not in v["traits"]:
                    return "schema_traits_forged: unconfirmed action must carry every trait (missing %s)" % t
        fl = floor_of(reg, v["traits"])
        if not leq(fl, v["floors"]):
            return "schema_floor_forged: floors are below the floor of the carried traits"
        if REV_RANK.get(v["floors"]["rev"], -1) < REV_RANK.get(worst, -1):
            return "schema_floor_forged: floors.rev is below the declared reversibility"
        return None
    except ActionKitError as e:
        return "%s: %s" % (e.code, e)
    except Exception as e:  # noqa: BLE001
        return "schema_floor_forged: %s" % e


def registry_of_schema(doc: dict) -> Dict[str, dict]:
    """Core + the document's own `trait_defs` (checked), and when it carries `traits_digest` the registry must hash to it."""
    td = doc.get("trait_defs")
    reg = extend_registry(CORE_REGISTRY, td) if isinstance(td, list) and len(td) > 0 else CORE_REGISTRY
    if "traits_digest" in doc and doc["traits_digest"] != traits_digest(reg):
        raise ActionKitError("traits_digest_mismatch", "the document's traits_digest does not match its trait registry")
    return reg


def schema_floor_error(doc: dict, pins: Any = None) -> Optional[str]:
    """Rule 22's integrity half for a whole v2 document. None = consistent. Never raises."""
    try:
        reg = registry_of_schema(doc)
        for v in doc["verbs"]:
            e = schema_verb_floor_error(v, reg, pins)
            if e:
                return "%s: %s" % (v["verb"], e)
        return None
    except ActionKitError as e:
        return "%s: %s" % (e.code, e)
    except Exception as e:  # noqa: BLE001
        return "bad_registry: %s" % e
