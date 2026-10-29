"""Intent Layer v2 W-A for the native Python verifier: signed action schemas (rule 14), intent sessions and their
revocation (rule 13), accumulators / monitors / sequencer receipts (rule 15) and the v2 verification pipeline that runs
after the `intent` check (schema -> intent_session -> layers -> accumulators -> facts -> provenance -> classes).

Mirrors packages/pca/src/action-schema.ts (verifier side; the MCP / OpenAPI importers are wallet / developer tooling and
are not ported), intent-session.ts, intent-acc.ts (verifier
parts), intent-revocation.ts (+ the signed revocation epoch and the sorted-Merkle non-membership proof of revocation.ts)
and intent-v2.ts (intent-artifacts.ts, the W-B artifact message / reference rules, lives in intent_wb.py). The suite-agile
artifact signatures of W-A (schemas, session roots, receipts, sequencer key sets, revocation epochs) all go through
atlas_pca.pca's existing suite dispatch (`verify_leaf_suite`) behind one pin resolver, `_pinned_suite_error` (pq.ts
verifyPinnedSuite); a registered suite the dispatch does not implement fails closed with reason `unsupported_suite`.
intent-required.ts (site-signed `intent_required` bodies) is host / wallet tooling the verifier pipeline does not read, so
it is not ported. The reference is STRICT (intent-strict.ts): numbers are safe integers or the check fails closed, lists
are real arrays, keyed lookups read own members only; nothing emulates a host language's coercions. Every public decide /
verify function is total.
"""
import functools
import math
import re
from typing import Any, Dict, List, Optional

from .pca import (
    ACC_ID_RE, _blen, _has_surrogate, _is_safe_int, _js_keys, _js_nonneg_int, _b32, _leaf_hash, _node_hash,
    _num, _path_shape, _resolve_pq_key, b64u, merkle_root, canonical_bytes_strict, canonicalize_strict, decode_b64u_strict,
    grant_session_caveat, hash_canonical, intent_session_caveat_error, params_digest, sha256, suite_available,
    verify_leaf_suite, REGISTERED_SUITES,
)
from .decision import decide_tighten, decide_units, model_paths_read
from .intent_layers import decide_layer_ceilings
from .intent_map import MAP_FORM_COMMIT, decide_map_disclosure
from .intent_wb import decide_intent_wb, validate_wb_context
from .predicates import _js_number_string, _jsnum

# ---- strict value helpers (intent-strict.ts: no host-language coercion anywhere) ------------------------------------
#
# NUMBERS are safe integers (never -0, never a bool, a string or null) or the check fails closed; LISTS are real JSON
# arrays (a string is never iterated); KEYED LOOKUPS read own members of JSON objects only. `_js_keys` (Object.keys
# order) and `compare_utf8` only decide which first failure is reported.

_UNDEF = object()  # an absent member, distinct from JSON null (None)

#: Names the predicate DSL cannot address; refused as parameter, accumulator and monitor names (intent-strict.ts).
RESERVED_NAMES = frozenset(("__proto__", "constructor", "prototype"))


def _prop(o: Any, k: str) -> Any:
    """The own member `k` of a JSON object; _UNDEF when `o` is not an object or has no such member."""
    if isinstance(o, dict) and k in o:
        return o[k]
    return _UNDEF


_own_get = _prop  # ownGet: own members of a JSON object only


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _js_strict_eq(a: Any, b: Any) -> bool:
    """`===` over JSON values: same JSON type and value (2 == 2.0; 1 != "1"; true != 1); containers by identity."""
    if a is _UNDEF or b is _UNDEF:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b


def _u16len(s: str) -> int:
    return sum(2 if ord(c) > 0xFFFF else 1 for c in s)


def _js_str(x: Any) -> str:
    """Text of a JSON value for a reason string (diagnostic only; never part of a decision)."""
    if x is _UNDEF:
        return "undefined"
    if x is None:
        return "null"
    if x is True:
        return "true"
    if x is False:
        return "false"
    if isinstance(x, str):
        return x
    if _is_num(x):
        return _js_number_string(_jsnum(x))  # ECMAScript Number::toString (1e+21, NaN, Infinity, 0 for -0)
    if isinstance(x, list):
        return _js_string(x)  # String([...]): the elements joined by ","
    return "[object Object]" if isinstance(x, dict) else repr(x)


def _js_string(x: Any) -> str:
    """JS String(x) of a JSON value or undefined: exact (it feeds decisions: verb / resource / aud of the PCActn)."""
    if isinstance(x, list):
        return ",".join("" if e is None or e is _UNDEF else _js_string(e) for e in x)
    return _js_str(x)


def _action_member(p: Any, k: str) -> Any:
    """p.action?.<k> (TS optional access: undefined when the PCActn has no action object)."""
    return _prop(_prop(p, "action"), k)


def _fffd(s: str) -> str:
    return "".join("\ufffd" if 0xD800 <= ord(c) <= 0xDFFF else c for c in s)


def compare_utf8(a: str, b: str) -> int:
    """`compareUtf8`: UTF-8 bytewise order (a lone surrogate encodes as U+FFFD, like TextEncoder), ties between distinct
    strings broken by UTF-16 code-unit order."""
    if a == b:
        return 0
    x, y = _fffd(a).encode("utf-8"), _fffd(b).encode("utf-8")
    if x != y:
        return -1 if x < y else 1
    ua, ub = a.encode("utf-16-be", "surrogatepass"), b.encode("utf-16-be", "surrogatepass")
    return -1 if ua < ub else 1


_UTF8_ORDER = functools.cmp_to_key(compare_utf8)


def _sorted_join(o: dict) -> str:
    """`Object.keys(o).sort().join()` (default sort = UTF-16 code-unit order)."""
    return ",".join(sorted(o.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass")))


def _obj_keys(o: Any) -> List[str]:
    """The keys of a JSON object; anything else is a TypeError (fail closed)."""
    if not isinstance(o, dict):
        raise TypeError("expected a JSON object")
    return _js_keys(o)


def _list(x: Any) -> list:
    """A real JSON array; anything else (a string included) is a TypeError (fail closed)."""
    if not isinstance(x, list):
        raise TypeError("expected a JSON array")
    return x


def _includes(container: Any, x: Any) -> bool:
    """Membership in a real JSON array (same JSON type and value); a non-array is a TypeError (fail closed)."""
    return any(_js_strict_eq(e, x) for e in _list(container))


def _in_strs(x: Any, options) -> bool:
    return isinstance(x, str) and x in options


def _bad(reason: str) -> dict:
    return {"ok": False, "reason": reason}


# ---- suite-agile signatures over a verifier-pinned key (pq.ts verifyPinnedSuite) -------------------------------------

UNSUPPORTED_SUITE = "unsupported_suite"


class UnsupportedSuiteReason(str):
    """A reason string that carries the STRUCTURED "unsupported suite" signal. Only `suite_capability_error` mints one
    (and `_ctx` keeps it when a caller prefixes context); `_unsupported` tests the type, never the text, so a shape error
    that merely echoes an attacker-chosen member name such as `unsupported_suite` is not misclassified."""

    __slots__ = ()


def _ctx(prefix: str, reason: str) -> str:
    """`prefix + reason`, preserving the UnsupportedSuiteReason signal."""
    return UnsupportedSuiteReason(prefix + reason) if isinstance(reason, UnsupportedSuiteReason) else prefix + reason


def _resolve_registered(alg: Any) -> Optional[str]:
    """The suite an artifact's `alg` names, as atlas_pca.pca's suite dispatch knows it: absent (_UNDEF) -> ed25519; a
    suite the dispatch implements in this runtime (`suite_available`) -> itself; anything else (JSON null, a non-string,
    an unimplemented or unknown name) -> None. (The README's suite capability: what this verifier cannot check it never accepts.)"""
    if alg is _UNDEF:
        return "ed25519"
    if isinstance(alg, str) and suite_available(alg):
        return alg
    return None


def suite_capability_error(alg: Any) -> Optional[str]:
    """intent-strict.ts suiteCapabilityError with this verifier's dispatch: absent `alg` = ed25519 (None); a non-string
    is malformed; a string the suite dispatch does not implement is "unsupported_suite: '<alg>'"."""
    if alg is _UNDEF:
        return None
    if not isinstance(alg, str):
        return "alg must be a string"
    return None if suite_available(alg) else UnsupportedSuiteReason("%s: '%s'" % (UNSUPPORTED_SUITE, alg))


def _suite_known_error(alg: Any) -> Optional[str]:
    """suite_capability_error for a session root's SHAPE: a registered suite (REGISTERED_SUITES, the TS registry) passes
    even when this runtime cannot run it, so verify_session_root's verifier-pin checks (no crypto) run before
    availability, in the reference's order; verify_session_root refuses an unavailable signer suite after the pins."""
    if alg is _UNDEF:
        return None
    if not isinstance(alg, str):
        return "alg must be a string"
    return None if alg in REGISTERED_SUITES else UnsupportedSuiteReason("%s: '%s'" % (UNSUPPORTED_SUITE, alg))


def _bind_suite_fields(base: dict, alg: Any, pq_pk: Any) -> dict:
    """`bindSuiteFields`: a non-ed25519 suite binds `alg` and `pq_pk` into the signed body (an absent pq_pk cannot be
    canonicalised: TypeError, fail closed)."""
    suite = _resolve_registered(alg)
    if suite is None or suite == "ed25519":
        return base
    if pq_pk is _UNDEF:
        raise TypeError("canonicalize: unsupported type undefined")
    out = dict(base)
    out["alg"] = suite
    out["pq_pk"] = pq_pk
    return out


def _pinned_suite_error(alg: Any, identity: Any, artifact_pq_pk: Any, msg: bytes, sig: Any, pq_sig: Any,
                        pins: Optional[dict]) -> Optional[str]:
    """`verifyPinnedSuite(alg, identity, artifactPqPk, msg, {sig, pq_sig}, {pqPins: pins})` through atlas_pca.pca's
    EXISTING suite dispatch (`verify_leaf_suite`, the one the leaf and the pq_artifact checks use). A non-ed25519 suite
    verifies only under `pins[identity]`, which must equal the artifact's `pq_pk` (natives have no allowUnboundPq).
    Returns None when the signature verifies, "invalid" when it does not, and a reason containing "unsupported_suite"
    for a suite the dispatch does not implement. Total."""
    try:
        se = suite_capability_error(alg)
        if se is not None:
            return se if _unsupported(se) else "invalid"
        suite = _resolve_registered(alg)
        p = {"sig": sig} if suite == "ed25519" else {"alg": suite, "sig": sig}
        if suite != "ed25519":
            pq = _resolve_pq_key(identity, None if artifact_pq_pk is _UNDEF else artifact_pq_pk, pq_pins=pins)
            if pq is None:
                return "invalid"
            p["pq_pk"] = pq.key
            if pq_sig is not _UNDEF:
                p["pq_sig"] = pq_sig
        if not isinstance(sig, str) or not isinstance(identity, str):
            return "invalid"
        return None if verify_leaf_suite(p, identity, msg) else "invalid"
    except Exception:  # noqa: BLE001 - total
        return "invalid"


def _unsupported(err: Optional[str]) -> bool:
    return isinstance(err, UnsupportedSuiteReason)


# ---- action-schema.ts (rule 14) ---------------------------------------------------------------------------------------

ACTION_SCHEMA_DOMAIN = "atlas-pca/action-schema/v1\x00"
ACTION_SCHEMA_REF_DOMAIN = "atlas-pca/action-schema-ref/v1"
ACTION_SCHEMA_KIND = "pca-action-schema"
SENSITIVITIES = ("free", "material", "critical")
SCHEMA_REVERSIBILITY = ("reversible", "rate_limited", "irreversible")
PARAM_TYPES = ("string", "integer", "boolean", "date", "set", "array")
PARAM_TYPES_V2 = PARAM_TYPES + ("datetime", "duration", "object_ref")
SCHEMA_V2_EFFECTS = ("read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign")
SCHEMA_V2_CAVEATS = ("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap")
SCHEMA_V2_PRULES = ("array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
                    "pay_has_idempotency", "recipient_param_declared", "secret_not_logged")
SCHEMA_V2_CONTEXT = ("approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested")
SCHEMA_V2_TAGS = ("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql")
SCHEMA_V2_PROVENANCE = ("first_party", "tool", "agent")
MAX_SCHEMA_VERBS = 256
MAX_SCHEMA_PARAMS = 64
MAX_SCHEMA_VALUES = 256
DEFAULT_MAX_LEN = 1024
DEFAULT_MAX_ITEMS = 64
PARAM_PATH_RE = re.compile(r"action\.params\.[A-Za-z0-9_]{1,64}")  # always used with fullmatch
UNIT_ID_RE = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)*")  # always used with fullmatch
PARAM_PATH_RE_V2 = re.compile(r"action\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}")
_PARAMS_PREFIX = "action.params."
_TRAIT_ID_RE = re.compile(r"[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}")
_TAINT_CTX_RE = re.compile(r"session_taint_max:[a-z_]{1,16}")

_DOC_KEYS = frozenset(("v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig"))
_DOC_KEYS_V2 = _DOC_KEYS | frozenset(("traits_digest", "trait_defs", "pack"))
_VERB_KEYS = frozenset(("verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world",
                        "effects", "returns", "description"))
_VERB_KEYS_V2 = _VERB_KEYS | frozenset(("traits", "def", "floors", "confirmation"))
_PARAM_KEYS = frozenset((
    "type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items", "min_items",
    "max_items", "default", "principal_neutral_default", "accumulates_into", "issued_by_site", "description",
))
_PARAM_KEYS_V2 = _PARAM_KEYS | frozenset(("role", "format", "tags", "provenance_min"))
_SIG_KEYS = frozenset(("alg", "kid", "value", "pq_value"))


def _is_str(v: Any, mx: int = 256) -> bool:
    return isinstance(v, str) and len(v) > 0 and not _has_surrogate(v) and _blen(v) <= mx


def _param_decl_error(path: str, d: Any, units: Any, v2: bool = False) -> Optional[str]:
    if (PARAM_PATH_RE_V2 if v2 else PARAM_PATH_RE).fullmatch(path) is None:
        return "parameter path '%s' is not action.params.<name>" % path
    if any(seg in RESERVED_NAMES for seg in path[len(_PARAMS_PREFIX):].split(".")):
        return "parameter name '%s' is reserved (__proto__ / constructor / prototype)" % path
    if not isinstance(d, dict):
        return "%s: declaration must be an object" % path
    for k in _js_keys(d):
        if k not in (_PARAM_KEYS_V2 if v2 else _PARAM_KEYS):
            return "%s: unknown member '%s'" % (path, k)
    t = d.get("type", _UNDEF)
    if not _in_strs(t, PARAM_TYPES_V2 if v2 else PARAM_TYPES):
        return "%s: unknown type" % path
    if not _is_str(d.get("semantic"), 128):
        return "%s: semantic must be a non-empty string" % path
    if not _in_strs(d.get("sensitivity"), SENSITIVITIES):
        return "%s: unknown sensitivity" % path
    if "required" in d and not isinstance(d["required"], bool):
        return "%s: required must be a boolean" % path
    if "values" in d:
        vals = d["values"]
        if not isinstance(vals, list) or len(vals) == 0 or len(vals) > MAX_SCHEMA_VALUES or not all(_is_str(x) for x in vals):
            return "%s: values must be 1..%d strings" % (path, MAX_SCHEMA_VALUES)
        if len(set(vals)) != len(vals):
            return "%s: values must be distinct" % path
        if t != "string" and t != "set":
            return "%s: values apply to string and set only" % path
    if t == "set" and "values" not in d:
        return "%s: a set needs values" % path
    for k in ("min", "max"):
        if k in d and (not _is_safe_int(d[k]) or (t != "integer" and not (v2 and t == "duration") and not (t == "array" and _js_strict_eq(d.get("items", _UNDEF), "integer")))):
            return "%s: %s must be a safe integer on an integer parameter" % (path, k)
    if _is_safe_int(d.get("min")) and _is_safe_int(d.get("max")) and d["min"] > d["max"]:
        return "%s: min > max" % path
    if "unit" in d and (t != "integer" or not isinstance(d["unit"], str) or not isinstance(units, dict)
                        or _own_get(units, d["unit"]) is _UNDEF):
        return "%s: unit must name a declared unit of an integer parameter" % path
    if "max_len" in d and (not _is_safe_int(d["max_len"]) or d["max_len"] < 1):
        return "%s: max_len must be a positive safe integer" % path
    if "items" in d and (t != "array" or not _is_str(d["items"], 64)):
        return "%s: items applies to array only" % path
    for k in ("min_items", "max_items"):
        if k in d and (not _js_nonneg_int(d[k]) or (t != "set" and t != "array")):
            return "%s: %s must be a non-negative safe integer on a set or array" % (path, k)
    if _is_safe_int(d.get("min_items")) and _is_safe_int(d.get("max_items")) and d["min_items"] > d["max_items"]:
        return "%s: min_items > max_items" % path
    if "default" in d and d["default"] is None:
        return "%s: default must not be null (absent = no default)" % path
    if "principal_neutral_default" in d and not isinstance(d["principal_neutral_default"], bool):
        return "%s: principal_neutral_default must be a boolean" % path
    if d.get("principal_neutral_default") is True and "default" not in d:
        return "%s: principal_neutral_default needs a default" % path
    if "accumulates_into" in d:
        ai = d["accumulates_into"]
        if t != "integer":
            return "%s: accumulates_into applies to integer parameters only" % path
        if not isinstance(ai, list) or len(ai) == 0 or len(ai) > 8:
            return "%s: accumulates_into must be 1..8 unit ids" % path
        if not all(isinstance(u, str) and _u16len(u) <= 64 and UNIT_ID_RE.fullmatch(u) for u in ai):
            return "%s: accumulates_into entries must be unit ids" % path
        if len(set(ai)) != len(ai):
            return "%s: accumulates_into must be distinct" % path
    if "issued_by_site" in d and not isinstance(d["issued_by_site"], bool):
        return "%s: issued_by_site must be a boolean" % path
    if "description" in d and not _is_str(d["description"], 1024):
        return "%s: description must be a string" % path
    if v2:
        if "role" in d and not _is_str(d["role"], 128):
            return "%s: role must be a non-empty string" % path
        if "format" in d and (not isinstance(d["format"], str) or format_check(d["format"]) is None or t not in ("string", "object_ref")):
            return "%s: format must be a known format on a string parameter" % path
        if "tags" in d:
            tg = d["tags"]
            if not isinstance(tg, list) or len(tg) > len(SCHEMA_V2_TAGS) or len(set(map(str, tg))) != len(tg) or not all(_in_strs(x, SCHEMA_V2_TAGS) for x in tg):
                return "%s: tags must be distinct known tags" % path
        if "provenance_min" in d and not _in_strs(d["provenance_min"], SCHEMA_V2_PROVENANCE):
            return "%s: unknown provenance_min" % path
    return None


def schema_floors_error(f: Any) -> Optional[str]:
    """Null if `f` is a well-formed materialized profile (shape only; the semantic check is rule 22)."""
    if not isinstance(f, dict):
        return "floors must be an object"
    for k in _js_keys(f):
        if k not in ("risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"):
            return "floors: unknown member '%s'" % k
    def rng(x, lo, hi):
        return _is_safe_int(x) and lo <= x <= hi
    if not rng(f.get("risk"), 0, 3) or not rng(f.get("esc"), 0, 3):
        return "floors.risk and floors.esc must be integers in 0..3"
    if not _in_strs(f.get("rev"), SCHEMA_REVERSIBILITY):
        return "floors.rev is not a reversibility class"
    if not rng(f.get("blast_ppm"), 0, 1000000):
        return "floors.blast_ppm must be an integer in 0..1000000"
    for name, ok in (("caveats", lambda x: x in SCHEMA_V2_CAVEATS),
                     ("context", lambda x: x in SCHEMA_V2_CONTEXT or _TAINT_CTX_RE.fullmatch(x) is not None),
                     ("prules", lambda x: x in SCHEMA_V2_PRULES)):
        a = f.get(name)
        if not isinstance(a, list) or len(a) > 64 or not all(isinstance(x, str) and ok(x) for x in a):
            return "floors.%s must be an array of known entries" % name
        for i in range(1, len(a)):
            if not (a[i - 1] < a[i]):
                return "floors.%s must be sorted and distinct" % name
    return None


def confirmation_shape_error(c: Any) -> Optional[str]:
    """None if `c` is a well-formed verb `confirmation` (shape only; the signature check is rule 22)."""
    if not isinstance(c, dict):
        return "confirmation must be an object"
    for k in _js_keys(c):
        if k not in ("def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig"):
            return "confirmation: unknown member '%s'" % k
    if decode_b64u_strict(c.get("def_digest"), 32) is None or decode_b64u_strict(c.get("traits_digest"), 32) is None or decode_b64u_strict(c.get("facts_digest"), 32) is None:
        return "confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests"
    if decode_b64u_strict(c.get("sig"), 64) is None:
        return "confirmation: sig must be a canonical base64url 64-byte signature"
    ft = c.get("final_traits")
    if not isinstance(ft, list) or len(ft) > 64 or not all(isinstance(x, str) and _TRAIT_ID_RE.fullmatch(x) for x in ft):
        return "confirmation: final_traits must be trait ids"
    if any(not (ft[i - 1] < ft[i]) for i in range(1, len(ft))):
        return "confirmation: final_traits must be sorted and distinct"
    dm = c.get("dismissed")
    if not isinstance(dm, list) or len(dm) > 64:
        return "confirmation: dismissed must be an array"
    for d in dm:
        if not isinstance(d, dict) or any(k not in ("trait", "reason") for k in d) or not isinstance(d.get("trait"), str) \
                or not _TRAIT_ID_RE.fullmatch(d["trait"]) or not _is_str(d.get("reason"), 256):
            return "confirmation: dismissed entries must be {trait, reason}"
    if not _is_str(c.get("reviewer_kid"), 128):
        return "confirmation: reviewer_kid must be a non-empty string"
    ts = c.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not _is_safe_int(ts) or ts < 0:
        return "confirmation: ts must be a non-negative safe integer"
    return None


def _verb_decl_error(v: Any, units: Any, v2: bool = False) -> Optional[str]:
    if not isinstance(v, dict):
        return "verb entry must be an object"
    for k in _js_keys(v):
        if k not in (_VERB_KEYS_V2 if v2 else _VERB_KEYS):
            return "verb entry: unknown member '%s'" % k
    if not _is_str(v.get("verb"), 128):
        return "verb entry: verb must be a non-empty string"
    at = "verb '%s'" % v["verb"]
    if not _in_strs(v.get("kind"), ("read", "write")):
        return "%s: kind must be read or write" % at
    params = v.get("params")
    if not isinstance(params, dict):
        return "%s: params must be an object" % at
    names = _js_keys(params)
    if len(names) > MAX_SCHEMA_PARAMS:
        return "%s: more than %d parameters" % (at, MAX_SCHEMA_PARAMS)
    for p in names:
        e = _param_decl_error(p, params[p], units, v2)
        if e:
            return "%s: %s" % (at, e)
    if v2:
        for p in names:
            for q in names:
                if q != p and q.startswith(p + "."):
                    return "%s: parameter '%s' is both a value and the parent of '%s'" % (at, p, q)
    if "reversibility" in v and not _in_strs(v["reversibility"], SCHEMA_REVERSIBILITY):
        return "%s: unknown reversibility" % at
    if "reversibility_by" in v:
        r = v["reversibility_by"]
        if not isinstance(r, dict) or any(k not in ("param", "map", "default") for k in r):
            return "%s: reversibility_by must be {param, map, default?}" % at
        if not isinstance(r.get("param"), str) or r["param"] not in params:
            return "%s: reversibility_by.param must be a declared parameter" % at
        m = r.get("map")
        if not isinstance(m, dict) or len(m) == 0 or not all(_in_strs(x, SCHEMA_REVERSIBILITY) for x in m.values()):
            return "%s: reversibility_by.map must map values to reversibility classes" % at
        if "default" in r and not _in_strs(r["default"], SCHEMA_REVERSIBILITY):
            return "%s: reversibility_by.default is not a reversibility class" % at
    if "mcp" in v:
        m = v["mcp"]
        if not isinstance(m, dict) or ",".join(_js_keys(m)) != "tool" or not _is_str(m.get("tool"), 128):
            return "%s: mcp must be {tool}" % at
    if "openapi" in v:
        o = v["openapi"]
        if not isinstance(o, dict) or ",".join(_js_keys(o)) != "operationId" or not _is_str(o.get("operationId"), 128):
            return "%s: openapi must be {operationId}" % at
    for k in (("harm", "returns") if v2 else ("harm", "effects", "returns")):
        if k in v and not isinstance(v[k], dict):
            return "%s: %s must be an object" % (at, k)
    if v2:
        ef = v.get("effects")
        if not isinstance(ef, list) or len(ef) == 0 or len(ef) > len(SCHEMA_V2_EFFECTS) or not all(_in_strs(x, SCHEMA_V2_EFFECTS) for x in ef):
            return "%s: effects must be 1..%d known effects" % (at, len(SCHEMA_V2_EFFECTS))
        for i in range(1, len(ef)):
            if not (ef[i - 1] < ef[i]):
                return "%s: effects must be sorted and distinct" % at
        if (v.get("kind") == "read") != all(x == "read" for x in ef):
            return "%s: kind read must hold exactly when every effect is read" % at
        tr = v.get("traits")
        if not isinstance(tr, list) or len(tr) > 64 or not all(isinstance(x, str) and _TRAIT_ID_RE.fullmatch(x) for x in tr):
            return "%s: traits must be trait ids" % at
        for i in range(1, len(tr)):
            if not (tr[i - 1] < tr[i]):
                return "%s: traits must be sorted and distinct" % at
        if decode_b64u_strict(v.get("def"), 32) is None:
            return "%s: def must be a canonical base64url SHA-256 digest" % at
        fe = schema_floors_error(v.get("floors"))
        if fe:
            return "%s: %s" % (at, fe)
        if "confirmation" in v:
            ce = confirmation_shape_error(v["confirmation"])
            if ce:
                return "%s: %s" % (at, ce)
    if "world" in v and not isinstance(v["world"], list):
        return "%s: world must be an array" % at
    if "description" in v and not _is_str(v["description"], 1024):
        return "%s: description must be a string" % at
    return None


def action_schema_shape_error(doc: Any, signed: bool = True) -> Optional[str]:
    """Structural validation of an (optionally unsigned) `pca-action-schema` v1 document. None = well-formed. Total."""
    try:
        if not isinstance(doc, dict):
            return "schema is not an object"
        v2 = _js_strict_eq(doc.get("v", _UNDEF), 2)
        for k in _js_keys(doc):
            if k not in (_DOC_KEYS_V2 if v2 else _DOC_KEYS):
                return "unknown member '%s'" % k
        if not _js_strict_eq(doc.get("v", _UNDEF), 1) and not v2:
            return "unsupported schema version"
        if not _js_strict_eq(doc.get("kind", _UNDEF), ACTION_SCHEMA_KIND):
            return "kind must be '%s'" % ACTION_SCHEMA_KIND
        if not _is_str(doc.get("site"), 2048) or not _is_str(doc.get("aud"), 256) or not _is_str(doc.get("version"), 128):
            return "site, aud and version must be non-empty strings"
        units = doc.get("units", _UNDEF)
        if units is not _UNDEF:
            if not isinstance(units, dict):
                return "units must be an object"
            for uid in _js_keys(units):
                u = units[uid]
                if UNIT_ID_RE.fullmatch(uid) is None or _u16len(uid) > 64:
                    return "unit id '%s' is malformed" % uid
                if not isinstance(u, dict) or not _is_str(u.get("kind"), 64):
                    return "unit '%s' must be an object with a kind" % uid
                if any(k not in ("kind", "currency", "exponent") for k in u):
                    return "unit '%s': unknown member" % uid
                if "currency" in u and not _is_str(u["currency"], 16):
                    return "unit '%s': currency must be a string" % uid
                if "exponent" in u and not (_js_nonneg_int(u["exponent"]) and u["exponent"] <= 18):
                    return "unit '%s': exponent must be an integer in [0, 18]" % uid
        if "state" in doc and not isinstance(doc["state"], list):
            return "state must be an array"
        if v2:
            if "traits_digest" in doc and decode_b64u_strict(doc["traits_digest"], 32) is None:
                return "traits_digest must be a canonical base64url SHA-256 digest"
            if "trait_defs" in doc and (not isinstance(doc["trait_defs"], list) or len(doc["trait_defs"]) > 64
                                        or not all(isinstance(x, dict) for x in doc["trait_defs"])):
                return "trait_defs must be an array of up to 64 objects"
            if "pack" in doc:
                pk = doc["pack"]
                if (not isinstance(pk, dict) or _sorted_join(pk) != "ns,root,version" or not _is_str(pk.get("ns"), 64)
                        or not _is_str(pk.get("version"), 128) or decode_b64u_strict(pk.get("root"), 32) is None):
                    return "pack must be {ns, version, root}"
        verbs = doc.get("verbs")
        if not isinstance(verbs, list) or len(verbs) == 0 or len(verbs) > MAX_SCHEMA_VERBS:
            return "verbs must be 1..%d entries" % MAX_SCHEMA_VERBS
        seen = set()
        for v in verbs:
            e = _verb_decl_error(v, units, v2)
            if e:
                return e
            if v["verb"] in seen:
                return "verb '%s' is declared twice" % v["verb"]
            seen.add(v["verb"])
        if signed:
            s = doc.get("sig")
            if not isinstance(s, dict):
                return "sig must be an object"
            for k in _js_keys(s):
                if k not in _SIG_KEYS:
                    return "sig: unknown member '%s'" % k
            se = suite_capability_error(s.get("alg", _UNDEF))
            if se:
                return _ctx("sig.alg: ", se)
            if not _is_str(s.get("kid"), 128):
                return "sig.kid must be a non-empty string"
            if decode_b64u_strict(s.get("value")) is None:
                return "sig.value is not canonical base64url"
            if "pq_value" in s and decode_b64u_strict(s["pq_value"]) is None:
                return "sig.pq_value is not canonical base64url"
        elif "sig" in doc:
            return "an unsigned schema must not carry sig"
        canonical_bytes_strict({k: v for k, v in doc.items() if k != "sig"})
        return None
    except Exception as e:  # noqa: BLE001
        return "malformed schema: %s" % e


def _schema_message(doc: dict) -> bytes:
    return ACTION_SCHEMA_DOMAIN.encode("utf-8") + canonical_bytes_strict({k: v for k, v in doc.items() if k != "sig"})


def verify_action_schema(doc: Any, keys: Any) -> dict:
    """Verify a site-signed schema against the discovery key list: shape, `sig.kid` names a listed key, `sig.alg` equals
    that key's suite (the suite is pinned by the key entry), and the signature verifies (a PQ key only as the entry's
    pinned `pq_pk`). Returns {"ok": True} or {"ok": False, "reason"}. Total."""
    try:
        bad = action_schema_shape_error(doc)
        if bad:
            return _bad(bad)
        kid = doc["sig"]["kid"]
        if not isinstance(keys, list):
            return _bad("the schema keys must be an array")
        key = None
        for k in keys:
            if isinstance(k, dict) and _js_strict_eq(k.get("kid", _UNDEF), kid):
                key = k
                break
        if key is None:
            return _bad("no schema key with kid '%s'" % kid)
        if "pq_pk" in key and not isinstance(key["pq_pk"], str):
            return _bad("the schema key pq_pk must be a string")
        if decode_b64u_strict(key.get("pk"), 32) is None:
            return _bad("schema key pk is not canonical base64url (32 bytes)")
        kse = suite_capability_error(key.get("alg", _UNDEF))
        if kse:
            return _bad("schema key: %s" % kse)
        ka = _resolve_registered(key.get("alg", _UNDEF))
        if ka is None or ka != _resolve_registered(doc["sig"].get("alg", _UNDEF)):
            return _bad("sig.alg does not match the pinned key suite")
        pins = {key["pk"]: key["pq_pk"]} if "pq_pk" in key else None
        err = _pinned_suite_error(ka, key["pk"], key.get("pq_pk", _UNDEF), _schema_message(doc), doc["sig"]["value"],
                                  doc["sig"].get("pq_value", _UNDEF), pins)
        if err is not None:
            return _bad(err if _unsupported(err) else "schema signature invalid")
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return _bad("schema verification error: %s" % e)


def action_schema_digest(doc: Any) -> str:
    """The schema's content address over the whole signed document. Raises on an out-of-profile document."""
    return hash_canonical({"d": ACTION_SCHEMA_REF_DOMAIN, "s": doc})


def schema_verb(doc: Any, verb: Any) -> Optional[dict]:
    """The verb entry named `verb` (first match), else None."""
    verbs = _prop(doc, "verbs")
    if not isinstance(verbs, list):
        return None
    for v in verbs:
        if v is None:
            raise TypeError("a verb entry must not be null")  # TS: `null.verb` throws
        if not isinstance(v, dict):
            continue  # a string / number / array has no own `verb` member (reads undefined)
        if _js_strict_eq(v.get("verb", _UNDEF), verb):
            return v
    return None


_DATE_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")  # always used with fullmatch


def _is_calendar_date(s: str) -> bool:
    m = _DATE_RE.fullmatch(s)
    if not m:
        return False
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if y < 1 or mo < 1 or mo > 12 or d < 1:
        return False
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    return d <= dim


def _str_ok(x: Any, max_len: Any) -> bool:
    return isinstance(x, str) and not _has_surrogate(x) and _blen(x) <= max_len


def _dflt(d: dict, k: str, default: Any) -> Any:
    """`d.k` when present, `default` when absent (a validated declaration never carries null)."""
    v = d.get(k, _UNDEF)
    return default if v is _UNDEF else v


# ---- v2 string formats (syntactic checks, identical in every language) ------------------------------------------------
_JS_WS = "\\t\\n\\v\\f\\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"  # ECMAScript \s
_NS = "[^%s]" % _JS_WS
_FORMAT_RES = {
    "email": re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+"),
    "url": re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^%s/?#]+%s*" % (_JS_WS, _NS)),
    "uri_https": re.compile(r"https://[^%s/?#]+%s*" % (_JS_WS, _NS)),
    "uuid": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "phone_e164": re.compile(r"\+[1-9][0-9]{6,14}"),
    "iso_country": re.compile(r"[A-Z]{2}"),
    "iso_currency": re.compile(r"[A-Z]{3}"),
    "semver": re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?(?:\+[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?"),
    "sha256": re.compile(r"[0-9a-f]{64}"),
}
_IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")
_CIDR4_RE = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})")
_CIDR6_RE = re.compile(r"([0-9a-fA-F:]{2,39})/([0-9]{1,3})")
_ID_FORMAT_RE = re.compile(r"id:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}")
_ID_VALUE_RE = re.compile(r"[A-Za-z0-9._:\-]{1,128}")
_DATETIME_RE = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.[0-9]{1,3})?Z")


def _canon_dec(n: str) -> bool:
    return str(int(n)) == n


def _iban_ok(s: str) -> bool:
    if _IBAN_RE.fullmatch(s) is None:
        return False
    rem = 0
    for ch in s[4:] + s[:4]:
        v = ord(ch) - 55 if ch >= "A" else ord(ch) - 48
        rem = (rem * 100 + v if v > 9 else rem * 10 + v) % 97
    return rem == 1


def _cidr_ok(s: str) -> bool:
    m = _CIDR4_RE.fullmatch(s)
    if m:
        return all(int(o) <= 255 and _canon_dec(o) for o in m.groups()[:4]) and int(m.group(5)) <= 32 and _canon_dec(m.group(5))
    m = _CIDR6_RE.fullmatch(s)
    return bool(m) and m.group(1).count(":") >= 2 and ":::" not in m.group(1) and int(m.group(2)) <= 128 and _canon_dec(m.group(2))


def format_check(f: str):
    """The checker of a v2 `format`, or None when the format is unknown. `id:<type>` accepts a 1..128 character safe id."""
    if f == "email":
        return lambda s: len(s) <= 254 and _FORMAT_RES["email"].fullmatch(s) is not None
    if f == "iban":
        return _iban_ok
    if f == "cidr":
        return _cidr_ok
    if f in _FORMAT_RES:
        return lambda s, r=_FORMAT_RES[f]: r.fullmatch(s) is not None
    if _ID_FORMAT_RE.fullmatch(f):
        return lambda s: _ID_VALUE_RE.fullmatch(s) is not None
    return None


def _format_violation(d: dict, x: str) -> Optional[dict]:
    if "format" not in d:
        return None
    ck = format_check(d["format"])
    if ck is None or not ck(x):
        return {"code": "out_of_domain", "reason": "not a valid %s" % _js_str(d["format"])}
    return None


def param_value_violation(d: dict, x: Any) -> Optional[dict]:
    """Value check of one declared parameter: None = in the declared domain, else {"code", "reason"} with code
    `bad_type` or `out_of_domain`. A declaration that is not an object is a TypeError (fail closed)."""
    if not isinstance(d, dict):
        raise TypeError("a parameter declaration must be an object")
    max_len = _dflt(d, "max_len", DEFAULT_MAX_LEN)
    t = d.get("type", _UNDEF)
    if t == "string":
        if not isinstance(x, str) or _has_surrogate(x):
            return {"code": "bad_type", "reason": "expected a string"}
        if _blen(x) > max_len:
            return {"code": "out_of_domain", "reason": "longer than %s UTF-8 bytes" % _js_str(max_len)}
        if "values" in d and not _includes(d["values"], x):
            return {"code": "out_of_domain", "reason": "not one of the declared values"}
        return _format_violation(d, x)
    if t == "object_ref":
        if not isinstance(x, str) or _has_surrogate(x) or len(x) == 0:
            return {"code": "bad_type", "reason": "expected a non-empty id string"}
        if _blen(x) > max_len:
            return {"code": "out_of_domain", "reason": "longer than %s UTF-8 bytes" % _js_str(max_len)}
        return _format_violation(d, x)
    if t == "datetime":
        if not isinstance(x, str):
            return {"code": "bad_type", "reason": "expected an RFC 3339 UTC string"}
        m = _DATETIME_RE.fullmatch(x)
        if m and _is_calendar_date(m.group(1)):
            return None
        return {"code": "out_of_domain", "reason": "not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z"}
    if t == "duration":
        if not _is_safe_int(x):
            return {"code": "bad_type", "reason": "expected a safe integer (milliseconds)"}
        if x < 0:
            return {"code": "out_of_domain", "reason": "a duration is not negative"}
        if "min" in d and x < d["min"]:
            return {"code": "out_of_domain", "reason": "below min %s" % _js_str(d["min"])}
        if "max" in d and x > d["max"]:
            return {"code": "out_of_domain", "reason": "above max %s" % _js_str(d["max"])}
        return None
    if t == "integer":
        if not _is_safe_int(x):
            return {"code": "bad_type", "reason": "expected a safe integer"}
        if "min" in d and x < d["min"]:
            return {"code": "out_of_domain", "reason": "below min %s" % _js_str(d["min"])}
        if "max" in d and x > d["max"]:
            return {"code": "out_of_domain", "reason": "above max %s" % _js_str(d["max"])}
        return None
    if t == "boolean":
        return None if isinstance(x, bool) else {"code": "bad_type", "reason": "expected a boolean"}
    if t == "date":
        if not isinstance(x, str):
            return {"code": "bad_type", "reason": "expected a YYYY-MM-DD string"}
        return None if _is_calendar_date(x) else {"code": "out_of_domain", "reason": "not a calendar date YYYY-MM-DD"}
    if t == "set":
        if not isinstance(x, list) or not all(isinstance(e, str) for e in x):
            return {"code": "bad_type", "reason": "expected an array of strings"}
        if len(set(x)) != len(x):
            return {"code": "out_of_domain", "reason": "set members must be distinct"}
        vals = d["values"]
        if not all(_includes(vals, e) for e in x):
            return {"code": "out_of_domain", "reason": "set member not among the declared values"}
        if len(x) < _dflt(d, "min_items", 0) or len(x) > _dflt(d, "max_items", len(vals)):
            return {"code": "out_of_domain", "reason": "set size outside the declared bounds"}
        return None
    if t == "array":
        if not isinstance(x, list):
            return {"code": "bad_type", "reason": "expected an array"}
        ints = _js_strict_eq(d.get("items", _UNDEF), "integer")
        for e in x:
            if (not _is_safe_int(e)) if ints else (not _str_ok(e, max_len)):
                return {"code": "bad_type", "reason": "array items must be safe integers" if ints
                        else "array items must be strings of at most %s UTF-8 bytes" % _js_str(max_len)}
            if ints and (("min" in d and e < d["min"]) or ("max" in d and e > d["max"])):
                return {"code": "out_of_domain", "reason": "array item outside min/max"}
        if len(x) < _dflt(d, "min_items", 0) or len(x) > _dflt(d, "max_items", DEFAULT_MAX_ITEMS):
            return {"code": "out_of_domain", "reason": "array length outside the declared bounds"}
        return None
    return {"code": "bad_type", "reason": "unknown declared type"}


def conform_action(doc: Any, verb: Any, params: Any) -> dict:
    """Map an action to Omega_S or to the fail-closed cell (rule 14 step 5). First failure wins:
      1. `params` is not a JSON object                                        -> params_not_object
      2. no verb entry named `verb`                                           -> unknown_verb
      3. a key of `params` (UTF-8 byte order) whose `action.params.<key>` is not declared -> undeclared_param
      4. every declared path in UTF-8 byte order: absent and required (default true) -> missing_param; present: the
         value check of param_value_violation                                 -> bad_type / out_of_domain
    Returns {"ok": True, "verb": entry} or {"ok": False, "code", "path"?, "reason"}. Like the TS it is not wrapped:
    a malformed (unverified) schema raises TypeError."""
    if not isinstance(params, dict):
        return {"ok": False, "code": "params_not_object", "reason": "params must be a JSON object"}
    v = schema_verb(doc, verb)
    if v is None:
        return {"ok": False, "code": "unknown_verb", "reason": "verb '%s' is not declared by the schema" % _js_str(verb)}
    vp = v.get("params", _UNDEF)
    if not isinstance(vp, dict):
        raise TypeError("the verb's params must be an object")
    for k in sorted(params.keys(), key=_UTF8_ORDER):
        path = _PARAMS_PREFIX + k
        if _own_get(vp, path) is _UNDEF:
            return {"ok": False, "code": "undeclared_param", "path": path,
                    "reason": "parameter '%s' is not declared for '%s'" % (path, _js_str(verb))}
    for path in sorted(_obj_keys(vp), key=_UTF8_ORDER):
        d = _own_get(vp, path)
        name = path[len(_PARAMS_PREFIX):]
        if name not in params:
            if not isinstance(d, dict):
                raise TypeError("a parameter declaration must be an object")
            if d.get("required", _UNDEF) is not False:
                return {"ok": False, "code": "missing_param", "path": path,
                        "reason": "required parameter '%s' is missing" % path}
            continue
        bad = param_value_violation(d, params[name])
        if bad:
            return {"ok": False, "code": bad["code"], "path": path, "reason": "'%s': %s" % (path, bad["reason"])}
    return {"ok": True, "verb": v}


def accumulation_params(v: dict, unit: Any) -> List[str]:
    """The integer parameters of a verb entry whose `accumulates_into` lists `unit`, in UTF-8 byte order."""
    vp = _prop(v, "params")
    out = []
    for p in _obj_keys(vp):
        decl = _own_get(vp, p)
        if not isinstance(decl, dict):
            raise TypeError("a parameter declaration must be an object")
        if _js_strict_eq(decl.get("type", _UNDEF), "integer"):
            ai = decl.get("accumulates_into", _UNDEF)
            if _includes([] if ai is _UNDEF else ai, unit):
                out.append(p)
    return sorted(out, key=_UTF8_ORDER)


def canon_projection(doc: dict, verb: Any, params: dict) -> Dict[str, str]:
    """`env.canon` for a conforming action: every PRESENT boolean ("true" / "false"), set (strict canonical JSON of its
    members sorted by UTF-8 bytes) and array (strict canonical JSON as sent) parameter."""
    v = schema_verb(doc, verb)
    out: Dict[str, str] = {}
    if v is None:
        return out
    for path in sorted(_js_keys(v["params"]), key=_UTF8_ORDER):
        d = v["params"][path]
        name = path[len(_PARAMS_PREFIX):]
        if name not in params:
            continue
        x = params[name]
        if d["type"] == "boolean":
            out[name] = "true" if x is True else "false"
        elif d["type"] == "set":
            out[name] = canonicalize_strict(sorted(x, key=_UTF8_ORDER))
        elif d["type"] == "array":
            out[name] = canonicalize_strict(x)
    return out


# ---- intent-acc.ts: accumulators, monitors, receipts (rule 15) ------------------------------------------------------

ACC_AGGS = ("sum", "count", "distinct", "max")
MONITOR_KINDS = ("requires_prior", "precedes", "never", "always", "responds_within")
MAX_SESSION_ACCUMULATORS = 16
MAX_SESSION_MONITORS = 16
MAX_MONITOR_WITHIN = 64
_ACC_PARAM_PATH_RE = PARAM_PATH_RE
_UNIT_RE = UNIT_ID_RE


def monitor_states(m: dict) -> List[str]:
    """The closed state set Q of a monitor."""
    k = m.get("kind")
    if k in ("requires_prior", "precedes"):
        return ["unmet", "met"]
    if k == "never":
        return ["clean", "seen"]
    if k == "always":
        return ["ok", "broken"]
    if k == "responds_within":
        w = m.get("within", _UNDEF)
        w = int(w) if _is_safe_int(w) else 0
        return ["idle"] + ["pending:%d" % (i + 1) for i in range(w)] + ["missed"]
    return []


def _predicate_shape_ok(p: Any) -> bool:
    if not isinstance(p, dict):
        return False
    vb = p.get("verb", _UNDEF)
    return isinstance(vb, str) or (isinstance(vb, list) and len(vb) > 0 and all(isinstance(x, str) for x in vb))


def accumulator_decl_error(a: Any) -> Optional[str]:
    """Shape of an accumulator declaration in a session root (mirrors accumulatorDeclError). None = well-formed."""
    if not isinstance(a, dict):
        return "accumulator must be an object"
    for k in _js_keys(a):
        if k not in ("id", "agg", "val", "unit", "sel", "win", "key", "domain_max", "cap", "holder"):
            return "accumulator: unknown member '%s'" % k
    aid = a.get("id")
    if not isinstance(aid, str) or ACC_ID_RE.fullmatch(aid) is None or aid in RESERVED_NAMES:
        return "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
    at = "accumulator '%s'" % aid
    agg = a.get("agg", _UNDEF)
    if not _in_strs(agg, ACC_AGGS):
        return "%s: unknown agg" % at
    if "val" in a and (not isinstance(a["val"], str) or _ACC_PARAM_PATH_RE.fullmatch(a["val"]) is None):
        return "%s: val must be action.params.<name>" % at
    if "unit" in a and (not isinstance(a["unit"], str) or _u16len(a["unit"]) > 64 or _UNIT_RE.fullmatch(a["unit"]) is None):
        return "%s: unit must be a unit id" % at
    sel = a.get("sel")
    if not isinstance(sel, dict):
        return "%s: sel must be an object" % at
    for k in _js_keys(sel):
        if k not in ("verbs", "accumulates_into", "event"):
            return "%s: sel has unknown member '%s'" % (at, k)
    if "verbs" in sel:
        vs = sel["verbs"]
        if not isinstance(vs, list) or len(vs) == 0 or len(vs) > 64 or not all(isinstance(x, str) and len(x) > 0 for x in vs):
            return "%s: sel.verbs must be 1..64 verb names" % at
    if "accumulates_into" in sel and (not isinstance(sel["accumulates_into"], str) or _UNIT_RE.fullmatch(sel["accumulates_into"]) is None):
        return "%s: sel.accumulates_into must be a unit id" % at
    if "event" in sel and not _in_strs(sel["event"], ("intent_required", "question", "clarification")):
        return "%s: unknown sel.event" % at
    action_sel = "verbs" in sel or "accumulates_into" in sel
    if action_sel == ("event" in sel):
        return "%s: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind" % at
    w = a.get("win")
    if not isinstance(w, dict):
        return "%s: win must be an object" % at
    wk = w.get("kind", _UNDEF)
    if _js_strict_eq(wk, "task"):
        if len(w) != 1:
            return "%s: win {kind: task} has no other member" % at
    elif _js_strict_eq(wk, "sliding"):
        if _sorted_join(w) != "kind,ms" or not (_is_safe_int(w.get("ms")) and w["ms"] > 0):
            return "%s: win sliding needs a positive ms" % at
    elif _js_strict_eq(wk, "period"):
        if _sorted_join(w) != "kind,ms,t0" or not (_is_safe_int(w.get("ms")) and w["ms"] > 0) or not _js_nonneg_int(w.get("t0")):
            return "%s: win period needs a positive ms and t0 >= 0" % at
    else:
        return "%s: unknown win kind" % at
    key = a.get("key", _UNDEF)
    if key is not None and (not isinstance(key, str) or _ACC_PARAM_PATH_RE.fullmatch(key) is None):
        return "%s: key must be null or action.params.<name>" % at
    if "domain_max" in a and not _js_nonneg_int(a["domain_max"]):
        return "%s: domain_max must be a non-negative safe integer" % at
    if "cap" in a and not _js_nonneg_int(a["cap"]):
        return "%s: cap must be a non-negative safe integer" % at
    h = a.get("holder")
    if not isinstance(h, dict):
        return "%s: holder must be an object" % at
    hk = h.get("kind", _UNDEF)
    if _js_strict_eq(hk, "site_local") or _js_strict_eq(hk, "wallet"):
        if len(h) != 1:
            return "%s: holder %s has no other member" % (at, hk)
    elif _js_strict_eq(hk, "sequenced"):
        for k in _js_keys(h):
            if k not in ("kind", "uri", "root", "root_alg", "root_pq_pk", "keys_uri"):
                return "%s: holder sequenced has unknown member '%s'" % (at, k)
        if not isinstance(h.get("uri"), str) or len(h["uri"]) == 0:
            return "%s: holder sequenced needs a uri" % at
        if decode_b64u_strict(h.get("root"), 32) is None:
            return "%s: holder.root is not canonical base64url (32 bytes)" % at
        if _suite_known_error(h.get("root_alg", _UNDEF)):
            return _ctx("%s: holder.root_alg: " % at, _suite_known_error(h["root_alg"]))
        if "root_pq_pk" in h and decode_b64u_strict(h["root_pq_pk"]) is None:
            return "%s: holder.root_pq_pk is not canonical base64url" % at
        if "keys_uri" in h and (not isinstance(h["keys_uri"], str) or len(h["keys_uri"]) == 0):
            return "%s: holder.keys_uri must be a non-empty string" % at
    else:
        return "%s: unknown holder kind" % at
    wallet = _js_strict_eq(hk, "wallet")
    if wallet != ("event" in sel):
        return "%s: wallet events are wallet-held and only wallet events are" % at
    if not wallet:
        if agg != "count" and "val" not in a and "accumulates_into" not in sel:
            return "%s: %s needs val (or sel.accumulates_into for a sum)" % (at, agg)
        if agg != "sum" and agg != "count" and "val" not in a:
            return "%s: %s needs val" % (at, agg)
        if agg == "count" and "val" in a:
            return "%s: count takes no val" % at
    return None


def monitor_decl_error(m: Any) -> Optional[str]:
    """Shape of a monitor declaration in a session root (mirrors monitorDeclError). None = well-formed."""
    if not isinstance(m, dict):
        return "monitor must be an object"
    for k in _js_keys(m):
        if k not in ("id", "kind", "p", "q", "status", "within"):
            return "monitor: unknown member '%s'" % k
    mid = m.get("id")
    if not isinstance(mid, str) or ACC_ID_RE.fullmatch(mid) is None or mid in RESERVED_NAMES:
        return "monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
    at = "monitor '%s'" % mid
    kind = m.get("kind", _UNDEF)
    if not _in_strs(kind, MONITOR_KINDS):
        return "%s: unknown kind" % at
    if not _predicate_shape_ok(m.get("p", _UNDEF)):
        return "%s: p must be a predicate" % at
    needs_q = kind in ("requires_prior", "precedes", "responds_within")
    if needs_q != ("q" in m):
        return "%s: q is required exactly for requires_prior / precedes / responds_within" % at
    if "q" in m and not _predicate_shape_ok(m["q"]):
        return "%s: q must be a predicate" % at
    if "status" in m and not _in_strs(m["status"], ("admitted", "committed")):
        return "%s: status must be admitted or committed" % at
    if (kind == "responds_within") != ("within" in m):
        return "%s: within is required exactly for responds_within" % at
    if "within" in m and not (_is_safe_int(m["within"]) and 1 <= m["within"] <= MAX_MONITOR_WITHIN):
        return "%s: within must be an integer in 1..%d" % (at, MAX_MONITOR_WITHIN)
    return None


def acc_selects(a: dict, verb: Any, schema: Any = None) -> bool:
    """omega in sel_psi (action selectors only): the verb is listed, or the schema's verb entry has an integer parameter
    feeding `sel.accumulates_into`."""
    sel = a["sel"]
    if "event" in sel:
        return False
    if "verbs" in sel and _includes(sel["verbs"], verb):
        return True
    if "accumulates_into" in sel and schema is not None:
        v = schema_verb(schema, verb)
        return v is not None and len(accumulation_params(v, sel["accumulates_into"])) > 0
    return False


def distinct_key(x: Any) -> Optional[str]:
    """The canonical key of a `distinct` value: the strict canonical JSON text of a string or a safe integer."""
    if isinstance(x, str) or _is_safe_int(x):
        try:
            return canonicalize_strict(x)
        except Exception:  # noqa: BLE001
            return None
    return None


def acc_value_of(a: dict, verb: Any, params: dict, schema: Any = None) -> dict:
    """val(omega) for a selected action: {"ok": True, "val", "key"?} or {"ok": False, "reason"} (mirrors accValueOf)."""
    def read(path: str) -> Any:
        return _own_get(params, path[len(_PARAMS_PREFIX):])

    agg = a["agg"]
    if agg == "count":
        return {"ok": True, "val": 1}
    if agg == "distinct":
        k = distinct_key(read(a["val"]))
        if k is None:
            return _bad("%s must be a string or a safe integer" % a["val"])
        return {"ok": True, "val": 1, "key": k}
    if "val" in a:
        x = read(a["val"])
        return {"ok": True, "val": x} if _js_nonneg_int(x) else _bad("%s must be a non-negative safe integer" % a["val"])
    v = schema_verb(schema, verb) if schema is not None else None
    if v is None:
        return _bad("no schema entry for '%s' to read accumulates_into" % _js_str(verb))
    s = 0
    for p in accumulation_params(v, a["sel"]["accumulates_into"]):
        x = read(p)
        if x is _UNDEF:
            continue
        if not _js_nonneg_int(x):
            return _bad("%s must be a non-negative safe integer" % p)
        s = s + x
        if not _is_safe_int(s):
            return _bad("accumulated value exceeds 2^53-1")
    return {"ok": True, "val": s}


def _pre_want(agg: str) -> str:
    return "sum" if agg == "sum" else "count" if agg == "count" else "max" if agg == "max" else "values"


def pre_state_error(a: dict, s: Any) -> Optional[str]:
    """The host-injected pre-state of an accumulator group must be exactly {sum} / {count} / {max} (safe integers >= 0)
    or {values} (distinct strings). None = well-formed."""
    if not isinstance(s, dict):
        return "pre-state must be an object"
    want = _pre_want(a["agg"])
    if ",".join(_js_keys(s)) != want:
        return "pre-state of a %s accumulator is {%s}" % (a["agg"], want)
    if want == "values":
        vs = s["values"]
        if not isinstance(vs, list) or not all(isinstance(x, str) for x in vs):
            return "pre-state values must be strings"
        if len(set(vs)) != len(vs):
            return "pre-state values must be distinct"
        return None
    return None if _js_nonneg_int(s[want]) else "pre-state %s must be a non-negative safe integer" % want


def combine_acc(a: dict, pre: dict, v: dict) -> Optional[Any]:
    """The post-action value from the pre-state (None when it leaves the safe-integer range)."""
    agg = a["agg"]
    if agg == "sum":
        post = pre["sum"] + v["val"]
    elif agg == "count":
        post = pre["count"] + 1
    elif agg == "max":
        post = max(pre["max"], v["val"])
    else:
        vs = pre["values"]
        post = len(vs) + (0 if v.get("key") in vs else 1)
    return post if _is_safe_int(post) else None


def pre_value(a: dict, pre: dict) -> Any:
    """The value of an accumulator group this action does NOT feed (post = pre)."""
    agg = a["agg"]
    if agg == "distinct":
        return len(pre["values"])
    return pre[_pre_want(agg)]


ACC_RECEIPT_DOMAIN = "atlas-pca/acc-receipt/v1\x00"
ACC_RECEIPT_REF_DOMAIN = "atlas-pca/acc-receipt-ref/v1"
ACC_RESERVE_DOMAIN = "atlas-pca/acc-reserve/v1"
SEQUENCER_KEYS_DOMAIN = "atlas-pca/sequencer-keys/v1\x00"
KID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")  # always used with fullmatch
RECEIPT_SKEW_MS = 60_000  # allowed skew of a receipt's / key set's issued_at ahead of the verifier clock
MAX_RECEIPT_LIFETIME_MS = 900_000  # issued_at <= expires_at <= issued_at + 15 min
DEFAULT_MAX_RECEIPT_AGE_MS = 900_000  # policy acc.max_receipt_age_s default (15 min)
DEFAULT_MAX_KEYSET_AGE_MS = 3_600_000  # policy acc.max_keyset_age_s default (1 h)
_RECEIPT_KEYS = ("v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at",
                 "expires_at", "kid", "ledger", "signer", "alg", "pq_pk", "sig", "pq_sig")


def pcactn_reservation_digest(p: dict) -> str:
    """The digest a reservation binds: the PCActn without `sig`, `pq_sig`, `threshold` and `intent_session`."""
    body = {k: v for k, v in p.items() if k not in ("sig", "pq_sig", "threshold", "intent_session")}
    return hash_canonical({"d": ACC_RESERVE_DOMAIN, "b": body})


def acc_receipt_shape_error(r: Any) -> Optional[str]:
    """Shape of a `pca-acc-receipt` v1 (closed). None = well-formed."""
    if not isinstance(r, dict):
        return "receipt is not an object"
    for k in _js_keys(r):
        if k not in _RECEIPT_KEYS:
            return "receipt: unknown member '%s'" % k
    if not _js_strict_eq(r.get("v", _UNDEF), 1) or not _js_strict_eq(r.get("kind", _UNDEF), "pca-acc-receipt"):
        return "not a pca-acc-receipt v1"
    if decode_b64u_strict(r.get("session"), 32) is None:
        return "receipt.session is not canonical base64url (32 bytes)"
    if not isinstance(r.get("acc"), str) or ACC_ID_RE.fullmatch(r["acc"]) is None:
        return "receipt.acc is not an accumulator id"
    if not (_is_safe_int(r.get("seq")) and r["seq"] >= 1):
        return "receipt.seq must be a safe integer >= 1"
    if not _js_nonneg_int(r.get("pre")) or not _js_nonneg_int(r.get("delta")) or not _js_nonneg_int(r.get("post")):
        return "receipt pre / delta / post must be non-negative safe integers"
    if decode_b64u_strict(r.get("pcactn_digest"), 32) is None:
        return "receipt.pcactn_digest is not canonical base64url (32 bytes)"
    if not isinstance(r.get("aud"), str) or len(r["aud"]) == 0:
        return "receipt.aud must be a non-empty string"
    if not _js_nonneg_int(r.get("issued_at")) or not _js_nonneg_int(r.get("expires_at")):
        return "receipt.issued_at / expires_at must be non-negative safe integers"
    if not (r["expires_at"] >= r["issued_at"] and r["expires_at"] - r["issued_at"] <= MAX_RECEIPT_LIFETIME_MS):
        return "receipt.expires_at must be within %d ms after issued_at" % MAX_RECEIPT_LIFETIME_MS
    if not isinstance(r.get("kid"), str) or KID_RE.fullmatch(r["kid"]) is None:
        return "receipt.kid must match [A-Za-z0-9_.:-]{1,64}"
    led = r.get("ledger")
    if not isinstance(led, dict) or _sorted_join(led) != "head,index" or not _js_nonneg_int(led.get("index")) \
            or decode_b64u_strict(led.get("head"), 32) is None:
        return "receipt.ledger must be {index, head}"
    if decode_b64u_strict(r.get("signer"), 32) is None:
        return "receipt.signer is not canonical base64url (32 bytes)"
    if suite_capability_error(r.get("alg", _UNDEF)):
        return _ctx("receipt.alg: ", suite_capability_error(r["alg"]))
    suite = _resolve_registered(r.get("alg", _UNDEF))
    if suite == "ed25519" and ("pq_pk" in r or "pq_sig" in r):
        return "an ed25519 receipt must not carry pq_pk / pq_sig"
    if not isinstance(r.get("sig"), str):
        return "receipt.sig must be a string"
    return None


def _receipt_body(r: dict) -> dict:
    return {
        "v": r["v"], "kind": r["kind"], "session": r["session"], "acc": r["acc"], "seq": r["seq"], "pre": r["pre"],
        "delta": r["delta"], "post": r["post"], "pcactn_digest": r["pcactn_digest"], "aud": r["aud"],
        "issued_at": r["issued_at"], "expires_at": r["expires_at"], "kid": r["kid"],
        "ledger": {"index": r["ledger"]["index"], "head": r["ledger"]["head"]}, "signer": r["signer"],
    }


def acc_receipt_signature_error(r: Any, expected_signer: Any, pins: Optional[dict] = None) -> Optional[str]:
    """A receipt's suite signature under `expected_signer` (its PQ key only as pinned in `pins`): None when it verifies,
    "invalid", or a reason starting with "unsupported_suite". Total."""
    try:
        rse = acc_receipt_shape_error(r)
        if rse is not None:
            return rse if _unsupported(rse) else "invalid"
        if not _js_strict_eq(r["signer"], expected_signer):
            return "invalid"
        msg = ACC_RECEIPT_DOMAIN.encode("utf-8") + canonical_bytes_strict(
            _bind_suite_fields(_receipt_body(r), r.get("alg", _UNDEF), r.get("pq_pk", _UNDEF)))
        return _pinned_suite_error(r.get("alg", _UNDEF), r["signer"], r.get("pq_pk", _UNDEF), msg, r["sig"],
                                   r.get("pq_sig", _UNDEF), pins)
    except Exception:  # noqa: BLE001
        return "invalid"


def verify_acc_receipt_signature(r: Any, expected_signer: Any, pins: Optional[dict] = None) -> bool:
    """True iff the receipt's suite signature verifies under `expected_signer` (see acc_receipt_signature_error)."""
    return acc_receipt_signature_error(r, expected_signer, pins) is None


def acc_receipt_digest(r: Any) -> str:
    """The receipt's content address (what `intent_session.acc[].receipt` carries). Raises on an out-of-profile value."""
    return hash_canonical({"d": ACC_RECEIPT_REF_DOMAIN, "r": r})


def sequencer_key_set_shape_error(k: Any) -> Optional[str]:
    """Shape of a `pca-sequencer-keys` v1 document (closed). None = well-formed."""
    if not isinstance(k, dict):
        return "key set is not an object"
    for x in _js_keys(k):
        if x not in ("v", "kind", "sequencer", "version", "issued_at", "keys", "alg", "pq_pk", "sig", "pq_sig"):
            return "key set: unknown member '%s'" % x
    if not _js_strict_eq(k.get("v", _UNDEF), 1) or not _js_strict_eq(k.get("kind", _UNDEF), "pca-sequencer-keys"):
        return "not a pca-sequencer-keys v1"
    if decode_b64u_strict(k.get("sequencer"), 32) is None:
        return "sequencer is not canonical base64url (32 bytes)"
    if not (_js_nonneg_int(k.get("version")) and k["version"] >= 1):
        return "version must be a safe integer >= 1"
    if not _js_nonneg_int(k.get("issued_at")):
        return "issued_at must be a non-negative safe integer"
    keys = k.get("keys")
    if not isinstance(keys, list) or len(keys) == 0 or len(keys) > 256:
        return "keys must be 1..256 entries"
    kids = set()
    for e in keys:
        if not isinstance(e, dict) or any(x not in ("kid", "pk", "alg", "pq_pk", "not_before", "not_after") for x in e):
            return "keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}"
        kid = e.get("kid")
        if not isinstance(kid, str) or KID_RE.fullmatch(kid) is None or kid in kids:
            return "key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct"
        kids.add(kid)
        if decode_b64u_strict(e.get("pk"), 32) is None:
            return "key pk is not canonical base64url (32 bytes)"
        if suite_capability_error(e.get("alg", _UNDEF)):
            return _ctx("key alg: ", suite_capability_error(e["alg"]))
        if "pq_pk" in e and decode_b64u_strict(e["pq_pk"]) is None:
            return "key pq_pk is not canonical base64url"
        if not _js_nonneg_int(e.get("not_before")) or (
                "not_after" in e and not (_js_nonneg_int(e["not_after"]) and e["not_after"] >= e["not_before"])):
            return "key validity must be 0 <= not_before <= not_after"
    if suite_capability_error(k.get("alg", _UNDEF)):
        return _ctx("alg: ", suite_capability_error(k["alg"]))
    suite = _resolve_registered(k.get("alg", _UNDEF))
    if suite == "ed25519" and ("pq_pk" in k or "pq_sig" in k):
        return "an ed25519 key set must not carry pq_pk / pq_sig"
    if not isinstance(k.get("sig"), str):
        return "sig must be a string"
    return None


def sequencer_key_set_error(k: Any, root: Any, root_pq_pk: Any = None) -> Optional[str]:
    """Verify a key set under the session's pinned sequencer root (a PQ suite only under `root_pq_pk`): None when it
    verifies, "invalid", or a reason starting with "unsupported_suite". Total."""
    try:
        kse = sequencer_key_set_shape_error(k)
        if kse is not None:
            return kse if _unsupported(kse) else "invalid"
        if not _js_strict_eq(k["sequencer"], root):
            return "invalid"
        pins = {root: root_pq_pk} if root_pq_pk is not None else None
        body = {"v": k["v"], "kind": k["kind"], "sequencer": k["sequencer"], "version": k["version"],
                "issued_at": k["issued_at"], "keys": k["keys"]}
        msg = SEQUENCER_KEYS_DOMAIN.encode("utf-8") + canonical_bytes_strict(
            _bind_suite_fields(body, k.get("alg", _UNDEF), k.get("pq_pk", _UNDEF)))
        return _pinned_suite_error(k.get("alg", _UNDEF), root, k.get("pq_pk", _UNDEF), msg, k["sig"],
                                   k.get("pq_sig", _UNDEF), pins)
    except Exception:  # noqa: BLE001
        return "invalid"


def verify_sequencer_key_set(k: Any, root: Any, root_pq_pk: Any = None) -> bool:
    """True iff the key set verifies under the pinned root (see sequencer_key_set_error)."""
    return sequencer_key_set_error(k, root, root_pq_pk) is None


SEQUENCER_KEYS_REF_DOMAIN = "atlas-pca/sequencer-keys-ref/v1"


def sequencer_key_set_digest(ks: Any) -> str:
    """A key set's content address: b64u(sha256(strictCanonical({"d": "atlas-pca/sequencer-keys-ref/v1", "k": set})))
    (signature fields included). Raises on an out-of-profile value."""
    return hash_canonical({"d": SEQUENCER_KEYS_REF_DOMAIN, "k": ks})


def tracked_key_set_error(t: Any) -> Optional[str]:
    """`acc.keyset_versions[root]` is exactly {version, digest}: version a safe integer >= 1, digest canonical base64url of
    32 bytes (trackedKeySetError). None = well-formed."""
    if not isinstance(t, dict):
        return "a tracked key set must be an object {version, digest}"
    for k in _js_keys(t):
        if k not in ("version", "digest"):
            return "a tracked key set has the unknown member '%s'" % k
    if not (_is_safe_int(t.get("version")) and t["version"] >= 1):
        return "a tracked key set version must be a safe integer >= 1"
    if not isinstance(t.get("digest"), str) or decode_b64u_strict(t["digest"], 32) is None:
        return "a tracked key set digest must be canonical base64url (32 bytes)"
    return None


def receipt_against_holder_error(r: Any, holder: dict, key_sets: Any, now: Any, max_receipt_age_ms: Any = None,
                                 max_keyset_age_ms: Any = None, min_keyset_version: Any = None,
                                 tracked: Any = None) -> Optional[str]:
    """Rule 15 step 3, sequenced (verifyReceiptAgainstHolder). Holds iff ALL of:
      - `now` is a safe integer and every bound is a non-negative safe integer (absent bounds: 15 min / 1 h);
      - the receipt is well-formed (`issued_at <= expires_at <= issued_at + 15 min`), `issued_at <= now + 60 s` and
        `now - issued_at <= max_receipt_age_ms`;
      - SOME presented key set (a JSON array) verifies under `holder.root` (PQ: `holder.root_pq_pk`), has
        `version >= min_keyset_version` (a bare floor, when given) and, when the verifier tracks `tracked` =
        {version, digest} for the root, `version >= tracked.version` (no rollback) and, at `version == tracked.version`,
        `sequencer_key_set_digest(set) == tracked.digest` (else an EQUIVOCATION), `issued_at <= now + 60 s` and `now - issued_at <=
        max_keyset_age_ms`, and lists `receipt.kid` with `pk == signer`, `not_before <= receipt.issued_at` and, when
        `not_after` is set, `receipt.issued_at <= not_after` AND `not_after >= now - 60 s` (a retired key stops verifying);
        the entry's suite equals the receipt's;
      - the receipt's signature verifies under that entry (its PQ key pinned by the entry).
    None when it holds; otherwise the first "unsupported_suite" reason met, else "invalid". Total."""
    try:
        max_age = DEFAULT_MAX_RECEIPT_AGE_MS if max_receipt_age_ms is None else max_receipt_age_ms
        max_set_age = DEFAULT_MAX_KEYSET_AGE_MS if max_keyset_age_ms is None else max_keyset_age_ms
        if not _is_safe_int(now) or not _js_nonneg_int(max_age) or not _js_nonneg_int(max_set_age) or (
                tracked is not None and tracked_key_set_error(tracked) is not None) or (
                min_keyset_version is not None and not _js_nonneg_int(min_keyset_version)):
            return "invalid"
        if not isinstance(key_sets, list):
            return "invalid"
        rse = acc_receipt_shape_error(r)
        if rse is not None:
            return rse if _unsupported(rse) else "invalid"
        if not r["issued_at"] <= now + RECEIPT_SKEW_MS or not now - r["issued_at"] <= max_age:
            return "invalid"
        root_pq = holder["root_pq_pk"] if "root_pq_pk" in holder else None
        unsupported = None
        for k in key_sets:
            ke = sequencer_key_set_error(k, holder["root"], root_pq)
            if ke is not None:
                if unsupported is None and _unsupported(ke):
                    unsupported = ke
                continue
            if min_keyset_version is not None and k["version"] < min_keyset_version:
                continue
            if tracked is not None and (k["version"] < tracked["version"] or (
                    k["version"] == tracked["version"] and sequencer_key_set_digest(k) != tracked["digest"])):
                continue
            if not k["issued_at"] <= now + RECEIPT_SKEW_MS or not now - k["issued_at"] <= max_set_age:
                continue
            e = None
            for x in k["keys"]:
                if x["kid"] == r["kid"]:
                    e = x
                    break
            if e is None or e["pk"] != r["signer"] or r["issued_at"] < e["not_before"]:
                continue
            if "not_after" in e and (r["issued_at"] > e["not_after"] or e["not_after"] < now - RECEIPT_SKEW_MS):
                continue
            if _resolve_registered(e.get("alg", _UNDEF)) != _resolve_registered(r.get("alg", _UNDEF)):
                continue
            pins = {e["pk"]: e["pq_pk"]} if "pq_pk" in e else None
            re_ = acc_receipt_signature_error(r, e["pk"], pins)
            if re_ is None:
                return None
            if unsupported is None and _unsupported(re_):
                unsupported = re_
        return unsupported or "invalid"
    except Exception:  # noqa: BLE001
        return "invalid"


def verify_receipt_against_holder(r: Any, holder: dict, key_sets: Any, now: Any, max_receipt_age_ms: Any = None,
                                  max_keyset_age_ms: Any = None, min_keyset_version: Any = None,
                                  tracked: Any = None) -> bool:
    """True iff rule 15 step 3 (sequenced) holds (see receipt_against_holder_error)."""
    return receipt_against_holder_error(r, holder, key_sets, now, max_receipt_age_ms, max_keyset_age_ms,
                                        min_keyset_version, tracked) is None


def receipt_arithmetic_ok(a: dict, r: dict, val: Any) -> bool:
    """Rule 15 step 5d: the arithmetic a receipt must satisfy for its accumulator."""
    agg = a["agg"]
    pre, delta, post = r["pre"], r["delta"], r["post"]
    if agg == "sum":
        return delta == val and post == pre + delta
    if agg == "count":
        return delta == 1 and post == pre + 1
    if agg == "max":
        return delta == val and post == max(pre, delta)
    return (delta == 0 or delta == 1) and post == pre + delta


# ---- revocation.ts: the signed revocation epoch and the sorted-Merkle non-membership proof --------------------------

REVEPOCH_DOMAIN = "atlas-pca/revepoch/v1\x00"
_REVSET_PREFIX = b"pca-revset/v1\x00"
_EMPTY_TREE = b64u(sha256(b""))
_EPOCH_FIELDS = ("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after")


def _bind_root(size: Any, tree_root: str) -> str:
    return b64u(sha256(_REVSET_PREFIX + canonical_bytes_strict({"size": size, "tree": tree_root})))


def _epoch_message(ep: dict) -> bytes:
    body = {}
    for k in _EPOCH_FIELDS:
        if k not in ep:
            raise TypeError("canonicalize: unsupported type undefined")
        body[k] = ep[k]
    return REVEPOCH_DOMAIN.encode("utf-8") + canonical_bytes_strict(
        _bind_suite_fields(body, ep.get("alg", _UNDEF), ep.get("pq_pk", _UNDEF)))


def check_revocation_age(issued_at: Any, now: Any, max_age_ms: Any, what: str = "revocation state") -> dict:
    """revocation.ts `checkRevocationAge`: revocation state issued at `issued_at` (epoch ms) is acceptable at `now` when it
    is at most `max_age_ms` old. An unknown issue time is unverifiable and denies; a time more than 60 s in the future
    denies (the signed epoch's skew). Returns {"ok": True} or {"ok": False, "reason"}. Total."""
    try:
        if not _is_num(issued_at) or not math.isfinite(issued_at):
            return _bad("%s age is unknown (unverifiable revocation state)" % what)
        if not issued_at <= now + 60_000:
            return _bad("%s issued in the future" % what)
        if not now - issued_at <= max_age_ms:
            return _bad("%s is %s ms old, over the verifier's maximum of %s ms (stale revocation state)"
                        % (what, _js_str(now - issued_at), _js_str(max_age_ms)))
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return _bad("%s age is unknown (unverifiable revocation state)" % what)


def check_revocation_epoch(ep: Any, guardian_public: Any, now: Any, grant_ref: Any = _UNDEF,
                           last_accepted_epoch: Any = _UNDEF, pcactn_epoch: Any = _UNDEF,
                           pq_pins: Optional[dict] = None, max_age_ms: Any = _UNDEF) -> dict:
    """Verify a signed revocation epoch (revocation.ts checkRevocationEpoch; the `pq_artifact` "revocation" format: the
    guardian signs `"atlas-pca/revepoch/v1\\0" || strictCanonical({instance_id, grant_ref, epoch, set_size, root,
    issued_at, not_after} + bound suite fields)`): signer and suite, `epoch` / `set_size`, the signature through the suite
    dispatch (a PQ epoch only under `pq_pins[guardian]`), grant binding, `now <= not_after`, `issued_at <= now + 60 s`,
    rollback and PCActn freshness when given; `epoch`, `set_size` (>= 0) and the instants `issued_at`, `not_after` must be
    safe integers (else malformed). Returns {"ok": True} or {"ok": False, "reason"}. Total."""
    try:
        if not isinstance(ep, dict) or not _js_strict_eq(ep.get("guardian", _UNDEF), guardian_public) \
                or _resolve_registered(ep.get("alg", _UNDEF)) is None:
            return _bad("revocation epoch not signed by the pinned guardian")
        e, n = ep.get("epoch", _UNDEF), ep.get("set_size", _UNDEF)
        if not _js_nonneg_int(e) or not _js_nonneg_int(n) or not _is_safe_int(ep.get("issued_at", _UNDEF)) \
                or not _is_safe_int(ep.get("not_after", _UNDEF)):
            return _bad("malformed revocation epoch")
        err = _pinned_suite_error(ep.get("alg", _UNDEF), guardian_public, ep.get("pq_pk", _UNDEF), _epoch_message(ep),
                                  ep.get("sig", _UNDEF), ep.get("pq_sig", _UNDEF), pq_pins)
        if err is not None:
            return _bad(err if _unsupported(err) else "revocation epoch signature invalid")
        if grant_ref is not _UNDEF and not _js_strict_eq(ep["grant_ref"], grant_ref):
            return _bad("revocation epoch is for a different grant")
        if not now <= ep["not_after"]:
            return _bad("revocation epoch expired (stale revocation root)")
        if not ep["issued_at"] <= now + 60_000:
            return _bad("revocation epoch issued in the future")
        if max_age_ms is not _UNDEF:  # verifier-side cap on now - issued_at (T9)
            age = check_revocation_age(ep["issued_at"], now, max_age_ms, "revocation epoch")
            if not age["ok"]:
                return age
        if last_accepted_epoch is not _UNDEF and e < last_accepted_epoch:
            return _bad("revocation epoch %s is older than the last accepted %s (rollback)" % (_js_str(e), _js_str(last_accepted_epoch)))
        if pcactn_epoch is not _UNDEF and not pcactn_epoch >= e:
            return _bad("PCActn freshness.epoch %s predates the revocation epoch %s" % (_js_str(pcactn_epoch), _js_str(e)))
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return _bad("revocation epoch check error")


def _leaf_ok(root: Any, size: int, leaf_id: Any, proof: Any) -> bool:
    try:
        if not isinstance(proof, dict) or not isinstance(leaf_id, str):
            return False
        idx = proof.get("index", _UNDEF)
        if not _js_strict_eq(proof.get("size", _UNDEF), size) or not _js_nonneg_int(idx) or idx >= size:
            return False
        sides = _path_shape(int(idx), int(size))
        path = proof.get("path")
        if not isinstance(path, list) or len(path) != len(sides):
            return False
        h = _leaf_hash(leaf_id)
        for i, step in enumerate(path):
            if not isinstance(step, dict) or not _js_strict_eq(step.get("side", _UNDEF), sides[i]):
                return False
            sib = decode_b64u_strict(step.get("hash"), 32)  # STRICT: canonical 32-byte siblings only
            if sib is None:
                return False
            h = _node_hash(sib, h) if sides[i] == "L" else _node_hash(h, sib)
        return _js_strict_eq(_bind_root(size, b64u(h)), root)
    except Exception:  # noqa: BLE001
        return False


def verify_non_membership(root: Any, proof: Any, rid: Any) -> bool:
    """`rid` is NOT in the sorted Merkle revocation set `root` commits to (adjacent bracketing leaves, or below the first /
    above the last leaf, or the empty set). STRICT: `proof` is an object whose `size` is a safe integer >= 0; `lo` / `hi`,
    when present, are objects {id: string, proof}; ids are strings. Total."""
    try:
        if not isinstance(proof, dict) or not isinstance(rid, str):
            return False
        size = proof.get("size", _UNDEF)
        if not _js_nonneg_int(size):
            return False
        lo, hi = proof.get("lo", _UNDEF), proof.get("hi", _UNDEF)
        if (lo is not _UNDEF and not isinstance(lo, dict)) or (hi is not _UNDEF and not isinstance(hi, dict)):
            return False
        has_lo, has_hi = lo is not _UNDEF, hi is not _UNDEF
        if size == 0:
            return not has_lo and not has_hi and _js_strict_eq(root, _bind_root(0, _EMPTY_TREE))
        if not has_lo and not has_hi:
            return False
        if has_lo:
            lid = lo.get("id", _UNDEF)
            if not isinstance(lid, str) or not compare_utf8(lid, rid) < 0 or not _leaf_ok(root, size, lid, lo.get("proof", _UNDEF)):
                return False
            if not has_hi and lo["proof"]["index"] != size - 1:
                return False
        if has_hi:
            hid = hi.get("id", _UNDEF)
            if not isinstance(hid, str) or not compare_utf8(rid, hid) < 0 or not _leaf_ok(root, size, hid, hi.get("proof", _UNDEF)):
                return False
            if not has_lo and hi["proof"]["index"] != 0:
                return False
        if has_lo and has_hi and hi["proof"]["index"] != lo["proof"]["index"] + 1:
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


# ---- intent-revocation.ts (rule 13 step 7) ----------------------------------------------------------------------------

INTENT_REVOCATION_PREFIX = "pca-intent:"


def session_revocation_id(session: Any) -> str:
    return "pca-intent:session:" + _js_str(session)


def map_revocation_id(map_digest: Any) -> str:
    return "pca-intent:map:" + _js_str(map_digest)


def delta_revocation_id(grant_id: Any) -> str:
    return "pca-intent:delta:" + _js_str(grant_id)


def profile_revocation_id(profile_id: Any, version: Any) -> str:
    return "pca-intent:profile:%s@%s" % (_js_str(profile_id), _js_str(version))


def session_revocation_scope(session: Any) -> str:
    return "pca-intent-session:" + _js_str(session)


def profile_revocation_scope(profile_id: Any) -> str:
    return "pca-intent-profile:" + _js_str(profile_id)


def revocation_epoch_shape_error(ep: Any) -> Optional[str]:
    """Strict shape of a revocation epoch as rule 13 consumes it (revocationEpochShapeError): every number a
    non-negative safe integer, every string a string, `alg` a suite this verifier implements. None = well-formed."""
    if not isinstance(ep, dict):
        return "the revocation epoch must be an object"
    for k in ("instance_id", "grant_ref", "root", "guardian", "sig"):
        if not isinstance(ep.get(k), str):
            return "revocation epoch %s must be a string" % k
    for k in ("epoch", "set_size", "issued_at", "not_after"):
        if not _js_nonneg_int(ep.get(k)):
            return "revocation epoch %s must be a non-negative safe integer" % k
    if "guardian_epoch" in ep and not _js_nonneg_int(ep["guardian_epoch"]):
        return "revocation epoch guardian_epoch must be a non-negative safe integer"
    se = suite_capability_error(ep.get("alg", _UNDEF))
    if se:
        return _ctx("revocation epoch alg: ", se)
    if "pq_pk" in ep and not isinstance(ep["pq_pk"], str):
        return "revocation epoch pq_pk must be a string"
    if "pq_sig" in ep and not isinstance(ep["pq_sig"], str):
        return "revocation epoch pq_sig must be a string"
    return None


def revset_root(ids: List[str]) -> str:
    """The sorted-set root of a revoked list in order (RevocationSet.root): base64url(SHA-256("pca-revset/v1\\0" ||
    canonical({size, tree}))), `tree` the RFC 6962 Merkle root (leaf SHA-256(0x00 || canonical(id))) or
    base64url(SHA-256("")) for the empty list."""
    return _bind_root(len(ids), merkle_root(ids) if ids else _EMPTY_TREE)


def _revoked_list_error(epoch: dict, revoked: Any) -> Optional[str]:
    """The revoked list is well-formed and is exactly what the epoch signs (revokedListError)."""
    if not isinstance(revoked, list) or not all(isinstance(x, str) for x in revoked):
        return "revoked must be an array of ids"
    for i in range(1, len(revoked)):
        if not compare_utf8(revoked[i - 1], revoked[i]) < 0:
            return "revoked must be sorted by UTF-8 bytes and distinct"
    if len(revoked) != epoch["set_size"] or epoch["epoch"] != epoch["set_size"]:
        return "the epoch must be numbered by its set size and list exactly set_size ids"
    if revset_root(revoked) != epoch["root"]:
        return "the revoked list is not the signed set (root mismatch)"
    return None


def _closed_evidence_error(ev: dict) -> Optional[str]:
    """The evidence is CLOSED (closedEvidenceError): the first own member, in key order, that is neither `epoch` nor
    `revoked` is malformed. A MISSING member is not judged here (the epoch shape / revoked-list steps refuse it)."""
    for k in _js_keys(ev):
        if k not in ("epoch", "revoked"):
            return "has the unknown member '%s' (it is exactly {epoch, revoked})" % k
    return None


def check_session_revocation(ev: Any, *, session: Any, authority: Any, ids: Any, now: Any, max_age_ms: Any,
                             scope: Any = None, pq_pins: Optional[dict] = None, last: Any = _UNDEF) -> dict:
    """The session revocation step (rule 13 step 7; mirrors checkSessionRevocation). First failure wins:
      a. `max_age_ms` a safe integer >= 0, `now` a safe integer, `ids` an array, `authority` a string;
      b. the evidence is an object with no member but `epoch` and `revoked` (closed; so is `last`), its `epoch` strictly typed (revocation_epoch_shape_error) and signed by `authority`
         (the DEDICATED revocation authority, never a principal);
      c. the epoch verifies (check_revocation_epoch; `grant_ref` == `scope`, default "pca-intent-session:"+session; a PQ
         epoch only under `pq_pins[authority]`; now <= not_after; issued_at <= now + 60 s);
      d. now - issued_at <= max_age_ms (T22);
      e. `revoked` is the signed set: an array of strings strictly ascending in UTF-8 byte order, length == set_size ==
         epoch, and revset_root(revoked) == root;
      f. APPEND-ONLY when `last` (the tracked last accepted evidence, itself well-formed per b's shape and e) is given:
         epoch >= last.epoch; every id of last.revoked is in revoked; epoch == last.epoch implies root == last.root;
      g. no id of `ids` is in `revoked`.
    `ev` = {"epoch", "revoked"}. Returns {"ok": True} or {"ok": False, "reason"}. Total."""
    try:
        if not _js_nonneg_int(max_age_ms):
            return _bad("revocation max age misconfigured (fail closed)")
        if not _is_safe_int(now):
            return _bad("the verifier clock is not a safe integer (fail closed)")
        if not isinstance(ids, list) or not isinstance(authority, str):
            return _bad("ids must be an array and the authority a key")
        if not isinstance(ev, dict):
            return _bad("no session revocation epoch supplied")
        ce = _closed_evidence_error(ev)
        if ce:
            return _bad("the revocation evidence " + ce)
        ep = ev.get("epoch", _UNDEF)
        shape = revocation_epoch_shape_error(ep)
        if shape:
            return _bad(shape)
        if ep["guardian"] != authority:
            return _bad("the revocation epoch is not signed by the session revocation authority")
        r = check_revocation_epoch(ep, ep["guardian"], now, session_revocation_scope(session) if scope is None else scope,
                                   pq_pins=pq_pins)
        if not r["ok"]:
            return _bad(r.get("reason") or "revocation epoch rejected")
        if not now - ep["issued_at"] <= max_age_ms:
            return _bad("the session revocation epoch is older than %s ms" % _js_str(max_age_ms))
        le = _revoked_list_error(ep, ev.get("revoked", _UNDEF))
        if le:
            return _bad(le)
        revoked = ev["revoked"]
        if last is not _UNDEF:
            if not isinstance(last, dict) or _closed_evidence_error(last) is not None \
                    or revocation_epoch_shape_error(last.get("epoch", _UNDEF)) is not None \
                    or _revoked_list_error(last["epoch"], last.get("revoked", _UNDEF)) is not None:
                return _bad("the tracked last epoch is malformed (fail closed)")
            le_ep = last["epoch"]
            if ep["epoch"] < le_ep["epoch"]:
                return _bad("revocation epoch rollback (older than the last accepted)")
            have = set(revoked)
            for rid in last["revoked"]:
                if rid not in have:
                    return _bad("the epoch drops '%s', revoked in the last accepted epoch (not append-only)" % rid)
            if ep["epoch"] == le_ep["epoch"] and ep["root"] != le_ep["root"]:
                return _bad("two different revocation sets under one epoch number (equivocation)")
        rset = set(revoked)
        for rid in ids:
            if not isinstance(rid, str) or rid in rset:
                return _bad("'%s' is revoked" % _js_str(rid))
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return _bad("session revocation check error (fail closed): %s" % e)


# ---- intent-session.ts: the session root S (rule 13) ----------------------------------------------------------------

INTENT_SESSION_KIND = "pca-intent-session"
INTENT_SESSION_SIG_DOMAIN = "atlas-pca/intent-session/v1\x00"
INTENT_SESSION_REF_DOMAIN = "atlas-pca/intent-session-ref/v1"
MAX_SESSION_PRINCIPALS = 16
_ROOT_KEYS = ("v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
              "question_uri", "revocation", "flows", "expires_at", "signer", "alg", "pq_pk", "sig", "pq_sig")


def session_root_shape_error(s: Any, signed: bool = True) -> Optional[str]:
    """Shape of a session root `pca-intent-session` v1 (closed; mirrors sessionRootShapeError). None = well-formed."""
    try:
        if not isinstance(s, dict):
            return "session root is not an object"
        for k in _js_keys(s):
            if k not in _ROOT_KEYS:
                return "session root: unknown member '%s'" % k
        if not _js_strict_eq(s.get("v", _UNDEF), 1) or not _js_strict_eq(s.get("kind", _UNDEF), INTENT_SESSION_KIND):
            return "not a pca-intent-session v1"
        if not _b32(s.get("session")) or not _b32(s.get("intent_ref")):
            return "session and intent_ref must be canonical base64url (32 bytes)"
        ps = s.get("principals")
        if not isinstance(ps, list) or len(ps) == 0 or len(ps) > MAX_SESSION_PRINCIPALS:
            return "principals must be 1..%d keys" % MAX_SESSION_PRINCIPALS
        keys = set()
        for p in ps:
            if not isinstance(p, dict) or any(k not in ("key", "alg", "pq_pk") for k in p) or not _b32(p.get("key")):
                return "principals entries are {key, alg?, pq_pk?} with a 32-byte key"
            if _suite_known_error(p.get("alg", _UNDEF)):
                return _ctx("principal alg: ", _suite_known_error(p["alg"]))
            if "pq_pk" in p and decode_b64u_strict(p["pq_pk"]) is None:
                return "principal pq_pk is not canonical base64url"
            if p["key"] in keys:
                return "principal keys must be distinct"
            keys.add(p["key"])
        sc = s.get("schema")
        if not isinstance(sc, dict) or _sorted_join(sc) != "aud,digest" or not isinstance(sc.get("aud"), str) \
                or len(sc["aud"]) == 0 or not _b32(sc.get("digest")):
            return "schema must be {aud, digest}"
        L = s.get("layers")
        if not isinstance(L, dict):
            return "layers must be an object"
        for k in _js_keys(L):
            if k not in ("org", "std", "task"):
                return "layers: unknown member '%s'" % k
        task = L.get("task")
        if not isinstance(task, dict) or ",".join(_js_keys(task)) != "map_digest" or not _b32(task.get("map_digest")):
            return "layers.task must be {map_digest}"
        org = L.get("org", _UNDEF)
        if org is not _UNDEF and (not isinstance(org, dict) or not _b32(org.get("digest"))):
            return "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)"
        std = L.get("std", _UNDEF)
        if std is not _UNDEF:
            if not isinstance(std, dict) or _sorted_join(std) != "digest,profile,version" or not isinstance(std.get("profile"), str) \
                    or len(std["profile"]) == 0 or _blen(std["profile"]) > 128 \
                    or not (_is_safe_int(std.get("version")) and std["version"] >= 1) or not _b32(std.get("digest")):
                return "layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)"
        accs = s.get("accumulators")
        if not isinstance(accs, list) or len(accs) > MAX_SESSION_ACCUMULATORS:
            return "accumulators must be an array of at most %d" % MAX_SESSION_ACCUMULATORS
        ids = set()
        for a in accs:
            e = accumulator_decl_error(a)
            if e:
                return e
            if a["id"] in ids:
                return "accumulator and monitor ids must be distinct"
            ids.add(a["id"])
        mons = s.get("monitors")
        if not isinstance(mons, list) or len(mons) > MAX_SESSION_MONITORS:
            return "monitors must be an array of at most %d" % MAX_SESSION_MONITORS
        mids = set()
        for m in mons:
            e = monitor_decl_error(m)
            if e:
                return e
            if m["id"] in mids:
                return "monitor ids must be distinct"
            mids.add(m["id"])
        qu = s.get("question_uri")
        if not isinstance(qu, str) or len(qu) == 0 or _blen(qu) > 2048:
            return "question_uri must be a non-empty string"
        if "revocation" in s:
            r = s["revocation"]
            if not isinstance(r, dict) or any(k not in ("epoch_uri", "max_age_s", "key", "pq_pk") for k in r):
                return "revocation must be {epoch_uri, max_age_s, key, pq_pk?}"
            if not isinstance(r.get("epoch_uri"), str) or len(r["epoch_uri"]) == 0:
                return "revocation.epoch_uri must be a non-empty string"
            if not _js_nonneg_int(r.get("max_age_s")):
                return "revocation.max_age_s must be a non-negative safe integer"
            if not _b32(r.get("key")):
                return "revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)"
            if r["key"] in keys:
                return "revocation.key must not be a session principal (a dedicated revocation authority)"
            if "pq_pk" in r and decode_b64u_strict(r["pq_pk"]) is None:
                return "revocation.pq_pk must be canonical base64url"
        if "flows" in s and not isinstance(s["flows"], dict):
            return "flows must be an object"
        if not _js_nonneg_int(s.get("expires_at")):
            return "expires_at must be a non-negative safe integer (epoch ms)"
        if signed:
            if not _b32(s.get("signer")):
                return "signer must be canonical base64url (32 bytes)"
            if s["signer"] not in keys:
                return "signer is not one of the session principals"
            if _suite_known_error(s.get("alg", _UNDEF)):
                return _ctx("alg: ", _suite_known_error(s["alg"]))
            if s.get("alg", "ed25519") == "ed25519" and ("pq_pk" in s or "pq_sig" in s):
                return "an ed25519 session root must not carry pq_pk / pq_sig"
            if not isinstance(s.get("sig"), str):
                return "sig must be a string"
        canonical_bytes_strict(_session_root_body(s))
        return None
    except Exception as e:  # noqa: BLE001
        return "malformed session root: %s" % e


def _session_root_body(s: dict) -> dict:
    body = {k: s.get(k, _UNDEF) for k in ("v", "kind", "session", "principals", "intent_ref", "schema", "layers",
                                          "accumulators", "monitors", "question_uri")}
    if "revocation" in s:
        body["revocation"] = s["revocation"]
    if "flows" in s:
        body["flows"] = s["flows"]
    body["expires_at"] = s.get("expires_at", _UNDEF)
    for v in body.values():
        if v is _UNDEF:
            raise TypeError("canonicalize: unsupported type undefined")
    return body


def verify_session_root(s: Any, pq_pins: Any = None) -> dict:
    """Verify S: shape, signer listed, suite signature. R3-01 (fail closed): a non-ed25519 root verifies only under the
    VERIFIER's pin for its signer (`pq_pins` = context session.pq_pins, a dict whose member for the signer is a str),
    never under the root's own principals[].pq_pk; the signer's own entry, when it declares a pq_pk, must agree. An
    ed25519 root never consults the pins. Returns {"ok": True} or {"ok": False, "reason"}. Total."""
    try:
        bad = session_root_shape_error(s)
        if bad:
            return _bad(bad)
        alg = s.get("alg", _UNDEF)
        suite = "ed25519" if alg is _UNDEF else alg  # a registered name (session_root_shape_error)
        p = next(x for x in s["principals"] if x["key"] == s["signer"])
        pins = None
        if suite != "ed25519":
            pin = pq_pins.get(s["signer"]) if isinstance(pq_pins, dict) else None
            if not isinstance(pin, str):
                return _bad("session root suite '%s' needs the signer's PQ key pinned by the verifier (pq_pins); "
                            "the root's own principals entry proves nothing about who signed it" % suite)
            if s.get("pq_pk", _UNDEF) != pin:
                return _bad("session root pq_pk does not match the verifier's pin for the signer")
            if "pq_pk" in p and p["pq_pk"] != s.get("pq_pk", _UNDEF):
                return _bad("session root pq_pk does not match the signer's principals entry")
            pins = {s["signer"]: pin}
        se = suite_capability_error(alg)  # availability in this runtime, AFTER the pins (the reference's order)
        if se is not None:
            return _bad(_ctx("alg: ", se) if _unsupported(se) else "session root signature invalid")
        body = dict(_session_root_body(s), signer=s["signer"])
        msg = INTENT_SESSION_SIG_DOMAIN.encode("utf-8") + canonical_bytes_strict(
            _bind_suite_fields(body, s.get("alg", _UNDEF), s.get("pq_pk", _UNDEF)))
        err = _pinned_suite_error(s.get("alg", _UNDEF), s["signer"], s.get("pq_pk", _UNDEF), msg, s["sig"],
                                  s.get("pq_sig", _UNDEF), pins)
        if err is not None:
            return _bad(err if _unsupported(err) else "session root signature invalid")
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return _bad("malformed session root: %s" % e)


def session_root_digest(s: Any) -> str:
    """digest(S): the content address of the whole signed session root."""
    return hash_canonical({"d": INTENT_SESSION_REF_DOMAIN, "s": s})


def intent_goal_v2(session: str, map_digest: str) -> str:
    """The goal a session grant (G_0 or D_k) commits to: `pca-intent:v2:<session>:<map_digest>`."""
    return "pca-intent:v2:" + session + ":" + map_digest


# ---- intent-v2.ts: the verifier pipeline ----------------------------------------------------------------------------
#
# The verifier context (TS IntentV2Context) follows the README "Absent vs null" rule: an optional member that is ABSENT
# means empty / default; PRESENT with null or of the wrong JSON type it is MALFORMED and fails closed.

def _opt_obj(o: dict, k: str) -> bool:
    return k not in o or isinstance(o[k], dict)


def _opt_arr(o: dict, k: str) -> bool:
    return k not in o or isinstance(o[k], list)


def intent_v2_context_error(ctx: Any) -> Optional[str]:
    """The whole v2 context (intentV2ContextError). None (absent context) or a well-formed one -> None; otherwise the
    reason, and every v2 check that could be reported fails with "malformed v2 context: <reason>"."""
    if ctx is None:
        return None
    if not isinstance(ctx, dict):
        return "the v2 verifier context must be an object"
    if not _opt_obj(ctx, "policy"):
        return "policy must be an object"
    if "policy" in ctx:
        # closed member sets; every flag a JSON boolean, every number a safe integer when present (absent = default)
        pol = ctx["policy"]
        for k in _js_keys(pol):
            if k not in ("session", "schema", "acc", "map", "model_polarity"):
                return "policy: unknown member '%s'" % k
        if "model_polarity" in pol and pol["model_polarity"] not in ("strict", "legacy"):
            return "policy.model_polarity must be 'strict' or 'legacy'"
        if not _opt_obj(pol, "session"):
            return "policy.session must be an object"
        if "session" in pol:
            o = pol["session"]
            for k in _js_keys(o):
                if k not in ("require", "max_revocation_age_s"):
                    return "policy.session: unknown member '%s'" % k
            if "require" in o and not isinstance(o["require"], bool):
                return "policy.session.require must be a boolean"
            if "max_revocation_age_s" in o and not _js_nonneg_int(o["max_revocation_age_s"]):
                return "policy.session.max_revocation_age_s must be a non-negative safe integer"
        if not _opt_obj(pol, "schema"):
            return "policy.schema must be an object"
        if "schema" in pol:
            o = pol["schema"]
            for k in _js_keys(o):
                if k != "closed_world":
                    return "policy.schema: unknown member '%s'" % k
            if "closed_world" in o and not isinstance(o["closed_world"], bool):
                return "policy.schema.closed_world must be a boolean"
        if not _opt_obj(pol, "acc"):
            return "policy.acc must be an object"
        if "acc" in pol:
            o = pol["acc"]
            for k in _js_keys(o):
                if k not in ("max_receipt_age_s", "max_keyset_age_s"):
                    return "policy.acc: unknown member '%s'" % k
            for k in ("max_receipt_age_s", "max_keyset_age_s"):
                if k in o and not _js_nonneg_int(o[k]):
                    return "policy.acc.%s must be a non-negative safe integer" % k
        if not _opt_obj(pol, "map"):
            return "policy.map must be an object"
        if "map" in pol:
            o = pol["map"]
            for k in _js_keys(o):
                if k not in ("require", "max_residual_risk_ppm"):
                    return "policy.map: unknown member '%s'" % k
            if "require" in o and not isinstance(o["require"], bool):
                return "policy.map.require must be a boolean"
            if "max_residual_risk_ppm" in o and not _js_nonneg_int(o["max_residual_risk_ppm"]):
                return "policy.map.max_residual_risk_ppm must be a non-negative safe integer"
    if not _opt_obj(ctx, "params"):
        return "params must be an object"
    if not _opt_obj(ctx, "env"):
        return "env must be an object"
    for k in ("schema", "session", "acc"):
        if not _opt_obj(ctx, k):
            return "%s must be an object" % k
    if not _opt_obj(ctx, "map"):
        return "map must be an object"
    if "map" in ctx:
        for k in _js_keys(ctx["map"]):
            if k != "disclosure":
                return "map: unknown member '%s'" % k
    if "layers" in ctx:
        L = ctx["layers"]
        if not isinstance(L, dict):
            return "layers must be an object"
        for k in _js_keys(L):
            if k not in ("org", "site", "std"):
                return "layers: unknown member '%s'" % k
            v = L[k]
            if not isinstance(v, dict) or not isinstance(v.get("predicates"), list):
                return "layers.%s must be {predicates: [...]}" % k
    if "wb" in ctx:
        return validate_wb_context(ctx["wb"])  # the W-B members (intent_wb.py, same order and reasons)
    return None


def _schema_ctx_error(ctx: Any) -> Optional[str]:
    sc = _prop(ctx, "schema")
    if sc is _UNDEF:
        return None
    if not isinstance(sc, dict) or not isinstance(sc.get("docs"), list) or not isinstance(sc.get("keys"), list):
        return "the schema context must be {docs: [...], keys: [...]}"
    return None


def _session_ctx_error(ctx: Any) -> Optional[str]:
    se = _prop(ctx, "session")
    if se is _UNDEF:
        return None
    if not isinstance(se, dict):
        return "the session context must be an object"
    if not _opt_arr(se, "grants"):
        return "the session grants must be an array"
    if not _opt_obj(se, "revocation"):
        return "the session revocation evidence must be an object"
    if not _opt_obj(se, "revocation_last"):
        return "the tracked last revocation epoch must be an object"
    if "pq_pins" in se and (not isinstance(se["pq_pins"], dict) or any(not isinstance(v, str) for v in se["pq_pins"].values())):
        return "the session pq_pins must be an object of strings"
    return None


def _acc_ctx_error(ctx: Any) -> Optional[str]:
    a = _prop(ctx, "acc")
    if a is _UNDEF:
        return None
    if not isinstance(a, dict):
        return "the accumulator context must be an object"
    for k in ("state", "monitors", "last_seq", "keyset_versions"):
        if not _opt_obj(a, k):
            return "acc.%s must be an object" % k
    if "keyset_versions" in a:
        kv = a["keyset_versions"]
        for k in _js_keys(kv):
            e = tracked_key_set_error(kv[k])
            if e:
                return "acc.keyset_versions: " + e
    for k in ("receipts", "sequencer_keys"):
        if not _opt_arr(a, k):
            return "acc.%s must be an array" % k
    if "last_seq" in a:
        for v in a["last_seq"].values():
            if not _js_nonneg_int(v):
                return "acc.last_seq values must be non-negative safe integers"
    return None


def _schema_step(p: dict, ctx: Any) -> dict:
    """Rule 14 (`schema`). On success {"ok": True, "doc": schema}."""
    is_ = p.get("intent_session", _UNDEF)
    ce = _schema_ctx_error(ctx)
    if ce:
        return _bad(ce)
    sch = _prop(ctx, "schema")
    docs = _prop(sch, "docs")
    if not isinstance(docs, list) or len(docs) == 0:
        return _bad("this verifier has no action schema configured")
    if is_ is not _UNDEF:
        doc = _UNDEF
        for d in docs:
            try:
                hit = action_schema_digest(d) == is_["schema"]
            except Exception:  # noqa: BLE001
                hit = False
            if hit:
                doc = d
                break
        if doc is _UNDEF:
            return _bad("intent_session.schema names no schema this verifier accepts")
    else:
        doc = docs[0]
    v = verify_action_schema(doc, sch["keys"])
    if not v["ok"]:
        return _bad("schema does not verify: %s" % v["reason"])
    if not _js_strict_eq(doc["aud"], _prop(p, "aud")):
        return _bad("schema aud does not match the PCActn aud")
    params = _prop(ctx, "params")
    if not isinstance(params, dict):
        return _bad("no plaintext params to check against the schema (closed world needs them)")
    if params_digest(params) != _action_member(p, "params_digest"):
        return _bad("params do not hash to action.params_digest")
    c = conform_action(doc, _js_string(_action_member(p, "verb")), params)
    if not c["ok"]:
        return _bad("schema_violation: %s: %s" % (c["code"], c["reason"]))
    return {"ok": True, "doc": doc}


def _bound_root(p: dict, ctx: Any, now: int) -> dict:
    """The bound, verified session root (shared by rules 13 and 15). On success {"ok": True, "S": root}."""
    is_ = p["intent_session"]
    S = _prop(_prop(ctx, "session"), "root")
    if S is _UNDEF:
        return _bad("no session root for this session")
    # a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals
    v = verify_session_root(S, _prop(_prop(ctx, "session"), "pq_pins"))
    if not v["ok"]:
        return _bad("session root: %s" % v["reason"])
    if session_root_digest(S) != is_["root"]:
        return _bad("intent_session.root is not the digest of the session root")
    if S["session"] != is_["session"]:
        return _bad("the session root names another session")
    if not now < S["expires_at"]:
        return _bad("the session root has expired")
    return {"ok": True, "S": S}


def _str_in(x: Any, s: set) -> bool:
    return isinstance(x, str) and x in s


def _session_step(p: dict, grant: Any, ctx: Any, now: int) -> dict:
    """Rule 13 (`intent_session`)."""
    pol = _prop(_prop(ctx, "policy"), "session")
    max_age_s = _prop(pol, "max_revocation_age_s")
    if max_age_s is not _UNDEF and not _js_nonneg_int(max_age_s):
        return _bad("session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)")
    if "intent_session" not in p:
        return _bad("this verifier requires an intent_session but the PCActn carries none")
    is_ = p["intent_session"]
    ce = _session_ctx_error(ctx)
    if ce:
        return _bad(ce)
    if "intent" not in p:
        return _bad("an intent_session needs the envelope.intent binding")
    intent = p["intent"]
    r = _bound_root(p, ctx, now)
    if not r["ok"]:
        return r
    S = r["S"]
    if S["intent_ref"] != intent["ref"]:
        return _bad("intent.ref is not the session statement")
    if S["schema"]["digest"] != is_["schema"]:
        return _bad("intent_session.schema is not the session schema")
    if S["schema"]["aud"] != _prop(p, "aud"):
        return _bad("the session schema is for another audience")
    seq = is_["seq"]
    if seq == 0 and intent["map_digest"] != S["layers"]["task"]["map_digest"]:
        return _bad("a seq-0 action must use the session task map")
    gc = grant_session_caveat(grant)
    ge = intent_session_caveat_error(gc)
    if ge:
        return _bad("admitting root: %s" % ge)
    if gc["session"] != is_["session"] or gc["root"] != is_["root"] or gc["seq"] != seq:
        return _bad("the admitting root is bound to another session, root or seq")
    principals = [x["key"] for x in S["principals"]]
    pset = set(principals)
    if not _str_in(grant.get("issuer"), pset):
        return _bad("the admitting root is not signed by a session principal")
    prior = _prop(_prop(ctx, "session"), "grants")
    if prior is _UNDEF:
        prior = []
    if not isinstance(prior, list) or len(prior) < seq:
        return _bad("the verifier does not hold the %s earlier grants of this session" % _js_str(seq))
    n = int(seq)
    for i in range(n):
        g = prior[i]
        if not isinstance(g, dict) or not isinstance(g.get("id"), str) or not isinstance(g.get("issuer"), str):
            return _bad("session grant %d is not a capability" % i)
        gse = suite_capability_error(g.get("alg", _UNDEF))
        if gse:
            return _bad("session grant %d: %s" % (i, gse))
        c = grant_session_caveat(g)
        if intent_session_caveat_error(c) is not None or c["session"] != is_["session"] or c["root"] != is_["root"] or c["seq"] != i:
            return _bad("session grant %d does not belong to this session at seq %d" % (i, i))
        if g["issuer"] not in pset:
            return _bad("session grant %d is not signed by a session principal" % i)
        if i > 0 and not _js_strict_eq(c.get("prev", _UNDEF), prior[i - 1]["id"]):
            return _bad("session grant %d does not chain to grant %d" % (i, i - 1))
    if n > 0 and not _js_strict_eq(gc.get("prev", _UNDEF), prior[n - 1]["id"]):
        return _bad("the admitting root does not chain to grant %d" % (n - 1))
    srev = S.get("revocation", _UNDEF)
    if srev is not _UNDEF or max_age_s is not _UNDEF:
        ages = [x for x in (srev["max_age_s"] if srev is not _UNDEF else _UNDEF, max_age_s) if x is not _UNDEF]
        max_age_ms = min(ages) * 1000
        if srev is _UNDEF:
            return _bad("revocation: the policy requires a revocation epoch but the session root names no revocation authority")
        ids = [session_revocation_id(is_["session"]), map_revocation_id(intent["map_digest"])]
        ids += [delta_revocation_id(g["id"]) for g in prior[:n]]
        ids.append(delta_revocation_id(grant.get("id", _UNDEF)))
        std = S["layers"].get("std", _UNDEF)
        if std is not _UNDEF:
            ids.append(profile_revocation_id(std["profile"], std["version"]))
        # only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
        pins = {srev["key"]: srev["pq_pk"]} if "pq_pk" in srev else {}
        sess = _prop(ctx, "session")
        rv = check_session_revocation(_prop(sess, "revocation"), session=is_["session"], authority=srev["key"], ids=ids,
                                      now=now, max_age_ms=max_age_ms, pq_pins=pins,
                                      last=_prop(sess, "revocation_last"))
        if not rv["ok"]:
            return _bad("revocation: %s" % rv["reason"])
    return {"ok": True}


def _acc_step(p: dict, ctx: Any, now: int) -> dict:
    """Rule 15 (`accumulators`). On success {"ok": True, "env": {"acc": {...}, "mon": {...}}}."""
    is_ = p["intent_session"]
    r = _bound_root(p, ctx, now)
    if not r["ok"]:
        return r
    S = r["S"]
    ce = _acc_ctx_error(ctx) or _schema_ctx_error(ctx)
    if ce:
        return _bad(ce)
    verb = _js_string(_action_member(p, "verb"))
    claims = is_.get("acc", [])
    for c in claims:
        a = next((x for x in S["accumulators"] if x["id"] == c["id"]), None)
        if a is None:
            return _bad("claim '%s' names no accumulator of the session" % c["id"])
        if a["holder"]["kind"] == "wallet":
            return _bad("accumulator '%s' is wallet-held and cannot be claimed at a site" % c["id"])
    acc_ctx = _prop(ctx, "acc")
    acc_ctx = {} if acc_ctx is _UNDEF else acc_ctx
    docs = _prop(_prop(ctx, "schema"), "docs")
    schema_doc = None
    for d in ([] if docs is _UNDEF else docs):
        try:
            hit = action_schema_digest(d) == is_["schema"]
        except Exception:  # noqa: BLE001
            hit = False
        if hit:
            schema_doc = d if isinstance(d, dict) else None
            break
    params = _prop(ctx, "params")
    env = {"acc": {}, "mon": {}}
    state = acc_ctx.get("state", {})
    for a in S["accumulators"]:
        aid, holder = a["id"], a["holder"]
        if holder["kind"] == "wallet":
            continue
        if "accumulates_into" in a["sel"] and schema_doc is None:
            return _bad("accumulator '%s' selects by accumulates_into but the session schema is not available" % aid)
        selected = acc_selects(a, verb, schema_doc)
        claim = next((c for c in claims if c["id"] == aid), None)
        pre = _own_get(state, aid)
        if not selected:
            if claim is not None:
                return _bad("claim '%s' for an accumulator this action does not feed" % aid)
            if holder["kind"] == "site_local" and pre is not _UNDEF:
                pe = pre_state_error(a, pre)
                if pe:
                    return _bad("accumulator '%s': %s" % (aid, pe))
                env["acc"][aid] = {"post": pre_value(a, pre)}
            continue
        if claim is None:
            return _bad("no claim for accumulator '%s' that this action feeds" % aid)
        if not isinstance(params, dict):
            return _bad("no plaintext params to compute accumulator values")
        if a["key"] is not None:
            key = a["key"]
            if _own_get(params, key[len(_PARAMS_PREFIX):]) is _UNDEF:
                return _bad("accumulator '%s': the key parameter %s is missing" % (aid, key))
            kd = _UNDEF
            if schema_doc is not None:
                v = schema_verb(schema_doc, verb)
                if v is not None:
                    vp = v.get("params", _UNDEF)
                    if not isinstance(vp, dict):
                        raise TypeError("the verb's params must be an object")
                    kd = _own_get(vp, key)
            sem = _prop(kd, "semantic")
            if not isinstance(sem, str) or sem.startswith("text."):
                return _bad("accumulator '%s': the key must be a schema-declared identity (not free text)" % aid)
        v = acc_value_of(a, verb, params, schema_doc)
        if not v["ok"]:
            return _bad("accumulator '%s': %s" % (aid, v["reason"]))
        if holder["kind"] == "site_local":
            if "receipt" in claim:
                return _bad("accumulator '%s' is site-local: a receipt is not accepted" % aid)
            if pre is _UNDEF:
                return _bad("no state for site-local accumulator '%s'" % aid)
            pe = pre_state_error(a, pre)
            if pe:
                return _bad("accumulator '%s': %s" % (aid, pe))
            x = combine_acc(a, pre, v)
            if x is None:
                return _bad("accumulator '%s' overflows 2^53-1" % aid)
            post = x
        else:
            if "receipt" not in claim:
                return _bad("accumulator '%s' is sequenced: the claim needs a reservation receipt" % aid)
            rc = _UNDEF
            for x in acc_ctx.get("receipts", []):
                try:
                    hit = acc_receipt_digest(x) == claim["receipt"]
                except Exception:  # noqa: BLE001
                    hit = False
                if hit:
                    rc = x
                    break
            if rc is _UNDEF:
                return _bad("the reservation receipt for '%s' was not presented" % aid)
            pa = _prop(_prop(ctx, "policy"), "acc")
            mra, mka = _prop(pa, "max_receipt_age_s"), _prop(pa, "max_keyset_age_s")
            trk = _own_get(acc_ctx.get("keyset_versions", {}), holder["root"])  # {version, digest} (_acc_ctx_error)
            he = receipt_against_holder_error(
                rc, holder, acc_ctx.get("sequencer_keys", []), now,
                None if mra is _UNDEF else mra * 1000, None if mka is _UNDEF else mka * 1000,
                None, None if trk is _UNDEF else trk)
            if he is not None:
                if _unsupported(he):
                    return _bad("the reservation receipt for '%s': %s" % (aid, he))
                return _bad("the reservation receipt for '%s' is not signed by a key the session sequencer's root-signed "
                            "key set lists for its issue time" % aid)
            if rc["session"] != is_["session"] or rc["acc"] != aid or rc["aud"] != p["aud"]:
                return _bad("the reservation receipt for '%s' is for another session, accumulator or audience" % aid)
            if rc["pcactn_digest"] != pcactn_reservation_digest(p):
                return _bad("the reservation receipt for '%s' is for another action" % aid)
            if not now <= rc["expires_at"]:
                return _bad("the reservation receipt for '%s' has expired" % aid)
            last = _own_get(acc_ctx.get("last_seq", {}), aid)  # a non-negative safe integer (_acc_ctx_error)
            if last is not _UNDEF and not rc["seq"] > last:
                return _bad("the reservation receipt for '%s' replays seq %s (last accepted %s)" % (aid, _js_str(rc["seq"]), _js_str(last)))
            if not receipt_arithmetic_ok(a, rc, v["val"]):
                return _bad("the reservation receipt for '%s' does not add up" % aid)
            post = rc["post"]
        if "domain_max" in a and post > a["domain_max"]:
            return _bad("accumulator '%s' post %s is outside its domain (max %s)" % (aid, _js_str(post), _js_str(a["domain_max"])))
        if claim["post"] != post:
            return _bad("claimed post %s for '%s' differs from the verifier's %s" % (_js_str(claim["post"]), aid, _js_str(post)))
        env["acc"][aid] = {"post": post}
    mons = acc_ctx.get("monitors", {})
    for m in S["monitors"]:
        st = _own_get(mons, m["id"])
        if not isinstance(st, str) or st not in monitor_states(m):
            return _bad("no valid state for monitor '%s'" % m["id"])
        env["mon"][m["id"]] = {"state": st}
    return {"ok": True, "env": env}


def decide_intent_v2(p: Any, grant: Any, ctx: Any, now: Any) -> dict:
    """Run the Intent Layer v2 checks after `intent` (rule 12), in the normative order (conformance README "Intent Layer
    v2: the verification pipeline"):
      1 `schema`         iff the PCActn carries `intent_session` or `policy.schema.closed_world` is True   (rule 14)
      2 `intent_session` iff the PCActn carries it or `policy.session.require` is True                   (rule 13)
      3 `layers`         iff the PCActn carries `intent_session` and `ctx` has a `layers` member         (V5)
      4 `accumulators`   iff the PCActn carries `intent_session`                                           (rule 15)
      4a `map`           iff `intent_session.map_form` is "commit" or `policy.map.require` is True         (rule 19)
      5-7 `facts` / `provenance` / `classes`: the W-B unit (decide_intent_wb), only with `intent_session`; the first
          failing one ends the unit; a rule-17 `question` fails `provenance` with reason "intent_required: ...".
    Checks 1-4a are independent (each runs even when an earlier one failed; `map` is reported also for a PCActn without
    `intent_session` when the policy requires it, and then fails). `ctx` is the verifier state (TS IntentV2Context,
    None = absent). A malformed context fails `schema`, `intent_session` (and `accumulators` with the member, and `map`
    with map_form "commit") with "malformed v2 context: ..."; a clock `now` that is not a safe integer fails every check run. Returns
    {"checks": [{"name", "ok", "reason"?}], "env"?: {canon?, acc?, mon?, world?, prov?, class?}, "schema"?: doc}.
    Never raises: an internal error fails the check being evaluated."""
    out: dict = {"checks": []}
    try:
        _decide_intent_v2(out, p, grant, ctx, now)
    except Exception as e:  # noqa: BLE001 - totality outside the per-check guards
        out["checks"].append({"name": "intent_session", "ok": False, "reason": "intent v2 error (fail closed): %s" % e})
    return out


def _decide_intent_v2(out: dict, p: Any, grant: Any, ctx: Any, now: Any) -> None:
    present = isinstance(p, dict) and "intent_session" in p
    clock_ok = _is_safe_int(now)
    ctx_err = intent_v2_context_error(ctx)
    if ctx_err is not None:
        committed = present and p["intent_session"].get("map_form") == MAP_FORM_COMMIT
        for name in ("schema", "intent_session") + (("accumulators",) if present else ()) + (("map",) if committed else ()):
            out["checks"].append({"name": name, "ok": False, "reason": "malformed v2 context: %s" % ctx_err})
        return

    def run(name: str, f) -> dict:
        try:
            s = f() if clock_ok else _bad("the verifier clock is not a safe integer (fail closed)")
        except Exception as e:  # noqa: BLE001
            s = _bad("%s error (fail closed): %s" % (name, e))
        out["checks"].append({"name": name, "ok": True} if s["ok"] else {"name": name, "ok": False, "reason": s["reason"]})
        return s

    pol = _prop(ctx, "policy")
    if present or _prop(_prop(pol, "schema"), "closed_world") is True:
        def schema():
            s = _schema_step(p, ctx)
            if s["ok"]:
                out["schema"] = s["doc"]
                out["env"] = {"canon": canon_projection(s["doc"], _js_string(_action_member(p, "verb")), ctx["params"])}
            return s
        run("schema", schema)
    if present or _prop(_prop(pol, "session"), "require") is True:
        run("intent_session", lambda: _session_step(p, grant, ctx, now))
    map_active = (present and p["intent_session"].get("map_form") == MAP_FORM_COMMIT) \
        or _prop(_prop(pol, "map"), "require") is True
    params = _prop(ctx, "params")
    action = {"verb": _js_string(_action_member(p, "verb")), "resource": _js_string(_action_member(p, "resource")),
              "params": params if isinstance(params, dict) else {}}
    layers = _prop(ctx, "layers")
    if present and layers is not _UNDEF:
        def lay():
            env = {"canon": out["env"]["canon"]} if "env" in out and "canon" in out["env"] else {}
            d = decide_layer_ceilings(layers, {"action": action, "env": env})
            return {"ok": True} if d.get("status") == "pass" else _bad(d.get("reason"))
        run("layers", lay)
    if not present:
        if map_active:
            run("map", lambda: _map_step(p, ctx))
        _model_rules(out, p, grant, ctx, run, action)
        return

    def acc():
        s = _acc_step(p, ctx, now)
        if s["ok"]:
            out["env"] = dict(out.get("env", {}), **s["env"])
        return s
    run("accumulators", acc)
    if map_active:
        run("map", lambda: _map_step(p, ctx))
    wb = None
    try:
        wbctx = _prop(ctx, "wb")
        inp = {"now": now, "aud": _js_string(_prop(p, "aud")), "session": p["intent_session"]["session"], "action": action,
               "intent_session": p["intent_session"]}
        arts = _prop(wbctx, "artifacts")
        if arts is not _UNDEF:
            inp["artifacts"] = arts
        wpol = _prop(wbctx, "policy")
        inp["policy"] = {} if wpol is _UNDEF else wpol
        wb = decide_intent_wb(inp)
    except Exception as e:  # noqa: BLE001
        out["checks"].append({"name": "facts", "ok": False, "reason": "W-B error (fail closed): %s" % e})
    if wb is not None:
        if wb.get("single_source"):
            out["single_source"] = list(wb["single_source"])
        checks = wb.get("checks") or {}
        reason = wb.get("reason")
        for name in ("facts", "provenance", "classes"):
            c = checks.get(name)
            if c is None:
                continue
            if c == "pass":
                out["checks"].append({"name": name, "ok": True})
            elif c == "question":
                out["checks"].append({"name": name, "ok": False, "reason": "intent_required: %s" % (
                    "a question is required" if reason is None else reason)})
            else:
                out["checks"].append({"name": name, "ok": False, "reason": "rejected" if reason is None else reason})
        if wb.get("outcome") != "deny":
            wenv = wb.get("env") or {}
            merged = dict(out.get("env", {}))
            for k in ("world", "prov", "class"):
                if wenv.get(k) is not None:
                    merged[k] = wenv[k]
            out["env"] = merged
    _model_rules(out, p, grant, ctx, run, action)


def _allow_side_predicates(env: Any, ctx: Any) -> list:
    """The predicate lists a model-derived path could widen: the grant's allow-list and the ceilings (V5 layers)."""
    lists: list = [None if env is None else env.get("predicates")]
    layers = _prop(ctx, "layers")
    if isinstance(layers, dict):
        for k in ("org", "site", "std"):
            e = layers.get(k)
            lists.append(e.get("predicates") if isinstance(e, dict) else None)
    return lists


def _model_rules(out: dict, p: Any, grant: Any, ctx: Any, run: Any, action: dict) -> None:
    """Rules 20 and 21 (intent-v2.ts `modelRules`), evaluated last so the verifier-computed `env` is complete. Both read the
    signed ENVELOPE of the stored grant:
      `units` (20): reported iff `envelope.units` is present.
      `tighten` (21): reported iff `envelope.tighten` or a `model_polarity` (envelope or policy) is present, or a grant-side
      `where` reads a model-derived env path (so that case is refused, never silently skipped). A PCActn with none of these
      verifies byte-identically to a verifier without the two rules."""
    from .authorize import read_envelope  # deferred: authorize imports this package's core
    env = read_envelope(grant)
    preds = _allow_side_predicates(env, ctx)
    if env is not None and "units" in env:
        def units():
            if "schema" in out:
                doc = out["schema"]
            else:
                s = _schema_step(p, ctx)
                if not s["ok"]:
                    return s
                doc = s["doc"]
            v = schema_verb(doc, action["verb"])
            inp = {"units": env["units"], "verb": action["verb"], "predicates": preds}
            su = _prop(doc, "units")
            if su is not _UNDEF:  # an explicit null is NOT absent (rule 20 refuses it)
                inp["schema_units"] = su
            if v is not None and "params" in v:
                inp["verb_params"] = v["params"]
            d = decide_units(inp)
            return {"ok": True} if d["ok"] else _bad(d["reason"])
        run("units", units)
    single = out.get("single_source") or []
    pol = _prop(_prop(ctx, "policy"), "model_polarity")
    if pol == "strict":
        polarity = _UNDEF
    elif pol is not _UNDEF:
        polarity = pol
    else:
        polarity = _UNDEF if env is None else env.get("model_polarity", _UNDEF)
    if (env is not None and "tighten" in env) or polarity is not _UNDEF or pol is not _UNDEF or model_paths_read(preds, single):
        def tighten_rule():
            host_env = _prop(ctx, "env")
            inp = {"predicates": preds, "single_source": single,
                   "context": {"action": action, "env": dict(host_env if isinstance(host_env, dict) else {}, **(out.get("env") or {}))}}
            if env is not None and "tighten" in env:
                inp["tighten"] = env["tighten"]
            if polarity is not _UNDEF:
                inp["polarity"] = polarity
            r = decide_tighten(inp)
            if r["legacy"]:
                out["legacy_model_polarity"] = True
            return {"ok": True} if r["outcome"] == "ok" else _bad(r.get("reason") or "refused")
        run("tighten", tighten_rule)


def _map_step(p: dict, ctx: Any) -> dict:
    """Rule 19 (`map`, V15 Z0): the PCActn uses the committed map form, carries `intent`, and the verifier holds the
    agent's disclosure; then decide_map_disclosure over `intent.map_digest`, the action, the plaintext params and ε."""
    is_ = p.get("intent_session", _UNDEF)
    if not (isinstance(is_, dict) and is_.get("map_form") == MAP_FORM_COMMIT):
        return _bad('this verifier requires a committed map (intent_session.map_form "commit")')
    if "intent" not in p:
        return _bad("a committed map needs the envelope.intent binding")
    disclosure = _prop(_prop(ctx, "map"), "disclosure")
    if disclosure is _UNDEF:
        return _bad("no disclosure of the committed map was presented")
    kw = {}
    params = _prop(ctx, "params")
    if params is not _UNDEF:
        kw["params"] = params
    eps = _prop(_prop(_prop(ctx, "policy"), "map"), "max_residual_risk_ppm")
    if eps is not _UNDEF:
        kw["max_residual_risk_ppm"] = eps
    d = decide_map_disclosure(p["intent"]["map_digest"], p.get("action", {}), disclosure, **kw)
    return {"ok": True} if d["ok"] else _bad(d["reason"])


def intent_v2_active(p: Any, ctx: Any) -> bool:
    """True iff any v2 check would be reported (the PCActn carries `intent_session`, a v2 policy is active, or a present
    context is malformed and the checks fail closed)."""
    pol = _prop(ctx, "policy")
    return (isinstance(p, dict) and "intent_session" in p) or intent_v2_context_error(ctx) is not None or _prop(_prop(pol, "schema"), "closed_world") is True \
        or _prop(_prop(pol, "session"), "require") is True or _prop(_prop(pol, "map"), "require") is True
