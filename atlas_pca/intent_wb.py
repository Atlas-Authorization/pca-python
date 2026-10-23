"""Intent Layer v2 wire batch W-B: NORMATIVE conformance rules 16 (world facts, relational dimensions, offer sets), 17
(per-parameter provenance, label receipts, flow rules) and 18 (classifier verdicts), and their composition
`decide_intent_wb` (the facts -> provenance -> classes unit of the v2 verification pipeline).

Port of packages/pca/src oracle-facts.ts, offer-set.ts, param-provenance.ts, label-receipts.ts (verifier side),
intent-classifier.ts, intent-env.ts, the shared plumbing of intent-artifacts.ts and the label lattice of taint.ts. Step order,
boundaries and reason strings follow the TypeScript reference. Inputs are dicts shaped like the TS input interfaces (the
`input` objects of primitives.intent_world / intent_provenance / intent_classifier in conformance/vectors.json). Every public
decide function is total: an internal error fails closed where the TS try/catch does.

JS semantics reproduced here (the reference runs on JSON.parse values):
  * `undefined` (a member that is absent) and `null` are distinct: `x !== undefined` tests key presence, `x ?? d` treats both
    absent and null as `d`. `_UNDEF` is the absent marker; it never appears in an output.
  * Object key iteration (Object.keys / Object.entries) is canonical array-index keys ascending, then insertion order
    (`_js_keys`); the provenance sorts are UTF-8 byte order (hash.ts compareUtf8, `_sorted_utf8`).
  * Safe integers reject -0 (isSafeInt of intent-artifacts.ts); bool is never a number; an integral float is the same number
    as the int.
  * Keyed lookups and tallies are over own members only (dicts): `constructor`, `__proto__`, `toString` are ordinary keys.
  * CLOCK: `now` must be a safe integer (`is_clock`); any other value is never coerced and makes every fact and every offer
    set stale.
  * ABSENT VS NULL: an optional member that is ABSENT means empty / default (`_absent_or`); one PRESENT with JSON null or
    of the wrong JSON type is malformed and fails closed. Supplied lists are real arrays (a string is never iterated).
  * SUITES: every W-B artifact may carry `alg` / `pq_pk` / `pq_sig`. The signature goes through atlas_pca.pca's EXISTING
    suite dispatch (`verify_leaf_suite`); a suite the dispatch does not implement is `unsupported_suite`, and a PQ / hybrid
    signature verifies only under the PQ key the verifier PINS for that signer (`_resolve_pq_key`).
"""
import math
import re
from typing import Any, Dict, List, Optional

from .pca import (
    MAX_SAFE, _resolve_pq_key, canonical_bytes_strict, decode_b64u_strict, hash_canonical, suite_available,
    verify_leaf_suite,
)

# ---- constants ---------------------------------------------------------------------------------------------------------

FACT_DOMAIN = "atlas-pca/fact/v1\x00"
FACT_REF_DOMAIN = "atlas-pca/fact-ref/v1"
MAX_COMMITTED_FACTS = 16
MAX_WORLDS = 16
MAX_RELATIONAL = 16
DEFAULT_WORLD_SKEW_MS = 60_000

OFFER_SET_DOMAIN = "atlas-pca/offer-set/v1\x00"
OFFER_SET_REF_DOMAIN = "atlas-pca/offer-set-ref/v1"
MAX_OFFERS = 256
MAX_OFFER_ATTRS = 32
MAX_QUERY_KEYS = 32

LABELS_DOMAIN = "atlas-pca/labels/v1\x00"
LABELS_REF_DOMAIN = "atlas-pca/labels-ref/v1"
MAX_LABEL_FIELDS = 64
PUBLIC_CLASS = "public"

LABEL_REF_PREFIX = "pca-labels:"
MAX_PROV_PATHS = 32
MAX_PROV_REFS = 8
MAX_COMMITTED_LABELS = 16

INTENT_CLASSIFIER_DOMAIN = "atlas-pca/intent-classifier/v1\x00"
INTENT_CLASSIFIER_REF_DOMAIN = "atlas-pca/intent-classifier-ref/v1"
MAX_COMMITTED_CLASSES = 8
MAX_CLASSIFIER_LABELS = 32

INTENT_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")  # always fullmatch
DATA_CLASS_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*")  # always fullmatch
PARAM_SEGMENT_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")  # always fullmatch
PROV_PATH_RE = re.compile(r"action\.params\.[A-Za-z0-9_]{1,64}")  # always fullmatch
_FORBIDDEN_SEGMENTS = frozenset(("__proto__", "constructor", "prototype"))
_ARRAY_INDEX_RE = re.compile(r"0|[1-9][0-9]*")

# taint.ts label lattice: trusted < first_party < tool < web < agent; TAINTED = rank >= tool.
TAINT_LEVELS = ("trusted", "first_party", "tool", "web", "agent")
_RANK = {k: i for i, k in enumerate(TAINT_LEVELS)}
_MAX_RANK = len(TAINT_LEVELS) - 1
_TAINTED_RANK = 2
_MODES = ("allow", "question", "question_typed", "deny")

_UNDEF = object()  # a JS `undefined` (absent member)


# ---- JS value helpers --------------------------------------------------------------------------------------------------

def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_safe_int(v: Any) -> bool:
    """intent-artifacts.ts isSafeInt: Number.isSafeInteger and not -0."""
    if isinstance(v, bool):
        return False
    if isinstance(v, float):
        if not math.isfinite(v) or v != math.trunc(v) or (v == 0 and math.copysign(1.0, v) < 0):
            return False
        return abs(v) <= MAX_SAFE
    return isinstance(v, int) and abs(v) <= MAX_SAFE


def is_clock(v: Any) -> bool:
    """A usable clock value: a safe integer (anything else makes every freshness bound fail, i.e. stale)."""
    return _is_safe_int(v)


def _non_empty_array(v: Any) -> bool:
    return isinstance(v, list) and len(v) > 0


def _int(v: Any) -> int:
    """A safe-integer JS number as a Python int (2.0 and 2 are the same JS number)."""
    return int(v)


def _get(o: Any, k: str) -> Any:
    """`o?.[k]`: the own member, or _UNDEF (absent member, or `o` not an object)."""
    if isinstance(o, dict) and k in o:
        return o[k]
    return _UNDEF


def _member(o: Any, k: str) -> Any:
    """`o[k]` where the reference throws on null / undefined (a TypeError the decide functions' try/catch reports)."""
    if o is None or o is _UNDEF:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return _get(o, k)


def _dflt(v: Any, d: Any) -> Any:
    """`v ?? d` (activity helpers only: absent or null count as nothing there)."""
    return d if v is None or v is _UNDEF else v


def _absent_or(v: Any, d: Any) -> Any:
    """`v === undefined ? d : v`: an ABSENT optional member is the default; a PRESENT one (JSON null included) is returned
    as is and judged by the caller's type check (null is malformed, never read as empty)."""
    return d if v is _UNDEF else v


def _present(v: Any) -> bool:
    """`v !== undefined`."""
    return v is not _UNDEF


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _utf8_key(s: str) -> tuple:
    """Sort key of hash.ts `compareUtf8`: the UTF-8 bytes TextEncoder writes (a lone surrogate becomes U+FFFD), and for
    two distinct strings with equal bytes the UTF-16 code-unit order (`a < b`)."""
    return (_SURROGATE_RE.sub("\ufffd", s).encode("utf-8"), s.encode("utf-16-be", "surrogatepass"))


def _utf8_len(s: str) -> int:
    # TextEncoder writes a lone surrogate as U+FFFD (3 bytes), as surrogatepass does.
    return len(s.encode("utf-8", "surrogatepass"))


def _js_keys(o: dict) -> list:
    """Object.keys order: canonical array-index keys ascending numerically, then the other keys in insertion order."""
    idx, rest = [], []
    for k in o:
        if isinstance(k, str) and _ARRAY_INDEX_RE.fullmatch(k) and int(k) <= 4294967294:
            idx.append(k)
        else:
            rest.append(k)
    idx.sort(key=int)
    return idx + rest


def _js_num_str(x: Any) -> str:
    """ECMAScript Number::toString."""
    if isinstance(x, int):
        if abs(x) < 10 ** 21:
            return str(x)
        try:
            x = float(x)
        except OverflowError:
            return "Infinity" if x > 0 else "-Infinity"
    if math.isnan(x):
        return "NaN"
    if math.isinf(x):
        return "Infinity" if x > 0 else "-Infinity"
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))
    mant, _, exp = r.partition("e")
    e = int(exp) if exp else 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + e - lead_zeros  # value = 0.digits * 10^n
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    ee = n - 1
    es = ("+" if ee > 0 else "-") + str(abs(ee))
    if k == 1:
        return sign + digits + "e" + es
    return sign + digits[0] + "." + digits[1:] + "e" + es


def _js_str(v: Any) -> str:
    """ECMAScript String(v) for JSON values (template-literal interpolation in reasons)."""
    if v is _UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    if _is_num(v):
        return _js_num_str(v)
    if isinstance(v, list):
        return ",".join("" if x is None or x is _UNDEF else _js_str(x) for x in v)
    return "[object Object]"


# ---- shared artifact plumbing (intent-artifacts.ts) --------------------------------------------------------------------

def is_path_segment(s: Any) -> bool:
    return isinstance(s, str) and PARAM_SEGMENT_RE.fullmatch(s) is not None and s not in _FORBIDDEN_SEGMENTS


def _is_bounded_string(v: Any, mx: int) -> bool:
    return isinstance(v, str) and len(v) > 0 and _utf8_len(v) <= mx


def _is_digest(v: Any) -> bool:
    return decode_b64u_strict(v, 32) is not None


def _is_scalar(v: Any) -> bool:
    return isinstance(v, (str, bool)) or _is_safe_int(v)


def scalar_eq(a: Any, b: Any) -> bool:
    """Same JSON type and value: 2 == 2.0, but 2 != "2" and true != 1 (JS `typeof a === typeof b && a === b`)."""
    if a is _UNDEF or b is _UNDEF:
        return a is b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_num(a) or _is_num(b):
        return _is_num(a) and _is_num(b) and a == b  # NaN != NaN, as ===
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    return a is b  # objects: identity


def _closed_members(o: dict, required, optional=(), where: str = "object") -> Optional[str]:
    for k in _js_keys(o):
        if k not in required and k not in optional:
            return "unknown member '%s.%s'" % (where, k)
    for k in required:
        if k not in o:
            return "missing member '%s.%s'" % (where, k)
    return None


SUITE_MEMBERS = ("alg", "pq_pk", "pq_sig")
UNSUPPORTED_SUITE = "unsupported_suite"


def pin_pq_ok(v: Any) -> bool:
    """A pin's optional `pq_pk`: absent, or a non-empty string (JSON null is malformed)."""
    return v is _UNDEF or (isinstance(v, str) and len(v) > 0)


def artifact_suite_error(a: dict) -> Optional[str]:
    """intent-artifacts.ts `artifactSuiteError` with this verifier's suite dispatch (`suite_available`): absent `alg` =
    ed25519; a non-string `alg` is malformed; an `alg` the dispatch does not implement is "unsupported_suite: '<alg>'";
    non-string `pq_pk` / `pq_sig` are malformed; an ed25519 artifact carries neither. None = usable."""
    if not isinstance(a, dict):
        return "artifact must be an object"
    alg = _get(a, "alg")
    if alg is not _UNDEF:
        if not isinstance(alg, str):
            return "alg must be a string"
        if not suite_available(alg):
            return "%s: '%s'" % (UNSUPPORTED_SUITE, alg)
    for k in ("pq_pk", "pq_sig"):
        v = _get(a, k)
        if v is not _UNDEF and not isinstance(v, str):
            return "%s must be a string" % k
    if (alg is _UNDEF or alg == "ed25519") and (_get(a, "pq_pk") is not _UNDEF or _get(a, "pq_sig") is not _UNDEF):
        return "an ed25519 artifact must not carry pq_pk / pq_sig"
    return None


def artifact_message(domain: str, artifact: dict) -> bytes:
    """utf8(domain) || strictCanonical(artifact without `sig` and `pq_sig`) (`alg` and `pq_pk` are signed). Raises on a
    non-canonical body."""
    body = {k: v for k, v in artifact.items() if k != "sig" and k != "pq_sig"}
    return domain.encode("utf-8") + canonical_bytes_strict(body)


def verify_artifact_sig(domain: str, artifact: Any, pin: Any) -> bool:
    """Verify an artifact's signature under a PINNED signer (`{pk, pq_pk?}`, or a bare b64u Ed25519 key) through
    atlas_pca.pca's suite dispatch (`verify_leaf_suite`). Ed25519 under `pin.pk`; a PQ / hybrid suite only when the
    artifact's `pq_pk` equals `pin.pq_pk` (`_resolve_pq_key`; the artifact's own key never authorises it). The caller has
    checked `artifact_suite_error`. Total: False on any malformed input."""
    try:
        if not isinstance(artifact, dict):
            return False
        pk = pin if isinstance(pin, str) else _get(pin, "pk")
        pin_pq = _UNDEF if isinstance(pin, str) else _get(pin, "pq_pk")
        sig = _get(artifact, "sig")
        if not isinstance(sig, str) or not isinstance(pk, str):
            return False
        alg = _get(artifact, "alg")
        suite = "ed25519" if alg is _UNDEF else alg
        if not isinstance(suite, str) or not suite_available(suite):
            return False
        msg = artifact_message(domain, artifact)
        p = {"sig": sig} if suite == "ed25519" else {"alg": suite, "sig": sig}
        if suite != "ed25519":
            pins = {pk: pin_pq} if isinstance(pin_pq, str) else {}
            art_pq = _get(artifact, "pq_pk")
            pq = _resolve_pq_key(pk, None if art_pq is _UNDEF else art_pq, pq_pins=pins)
            if pq is None:
                return False
            p["pq_pk"] = pq.key
            pq_sig = _get(artifact, "pq_sig")
            if pq_sig is not _UNDEF:
                p["pq_sig"] = pq_sig
        return verify_leaf_suite(p, pk, msg)
    except Exception:  # noqa: BLE001 - total
        return False


def artifact_ref(ref_domain: str, slot: str, artifact: Any) -> str:
    """b64u(sha256(strictCanonical({d, [slot]: artifact}))) (signature included). Raises on a non-canonical artifact."""
    return hash_canonical({"d": ref_domain, slot: artifact})


def resolve_param_path(params: Any, path: Any) -> dict:
    """{"found": bool, "value"?: any}: own members of `params` along `action.params.<a>.<b>...`."""
    if not isinstance(path, str) or not path.startswith("action.params."):
        return {"found": False}
    cur = params
    for s in path[len("action.params."):].split("."):
        if not is_path_segment(s) or not isinstance(cur, dict) or s not in cur:
            return {"found": False}
        cur = cur[s]
    return {"found": True, "value": cur}


def is_param_path(path: Any) -> bool:
    """A well-formed `action.params.*` path of 1..8 segments."""
    if not isinstance(path, str) or not path.startswith("action.params."):
        return False
    segs = path[len("action.params."):].split(".")
    return 1 <= len(segs) <= 8 and all(is_path_segment(s) for s in segs)


def _set_nested(root: dict, path: str, value: Any) -> bool:
    segs = path.split(".")
    cur = root
    for k in segs[:-1]:
        if k not in cur:
            cur[k] = {}
        nxt = cur[k]
        if not isinstance(nxt, dict):
            return False
        cur = nxt
    last = segs[-1]
    if last in cur:
        return False
    cur[last] = value
    return True


def value_digest(value: Any) -> str:
    """b64u(sha256(strictCanonical(value))): a label field's `value_digest` and a verdict's `content_digest`."""
    return hash_canonical(value)


def classifier_content_digest(value: Any) -> str:
    """The content digest a classifier verdict binds."""
    return hash_canonical(value)


# ---- rule 16: oracle facts ---------------------------------------------------------------------------------------------

def validate_fact_wire(f: Any) -> Optional[str]:
    if not isinstance(f, dict):
        return "fact must be an object"
    m = _closed_members(f, ("v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"), SUITE_MEMBERS, "fact")
    if m:
        return m
    if not scalar_eq(f["v"], 1) or f["kind"] != "pca-fact" or not isinstance(f["kind"], str):
        return 'fact must be {v: 1, kind: "pca-fact"}'
    if not isinstance(f["name"], str) or INTENT_NAME_RE.fullmatch(f["name"]) is None:
        return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$"
    if not _is_bounded_string(f["subject"], 256):
        return "'fact.subject' must be a non-empty string (<= 256 bytes)"
    if not _is_safe_int(f["value"]) and not _is_bounded_string(f["value"], 256):
        return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)"
    if not _is_safe_int(f["t_obs"]) or f["t_obs"] < 0:
        return "'fact.t_obs' must be a non-negative safe integer"
    if not _is_bounded_string(f["oracle"], 64):
        return "'fact.oracle' must be a non-empty string (<= 64 bytes)"
    if not isinstance(f["sig"], str):
        return "'fact.sig' must be a string"
    return None


def fact_ref(f: Any) -> str:
    """The content address committed in `intent_session.facts[]`."""
    return artifact_ref(FACT_REF_DOMAIN, "f", f)


def lower_median(xs: List[Any]) -> Any:
    """Index floor((n-1)/2) of the ascending values."""
    if len(xs) == 0:
        raise ValueError("lowerMedian: empty")
    s = sorted(xs)
    return s[(len(s) - 1) // 2]


def ratio_ppm(a: Any, b: Any) -> Optional[int]:
    """floor(a * 10^6 / b) exactly, or None when b <= 0, a < 0 or the result is not a safe integer."""
    if not _is_safe_int(a) or not _is_safe_int(b) or not (b > 0) or a < 0:  # total: never a non-integer
        return None
    q = (_int(a) * 1_000_000) // _int(b)
    return q if q <= MAX_SAFE else None


# ---- rule 16 step 6: offer sets ----------------------------------------------------------------------------------------

_OFFER_SET_FIELDS = ("v", "kind", "site", "session", "query", "rank", "complete", "offers", "issued_at", "kid", "sig")


def validate_offer_set_wire(o: Any) -> Optional[str]:
    if not isinstance(o, dict):
        return "offer set must be an object"
    m = _closed_members(o, _OFFER_SET_FIELDS, SUITE_MEMBERS, "offer_set")
    if m:
        return m
    if not scalar_eq(o["v"], 1) or not isinstance(o["kind"], str) or o["kind"] != "pca-offer-set":
        return 'offer set must be {v: 1, kind: "pca-offer-set"}'
    if not _is_bounded_string(o["site"], 256):
        return "'offer_set.site' must be a non-empty string (<= 256 bytes)"
    if not _is_digest(o["session"]):
        return "'offer_set.session' must be canonical base64url (32 bytes)"
    q = o["query"]
    if not isinstance(q, dict) or len(q) > MAX_QUERY_KEYS:
        return "'offer_set.query' must be an object with <= %d keys" % MAX_QUERY_KEYS
    for k in _js_keys(q):
        if not _is_bounded_string(k, 64) or not _is_scalar(q[k]):
            return "'offer_set.query.%s' must be a scalar" % k
    if not isinstance(o["rank"], str) or o["rank"] != "price_asc":
        return "'offer_set.rank' must be \"price_asc\""
    if not isinstance(o["complete"], bool):
        return "'offer_set.complete' must be a boolean"
    offers = o["offers"]
    if not isinstance(offers, list) or len(offers) == 0 or len(offers) > MAX_OFFERS:
        return "'offer_set.offers' must hold 1..%d offers" % MAX_OFFERS
    ids = set()
    for i, of in enumerate(offers):
        if not isinstance(of, dict):
            return "offer %d must be an object" % i
        oid = _get(of, "offer_id")
        if not _is_bounded_string(oid, 128):
            return "offer %d: 'offer_id' must be a non-empty string (<= 128 bytes)" % i
        if oid in ids:
            return "offer %d: duplicate offer_id" % i
        ids.add(oid)
        price = _get(of, "price")
        if not _is_safe_int(price) or price < 0:
            return "offer %d: 'price' must be a non-negative safe integer" % i
        attrs = [k for k in _js_keys(of) if k != "offer_id" and k != "price"]
        if len(attrs) > MAX_OFFER_ATTRS:
            return "offer %d: more than %d attributes" % (i, MAX_OFFER_ATTRS)
        for k in attrs:
            if not _is_bounded_string(k, 64) or not _is_scalar(of[k]):
                return "offer %d: attribute '%s' must be a scalar" % (i, k)
    if not _is_safe_int(o["issued_at"]) or o["issued_at"] < 0:
        return "'offer_set.issued_at' must be a non-negative safe integer"
    if not _is_bounded_string(o["kid"], 64):
        return "'offer_set.kid' must be a non-empty string (<= 64 bytes)"
    if not isinstance(o["sig"], str):
        return "'offer_set.sig' must be a string"
    return None


def offer_set_ref(o: Any) -> str:
    """The content address committed in `intent_session.offer_set`."""
    return artifact_ref(OFFER_SET_REF_DOMAIN, "o", o)


def offer_matches(offer: dict, f: dict) -> bool:
    """Every key of the filter's offer part is an own member of the offer with a scalar-equal value."""
    if not isinstance(offer, dict) or not isinstance(f, dict):
        return False
    for k in _js_keys(f):
        if k not in offer or not scalar_eq(offer[k], f[k]):
            return False
    return True


def query_covers(query: dict, fq: dict) -> bool:
    """Coverage: keys(query) within keys(filter.query) with scalar-equal values (the search was not narrowed)."""
    if not isinstance(query, dict) or not isinstance(fq, dict):
        return False
    for k in _js_keys(query):
        if k not in fq or not scalar_eq(fq[k], query[k]):
            return False
    return True


def validate_offer_policy(p: Any) -> Optional[str]:
    if not isinstance(p, dict):
        return "offers policy must be an object"
    cm = _closed_members(p, ("name", "site_keys", "max_age_ms", "offer_param", "filter"), (), "offers")
    if cm:
        return cm
    if not isinstance(_get(p, "name"), str):
        return "offers policy needs a name"
    sk = _get(p, "site_keys")
    if not isinstance(sk, list) or len(sk) == 0:
        return "offers policy needs at least one pinned site key"
    kids = set()
    for k in sk:
        kid = _get(k, "kid")
        if (not isinstance(k, dict) or _closed_members(k, ("kid", "pk"), ("pq_pk",), "site_key") is not None
                or not _is_bounded_string(kid, 64) or not _is_digest(_get(k, "pk"))
                or not pin_pq_ok(_get(k, "pq_pk")) or kid in kids):
            return "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk"
        kids.add(kid)
    mx = _get(p, "max_age_ms")
    if not _is_safe_int(mx) or mx < 0:
        return "offers policy: max_age_ms must be a non-negative safe integer"
    op = _get(p, "offer_param")
    if not isinstance(op, str) or not op.startswith("action.params."):
        return "offers policy: offer_param must be an action.params.* path"
    f = _get(p, "filter")
    if (not isinstance(f, dict) or _closed_members(f, ("query", "offer"), (), "filter") is not None
            or not isinstance(_get(f, "query"), dict) or not isinstance(_get(f, "offer"), dict)):
        return "offers policy: filter must be exactly {query: {}, offer: {}}"
    for part in (f["query"], f["offer"]):
        for k in _js_keys(part):
            if not _is_scalar(part[k]):
                return "offers policy: filter values must be scalars"
    return None


def decide_offer_set(policy: Any, committed: Any, offer_set: Any, params: Any, aud: Any, session: Any, now: Any,
                     skew_ms: Any) -> dict:
    """Rule 16 step 6. {"ok": True, "excess", "chosen_price", "min_price"} or {"ok": False, "reason"}. `committed` /
    `offer_set` are _UNDEF when absent. A policy that fails validate_offer_policy is refused first. Never raises: an
    internal error is "offers: evaluation error (fail closed): ..."."""
    try:
        return _decide_offer_set(policy, committed, offer_set, params, aud, session, now, skew_ms)
    except Exception as e:  # noqa: BLE001 - total
        return {"ok": False, "reason": "offers: evaluation error (fail closed): %s" % e}


def _decide_offer_set(policy: Any, committed: Any, offer_set: Any, params: Any, aud: Any, session: Any, now: Any,
                      skew_ms: Any) -> dict:
    pe = validate_offer_policy(policy)
    if pe:
        return {"ok": False, "reason": "offers: policy misconfigured (fail closed): " + pe}
    if committed is _UNDEF:
        return {"ok": False, "reason": "offers: the PCActn commits no offer set but the policy requires one"}
    if offer_set is _UNDEF:
        return {"ok": False, "reason": "offers: the committed offer set was not supplied"}
    w = validate_offer_set_wire(offer_set)
    if w:
        return {"ok": False, "reason": "offers: " + w}
    os_ = offer_set
    try:
        ref = offer_set_ref(os_)
    except Exception:
        return {"ok": False, "reason": "offers: the offer set is not strictly canonical"}
    if ref != committed:
        return {"ok": False, "reason": "offers: the supplied offer set does not match the committed reference"}
    se = artifact_suite_error(os_)
    if se:
        return {"ok": False, "reason": "offers: signature suite: " + se}
    key = next((k for k in policy["site_keys"] if k["kid"] == os_["kid"]), None)
    if key is None:
        return {"ok": False, "reason": "offers: signing key '%s' is not pinned" % os_["kid"]}
    if not verify_artifact_sig(OFFER_SET_DOMAIN, os_, key):
        return {"ok": False, "reason": "offers: bad site signature"}
    if not (isinstance(aud, str) and os_["site"] == aud):
        return {"ok": False, "reason": "offers: the offer set was issued for another audience"}
    if not (isinstance(session, str) and os_["session"] == session):
        return {"ok": False, "reason": "offers: the offer set is bound to another session"}
    if not is_clock(now) or not _is_safe_int(skew_ms):
        return {"ok": False, "reason": "offers: no usable clock (now must be a safe integer): the offer set counts as stale"}
    # Exact integer arithmetic gives the same verdicts as the reference's binary64 sums of safe integers.
    if _int(os_["issued_at"]) > _int(now) + _int(skew_ms):
        return {"ok": False, "reason": "offers: the offer set is issued in the future"}
    if _int(now) - _int(os_["issued_at"]) > policy["max_age_ms"]:
        return {"ok": False, "reason": "offers: the offer set is stale"}
    if os_["complete"] is not True:
        return {"ok": False, "reason": "offers: the offer set is not declared complete"}
    if not query_covers(os_["query"], policy["filter"]["query"]):
        return {"ok": False, "reason": "offers: the search was narrowed beyond the intent filter (coverage)"}
    oid = resolve_param_path(params, policy["offer_param"])
    if not oid["found"] or not isinstance(oid["value"], str):
        return {"ok": False, "reason": "offers: the action names no offer id at the declared parameter"}
    chosen = next((x for x in os_["offers"] if x["offer_id"] == oid["value"]), None)
    if chosen is None:
        return {"ok": False, "reason": "offers: the chosen offer is not in the signed offer set"}
    fo = policy["filter"]["offer"]
    if not offer_matches(chosen, fo):
        return {"ok": False, "reason": "offers: the chosen offer does not satisfy the intent filter"}
    mn = _int(chosen["price"])
    for x in os_["offers"]:
        if offer_matches(x, fo) and x["price"] < mn:
            mn = _int(x["price"])
    cp = _int(chosen["price"])
    return {"ok": True, "excess": cp - mn, "chosen_price": cp, "min_price": mn}


# ---- rule 16: policy, activity, decision -------------------------------------------------------------------------------

def validate_world_policy(p: Any) -> Optional[str]:
    """Rule 16 step 0. None = well-formed."""
    if not isinstance(p, dict):
        return "world policy must be an object"
    # Closed member sets everywhere (README "closed and typed"): an unknown member is malformed.
    cm = _closed_members(p, (), ("skew_ms", "worlds", "relational", "offers"), "policy")
    if cm:
        return cm
    skew = _get(p, "skew_ms")
    if _present(skew) and (not _is_safe_int(skew) or skew < 0):
        return "skew_ms must be a non-negative safe integer"
    names = set()

    def claim(n: Any) -> Optional[str]:
        if not isinstance(n, str) or INTENT_NAME_RE.fullmatch(n) is None:
            return "dimension name '%s' must match ^[a-z][a-z0-9_]{0,63}$" % _js_str(n)
        if n in names:
            return "duplicate dimension name '%s'" % n
        names.add(n)
        return None

    worlds = _absent_or(_get(p, "worlds"), [])  # absent = []; null or any non-array is malformed
    if not isinstance(worlds, list) or len(worlds) > MAX_WORLDS:
        return "worlds must be a list of at most %d" % MAX_WORLDS
    for w in worlds:
        if not isinstance(w, dict):
            return "world entry must be an object"
        wm = _closed_members(w, ("name", "subject_path", "oracles", "freshness_ms", "min_oracles", "max_faulty"), (), "world")
        if wm:
            return wm
        e = claim(_get(w, "name"))
        if e:
            return e
        wn = w["name"]
        sp = _get(w, "subject_path")
        if not isinstance(sp, str) or not sp.startswith("action."):
            return "world '%s': subject_path must be rooted at action." % wn
        fr = _get(w, "freshness_ms")
        if not _is_safe_int(fr) or fr < 0:
            return "world '%s': freshness_ms must be a non-negative safe integer" % wn
        mf = _get(w, "max_faulty")
        if not _is_safe_int(mf) or mf < 0:
            return "world '%s': max_faulty must be a non-negative safe integer" % wn
        mo = _get(w, "min_oracles")
        if not _is_safe_int(mo) or mo < 2 * _int(mf) + 1:
            return "world '%s': min_oracles must be a safe integer >= 2*max_faulty+1" % wn
        ors = _get(w, "oracles")
        if not isinstance(ors, list) or len(ors) < mo:
            return "world '%s': fewer pinned oracles than min_oracles" % wn
        kids = set()
        for o in ors:
            kid = _get(o, "kid")
            if (not isinstance(o, dict) or _closed_members(o, ("kid", "pk"), ("pq_pk",), "oracle") is not None
                    or not _is_bounded_string(kid, 64) or not _is_digest(_get(o, "pk"))
                    or not pin_pq_ok(_get(o, "pq_pk")) or kid in kids):
                return "world '%s': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk" % wn
            kids.add(kid)
    rel = _absent_or(_get(p, "relational"), [])
    if not isinstance(rel, list) or len(rel) > MAX_RELATIONAL:
        return "relational must be a list of at most %d" % MAX_RELATIONAL
    for r in rel:
        if not isinstance(r, dict):
            return "relational entry must be an object"
        rm = _closed_members(r, ("name", "fn", "a", "b"), (), "relational")
        if rm:
            return rm
        e = claim(_get(r, "name"))
        if e:
            return e
        rn = r["name"]
        fn = _get(r, "fn")
        if fn != "sub" and fn != "ratio_ppm" or not isinstance(fn, str):
            return "relational '%s': fn must be \"sub\" or \"ratio_ppm\"" % rn
        for op in (_get(r, "a"), _get(r, "b")):
            ok = is_param_path(op) or (
                isinstance(op, str) and op.startswith("env.world.") and op[len("env.world."):] in names
                and op[len("env.world."):] != rn
            )
            if not ok:
                return ("relational '%s': operand '%s' must be an action.params path or an earlier env.world dimension"
                        % (rn, _js_str(op)))
    offers = _get(p, "offers")
    if _present(offers):
        e = validate_offer_policy(offers)
        if e is None:
            e = claim(offers["name"])
        if e:
            return e
    return None


def intent_world_active(input: Any) -> bool:
    """Rule 16 is reported iff `committed.facts` is a non-empty ARRAY, `committed.offer_set` is a STRING, `policy.worlds` or
    `policy.relational` is a non-empty ARRAY, or `policy.offers` is a plain object (strict typing: an object with its own
    `length` member is not an array). A non-object input has no members (False)."""
    if not isinstance(input, dict):
        return False
    c = _dflt(_get(input, "committed"), {})
    p = _dflt(_get(input, "policy"), {})
    return (_non_empty_array(_get(c, "facts")) or isinstance(_get(c, "offer_set"), str)
            or _non_empty_array(_get(p, "worlds")) or _non_empty_array(_get(p, "relational"))
            or isinstance(_get(p, "offers"), dict))


def _subject_of(action: dict, params: dict, path: str) -> Optional[str]:
    if path == "action.resource":
        r = _get(action, "resource")
        return r if isinstance(r, str) else None
    if path == "action.verb":
        v = _get(action, "verb")
        return v if isinstance(v, str) else None
    r = resolve_param_path(params, path)
    return r["value"] if r["found"] and isinstance(r["value"], str) else None


def decide_intent_world(input: Any) -> dict:
    """NORMATIVE rule 16 (`facts`): {"ok": True, "world", "single_source"} or {"ok": False, "reason"}. Never raises."""
    def fail(reason: str) -> dict:
        return {"ok": False, "reason": "facts: " + reason}

    try:
        if not isinstance(input, dict):
            return fail("input must be an object")
        # ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail closed.
        policy = _absent_or(_member(input, "policy"), {})
        pe = validate_world_policy(policy)
        if pe:
            return fail("policy misconfigured (fail closed): " + pe)
        skew = _absent_or(_get(policy, "skew_ms"), DEFAULT_WORLD_SKEW_MS)
        action = _get(input, "action")
        if not isinstance(action, dict):
            return fail("action must be an object")
        params = _absent_or(_get(action, "params"), {})
        if not isinstance(params, dict):
            return fail("action.params must be an object")
        committed = _absent_or(_get(input, "committed"), {})
        if not isinstance(committed, dict):
            return fail("committed must be an object")
        committed_facts = _absent_or(_get(committed, "facts"), [])
        if not isinstance(committed_facts, list) or len(committed_facts) > MAX_COMMITTED_FACTS:
            return fail("committed facts must be a list of at most %d digests" % MAX_COMMITTED_FACTS)
        seen = set()
        for d in committed_facts:
            if not _is_digest(d):
                return fail("a committed fact digest is not canonical base64url (32 bytes)")
            if d in seen:
                return fail("duplicate committed fact digest")
            seen.add(d)
        committed_offer = _get(committed, "offer_set")
        if _present(committed_offer) and not _is_digest(committed_offer):
            return fail("the committed offer_set is not canonical base64url (32 bytes)")

        supplied = _absent_or(_get(input, "facts"), [])
        if not isinstance(supplied, list):
            return fail("facts must be an array")
        offer_set_in = _get(input, "offer_set")
        if offer_set_in is not _UNDEF and not isinstance(offer_set_in, dict):
            return fail("offer_set must be an object")
        by_ref: Dict[str, dict] = {}
        for f in supplied:
            if validate_fact_wire(f) is not None:
                continue
            try:
                by_ref[fact_ref(f)] = f
            except Exception:
                pass  # not strictly canonical: no reference, never matches a commitment
        worlds = _absent_or(_get(policy, "worlds"), [])
        accepted: List[dict] = []
        pairs = set()
        for d in committed_facts:
            fact = by_ref.get(d)
            if fact is None:
                return fail("a committed fact was not supplied (or is malformed)")
            se = artifact_suite_error(fact)
            if se:
                return fail("fact signature suite: " + se)
            w = next((x for x in worlds if x["name"] == fact["name"]), None)
            if w is None:
                return fail("fact for undeclared world '%s'" % fact["name"])
            pin = next((o for o in w["oracles"] if o["kid"] == fact["oracle"]), None)
            if pin is None:
                return fail("oracle '%s' is not pinned for world '%s'" % (fact["oracle"], w["name"]))
            if not verify_artifact_sig(FACT_DOMAIN, fact, pin):
                return fail("bad oracle signature on a '%s' fact" % w["name"])
            subject = _subject_of(action, params, w["subject_path"])
            if subject is None or fact["subject"] != subject:
                return fail("a '%s' fact names another subject" % w["name"])
            pair = (w["name"], fact["oracle"])
            if pair in pairs:
                return fail("two facts from oracle '%s' for world '%s'" % (fact["oracle"], w["name"]))
            pairs.add(pair)
            accepted.append(fact)

        now = _get(input, "now")
        clock = is_clock(now)
        world: Dict[str, Any] = {}
        single_source: List[str] = []
        for w in worlds:
            # A non-integer `now` (a string, a float, null) is no clock: every fact is stale (never coerced).
            fresh = [f for f in accepted if f["name"] == w["name"] and _int(f["t_obs"]) <= _int(now) + _int(skew)
                     and _int(now) - _int(f["t_obs"]) <= w["freshness_ms"]] if clock else []
            if len(fresh) < w["min_oracles"]:
                return fail("world '%s' has %d fresh fact(s), needs %s" % (w["name"], len(fresh), _js_str(w["min_oracles"])))
            nums = [_int(f["value"]) for f in fresh if _is_num(f["value"])]
            if len(nums) == len(fresh):
                world[w["name"]] = lower_median(nums)
            elif len(nums) == 0:
                v = fresh[0]["value"]
                if any(f["value"] != v for f in fresh):
                    return fail("world '%s': string facts disagree" % w["name"])
                world[w["name"]] = v
            else:
                return fail("world '%s': facts mix integer and string values" % w["name"])
            if w["min_oracles"] == 1:
                single_source.append(w["name"])

        def operand(path: str) -> Optional[int]:
            if path.startswith("env.world."):
                v = world.get(path[len("env.world."):], _UNDEF)
                return _int(v) if _is_safe_int(v) else None
            r = resolve_param_path(params, path)
            return _int(r["value"]) if r["found"] and _is_safe_int(r["value"]) else None

        for r in _absent_or(_get(policy, "relational"), []):
            a = operand(r["a"])
            b = operand(r["b"])
            if a is None or b is None:
                return fail("relational '%s': an operand is missing or not a safe integer" % r["name"])
            v = a - b if r["fn"] == "sub" else ratio_ppm(a, b)
            if v is None or not _is_safe_int(v):
                return fail("relational '%s': result undefined or outside the safe integer range" % r["name"])
            world[r["name"]] = v

        offers = _get(policy, "offers")
        if _present(offers):
            od = decide_offer_set(
                policy=offers,
                committed=committed_offer,
                offer_set=offer_set_in,
                params=params,
                aud=_get(input, "aud"),
                session=_get(input, "session"),
                now=now,
                skew_ms=skew,
            )
            if not od["ok"]:
                return fail(od["reason"])
            world[offers["name"]] = od["excess"]
        return {"ok": True, "world": world, "single_source": single_source}
    except Exception as e:  # noqa: BLE001 - fail closed like the reference try/catch
        return fail("evaluation error (fail closed): %s" % e)


# ---- rule 17: label receipts and flow rules ----------------------------------------------------------------------------

def validate_labels_wire(l: Any) -> Optional[str]:
    if not isinstance(l, dict):
        return "label receipt must be an object"
    m = _closed_members(l, ("v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"),
                        SUITE_MEMBERS, "labels")
    if m:
        return m
    if not scalar_eq(l["v"], 1) or not isinstance(l["kind"], str) or l["kind"] != "pca-labels":
        return 'label receipt must be {v: 1, kind: "pca-labels"}'
    if not _is_bounded_string(l["site"], 256):
        return "'labels.site' must be a non-empty string (<= 256 bytes)"
    if not _is_digest(l["session"]):
        return "'labels.session' must be canonical base64url (32 bytes)"
    if not _is_digest(l["response_digest"]):
        return "'labels.response_digest' must be canonical base64url (32 bytes)"
    fields = l["fields"]
    if not isinstance(fields, dict):
        return "'labels.fields' must be an object"
    keys = _js_keys(fields)
    if len(keys) == 0 or len(keys) > MAX_LABEL_FIELDS:
        return "'labels.fields' must hold 1..%d fields" % MAX_LABEL_FIELDS
    for k in keys:
        f = fields[k]
        if not _is_bounded_string(k, 256):
            return "label field paths must be non-empty strings (<= 256 bytes)"
        if not isinstance(f, dict) or _closed_members(f, ("class", "value_digest")) is not None:
            return "label field '%s' must be exactly {class, value_digest}" % k
        c = f["class"]
        if not isinstance(c, str) or _utf16_len(c) > 128 or DATA_CLASS_RE.fullmatch(c) is None:
            return "label field '%s': invalid data class" % k
        if not _is_digest(f["value_digest"]):
            return "label field '%s': value_digest must be canonical base64url (32 bytes)" % k
    if not _is_safe_int(l["issued_at"]) or l["issued_at"] < 0:
        return "'labels.issued_at' must be a non-negative safe integer"
    if not _is_bounded_string(l["kid"], 64):
        return "'labels.kid' must be a non-empty string (<= 64 bytes)"
    if not isinstance(l["sig"], str):
        return "'labels.sig' must be a string"
    return None


def label_receipt_ref(l: Any) -> str:
    """The content address committed in `intent_session.labels[]` and named by `pca-labels:<ref>#<field>` refs."""
    return artifact_ref(LABELS_REF_DOMAIN, "l", l)


def verify_labels(l: Any, keys: Any) -> Optional[str]:
    """Wire shape and signature under the key pinned for (site, kid). None = valid. Total."""
    w = validate_labels_wire(l)
    if w:
        return w
    if not isinstance(keys, list):
        return "label keys must be an array"
    se = artifact_suite_error(l)
    if se:
        return "signature suite: " + se
    key = next((k for k in keys if isinstance(k, dict) and _get(k, "site") == l["site"] and _get(k, "kid") == l["kid"]), None)
    if key is None:
        return "no pinned label key for site '%s' kid '%s'" % (l["site"], l["kid"])
    return None if verify_artifact_sig(LABELS_DOMAIN, l, key) else "bad label receipt signature"


def _class_covered(patterns: list, cls: str) -> bool:
    return cls == PUBLIC_CLASS or any(
        p == "*" or p == cls or (p.endswith(".*") and cls.startswith(p[:-1])) for p in patterns)


def decide_read_purpose(input: Any) -> dict:
    """label-receipts.ts `decideReadPurpose` (README "READ PURPOSE", conformance `primitives.intent_read_purpose`). Input
    {fields: [{path, class, optional?}], purpose, coverage: {purpose: [pattern]}, on_uncovered?} -> {"outcome":
    "allow"|"question"|"deny", "minimise": [...], "uncovered": [...]}. Malformed input (JSON null anywhere included) is
    {"outcome": "deny", "minimise": [], "uncovered": []}. `coverage[purpose]` is an OWN member; an uncovered field with
    `optional: true` is minimised, any other uncovered field is uncovered; both lists de-duplicated and sorted in UTF-8
    byte order. `on_uncovered` absent = "question". Never raises."""
    malformed = {"outcome": "deny", "minimise": [], "uncovered": []}
    try:
        fields = _get(input, "fields")
        purpose = _get(input, "purpose")
        coverage = _get(input, "coverage")
        on_uncovered = _absent_or(_get(input, "on_uncovered"), "question")
        if (not isinstance(fields, list) or not isinstance(purpose, str) or not isinstance(coverage, dict)
                or not isinstance(on_uncovered, str) or on_uncovered not in ("question", "deny")):
            return malformed
        for pats in coverage.values():
            if not isinstance(pats, list) or any(not isinstance(x, str) for x in pats):
                return malformed
        for f in fields:
            opt = _get(f, "optional")
            if (not isinstance(f, dict) or not isinstance(_get(f, "path"), str) or not isinstance(_get(f, "class"), str)
                    or (opt is not _UNDEF and not isinstance(opt, bool))):
                return malformed
        patterns = coverage[purpose] if purpose in coverage else []
        minimise: List[str] = []
        uncovered: List[str] = []
        for f in fields:
            if _class_covered(patterns, f["class"]):
                continue
            target = minimise if f.get("optional") is True else uncovered
            if f["path"] not in target:
                target.append(f["path"])
        return {"outcome": on_uncovered if uncovered else "allow", "minimise": _sorted_utf8(minimise),
                "uncovered": _sorted_utf8(uncovered)}
    except Exception:  # noqa: BLE001 - total
        return malformed


def flow_rule_for(rules: dict, cls: str) -> Optional[str]:
    """Most specific matching flow pattern: exact > longest `prefix.*` > `*`, or None (also for non-object rules or a
    non-string class)."""
    if not isinstance(rules, dict) or not isinstance(cls, str):
        return None
    if cls in rules:
        return cls
    best = None
    for p in _js_keys(rules):
        if not p.endswith(".*"):
            continue
        prefix = p[:-1]  # keeps the dot: 'pii.' matches 'pii.contact', never 'piix'
        if cls.startswith(prefix) and (best is None or _utf16_len(p) > _utf16_len(best)):
            best = p
    if best is not None:
        return best
    return "*" if "*" in rules else None


def flow_allowed(rules: dict, cls: str, origin: Any, aud: Any) -> bool:
    """Back to its origin: yes; `public`: yes; otherwise the most specific rule must list `aud`. Non-string class, origin
    or audience: False."""
    if not isinstance(cls, str) or not isinstance(origin, str) or not isinstance(aud, str):
        return False
    if (isinstance(aud, str) and isinstance(origin, str) and aud == origin) or cls == PUBLIC_CLASS:
        return True
    p = flow_rule_for(rules, cls)
    if p is None:
        return False
    sinks = rules[p]
    return isinstance(sinks, list) and isinstance(aud, str) and any(isinstance(s, str) and s == aud for s in sinks)


def validate_flow_rules(rules: Any) -> Optional[str]:
    if not isinstance(rules, dict):
        return "flows must be an object"
    for p in _js_keys(rules):
        sinks = rules[p]
        base = "x" if p == "*" else (p[:-2] if p.endswith(".*") else p)
        if DATA_CLASS_RE.fullmatch(base) is None:
            return "flow pattern '%s' is not a class, a 'prefix.*' or '*'" % p
        if not isinstance(sinks, list) or any(not _is_bounded_string(s, 256) for s in sinks):
            return "flow pattern '%s' needs a list of audiences" % p
    return None


# ---- rule 17: provenance -----------------------------------------------------------------------------------------------

def is_taint_level(kind: Any) -> bool:
    return isinstance(kind, str) and kind in _RANK


def _rank(kind: Any) -> int:
    return _RANK[kind] if is_taint_level(kind) else _MAX_RANK


def is_prov_path(k: Any) -> bool:
    return (isinstance(k, str) and PROV_PATH_RE.fullmatch(k) is not None
            and k[len("action.params."):] not in _FORBIDDEN_SEGMENTS)


def is_label_key(k: Any) -> bool:
    """label-receipts.ts `isLabelKey`: {site (1..256 B), kid (1..64 B), pk (digest), pq_pk? (non-empty string)}."""
    return (isinstance(k, dict) and _closed_members(k, ("site", "kid", "pk"), ("pq_pk",), "label_key") is None
            and _is_bounded_string(_get(k, "site"), 256) and _is_bounded_string(_get(k, "kid"), 64)
            and _is_digest(_get(k, "pk")) and pin_pq_ok(_get(k, "pq_pk")))


def validate_provenance_policy(p: Any) -> Optional[str]:
    """Rule 17 step 0. None = well-formed."""
    if not isinstance(p, dict) or not isinstance(_get(p, "params"), dict):
        return "provenance policy needs a params map"
    cm = _closed_members(p, ("params",), ("registry", "label_keys", "critical_max", "material_tainted", "critical_tainted",
                                         "flows"), "policy")
    if cm:
        return cm
    params = p["params"]
    for k in _js_keys(params):
        if not is_param_path(k):
            return "policy param '%s' is not an action.params path" % k
        if params[k] != "material" and params[k] != "critical" or not isinstance(params[k], str):
            return "policy param '%s': sensitivity must be material or critical" % k
    reg = _get(p, "registry")
    if _present(reg):
        if not isinstance(reg, dict):
            return "registry must be an object"
        for k in _js_keys(reg):
            if not _is_bounded_string(k, 256) or not is_taint_level(reg[k]):
                return "registry entry '%s' must map to a taint level" % k
    lk = _get(p, "label_keys")
    if _present(lk):
        if not isinstance(lk, list):
            return "label_keys must be a list"
        for k in lk:
            if not is_label_key(k):
                return "every label key needs site, kid, a 32-byte pk and an optional string pq_pk"
    cm = _get(p, "critical_max")
    if _present(cm) and not is_taint_level(cm):
        return "critical_max must be a taint level"
    mt = _get(p, "material_tainted")
    if _present(mt) and not (isinstance(mt, str) and mt in _MODES):
        return "material_tainted must be allow | question | question_typed | deny"
    ct = _get(p, "critical_tainted")
    if _present(ct) and (ct == "allow" or not (isinstance(ct, str) and ct in _MODES)):
        return "critical_tainted must be question | question_typed | deny"
    fl = _get(p, "flows")
    if _present(fl):
        e = validate_flow_rules(fl)
        if e:
            return e
    return None


def validate_prov_wire(prov: Any) -> Optional[str]:
    """The `intent_session.prov` member. None = well-formed."""
    if not isinstance(prov, dict):
        return "'prov' must be an object"
    keys = _js_keys(prov)
    if len(keys) > MAX_PROV_PATHS:
        return "'prov' holds more than %d paths" % MAX_PROV_PATHS
    for k in keys:
        if not is_prov_path(k):
            return "'prov' key '%s' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)" % k
        refs = prov[k]
        if not isinstance(refs, list) or len(refs) == 0 or len(refs) > MAX_PROV_REFS:
            return "'prov.%s' must hold 1..%d refs" % (k, MAX_PROV_REFS)
        for r in refs:
            if not _is_bounded_string(r, 256):
                return "'prov.%s' refs must be non-empty strings (<= 256 bytes)" % k
    return None


def parse_label_ref(ref: str) -> Optional[dict]:
    """`pca-labels:<ref>#<field>` (split at the FIRST '#') -> {"receipt", "field"}; None when malformed."""
    if not isinstance(ref, str) or not ref.startswith(LABEL_REF_PREFIX):
        return None
    rest = ref[len(LABEL_REF_PREFIX):]
    i = rest.find("#")
    if i < 0:
        return None
    receipt, field = rest[:i], rest[i + 1:]
    return {"receipt": receipt, "field": field} if _is_digest(receipt) and len(field) > 0 else None


def _sorted_utf8(keys) -> list:
    """param-provenance.ts `sortUtf8` (hash.ts compareUtf8): UTF-8 byte order, never UTF-16 code-unit order."""
    return sorted(keys, key=_utf8_key)


def decide_param_provenance(input: Any) -> dict:
    """NORMATIVE rule 17 (`provenance`): {"outcome": "pass"|"question"|"deny", "reason"?, "friction"?, "labels",
    "classes", "env"}. Never raises."""
    labels: Dict[str, str] = {}
    classes: Dict[str, List[str]] = {}

    def deny(reason: str) -> dict:
        return {"outcome": "deny", "reason": "provenance: " + reason, "labels": labels, "classes": classes, "env": {}}

    try:
        if not isinstance(input, dict):
            return deny("input must be an object")
        policy = _member(input, "policy")
        pe = validate_provenance_policy(policy)
        if pe:
            return deny("policy misconfigured (fail closed): " + pe)
        # ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) deny.
        prov = _absent_or(_get(input, "prov"), {})
        we = validate_prov_wire(prov)
        if we:
            return deny(we)
        committed = _absent_or(_get(input, "committed_labels"), [])
        if not isinstance(committed, list) or len(committed) > MAX_COMMITTED_LABELS:
            return deny("committed labels must be a list of at most %d digests" % MAX_COMMITTED_LABELS)
        committed_set = set()
        for d in committed:
            if not _is_digest(d) or d in committed_set:
                return deny("committed labels must be distinct canonical 32-byte digests")
            committed_set.add(d)
        action = _get(input, "action")
        if not isinstance(action, dict):
            return deny("action must be an object")
        params = _absent_or(_get(action, "params"), {})
        if not isinstance(params, dict):
            return deny("action.params must be an object")
        supplied = _absent_or(_get(input, "labels"), [])
        if not isinstance(supplied, list):
            return deny("labels must be an array")
        label_keys = _absent_or(_get(policy, "label_keys"), [])
        reg = _absent_or(_get(policy, "registry"), {})
        flows = _absent_or(_get(policy, "flows"), {})
        paths = _sorted_utf8(prov.keys())
        for p in paths:
            if not resolve_param_path(params, p)["found"]:
                return deny("prov names '%s', a parameter the action does not carry" % p)
        for a in paths:
            for b in paths:
                if a != b and b.startswith(a + "."):
                    return deny("prov paths '%s' and '%s' overlap" % (a, b))

        receipts: Dict[str, dict] = {}
        for r in supplied:
            try:
                if validate_labels_wire(r) is None:
                    receipts[label_receipt_ref(r)] = r
            except Exception:
                pass  # not strictly canonical: no reference, never matches a commitment
        aud = _get(input, "aud")
        session = _get(input, "session")
        origins: Dict[str, List[tuple]] = {}

        for p in paths:
            value = resolve_param_path(params, p)["value"]
            ranks: List[int] = []
            for ref in prov[p]:
                if not ref.startswith(LABEL_REF_PREFIX):
                    lvl = reg[ref] if ref in reg and is_taint_level(reg[ref]) else "agent"
                    ranks.append(_RANK[lvl])
                    continue
                lr = parse_label_ref(ref)
                if lr is None:
                    return deny("malformed label ref on '%s'" % p)
                if lr["receipt"] not in committed_set:
                    return deny("label ref on '%s' names a receipt the PCActn does not commit" % p)
                rc = receipts.get(lr["receipt"])
                if rc is None:
                    return deny("label receipt for '%s' was not supplied" % p)
                ve = verify_labels(rc, label_keys)
                if ve:
                    return deny("label receipt for '%s': %s" % (p, ve))
                if not (isinstance(session, str) and rc["session"] == session):
                    return deny("label receipt for '%s' is bound to another session" % p)
                if lr["field"] not in rc["fields"]:
                    return deny("label receipt for '%s' has no field '%s'" % (p, lr["field"]))
                field = rc["fields"][lr["field"]]
                try:
                    match = hash_canonical(value) == field["value_digest"]
                except Exception:
                    match = False
                if match:
                    ranks.append(_RANK["first_party"] if isinstance(aud, str) and rc["site"] == aud else _RANK["tool"])
                else:
                    ranks.append(_RANK["agent"])
                origins.setdefault(p, []).append((field["class"], rc["site"]))
            labels[p] = TAINT_LEVELS[max(ranks)] if ranks else "agent"  # joinLabels([]) is TOP
        pol_params = policy["params"]
        for p in _sorted_utf8(pol_params.keys()):
            if p in labels:
                continue
            if resolve_param_path(params, p)["found"]:
                labels[p] = "agent"
        for p in _sorted_utf8(origins.keys()):
            seen: List[str] = []
            for cls, _o in origins[p]:
                if cls not in seen:
                    seen.append(cls)
            classes[p] = _sorted_utf8(seen)
            for cls, origin in origins[p]:
                if not flow_allowed(flows, cls, origin, aud):
                    return deny("flow: class '%s' from '%s' may not reach '%s' (parameter '%s')" % (cls, origin, _js_str(aud), p))
        critical_max = _get(policy, "critical_max")
        cap_rank = _rank(_absent_or(critical_max, "agent"))

        def sens(p: str) -> Any:
            return pol_params[p] if p in pol_params else _UNDEF

        for p in _sorted_utf8(labels.keys()):
            if sens(p) == "critical" and _RANK[labels[p]] > cap_rank:
                return deny("critical parameter '%s' has provenance '%s', above the policy maximum '%s'"
                            % (p, labels[p], _js_str(critical_max)))
        question = False
        typed = False
        for p in _sorted_utf8(labels.keys()):
            s = sens(p)
            if s is _UNDEF or _RANK[labels[p]] < _TAINTED_RANK:
                continue
            if s == "critical":
                mode = _absent_or(_get(policy, "critical_tainted"), "question_typed")
            else:
                mode = _absent_or(_get(policy, "material_tainted"), "question")
            if mode == "deny":
                return deny("tainted %s parameter '%s' (provenance '%s') is denied by policy" % (s, p, labels[p]))
            if mode == "question" or mode == "question_typed":
                question = True
            if mode == "question_typed":
                typed = True
        env: Dict[str, Any] = {}
        for p in _sorted_utf8(labels.keys()):
            if not _set_nested(env, p, labels[p]):
                return deny("provenance paths overlap at '%s'" % p)
        if question:
            return {"outcome": "question", "reason": "provenance: a tainted value needs the principal (lazy question)",
                    "friction": "typed" if typed else "tap", "labels": labels, "classes": classes, "env": env}
        return {"outcome": "pass", "labels": labels, "classes": classes, "env": env}
    except Exception as e:  # noqa: BLE001 - fail closed like the reference try/catch
        return deny("evaluation error (fail closed): %s" % e)


# ---- rule 18: classifier verdicts --------------------------------------------------------------------------------------

def validate_classifier_verdict_wire(v: Any) -> Optional[str]:
    if not isinstance(v, dict):
        return "verdict must be an object"
    m = _closed_members(v, ("v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"),
                        SUITE_MEMBERS, "verdict")
    if m:
        return m
    if not scalar_eq(v["v"], 1) or not isinstance(v["kind"], str) or v["kind"] != "pca-intent-classification":
        return 'verdict must be {v: 1, kind: "pca-intent-classification"}'
    if not isinstance(v["classifier"], str) or INTENT_NAME_RE.fullmatch(v["classifier"]) is None:
        return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$"
    if not _is_digest(v["session"]):
        return "'verdict.session' must be canonical base64url (32 bytes)"
    if not _is_digest(v["content_digest"]):
        return "'verdict.content_digest' must be canonical base64url (32 bytes)"
    if not _is_bounded_string(v["label"], 64):
        return "'verdict.label' must be a non-empty string (<= 64 bytes)"
    if not _is_bounded_string(v["measurement"], 256):
        return "'verdict.measurement' must be a non-empty string (<= 256 bytes)"
    if not _is_digest(v["judge"]):
        return "'verdict.judge' must be canonical base64url (32 bytes)"
    if not isinstance(v["sig"], str):
        return "'verdict.sig' must be a string"
    return None


def classifier_verdict_ref(v: Any) -> str:
    """The content address committed in `intent_session.classes[]`."""
    return artifact_ref(INTENT_CLASSIFIER_REF_DOMAIN, "c", v)


def validate_classifier_policy(p: Any) -> Optional[str]:
    """Rule 18 step 0. None = well-formed."""
    if not isinstance(p, dict) or not isinstance(_get(p, "classifiers"), list):
        return "classifier policy needs a classifiers list"
    cm = _closed_members(p, ("classifiers",), (), "policy")
    if cm:
        return cm
    ids = set()
    for c in p["classifiers"]:
        if (not isinstance(c, dict)
                or _closed_members(c, ("id", "param", "labels", "keys", "k"), ("measurements", "pq_keys"), "classifier") is not None):
            return "every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}"
        cid = _get(c, "id")
        if not isinstance(cid, str) or INTENT_NAME_RE.fullmatch(cid) is None or cid in ids:
            return "every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$"
        ids.add(cid)
        if not is_param_path(_get(c, "param")):
            return "classifier '%s': param must be an action.params path" % cid
        labs = _get(c, "labels")
        if not isinstance(labs, list) or len(labs) == 0 or len(labs) > MAX_CLASSIFIER_LABELS:
            return "classifier '%s': labels must hold 1..%d strings" % (cid, MAX_CLASSIFIER_LABELS)
        if any(not _is_bounded_string(l, 64) for l in labs) or len(set(labs)) != len(labs):
            return "classifier '%s': labels must be distinct non-empty strings" % cid
        keys = _get(c, "keys")
        if (not isinstance(keys, list) or len(keys) == 0 or any(not _is_digest(k) for k in keys)
                or len(set(keys)) != len(keys)):
            return "classifier '%s': keys must be distinct 32-byte keys" % cid
        k = _get(c, "k")
        if not _is_safe_int(k) or k < 1 or k > len(keys):
            return "classifier '%s': k must be an integer in [1, %d]" % (cid, len(keys))
        ms = _get(c, "measurements")
        if _present(ms) and (not isinstance(ms, list) or any(not isinstance(m, str) for m in ms)):
            return "classifier '%s': measurements must be a list of strings" % cid
        pqk = _get(c, "pq_keys")
        if _present(pqk) and (not isinstance(pqk, dict) or any(
                k not in keys or not isinstance(v, str) or len(v) == 0 for k, v in pqk.items())):
            return "classifier '%s': pq_keys must map allowlisted keys to PQ keys" % cid
    return None


def classifier_check_active(input: Any) -> bool:
    """Rule 18 is reported iff `committed` or `policy.classifiers` is a non-empty ARRAY (strict typing). A non-object input
    has no members (False)."""
    if not isinstance(input, dict):
        return False
    return _non_empty_array(_get(input, "committed")) or _non_empty_array(_get(_get(input, "policy"), "classifiers"))


def decide_classifier_dimensions(input: Any) -> dict:
    """NORMATIVE rule 18 (`classes`): {"ok": True, "classes", "votes"} or {"ok": False, "reason"}. Never raises."""
    def fail(reason: str) -> dict:
        return {"ok": False, "reason": "classes: " + reason}

    try:
        if not isinstance(input, dict):
            return fail("input must be an object")
        policy = _member(input, "policy")
        pe = validate_classifier_policy(policy)
        if pe:
            return fail("policy misconfigured (fail closed): " + pe)
        # ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail.
        committed = _absent_or(_get(input, "committed"), [])
        if not isinstance(committed, list) or len(committed) > MAX_COMMITTED_CLASSES:
            return fail("committed verdicts must be a list of at most %d digests" % MAX_COMMITTED_CLASSES)
        seen = set()
        for d in committed:
            if not _is_digest(d) or d in seen:
                return fail("committed verdicts must be distinct canonical 32-byte digests")
            seen.add(d)
        supplied = _absent_or(_get(input, "verdicts"), [])
        if not isinstance(supplied, list):
            return fail("verdicts must be an array")
        action = _get(input, "action")
        if not isinstance(action, dict):
            return fail("action must be an object")
        params = _absent_or(_get(action, "params"), {})
        if not isinstance(params, dict):
            return fail("action.params must be an object")
        by_ref: Dict[str, dict] = {}
        for v in supplied:
            if validate_classifier_verdict_wire(v) is not None:
                continue
            try:
                by_ref[classifier_verdict_ref(v)] = v
            except Exception:
                pass  # not strictly canonical: no reference
        session = _get(input, "session")
        classifiers = policy["classifiers"]
        votes: Dict[str, Dict[str, int]] = {}
        pairs = set()
        for d in committed:
            v = by_ref.get(d)
            if v is None:
                return fail("a committed verdict was not supplied (or is malformed)")
            se = artifact_suite_error(v)
            if se:
                return fail("verdict signature suite: " + se)
            c = next((x for x in classifiers if x["id"] == v["classifier"]), None)
            if c is None:
                return fail("verdict for undeclared classifier '%s'" % v["classifier"])
            cid = c["id"]
            if v["judge"] not in c["keys"]:
                return fail("classifier '%s': judge key is not on the allowlist" % cid)
            pq = _get(c["pq_keys"], v["judge"]) if "pq_keys" in c else _UNDEF
            judge_pin = {"pk": v["judge"]} if pq is _UNDEF else {"pk": v["judge"], "pq_pk": pq}
            if not verify_artifact_sig(INTENT_CLASSIFIER_DOMAIN, v, judge_pin):
                return fail("classifier '%s': bad verdict signature" % cid)
            if not (isinstance(session, str) and v["session"] == session):
                return fail("classifier '%s': verdict bound to another session" % cid)
            content = resolve_param_path(params, c["param"])
            if not content["found"]:
                return fail("classifier '%s': the action carries no '%s'" % (cid, c["param"]))
            if classifier_content_digest(content["value"]) != v["content_digest"]:
                return fail("classifier '%s': verdict is about other content" % cid)
            if v["label"] not in c["labels"]:
                return fail("classifier '%s': label '%s' is not in its label set" % (cid, v["label"]))
            if "measurements" in c and v["measurement"] not in c["measurements"]:
                return fail("classifier '%s': measurement is not pinned" % cid)
            pair = (cid, v["judge"])
            if pair in pairs:
                return fail("classifier '%s': two verdicts from one judge" % cid)
            pairs.add(pair)
            t = votes.setdefault(cid, {})
            t[v["label"]] = t.get(v["label"], 0) + 1
        out: Dict[str, str] = {}
        for c in classifiers:
            t = votes.get(c["id"], {})
            winners = [l for l in c["labels"] if t.get(l, 0) >= c["k"]]
            if len(winners) == 0:
                return fail("classifier '%s': no label reaches the quorum %s" % (c["id"], _js_str(c["k"])))
            if len(winners) > 1:
                return fail("classifier '%s': ambiguous, %d labels reach the quorum" % (c["id"], len(winners)))
            out[c["id"]] = winners[0]
        return {"ok": True, "classes": out, "votes": votes}
    except Exception as e:  # noqa: BLE001 - fail closed like the reference try/catch
        return fail("evaluation error (fail closed): %s" % e)


# ---- composition (intent-env.ts) ---------------------------------------------------------------------------------------

def _put(d: dict, k: str, v: Any) -> None:
    """Set `d[k] = v` unless `v` is undefined (an absent member stays absent)."""
    if v is not _UNDEF:
        d[k] = v


def validate_wb_context(wb: Any) -> Optional[str]:
    """The W-B part of the v2 verifier context check (intent-v2.ts `intentV2ContextError`), for a PRESENT `intent_v2.wb`
    member (call it only when the key exists; an absent `wb` is fine). ABSENT optional members mean empty / default; a
    member PRESENT with null or of the wrong JSON type is malformed and fails closed. None = well-formed."""
    def opt_obj(v: Any) -> bool:
        return v is _UNDEF or isinstance(v, dict)

    def opt_arr(v: Any) -> bool:
        return v is _UNDEF or isinstance(v, list)

    if wb is _UNDEF:
        return None
    if not isinstance(wb, dict):
        return "wb must be an object"
    a = _get(wb, "artifacts")
    if not opt_obj(a):
        return "wb.artifacts must be an object"
    if a is not _UNDEF:
        for k in ("facts", "labels", "verdicts"):
            if not opt_arr(_get(a, k)):
                return "wb.artifacts.%s must be an array" % k
        if not opt_obj(_get(a, "offer_set")):
            return "wb.artifacts.offer_set must be an object"
    p = _get(wb, "policy")
    if not opt_obj(p):
        return "wb.policy must be an object"
    if p is not _UNDEF:
        if not opt_obj(_get(p, "world")) or not opt_obj(_get(p, "provenance")):
            return "wb.policy.world / provenance must be objects"
        if not opt_arr(_get(p, "classifiers")):
            return "wb.policy.classifiers must be an array"
    return None


def intent_provenance_active(x: Any) -> bool:
    """Rule 17 is reported iff `prov` is present (any value, null included: rule 17 then judges it), `labels` is a non-empty
    ARRAY, or `policy` is a plain object. A non-object input has no members (False)."""
    if not isinstance(x, dict):
        return False
    return _present(_get(x, "prov")) or _non_empty_array(_get(x, "labels")) or isinstance(_get(x, "policy"), dict)


def intent_wb_active(input: Any) -> dict:
    """Which W-B checks a verifier reports (conformance `primitives.intent_wb_active`): input {intent_session, policy:
    {world?, provenance?, classifiers?}} -> {"facts", "provenance", "classes"} booleans. Never raises."""
    s = _get(input, "intent_session")  # `mem`: a container that is absent or not a plain object has no members
    p = _get(input, "policy")
    committed: Dict[str, Any] = {}
    _put(committed, "facts", _get(s, "facts"))
    _put(committed, "offer_set", _get(s, "offer_set"))
    prov: Dict[str, Any] = {}
    _put(prov, "prov", _get(s, "prov"))
    _put(prov, "labels", _get(s, "labels"))
    _put(prov, "policy", _get(p, "provenance"))
    cls: Dict[str, Any] = {"policy": {"classifiers": _get(p, "classifiers")}}
    _put(cls, "committed", _get(s, "classes"))
    return {
        "facts": intent_world_active({"committed": committed, "policy": _get(p, "world")}),
        "provenance": intent_provenance_active(prov),
        "classes": classifier_check_active(cls),
    }


def intent_wb_context_error(input: Any) -> Optional[str]:
    """intent-env.ts `intentWBContextError`, the shape rule for the W-B context (absent vs null): `intent_session` a plain
    object; `artifacts` absent or a plain object whose `facts` / `labels` / `verdicts` are absent or arrays and whose
    `offer_set` is absent or a plain object; `policy` absent or a plain object whose `world` / `provenance` are absent or
    plain objects and whose `classifiers` is absent or an array. JSON null anywhere here is malformed, and both objects are
    CLOSED (an unknown member is malformed). A non-object input is malformed. None = well-formed."""
    if not isinstance(input, dict):
        return "input must be an object"
    if not isinstance(_get(input, "intent_session"), dict):
        return "intent_session must be an object"
    a = _get(input, "artifacts")
    if a is not _UNDEF:
        if not isinstance(a, dict):
            return "artifacts must be an object"
        am = _closed_members(a, (), ("facts", "labels", "verdicts", "offer_set"), "artifacts")
        if am:
            return am
        for k in ("facts", "labels", "verdicts"):
            if _get(a, k) is not _UNDEF and not isinstance(a[k], list):
                return "artifacts.%s must be an array" % k
        if _get(a, "offer_set") is not _UNDEF and not isinstance(a["offer_set"], dict):
            return "artifacts.offer_set must be an object"
    p = _get(input, "policy")
    if p is not _UNDEF:
        if not isinstance(p, dict):
            return "policy must be an object"
        pm = _closed_members(p, (), ("world", "provenance", "classifiers"), "policy")
        if pm:
            return pm
        for k in ("world", "provenance"):
            if _get(p, k) is not _UNDEF and not isinstance(p[k], dict):
                return "policy.%s must be an object" % k
        if _get(p, "classifiers") is not _UNDEF and not isinstance(p["classifiers"], list):
            return "policy.classifiers must be an array"
    return None


def decide_intent_wb(input: Any) -> dict:
    """Rules 16, 17 and 18 in order (spec §5): {"outcome": "admit"|"question"|"deny", "checks": {"facts"?, "provenance"?,
    "classes"?}, "env": {"world"?, "prov"?, "class"?}, "reason"?, "friction"?, "single_source"?}. Each check is reported
    only when active; the first failing check denies and later checks are not reported. A malformed W-B context
    (`intent_wb_context_error`) fails `facts`, the first check of the unit. Never raises."""
    out: Dict[str, Any] = {"outcome": "admit", "checks": {}, "env": {}}
    try:
        ce = intent_wb_context_error(input)
        if ce:
            return dict(out, outcome="deny", checks={"facts": "fail"}, reason="facts: the W-B context is malformed: " + ce)
        s = input["intent_session"]
        a = _absent_or(_get(input, "artifacts"), {})
        pol = _absent_or(_get(input, "policy"), {})
        world_policy = _absent_or(_get(pol, "world"), {})
        committed: Dict[str, Any] = {}
        _put(committed, "facts", _get(s, "facts"))
        _put(committed, "offer_set", _get(s, "offer_set"))
        if intent_world_active({"committed": committed, "policy": world_policy}):
            wi: Dict[str, Any] = {}
            _put(wi, "now", _get(input, "now"))
            _put(wi, "aud", _get(input, "aud"))
            _put(wi, "session", _get(input, "session"))
            _put(wi, "action", _get(input, "action"))
            wi["committed"] = committed
            _put(wi, "facts", _get(a, "facts"))
            _put(wi, "offer_set", _get(a, "offer_set"))
            wi["policy"] = world_policy
            w = decide_intent_world(wi)
            if not w["ok"]:
                return dict(out, outcome="deny", checks={"facts": "fail"}, reason=w["reason"])
            out["checks"]["facts"] = "pass"
            out["env"]["world"] = w["world"]
            if len(w["single_source"]):
                out["single_source"] = w["single_source"]
        s_prov = _get(s, "prov")
        s_labels = _get(s, "labels")
        pol_prov = _get(pol, "provenance")
        prov_act: Dict[str, Any] = {}
        _put(prov_act, "prov", s_prov)
        _put(prov_act, "labels", s_labels)
        _put(prov_act, "policy", pol_prov)
        if intent_provenance_active(prov_act):
            pi: Dict[str, Any] = {}
            _put(pi, "aud", _get(input, "aud"))
            _put(pi, "session", _get(input, "session"))
            _put(pi, "action", _get(input, "action"))
            _put(pi, "prov", s_prov)
            _put(pi, "committed_labels", s_labels)
            _put(pi, "labels", _get(a, "labels"))
            pi["policy"] = _absent_or(pol_prov, {"params": {}})
            p = decide_param_provenance(pi)
            if p["outcome"] == "deny":
                return dict(out, outcome="deny", checks=dict(out["checks"], provenance="fail"), reason=p["reason"])
            out["checks"]["provenance"] = "question" if p["outcome"] == "question" else "pass"
            out["env"]["prov"] = p["env"]
            if p["outcome"] == "question":
                out["outcome"] = "question"
                out["reason"] = p["reason"]
                out["friction"] = p["friction"]
        cls_policy = {"classifiers": _absent_or(_get(pol, "classifiers"), [])}
        s_classes = _get(s, "classes")
        ci_active: Dict[str, Any] = {"policy": cls_policy}
        _put(ci_active, "committed", s_classes)
        if classifier_check_active(ci_active):
            ci: Dict[str, Any] = {}
            _put(ci, "session", _get(input, "session"))
            _put(ci, "action", _get(input, "action"))
            _put(ci, "committed", s_classes)
            _put(ci, "verdicts", _get(a, "verdicts"))
            ci["policy"] = cls_policy
            c = decide_classifier_dimensions(ci)
            if not c["ok"]:
                return dict(out, outcome="deny", checks=dict(out["checks"], classes="fail"), reason=c["reason"])
            out["checks"]["classes"] = "pass"
            out["env"]["class"] = c["classes"]
        return out
    except Exception as e:  # noqa: BLE001 - total
        # 45a1599e: the reference never throws either; any internal error is a `facts` failure (fail closed).
        return {"outcome": "deny", "checks": {"facts": "fail"}, "env": {}, "reason": "facts: evaluation error (fail closed): %s" % e}
