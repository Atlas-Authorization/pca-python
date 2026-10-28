"""Caveat language v2 (track K1): a port of packages/pca/src/caveat-lang.ts (security contracts C-220 to C-229).

Six verifier-side features, every one of them a RESTRICTION (conjunctive with the rest of the chain; a verifier that does not
know a caveat type refuses the chain): ``needs_discharge`` (third-party caveat satisfied by a discharge signed under a key the
VERIFIER pinned), ``sealed``, the ``narrow`` block (holder-signed self-attenuation beside the PCActn), ``max_uses`` (n atomic
first-use slots in the replay store), ``derive`` (bounded Kleene three-valued derived facts) and ``spiffe_bound``.

Total: a malformed caveat, discharge, narrow block or context is a refusal, never an exception and never an allow.
"""
import re
from typing import Any, Dict, List, Optional

from .intent_wb import (
    _closed_members, _is_bounded_string, _is_digest, _is_safe_int, _is_scalar, _utf8_len, artifact_suite_error, is_path_segment,
    resolve_param_path, scalar_eq, verify_artifact_sig,
)
from .pca import (
    b64u, cap_hash, decode_b64u_strict, evaluate_caveats, hash_canonical, holder_pq_commitment, policy_caveats, sha256,
)

__all__ = [
    "K1_CAVEAT_TYPES", "DISCHARGE_DOMAIN", "NARROW_DOMAIN", "MAX_USES_DOMAIN", "is_k1_caveat", "spiffe_id_error", "bound_caveats",
    "needs_discharge_error", "max_uses_error", "derive_error", "spiffe_bound_error", "discharge_shape_error", "verify_discharge",
    "discharge_digest", "discharge_action_digest", "narrow_shape_error", "verify_narrow", "max_uses_slot_key", "reserve_max_uses",
    "evaluate_derive", "evaluate_k1", "evaluate_caveats_k1",
]

CAVEAT_NEEDS_DISCHARGE = "needs_discharge"
CAVEAT_SEALED = "sealed"
CAVEAT_MAX_USES = "max_uses"
CAVEAT_DERIVE = "derive"
CAVEAT_SPIFFE_BOUND = "spiffe_bound"
K1_CAVEAT_TYPES = (CAVEAT_NEEDS_DISCHARGE, CAVEAT_SEALED, CAVEAT_MAX_USES, CAVEAT_DERIVE, CAVEAT_SPIFFE_BOUND)

DISCHARGE_DOMAIN = "atlas-pca/discharge/v1\0"
DISCHARGE_REF_DOMAIN = "atlas-pca/discharge-ref/v1"
DISCHARGE_ACTION_DOMAIN = "atlas-pca/discharge-action/v1"
NARROW_DOMAIN = "atlas-pca/narrow/v1\0"
MAX_USES_DOMAIN = "atlas-pca/max-uses/v1\0"
K1_MAX_LIFETIME_MS = 86_400_000
MAX_USES_LIMIT = 256
NARROW_MAX_CAVEATS = 16
DERIVE_MAX_DEFS = 8
DERIVE_MAX_NODES = 32
DERIVE_MAX_DEPTH = 4
DERIVE_MAX_WINDOW_MS = 30 * 86_400_000
DERIVE_MAX_HISTORY = 10_000
SPIFFE_MAX_ID_BYTES = 2048

# fullmatch everywhere: no `$` (which would tolerate a trailing newline)
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_TD_RE = re.compile(r"[a-z0-9._-]+")
_SEG_RE = re.compile(r"[A-Za-z0-9._-]+")
_ISSUER_CLASSES = ("human", "org", "workload", "model", "artifact")
_OPS = ("eq", "neq", "gte", "lte", "in")
_CMP_OPS = ("eq", "neq", "lt", "lte", "gt", "gte")
_NARROW_FORBIDDEN = ("envelope", CAVEAT_SEALED, "budget_alloc", "intent_session")


def _str256(v: Any) -> bool:
    return _is_bounded_string(v, 256)


def _scalar_claim(v: Any) -> bool:
    return _is_scalar(v) and (not isinstance(v, str) or _str256(v))


def _is_id(v: Any) -> bool:
    return isinstance(v, str) and _ID_RE.fullmatch(v) is not None


def _is_name(v: Any) -> bool:
    return isinstance(v, str) and _NAME_RE.fullmatch(v) is not None


def is_k1_caveat(c: Any) -> bool:
    return isinstance(c, dict) and isinstance(c.get("type"), str) and c["type"] in K1_CAVEAT_TYPES


# ---- SPIFFE ID ---------------------------------------------------------------------------------------------------------

def spiffe_id_error(s: Any) -> Optional[str]:
    if not isinstance(s, str) or len(s) == 0:
        return "SPIFFE ID must be a non-empty string"
    if _utf8_len(s) > SPIFFE_MAX_ID_BYTES:
        return "SPIFFE ID is too long"
    if not s.startswith("spiffe://"):
        return "SPIFFE ID must begin with spiffe://"
    rest = s[9:]
    slash = rest.find("/")
    td = rest if slash == -1 else rest[:slash]
    path = "" if slash == -1 else rest[slash:]
    if len(td) == 0 or len(td) > 255 or _TD_RE.fullmatch(td) is None:
        return "invalid trust domain"
    if path == "":
        return None
    if path.endswith("/"):
        return "path must not end with a slash"
    for seg in path.split("/")[1:]:
        if seg in ("", ".", "..") or _SEG_RE.fullmatch(seg) is None:
            return "invalid path segment"
    return None


# ---- which hop introduced a caveat -------------------------------------------------------------------------------------

def _hops_of(grant: Any, chain: Any) -> list:
    return chain if isinstance(chain, list) and len(chain) > 0 else [grant]


def bound_caveats(grant: Any, chain: Any = None) -> Optional[List[Dict[str, Any]]]:
    """Every caveat of the leaf hop as ``{"caveat", "hop", "cap_hash"}`` (the first hop whose list is longer than the caveat's
    position introduced it; cap_hash is the capability content hash of that hop). None for a malformed chain."""
    try:
        hops = _hops_of(grant, chain)
        leaf = hops[-1]
        if not isinstance(leaf, dict) or not isinstance(leaf.get("caveats"), list):
            return None
        out = []
        hashes: Dict[int, str] = {}
        for p, caveat in enumerate(leaf["caveats"]):
            h = next((i for i, x in enumerate(hops) if isinstance(x, dict) and isinstance(x.get("caveats"), list) and len(x["caveats"]) > p), -1)
            if h < 0:
                h = len(hops) - 1
            if h not in hashes:
                hashes[h] = cap_hash(hops[h])
            out.append({"caveat": caveat, "hop": h, "cap_hash": hashes[h]})
        return out
    except Exception:  # noqa: BLE001 - total
        return None


# ---- needs_discharge ---------------------------------------------------------------------------------------------------

def _require_error(r: Any) -> Optional[str]:
    if not isinstance(r, dict):
        return "requirement must be an object"
    e = _closed_members(r, ("claim", "op", "value"), (), "require")
    if e:
        return e
    if not _is_name(r["claim"]):
        return "claim name is malformed"
    op = r["op"]
    if not (isinstance(op, str) and op in _OPS):
        return "op must be eq, neq, gte, lte or in"
    v = r["value"]
    if op == "in":
        if not isinstance(v, list) or len(v) == 0 or len(v) > 16 or not all(_scalar_claim(x) for x in v):
            return "'in' needs 1..16 scalar values"
    elif op in ("gte", "lte"):
        if not _is_safe_int(v):
            return "'%s' needs a safe integer" % op
    elif not _scalar_claim(v):
        return "value must be a scalar"
    return None


def needs_discharge_error(c: Any) -> Optional[str]:
    if not isinstance(c, dict):
        return "caveat must be an object"
    e = _closed_members(c, ("type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require"), ("issuer_spiffe",), "needs_discharge")
    if e:
        return e
    if c["type"] != CAVEAT_NEEDS_DISCHARGE:
        return "not a needs_discharge caveat"
    if not _is_id(c["id"]):
        return "id is malformed"
    if not _is_id(c["issuer"]):
        return "issuer label is malformed"
    if not (isinstance(c["issuer_class"], str) and c["issuer_class"] in _ISSUER_CLASSES):
        return "issuer_class must be human, org, workload, model or artifact"
    if not (isinstance(c["bind"], str) and c["bind"] in ("chain_hop", "action")):
        return "bind must be 'chain_hop' or 'action'"
    ttl = c["ttl_ms"]
    if not (_is_safe_int(ttl) and 1 <= ttl <= K1_MAX_LIFETIME_MS):
        return "ttl_ms must be 1..86400000"
    if not isinstance(c["require"], list) or len(c["require"]) > 16:
        return "require must be an array of at most 16 requirements"
    for r in c["require"]:
        re_ = _require_error(r)
        if re_:
            return re_
    if "issuer_spiffe" in c:
        se = spiffe_id_error(c["issuer_spiffe"])
        if se:
            return "issuer_spiffe: " + se
    return None


def discharge_action_digest(pcactn: Any) -> str:
    return hash_canonical({"d": DISCHARGE_ACTION_DOMAIN, "pcactn": pcactn})


def discharge_digest(d: Any) -> str:
    return hash_canonical({"d": DISCHARGE_REF_DOMAIN, "discharge": d})


_D_REQUIRED = ("v", "kind", "caveat_id", "issuer", "cap_hash", "bind", "claims", "iat", "not_after", "nonce", "sig")
_D_OPTIONAL = ("action_digest", "alg", "pq_pk", "pq_sig")


def _window_error(a: dict, what: str) -> Optional[str]:
    iat, na = a["iat"], a["not_after"]
    if not (_is_safe_int(iat) and iat >= 0) or not (_is_safe_int(na) and na >= 0):
        return "iat and not_after must be non-negative safe integers"
    if not na > iat:
        return "not_after must be greater than iat"
    if na - iat > K1_MAX_LIFETIME_MS:
        return "%s lives at most %d ms" % (what, K1_MAX_LIFETIME_MS)
    nb = decode_b64u_strict(a["nonce"]) if isinstance(a["nonce"], str) else None
    if nb is None or len(nb) < 16:
        return "nonce must be canonical base64url of at least 16 bytes"
    if not isinstance(a["sig"], str):
        return "sig must be a string"
    return None


def discharge_shape_error(a: Any) -> Optional[str]:
    if not isinstance(a, dict):
        return "not an object"
    e = _closed_members(a, _D_REQUIRED, _D_OPTIONAL, "discharge")
    if e:
        return e
    if not (a["v"] == 1 and not isinstance(a["v"], bool)) or a["kind"] != "pca-discharge":
        return "not a pca-discharge v1"
    if not _is_id(a["caveat_id"]):
        return "caveat_id is malformed"
    if not _is_id(a["issuer"]):
        return "issuer label is malformed"
    if not _is_digest(a["cap_hash"]):
        return "cap_hash must be canonical base64url (32 bytes)"
    if not (isinstance(a["bind"], str) and a["bind"] in ("chain_hop", "action")):
        return "bind must be 'chain_hop' or 'action'"
    if (not _is_digest(a.get("action_digest"))) if a["bind"] == "action" else ("action_digest" in a):
        return "action_digest is required for bind action and forbidden for chain_hop"
    cl = a["claims"]
    if not isinstance(cl, dict) or len(cl) > 16:
        return "claims must be an object of at most 16 members"
    for k, v in cl.items():
        if not _is_name(k) or not _scalar_claim(v):
            return "claim '%s' is malformed" % k
    w = _window_error(a, "a discharge")
    if w:
        return w
    return artifact_suite_error(a)


def _claim_holds(r: dict, claims: dict) -> bool:
    if r["claim"] not in claims:
        return False
    v = claims[r["claim"]]
    op, rv = r["op"], r["value"]
    if op == "eq":
        return scalar_eq(v, rv)
    if op == "neq":
        return not scalar_eq(v, rv)
    if op == "gte":
        return _is_safe_int(v) and v >= rv
    if op == "lte":
        return _is_safe_int(v) and v <= rv
    return any(scalar_eq(v, x) for x in rv)  # in


def verify_discharge(discharge: Any, caveat: Any, binding: Any) -> Dict[str, Any]:
    """``{"ok": True, "digest", "claims"}`` or ``{"ok": False, "reason"}``. ``binding`` = ``{cap_hash, action_digest?, pins, now,
    revoked?}``. Total."""
    def no(r: str) -> Dict[str, Any]:
        return {"ok": False, "reason": r}

    try:
        b = binding if isinstance(binding, dict) else {}
        now = b.get("now")
        if not _is_safe_int(now):
            return no("the verifier clock is not a safe integer (fail closed)")
        ce = needs_discharge_error(caveat)
        if ce:
            return no("malformed needs_discharge caveat: " + ce)
        c = caveat
        de = discharge_shape_error(discharge)
        if de:
            return no("malformed discharge: " + de)
        d = discharge
        if d["caveat_id"] != c["id"]:
            return no("the discharge is for another caveat")
        if d["issuer"] != c["issuer"]:
            return no("the discharge names another issuer")
        pins_in = b.get("pins")
        if not isinstance(pins_in, (list, tuple)):
            return no("no issuer is pinned")
        pins = [p for p in pins_in if isinstance(p, dict) and p.get("label") == c["issuer"]]
        if len(pins) == 0:
            return no("the issuer is not pinned by this verifier")
        if len(pins) > 1:
            return no("the issuer label is pinned more than once (ambiguous)")
        pin = pins[0]
        if pin.get("class") != c["issuer_class"]:
            return no("the pinned issuer is not of the class the caveat requires")
        if "issuer_spiffe" in c and pin.get("spiffe_id") != c["issuer_spiffe"]:
            return no("the pinned issuer does not carry the SPIFFE ID the caveat requires")
        sp = {k: pin[k] for k in ("pk", "pq_pk") if k in pin}
        if not verify_artifact_sig(DISCHARGE_DOMAIN, d, sp):
            return no("discharge signature invalid")
        if d["bind"] != c["bind"]:
            return no("the discharge binds differently than the caveat requires")
        if d["cap_hash"] != b.get("cap_hash"):
            return no("the discharge is bound to another hop")
        if c["bind"] == "action" and d.get("action_digest") != b.get("action_digest"):
            return no("the discharge is bound to another action")
        if now < d["iat"]:
            return no("the discharge is from the future")
        if now > d["not_after"]:
            return no("the discharge has expired")
        if d["not_after"] - d["iat"] > c["ttl_ms"]:
            return no("the discharge lives longer than the caveat allows")
        digest = discharge_digest(d)
        rev = b.get("revoked")
        if isinstance(rev, (list, tuple)) and digest in rev:
            return no("the discharge is revoked")
        for r in c["require"]:
            if not _claim_holds(r, d["claims"]):
                return no("claim '%s' does not satisfy the caveat" % r["claim"])
        return {"ok": True, "digest": digest, "claims": d["claims"]}
    except Exception as err:  # noqa: BLE001 - total
        return no("discharge error (fail closed): %s" % type(err).__name__)


# ---- narrow ------------------------------------------------------------------------------------------------------------

_N_REQUIRED = ("v", "kind", "cap_hash", "holder", "caveats", "iat", "not_after", "nonce", "sig")
_N_OPTIONAL = ("action_digest", "alg", "pq_pk", "pq_sig")


def narrow_shape_error(a: Any) -> Optional[str]:
    if not isinstance(a, dict):
        return "not an object"
    e = _closed_members(a, _N_REQUIRED, _N_OPTIONAL, "narrow")
    if e:
        return e
    if not (a["v"] == 1 and not isinstance(a["v"], bool)) or a["kind"] != "pca-narrow":
        return "not a pca-narrow v1"
    if not _is_digest(a["cap_hash"]):
        return "cap_hash must be canonical base64url (32 bytes)"
    if not _is_bounded_string(a["holder"], 64) or decode_b64u_strict(a["holder"], 32) is None:
        return "holder must be canonical base64url (32 bytes)"
    cs = a["caveats"]
    if not isinstance(cs, list) or len(cs) < 1 or len(cs) > NARROW_MAX_CAVEATS:
        return "caveats must be 1..%d caveats" % NARROW_MAX_CAVEATS
    for c in cs:
        if not isinstance(c, dict) or not isinstance(c.get("type"), str):
            return "every caveat must be an object with a string type"
        if c["type"] in _NARROW_FORBIDDEN:
            return "a narrow block cannot carry a '%s' caveat" % c["type"]
    if "action_digest" in a and not _is_digest(a["action_digest"]):
        return "action_digest must be canonical base64url (32 bytes)"
    w = _window_error(a, "a narrow block")
    if w:
        return w
    return artifact_suite_error(a)


def verify_narrow(narrow: Any, grant: Any, chain: Any, bind: Any) -> Dict[str, Any]:
    """``{"ok": True, "caveats"}`` or ``{"ok": False, "reason"}``; ``bind`` = ``{now, action_digest?}``. Total."""
    def no(r: str) -> Dict[str, Any]:
        return {"ok": False, "reason": r}

    try:
        bd = bind if isinstance(bind, dict) else {}
        now = bd.get("now")
        if not _is_safe_int(now):
            return no("the verifier clock is not a safe integer (fail closed)")
        e = narrow_shape_error(narrow)
        if e:
            return no("malformed narrow block: " + e)
        n = narrow
        leaf = _hops_of(grant, chain)[-1]
        if n["holder"] != leaf.get("holder"):
            return no("the narrow block is not signed by the leaf holder")
        if n["cap_hash"] != cap_hash(leaf):
            return no("the narrow block is bound to another hop")
        sp = {"pk": n["holder"]}
        if "pq_pk" in n and "holder_pq" in leaf and holder_pq_commitment(n["pq_pk"]) == leaf["holder_pq"]:
            sp["pq_pk"] = n["pq_pk"]
        if not verify_artifact_sig(NARROW_DOMAIN, n, sp):
            return no("narrow signature invalid")
        if "action_digest" in n and n["action_digest"] != bd.get("action_digest"):
            return no("the narrow block is bound to another action")
        if now < n["iat"]:
            return no("the narrow block is from the future")
        if now > n["not_after"]:
            return no("the narrow block has expired")
        return {"ok": True, "caveats": n["caveats"]}
    except Exception as err:  # noqa: BLE001 - total
        return no("narrow error (fail closed): %s" % type(err).__name__)


# ---- max_uses ----------------------------------------------------------------------------------------------------------

def max_uses_error(c: Any) -> Optional[str]:
    if not isinstance(c, dict):
        return "caveat must be an object"
    e = _closed_members(c, ("type", "id", "n", "until"), (), "max_uses")
    if e:
        return e
    if c["type"] != CAVEAT_MAX_USES:
        return "not a max_uses caveat"
    if not _is_id(c["id"]):
        return "id is malformed"
    if not (_is_safe_int(c["n"]) and 1 <= c["n"] <= MAX_USES_LIMIT):
        return "n must be 1..%d" % MAX_USES_LIMIT
    if not (_is_safe_int(c["until"]) and c["until"] >= 0):
        return "until must be a non-negative safe integer"
    return None


def max_uses_slot_key(cap_hash_of_hop: str, id: str, i: int) -> str:
    return b64u(sha256(("%s%s\0%s\0%d" % (MAX_USES_DOMAIN, cap_hash_of_hop, id, i)).encode("utf-8")))


def reserve_max_uses(store: Any, bound: Any, now: Any) -> Dict[str, Any]:
    """Spend one use of every ``max_uses`` caveat in ``bound`` (``[{"caveat", "cap_hash"}]``), in order. Each takes the first
    free slot of its ``n``: a slot is one ``store.claim(key, 1)`` of the existing atomic replay store (the first claim of a
    key wins, every later one is refused). Slots already taken stay spent when a later caveat refuses (fail closed)."""
    def no(r: str) -> Dict[str, Any]:
        return {"ok": False, "reason": r}

    try:
        if not _is_safe_int(now):
            return no("the verifier clock is not a safe integer (fail closed)")
        spent = 0
        ids = set()
        for item in bound:
            caveat, ch = item["caveat"], item["cap_hash"]
            if not isinstance(caveat, dict) or caveat.get("type") != CAVEAT_MAX_USES:
                continue
            err = max_uses_error(caveat)
            if err:
                return no("malformed max_uses caveat: " + err)
            key = (ch, caveat["id"])
            if key in ids:
                return no("duplicate max_uses id '%s'" % caveat["id"])
            ids.add(key)
            if now >= caveat["until"]:
                return no("max_uses '%s' has expired" % caveat["id"])
            took = False
            i = 0
            while i < caveat["n"] and not took:
                slot = max_uses_slot_key(ch, caveat["id"], i)
                # a TTL'd slot (forgotten once `until` has passed); a store without consume_once keeps the slot for good
                took = store.consume_once(slot, caveat["until"], now) is True if hasattr(store, "consume_once") else bool(store.claim(slot, 1).ok)
                i += 1
            if not took:
                return no("max_uses '%s' is exhausted" % caveat["id"])
            spent += 1
        return {"ok": True, "spent": spent}
    except Exception as err:  # noqa: BLE001 - total
        return no("max_uses error (fail closed): %s" % type(err).__name__)


# ---- derive ------------------------------------------------------------------------------------------------------------

def _expr_error(x: Any, names: set, depth: int, count: list) -> Optional[str]:
    if depth > DERIVE_MAX_DEPTH:
        return "expression nests deeper than %d" % DERIVE_MAX_DEPTH
    count[0] += 1
    if count[0] > DERIVE_MAX_NODES:
        return "more than %d expression nodes" % DERIVE_MAX_NODES
    if not isinstance(x, dict):
        return "expression must be an object"
    if "ref" in x:
        e = _closed_members(x, ("ref",), (), "ref")
        if e:
            return e
        return None if isinstance(x["ref"], str) and x["ref"] in names else "ref names no earlier def"
    if "const" in x:
        e = _closed_members(x, ("const",), (), "const")
        if e:
            return e
        return None if _scalar_claim(x["const"]) else "const must be a scalar"
    op = x.get("op")
    if op in ("and", "or"):
        e = _closed_members(x, ("op", "args"), (), op)
        if e:
            return e
        if not isinstance(x["args"], list) or len(x["args"]) < 1 or len(x["args"]) > 8:
            return "%s needs 1..8 arguments" % op
        for a in x["args"]:
            r = _expr_error(a, names, depth + 1, count)
            if r:
                return r
        return None
    if op == "not":
        e = _closed_members(x, ("op", "arg"), (), "not")
        return e or _expr_error(x["arg"], names, depth + 1, count)
    if isinstance(op, str) and op in _CMP_OPS:
        e = _closed_members(x, ("op", "a", "b"), (), op)
        return e or _expr_error(x["a"], names, depth + 1, count) or _expr_error(x["b"], names, depth + 1, count)
    return "unknown expression"


def derive_error(c: Any) -> Optional[str]:
    if not isinstance(c, dict):
        return "caveat must be an object"
    e = _closed_members(c, ("type", "id", "defs", "check"), (), "derive")
    if e:
        return e
    if c["type"] != CAVEAT_DERIVE:
        return "not a derive caveat"
    if not _is_id(c["id"]):
        return "id is malformed"
    if not isinstance(c["defs"], list) or len(c["defs"]) > DERIVE_MAX_DEFS:
        return "defs must be an array of at most %d" % DERIVE_MAX_DEFS
    names: set = set()
    count = [0]
    for d in c["defs"]:
        if not isinstance(d, dict) or not _is_name(d.get("name")):
            return "def name is malformed"
        if d["name"] in names:
            return "def '%s' is defined twice" % d["name"]
        kind = d.get("kind")
        de: Optional[str]
        if kind == "count":
            de = _closed_members(d, ("name", "kind", "window_ms"), ("verb", "resource_prefix"), "count")
            if not de and not (_is_safe_int(d["window_ms"]) and 1 <= d["window_ms"] <= DERIVE_MAX_WINDOW_MS):
                de = "window_ms out of range"
            if not de and "verb" in d and not _str256(d["verb"]):
                de = "verb must be a non-empty string"
            if not de and "resource_prefix" in d and not _str256(d["resource_prefix"]):
                de = "resource_prefix must be a non-empty string"
        elif kind == "param":
            de = _closed_members(d, ("name", "kind", "path"), (), "param")
            if not de:
                p = d["path"]
                if not (isinstance(p, str) and len(p.split(".")) <= 4 and all(is_path_segment(s) for s in p.split("."))):
                    de = "param path is malformed"
        elif kind == "action":
            de = _closed_members(d, ("name", "kind", "field"), (), "action")
            if not de and d["field"] not in ("verb", "resource"):
                de = "field must be 'verb' or 'resource'"
        elif kind == "claim":
            de = _closed_members(d, ("name", "kind", "caveat_id", "claim"), (), "claim")
            if not de and not (_is_id(d["caveat_id"]) and _is_name(d["claim"])):
                de = "claim reference is malformed"
        elif kind == "expr":
            de = _closed_members(d, ("name", "kind", "expr"), (), "expr") or _expr_error(d["expr"], names, 1, count)
        else:
            de = "unknown def kind"
        if de:
            return "def '%s': %s" % (d["name"], de)
        names.add(d["name"])
    return _expr_error(c["check"], names, 1, count)


def _eval_expr(x: dict, env: dict) -> Any:
    """A scalar or None (unknown)."""
    if "ref" in x:
        return env.get(x["ref"])
    if "const" in x:
        return x["const"]
    op = x["op"]
    if op == "not":
        v = _eval_expr(x["arg"], env)
        return (not v) if isinstance(v, bool) else None
    if op in ("and", "or"):
        stop = op == "or"
        unknown = False
        for a in x["args"]:
            v = _eval_expr(a, env)
            if not isinstance(v, bool):
                unknown = True
            elif v is stop:
                return stop
        return None if unknown else (not stop)
    a, b = _eval_expr(x["a"], env), _eval_expr(x["b"], env)
    if a is None or b is None:
        return None
    if op == "eq":
        return scalar_eq(a, b)
    if op == "neq":
        return not scalar_eq(a, b)
    if not _is_safe_int(a) or not _is_safe_int(b):
        return None
    return a < b if op == "lt" else a <= b if op == "lte" else a > b if op == "gt" else a >= b


def evaluate_derive(c: Any, inp: Any) -> Optional[bool]:
    """True / False / None (unknown) for a WELL-FORMED derive caveat. ``inp`` = ``{now, action?, history?, claims}``."""
    env: dict = {}
    act = inp.get("action")
    act = act if isinstance(act, dict) else {}
    now = inp["now"]
    for d in c["defs"]:
        v: Any = None
        kind = d["kind"]
        if kind == "count":
            h = inp.get("history")
            if isinstance(h, (list, tuple)) and len(h) <= DERIVE_MAX_HISTORY:
                n = 0
                bad = False
                for e in h:
                    if not isinstance(e, dict) or not _is_safe_int(e.get("t")) or not isinstance(e.get("verb"), str) or not isinstance(e.get("resource"), str):
                        bad = True
                        break
                    if (e["t"] > now - d["window_ms"] and e["t"] <= now and ("verb" not in d or e["verb"] == d["verb"])
                            and ("resource_prefix" not in d or e["resource"].startswith(d["resource_prefix"]))):
                        n += 1
                v = None if bad else n
        elif kind == "param":
            r = resolve_param_path(act.get("params"), "action.params." + d["path"])
            v = r["value"] if r["found"] and _scalar_claim(r.get("value")) else None
        elif kind == "action":
            f = act.get(d["field"])
            v = f if _str256(f) else None
        elif kind == "claim":
            cl = (inp.get("claims") or {}).get(d["caveat_id"])
            v = cl.get(d["claim"]) if isinstance(cl, dict) else None
        elif kind == "expr":
            v = _eval_expr(d["expr"], env)
        env[d["name"]] = v
    r = _eval_expr(c["check"], env)
    return r if isinstance(r, bool) else None


# ---- spiffe_bound ------------------------------------------------------------------------------------------------------

def spiffe_bound_error(c: Any) -> Optional[str]:
    if not isinstance(c, dict):
        return "caveat must be an object"
    e = _closed_members(c, ("type",), ("spiffe_id", "spiffe_prefix"), "spiffe_bound")
    if e:
        return e
    if c["type"] != CAVEAT_SPIFFE_BOUND:
        return "not a spiffe_bound caveat"
    if ("spiffe_id" not in c) == ("spiffe_prefix" not in c):
        return "exactly one of spiffe_id and spiffe_prefix"
    v = c["spiffe_id"] if c.get("spiffe_id") is not None else c.get("spiffe_prefix")
    return spiffe_id_error(v)


def _spiffe_satisfied(c: dict, peer: Any) -> bool:
    if spiffe_bound_error(c) is not None or spiffe_id_error(peer) is not None:
        return False
    if "spiffe_id" in c:
        return peer == c["spiffe_id"]
    pre = c["spiffe_prefix"]
    return peer == pre or peer.startswith(pre + "/")


# ---- the K1 evaluator --------------------------------------------------------------------------------------------------

def evaluate_k1(grant: Any, chain: Any, k1: Any, ctx: Any) -> Dict[str, Any]:
    """Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block). Returns ``{ok, failed, reasons, plain,
    bound}``; ``plain`` holds the verified narrow block's non-K1 caveats for the caller's stock evaluator, ``bound`` the K1
    caveats evaluated (hand it to :func:`reserve_max_uses` once everything allowed). Total."""
    failed: List[str] = []
    reasons: List[str] = []

    def fail(c: Any, why: str) -> None:
        failed.append(c["type"] if isinstance(c, dict) and isinstance(c.get("type"), str) else "<malformed>")
        reasons.append(why)

    def result(plain: list, bound: list) -> Dict[str, Any]:
        return {"ok": len(failed) == 0, "failed": failed, "reasons": reasons, "plain": plain, "bound": bound}

    try:
        ctx = ctx if isinstance(ctx, dict) else {}
        base = bound_caveats(grant, chain)
        now = ctx.get("now")
        if base is None or not _is_safe_int(now):
            fail({"type": "<malformed>"}, "malformed capability chain" if base is None else "the verifier clock is not a safe integer (fail closed)")
            return result([], [])
        # No K1 input at all (not even ``{}``): every K1 caveat is refused, whatever its type.
        if not isinstance(k1, dict):
            mine = [b for b in base if is_k1_caveat(b["caveat"])]
            for b in mine:
                fail(b["caveat"], "the caveat language is not configured (no k1 input)")
            return result([], mine)
        hops = _hops_of(grant, chain)
        leaf_index = len(hops) - 1
        bound = base
        plain: list = []
        if "narrow" in k1:
            nb = {"now": now}
            if "action_digest" in k1:
                nb["action_digest"] = k1["action_digest"]
            nv = verify_narrow(k1["narrow"], grant, chain, nb)
            if not nv["ok"]:
                fail({"type": "narrow"}, nv["reason"])
                return result([], [b for b in bound if is_k1_caveat(b["caveat"])])
            leaf_hash = cap_hash(hops[leaf_index])
            bound = bound + [{"caveat": c, "hop": leaf_index, "cap_hash": leaf_hash} for c in nv["caveats"]]
            plain = [c for c in nv["caveats"] if not is_k1_caveat(c)]
        k1_bound = [b for b in bound if is_k1_caveat(b["caveat"])]
        seen: Dict[tuple, int] = {}
        for b in k1_bound:
            cid = b["caveat"].get("id")
            if isinstance(cid, str):
                k = (b["caveat"]["type"], cid)
                seen[k] = seen.get(k, 0) + 1
        claims: Dict[str, dict] = {}
        discharges = k1.get("discharges")
        discharges = discharges if isinstance(discharges, (list, tuple)) else []
        # pass 1: discharges (derive reads their claims)
        for b in k1_bound:
            c = b["caveat"]
            if c["type"] != CAVEAT_NEEDS_DISCHARGE:
                continue
            bad = needs_discharge_error(c)
            if bad:
                fail(c, bad)
                continue
            if seen.get((CAVEAT_NEEDS_DISCHARGE, c["id"]), 0) > 1:
                fail(c, "duplicate needs_discharge id '%s'" % c["id"])
                continue
            why = "no discharge presented"
            okd = None
            for d in discharges:
                if not isinstance(d, dict) or d.get("caveat_id") != c["id"]:
                    continue
                bind = {"cap_hash": b["cap_hash"], "pins": k1.get("pins") if k1.get("pins") is not None else [], "now": now}
                if "action_digest" in k1:
                    bind["action_digest"] = k1["action_digest"]
                if "revoked_discharges" in k1:
                    bind["revoked"] = k1["revoked_discharges"]
                v = verify_discharge(d, c, bind)
                if v["ok"]:
                    okd = v
                    break
                why = v["reason"]
            if okd is not None:
                claims[c["id"]] = okd["claims"]
            else:
                fail(c, why)
        # pass 2: everything else, in order
        for b in k1_bound:
            c = b["caveat"]
            t = c["type"]
            if t == CAVEAT_SEALED:
                e = _closed_members(c, ("type",), (), "sealed")
                if e:
                    fail(c, e)
                elif b["hop"] != leaf_index:
                    fail(c, "a hop was appended below a sealed hop")
            elif t == CAVEAT_MAX_USES:
                e = max_uses_error(c)
                if e:
                    fail(c, e)
                elif seen.get((CAVEAT_MAX_USES, c["id"]), 0) > 1:
                    fail(c, "duplicate max_uses id '%s'" % c["id"])
                elif now >= c["until"]:
                    fail(c, "max_uses '%s' has expired" % c["id"])
            elif t == CAVEAT_DERIVE:
                e = derive_error(c)
                if e:
                    fail(c, e)
                elif seen.get((CAVEAT_DERIVE, c["id"]), 0) > 1:
                    fail(c, "duplicate derive id '%s'" % c["id"])
                else:
                    r = evaluate_derive(c, {"now": now, "action": ctx.get("action"), "history": k1.get("history"), "claims": claims})
                    if r is not True:
                        fail(c, "derive check is unknown (a fact is missing)" if r is None else "derive check is false")
            elif t == CAVEAT_SPIFFE_BOUND:
                if not _spiffe_satisfied(c, k1.get("spiffe_id")):
                    fail(c, "the presenting workload does not carry the required SPIFFE ID")
        return result(plain, k1_bound)
    except Exception as err:  # noqa: BLE001 - total
        fail({"type": "<malformed>"}, "caveat language error (fail closed): %s" % type(err).__name__)
        return result([], [])


def evaluate_caveats_k1(grant: Any, chain: Any, k1: Any, context: Any) -> "tuple[bool, list]":
    """``(allow, failed sorted)``: the K1 types of the leaf's list by :func:`evaluate_k1`, every other caveat of
    ``policy_caveats(grant, chain)`` plus the verified narrow block's plain caveats by the stock ``evaluate_caveats``."""
    try:
        ctx = context if isinstance(context, dict) else {}
        r = evaluate_k1(grant, chain, k1, {"now": ctx.get("now"), "action": ctx.get("action")})
        cs = policy_caveats(grant, chain)
        stock = [c for c in cs if not is_k1_caveat(c)] + r["plain"] if isinstance(cs, list) else cs
        ok, sfailed = evaluate_caveats(stock, ctx)
        return (ok and r["ok"]), sorted(list(sfailed) + list(r["failed"]))
    except Exception:  # noqa: BLE001 - total
        return False, ["<malformed>"]
