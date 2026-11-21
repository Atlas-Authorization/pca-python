"""The wallet side of the PCA Intent Layer v2: the principal-signed answer (wire), friction tiers scaled by harm, cell
coordinates over the wallet's own outcome space, the statistics behind the noise estimates, attention canaries and the
approval-fatigue model. A port of the TypeScript reference (@atlasauth/pca-wallet). The trusted card and clarification
planning live in :mod:`atlas_pca.wallet_card`, risk-priced escalation in :mod:`atlas_pca.wallet_pricing`.

Values are plain JSON (dicts, lists, numbers, strings). Where the reference takes a callback or a Set, this port takes a callable or
a set. A reference refusal that is a thrown Error is a raised ValueError here. Floats follow the reference operation by operation."""
import math
import re
from typing import Any, Dict, List, Optional, Sequence

from ._fin import fin
from .ed25519 import sign_secret
from .ed25519 import verify as _ed_verify
from .ed25519 import public_key as _ed_public_key
from .pca import b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical, params_digest
from .predicates import _UNDEF, _js_string
from .signers_more import _cell_coords_error
from .wallet_omega import cell_count, cell_of, clopper_pearson_upper, is_int, is_number, num_cells

__all__ = [
    "INTENT_ANSWER_SIG_DOMAIN", "INTENT_ANSWER_REF_DOMAIN", "INTENT_TYPED_DOMAIN", "INTENT_DEVICE_CHALLENGE_DOMAIN", "INTENT_ACTION_DOMAIN",
    "FRICTION_ORDER", "MIN_HOLD_MS", "PROVENANCE_ORDER", "DEFAULT_FRICTION_THRESHOLDS", "EMPTY_NOISE", "NOISE_PRIOR", "DEFAULT_FATIGUE",
    "is_friction_tier", "friction_rank", "max_friction", "satisfies_tier", "is_provenance_level", "worst_provenance", "friction_for",
    "pca_action_digest", "action_values_of", "is_obj", "is_b64u32", "coords_error", "answer_shape_error", "sign_intent_answer",
    "verify_intent_answer", "answer_ref", "typed_digest", "device_challenge",
    "coord_key_of", "cat_label", "resolve_coords", "coords_of_box", "coords_of_cell", "cell_in_box", "box_cells", "box_size",
    "cell_of_action", "flat_index",
    "ln_gamma", "betacf", "beta_inc", "beta_quantile", "clopper_pearson_upper", "bin_ent",
    "record_canary", "estimate_noise", "cell_key", "boundary_neighbours", "pick_canary",
    "eta_under_load", "noise_state", "admission_policy", "SlidingWindowCounter", "double_confirmed",
]

INTENT_ANSWER_SIG_DOMAIN = "atlas-pca/intent-obs/v2\0"
INTENT_ANSWER_REF_DOMAIN = "atlas-pca/intent-answer-ref/v1"
INTENT_TYPED_DOMAIN = "atlas-pca/intent-typed/v1"
INTENT_DEVICE_CHALLENGE_DOMAIN = "atlas-pca/intent-device/v1"
INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1"
MIN_HOLD_MS = 2000

# ---- friction (wire.ts, friction.ts) ------------------------------------------------------------------------------------------

FRICTION_ORDER = ("tap", "hold", "typed", "device")
PROVENANCE_ORDER = ("trusted", "first_party", "tool", "web", "agent")
DEFAULT_FRICTION_THRESHOLDS = {"hTap": 5, "hDevice": 100_000}
_TAINTED = ("web", "agent")


def is_friction_tier(x: Any) -> bool:
    return isinstance(x, str) and x in FRICTION_ORDER


def friction_rank(t: Any) -> int:
    return FRICTION_ORDER.index(t) if isinstance(t, str) and t in FRICTION_ORDER else -1


def max_friction(*ts: Any) -> Any:
    best = "tap"
    for t in ts:
        if friction_rank(t) > friction_rank(best):
            best = t
    return best


def satisfies_tier(given: Any, required: Any) -> bool:
    return friction_rank(given) >= friction_rank(required)


def is_provenance_level(x: Any) -> bool:
    return isinstance(x, str) and x in PROVENANCE_ORDER


def _iterate(v: Any):
    """for...of over a JSON value: arrays and strings iterate, anything else is not iterable."""
    if isinstance(v, (list, str)):
        return iter(v)
    raise TypeError("levels is not iterable")


def worst_provenance(levels: Any) -> str:
    """The least trusted level of a set; "agent" for an empty or unknown set (fail closed)."""
    best = -1
    for lv in _iterate(levels):
        if not is_provenance_level(lv):
            return "agent"
        best = max(best, PROVENANCE_ORDER.index(lv))
    return "agent" if best < 0 else PROVENANCE_ORDER[best]


def _truthy(v: Any) -> bool:
    return not (v is None or v is False or v is _UNDEF or v == 0 and not isinstance(v, (list, dict)) or v == "")


def friction_for(inp: Dict[str, Any], th: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    th = DEFAULT_FRICTION_THRESHOLDS if th is None else th
    harm = inp.get("expectedHarm")
    if not (is_number(harm) and fin(harm) and harm >= 0):
        return {"tier": "device", "rules": ["harm-unknown"]}
    rules: List[str] = []
    tier = "tap"

    def raise_(t: Any, why: str) -> None:
        nonlocal tier
        if friction_rank(t) >= friction_rank(tier):
            rules.append(why)
        tier = max_friction(tier, t)

    rev = inp.get("reversibility")
    if rev == "rate_limited":
        raise_("hold", "rate-limited")
    if harm >= th["hTap"]:
        raise_("hold", "harm>=h_tap")
    if rev == "irreversible":
        raise_("typed", "irreversible")
    prov = inp.get("provenance")
    tainted_critical = any(p.get("sensitivity") == "critical" and worst_provenance(p.get("levels")) in _TAINTED
                           for p in (prov if prov is not None else []))
    if tainted_critical:
        raise_("typed", "tainted-critical")
    if _truthy(inp.get("widensCriticalIdentity")) and rev == "irreversible":
        raise_("device", "critical-irreversible")
    if harm >= th["hDevice"]:
        raise_("device", "harm>=h_device")
    if _truthy(inp.get("singleSource")):
        raise_(FRICTION_ORDER[min(len(FRICTION_ORDER) - 1, friction_rank(tier) + 1)], "single-source")
    if "siteMin" in inp:
        raise_(inp["siteMin"], "site-minimum")
    return {"tier": tier, "rules": rules}


# ---- helpers (wire.ts) ---------------------------------------------------------------------------------------------------------

def is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def is_b64u32(v: Any) -> bool:
    return decode_b64u_strict(v, 32) is not None


def coords_error(c: Any) -> Optional[str]:
    """Cell coordinates as the core validates them (shared with `intent_required`)."""
    return _cell_coords_error(c)


def _g(o: Any, k: str) -> Any:
    return o[k] if isinstance(o, dict) and k in o else _UNDEF


def _entries(v: Any):
    """Object.entries of a JSON value (strings and arrays yield their indices; null and undefined throw)."""
    if isinstance(v, dict):
        return list(v.items())
    if isinstance(v, list):
        return [(str(i), x) for i, x in enumerate(v)]
    if isinstance(v, str):
        return [(str(i), c) for i, c in enumerate(v)]
    if v is None or v is _UNDEF:
        raise TypeError("Cannot convert undefined or null to object")
    return []


def _plain(v: Any) -> Any:
    """JSON.parse(JSON.stringify(v)): -0 becomes 0, an integral float an integer."""
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, float) and v == v and v not in (math.inf, -math.inf) and v.is_integer():
        return int(v)
    return v


def pca_action_digest(a: Dict[str, Any]) -> str:
    """The action digest of an attempted action (what `intent_required.action_digest` and a JIT consent bind to)."""
    act = {}
    for k, v in (("verb", _g(a, "verb")), ("resource", _g(a, "resource")), ("params_digest", params_digest(None if _g(a, "params") is _UNDEF else a["params"])),
               ("reversibility_class", _g(a, "reversibility_class"))):
        if v is _UNDEF:
            raise TypeError("canonicalize: undefined")
        act[k] = v
    return hash_canonical({"d": INTENT_ACTION_DOMAIN, "action": act})


def action_values_of(a: Dict[str, Any]) -> Dict[str, Any]:
    """The default projection of an attempted action onto Omega paths: the resource and every scalar param."""
    values: Dict[str, Any] = {}
    res = _g(a, "resource")
    if res is not _UNDEF:
        values["action.resource"] = res
    for k, v in _entries(_g(a, "params")):
        if isinstance(v, str) or (is_number(v) and fin(v)):
            values["action.params." + k] = v
    out: Dict[str, Any] = {"values": values}
    if _g(a, "verb") is not _UNDEF:
        out["verb"] = a["verb"]
    return out


# ---- M6: the signed answer ------------------------------------------------------------------------------------------------------

_ANS_KEYS = ("v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg", "sig")
_UX_KEYS = ("tier", "rendered_digest", "typed_digest", "hold_ms", "webauthn", "canary", "action_digest", "consent_for_action")
_WA_KEYS = ("credential_id", "authenticator_data", "client_data_json", "signature")
_QID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)


def _num_eq(v: Any, n: int) -> bool:
    return is_number(v) and v == n


def _only_keys(o: Dict[str, Any], allowed) -> Optional[str]:
    for k in o:
        if k not in allowed:
            return 'unknown member "%s"' % k
    return None


def _partial_error(p: Any) -> Optional[str]:
    if not is_obj(p) or not isinstance(p.get("path"), str) or len(p["path"]) == 0:
        return "partial.path must be a non-empty string"
    keys = [k for k in p if k != "path"]
    if len(keys) != 1:
        return "partial must carry exactly one of upTo / from / except / notFor"
    k = keys[0]
    v = p[k]
    if k in ("upTo", "from") and not is_int(v):
        return "partial.%s must be an integer" % k
    if k == "except" and not (isinstance(v, list) and len(v) > 0 and all(is_int(x) for x in v)):
        return "partial.except must be a non-empty integer array"
    if k == "notFor" and not (isinstance(v, list) and len(v) > 0 and all(isinstance(x, str) and len(x) > 0 for x in v)):
        return "partial.notFor must be a non-empty string array"
    if k not in ("upTo", "from", "except", "notFor"):
        return 'unknown partial member "%s"' % k
    return None


def answer_shape_error(a: Any) -> Optional[str]:
    if not is_obj(a):
        return "not an object"
    extra = _only_keys(a, _ANS_KEYS)
    if extra:
        return extra
    if not _num_eq(a.get("v"), 2) or a.get("kind") != "pca-intent-observation":
        return "not a pca-intent-observation v2"
    for k in ("map_digest", "session", "signer"):
        if not is_b64u32(a.get(k)):
            return "%s is not canonical base64url (32 bytes)" % k
    qid = a.get("question_id")
    if not isinstance(qid, str) or _QID_RE.fullmatch(qid) is None:
        return "question_id must match [A-Za-z0-9_-]{1,64}"
    if not isinstance(a.get("verb"), str) or len(a["verb"]) == 0:
        return "verb must be a non-empty string"
    ce = coords_error(a.get("cell"))
    if ce:
        return "cell: " + ce
    if not (_num_eq(a.get("y"), 0) or _num_eq(a.get("y"), 1)):
        return "y must be 0 or 1"
    if "partial" in a:
        pe = _partial_error(a["partial"])
        if pe:
            return pe
        if not _num_eq(a.get("y"), 1):
            return "a partial answer carries y = 1 (yes for the part)"
    if a.get("source") not in ("elicitation", "clarification"):
        return "source must be elicitation or clarification"
    if not is_int(a.get("observed_at")) or a["observed_at"] < 0:
        return "observed_at must be a non-negative safe integer"
    if a.get("alg") != "ed25519":
        return "alg must be ed25519"
    ux = a.get("ux")
    if not is_obj(ux):
        return "ux must be an object"
    ue = _only_keys(ux, _UX_KEYS)
    if ue:
        return "ux: " + ue
    if not is_friction_tier(ux.get("tier")):
        return "ux.tier is not a friction tier"
    if not is_b64u32(ux.get("rendered_digest")):
        return "ux.rendered_digest is not canonical base64url (32 bytes)"
    if not isinstance(ux.get("canary"), bool):
        return "ux.canary must be a boolean"
    if "typed_digest" in ux and not is_b64u32(ux["typed_digest"]):
        return "ux.typed_digest is not canonical base64url (32 bytes)"
    if "hold_ms" in ux and not (is_int(ux["hold_ms"]) and ux["hold_ms"] >= 0):
        return "ux.hold_ms must be a non-negative integer"
    if "action_digest" in ux and not is_b64u32(ux["action_digest"]):
        return "ux.action_digest is not canonical base64url (32 bytes)"
    if "consent_for_action" in ux and not isinstance(ux["consent_for_action"], bool):
        return "ux.consent_for_action must be a boolean"
    if ux.get("consent_for_action") is True and ("action_digest" not in ux or not _num_eq(a.get("y"), 1) or "partial" in a):
        return "consent_for_action needs action_digest and a plain yes"
    if ux.get("consent_for_action") is True and ux.get("canary") is True:
        return "a canary never consents to an action"
    if "webauthn" in ux:
        wa = ux["webauthn"]
        if not is_obj(wa) or _only_keys(wa, _WA_KEYS) or not all(isinstance(wa.get(k), str) for k in _WA_KEYS):
            return "ux.webauthn is malformed"
    if _num_eq(a.get("y"), 1) and not ux["canary"]:
        tier = ux["tier"]
        if tier == "hold" and not (is_int(ux.get("hold_ms")) and ux["hold_ms"] >= MIN_HOLD_MS):
            return "hold tier needs hold_ms >= %d" % MIN_HOLD_MS
        if tier == "typed" and "typed_digest" not in ux:
            return "typed tier needs typed_digest"
        if tier == "device" and "webauthn" not in ux:
            return "device tier needs a WebAuthn assertion"
    return None


def _answer_body(a: Dict[str, Any]) -> Dict[str, Any]:
    body: Dict[str, Any] = {}
    for k in ("v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg"):
        if k in a:
            body[k] = a[k]
    return _plain(body)


def _domain_message(domain: str, body: Any) -> bytes:
    return domain.encode("utf-8") + canonical_bytes_strict(body)


def sign_intent_answer(a: Dict[str, Any], principal_secret: bytes) -> Dict[str, Any]:
    """Wallet side: sign the principal's answer with the principal key (Ed25519, domain-separated, over the canonical body)."""
    base = dict(a)
    base.update({"v": 2, "kind": "pca-intent-observation", "signer": b64u(_ed_public_key(principal_secret)), "alg": "ed25519"})
    body = _answer_body(base)
    bad = answer_shape_error(body)
    if bad:
        raise ValueError("signIntentAnswer: " + bad)
    out = dict(body)
    out["sig"] = b64u(sign_secret(principal_secret, _domain_message(INTENT_ANSWER_SIG_DOMAIN, body)))
    return out


def verify_intent_answer(a: Any, principals: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Verify a signed answer; `principals` restricts the signer (the keys named in the session root). Never raises."""
    try:
        bad = answer_shape_error(a)
        if bad:
            return {"ok": False, "reason": bad}
        if principals is not None and a["signer"] not in principals:
            return {"ok": False, "reason": "signer is not a principal of the session"}
        sig = a.get("sig")
        if not isinstance(sig, str):
            return {"ok": False, "reason": "bad signature"}
        pk, sg = decode_b64u_strict(a["signer"], 32), decode_b64u_strict(sig, 64)
        if pk is None or sg is None or not _ed_verify(pk, _domain_message(INTENT_ANSWER_SIG_DOMAIN, _answer_body(a)), sg):
            return {"ok": False, "reason": "bad signature"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001 - the reference turns every throw into a refusal
        return {"ok": False, "reason": "malformed answer: %s" % e}


def answer_ref(a: Dict[str, Any]) -> str:
    """Content address of a signed answer (evidence bundles and delta grants refer to it)."""
    return hash_canonical({"d": INTENT_ANSWER_REF_DOMAIN, "a": a})


def typed_digest(question_id: str, normalized_value: str) -> str:
    return hash_canonical({"d": INTENT_TYPED_DOMAIN, "q": question_id, "v": normalized_value})


def device_challenge(question_id: str, rendered_digest: str, y: int, action_digest: Optional[str] = None) -> str:
    """The 32-byte WebAuthn challenge of a device-tier answer: binds the question, the card the human saw, y and the action."""
    return hash_canonical({"d": INTENT_DEVICE_CHALLENGE_DOMAIN, "q": question_id, "r": rendered_digest, "y": y, "a": action_digest})


# ---- cell coordinates <-> the wallet's own Omega (box.ts) -------------------------------------------------------------------------

_ACC = re.compile(r"env\.acc\.([A-Za-z0-9_.-]+)\.post")
_MON = re.compile(r"env\.mon\.([A-Za-z0-9_.-]+)\.state")
_PROV = re.compile("env\\.prov\\.([^\n\r\u2028\u2029]+)")
_WORLD = re.compile(r"env\.world\.([A-Za-z0-9_.-]+)")


def coord_key_of(path: str) -> str:
    m = _ACC.fullmatch(path)
    if m:
        return m.group(1)
    m = _MON.fullmatch(path)
    if m:
        return "mon:" + m.group(1)
    m = _PROV.fullmatch(path)
    if m:
        return "prov:" + m.group(1)
    m = _WORLD.fullmatch(path)
    if m:
        return m.group(1)
    return path


def cat_label(d: Dict[str, Any], i: int) -> str:
    return d["values"][i]["value"]


def _keys(o: Any) -> List[str]:
    return [k for k, _ in _entries(o)]


def resolve_coords(omega: Dict[str, Any], verb: str, coords: Any) -> Dict[str, Any]:
    """Resolve coordinates to a box of cells of the verb's space: {ok, vs, box} or {ok: False, reason}. Every dimension must be
    named exactly once; anything the wallet cannot resolve exactly is refused."""
    vs = next((v for v in omega["verbs"] if v["verb"] == verb), None)
    if vs is None:
        return {"ok": False, "reason": "verb %s is not in the wallet's outcome space" % (verb if isinstance(verb, str) else _js_string(verb))}
    by_key: Dict[str, int] = {}
    for k, d in enumerate(vs["dims"]):
        by_key[d["path"]] = k
        by_key[coord_key_of(d["path"])] = k
    named = set()
    for key in _keys(coords):
        k = by_key.get(key)
        if k is None:
            return {"ok": False, "reason": "unknown dimension %s" % key}
        if k in named:
            return {"ok": False, "reason": "dimension %s is named twice" % vs["dims"][k]["path"]}
        named.add(k)
    box: List[List[int]] = []
    for k, d in enumerate(vs["dims"]):
        c = _g(coords, d["path"])
        if c is _UNDEF or c is None:
            c = _g(coords, coord_key_of(d["path"]))
        if c is _UNDEF:
            return {"ok": False, "reason": "coordinates leave out dimension %s" % d["path"]}
        if c is None:
            raise TypeError("Cannot read properties of null")
        if d["kind"] == "num":
            if not (isinstance(c, list) and len(c) == 2 and is_number(c[0]) and is_number(c[1])):
                return {"ok": False, "reason": "dimension %s is numeric: expected an index range" % d["path"]}
            lo, hi = c
            if not (_is_integral(lo) and _is_integral(hi) and not _neg_zero(lo) and not _neg_zero(hi) and lo >= 0 and lo <= hi and hi < len(num_cells(d))):
                return {"ok": False, "reason": "index range of %s is out of range" % d["path"]}
            box.append(list(range(int(lo), int(hi) + 1)))
        else:
            if not isinstance(c, list):
                raise TypeError("c.every is not a function")
            if not all(isinstance(x, str) for x in c):
                return {"ok": False, "reason": "dimension %s is categorical: expected a value set" % d["path"]}
            ids: List[int] = []
            for label in c:
                hits = [j for j, v in enumerate(d["values"]) if v["value"] == label]
                if len(hits) == 0:
                    return {"ok": False, "reason": "unknown value %s for %s" % (_json_str(label), d["path"])}
                if len(hits) > 1:
                    return {"ok": False, "reason": "value %s names two cells of %s" % (_json_str(label), d["path"])}
                ids.append(hits[0])
            box.append(sorted(set(ids)))
    return {"ok": True, "vs": vs, "box": box}


def _is_integral(x: Any) -> bool:
    return (isinstance(x, int) and not isinstance(x, bool)) or (isinstance(x, float) and fin(x) and x.is_integer())


def _neg_zero(x: Any) -> bool:
    return isinstance(x, float) and x == 0 and math.copysign(1.0, x) < 0


def _json_str(s: str) -> str:
    """JSON.stringify of a string (a lone surrogate is escaped)."""
    import json
    out = json.dumps(s, ensure_ascii=False)
    return re.sub("[\ud800-\udfff]", lambda m: "\\u%04x" % ord(m.group(0)), out)


def coords_of_box(vs: Dict[str, Any], box: List[List[int]]) -> Dict[str, Any]:
    """The coordinates of a box (the inverse of resolve_coords; numeric sides must be contiguous)."""
    out: Dict[str, Any] = {}
    for k, d in enumerate(vs["dims"]):
        ids = box[k]
        if d["kind"] == "num":
            lo, hi = min(ids), max(ids)
            if hi - lo + 1 != len(ids):
                raise ValueError("coordsOfBox: numeric side of %s is not contiguous" % d["path"])
            out[d["path"]] = [lo, hi]
        else:
            out[d["path"]] = [cat_label(d, i) for i in ids]
    return out


def coords_of_cell(vs: Dict[str, Any], idx: Sequence[int]) -> Dict[str, Any]:
    return coords_of_box(vs, [[i] for i in idx])


def cell_in_box(box: List[List[int]], idx: Sequence[int]) -> bool:
    return len(box) == len(idx) and all(idx[k] in ids for k, ids in enumerate(box))


def box_cells(box: List[List[int]]) -> List[List[int]]:
    out: List[List[int]] = [[]]
    for ids in box:
        out = [pre + [i] for pre in out for i in ids]
    return out


def box_size(box: List[List[int]]) -> int:
    n = 1
    for ids in box:
        n *= len(ids)
    return n


def cell_of_action(omega: Dict[str, Any], a: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The cell of a concrete action in the wallet's Omega ({vs, idx}); None when it falls outside it (fail closed)."""
    vs = next((v for v in omega["verbs"] if v["verb"] == a.get("verb")), None)
    if vs is None:
        return None
    values = a["values"] if isinstance(a, dict) and "values" in a else None
    if not isinstance(values, (dict, list)):
        raise TypeError("Cannot use 'in' operator")
    for d in vs["dims"]:
        if not (isinstance(values, dict) and d["path"] in values):
            return None
    idx = cell_of(vs, {"verb": a["verb"], "values": values})
    return {"vs": vs, "idx": idx} if idx is not None else None


def flat_index(vs: Dict[str, Any], idx: Sequence[int]) -> int:
    f = 0
    for k, d in enumerate(vs["dims"]):
        f = f * cell_count(d) + idx[k]
    return f


# ---- stats (stats.ts) ------------------------------------------------------------------------------------------------------------

_LANCZOS = [676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905,
            -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7]


def ln_gamma(x: float) -> float:
    x = float(x)
    if x < 0.5:
        return math.log(math.pi / math.sin(math.pi * x)) - ln_gamma(1 - x)
    z = x - 1
    a = 0.99999999999980993
    t = z + 7.5
    for i in range(len(_LANCZOS)):
        a += _LANCZOS[i] / (z + i + 1)
    return 0.5 * math.log(2 * math.pi) + (z + 0.5) * math.log(t) - t + math.log(a)


def betacf(a: float, b: float, x: float) -> float:
    """The continued fraction of I_x(a, b) (modified Lentz; a zero denominator is replaced by 1e-300, never divided by)."""
    a, b, x = float(a), float(b), float(x)
    tiny = 1e-300
    qab = a + b
    qap = a + 1
    qam = a - 1
    c = 1.0
    d = 1 - (qab * x) / qap
    if abs(d) < tiny:
        d = tiny
    d = 1 / d
    h = d
    for m in range(1, 301):
        m2 = 2 * m
        aa = (m * (b - m) * x) / ((qam + m2) * (a + m2))
        d = 1 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1 / d
        h *= d * c
        aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2))
        d = 1 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1 / d
        dl = d * c
        h *= dl
        if abs(dl - 1) < 1e-15:
            break
    return h


def beta_inc(x: float, a: float, b: float) -> float:
    """Regularized incomplete beta I_x(a, b), a, b > 0, x in [0, 1]."""
    if not (a > 0 and b > 0):
        raise ValueError("betaInc: a and b must be > 0")
    if x <= 0:
        return 0
    if x >= 1:
        return 1
    a, b, x = float(a), float(b), float(x)
    lbt = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * math.log(x) + b * math.log(1 - x)
    bt = math.exp(lbt)
    if x < (a + 1) / (a + b + 2):
        return (bt * betacf(a, b, x)) / a
    return 1 - (bt * betacf(b, a, 1 - x)) / b


def beta_quantile(q: float, a: float, b: float) -> float:
    """The q-quantile of Beta(a, b) by bisection (200 steps)."""
    if not (q >= 0 and q <= 1):
        raise ValueError("betaQuantile: q must be in [0, 1]")
    if q == 0:
        return 0
    if q == 1:
        return 1
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if beta_inc(mid, a, b) < q:
            lo = mid
        else:
            hi = mid
    return hi


def bin_ent(p: float) -> float:
    """Binary entropy in bits."""
    if p <= 0 or p >= 1:
        return 0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


# ---- canaries (canary.ts) ---------------------------------------------------------------------------------------------------------

EMPTY_NOISE = {"falseYes": 0, "correctNo": 0, "falseNo": 0, "correctYes": 0}
NOISE_PRIOR = {"a": 1, "b": 9}


def record_canary(n: Dict[str, Any], expected: int, y: int) -> Dict[str, Any]:
    """Fold one canary answer into the counts (pure)."""
    out = dict(n)
    if _num_eq(expected, 0):
        if _num_eq(y, 1):
            out["falseYes"] = n["falseYes"] + 1
        else:
            out["correctNo"] = n["correctNo"] + 1
    elif _num_eq(y, 0):
        out["falseNo"] = n["falseNo"] + 1
    else:
        out["correctYes"] = n["correctYes"] + 1
    return out


def estimate_noise(n: Dict[str, Any], delta_c: float = 0.05) -> Dict[str, Any]:
    if not (delta_c > 0 and delta_c < 1):
        raise ValueError("estimateNoise: deltaC must be in (0, 1)")
    ap = NOISE_PRIOR["a"] + n["falseYes"]
    bp = NOISE_PRIOR["b"] + n["correctNo"]
    an = NOISE_PRIOR["a"] + n["falseNo"]
    bn = NOISE_PRIOR["b"] + n["correctYes"]
    known_no = n["falseYes"] + n["correctNo"]
    known_yes = n["falseNo"] + n["correctYes"]
    return {
        "etaPos": ap / (ap + bp),
        "etaNeg": an / (an + bn),
        "etaPosUpper": beta_quantile(1 - delta_c, ap, bp),
        "etaNegUpper": beta_quantile(1 - delta_c, an, bn),
        "etaPosCP": 1 if known_no == 0 else clopper_pearson_upper(n["falseYes"], known_no, delta_c),
        "etaNegCP": 1 if known_yes == 0 else clopper_pearson_upper(n["falseNo"], known_yes, delta_c),
        "asked": known_no + known_yes,
    }


def cell_key(verb: str, idx: Sequence[int]) -> str:
    return "%s|%s" % (verb, ",".join(str(int(i)) if _is_integral(i) else str(i) for i in idx))


def boundary_neighbours(omega: Dict[str, Any], confirmed: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Cells one step outside the confirmed region in exactly one dimension (deterministic order)."""
    inside = {cell_key(c["verb"], c["idx"]) for c in confirmed}
    out: Dict[str, Dict[str, Any]] = {}
    for c in confirmed:
        vs = next((v for v in omega["verbs"] if v["verb"] == c["verb"]), None)
        if vs is None:
            continue
        for k, d in enumerate(vs["dims"]):
            n = cell_count(d)
            alts = [c["idx"][k] - 1, c["idx"][k] + 1] if d["kind"] == "num" else list(range(n))
            for a in alts:
                if a < 0 or a >= n or a == c["idx"][k]:
                    continue
                idx = list(c["idx"])
                idx[k] = a
                key = cell_key(c["verb"], idx)
                if key not in inside:
                    out[key] = {"verb": c["verb"], "idx": idx}
    return [v for _k, v in sorted(out.items(), key=lambda e: e[0].encode("utf-16-be"))]


def pick_canary(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Decide whether to insert a canary now, and which (None: no canary this time). `ctx` carries omega, confirmed, knownNo
    (callable (verb, idx) -> "ceiling" | "veto" | None), knownYes, exclude (set of `verb|i,j,..` keys), rand (callable), optional
    rho (default 0.1), lowHarmSession and canariesSoFar."""
    rho = ctx.get("rho")
    rho = 0.1 if rho is None else rho
    if not (rho >= 0 and rho <= 1):
        raise ValueError("pickCanary: rho must be in [0, 1]")
    if ctx["lowHarmSession"] and ctx["canariesSoFar"] >= 1:
        return None
    if not (ctx["rand"]() < rho):
        return None
    exclude = ctx["exclude"]
    no: List[Dict[str, Any]] = []
    for c in boundary_neighbours(ctx["omega"], ctx["confirmed"]):
        if cell_key(c["verb"], c["idx"]) in exclude:
            continue
        why = ctx["knownNo"](c["verb"], c["idx"])
        if why:
            no.append({"verb": c["verb"], "idx": c["idx"], "expected": 0, "source": why})
    yes = [{"verb": c["verb"], "idx": list(c["idx"]), "expected": 1, "source": "confirmed-yes"}
           for c in ctx["knownYes"] if cell_key(c["verb"], c["idx"]) not in exclude]
    if not no and not yes:
        return None
    if no and yes:
        pool = no if ctx["rand"]() < 0.5 else yes
    else:
        pool = no if no else yes
    return pool[min(len(pool) - 1, math.floor(ctx["rand"]() * len(pool)))]


# ---- approval fatigue (fatigue.ts) ------------------------------------------------------------------------------------------------

DEFAULT_FATIGUE = {"betaF": 0.005, "etaStop": 0.15, "deltaC": 0.05, "freezeOn": "mean", "assumeNoiseFree": False, "delta": 0.05}
_BELOW_HALF = 0.5 - 1e-9


def eta_under_load(base: float, beta_f: float, n_recent: int) -> float:
    """eta+ under load: base + beta_f * n_recent, capped at 1/2."""
    if not (base >= 0 and beta_f >= 0 and _is_integral(n_recent) and n_recent >= 0):
        raise ValueError("etaUnderLoad: bad arguments")
    return min(0.5, base + beta_f * n_recent)


def noise_state(counts: Dict[str, Any], n_recent: int, model: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    model = DEFAULT_FATIGUE if model is None else model
    e = estimate_noise(counts, model["deltaC"])
    eta_pos = eta_under_load(e["etaPos"], model["betaF"], n_recent)
    eta_pos_bar = eta_under_load(e["etaPosUpper"], model["betaF"], n_recent)
    stat = eta_pos if model["freezeOn"] == "mean" else eta_pos_bar
    return {"etaPos": eta_pos, "etaPosBar": eta_pos_bar, "etaNegBar": min(0.5, e["etaNegUpper"]), "frozen": stat > model["etaStop"]}


def admission_policy(state: Dict[str, Any], model: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    model = DEFAULT_FATIGUE if model is None else model
    if _truthy(model["assumeNoiseFree"]):
        return {"tau": 1, "etaPos": 0, "etaNeg": 0, "doubleConfirmIrreversible": False, "falseAdmitBound": 0}
    if not (model["delta"] > 0 and model["delta"] < 1):
        raise ValueError("admissionPolicy: delta must be in (0, 1)")
    ep = min(_BELOW_HALF, state["etaPosBar"])
    en = min(_BELOW_HALF, state["etaNegBar"])
    return {"tau": 1 - model["delta"], "etaPos": ep, "etaNeg": en, "doubleConfirmIrreversible": ep > 0, "falseAdmitBound": ep * ep}


class SlidingWindowCounter:
    """Sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an agent cannot split
    around it by opening sessions). Keeps only timestamps inside the window."""

    def __init__(self, window_ms: Any = 3_600_000):
        if not (_is_integral(window_ms) and window_ms > 0):
            raise ValueError("SlidingWindowCounter: windowMs must be a positive integer")
        self.window_ms = window_ms
        self._times: List[Any] = []

    def _prune(self, now: Any) -> None:
        if not fin(now):
            return  # an infinite clock must never forget a recorded event
        while self._times and self._times[0] <= now - self.window_ms:
            self._times.pop(0)

    def count(self, now: Any) -> int:
        self._prune(now)
        return len(self._times)

    def try_add(self, now: Any, cap: Any) -> bool:
        """Record one event at `now` if the count is below `cap`; False (and nothing recorded) otherwise."""
        self._prune(now)
        if len(self._times) >= cap:
            return False
        if self._times and not (now >= self._times[-1]):
            raise ValueError("SlidingWindowCounter: time went backwards")
        if not fin(now):
            return False
        self._times.append(now)
        return True


def double_confirmed(records: Sequence[Dict[str, Any]]) -> bool:
    """Two "yes" answers at typed or device tier, on different screens, with at least one other screen between them."""
    strong = sorted(r["screen"] for r in records if r["tier"] in ("typed", "device"))
    for i in range(len(strong)):
        for j in range(i + 1, len(strong)):
            if strong[j] - strong[i] >= 2:
                return True
    return False
