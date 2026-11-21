"""Portable, revocable intent profiles: the principal's signed, versioned record of standing rules and prior answers,
append-only succession, scoped use (deny wins, permit is explicit, negative observations veto) and revocation. Native
port of the TypeScript reference (@atlasauth/pca-intent); signing is Ed25519 (a suite-agile profile verifies under the
verifier's pin)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import ed25519
from .intent_omega import cell_of, u16key
from .intent_policy import outcome_to_action
from .intent_v2 import (_UNDEF, _bind_suite_fields, _ctx, _js_keys, _js_string, _js_strict_eq, _pinned_suite_error,
                        _suite_known_error, check_session_revocation, profile_revocation_id, profile_revocation_scope)
from .pca import _is_safe_int, b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical
from .predicates import predicate_matches

INTENT_PROFILE_KIND = "pca-intent-profile"
INTENT_PROFILE_SIG_DOMAIN = "atlas-pca/intent-profile/v1\0"
INTENT_PROFILE_REF_DOMAIN = "atlas-pca/intent-profile-ref/v1"
MAX_PROFILE_RULES = 256
MAX_PROFILE_OBSERVATIONS = 2000

_KEYS = ("v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev", "alg",
         "pq_pk", "sig", "pq_sig")
_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")


def _g(o: dict, k: str) -> Any:
    return o.get(k, _UNDEF)


def _str_list(v: Any, mx: int = 256) -> bool:
    return isinstance(v, list) and len(v) <= mx and all(isinstance(x, str) and len(x) > 0 for x in v)


def _pred_ok(p: Any) -> bool:
    if not isinstance(p, dict):
        return False
    v = _g(p, "verb")
    return isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))


def _sorted_keys(o: dict) -> str:
    return ",".join(sorted(_js_keys(o), key=u16key))


def _is_b32(x: Any) -> bool:
    return decode_b64u_strict(x, 32) is not None


def intent_profile_shape_error(p: Any, signed: bool = True) -> Optional[str]:
    """None when the profile is well-formed (closed, strictly typed); else the first problem."""
    try:
        if not isinstance(p, dict):
            return "profile is not an object"
        for k in _js_keys(p):
            if k not in _KEYS:
                return "profile: unknown member '%s'" % k
        if not _js_strict_eq(_g(p, "v"), 1) or _g(p, "kind") != INTENT_PROFILE_KIND:
            return "not a pca-intent-profile v1"
        pid = _g(p, "profile_id")
        if not isinstance(pid, str) or _ID_RE.fullmatch(pid) is None:
            return "profile_id must match [A-Za-z0-9_.-]{1,128}"
        ver = _g(p, "version")
        if not (_is_safe_int(ver) and ver >= 1):
            return "version must be a safe integer >= 1"
        if not _is_b32(_g(p, "owner")):
            return "owner must be canonical base64url (32 bytes)"
        scope = _g(p, "scope")
        if not isinstance(scope, dict) or any(k not in ("sites", "verbs", "semantic_types") for k in _js_keys(scope)):
            return "scope must be {sites?, verbs?, semantic_types?}"
        for k in ("sites", "verbs", "semantic_types"):
            if _g(scope, k) is not _UNDEF and not _str_list(_g(scope, k)):
                return "scope.%s must be a list of strings" % k
        standing = _g(p, "standing")
        if not isinstance(standing, dict) or _sorted_keys(standing) != "deny,permit":
            return "standing must be {deny, permit}"
        for k in ("deny", "permit"):
            r = standing[k]
            if not isinstance(r, list) or len(r) > MAX_PROFILE_RULES or not all(_pred_ok(x) for x in r):
                return "standing.%s must be at most %d predicates" % (k, MAX_PROFILE_RULES)
        prior = _g(p, "prior")
        if not isinstance(prior, dict) or _sorted_keys(prior) != "maps,observations":
            return "prior must be {observations, maps}"
        obs = prior["observations"]
        if not isinstance(obs, list) or len(obs) > MAX_PROFILE_OBSERVATIONS:
            return "prior.observations must be at most %d" % MAX_PROFILE_OBSERVATIONS
        for o in obs:
            if (not isinstance(o, dict) or _sorted_keys(o) != "at,values,verb,y" or not isinstance(o["verb"], str)
                    or not isinstance(o["values"], dict) or not (_js_strict_eq(o["y"], 0) or _js_strict_eq(o["y"], 1))
                    or not (_is_safe_int(o["at"]) and o["at"] >= 0)):
                return "prior.observations entries are {verb, values, y, at}"
        maps = prior["maps"]
        if not isinstance(maps, list) or not all(_is_b32(m) for m in maps):
            return "prior.maps must be 32-byte digests"
        ea = _g(p, "expires_at")
        if not (_is_safe_int(ea) and ea >= 0):
            return "expires_at must be a non-negative safe integer"
        rev = _g(p, "revocation")
        if (not isinstance(rev, dict) or any(k not in ("epoch_uri", "key") for k in _js_keys(rev))
                or not isinstance(_g(rev, "epoch_uri"), str) or len(rev["epoch_uri"]) == 0):
            return "revocation must be {epoch_uri, key?}"
        if _g(rev, "key") is not _UNDEF and not _is_b32(rev["key"]):
            return "revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)"
        prev = _g(p, "prev")
        if _js_strict_eq(ver, 1) != (prev is _UNDEF):
            return "prev is required exactly when version > 1"
        if prev is not _UNDEF and not _is_b32(prev):
            return "prev must be canonical base64url (32 bytes)"
        if signed:
            alg = _g(p, "alg")
            if alg is not _UNDEF and not isinstance(alg, str):
                return "alg must be a string"
            se = _suite_known_error(alg)
            if se is not None:
                return _ctx("alg: ", se)
            if (alg is _UNDEF or alg == "ed25519") and (_g(p, "pq_pk") is not _UNDEF or _g(p, "pq_sig") is not _UNDEF):
                return "an ed25519 profile must not carry pq_pk / pq_sig"
            if not isinstance(_g(p, "sig"), str):
                return "sig must be a string"
        canonical_bytes_strict(_profile_body(p))
        return None
    except Exception as e:  # noqa: BLE001
        return "malformed profile: %s" % e


def _profile_body(p: dict) -> dict:
    b = {k: p[k] for k in ("v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation") if k in p}
    if "prev" in p and p["prev"] is not _UNDEF:
        b["prev"] = p["prev"]
    return b


def _message(body: dict) -> bytes:
    return INTENT_PROFILE_SIG_DOMAIN.encode("utf-8") + canonical_bytes_strict(body)


def sign_intent_profile(body: dict, owner_secret: bytes, suite: Any = None) -> dict:
    """Sign a profile version as its owner (the owner identity must be the signer's Ed25519 key)."""
    if suite is not None and suite.get("alg") not in (None, "ed25519"):
        raise ValueError("signIntentProfile: only Ed25519 signing is supported natively")
    owner = b64u(ed25519.public_key(owner_secret))
    if "owner" in body and body["owner"] != owner:
        raise ValueError("signIntentProfile: owner does not match the signing key")
    b = _profile_body({**body, "owner": owner})
    bad = intent_profile_shape_error(b, signed=False)
    if bad:
        raise ValueError("signIntentProfile: %s" % bad)
    return {**b, "sig": b64u(ed25519.sign_secret(owner_secret, _message(b)))}


def _pins_of(pin: Any) -> Optional[dict]:
    pq = pin.get("pqPins") if isinstance(pin, dict) else None
    return pq if isinstance(pq, dict) else None


def verify_intent_profile(p: Any, pin: Any = None) -> dict:
    try:
        bad = intent_profile_shape_error(p)
        if bad:
            return {"ok": False, "reason": bad}
        body = _bind_suite_fields(_profile_body(p), _g(p, "alg"), _g(p, "pq_pk"))
        err = _pinned_suite_error(_g(p, "alg"), p["owner"], _g(p, "pq_pk"), _message(body), p["sig"], _g(p, "pq_sig"), _pins_of(pin))
        if err is not None:
            return {"ok": False, "reason": "profile signature invalid"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "malformed profile: %s" % e}


def intent_profile_digest(p: dict) -> str:
    """The content address of a signed profile version."""
    return hash_canonical({"d": INTENT_PROFILE_REF_DOMAIN, "p": p})


def verify_profile_succession(prev: Any, nxt: Any) -> dict:
    """Append-only succession: same id and owner, version + 1, prev = digest(previous)."""
    for x, n in ((prev, "previous"), (nxt, "next")):
        v = verify_intent_profile(x)
        if not v["ok"]:
            return {"ok": False, "reason": "%s version: %s" % (n, v["reason"])}
    if nxt["profile_id"] != prev["profile_id"] or nxt["owner"] != prev["owner"]:
        return {"ok": False, "reason": "a profile version cannot change its id or owner"}
    if nxt["version"] != prev["version"] + 1:
        return {"ok": False, "reason": "versions are append-only: next.version must be previous + 1"}
    if _g(nxt, "prev") != intent_profile_digest(prev):
        return {"ok": False, "reason": "next.prev is not the digest of the previous version"}
    return {"ok": True}


def _lt(a: Any, b: Any) -> bool:
    ok = lambda x: isinstance(x, (int, float)) and not isinstance(x, bool)  # noqa: E731
    return ok(a) and ok(b) and a < b


def _truthy_list(x: Any) -> bool:
    return x is not _UNDEF and x is not None


def profile_applies(p: dict, u: dict) -> bool:
    """Is the profile in scope (and unexpired) for this action?"""
    if not _lt(u.get("now"), p["expires_at"]):
        return False
    scope = p["scope"]
    sites, verbs, sem = _g(scope, "sites"), _g(scope, "verbs"), _g(scope, "semantic_types")
    if _truthy_list(sites) and not any(_js_strict_eq(x, _g(u, "aud")) for x in sites):
        return False
    if _truthy_list(verbs) and not any(_js_strict_eq(x, _g(u, "verb")) for x in verbs):
        return False
    if _truthy_list(sem):
        sems = _g(u, "semantics")
        sems = [] if sems is _UNDEF or sems is None else sems
        if not any(any(_js_strict_eq(t, s) for t in sem) for s in sems):
            return False
    return True


def standing_admits(p: dict, u: dict, action: Any) -> bool:
    """G^std membership: an in-scope action is outside the standing layer iff a deny rule matches it (deny wins)."""
    if not profile_applies(p, u):
        return True
    return not any(predicate_matches(r, action) for r in p["standing"]["deny"])


def standing_permits(p: dict, u: dict, action: Any) -> bool:
    """The explicit standing-permission layer: an in-scope permit rule matches (the only positive import)."""
    return profile_applies(p, u) and any(predicate_matches(r, action) for r in p["standing"]["permit"])


def profile_veto_cells(p: dict, omega: dict) -> List[dict]:
    """The cells that the profile's negative observations veto."""
    out: List[dict] = []
    seen: set = set()
    for o in p["prior"]["observations"]:
        if o["y"] != 0:
            continue
        vs = next((v for v in omega["verbs"] if v["verb"] == o["verb"]), None)
        cell = cell_of(vs, {"verb": o["verb"], "values": o["values"]}) if vs else None
        if vs is None or cell is None:
            continue
        k = "%s|%s" % (o["verb"], ",".join(str(i) for i in cell))
        if k not in seen:
            seen.add(k)
            out.append({"verb": o["verb"], "cell": cell})
    return out


def profile_ceiling(p: dict, u: dict):
    """A ceiling function (for a visit decision) from the profile's standing deny rules over outcomes."""
    def ceiling(vs: dict, o: dict) -> bool:
        a = outcome_to_action(vs, o)
        ctx: Dict[str, Any] = {"action": {"verb": a["verb"], "resource": a["resource"], "params": a["params"]}}
        if a.get("env"):
            ctx["env"] = a["env"]
        if a.get("subject"):
            ctx["subject"] = a["subject"]
        return standing_admits(p, {**u, "verb": o["verb"]}, ctx)
    return ceiling


def profile_usable(p: Any, c: dict) -> dict:
    """Is this profile version usable now: signed, unexpired, and not revoked per a fresh epoch of its revocation authority."""
    v = verify_intent_profile(p, c.get("pin"))
    if not v["ok"]:
        return v
    if not _lt(c.get("now"), p["expires_at"]):
        return {"ok": False, "reason": "the profile has expired"}
    rev = p["revocation"]
    authority = rev["key"] if _g(rev, "key") is not _UNDEF and rev["key"] is not None else p["owner"]
    r = check_session_revocation(c.get("revocation", _UNDEF), session=p["profile_id"], scope=profile_revocation_scope(p["profile_id"]),
                                 authority=authority, ids=[profile_revocation_id(p["profile_id"], p["version"])], now=c.get("now", _UNDEF),
                                 max_age_ms=c.get("maxAgeMs", _UNDEF), pq_pins=_pins_of(c.get("pin")), last=c.get("last", _UNDEF))
    return {"ok": True} if r["ok"] else {"ok": False, "reason": "profile revocation: %s" % r["reason"]}
