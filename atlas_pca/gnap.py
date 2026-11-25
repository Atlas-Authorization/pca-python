"""GNAP (RFC 9635) bridge for Proof-Carrying Authority: access rights <-> PCA predicates, a grant request -> an attenuated, key-bound
capability chain, action authorization over the chain, bound access tokens, the `jwsd` detached-JWS key proof (sign / verify, with a
replay store), continuation / step-up through threshold co-signatures, and the interaction modes (start modes, finish methods, the
interaction hash, the AS interaction state machine). Mirrors the TypeScript reference (@atlasauth/pca-gnap). Options and arguments are
dicts keyed in snake_case (wire members of GNAP messages keep their RFC names); a signing secret is the 32-byte Ed25519 seed (bytes);
`now` is epoch milliseconds, except the interaction server's clock, which returns seconds. Ed25519 signing uses the optional
``cryptography`` package (see ``atlas_pca.ed25519``). Every verification fails closed.

An argument the reference reads as ``undefined`` is an absent dict key here, and a JSON null is None (the two differ where the
reference tells them apart). Functions with a trailing optional parameter that can be null use a private sentinel for "absent"."""
from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
import time
from typing import Any, Dict, List, Optional
from urllib.parse import unquote_to_bytes

from . import ed25519
from ._fin import fin
from .agent import DEFAULT_RISK_POLICY, KeyPair, build_pcactn, delegate, mint_grant
from .attest_common import js_str
from .authorize import read_envelope
from .dpop import _js_len, _utf8
from .oauth import _SPECIAL, _parse_url, _pct, _truthy
from .pca import (
    PQ_PK_LENGTHS,
    _SIG_SUITES,
    _verify_b64u,
    b64u,
    canonical_bytes_strict,
    canonicalize_strict,
    decode_b64u_strict,
    hash_canonical,
    sha256,
    strict_parse,
    utf8 as _pca_utf8,
    threshold_message,
    unb64u,
    verify_chain,
    verify_leaf_suite,
)
from .predicates import evaluate_predicates
from .sdjwt_jws import CanonicalJwsError, assert_canonical_jws_segments, js_json, js_json_bytes, js_json_parse, js_to_string

_UNDEF = object()  # a JavaScript `undefined` read
_UNSET = object()  # an optional argument that was not passed
ABSENT = _UNSET  # gnap_content_digest(ABSENT): a request that carries no content


class GnapError(Exception):
    """A malformed request on an issuance path (the verification paths return a refusal value instead)."""


GNAP_GRANT_CAVEAT = "gnap_grant"
GNAP_ACCESS_CAVEAT = "gnap_access"
GNAP_RESOURCE_PREFIX = "gnap"
MAX_DETACHED_JWS_CHARS = 8192
JWSD_TYP = "gnap-binding-jwsd"


def _prop(o: Any, k: str) -> Any:
    """`o.k` in JavaScript: a read of null raises, a non-object has no members."""
    if o is None:
        raise TypeError("cannot read properties of null (reading '%s')" % k)
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def _is_obj(x: Any) -> bool:
    """typeof x === 'object' && x !== null (arrays included)."""
    return isinstance(x, (dict, list))


def _def(v: Any) -> Any:
    return None if v is _UNDEF else v


def _str_arr(u: Any) -> Optional[List[str]]:
    return [s for s in u if isinstance(s, str)] if isinstance(u, list) else None


def _as_ed25519(x: Any) -> Optional[str]:
    return x if isinstance(x, str) and decode_b64u_strict(x, 32) is not None else None


def _now_ms() -> int:
    return int(time.time() * 1000)


def gnap_action_resource(type_: Any, location: Any) -> str:
    """The PCA resource string for a GNAP (type, location) pair: gnap:<type>:<location>."""
    return "%s:%s:%s" % (GNAP_RESOURCE_PREFIX, js_to_string(type_), js_to_string(location))


# ---- access rights ---------------------------------------------------------------------------------------------------------------

def _try_normalize_access_item(item: Any) -> Optional[Dict[str, Any]]:
    if isinstance(item, str):
        return {"type": item} if len(item) > 0 else None
    if not isinstance(item, dict):
        return None
    type_ = item.get("type")
    if not isinstance(type_, str) or len(type_) == 0:
        return None
    out: Dict[str, Any] = {"type": type_}
    for k in ("actions", "locations", "datatypes"):
        v = _str_arr(item.get(k))
        if v:
            out[k] = v
    if isinstance(item.get("identifier"), str):
        out["identifier"] = item["identifier"]
    privileges = _str_arr(item.get("privileges"))
    if privileges:
        out["privileges"] = privileges
    return out


def normalize_access(items: Any) -> List[Dict[str, Any]]:
    """Normalize an access array for issuance; raises GnapError on any malformed entry."""
    if not isinstance(items, list):
        raise GnapError("access must be an array")
    out = []
    for item in items:
        n = _try_normalize_access_item(item)
        if n is None:
            raise GnapError("malformed access item (needs a non-empty string `type`)")
        out.append(n)
    return out


def _read_access_array(u: Any) -> List[Dict[str, Any]]:
    """A stored access array (signed caveats), read totally: malformed entries are skipped."""
    if not isinstance(u, list):
        return []
    return [n for n in (_try_normalize_access_item(i) for i in u) if n is not None]


def access_to_predicates(access: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One PCA predicate per location: `type` namespaces the resource, `actions` are the verbs, `datatypes` / `identifier` are `where`
    conditions on the action params. Absent `actions` / `locations` mean any (verb `*` / the `*` resource)."""
    actions = access.get("actions")
    verb: Any = list(actions) if actions is not None and len(actions) > 0 else "*"
    locs = access.get("locations")
    locations = locs if locs is not None and len(locs) > 0 else ["*"]
    where: List[Dict[str, Any]] = []
    dts = access.get("datatypes")
    if dts is not None and len(dts) > 0:
        where.append({"field": "action.params.datatype", "op": "in", "value": list(dts)})
    if isinstance(access.get("identifier"), str):
        where.append({"field": "action.params.identifier", "op": "eq", "value": access["identifier"]})
    out = []
    for loc in locations:
        p: Dict[str, Any] = {"verb": list(verb) if isinstance(verb, list) else verb, "resource": gnap_action_resource(access.get("type"), loc)}
        if where:
            p["where"] = [dict(c) for c in where]
        out.append(p)
    return out


def _access_array_to_predicates(access: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [p for a in access for p in access_to_predicates(a)]


def _covers_strings(sup: Any, sub: Any) -> bool:
    if sup is None:
        return True  # the issuer allows all
    if sub is None:
        return False  # the request wants all, the issuer has a concrete set
    return all(s in sup for s in sub)


def _covers_locations(sup: Any, sub: Any) -> bool:
    if sup is None:
        return True
    if sub is None:
        return "*" in sup
    return all(any(g == s or g == "*" or (g.endswith("*") and s.startswith(g[:-1])) for g in sup) for s in sub)


def access_contains(g: Dict[str, Any], r: Dict[str, Any]) -> bool:
    """Does the issuer's granted right `g` fully contain the requested right `r`?"""
    if g.get("type") != r.get("type"):
        return False
    if not _covers_strings(g.get("actions"), r.get("actions")):
        return False
    if not _covers_locations(g.get("locations"), r.get("locations")):
        return False
    if not _covers_strings(g.get("datatypes"), r.get("datatypes")):
        return False
    if r.get("identifier") is not None and g.get("identifier") is not None and g["identifier"] != r["identifier"]:
        return False
    return True


def access_within(granted: List[Dict[str, Any]], r: Dict[str, Any]) -> bool:
    return any(access_contains(g, r) for g in granted)


def clamp_access(issuer_granted: List[Dict[str, Any]], requested: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Split a requested access array into the subset within the issuer's authority and the rest."""
    granted, dropped = [], []
    for r in requested:
        (granted if access_within(issuer_granted, r) else dropped).append(r)
    return {"granted": granted, "dropped": dropped}


# ---- provenance caveats ----------------------------------------------------------------------------------------------------------

def _read_gnap_grant(root: Any) -> Optional[Dict[str, Any]]:
    env = read_envelope(root)
    cv = next((c for c in env["caveats"] if isinstance(c, dict) and c.get("type") == GNAP_GRANT_CAVEAT), None) if env else None
    if not cv:
        return None
    client_id, digest = cv.get("client_id"), cv.get("request_digest")
    if not isinstance(client_id, str) or not isinstance(digest, str):
        return None
    ts = cv.get("ts")
    return {"type": GNAP_GRANT_CAVEAT, "client_id": client_id, "granted_access": _read_access_array(cv.get("granted_access")),
            "request_digest": digest, "interacted": cv.get("interacted") is True,
            "ts": ts if isinstance(ts, (int, float)) and not isinstance(ts, bool) else 0}


def granted_access_of(chain: Any) -> List[Dict[str, Any]]:
    """The effective granted access of a chain: the most recent delegated hop's recorded rights, or the root's."""
    if not isinstance(chain, list) or len(chain) == 0:
        return []
    leaf = chain[-1]
    caveats = _prop(leaf, "caveats")
    caveats = caveats if isinstance(caveats, list) else []
    for cv in reversed(caveats):
        if isinstance(cv, dict) and cv.get("type") == GNAP_ACCESS_CAVEAT:
            return _read_access_array(cv.get("access"))
    grant = _read_gnap_grant(chain[0])
    return grant["granted_access"] if grant else []


# ---- holder resolution -----------------------------------------------------------------------------------------------------------

def resolve_holder(req: Any, holder_override: Any = _UNSET) -> str:
    """The b64u Ed25519 holder key of a request's client key, or an explicit override (None is an override and is refused). The
    client key proof method must be `jwsd`: a declared other method is refused even with an override."""
    client = _prop(req, "client")
    declared = _prop(client, "key") if _is_obj(client) else _UNDEF
    if _is_obj(declared):
        proof = _prop(declared, "proof")
        method = proof if isinstance(proof, str) else (proof.get("method", _UNDEF) if isinstance(proof, dict) else _UNDEF)
        if method != "jwsd":
            raise GnapError("unsupported client key proof method: %s (only jwsd is supported)" % (method if isinstance(method, str) else "none"))
    if holder_override is not _UNSET:
        h = _as_ed25519(holder_override)
        if h is None:
            raise GnapError("holder override is not a canonical base64url Ed25519 public key")
        return h
    key = _prop(client, "key") if _is_obj(client) else _UNDEF
    if isinstance(key, dict):
        jwk = key.get("jwk")
        if isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            x = _as_ed25519(jwk.get("x"))
            if x is not None:
                return x
    raise GnapError("cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override")


def holder_jwk(holder: Any) -> Dict[str, Any]:
    """The holder key rendered as a GNAP JWK."""
    return {"kty": "OKP", "crv": "Ed25519", "x": holder, "use": "sig", "alg": "EdDSA"}


def _access_of(req: Any) -> list:
    at = _prop(req, "access_token")
    if isinstance(at, dict) and isinstance(at.get("access"), list):
        return at["access"]
    raise GnapError("grant request must carry access_token.access (single-token request)")


def _request_digest_of(holder: str, granted: List[Dict[str, Any]], interact: Any) -> str:
    return hash_canonical({"d": "atlas-pca/gnap/request/v1", "client_id": holder, "access": granted, "interact": None if interact is _UNDEF else interact})


# ---- grant request -> capability -------------------------------------------------------------------------------------------------

def grant_request_to_capability(req: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a GNAP grant request into a PCA capability bound to the client key and attenuated to never exceed the issuer. With no
    `parent` this mints a root grant whose envelope predicates ARE the requested rights; with a `parent` it delegates a narrower hop
    that records the clamped rights as an append-only `gnap_access` caveat. Options: issuer_secret (32-byte seed), issuer_public,
    parent, issuer_chain, clamp_to_issuer (default True), holder, interacted, now, and for a root grant goal, risk_policy,
    agent_binding, salt. Returns {grant, chain, holder, granted_access, dropped_access, provenance}."""
    holder = resolve_holder(req, opts["holder"] if "holder" in opts else _UNSET)
    requested = normalize_access(_access_of(req))
    now_v = opts.get("now")
    now = math.floor(_now_ms() if now_v is None else now_v)
    interacted = opts.get("interacted") is True
    granted, dropped = requested, []
    parent = opts.get("parent")
    if _truthy(parent):
        issuer_chain = opts.get("issuer_chain")
        issuer_chain = [parent] if issuer_chain is None else issuer_chain
        if opts.get("clamp_to_issuer") is not False:
            split = clamp_access(granted_access_of(issuer_chain), requested)
            granted, dropped = split["granted"], split["dropped"]
    request_digest = _request_digest_of(holder, granted, _prop(req, "interact"))
    signer = KeyPair(opts.get("issuer_secret"))
    if _truthy(parent):
        provenance: Dict[str, Any] = {"type": GNAP_ACCESS_CAVEAT, "access": granted, "predicates": _access_array_to_predicates(granted),
                                      "request_digest": request_digest, "client_id": holder, "ts": now}
        child = delegate(parent, signer, holder, [provenance])
        return {"grant": child, "chain": list(issuer_chain) + [child], "holder": holder, "granted_access": granted,
                "dropped_access": dropped, "provenance": provenance}
    provenance = {"type": GNAP_GRANT_CAVEAT, "client_id": holder, "granted_access": granted, "request_digest": request_digest,
                  "interacted": interacted, "ts": now}
    if opts.get("issuer_public") is not None:
        signer.public = opts["issuer_public"]  # the issuer id is the stated public key, as the reference takes it
    goal = opts.get("goal")
    risk = opts.get("risk_policy")
    binding = opts.get("agent_binding")
    minted = mint_grant(signer, holder, {"predicates": _access_array_to_predicates(granted), "caveats": [provenance],
                                          "agent_binding": {} if binding is None else binding,
                                          "risk_policy": DEFAULT_RISK_POLICY if risk is None else risk},
                        "gnap:grant:%s" % holder if goal is None else goal, opts.get("salt"))
    grant = minted["grant"]
    return {"grant": grant, "chain": [grant], "holder": holder, "granted_access": granted, "dropped_access": dropped, "provenance": provenance}


# ---- action authorization --------------------------------------------------------------------------------------------------------

class _Never:
    """An expected root issuer that equals nothing (the reference treats an explicit null as an expectation nothing meets)."""

    def __eq__(self, other: Any) -> bool:
        return False

    def __ne__(self, other: Any) -> bool:
        return True

    __hash__ = None  # type: ignore[assignment]


def _chain_args(opts: Dict[str, Any]) -> Dict[str, Any]:
    expected = opts.get("expected_root_issuer", _UNSET)
    return {"expected_root_issuer": None if expected is _UNSET else _Never() if expected is None else expected, "pq_pins": opts.get("pq_pins")}


def authorize_gnap_action(chain: Any, action: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Is `action` authorized by a GNAP-issued chain? The chain must verify, the root envelope must permit the action, and every
    delegated hop's recorded rights must permit it too. Fails closed. Options: expected_root_issuer, pq_pins. Returns {allowed, reason?}."""
    opts = opts or {}
    if not isinstance(chain, list) or len(chain) == 0:
        return {"allowed": False, "reason": "empty chain"}
    ok, reason = verify_chain(chain, **_chain_args(opts))
    if not ok:
        return {"allowed": False, "reason": "capability chain invalid: %s" % (reason if reason is not None else "unknown")}
    env = read_envelope(chain[0])
    if not env:
        return {"allowed": False, "reason": "root grant carries no policy envelope"}
    act: Dict[str, Any] = {}
    for k in ("verb", "resource", "params", "reversibility_class"):
        v = _prop(action, k)
        if v is not _UNDEF:
            act[k] = v
    ctx = {"action": act}
    root_decision = evaluate_predicates(env["predicates"], ctx)
    if not root_decision.get("allowed"):
        r = root_decision.get("reason")
        return {"allowed": False, "reason": "root authority denies: %s" % (r if r is not None else "no predicate matched")}
    caveats = _prop(chain[-1], "caveats")
    for cv in caveats if isinstance(caveats, list) else []:
        if not (isinstance(cv, dict) and cv.get("type") == GNAP_ACCESS_CAVEAT):
            continue
        hop = evaluate_predicates(_access_array_to_predicates(_read_access_array(cv.get("access"))), ctx)
        if not hop.get("allowed"):
            r = hop.get("reason")
            return {"allowed": False, "reason": "delegated hop denies: %s" % (r if r is not None else "no predicate matched")}
    return {"allowed": True}


# ---- bound token -----------------------------------------------------------------------------------------------------------------

def encode_bound_token(chain: Any) -> str:
    """A capability chain as a GNAP access-token value: base64url(JSON.stringify(chain))."""
    return b64u(_utf8(js_json(chain)))


def _is_capability_shape(x: Any) -> bool:
    if not isinstance(x, dict):
        return False
    return (isinstance(x.get("id"), str) and isinstance(x.get("issuer"), str) and isinstance(x.get("holder"), str)
            and isinstance(x.get("body_digest"), str) and isinstance(x.get("sig"), str) and isinstance(x.get("caveats"), list)
            and all(k not in x or isinstance(x[k], str) for k in ("parent", "alg", "pq_pk", "pq_sig")))


def _decode_bound_token(value: str) -> Optional[List[Dict[str, Any]]]:
    """A bound token back into a chain; None on any deviation (a leading byte-order mark is dropped by the reference's decoder)."""
    try:
        text = unb64u(value).decode("utf-8")
        if text.startswith("﻿"):
            text = text[1:]
        parsed = strict_parse(text)
        if not isinstance(parsed, list):
            return None
        chain = []
        for hop in parsed:
            if not _is_capability_shape(hop):
                return None
            chain.append(hop)
        return chain
    except Exception:  # noqa: BLE001 - total: any deviation is a refusal
        return None


def capability_to_grant_response(chain: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Render a (verified) chain as a GNAP grant response with a bound access token. Options: expires_in, bearer, instance_id,
    manage_uri, continue (a continuation handle); a present key counts even when its value is None, as in the reference."""
    opts = opts or {}
    if not isinstance(chain, list) or len(chain) == 0:
        raise GnapError("capabilityToGrantResponse: empty chain")
    leaf = chain[-1]
    token: Dict[str, Any] = {"value": encode_bound_token(chain), "access": granted_access_of(chain),
                             "key": False if opts.get("bearer") is True else holder_jwk(_def(_prop(leaf, "holder")))}
    if "expires_in" in opts:
        token["expires_in"] = opts["expires_in"]
    if "manage_uri" in opts:
        token["manage"] = {"uri": opts["manage_uri"]}
    out: Dict[str, Any] = {"access_token": token}
    if "continue" in opts:
        out["continue"] = opts["continue"]
    if "instance_id" in opts:
        out["instance_id"] = opts["instance_id"]
    return out


def verify_gnap_token(value: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Verify an incoming bound token back to a PCA principal + capability. Fails closed: {ok: False, reason} for a token that is not
    a decodable chain or whose chain does not verify. Options: expected_root_issuer, pq_pins."""
    opts = opts or {}
    if not isinstance(value, str) or len(value) == 0:
        return {"ok": False, "reason": "token value is empty"}
    chain = _decode_bound_token(value)
    if chain is None or len(chain) == 0:
        return {"ok": False, "reason": "token is not a decodable PCA capability chain"}
    ok, reason = verify_chain(chain, **_chain_args(opts))
    if not ok:
        return {"ok": False, "reason": "capability chain invalid: %s" % (reason if reason is not None else "unknown")}
    return {"ok": True, "principal": chain[0]["issuer"], "capability": chain[-1], "chain": chain, "access": granted_access_of(chain)}


# ---- jwsd: key-bound requests ---------------------------------------------------------------------------------------------------

def _ath_of(token: Any) -> str:
    return b64u(sha256(_utf8(js_to_string(token))))


def _to_plain(value: Any) -> Any:
    return js_json_parse(js_json(value))


def gnap_content_digest(body: Any = ABSENT) -> bytes:
    """The jwsd JWS payload (RFC 9635 7.3.3): SHA-256 of the request CONTENT, or nothing when there is none (ABSENT). A str / bytes is
    the exact content, hashed as is; any other value is hashed as its strict canonical JSON (the content the sender must send)."""
    if body is ABSENT:
        return b""
    if isinstance(body, str):
        return sha256(_utf8(body))
    if isinstance(body, (bytes, bytearray)):
        return sha256(bytes(body))
    return sha256(_utf8(canonicalize_strict(_to_plain(body))))


class HashArgError(TypeError):
    """The reference's Node ERR_INVALID_ARG_TYPE for a hash method that names an inherited object member."""
    code = "ERR_INVALID_ARG_TYPE"


class GnapKeyError(ValueError):
    """A client key Node cannot import as a JWK (its ERR_CRYPTO_INVALID_JWK)."""
    code = "ERR_CRYPTO_INVALID_JWK"


def sign_gnap_request(args: Dict[str, Any]) -> Dict[str, Any]:
    """A GNAP `jwsd` detached-JWS proof over `body`, signed by the client key. Arguments: body (omit for no content), key
    ({"secret_key": 32-byte seed, "public_key": 32 bytes}), htm, uri, created (epoch SECONDS, default now), kid, access_token_value.
    Returns {detached_jws, header, holder}."""
    created = args.get("created")
    created = int(time.time()) if created is None else created
    key = args["key"]
    if len(bytes(key["secret_key"])) != 32:
        raise GnapKeyError("Invalid JWK OKP key")
    holder = b64u(key["public_key"])
    header: Dict[str, Any] = {"alg": "EdDSA", "typ": JWSD_TYP, "htm": args["htm"].upper(), "uri": args["uri"], "created": created}
    if "kid" in args:
        header["kid"] = args["kid"]
    if "access_token_value" in args:
        header["ath"] = _ath_of(args["access_token_value"])
    payload = gnap_content_digest(args["body"] if "body" in args else ABSENT)
    protected = b64u(js_json_bytes(header))
    sig = ed25519.sign_secret(bytes(key["secret_key"]), ("%s.%s" % (protected, b64u(payload))).encode("ascii"))
    return {"detached_jws": "%s..%s" % (protected, b64u(sig)), "header": header, "holder": holder}


def _jws_header_ok(header: Dict[str, Any]) -> None:
    """The JOSE library's flattened-verify header rules that apply here: `crit` (only b64 is recognised), a boolean b64, a string alg."""
    if "crit" in header:
        crit = header["crit"]
        if not isinstance(crit, list) or len(crit) == 0 or any(not isinstance(c, str) or c == "" for c in crit):
            raise ValueError("crit")
        for p in crit:
            if p != "b64" or "b64" not in header:
                raise ValueError("crit")
        if not isinstance(header.get("b64"), bool):
            raise ValueError("b64")
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise ValueError("alg")


def verify_gnap_request(args: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a `jwsd` detached-JWS proof and bind the request to the holder key. Fails closed on a bad signature, a tampered body, a
    wrong holder, a mismatched htm / uri, a stale or future `created`, an `ath` that does not bind the named token, or a replay.
    Arguments: detached_jws, body (omit for no content), holder, htm, uri, max_age_sec (300), now (ms), access_token_value, and a
    replay store `seen_proof(proof_id, expires_sec) -> bool` (True = already seen), REQUIRED unless replay_check == "unchecked"
    (without either this raises GnapError). Returns {ok: True, holder, header} or {ok: False, reason}."""
    def fail(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}
    seen_proof = args.get("seen_proof")
    if not callable(seen_proof) and args.get("replay_check") != "unchecked":
        raise GnapError("verifyGnapRequest: supply args.seen_proof (a replay store) or set args.replay_check to 'unchecked'")
    detached = args.get("detached_jws")
    if isinstance(detached, str) and _js_len(detached) > MAX_DETACHED_JWS_CHARS:
        return fail("detached JWS exceeds the size limit")
    try:
        parts = detached.split(".")
        if len(parts) != 3:
            return fail("not a compact JWS (expected three dot-separated parts)")
        protected_b64u, mid, signature = parts
        holder = _as_ed25519(args.get("holder"))
        if holder is None:
            return fail("holder is not a canonical base64url Ed25519 public key")
        payload_b64u = b64u(gnap_content_digest(args["body"] if "body" in args else ABSENT))
        if mid != "" and mid != payload_b64u:
            return fail("not a DETACHED compact JWS")
        try:
            assert_canonical_jws_segments(protected_b64u, signature)  # the canonical-spelling gate BEFORE the signature check
        except CanonicalJwsError as e:
            return fail("non-canonical detached JWS: %s" % e)
        try:
            header = assert_canonical_jws_segments(protected_b64u, signature)
            _jws_header_ok(header)
            if header.get("alg") != "EdDSA":
                raise ValueError("alg")
            sig = decode_b64u_strict(signature)
            if sig is None or not ed25519.verify(decode_b64u_strict(holder), ("%s.%s" % (protected_b64u, payload_b64u)).encode("ascii"), sig):
                raise ValueError("signature")
        except Exception:  # noqa: BLE001
            return fail("jwsd signature does not verify under the holder key (or body was tampered)")
        if header.get("typ") != JWSD_TYP:
            return fail("unexpected typ (not gnap-binding-jwsd)")
        htm = header.get("htm")
        if not isinstance(htm, str) or htm.upper() != args["htm"].upper():
            return fail("htm does not match the request method")
        uri = header.get("uri")
        if not isinstance(uri, str) or uri != args["uri"]:
            return fail("uri does not match the request target")
        created = header.get("created")
        if isinstance(created, bool) or not isinstance(created, (int, float)) or not fin(created):
            return fail("missing or malformed created")
        now_v = args.get("now")
        now_raw = _now_ms() if now_v is None else now_v
        now_sec = math.floor(now_raw / 1000) if fin(now_raw) else math.nan
        max_age_v = args.get("max_age_sec")
        max_age = 300 if max_age_v is None else max_age_v
        if not (fin(now_sec) and created <= now_sec + 60):
            return fail("created is in the future")
        if not (fin(max_age) and now_sec - created <= max_age):
            return fail("jwsd proof is stale")
        ath = header.get("ath")
        if "access_token_value" in args:
            if not isinstance(ath, str) or ath != _ath_of(args["access_token_value"]):
                return fail("ath does not bind the named access token")
        if callable(seen_proof):
            try:
                replayed = seen_proof(_ath_of(detached), created + max_age) is not False
            except Exception:  # noqa: BLE001 - a store failure refuses
                replayed = True
            if replayed:
                return fail("jwsd proof replayed (or the replay store failed)")
        out: Dict[str, Any] = {"alg": "EdDSA", "typ": JWSD_TYP, "htm": htm, "uri": uri, "created": created}
        if isinstance(header.get("kid"), str):
            out["kid"] = header["kid"]
        if isinstance(ath, str):
            out["ath"] = ath
        return {"ok": True, "holder": holder, "header": out}
    except Exception:  # noqa: BLE001 - total: anything unexpected is a refusal
        return fail("malformed jwsd request")


# ---- threshold shares (the step-up co-signature carrier) ------------------------------------------------------------------------

_SIGNER_SET_DOMAIN = b"atlas-pca/signerset/v1\x00"
_ROLES = ("agent", "guardian", "principal")


def _valid_t(t: Any) -> bool:
    return not isinstance(t, bool) and isinstance(t, (int, float)) and t in (1, 2, 3)


def _signer_set_hash(signer_set: Any) -> bytes:
    """The signer-set hash exactly as the reference computes it, lenient on a malformed set (it hashes what is there)."""
    rows = []
    for s in signer_set if isinstance(signer_set, list) else []:
        row = {"publicKey": js_to_string(s.get("publicKey", "undefined")) if isinstance(s, dict) and "publicKey" in s else "undefined",
               "role": js_to_string(s["role"]) if isinstance(s, dict) and "role" in s else "undefined"}
        if isinstance(s, dict) and isinstance(s.get("pq_pk"), str):
            row["pq_pk"] = s["pq_pk"]
        rows.append(row)
    rows.sort(key=lambda r: (_pca_utf8(r["role"]), _pca_utf8(r["publicKey"])))
    return sha256(_SIGNER_SET_DOMAIN + canonical_bytes_strict(rows))


def _share_message(role: str, message: bytes, signer_set: Any, t: Any, alg: Any = None) -> bytes:
    if not _valid_t(t):
        raise ValueError("shareMessage: t must be 1, 2 or 3")
    tag = b""
    if isinstance(alg, str) and alg != "ed25519" and alg in _SIG_SUITES:
        tag = ("\x00atlas-pca/share-suite/v1\x00" + alg).encode("utf-8")
    return _utf8("atlas-pca/share/%s\x00" % js_to_string(role)) + sha256(message) + _signer_set_hash(signer_set) + bytes([int(t)]) + tag


def _sign_share(role: Any, secret: Any, message: bytes, signer_set: Any, t: Any) -> Dict[str, Any]:
    msg = _share_message(role, message, signer_set, t)
    seed = bytes(secret)
    if len(seed) != 32:
        raise ValueError("an Ed25519 secret is a 32-byte seed")
    return {"role": role, "publicKey": b64u(ed25519.public_key(seed)), "sig": b64u(ed25519.sign_secret(seed, msg))}


def _is_pq_pk(v: Any) -> bool:
    if not isinstance(v, str):
        return False
    raw = decode_b64u_strict(v)
    return raw is not None and len(raw) in PQ_PK_LENGTHS


def _show(v: Any) -> str:
    return ("<array>" if isinstance(v, list) else "<object>") if isinstance(v, (list, dict)) else js_to_string(v)


def _baseline_ok(b: Dict[str, Any], message: bytes, registered_pq: Optional[str]) -> bool:
    """The agent-leaf baseline's PQ-key rule (F-2) and its leaf signature over the bare threshold message."""
    from .pca import _PinnedPq, _resolve_pq_key, _resolve_suite, _verify_suite, _SIG_SUITES, pq_binding_error
    try:
        p = {k: b[k] for k in ("alg", "sig", "pq_pk", "pq_sig") if k in b}
        suite = _resolve_suite(p)[0]
        has_pq = suite is not None and suite != "ed25519" and _SIG_SUITES[suite][1]
        if registered_pq is not None:
            if not has_pq:  # R6-02: an agent with a registered pq_pk needs a PQ / hybrid leaf
                return False
            pq = _resolve_pq_key(b["holder"], None, trusted_pk=registered_pq)
        else:
            if pq_binding_error(b.get("alg"), b.get("pq_pk"), b.get("holder_pq"), "threshold baseline") is not None:
                return False
            pq = _resolve_pq_key(b["holder"], b.get("pq_pk"), holder_pq=b.get("holder_pq"))
        return _verify_suite(p, b["holder"], message, pq)
    except Exception:  # noqa: BLE001 - total
        return False


def _verify_threshold(sig: Any, message: bytes, signer_set: Any, t: Any, baseline: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A t-of-n multi-signature check: the signer set is validated first (known roles, one key per role, one role per key, well-formed
    keys), then the DISTINCT registered keys with a valid role / signer-set / t-bound share are counted; the verdict is
    {ok, count, roles, reason?}. Deterministic and total.

    `baseline` (the reference's AgentLeafBaseline: ``holder``, ``sig``, ``alg``, ``pq_pk``, ``pq_sig``, ``holder_pq``) admits the PCActn's own
    leaf signature over the bare `message` as the agent's effective-t=1 share: it counts only when its holder is the registered ``agent`` key
    and that key is not already satisfied by an explicit share."""
    st = list(signer_set) if isinstance(signer_set, list) else []
    reg: Dict[str, str] = {}  # role -> key
    pq_of_role: Dict[str, Optional[str]] = {}
    seen_entry: Dict[Any, Optional[str]] = {}
    tt = int(t) if _valid_t(t) else -1
    if tt not in (1, 2, 3):
        return {"ok": False, "count": 0, "roles": [], "reason": "invalid threshold t=%s (must be 1, 2 or 3)" % _show(t)}
    for i, s in enumerate(st):
        role = s.get("role") if isinstance(s, dict) else None
        role = role if isinstance(role, str) and role in _ROLES else None
        key_ok = isinstance(s, dict) and decode_b64u_strict(s.get("publicKey"), 32) is not None
        pq_ok = not _truthy(s) or not isinstance(s, dict) or "pq_pk" not in s or _is_pq_pk(s["pq_pk"])
        if role is not None and key_ok and pq_ok:
            ident = (role, s["publicKey"])
            pq = s["pq_pk"] if isinstance(s.get("pq_pk"), str) else None
            if ident in seen_entry and seen_entry[ident] != pq:
                pq_ok = False
            else:
                seen_entry[ident] = pq
        if role is None or not key_ok:
            return {"ok": False, "count": 0, "roles": [], "reason": "malformed signer set"}
        if not pq_ok:
            return {"ok": False, "count": 0, "roles": [], "reason": "malformed signer set (pq_pk)"}
        if role in reg and reg[role] != s["publicKey"]:
            return {"ok": False, "count": 0, "roles": [], "reason": "signer set registers more than one key for role " + _show(s["role"])}
        key_role = next((r for r, k in reg.items() if k == s["publicKey"]), None)
        if key_role is not None and key_role != role:
            return {"ok": False, "count": 0, "roles": [], "reason": "signer set registers one key under two roles"}
        if role not in reg:
            reg[role] = s["publicKey"]
            pq_of_role[role] = s["pq_pk"] if isinstance(s.get("pq_pk"), str) else None
    shares = sig.get("shares") if isinstance(sig, dict) and isinstance(sig.get("shares"), list) else []
    keys: List[str] = []
    roles: List[str] = []
    reason: Optional[str] = None

    def first(r: str) -> None:
        nonlocal reason
        reason = reason or r
    for i, share in enumerate(shares):
        well = isinstance(share, dict) and isinstance(share.get("role"), str) and isinstance(share.get("publicKey"), str)
        if not well:
            first("malformed share")
            continue
        if share["publicKey"] in keys:
            continue
        role = share["role"] if share["role"] in _ROLES else None
        reg_key = reg.get(role) if role is not None else None
        if reg_key is None:
            first("role %s is not in the signer set" % _show(share["role"]))
            continue
        if reg_key != share["publicKey"]:
            first("share for role %s uses a key not registered for that role" % _show(share["role"]))
            continue
        alg = share.get("alg")
        if "alg" in share and not (isinstance(alg, str) and alg in _SIG_SUITES):
            first("share for role %s declares an unknown signature alg" % _show(share["role"]))
            continue
        if "pq_pk" in share and not (isinstance(share["pq_pk"], str) and share["pq_pk"] == pq_of_role.get(role)):
            first("share for role %s names a pq_pk that is not the key its role registers" % _show(share["role"]))
            continue
        try:
            signed = _share_message(share["role"], message, signer_set, tt, alg)
            registered = pq_of_role.get(role)
            if alg is None or alg == "ed25519":
                good = registered is None and isinstance(share.get("sig"), str) and _verify_b64u(share["publicKey"], signed, share["sig"])
            else:
                good = registered is not None and verify_leaf_suite(dict(share, pq_pk=registered), share["publicKey"], signed)
        except Exception:  # noqa: BLE001
            good = False
        if not good:
            first("invalid signature for role %s" % _show(share["role"]))
            continue
        keys.append(share["publicKey"])
        roles.append(role)
    if baseline is not None and "agent" in reg and "agent" not in roles and isinstance(baseline.get("holder"), str) \
            and baseline["holder"] == reg["agent"] and _baseline_ok(baseline, message, pq_of_role.get("agent")):
        keys.append(reg["agent"])
        roles.append("agent")
    count = len(keys)
    if count >= tt:
        return {"ok": True, "count": count, "roles": roles}
    return {"ok": False, "count": count, "roles": roles, "reason": reason or "only %d distinct valid key(s), need %s" % (count, _show(t))}


# ---- continuation -> step-up ---------------------------------------------------------------------------------------------------

def gnap_request_requires_step_up(req: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Does a grant request need a continuation / step-up: when interaction is requested, a higher tier is asked for, or (given the
    issuer's chain) it asks for rights BEYOND the issuer's own authority. Options: issuer_chain, tier. Returns
    {required, reason, beyond, tier}."""
    opts = opts or {}
    beyond: List[Dict[str, Any]] = []
    if _truthy(opts.get("issuer_chain")):
        granted = granted_access_of(opts["issuer_chain"])
        for r in normalize_access(_access_of(req)):
            if not access_within(granted, r):
                beyond.append(r)
    interact = _prop(req, "interact")
    interact_requested = False
    if interact is not _UNDEF:
        start = _prop(interact, "start")
        interact_requested = isinstance(start, list) and len(start) > 0
    tier_in = opts.get("tier")
    tier_gt1 = False
    if not isinstance(tier_in, bool) and isinstance(tier_in, (int, float)):
        tier_gt1 = tier_in > 1
    required = interact_requested or len(beyond) > 0 or tier_gt1
    tier = (3 if beyond else 2) if tier_in is None else tier_in
    if not required:
        reason = "no step-up required"
    elif beyond:
        reason = "requested rights exceed the issuer's authority (%d right(s) beyond)" % len(beyond)
    elif interact_requested:
        reason = "GNAP interaction requested"
    else:
        reason = "tier %s step-up required" % js_to_string(tier)
    return {"required": required, "reason": reason, "beyond": beyond, "tier": tier}


def begin_gnap_continuation(args: Dict[str, Any]) -> Dict[str, Any]:
    """Begin a GNAP continuation: the `continue` handle (a grant response with no token yet) and the step-up it resolves through.
    Arguments: signer_set, t, tier, continue_uri, continue_token, wait, reason. Returns {response, step_up}."""
    cont: Dict[str, Any] = {"uri": args["continue_uri"], "access_token": {"value": args["continue_token"], "bound": True}}
    if "wait" in args:
        cont["wait"] = args["wait"]
    reason = args.get("reason")
    return {"response": {"continue": cont},
            "step_up": {"tier": args["tier"], "t": args["t"], "signer_set": args["signer_set"],
                        "reason": "tier %s co-signature required to continue" % js_to_string(args["tier"]) if reason is None else reason,
                        "continue_token": args["continue_token"]}}


def gnap_step_up_share(body: Dict[str, Any], role: str, secret: bytes, signer_set: Any, t: Any) -> Dict[str, Any]:
    """One role's step-up co-signature share over the action's PCActn body (bound to the signer set and `t`)."""
    return _sign_share(role, secret, threshold_message(body), signer_set, t)


def complete_gnap_continuation(args: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve a continuation: build the action's PCActn (the agent leaf signature), fold the step-up co-signatures into its
    `threshold`, and verify the threshold `t` is reached. Arguments: grant, chain, plan, node_id, params, counter, aud, now, ttl_ms,
    agent_leaf_secret (seed), signer_set, t, cosign_secrets ([{role, secret}]). Returns {pcactn, threshold, verdict}."""
    chain = args.get("chain")
    if not isinstance(chain, list) or len(chain) == 0:
        raise GnapError("completeGnapContinuation: empty chain")
    kw: Dict[str, Any] = {}
    for k in ("params", "now"):
        if k in args:
            kw[k] = args[k]
    if args.get("ttl_ms") is not None:
        kw["ttl_ms"] = args["ttl_ms"]
    pcactn = build_pcactn(args["grant"], chain, args["plan"], args["node_id"], args["counter"], KeyPair(args["agent_leaf_secret"]), args["aud"], **kw)
    message = threshold_message(pcactn)
    agent_share = _sign_share("agent", args["agent_leaf_secret"], message, args["signer_set"], args["t"])
    cosigns = [_sign_share(cs["role"], cs["secret"], message, args["signer_set"], args["t"]) for cs in args["cosign_secrets"]]
    threshold = {"shares": [agent_share] + cosigns}
    verdict = _verify_threshold(threshold, message, args["signer_set"], args["t"])
    return {"pcactn": dict(pcactn, threshold=threshold), "threshold": threshold, "verdict": verdict}


# ---- interaction modes (RFC 9635 sections 2.5, 3.3, 4, 5.1) -------------------------------------------------------------------

START_MODES = ("redirect", "app", "user_code", "user_code_uri")
FINISH_METHODS = ("redirect", "push")
HASH_METHODS = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512", "sha3-256": "sha3_256", "sha3-512": "sha3_512"}
# the names a JavaScript `in` test on the reference's method table also finds (it inherits them from Object.prototype)
_OBJECT_PROTO = frozenset(["constructor", "__defineGetter__", "__defineSetter__", "hasOwnProperty", "__lookupGetter__", "__lookupSetter__",
                           "isPrototypeOf", "propertyIsEnumerable", "toString", "valueOf", "__proto__", "toLocaleString"])
_USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class InteractionError(Exception):
    """An interaction refusal with a stable `code`: invalid_interaction, unknown_interaction, too_many_attempts, invalid_request,
    expired, wrong_state or unsupported_hash."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _in_hash_methods(v: Any) -> bool:
    k = js_to_string(v)
    return k in HASH_METHODS or k in _OBJECT_PROTO


def _start_name(e: Any) -> Optional[str]:
    if isinstance(e, str):
        return e
    if isinstance(e, dict) and isinstance(e.get("mode"), str):
        return e["mode"]
    return None


def callback_uri_ok(uri: Any) -> bool:
    """RFC 9635 2.5.2: an absolute URI without a fragment; HTTPS, a loopback HTTP host, or an application-specific scheme."""
    if not isinstance(uri, str) or _js_len(uri) > 2048:
        return False
    u = _parse_url(uri)
    if u is None or "#" in uri:
        return False
    scheme, host = u["scheme"], u["host"]
    if scheme == "https":
        return True
    if scheme == "http":
        hostname = host[:host.index("]") + 1] if host.startswith("[") else host.split(":")[0]
        return hostname in ("localhost", "127.0.0.1", "[::1]")
    return scheme not in ("javascript", "data", "file", "blob")


_NONCE_RE = re.compile(r"[\x21-\x7e]+")


def validate_interact_request(r: Any) -> List[str]:
    """Validate an `interact` request; returns the problems (empty = valid). Unknown start modes are tolerated."""
    e: List[str] = []
    if not isinstance(r, dict):
        return ["interact must be an object"]
    start = r.get("start")
    if not isinstance(start, list) or len(start) == 0 or len(start) > 16:
        e.append("start must be a non-empty array of modes")
    else:
        for s in start:
            if _start_name(s) is None:
                e.append("each start entry is a mode name or an object with a mode")
    if "finish" in r:
        f = r["finish"]
        if not _is_obj(f):
            e.append("finish must be an object")
        else:
            m = (lambda k: f.get(k, _UNDEF)) if isinstance(f, dict) else (lambda k: _UNDEF)
            if not (isinstance(m("method"), str) and m("method") in FINISH_METHODS):
                e.append("finish.method must be redirect or push")
            if not callback_uri_ok(m("uri")):
                e.append("finish.uri must be an absolute https, loopback or app-scheme URI without a fragment")
            nonce = m("nonce")
            if not isinstance(nonce, str) or _js_len(nonce) < 8 or _js_len(nonce) > 256 or _NONCE_RE.fullmatch(nonce) is None:
                e.append("finish.nonce must be 8..256 printable ASCII characters")
            hm = m("hash_method")
            if hm is not _UNDEF and not _in_hash_methods(hm):
                e.append("finish.hash_method is not a supported Named Information hash")
    return e


def _field(a: Dict[str, Any], k: str) -> str:
    return js_to_string(a[k]) if k in a else "undefined"


def interaction_hash(a: Dict[str, Any]) -> str:
    """RFC 9635 4.2.3: base64url (no padding) of HASH(client_nonce \\n as_nonce \\n interact_ref \\n grant_endpoint). Arguments:
    client_nonce, as_nonce, interact_ref, grant_endpoint, hash_method (default sha-256)."""
    m = a.get("hash_method")
    m = "sha-256" if m is None else m
    if not _in_hash_methods(m):
        raise InteractionError("unsupported_hash", "hash_method %s is not supported" % js_to_string(m))
    key = js_to_string(m)
    if key not in HASH_METHODS:
        raise HashArgError("hash_method %s is not a hash algorithm" % key)
    text = "%s\n%s\n%s\n%s" % (_field(a, "client_nonce"), _field(a, "as_nonce"), _field(a, "interact_ref"), _field(a, "grant_endpoint"))
    data = text.encode("utf-16-le", "surrogatepass")[0::2]  # Node's 'ascii' input encoding: the low byte of each UTF-16 unit
    return b64u(hashlib.new(HASH_METHODS[key], data).digest())


def verify_interaction_hash(received: Any, a: Dict[str, Any]) -> bool:
    """Client side: does the callback's `hash` match? Constant time; a non-validating hash means the interact_ref MUST NOT be sent."""
    if not isinstance(received, str):
        return False
    return hmac.compare_digest(interaction_hash(a).encode("utf-8"), _utf8(received))


def new_user_code(length: int = 8) -> str:
    """6..12 characters from an alphabet without look-alikes (random)."""
    if isinstance(length, bool) or not isinstance(length, int) or length < 6 or length > 12:
        raise ValueError("user code length 6..12")
    return "".join(_USER_CODE_ALPHABET[b % 32] for b in secrets.token_bytes(length))


_CODE_STRIP = re.compile("[\t\n\v\f\r    -     　﻿-]")


def _norm_code(c: str) -> str:
    return _CODE_STRIP.sub("", c).upper()


class Interaction:
    """One interaction's state. `as_dict()` is the wire-style view (camelCase members, only the members that are set)."""

    def __init__(self, id_: str, grant_endpoint: str, modes: List[str], expires_at: float):
        self.id = id_
        self.state = "pending"
        self.grant_endpoint = grant_endpoint
        self.modes = modes
        self.finish: Optional[Dict[str, Any]] = None  # {method, uri, client_nonce, as_nonce, hash_method}
        self.user_code: Optional[str] = None
        self.interact_ref: Optional[str] = None
        self.ref_used = False
        self.expires_at = expires_at

    def as_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"id": self.id, "state": self.state, "grantEndpoint": self.grant_endpoint, "modes": list(self.modes)}
        if self.finish is not None:
            f = self.finish
            d["finish"] = {"method": f["method"], "uri": f["uri"], "clientNonce": f["client_nonce"], "asNonce": f["as_nonce"], "hashMethod": f["hash_method"]}
        if self.user_code is not None:
            d["userCode"] = self.user_code
        if self.interact_ref is not None:
            d["interactRef"] = self.interact_ref
        d["refUsed"] = self.ref_used
        d["expiresAt"] = self.expires_at
        return d


_FORM_KEEP = frozenset(b"*-._0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_USERINFO_ENC = "\"#<>?`{}/:;=@[\\]^|"


def _form_decode(s: str) -> str:
    return unquote_to_bytes(s.replace("+", " ")).decode("utf-8", "replace")


def _form_encode(s: str) -> str:
    return "".join(chr(b) if b in _FORM_KEEP else "+" if b == 0x20 else "%%%02X" % b for b in _utf8(s))


def _redirect_url(uri: str, hash_: str, ref: str) -> str:
    """`u = new URL(uri); u.searchParams.set('hash', ..); u.searchParams.set('interact_ref', ..); u.toString()` for a URI that
    callback_uri_ok accepted (so no fragment): the URL is re-serialized and its query is rebuilt as application/x-www-form-urlencoded."""
    d = _parse_url(uri)
    if d is None:
        raise ValueError("invalid URL")
    s = re.sub(r"[\t\n\r]", "", re.sub(r"^[\x00-\x20]+|[\x00-\x20]+$", "", uri))
    rest = s[re.match(r"[A-Za-z][A-Za-z0-9+.\-]*:", s).end():]  # type: ignore[union-attr]
    q = rest.find("?")
    raw_q = rest[q + 1:] if q >= 0 else None
    body = rest[:q] if q >= 0 else rest
    scheme = d["scheme"]
    special = scheme in _SPECIAL
    authority = None
    if special:
        body = re.sub(r"^[/\\]+", "", body)
        cut = re.search(r"[/\\]", body)
        authority, path = (body[:cut.start()], body[cut.start():]) if cut else (body, "")
    elif body.startswith("//"):
        inner = body[2:]
        cut = inner.find("/")
        authority, path = (inner[:cut], inner[cut:]) if cut >= 0 else (inner, "")
    else:
        path = body
    out = scheme + ":"
    if authority is not None:
        out += "//"
        if "@" in authority:
            user, _, pw = authority.rpartition("@")[0].partition(":")
            user, pw = _pct(user, _USERINFO_ENC), _pct(pw, _USERINFO_ENC)
            if user or pw:
                out += user + (":" + pw if pw else "") + "@"
        out += d["host"]
    out += "" if authority is not None and not special and path == "" else d["pathname"]
    pairs: List[List[str]] = []
    for seg in (raw_q or "").split("&"):
        if seg == "":
            continue
        n, _, v = seg.partition("=")
        pairs.append([_form_decode(n), _form_decode(v)])
    for name, value in (("hash", hash_), ("interact_ref", ref)):
        hits = [p for p in pairs if p[0] == name]
        if hits:
            hits[0][1] = value
            pairs = [p for p in pairs if p is hits[0] or p[0] != name]
        else:
            pairs.append([name, value])
    return out + "?" + "&".join("%s=%s" % (_form_encode(n), _form_encode(v)) for n, v in pairs)


class InteractionServer:
    """The authorization-server side of GNAP interaction. The response never includes a mode the client did not ask for nor one the
    AS does not support (RFC 9635 3.3), and each interact_ref is single use: a second presentation is `too_many_attempts` and
    finalizes the grant. Options: grant_endpoint, supports, redirect_uri(id), app_uri(id)?, user_code_uri?, ttl_sec?, now() (seconds)."""

    def __init__(self, opts: Dict[str, Any]):
        self._o = opts
        self._by_id: Dict[str, Interaction] = {}
        self._by_code: Dict[str, str] = {}
        self._by_ref: Dict[str, str] = {}

    def start(self, req: Any) -> Dict[str, Any]:
        problems = validate_interact_request(req)
        if problems:
            raise InteractionError("invalid_request", "; ".join(problems))
        o = self._o
        asked = {_start_name(e) for e in req["start"]}
        modes = [m for m in o["supports"] if m in asked and (m != "app" or o.get("app_uri")) and (m != "user_code_uri" or o.get("user_code_uri"))]
        if len(modes) == 0 and not _truthy(req.get("finish")):
            raise InteractionError("invalid_interaction", "no requested interaction mode is supported")
        id_ = b64u(secrets.token_bytes(16))
        ttl = 600 if o.get("ttl_sec") is None else o["ttl_sec"]
        it = Interaction(id_, o["grant_endpoint"], modes, o["now"]() + ttl)
        res: Dict[str, Any] = {"expires_in": ttl}
        if "redirect" in modes:
            res["redirect"] = o["redirect_uri"](id_)
        if "app" in modes:
            res["app"] = o["app_uri"](id_)
        if "user_code" in modes or "user_code_uri" in modes:
            it.user_code = new_user_code()
            self._by_code[it.user_code] = id_
            if "user_code" in modes:
                res["user_code"] = it.user_code
            if "user_code_uri" in modes:
                res["user_code_uri"] = {"code": it.user_code, "uri": o["user_code_uri"]}
        if _truthy(req.get("finish")):
            f = req["finish"]
            as_nonce = b64u(secrets.token_bytes(24))
            hm = f.get("hash_method") if isinstance(f, dict) else None
            it.finish = {"method": f.get("method"), "uri": f.get("uri"), "client_nonce": f.get("nonce"), "as_nonce": as_nonce,
                         "hash_method": "sha-256" if hm is None else hm}
            res["finish"] = as_nonce
        self._by_id[id_] = it
        return {"interaction": it, "response": res}

    def _expired(self, it: Any) -> bool:
        """Fail closed: a non-finite clock or expiry reads as expired."""
        t = self._o["now"]()
        return not (fin(t) and fin(it.expires_at) and t <= it.expires_at)

    def lookup_user_code(self, code: str) -> Optional[Interaction]:
        """The resource owner typed a code (case-insensitive). A 32^8 code space is only safe behind a per-source rate limit on this
        lookup: the caller MUST apply one."""
        id_ = self._by_code.get(_norm_code(code))
        it = self._by_id.get(id_) if id_ else None
        if it is None or it.state != "pending" or self._expired(it):
            return None
        return it

    def get(self, id_: str) -> Optional[Interaction]:
        return self._by_id.get(id_)

    def approve(self, id_: str) -> Dict[str, Any]:
        """The resource owner approved. Returns {interact_ref, finish?}: finish is {method: "redirect", url} or
        {method: "push", uri, body: {hash, interact_ref}}, absent without a finish method."""
        it = self._live(id_)
        if it.state != "pending":
            raise InteractionError("wrong_state", "interaction is %s" % it.state)
        it.state = "approved"
        it.interact_ref = b64u(secrets.token_bytes(18))
        self._by_ref[it.interact_ref] = id_
        if it.user_code:
            self._by_code.pop(it.user_code, None)
        if it.finish is None:
            return {"interact_ref": it.interact_ref}
        f = it.finish
        h = interaction_hash({"client_nonce": f["client_nonce"], "as_nonce": f["as_nonce"], "interact_ref": it.interact_ref,
                              "grant_endpoint": it.grant_endpoint, "hash_method": f["hash_method"]})
        if f["method"] == "push":
            return {"interact_ref": it.interact_ref, "finish": {"method": "push", "uri": f["uri"], "body": {"hash": h, "interact_ref": it.interact_ref}}}
        return {"interact_ref": it.interact_ref, "finish": {"method": "redirect", "url": _redirect_url(f["uri"], h, it.interact_ref)}}

    def consume(self, interact_ref: str) -> Interaction:
        """Continuation (RFC 9635 5.1): present the interact_ref once. A replay finalizes the grant and is `too_many_attempts`."""
        id_ = self._by_ref.get(interact_ref)
        it = self._by_id.get(id_) if id_ else None
        if it is None:
            raise InteractionError("unknown_interaction", "no such interaction reference")
        if it.ref_used or it.state == "finalized":
            it.state = "finalized"
            raise InteractionError("too_many_attempts", "the interaction reference was already used")
        if self._expired(it):
            raise InteractionError("expired", "the interaction expired")
        if it.state != "approved":
            raise InteractionError("wrong_state", "interaction is %s" % it.state)
        it.ref_used = True
        return it

    def finalize(self, id_: str) -> None:
        it = self._by_id.get(id_)
        if it is not None:
            it.state = "finalized"

    def _live(self, id_: str) -> Interaction:
        it = self._by_id.get(id_)
        if it is None:
            raise InteractionError("unknown_interaction", "no such interaction")
        if self._expired(it):
            raise InteractionError("expired", "the interaction expired")
        return it


def accept_finish(cb: Dict[str, Any], ctx: Dict[str, Any]) -> str:
    """Client side: validate a finish callback (query for redirect, JSON body for push). Returns the interact_ref to send, or raises
    unknown_interaction. `ctx`: client_nonce, as_nonce, grant_endpoint, hash_method?."""
    ref, h = cb.get("interact_ref"), cb.get("hash")
    if not isinstance(ref, str) or ref == "" or not isinstance(h, str):
        raise InteractionError("unknown_interaction", "hash and interact_ref are required")
    if not verify_interaction_hash(h, dict(ctx, interact_ref=ref)):
        raise InteractionError("unknown_interaction", "the callback hash does not validate")
    return ref


def access_to_needs(access: Any) -> List[Dict[str, str]]:
    """One need {verb, resource} per (action, location) pair of an access array. An access right with no actions or no locations is a
    wildcard and is refused: a need must be explicit."""
    out = []
    for a in access:
        if a is None:
            raise TypeError("cannot read properties of null")
        actions, locations = _prop(a, "actions"), _prop(a, "locations")
        if not actions or actions is _UNDEF or not locations or locations is _UNDEF:
            raise InteractionError("invalid_request", 'access "%s" needs explicit actions and locations to become a need' % js_to_string(_def(_prop(a, "type"))))
        for verb in actions:
            for loc in locations:
                out.append({"verb": verb, "resource": "gnap:%s:%s" % (js_to_string(a.get("type")), js_to_string(loc))})
    return out


# ---- the Agent-GNAP profile, as a machine-readable spec object ----------------------------------------------------------------------

AGENT_GNAP_PROFILE = {'name': 'agent-gnap',
 'version': '1.0',
 'rfc': 'RFC 9635',
 'summary': 'A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is issued as an attenuated, '
            'key-bound PCA capability, never wider than the issuing agent.',
 'mapping': [{'gnap': 'access[].type',
              'pca': 'predicate resource namespace gnap:<type>:<location>',
              'note': 'the resource family the rights live in'},
             {'gnap': 'access[].actions', 'pca': 'predicate.verb (list, or * for any)', 'note': 'the operations permitted'},
             {'gnap': 'access[].locations', 'pca': 'predicate.resource (exact or trailing-* prefix)', 'note': 'the resource targets'},
             {'gnap': 'access[].datatypes / identifier', 'pca': 'predicate.where on action.params.*', 'note': 'value-level constraints'},
             {'gnap': 'client.key.jwk (OKP/Ed25519)', 'pca': 'capability.holder (cnf-bound key)', 'note': 'the proof-of-possession key'},
             {'gnap': 'grant request (no prior grant)',
              'pca': 'mintGrant → root capability',
              'note': 'envelope predicates = requested access'},
             {'gnap': 'grant request (delegated hop)',
              'pca': 'delegate → child capability + gnap_access caveat',
              'note': 'append-only attenuation'},
             {'gnap': 'access_token (§3.2)',
              'pca': 'a verifiable PCA capability chain (encodeBoundToken)',
              'note': 'bound, self-verifying token'},
             {'gnap': 'continue (§3.1) + interact (§3.3)',
              'pca': 'PCA step-up: FROST/threshold co-signature folded into a PCActn',
              'note': 'tier-2/3 escalation'},
             {'gnap': 'jwsd detached JWS (§7.3.4)',
              'pca': 'request proof binding the body to capability.holder',
              'note': 'verified with jose'}],
 'proofMethods': ['jwsd'],
 'multiHop': 'An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, recording its (clamped) rights '
             'as an append-only gnap_access caveat. Effective authority is the intersection of the root policy envelope and every hop; PCA '
             'caveats are conjunctive and append-only, so no hop can widen — "never wider than the issuer" holds across any depth.',
 'stepUp': 'A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue handle instead of a token. The '
           'client returns with the action PCActn plus a guardian/principal co-signature, which is folded into the PCActn threshold and '
           'verified at tier 2/3 (FROST or multi-signature) before the action is admitted.',
 'security': ['Attenuation is structural and append-only: a delegated hop can only ever narrow authority.',
              'Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.',
              'All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.',
              'Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).',
              'Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant.']}

