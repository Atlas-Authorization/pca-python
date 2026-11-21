"""SD-JWT serialization of a PCA ``PCActn`` (port of the TypeScript reference, @atlasauth/pca-sdjwt).

A PCActn is re-expressed as an IETF SD-JWT: standard claims in the clear, capability claims selectively disclosable, an
optional holder key-binding JWT. The PCActn's own canonical signature stays the source of truth (``verify_recovered``
rebuilds the PCActn from the recovered claims and re-verifies it with PCA Core). Every function fails closed.

Options are plain dicts keyed by the reference's option names in snake_case (``issuer_key``, ``expected_audience``, ...);
an absent key and a ``None`` value are told apart exactly as ``undefined`` and ``null`` are in the reference. Result dicts
keep the reference's member names (``protectedHeader``, ``keyBinding``).
"""
from __future__ import annotations

import math
import secrets
import time
from typing import Any, Dict, List, Optional

from . import pca as _pca
from ._fin import fin
from .sdjwt_jws import (
    CanonicalJwsError,
    JoseError,
    UNSET,
    assert_canonical_compact_jws,
    b64u,
    decode_canonical_json_segment,
    is_number,
    is_plain_object,
    js_json_bytes,
    js_to_string,
    jwt_verify,
    key_x,
    node_b64url_decode,
    public_key_from_jwk,
    sha256_ascii_b64u,
    sign_jwt,
    truthy,
)

SD_ALG = "sha-256"
PCA_SD_JWT_TYP = "pca+sd-jwt"
KB_JWT_TYP = "kb+jwt"
DEFAULT_SIGNING_ALG = "EdDSA"

PCA_CAPABILITY_CLAIMS = (
    "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "nonce",
    "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "alg", "pq_pk", "sig",
    "pq_sig", "threshold", "zk_compliance", "bond_ref",
)

_STANDARD_MAPPED = frozenset(("aud", "iat", "exp"))
_CLEAR_DISCRIMINATOR = "ver"
# RFC 9901 s9.7: security-critical claims are never accepted behind a Disclosure.
_CRITICAL_CLAIMS = frozenset(("iss", "aud", "exp", "nbf", "cnf", "status"))
_RESERVED_CLAIMS = frozenset(("iss", "sub", "aud", "iat", "exp", "_sd", "_sd_alg", "cnf"))


class SdJwtError(ValueError):
    """A refusal from this package (the message is the reference's, so callers can match on it)."""


class _SdJwtProcessingError(Exception):
    pass


def _prop(o: Any, k: str) -> Any:
    return o.get(k) if isinstance(o, dict) else None


def _is_jwk(v: Any) -> bool:
    return isinstance(v, dict) and isinstance(v.get("kty"), str)


# ---- Ed25519 raw-key bridge ------------------------------------------------------------------------------------------

def ed25519_public_jwk(raw: bytes) -> dict:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise SdJwtError("pca-sdjwt: Ed25519 public key must be 32 bytes")
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(bytes(raw))}


def import_ed25519_private_key(raw_seed: bytes) -> bytes:
    """The signing key for a raw 32-byte Ed25519 seed (atlas_pca keys are raw bytes, so this validates and returns it)."""
    if not isinstance(raw_seed, (bytes, bytearray)) or len(raw_seed) != 32:
        raise SdJwtError("pca-sdjwt: Ed25519 private seed must be 32 bytes")
    return bytes(raw_seed)


def import_ed25519_public_key(raw: bytes) -> bytes:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise SdJwtError("pca-sdjwt: Ed25519 public key must be 32 bytes")
    return bytes(raw)


# ---- issuance -------------------------------------------------------------------------------------------------------

def _leaf_holder_jwk(pc_actn: dict) -> dict:
    chain = pc_actn.get("cap_chain")
    leaf = chain[-1] if isinstance(chain, list) and len(chain) > 0 else None
    holder = _prop(leaf, "holder")
    if not truthy(leaf) or not isinstance(holder, str) or len(holder) == 0:
        raise SdJwtError("pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing")
    return ed25519_public_jwk(node_b64url_decode(holder))


def _resolve_cnf_jwk(pc_actn: dict, kb: Any) -> dict:
    hp = kb.get("holder_public_key", UNSET) if isinstance(kb, dict) else UNSET
    if hp is UNSET:
        return _leaf_holder_jwk(pc_actn)
    if isinstance(hp, (bytes, bytearray)):
        return ed25519_public_jwk(hp)
    if _is_jwk(hp):
        return hp
    raise SdJwtError("pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key")


def _to_numeric_date(ms: Any, label: str, rnd: Any) -> float:
    if not is_number(ms) or not fin(ms):
        raise SdJwtError("pca-sdjwt: PCActn.%s must be a finite number (epoch ms)" % label)
    return float(rnd(float(ms) / 1000))


def _make_disclosure(name: str, value: Any) -> Dict[str, str]:
    salt = b64u(secrets.token_bytes(16))
    encoded = b64u(js_json_bytes([salt, name, value]))
    return {"name": name, "encoded": encoded, "digest": sha256_ascii_b64u(encoded)}


def issue_pca_sd_jwt(pc_actn: Any, options: Dict[str, Any]) -> str:
    """Serialize a signed PCActn as ``<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~`` (no KB-JWT at issuance).
    Options: issuer_key (required), disclosable, key_binding ({"holderPublicKey"?}), iss, sub, typ, signing_alg."""
    if not is_plain_object(pc_actn):
        raise SdJwtError("pca-sdjwt: pcActn must be an object")
    chain = pc_actn.get("cap_chain")
    if not isinstance(chain, list) or len(chain) == 0:
        raise SdJwtError("pca-sdjwt: pcActn.cap_chain must be a non-empty array")
    root, leaf = chain[0], chain[-1]
    if not truthy(root) or not isinstance(_prop(root, "issuer"), str):
        raise SdJwtError("pca-sdjwt: cap_chain root issuer is missing")
    if not truthy(leaf) or not isinstance(_prop(leaf, "holder"), str):
        raise SdJwtError("pca-sdjwt: cap_chain leaf holder is missing")
    aud = pc_actn.get("aud")
    if not isinstance(aud, str) or len(aud) == 0:
        raise SdJwtError("pca-sdjwt: pcActn.aud is required")

    iss = options["iss"] if options.get("iss") is not None else root["issuer"]
    sub = options["sub"] if options.get("sub") is not None else leaf["holder"]
    iat = _to_numeric_date(pc_actn.get("iat"), "iat", math.floor)
    exp = _to_numeric_date(pc_actn.get("exp"), "exp", math.ceil)
    if exp <= iat:
        exp = iat + 1  # keep exp strictly after iat even for sub-second lifetimes

    disclosable = options.get("disclosable")
    disclosable_set = set(PCA_CAPABILITY_CLAIMS if disclosable is None else [d for d in disclosable if isinstance(d, str)])

    # iat_ms / exp_ms carry the exact signed epoch-ms values so verify_recovered can rebuild the byte-identical PCActn.
    payload: Dict[str, Any] = {"iss": iss, "sub": sub, "aud": aud, "iat": iat, "exp": exp}
    if _CLEAR_DISCRIMINATOR in pc_actn:
        payload[_CLEAR_DISCRIMINATOR] = pc_actn[_CLEAR_DISCRIMINATOR]
    payload["iat_ms"] = pc_actn["iat"]
    payload["exp_ms"] = pc_actn["exp"]
    payload["_sd_alg"] = SD_ALG
    disclosures: List[Dict[str, str]] = []
    sd: List[str] = []
    for key in list(pc_actn.keys()):
        if key in _STANDARD_MAPPED or key == _CLEAR_DISCRIMINATOR:
            continue
        value = pc_actn[key]
        if key in disclosable_set:
            d = _make_disclosure(key, value)
            disclosures.append(d)
            sd.append(d["digest"])
        else:
            payload[key] = value  # the caller chose to keep this capability claim in the clear
    if sd:
        payload["_sd"] = sd
    kb = options.get("key_binding")
    if truthy(kb):
        payload["cnf"] = {"jwk": _resolve_cnf_jwk(pc_actn, kb)}

    alg = options["signing_alg"] if options.get("signing_alg") is not None else DEFAULT_SIGNING_ALG
    typ = options["typ"] if options.get("typ") is not None else PCA_SD_JWT_TYP
    jwt = sign_jwt(payload, {"alg": alg, "typ": typ}, options["issuer_key"])
    return "".join(p + "~" for p in [jwt] + [d["encoded"] for d in disclosures])


# ---- parsing --------------------------------------------------------------------------------------------------------

class _Parsed:
    __slots__ = ("jwt", "disclosures", "kb_jwt", "presentation_head")

    def __init__(self, jwt: str, disclosures: List[str], kb_jwt: Optional[str], head: str):
        self.jwt, self.disclosures, self.kb_jwt, self.presentation_head = jwt, disclosures, kb_jwt, head


def _parse_sd_jwt(sdjwt: Any) -> _Parsed:
    if not isinstance(sdjwt, str) or len(sdjwt) == 0:
        raise SdJwtError("pca-sdjwt: empty SD-JWT")
    segments = sdjwt.split("~")
    if len(segments) < 2:
        raise SdJwtError("pca-sdjwt: malformed SD-JWT (missing ~ separator)")
    jwt = segments[0]
    if jwt == "":
        raise SdJwtError("pca-sdjwt: empty issuer JWT")
    last = segments[-1]
    disclosures = segments[1:-1]
    if any(len(s) == 0 for s in disclosures):  # `a~~b` is an aliasing vector: refuse, never drop
        raise SdJwtError("pca-sdjwt: empty disclosure segment")
    assert_canonical_compact_jws(jwt)
    if last != "":
        assert_canonical_compact_jws(last)
    if last == "":
        return _Parsed(jwt, disclosures, None, sdjwt)
    return _Parsed(jwt, disclosures, last, sdjwt[: len(sdjwt) - len(last)])


def _decode_disclosure_parts(encoded: str) -> list:
    try:
        parsed = decode_canonical_json_segment(encoded)
    except (CanonicalJwsError, RecursionError):
        raise SdJwtError("pca-sdjwt: disclosure is not canonical base64url strict JSON") from None
    if not isinstance(parsed, list) or len(parsed) not in (2, 3):
        raise SdJwtError("pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair")
    if not isinstance(parsed[0], str):
        raise SdJwtError("pca-sdjwt: disclosure salt must be a string")
    return parsed


# ---- holder presentation --------------------------------------------------------------------------------------------

def _collect_digests(node: Any) -> List[str]:
    """Every digest referenced by `_sd` arrays or {"...": digest} entries anywhere inside `node`."""
    out: List[str] = []

    def visit(n: Any) -> None:
        if isinstance(n, list):
            for x in n:
                visit(x)
        elif isinstance(n, dict):
            for k, v in n.items():
                if k == "_sd" and isinstance(v, list):
                    out.extend(x for x in v if isinstance(x, str))
                elif k == "..." and isinstance(v, str):
                    out.append(v)
                else:
                    visit(v)

    visit(node)
    return out


def _js_set(values: Any) -> set:
    """`new Set(values)` restricted to the strings (only strings can ever match a claim name)."""
    if values is None:
        return set()
    if isinstance(values, str):
        return set(values)
    if isinstance(values, (list, tuple)):
        return {v for v in values if isinstance(v, str)}
    raise TypeError("selectClaims is not iterable")


def present(sdjwt: str, select_claims: Any, options: Optional[dict] = None) -> str:
    """Holder presentation disclosing ONLY `select_claims` (by claim name), dropping every other Disclosure; an existing
    KB-JWT is stripped, and with options["key_binding"] ({holder_key, audience, nonce?, iat?, alg?, now?}) a fresh one is
    signed over the new presentation (`now` is epoch ms, used only when `iat` is absent)."""
    parsed = _parse_sd_jwt(sdjwt)
    keep = _js_set(select_claims)
    by_digest: Dict[str, str] = {}
    for encoded in parsed.disclosures:
        by_digest[sha256_ascii_b64u(encoded)] = encoded

    kept: set = set()

    def include(digest: str) -> None:
        encoded = by_digest.get(digest)
        if encoded is None or digest in kept:
            return
        kept.add(digest)
        parts = _decode_disclosure_parts(encoded)
        for d in _collect_digests(parts[-1]):
            include(d)

    try:
        seg = parsed.jwt.split(".")[1] if len(parsed.jwt.split(".")) > 1 else ""
        payload = _pca.strict_parse(node_b64url_decode(seg).decode("utf-8"))
    except (ValueError, RecursionError):
        raise SdJwtError("pca-sdjwt: issuer JWT payload is not valid base64url JSON") from None
    if is_plain_object(payload):
        sd = payload.get("_sd") if isinstance(payload.get("_sd"), list) else []
        for digest in sd:
            if not isinstance(digest, str):
                continue
            encoded = by_digest.get(digest)
            if encoded is None:
                continue
            parts = _decode_disclosure_parts(encoded)
            if isinstance(parts[1], str) and len(parts) == 3 and parts[1] in keep:
                include(digest)
        for key in list(payload.keys()):
            if key != "_sd" and key in keep:
                for d in _collect_digests(payload[key]):
                    include(d)
    kept_list = [e for e in parsed.disclosures if sha256_ascii_b64u(e) in kept]
    head = "~".join([parsed.jwt] + kept_list) + "~"
    kb = options.get("key_binding") if isinstance(options, dict) else None
    if not truthy(kb):
        return head

    iat = kb["iat"] if kb.get("iat") is not None else math.floor(
        (kb["now"] if kb.get("now") is not None else time.time() * 1000) / 1000)
    kb_payload: Dict[str, Any] = {"iat": iat}
    if "audience" in kb:
        kb_payload["aud"] = kb["audience"]
    kb_payload["sd_hash"] = sha256_ascii_b64u(head)
    if "nonce" in kb:
        kb_payload["nonce"] = kb["nonce"]
    alg = kb["alg"] if kb.get("alg") is not None else DEFAULT_SIGNING_ALG
    kb_jwt = sign_jwt(kb_payload, {"alg": alg, "typ": KB_JWT_TYP}, kb["holder_key"])
    return head + kb_jwt


# ---- verification ---------------------------------------------------------------------------------------------------

class _Decoded:
    __slots__ = ("encoded", "parts", "used")

    def __init__(self, encoded: str, parts: list):
        self.encoded, self.parts, self.used = encoded, parts, False


def _process_disclosures(payload: dict, by_digest: Dict[str, _Decoded]) -> Any:
    """RFC 9901 s7.1 payload processing: resolve `_sd` digests and {"...": digest} array entries recursively, refusing
    reserved / colliding names, reused digests and unreferenced Disclosures. Returns (processed, disclosed_top)."""
    seen: set = set()
    disclosed_top: Dict[str, Any] = {}

    def claim_digest(d: str) -> Optional[_Decoded]:
        if d in seen:
            raise _SdJwtProcessingError("a digest appears more than once in the payload")
        seen.add(d)
        return by_digest.get(d)

    def walk(node: Any, top: bool) -> Any:
        if isinstance(node, list):
            out: list = []
            for el in node:
                if isinstance(el, dict) and list(el.keys()) == ["..."]:
                    digest = el["..."]
                    if not isinstance(digest, str):
                        raise _SdJwtProcessingError("an array '...' entry must reference a string digest")
                    d = claim_digest(digest)
                    if d is None:
                        continue  # undisclosed element or decoy: removed
                    if len(d.parts) != 2:
                        raise _SdJwtProcessingError("an array-element disclosure must be [salt, value]")
                    d.used = True
                    out.append(walk(d.parts[1], False))
                else:
                    out.append(walk(el, False))
            return out
        if isinstance(node, dict):
            res: Dict[str, Any] = {}
            for key in list(node.keys()):
                if key == "_sd":
                    continue
                res[key] = walk(node[key], False)
            sd = node.get("_sd", UNSET)
            if sd is not UNSET:
                if not isinstance(sd, list) or not all(isinstance(x, str) for x in sd):
                    raise _SdJwtProcessingError("_sd must be an array of strings")
                for digest in sd:
                    d = claim_digest(digest)
                    if d is None:
                        continue  # decoy or undisclosed claim
                    if len(d.parts) != 3:
                        raise _SdJwtProcessingError("an object-property disclosure must be [salt, name, value]")
                    name = d.parts[1]
                    if not isinstance(name, str):
                        raise _SdJwtProcessingError("disclosure claim name must be a string")
                    if name in ("_sd", "..."):
                        raise _SdJwtProcessingError("disclosure claim name '%s' is reserved" % name)
                    if name in res:
                        raise _SdJwtProcessingError("disclosure claim '%s' collides with an existing claim" % name)
                    if top and name in _CRITICAL_CLAIMS:
                        raise _SdJwtProcessingError(
                            "'%s' is security-critical and must not be selectively disclosable" % name)
                    d.used = True
                    value = walk(d.parts[2], False)
                    res[name] = value
                    if top:
                        disclosed_top[name] = value
            return res
        return node

    processed = walk(payload, True)
    if not isinstance(processed, dict):
        raise _SdJwtProcessingError("payload is not an object")
    processed.pop("_sd_alg", None)
    for d in by_digest.values():
        if not d.used:
            raise _SdJwtProcessingError("a presented disclosure is not referenced by any digest in the payload")
    return processed, disclosed_top


def _same(a: Any, b: Any) -> bool:
    """JavaScript `===` over JSON values (UNSET stands for undefined)."""
    if a is UNSET or b is UNSET or a is None or b is None:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if is_number(a) and is_number(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b


def _js_number(v: Any) -> float:
    """Number(v) for a JSON value (null is 0, a non-numeric string NaN)."""
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if is_number(v):
        return v
    if isinstance(v, str):
        try:
            return float(v) if v.strip() else 0.0
        except ValueError:
            return math.nan
    return math.nan


def _fail(reason: str) -> dict:
    return {"ok": False, "reason": reason}


def verify_pca_sd_jwt(sdjwt: Any, options: Dict[str, Any]) -> dict:
    """Verify a PCA SD-JWT, FAIL CLOSED: any bad signature, unknown `_sd_alg`, unmatched / forged Disclosure, audience /
    expiry violation or key-binding failure returns {"ok": False, "reason"}. Options: issuer_key (required),
    required_disclosures, expected_audience, key_binding_key, expected_kb_audience, expected_nonce, require_key_binding,
    algorithms, kb_algorithms, now (epoch ms), kb_max_age_sec, clock_tolerance_sec."""
    try:
        # a non-finite clock, tolerance or window would slip past the date checks (NaN compares false and -Infinity is before every expiry)
        for n in (options.get("now"), options.get("clock_tolerance_sec"), options.get("kb_max_age_sec")):
            if n is not None and not (is_number(n) and fin(n)):
                return _fail("now, clockToleranceSec and kbMaxAgeSec must be finite")
        parsed = _parse_sd_jwt(sdjwt)
        algs = options.get("algorithms")
        algorithms = [DEFAULT_SIGNING_ALG] if algs is None else algs
        tol = options.get("clock_tolerance_sec", UNSET)
        now = options.get("now", UNSET)
        aud = options.get("expected_audience", UNSET)

        try:
            payload, protected_header = jwt_verify(parsed.jwt, options["issuer_key"], algorithms=algorithms, audience=aud,
                                                   now_ms=now, clock_tolerance=tol)
        except (JoseError, CanonicalJwsError) as e:
            return _fail(str(e))

        if "_sd_alg" in payload and payload["_sd_alg"] != SD_ALG:
            return _fail('unsupported _sd_alg (require "%s")' % SD_ALG)
        by_digest: Dict[str, _Decoded] = {}
        for encoded in parsed.disclosures:
            digest = sha256_ascii_b64u(encoded)
            if digest in by_digest:
                return _fail("duplicate disclosure")
            by_digest[digest] = _Decoded(encoded, _decode_disclosure_parts(encoded))
        try:
            processed, disclosed = _process_disclosures(payload, by_digest)
        except _SdJwtProcessingError as e:
            m = str(e)
            return _fail("a presented disclosure does not match any _sd digest (tampered)" if "not referenced" in m else m)

        req = options.get("required_disclosures")
        for required in ([] if req is None else req):
            if js_to_string(required) not in disclosed:
                return _fail("required disclosure '%s' was not presented" % js_to_string(required))

        cnf = payload.get("cnf")
        cnf_jwk = cnf["jwk"] if is_plain_object(cnf) and _is_jwk(cnf.get("jwk")) else None
        key_binding: Dict[str, Any] = {"presented": parsed.kb_jwt is not None, "verified": False}
        kbk = options.get("key_binding_key", UNSET)

        if parsed.kb_jwt is not None:
            if cnf_jwk is None:
                return _fail("KB-JWT presented but issuer JWT has no cnf key")
            if kbk is not UNSET:
                want, have = key_x(kbk), key_x(cnf_jwk)
                if want is None or have is None or want != have:
                    return _fail("cnf key does not match the expected keyBindingKey")
            kb_algs_o = options.get("kb_algorithms")
            kb_algorithms = [DEFAULT_SIGNING_ALG] if kb_algs_o is None else kb_algs_o
            first = kb_algorithms[0] if kb_algorithms else DEFAULT_SIGNING_ALG
            # importJWK builds the key from the JWK members it needs; a stray private member never changes which key verifies
            pub_jwk = {k: v for k, v in cnf_jwk.items() if k in ("kty", "crv", "x", "y", "n", "e")}
            kb_aud_o = options.get("expected_kb_audience")
            kb_audience = kb_aud_o if kb_aud_o is not None else options.get("expected_audience", UNSET)
            try:
                kb_key = public_key_from_jwk(pub_jwk, first if first is not None else DEFAULT_SIGNING_ALG)  # a key that cannot be imported is a KB-JWT failure
                kb_payload, kb_header = jwt_verify(parsed.kb_jwt, kb_key, algorithms=kb_algorithms, audience=kb_audience,
                                                   now_ms=now, clock_tolerance=tol)
            except (JoseError, CanonicalJwsError) as e:
                return _fail("KB-JWT signature/claims invalid: %s" % e)
            if kb_header.get("typ") != KB_JWT_TYP:
                return _fail('KB-JWT typ must be "%s"' % KB_JWT_TYP)
            if not is_number(kb_payload.get("iat")):
                return _fail("KB-JWT iat is required")
            max_age = options.get("kb_max_age_sec", UNSET)
            if max_age is not UNSET:
                now_sec = math.floor((now if now is not UNSET and now is not None else time.time() * 1000) / 1000)
                max_age = _js_number(max_age)
                if now_sec - kb_payload["iat"] > max_age:
                    return _fail("KB-JWT is older than the accepted window")
                ct = options.get("clock_tolerance_sec")
                if not (kb_payload["iat"] - now_sec <= (0 if ct is None else _js_number(ct))):
                    return _fail("KB-JWT iat is in the future")
            kb_aud = kb_payload.get("aud")
            if not isinstance(kb_aud, str) and not isinstance(kb_aud, list):
                return _fail("KB-JWT aud is required")
            if kb_payload.get("sd_hash") != sha256_ascii_b64u(parsed.presentation_head):
                return _fail("KB-JWT sd_hash does not cover this presentation")
            if "expected_nonce" in options and not _same(kb_payload.get("nonce", UNSET), options["expected_nonce"]):
                return _fail("KB-JWT nonce does not match")
            key_binding["verified"] = True
            if isinstance(kb_aud, str):
                key_binding["aud"] = kb_aud
            if isinstance(kb_payload.get("nonce"), str):
                key_binding["nonce"] = kb_payload["nonce"]
        elif kbk is not UNSET or truthy(options.get("require_key_binding")):
            return _fail("key binding required but no KB-JWT was presented")

        claims = {k: v for k, v in processed.items() if k not in _RESERVED_CLAIMS}
        return {"ok": True, "payload": payload, "processed": processed, "protectedHeader": protected_header,
                "disclosed": disclosed, "claims": claims, "keyBinding": key_binding}
    except Exception as e:  # noqa: BLE001 - fail closed: every error is a refusal carrying its message
        return _fail(str(e))


def verify_recovered(res: dict, core_opts: dict) -> Any:
    """Re-verify a verified SD-JWT with PCA Core: rebuild the PCActn from the recovered claims and run
    ``verify_pcactn_core`` (`core_opts` holds its keyword arguments: grant, now, audience, ...). FAIL CLOSED: a withheld
    required claim, missing or inconsistent iat_ms / exp_ms, or an iss / sub that disagrees with the chain denies."""

    def deny(reason: str) -> Any:
        return _pca.Verdict(allow=False, checks={}, reason=reason)

    c = dict(res["claims"])
    p = res["processed"]
    iat_ms = c.pop("iat_ms", None)
    exp_ms = c.pop("exp_ms", None)
    if not is_number(iat_ms) or not is_number(exp_ms):
        return deny("pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn")
    if math.floor(float(iat_ms) / 1000) != p.get("iat"):
        return deny("pca-sdjwt: iat_ms disagrees with iat")
    if max(math.ceil(float(exp_ms) / 1000), math.floor(float(iat_ms) / 1000) + 1) != p.get("exp"):
        return deny("pca-sdjwt: exp_ms disagrees with exp")
    for k in ("action", "cap_chain", "plan", "sig", "grant_ref", "counter"):
        if k not in c:
            return deny("pca-sdjwt: required claim '%s' was not disclosed" % k)
    if not isinstance(p.get("aud"), str):
        return deny("pca-sdjwt: aud must be a string")
    chain = c["cap_chain"]
    if not isinstance(chain, list) or len(chain) == 0:
        return deny("pca-sdjwt: cap_chain is empty")
    if p.get("iss") != _prop(chain[0], "issuer") or "iss" not in p:
        return deny("pca-sdjwt: iss does not match the chain root issuer")
    if p.get("sub") != _prop(chain[-1], "holder") or "sub" not in p:
        return deny("pca-sdjwt: sub does not match the chain leaf holder")
    pc_actn = dict(c)
    if "ver" in p:
        pc_actn["ver"] = p["ver"]
    pc_actn["aud"] = p["aud"]
    pc_actn["iat"] = iat_ms
    pc_actn["exp"] = exp_ms
    try:
        return _pca.verify_pcactn_core(pc_actn, **core_opts)
    except Exception as e:  # noqa: BLE001
        return deny("pca-sdjwt: core verification threw: %s" % e)
