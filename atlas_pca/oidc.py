"""OpenID Connect rooting for Proof-Carrying Authority, a native port of the TypeScript reference (@atlasauth/pca-oidc).

    discover_oidc(issuer)     the provider metadata (``jwks_uri``, endpoints); the HTTP fetch is an injected callable.
    verify_id_token(token)    the verified ID-token claims (signature + iss/aud/exp/iat/nonce/azp/at_hash/c_hash).
    oidc_principal(claims)    a PCA principal descriptor: a subject caveat + the b64u Ed25519 key a chain roots at.
    create_oidc_jwks(...)     a caching JWKS key resolver that fails closed on stale or unreachable keys.

Injected fetch: ``fetch(url, headers, timeout_ms) -> {"status": int, "body": str | bytes, "headers": {...}}`` (any exception
is a failed fetch). Keys: a public JWK dict, an HMAC secret (bytes), or a resolver ``(header, token) -> JWK | bytes``.
RS*/PS*/ES* signature checks need the ``cryptography`` package; EdDSA and HS* need nothing beyond the standard library.
Options are dicts with snake_case keys (``clock_tolerance_sec``, ``jwks_uri``, ``require_https`` ...); ``now`` is an
injectable epoch-seconds clock (default: the wall clock).
"""
from __future__ import annotations

from ._fin import fin, to_float
import base64
import copy
import hashlib
import hmac
import math
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from . import ed25519 as _ed
from .attest_common import CanonicalJwsError, decode_canonical_b64url, js_json_loads, js_number, js_str, node_b64decode
from .pca import StrictJsonError, strict_parse

__all__ = [
    "OidcVerificationError", "OidcDiscoveryError", "DEFAULT_ID_TOKEN_ALGS", "DEFAULT_MAX_DISCOVERY_BYTES",
    "DEFAULT_JWKS_TIMEOUT_MS", "OIDC_SUBJECT_CAVEAT", "discovery_url", "discover_oidc", "verify_id_token",
    "oidc_principal", "is_oidc_subject_caveat", "create_oidc_jwks", "create_oidc_jwks_from_issuer", "create_local_jwk_set",
]

OIDC_SUBJECT_CAVEAT = "oidc_subject"
DEFAULT_MAX_DISCOVERY_BYTES = 1024 * 1024
DEFAULT_JWKS_TIMEOUT_MS = 5000
DEFAULT_ID_TOKEN_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")
_MAX_JWS_CHARS = 64 * 1024
_WELL_KNOWN = "/.well-known/openid-configuration"


class OidcVerificationError(Exception):
    """Any ID-token verification failure; ``code`` is one of config, invalid_token, signature, issuer, audience, expired,
    issued_at, not_before, nonce, azp, at_hash, c_hash, keys, claims."""

    def __init__(self, code: str, message: str, cause: Optional[BaseException] = None) -> None:
        super().__init__(message)
        self.code = code
        self.__cause__ = cause


class _ArgTypeError(TypeError):
    code = "ERR_INVALID_ARG_TYPE"  # the reference surfaces Node's own error here, and its code is part of the contract


class OidcDiscoveryError(Exception):
    """Any discovery failure (network, non-2xx, bad JSON, issuer mismatch)."""


# ------------------------------------------------------------------------------------------------------------ helpers


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v: Any) -> Optional[Any]:
    return v if _is_num(v) and fin(v) else None


def _str(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and len(v) > 0 else None


def _to_number(v: Any) -> float:
    """JavaScript ToNumber for a JSON value (the reference compares byte counts against whatever limit it was handed)."""
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return to_float(v)
    if isinstance(v, str):
        return js_number(v)
    if isinstance(v, list):
        return js_number(",".join("" if x is None else js_str(x) for x in v))
    return math.nan


def _is_https(u: Any) -> bool:
    # stricter than WHATWG URL parsing on purpose: control characters, spaces or an empty host are never https
    if not isinstance(u, str) or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in u):
        return False
    try:
        s = urlsplit(u)
        return s.scheme.lower() == "https" and bool(s.hostname)
    except ValueError:
        return False


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode("ascii")


def _check_canonical_jws(token: Any) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """The one accepted spelling of a compact JWS: 3 canonical unpadded base64url segments, strict-JSON object header and payload."""
    if not isinstance(token, str):
        raise CanonicalJwsError("not-a-string")
    if len(token) > _MAX_JWS_CHARS:
        raise CanonicalJwsError("too-long")
    segs = token.split(".")
    if len(segs) != 3:
        raise CanonicalJwsError("bad-segment-count", "%d != 3" % len(segs))
    raws = []
    for i, seg in enumerate(segs):
        if len(seg) == 0:
            raise CanonicalJwsError("empty-segment", "segment %d" % i)
        raws.append(decode_canonical_b64url(seg))
    objs = []
    for raw in raws[:2]:
        if raw[:3] == b"\xef\xbb\xbf":
            raise CanonicalJwsError("bom")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise CanonicalJwsError("bad-utf8")
        try:
            v = strict_parse(text)
        except (StrictJsonError, RecursionError) as e:
            raise CanonicalJwsError("bad-json", str(e))
        if not isinstance(v, dict):
            raise CanonicalJwsError("not-an-object")
        objs.append(v)
    return objs[0], objs[1], segs


# ------------------------------------------------------------------------------------------------------------ discovery


def discovery_url(issuer: str) -> str:
    """The discovery URL: ``/.well-known/openid-configuration`` appended, one trailing slash of the issuer not doubled."""
    if not isinstance(issuer, str):
        raise TypeError("discovery_url: issuer must be a string")
    return (issuer[:-1] if issuer.endswith("/") else issuer) + _WELL_KNOWN


def _as_metadata(body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict):
        raise OidcDiscoveryError("discoverOidc: metadata is not a JSON object")
    issuer = body.get("issuer")
    if not isinstance(issuer, str) or issuer == "":
        raise OidcDiscoveryError('discoverOidc: metadata is missing a string "issuer"')
    jwks_uri = body.get("jwks_uri")
    if not isinstance(jwks_uri, str) or jwks_uri == "":
        raise OidcDiscoveryError('discoverOidc: metadata is missing a string "jwks_uri"')
    meta: Dict[str, Any] = {"issuer": issuer, "jwks_uri": jwks_uri}
    for k, v in body.items():
        if k != "issuer" and k != "jwks_uri":
            meta[k] = v
    return meta


def discover_oidc(issuer: str, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fetch and parse the issuer's discovery document. opts: ``fetch`` (required), ``max_bytes``, ``require_https`` (default True)."""
    opts = opts or {}
    if not isinstance(issuer, str) or issuer == "":
        raise OidcDiscoveryError("discoverOidc: issuer must be a non-empty string")
    require_https = opts.get("require_https") is not False
    if require_https and not _is_https(issuer):
        raise OidcDiscoveryError("discoverOidc: issuer '%s' is not an https URL" % issuer)
    do_fetch = opts.get("fetch")
    if not callable(do_fetch):
        raise OidcDiscoveryError("discoverOidc: no fetch implementation available (pass opts.fetch)")
    url = discovery_url(issuer)
    try:
        res = do_fetch(url, {"accept": "application/json"}, None)
    except Exception as e:  # noqa: BLE001 - any failure of the injected fetch is a failed discovery
        raise OidcDiscoveryError("discoverOidc: fetch of %s failed" % url) from e
    status = res.get("status") if isinstance(res, dict) else None
    if not _is_num(status) or not 200 <= status <= 299:
        raise OidcDiscoveryError("discoverOidc: %s returned HTTP %s" % (url, status))
    max_bytes = opts.get("max_bytes")
    if max_bytes is None:
        max_bytes = DEFAULT_MAX_DISCOVERY_BYTES
    cap = _to_number(max_bytes)
    headers = {str(k).lower(): v for k, v in (res.get("headers") or {}).items()}
    cl = headers.get("content-length")
    declared = 0.0 if cl is None else js_number(str(cl))
    if fin(declared) and declared > cap:
        raise OidcDiscoveryError("discoverOidc: %s response exceeds %s bytes" % (url, max_bytes))
    try:
        text = res.get("body", "")
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", "replace")
        if len(text.encode("utf-8", "surrogatepass")) > cap:
            raise OidcDiscoveryError("discoverOidc: %s response exceeds %s bytes" % (url, max_bytes))
        body = js_json_loads(text)
    except OidcDiscoveryError:
        raise
    except Exception as e:  # noqa: BLE001
        raise OidcDiscoveryError("discoverOidc: %s did not return valid JSON" % url) from e
    meta = _as_metadata(body)
    if meta["issuer"] != issuer:
        raise OidcDiscoveryError("discoverOidc: metadata issuer '%s' does not match requested '%s'" % (meta["issuer"], issuer))
    if require_https and not _is_https(meta["jwks_uri"]):
        raise OidcDiscoveryError("discoverOidc: jwks_uri '%s' is not an https URL" % meta["jwks_uri"])
    return meta


# ------------------------------------------------------------------------------------------------------------ JWK handling

_CURVES = {"ES256": ("P-256", 32, "sha256"), "ES384": ("P-384", 48, "sha384"), "ES512": ("P-521", 66, "sha512")}
_HASHES = {"256": "sha256", "384": "sha384", "512": "sha512"}


def _cryptography() -> Any:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError as e:  # pragma: no cover - only without the optional extra
        raise ImportError("RS*/PS*/ES* ID-token signatures need the 'cryptography' package: pip install cryptography") from e

    class _NS:
        pass

    ns = _NS()
    ns.InvalidSignature, ns.hashes, ns.ec, ns.padding, ns.rsa, ns.utils = InvalidSignature, hashes, ec, padding, rsa, utils  # type: ignore[attr-defined]
    return ns


def _invalid(msg: str) -> OidcVerificationError:
    return OidcVerificationError("invalid_token", msg)


def _jwk_type(jwk: Dict[str, Any]) -> str:
    kty = jwk.get("kty")
    if kty == "RSA":
        return "rsa"
    if kty == "EC":
        return "ec"
    if kty == "OKP":
        if jwk.get("crv") == "Ed25519":
            return "ed25519"
        if jwk.get("crv") == "Ed448":
            return "ed448"
        raise _invalid("Invalid key for this operation, its crv must be Ed25519 or Ed448")
    raise _invalid("Invalid key for this operation, its kty must be RSA, OKP, or EC")


def _jwk_b64(jwk: Dict[str, Any], name: str) -> bytes:
    v = jwk.get(name)
    if not isinstance(v, str):
        raise ValueError("JWK member %s is missing" % name)
    return node_b64decode(v)


def _load_public(jwk: Dict[str, Any]) -> Tuple[Any, ...]:
    """The usable public key of a JWK; ValueError when its key material is invalid."""
    t = _jwk_type(jwk)
    if t == "ed25519":
        x = _jwk_b64(jwk, "x")
        if len(x) != 32:
            raise ValueError("bad Ed25519 key")
        return (t, x)
    if t == "ed448":
        if len(_jwk_b64(jwk, "x")) != 57:
            raise ValueError("bad Ed448 key")
        return (t,)
    c = _cryptography()
    if t == "ec":
        crv = jwk.get("crv")
        size = {"P-256": 32, "P-384": 48, "P-521": 66}.get(crv)
        curve = {"P-256": c.ec.SECP256R1, "P-384": c.ec.SECP384R1, "P-521": c.ec.SECP521R1}.get(crv)
        if size is None or curve is None:
            raise ValueError("unsupported curve")
        x, y = _jwk_b64(jwk, "x"), _jwk_b64(jwk, "y")
        if len(x) != size or len(y) != size:
            raise ValueError("bad EC coordinates")
        key = c.ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve()).public_key()
        return (t, crv, key, size)
    n, e = _jwk_b64(jwk, "n"), _jwk_b64(jwk, "e")
    if len(n) == 0 or len(e) == 0:
        raise ValueError("bad RSA key")
    return (t, c.rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key(), len(n) * 8)


def _is_jwk(k: Any) -> bool:
    return isinstance(k, dict) and isinstance(k.get("kty"), str)


def _check_key_type(alg: str, key: Any) -> None:
    """jose's checkKeyTypeWithJwk for verification: the key must suit the alg family and, as a JWK, be public / usable for sig."""
    def matches_op(k: Dict[str, Any]) -> None:
        if "use" in k and k["use"] != "sig":
            raise _invalid("Invalid key for this operation, when present its use must be sig")
        if "key_ops" in k and not (isinstance(k["key_ops"], list) and "verify" in k["key_ops"]):
            raise _invalid("Invalid key for this operation, when present its key_ops must include verify")
        if "alg" in k and k["alg"] != alg:
            raise _invalid("Invalid key for this operation, when present its alg must be %s" % alg)

    if alg.startswith("HS"):
        if isinstance(key, (bytes, bytearray)):
            return
        if _is_jwk(key) and key["kty"] == "oct" and isinstance(key.get("k"), str):
            matches_op(key)
            return
        raise _invalid("Invalid key for a symmetric algorithm")
    if _is_jwk(key) and key["kty"] != "oct" and "d" not in key:
        matches_op(key)
        return
    raise _invalid("Invalid key for this operation: a public JWK is required")


def _verify_sig(alg: str, key: Any, sig: bytes, data: bytes) -> bool:
    """jose's runtime verify: a key unfit for the alg raises invalid_token; bad key material or a bad signature is False."""
    if alg.startswith("HS"):
        if alg not in ("HS256", "HS384", "HS512"):
            raise _invalid("alg %s is not supported" % alg)
        try:
            secret = bytes(key) if isinstance(key, (bytes, bytearray)) else node_b64decode(key["k"])
        except Exception:  # noqa: BLE001
            return False
        return hmac.compare_digest(hmac.new(secret, data, getattr(hashlib, _HASHES[alg[2:]])).digest(), sig)
    t = _jwk_type(key)
    if alg == "EdDSA":
        if t not in ("ed25519", "ed448"):
            raise _invalid("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448")
    elif alg[:2] in ("RS", "PS") and alg[2:] in _HASHES:
        if t != "rsa":
            raise _invalid("Invalid key for this operation, its asymmetricKeyType must be rsa")
        try:
            nbits = len(_jwk_b64(key, "n")) * 8
        except ValueError:
            nbits = 0
        if nbits < 2048:
            raise _invalid("%s requires key modulusLength to be 2048 bits or larger" % alg)
    elif alg in _CURVES:
        if t != "ec":
            raise _invalid("Invalid key for this operation, its asymmetricKeyType must be ec")
        if key.get("crv") != _CURVES[alg][0]:
            raise _invalid("Invalid key curve for the algorithm")
    else:
        raise _invalid("alg %s is not supported either by JOSE or your javascript runtime" % alg)
    try:
        loaded = _load_public(key)
        if alg == "EdDSA":
            return loaded[0] == "ed25519" and _ed.verify(loaded[1], data, sig)
        c = _cryptography()
        if alg in _CURVES:
            size, hname = loaded[3], _CURVES[alg][2]
            if len(sig) != 2 * size:
                return False
            der = c.utils.encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big"))
            loaded[2].verify(der, data, c.ec.ECDSA(getattr(c.hashes, hname.upper())()))
            return True
        h = getattr(c.hashes, "SHA" + alg[2:])()
        if alg.startswith("RS"):
            loaded[1].verify(sig, data, c.padding.PKCS1v15(), h)
        else:
            loaded[1].verify(sig, data, c.padding.PSS(c.padding.MGF1(h), h.digest_size), h)
        return True
    except ImportError:
        raise
    except Exception:  # noqa: BLE001 - InvalidSignature or unusable key material: not verified
        return False


def create_local_jwk_set(jwks: Any) -> Callable[[Dict[str, Any], Any], Dict[str, Any]]:
    """A resolver over a fixed JWK Set with jose's selection rules (kty from alg, kid, alg, use, key_ops, curve): exactly one
    candidate must match, and it must be a valid public key. Raises ValueError for a malformed set."""
    if not (isinstance(jwks, dict) and isinstance(jwks.get("keys"), list) and all(isinstance(k, dict) for k in jwks["keys"])):
        raise ValueError("JSON Web Key Set malformed")
    keys = copy.deepcopy(jwks["keys"])

    def get_key(header: Dict[str, Any], token: Any = None) -> Dict[str, Any]:
        alg, kid = header.get("alg"), header.get("kid")
        prefix = alg[:2] if isinstance(alg, str) else ""
        kty = {"RS": "RSA", "PS": "RSA", "ES": "EC", "Ed": "OKP"}.get(prefix)
        if kty is None:
            raise _invalid('Unsupported "alg" value for a JSON Web Key Set')
        out = []
        for jwk in keys:
            ok = jwk.get("kty") == kty
            if ok and isinstance(kid, str):
                ok = kid == jwk.get("kid")
            if ok and isinstance(jwk.get("alg"), str):
                ok = alg == jwk["alg"]
            if ok and isinstance(jwk.get("use"), str):
                ok = jwk["use"] == "sig"
            if ok and isinstance(jwk.get("key_ops"), list):
                ok = "verify" in jwk["key_ops"]
            if ok and alg == "EdDSA":
                ok = jwk.get("crv") in ("Ed25519", "Ed448")
            if ok:
                want = {"ES256": "P-256", "ES256K": "secp256k1", "ES384": "P-384", "ES512": "P-521"}.get(alg)
                if want is not None:
                    ok = jwk.get("crv") == want
            if ok:
                out.append(jwk)
        if len(out) == 0:
            raise _invalid("no applicable key found in the JSON Web Key Set")
        if len(out) != 1:
            raise _invalid("multiple matching keys found in the JSON Web Key Set")
        jwk = out[0]
        if jwk.get("d"):
            raise _invalid("JSON Web Key Set members must be public keys")
        try:
            _load_public(jwk)
        except ImportError:
            raise
        except Exception as e:  # noqa: BLE001
            raise _invalid("invalid JWK in the JSON Web Key Set") from e
        return jwk

    return get_key


# ------------------------------------------------------------------------------------------------------------ cached JWKS


def create_oidc_jwks(opts: Dict[str, Any]) -> Callable[[Dict[str, Any], Any], Dict[str, Any]]:
    """A caching resolver to pass as ``verify_id_token``'s ``key``. Keys are cached ``cache_max_age_sec`` (600); a stale set is
    refetched and, when that fails, verification is refused (code ``keys``). An unknown ``kid`` refetches at most once per
    ``cooldown_sec`` (30). opts: ``jwks_uri``, ``fetch``, ``cache_max_age_sec``, ``cooldown_sec``, ``max_bytes``,
    ``require_https``, ``timeout_ms``, ``now`` (a callable returning epoch milliseconds)."""
    jwks_uri = opts.get("jwks_uri")
    if not isinstance(jwks_uri, str) or jwks_uri == "":
        raise TypeError("createOidcJwks: jwksUri is required")
    rh = opts.get("require_https")
    if (rh if rh is not None else True) and not jwks_uri[:8].lower() == "https://":
        raise TypeError("createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)")
    now = opts.get("now") or (lambda: time.time() * 1000)
    for name in ("cache_max_age_sec", "cooldown_sec", "max_bytes", "timeout_ms"):
        v = opts.get(name)
        if v is not None and not (_is_num(v) and fin(v) and v >= 0):
            raise TypeError("createOidcJwks: %s must be a finite number >= 0" % name)
    max_age_ms = (600 if opts.get("cache_max_age_sec") is None else opts["cache_max_age_sec"]) * 1000
    cooldown_ms = (30 if opts.get("cooldown_sec") is None else opts["cooldown_sec"]) * 1000
    max_bytes = 1024 * 1024 if opts.get("max_bytes") is None else opts["max_bytes"]
    timeout_ms = DEFAULT_JWKS_TIMEOUT_MS if opts.get("timeout_ms") is None else opts["timeout_ms"]
    state: Dict[str, Any] = {"cache": None, "last_fetch": -math.inf}
    lock = threading.Lock()

    def keys_error(msg: str, cause: Optional[BaseException] = None) -> OidcVerificationError:
        return OidcVerificationError("keys", msg, cause)

    def refetch() -> None:
        do_fetch = opts.get("fetch")
        state["last_fetch"] = now()
        try:
            if not callable(do_fetch):
                raise RuntimeError("no fetch implementation available")
            if not to_float(timeout_ms).is_integer():  # AbortSignal.timeout takes an integer and throws before the fetch starts
                raise TypeError("The value of \"delay\" is out of range")
            res = do_fetch(jwks_uri, {"accept": "application/json"}, timeout_ms)
            status = res.get("status")
            if not _is_num(status) or not 200 <= status <= 299:
                raise RuntimeError("HTTP %s" % status)
            text = res.get("body", "")
            if isinstance(text, (bytes, bytearray)):
                text = bytes(text).decode("utf-8", "replace")
            if len(text.encode("utf-8", "surrogatepass")) > max_bytes:
                raise RuntimeError("response exceeds %s bytes" % max_bytes)
            jwks = js_json_loads(text)
            if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
                raise RuntimeError("not a JWK Set")
            resolve = create_local_jwk_set(jwks)
        except Exception as e:  # noqa: BLE001
            raise keys_error("could not fetch the issuer signing keys from %s" % jwks_uri, e) from e
        state["cache"] = {"at": now(), "resolve": resolve,
                          "kids": {k["kid"] for k in jwks["keys"] if isinstance(k.get("kid"), str)}}

    def load() -> None:
        with lock:  # shortcut: concurrent callers refetch one after another instead of sharing one in-flight request
            refetch()

    def resolver(header: Dict[str, Any], token: Any = None) -> Dict[str, Any]:
        t = now()
        if not (_is_num(t) and fin(t)):
            raise keys_error("the clock returned a non-finite time")
        cache = state["cache"]
        if cache is None or t - cache["at"] >= max_age_ms:
            state["cache"] = None  # never serve a stale set, even if the refetch below fails
            load()
        elif isinstance(header.get("kid"), str) and header["kid"] not in cache["kids"] and t - state["last_fetch"] >= cooldown_ms:
            load()
        return state["cache"]["resolve"](header, token)

    return resolver


def create_oidc_jwks_from_issuer(issuer: str, opts: Optional[Dict[str, Any]] = None) -> Callable[[Dict[str, Any], Any], Dict[str, Any]]:
    """Discover the issuer's ``jwks_uri`` (https required unless ``require_https`` is False) and build the resolver."""
    opts = opts or {}
    meta = discover_oidc(issuer, {"require_https": opts.get("require_https"), "fetch": opts.get("fetch")})
    return create_oidc_jwks(dict(opts, jwks_uri=meta["jwks_uri"]))


# ------------------------------------------------------------------------------------------------------------ verification


def _resolve_key(opts: Dict[str, Any]) -> Any:
    if opts.get("key") is not None:
        return opts["key"]
    require_https = opts.get("require_https")
    jwks_uri = opts.get("jwks_uri")
    if jwks_uri is None and opts.get("discover") is True:
        jwks_uri = discover_oidc(opts["issuer"], {"require_https": require_https, "fetch": opts.get("fetch")})["jwks_uri"]
    if jwks_uri is None:
        raise OidcVerificationError("config", "verifyIdToken: no key source (pass opts.key, opts.jwks_uri, or opts.discover)")
    try:
        return create_oidc_jwks({"jwks_uri": jwks_uri, "require_https": require_https, "fetch": opts.get("fetch")})
    except (TypeError, ValueError) as e:
        raise OidcVerificationError("config", "verifyIdToken: %s" % e, e) from e


def _truthy(v: Any) -> bool:
    """JavaScript truthiness of a JSON value ([] and {} are truthy)."""
    return not (v is None or v is False or v == 0 and not isinstance(v, (list, dict)) or v == "")


def _jwt_verify(token: str, header: Dict[str, Any], payload: Dict[str, Any], segs: List[str], key: Any,
                algs: List[str], opts: Dict[str, Any], audience: Any) -> None:
    """The jose jwtVerify steps, in jose's order; raises OidcVerificationError with the code the reference maps each failure to."""
    crit = header.get("crit")
    if "crit" in header:
        if not isinstance(crit, list) or len(crit) == 0 or any(not isinstance(c, str) or c == "" for c in crit):
            raise _invalid('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present')
        for p in crit:
            if p != "b64":
                raise _invalid('Extension Header Parameter "%s" is not recognized' % p)
            if "b64" not in header:
                raise _invalid('Extension Header Parameter "b64" is missing')
        if not isinstance(header["b64"], bool):
            raise _invalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean')
    alg = header.get("alg")
    if not isinstance(alg, str) or alg == "":
        raise _invalid('JWS "alg" (Algorithm) Header Parameter missing or invalid')
    if alg not in algs:
        raise _invalid('"alg" (Algorithm) Header Parameter value not allowed')
    from_fn = callable(key)
    if from_fn:
        key = key(header, None)
    _check_key_type(alg, key)
    data = ("%s.%s" % (segs[0], segs[1])).encode("utf-8")
    sig = decode_canonical_b64url(segs[2])
    if from_fn and _is_jwk(key) and not alg.startswith("HS"):
        try:
            _load_public(key)
        except ImportError:
            raise
        except Exception as e:  # noqa: BLE001
            raise _invalid("invalid JWK") from e
    if not _verify_sig(alg, key, sig, data):
        raise OidcVerificationError("signature", "id token signature verification failed")
    if isinstance(crit, list) and "b64" in crit and header.get("b64") is False:
        raise _invalid("JWTs MUST NOT use unencoded payload")

    issuer = opts["issuer"]
    max_age = opts.get("max_token_age_sec")
    for claim, code in (("iss", "issuer"), ("aud", "audience"), ("iat", "issued_at")):
        if claim == "iat" and max_age is None:
            continue
        if claim not in payload:
            raise OidcVerificationError(code, 'missing required "%s" claim' % claim)
    if issuer and payload.get("iss") != issuer:
        raise OidcVerificationError("issuer", 'unexpected "iss" claim value')
    if audience != "":
        want = [audience] if isinstance(audience, str) else list(audience)
        aud = payload.get("aud")
        if isinstance(aud, str):
            present = aud in want
        elif isinstance(aud, list):
            present = any(w in aud for w in want)
        else:
            present = False
        if not present:
            raise OidcVerificationError("audience", 'unexpected "aud" claim value')
    tol = opts.get("clock_tolerance_sec")
    if tol is None:
        tol = 0
    elif not _is_num(tol):
        raise _invalid("Invalid clockTolerance option type")  # stricter: no "5 s" strings
    now_opt = opts.get("now")
    now = math.floor(time.time() if now_opt is None else now_opt)
    if ("iat" in payload or _truthy(max_age)) and not _is_num(payload.get("iat")):
        raise OidcVerificationError("issued_at", '"iat" claim must be a number')
    if "nbf" in payload:
        if not _is_num(payload["nbf"]):
            raise OidcVerificationError("not_before", '"nbf" claim must be a number')
        if payload["nbf"] > now + tol:
            raise OidcVerificationError("not_before", '"nbf" claim timestamp check failed')
    if "exp" in payload:
        if not _is_num(payload["exp"]):
            raise OidcVerificationError("claims", '"exp" claim must be a number')
        if payload["exp"] <= now - tol:
            raise OidcVerificationError("expired", "id token has expired")
    if _truthy(max_age):
        if not _is_num(max_age):
            raise _invalid("invalid time period format")
        age = now - payload["iat"]
        if age - tol > max_age:
            raise OidcVerificationError("issued_at", "id token is older than the maximum accepted age")
        if age < 0 - tol:
            raise OidcVerificationError("issued_at", '"iat" claim timestamp check failed (it should be in the past)')


def _project_claims(payload: Dict[str, Any], opts: Dict[str, Any]) -> Dict[str, Any]:
    iss = _str(payload.get("iss"))
    if iss is None:
        raise OidcVerificationError("issuer", 'id token is missing the "iss" claim')
    sub = _str(payload.get("sub"))
    if sub is None:
        raise OidcVerificationError("claims", 'id token is missing the "sub" claim')
    if "aud" not in payload:
        raise OidcVerificationError("audience", 'id token is missing the "aud" claim')
    aud = payload["aud"]
    iat = _finite(payload.get("iat"))
    if iat is None:
        raise OidcVerificationError("issued_at", 'id token is missing a numeric "iat" claim')
    exp = _finite(payload.get("exp"))
    if exp is None:
        raise OidcVerificationError("expired", 'id token is missing a numeric "exp" claim')
    nonce, azp = _str(payload.get("nonce")), _str(payload.get("azp"))
    if opts.get("nonce") is not None and nonce != opts["nonce"]:
        raise OidcVerificationError(
            "nonce", "id token is missing the expected nonce" if nonce is None else "id token nonce does not match the expected value")
    aud_list = aud if isinstance(aud, list) else [aud]
    audience = opts["audience"]
    expected_azp = opts.get("authorized_party")
    if expected_azp is None:
        expected_azp = audience if isinstance(audience, str) else None
    if len(aud_list) > 1 and azp is None:
        raise OidcVerificationError("azp", "id token has multiple audiences but no azp (authorized party)")
    if azp is not None and expected_azp is not None and azp != expected_azp:
        raise OidcVerificationError("azp", "id token azp does not match the authorized party")
    out: Dict[str, Any] = {"iss": iss, "sub": sub, "aud": aud, "iat": iat, "exp": exp}
    for name, v in (("nonce", nonce), ("azp", azp), ("at_hash", _str(payload.get("at_hash"))), ("c_hash", _str(payload.get("c_hash")))):
        if v is not None:
            out[name] = v
    auth_time = _finite(payload.get("auth_time"))
    if auth_time is not None:
        out["auth_time"] = auth_time
    for name in ("email",):
        if _str(payload.get(name)) is not None:
            out[name] = payload[name]
    if isinstance(payload.get("email_verified"), bool):
        out["email_verified"] = payload["email_verified"]
    for name in ("name", "preferred_username", "given_name", "family_name", "picture"):
        if _str(payload.get(name)) is not None:
            out[name] = payload[name]
    if isinstance(payload.get("cnf"), dict):
        out["cnf"] = dict(payload["cnf"])
    return out


def _check_half_hash(name: str, actual: Optional[str], value: Any, alg: Any) -> None:
    """OIDC Core 3.1.3.6: base64url(left half of H(value)), H chosen by the ID token's alg (EdDSA = SHA-512)."""
    if actual is None:
        raise OidcVerificationError(name, "id token is missing the expected %s" % name)
    bits: Optional[str] = "512" if alg == "EdDSA" else (alg[-3:] if isinstance(alg, str) and alg[-3:] in ("256", "384", "512") else None)
    if bits is None:
        raise OidcVerificationError(name, "cannot compute %s for alg %s" % (name, alg))
    if not isinstance(value, str):
        raise _ArgTypeError("verifyIdToken: the %s source must be a string" % name)
    # Node's 'ascii' encoding keeps the low byte of each UTF-16 code unit
    units = value.encode("utf-16-le", "surrogatepass")
    ascii_bytes = bytes(units[i] for i in range(0, len(units), 2))
    digest = getattr(hashlib, "sha" + bits)(ascii_bytes).digest()
    if actual != _b64u(digest[: len(digest) // 2]):
        raise OidcVerificationError(name, "id token %s does not match the supplied value" % name)


def verify_id_token(id_token: str, opts: Dict[str, Any]) -> Dict[str, Any]:
    """Verify an ID token and return its verified claims. Raises OidcVerificationError (``.code``).

    opts: issuer, audience (str | list) required; nonce, authorized_party, access_token, code, clock_tolerance_sec,
    max_token_age_sec, algorithms, key | jwks_uri | discover (+ fetch), require_https, now (epoch seconds)."""
    if not isinstance(id_token, str) or id_token == "":
        raise OidcVerificationError("invalid_token", "verifyIdToken: idToken must be a non-empty string")
    if not isinstance(opts, dict):
        raise OidcVerificationError("config", "verifyIdToken: opts is required")
    if not isinstance(opts.get("issuer"), str) or opts["issuer"] == "":
        raise OidcVerificationError("config", "verifyIdToken: opts.issuer is required")
    audience = opts.get("audience")
    if not isinstance(audience, (str, list)):
        raise OidcVerificationError("config", "verifyIdToken: opts.audience is required")
    try:
        header, payload, segs = _check_canonical_jws(id_token)
    except CanonicalJwsError as e:
        raise OidcVerificationError("invalid_token", str(e)) from e

    key = _resolve_key(opts)
    algs = opts.get("algorithms")
    if algs is None:
        algs = list(DEFAULT_ID_TOKEN_ALGS)
    elif isinstance(algs, str):
        algs = list(algs)
    elif isinstance(algs, tuple):
        algs = list(algs)
    try:
        if not isinstance(algs, list) or any(not isinstance(a, str) for a in algs):
            raise TypeError('"algorithms" option must be an array of strings')
        _jwt_verify(id_token, header, payload, segs, key, algs, opts, audience)
    except OidcVerificationError:
        raise
    except ImportError:
        raise
    except Exception as e:  # noqa: BLE001 - every other verification failure is invalid_token, as the reference maps it
        raise OidcVerificationError("invalid_token", "id token verification failed", e) from e

    claims = _project_claims(payload, opts)
    alg = header.get("alg")
    if opts.get("access_token") is not None:
        _check_half_hash("at_hash", claims.get("at_hash"), opts["access_token"], alg)
    if opts.get("code") is not None:
        _check_half_hash("c_hash", claims.get("c_hash"), opts["code"], alg)
    return claims


# ------------------------------------------------------------------------------------------------------------ principal


def _canonical_ed25519_b64u(s: Any) -> Optional[str]:
    """`s` iff it is the canonical unpadded base64url of exactly 32 bytes."""
    if not isinstance(s, str) or s == "":
        return None
    try:
        raw = decode_canonical_b64url(s)
    except (CanonicalJwsError, ValueError):
        return None
    return s if len(raw) == 32 else None


def _ed25519_public_from_cnf(cnf: Any) -> Optional[str]:
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
        return None
    return _canonical_ed25519_b64u(jwk["x"])


def oidc_principal(claims: Dict[str, Any], opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Map verified claims onto a PCA principal: ``principal_id`` (``<iss>#<sub>``), a signed-in ``subject_caveat``, and
    ``principal_public`` when the token's ``cnf`` binds an Ed25519 key or ``opts['principal_public']`` supplies one (they must
    agree). Raises TypeError on a missing iss/sub or an invalid key, ValueError on a cnf mismatch."""
    opts = opts or {}
    if not isinstance(claims, dict):
        raise TypeError("oidcPrincipal: claims.iss is required")
    iss, sub = claims.get("iss"), claims.get("sub")
    if not isinstance(iss, str) or iss == "":
        raise TypeError("oidcPrincipal: claims.iss is required")
    if not isinstance(sub, str) or sub == "":
        raise TypeError("oidcPrincipal: claims.sub is required")
    if "cnf" in claims and claims["cnf"] is None:  # a null cnf is read as `null.jwk`
        raise TypeError("Cannot read properties of null (reading 'jwk')")
    from_token = _ed25519_public_from_cnf(claims.get("cnf"))
    principal_public = from_token
    if opts.get("principal_public") is not None:
        provided = _canonical_ed25519_b64u(opts["principal_public"])
        if provided is None:
            raise TypeError("oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key")
        if from_token is not None and from_token != provided:
            raise ValueError("oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token")
        principal_public = provided
    out: Dict[str, Any] = {"iss": iss, "sub": sub, "principal_id": "%s#%s" % (iss, sub),
                           "subject_caveat": {"type": OIDC_SUBJECT_CAVEAT, "iss": iss, "sub": sub}, "claims": claims}
    if principal_public is not None:
        out["principal_public"] = principal_public
    for src, dst in (("email", "email"), ("email_verified", "email_verified"), ("name", "name"),
                     ("preferred_username", "preferred_username"), ("auth_time", "auth_time")):
        if src in claims:
            out[dst] = claims[src]
    return out


def is_oidc_subject_caveat(cv: Any) -> bool:
    return (isinstance(cv, dict) and cv.get("type") == OIDC_SUBJECT_CAVEAT and isinstance(cv.get("iss"), str) and cv["iss"] != ""
            and isinstance(cv.get("sub"), str) and cv["sub"] != "")
