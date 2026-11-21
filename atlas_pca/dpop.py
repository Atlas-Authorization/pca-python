"""Sender-constrained proof of possession for PCA: RFC 9449 DPoP proofs (create / verify, replay store, server nonces), the
RFC 8705 mTLS confirmation, and the binding of both to a PCActn's leaf holder key. Mirrors the TypeScript reference
(@atlasauth/pca-dpop). Options are dicts keyed in snake_case. ES256 / ES384 / ES512 / PS256 / RS256 / Ed448 and X.509 parsing
use the optional ``cryptography`` package (imported lazily); Ed25519 uses ``atlas_pca.ed25519``. Every failure refuses.

Also holds the JOSE pieces the transaction-token module shares: the canonical compact-JWS gate and the JWT claim checks."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from . import ed25519
from ._fin import fin
from .oauth import _js_json, _parse_url, _truthy
from .pca import b64u, decode_b64u_strict, strict_parse

DPOP_ALLOWED_ALGS = ("EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256")
DPOP_JWT_TYP = "dpop+jwt"
DPOP_DEFAULT_MAX_AGE_SEC = 300
DPOP_CLOCK_SKEW_SEC = 5
DPOP_INMEMORY_MAX_ENTRIES = 100_000
DPOP_MAX_PROOF_BYTES = 8192
DEFAULT_MAX_JWS_BYTES = 64 * 1024


class DpopVerificationError(Exception):
    """A DPoP proof (or PCActn / DPoP binding) that failed to verify; `code` names the check."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class CanonicalJwsError(ValueError):
    def __init__(self, reason: str, detail: Optional[str] = None):
        super().__init__("non-canonical compact JWS: %s%s" % (reason, " (%s)" % detail if detail else ""))
        self.reason = reason


class InvalidUrlError(ValueError):
    code = "ERR_INVALID_URL"


class JoseError(Exception):
    """A JOSE-level refusal carrying the library's stable error code (ERR_JWS_INVALID, ERR_JWT_EXPIRED ...)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _jws_invalid(m):
    return JoseError("ERR_JWS_INVALID", m)


def _jwt_invalid(m):
    return JoseError("ERR_JWT_INVALID", m)


def _claim_failed(m):
    return JoseError("ERR_JWT_CLAIM_VALIDATION_FAILED", m)


def _need_crypto():
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise RuntimeError("this algorithm needs the 'cryptography' package (pip install 'atlas-pca[fast]')") from None


def _js_len(s: str) -> int:
    """JavaScript string length (UTF-16 code units)."""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _utf8(s: str) -> bytes:
    """TextEncoder.encode: a lone surrogate becomes U+FFFD."""
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def _now_sec(now: Any = None) -> int:
    if now is None:
        return int(time.time())
    if hasattr(now, "timestamp"):
        return int(math.floor(now.timestamp()))
    return int(math.floor(now))


# ---- canonical compact JWS (one accepted spelling per token) -------------------------------------------------------

def _decode_canonical_b64u(seg: str) -> bytes:
    if re.fullmatch(r"[A-Za-z0-9_-]*", seg) is None:
        raise CanonicalJwsError("bad-character")
    if len(seg) % 4 == 1:
        raise CanonicalJwsError("non-canonical-base64url", "impossible length")
    raw = decode_b64u_strict(seg)
    if raw is None:
        raise CanonicalJwsError("non-canonical-base64url")
    return raw


def _parse_json_bytes(raw: bytes) -> Any:
    if raw[:3] == b"\xef\xbb\xbf":
        raise CanonicalJwsError("bom")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CanonicalJwsError("bad-utf8") from None
    try:
        return strict_parse(text)
    except Exception as e:  # noqa: BLE001 - any strict-JSON refusal
        raise CanonicalJwsError("bad-json", str(e)) from None


def _as_object(v: Any) -> Dict[str, Any]:
    if not isinstance(v, dict):
        raise CanonicalJwsError("not-an-object")
    return v


def assert_canonical_compact_jws(token: Any, parts: int = 3, max_bytes: int = DEFAULT_MAX_JWS_BYTES, payload: str = "json") -> Dict[str, Any]:
    """Raises CanonicalJwsError unless `token` is the one canonical spelling of a compact JWS (or JWE with parts=5)."""
    if not isinstance(token, str):
        raise CanonicalJwsError("not-a-string")
    if _js_len(token) > max_bytes:
        raise CanonicalJwsError("too-long")
    segments = token.split(".")
    if len(segments) != parts:
        raise CanonicalJwsError("bad-segment-count", "%d != %d" % (len(segments), parts))
    raws: List[bytes] = []
    for i, seg in enumerate(segments):
        if len(seg) == 0:
            if parts == 5 and i == 1:
                raws.append(b"")
                continue
            raise CanonicalJwsError("empty-segment", "segment %d" % i)
        raws.append(_decode_canonical_b64u(seg))
    out: Dict[str, Any] = {"segments": segments, "header": _as_object(_parse_json_bytes(raws[0]))}
    if parts == 3 and payload == "json":
        out["payload"] = _as_object(_parse_json_bytes(raws[1]))
    return out


# ---- JWT claim checks (the library's jwtVerify claims stage) ---------------------------------------------------------

def _norm_typ(v: str) -> str:
    v = v.lower()
    return v[len("application/"):] if v.startswith("application/") else v


def jwt_claims_check(header: Dict[str, Any], payload: Any, typ: Optional[str] = None, required: Any = (), audience: Any = None,
                     clock_tolerance: Any = None, now: Any = None) -> Dict[str, Any]:
    """Raises JoseError on a failed typ / presence / aud / iat / nbf / exp check. `audience` None means no audience option."""
    if not isinstance(payload, dict):
        raise _jwt_invalid("JWT Claims Set must be a top-level JSON object")
    if typ and (not isinstance(header.get("typ"), str) or _norm_typ(header["typ"]) != _norm_typ(typ)):
        raise _claim_failed('unexpected "typ" JWT header value')
    presence = list(required)
    if audience is not None:
        presence.append("aud")
    for claim in presence:
        if claim not in payload:
            raise _claim_failed('missing required "%s" claim' % claim)
    if _truthy(audience):
        opts = [audience] if isinstance(audience, str) else audience
        if not isinstance(opts, list):
            raise TypeError("audience option must be a string or an array")
        aud = payload.get("aud")
        if isinstance(aud, str):
            ok = aud in opts
        elif isinstance(aud, list):
            ok = any(o in aud for o in opts)
        else:
            ok = False
        if not ok:
            raise _claim_failed('unexpected "aud" claim value')
    if clock_tolerance is None:
        tol = 0
    elif isinstance(clock_tolerance, (int, float)) and not isinstance(clock_tolerance, bool):
        tol = clock_tolerance
    else:
        raise TypeError("Invalid clockTolerance option type")
    epoch = _now_sec(now)

    def num(x):
        return isinstance(x, (int, float)) and not isinstance(x, bool)
    if "iat" in payload and not num(payload["iat"]):
        raise _claim_failed('"iat" claim must be a number')
    if "nbf" in payload:
        if not num(payload["nbf"]):
            raise _claim_failed('"nbf" claim must be a number')
        if payload["nbf"] > epoch + tol:
            raise _claim_failed('"nbf" claim timestamp check failed')
    if "exp" in payload:
        if not num(payload["exp"]):
            raise _claim_failed('"exp" claim must be a number')
        if payload["exp"] <= epoch - tol:
            raise JoseError("ERR_JWT_EXPIRED", '"exp" claim timestamp check failed')
    return payload


def _check_crit(header: Dict[str, Any]) -> None:
    """The library's critical-header rules: only `b64` is recognised, and an unencoded payload is refused for a JWT."""
    if "crit" not in header:
        return
    crit = header["crit"]
    if not isinstance(crit, list) or len(crit) == 0 or any(not isinstance(c, str) or c == "" for c in crit):
        raise _jws_invalid('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present')
    for p in crit:
        if p != "b64":
            raise JoseError("ERR_JOSE_NOT_SUPPORTED", 'Extension Header Parameter "%s" is not recognized' % p)
        if "b64" not in header:
            raise _jws_invalid('Extension Header Parameter "b64" is missing')
        if not isinstance(header["b64"], bool):
            raise _jws_invalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean')
        if header["b64"] is False:
            raise _jwt_invalid("JWTs MUST NOT use unencoded payload")


def jws_verify_compact(token: str, parsed: Dict[str, Any], algorithms: Any, resolve_verifier: Callable[[str, Dict[str, Any]], Callable[[bytes, bytes], bool]]) -> None:
    """The library's compact-JWS verification over an already canonical token: crit, alg allow-list, key, signature.
    `resolve_verifier(alg, header)` returns verify(data, signature) -> bool (or raises)."""
    header = parsed["header"]
    _check_crit(header)
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise _jws_invalid('JWS "alg" (Algorithm) Header Parameter missing or invalid')
    if alg not in algorithms:
        raise JoseError("ERR_JOSE_ALG_NOT_ALLOWED", '"alg" (Algorithm) Header Parameter value not allowed')
    verify = resolve_verifier(alg, header)
    p, pl, sg = parsed["segments"]
    sig = decode_b64u_strict(sg)
    if sig is None:
        raise _jws_invalid("Failed to base64url decode the signature")
    if not verify(("%s.%s" % (p, pl)).encode("ascii"), sig):
        raise JoseError("ERR_JWS_SIGNATURE_VERIFICATION_FAILED", "signature verification failed")


# ---- JWK helpers --------------------------------------------------------------------------------------------------

def _jwk_get(jwk: Any, k: str) -> Any:
    if jwk is None:
        raise TypeError("jwk is null")
    return jwk.get(k) if isinstance(jwk, dict) else None


def jwk_thumbprint(jwk: Any, digest: Optional[str] = "sha256") -> str:
    """RFC 7638 JWK thumbprint (base64url) of an EC / OKP / RSA / oct key."""
    if not isinstance(jwk, dict):
        raise TypeError("JWK must be an object")
    digest = "sha256" if digest is None else digest
    if digest not in ("sha256", "sha384", "sha512"):
        raise TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"')

    def check(v):
        if not isinstance(v, str) or not v:
            raise JoseError("ERR_JWK_INVALID", "JWK member missing or invalid")
        return v
    kty = jwk.get("kty")
    if kty == "EC":
        comp = {"crv": check(jwk.get("crv")), "kty": kty, "x": check(jwk.get("x")), "y": check(jwk.get("y"))}
    elif kty == "OKP":
        comp = {"crv": check(jwk.get("crv")), "kty": kty, "x": check(jwk.get("x"))}
    elif kty == "RSA":
        comp = {"e": check(jwk.get("e")), "kty": kty, "n": check(jwk.get("n"))}
    elif kty == "oct":
        comp = {"k": check(jwk.get("k")), "kty": kty}
    else:
        raise JoseError("ERR_JOSE_NOT_SUPPORTED", '"kty" (Key Type) Parameter missing or unsupported')
    return b64u(hashlib.new(digest, _utf8(_js_json(comp))).digest())


def dpop_alg_for_jwk(jwk: Any) -> str:
    """The JWS `alg` for a key from its kty / crv. Raises DpopVerificationError(unsupported_key) for anything else."""
    kty, crv = _jwk_get(jwk, "kty"), _jwk_get(jwk, "crv")
    if kty == "OKP":
        if crv in ("Ed25519", "Ed448"):
            return "EdDSA"
        raise DpopVerificationError("unsupported_key", "unsupported OKP curve for DPoP")
    if kty == "EC":
        if crv == "P-256":
            return "ES256"
        if crv == "P-384":
            return "ES384"
        if crv == "P-521":
            return "ES512"
        raise DpopVerificationError("unsupported_key", "unsupported EC curve for DPoP")
    if kty == "RSA":
        return "PS256"
    raise DpopVerificationError("unsupported_key", "unsupported key type for DPoP")


def dpop_alg_matches_jwk(alg: Any, jwk: Any) -> bool:
    """True when the allow-listed JWS `alg` belongs to the key type of `jwk`. Unknown algs never match."""
    if alg not in ("EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256"):
        return False
    kty, crv = _jwk_get(jwk, "kty"), _jwk_get(jwk, "crv")
    if alg == "EdDSA":
        return kty == "OKP" and crv in ("Ed25519", "Ed448")
    if alg in ("PS256", "RS256"):
        return kty == "RSA"
    return kty == "EC" and crv == {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg]


def _to_public_jwk(jwk: Any) -> Dict[str, Any]:
    if not isinstance(jwk, dict):
        raise TypeError("publicJwk must be an object")
    pub: Dict[str, Any] = {"kty": jwk.get("kty")}
    for k in ("crv", "x", "y", "n", "e"):
        if k in jwk:
            pub[k] = jwk[k]
    return pub


def normalize_htu(url: Any) -> str:
    """The HTTP target URI with query and fragment stripped (RFC 9449 section 4.3): protocol, host and path of the parsed URL.
    Raises InvalidUrlError for text the platform URL parser refuses."""
    u = _parse_url(url) if isinstance(url, str) else None
    if u is None:
        raise InvalidUrlError("Invalid URL")
    return u["htu"]


def ath_for(access_token: str) -> str:
    """The DPoP access-token hash: base64url(SHA-256(access token))."""
    return b64u(hashlib.sha256(_utf8(access_token)).digest())


# ---- replay store, nonces ---------------------------------------------------------------------------------------

class InMemoryDpopReplayStore:
    """Single-process, bounded jti store: at capacity a new key raises (the verifier then refuses replay_store_error)."""

    def __init__(self, max_entries: int = DPOP_INMEMORY_MAX_ENTRIES):
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise DpopVerificationError("misconfigured", "maxEntries must be a positive integer")
        self._max = max_entries
        self._seen: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def add_if_absent(self, key: str, expires_at_sec: float, now_sec: float) -> bool:
        if not (fin(now_sec) and fin(expires_at_sec)):
            return False  # a non-finite clock or expiry never records or releases an entry
        with self._lock:
            held = self._seen.get(key)
            if held is not None and not (now_sec >= held):
                return False
            if held is None and len(self._seen) >= self._max:
                for k in [k for k, exp in self._seen.items() if now_sec >= exp]:
                    del self._seen[k]
                if len(self._seen) >= self._max:
                    raise RuntimeError("replay store is full")
            self._seen[key] = expires_at_sec
            return True


def create_in_memory_dpop_replay_store(max_entries: Optional[int] = None) -> InMemoryDpopReplayStore:
    return InMemoryDpopReplayStore(DPOP_INMEMORY_MAX_ENTRIES if max_entries is None else max_entries)


def run_dpop_replay_store_conformance(make: Callable[[], Any]) -> List[str]:
    """Conformance suite for a replay store: the failed checks (empty means conformant). `make` returns a fresh empty store."""
    failures: List[str] = []

    def check(ok, name):
        if not ok:
            failures.append(name)
    s = make()
    check(s.add_if_absent("a", 200, 100) is True, "first sight of a key returns true")
    check(s.add_if_absent("a", 200, 101) is False, "second sight of the same key returns false")
    check(s.add_if_absent("b", 200, 101) is True, "a different key is independent")
    check(s.add_if_absent("a", 200, 199) is False, "still seen one second before expiry")
    t = make()
    t.add_if_absent("c", 200, 100)
    check(t.add_if_absent("c", 400, 200) is True, "an expired entry may be added again (nowSec >= expiresAtSec)")
    u = make()
    results: List[Any] = []
    threads = [threading.Thread(target=lambda: results.append(u.add_if_absent("race", 200, 100))) for _ in range(16)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    wins = len([r for r in results if r])
    check(wins == 1, "16 concurrent adds of one key: exactly one wins (got %d)" % wins)
    return failures


class DpopNonceIssuer:
    """Stateless server DPoP nonces (RFC 9449 sections 8 and 9): a timestamp MACed with a server secret."""

    def __init__(self, secret: Any, ttl_sec: Any = None):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise DpopVerificationError("misconfigured", "nonce secret must be at least 32 bytes")
        ttl = 300 if ttl_sec is None else ttl_sec
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not fin(ttl) or ttl <= 0:
            raise DpopVerificationError("misconfigured", "nonce ttlSec must be positive")
        self._secret, self._ttl = bytes(secret), ttl

    def _mac(self, ts: bytes) -> bytes:
        return hmac.new(self._secret, b"dpop-nonce\x00" + ts, hashlib.sha256).digest()[:16]

    def issue(self, now_sec: Any = None) -> str:
        n = _now_sec() if now_sec is None else now_sec
        if isinstance(n, float):
            if n != math.floor(n):
                raise ValueError("The number cannot be converted to a BigInt")
            n = int(n)
        ts = int(n).to_bytes(8, "big")
        return b64u(ts + self._mac(ts))

    def check(self, nonce: Any, now_sec: Any = None) -> bool:
        if not isinstance(nonce, str):
            return False
        raw = decode_b64u_strict(nonce)
        if raw is None or len(raw) != 24:
            return False
        ts = raw[:8]
        if not hmac.compare_digest(raw[8:], self._mac(ts)):
            return False
        n = _now_sec() if now_sec is None else now_sec
        issued = int.from_bytes(ts, "big")
        return fin(n) and issued <= n + DPOP_CLOCK_SKEW_SEC and n - issued <= self._ttl


def create_dpop_nonce_issuer(secret: Any, ttl_sec: Any = None) -> DpopNonceIssuer:
    return DpopNonceIssuer(secret, ttl_sec)


# ---- key import / signing (ES / PS / RS / Ed448 through `cryptography`) -------------------------------------------

_EC = {"P-256": ("SECP256R1", 32, "sha256"), "P-384": ("SECP384R1", 48, "sha384"), "P-521": ("SECP521R1", 66, "sha512")}


def _b64u_int(v: Any) -> int:
    raw = decode_b64u_strict(v) if isinstance(v, str) else None
    if raw is None:
        raise TypeError("invalid JWK member")
    return int.from_bytes(raw, "big")


def _jwk_verifier(jwk: Any, alg: str) -> Callable[[bytes, bytes], bool]:
    """A verify(data, signature) for a PUBLIC embedded JWK under `alg` (the key type already matches the alg)."""
    if not isinstance(jwk, dict):
        raise _jws_invalid('"jwk" (JSON Web Key) Header Parameter must be a JSON object')
    kty = jwk.get("kty")
    if kty == "RSA" and "oth" in jwk:
        raise JoseError("ERR_JOSE_NOT_SUPPORTED", 'RSA JWK "oth" (Other Primes Info) Parameter value is not supported')
    if kty not in ("RSA", "EC", "OKP"):
        raise _jws_invalid('"jwk" (JSON Web Key) Header Parameter must be a public key')
    if _truthy(jwk.get("d")):
        raise _jws_invalid('"jwk" (JSON Web Key) Header Parameter must be a public key')
    if kty == "OKP":
        if jwk.get("crv") == "Ed25519":
            pub = decode_b64u_strict(jwk.get("x"), 32)
            if pub is None:
                raise TypeError("invalid Ed25519 key")
            return lambda data, sig: ed25519.verify(pub, data, sig)
        _need_crypto()
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
        raw = decode_b64u_strict(jwk.get("x"), 57)
        if raw is None or jwk.get("crv") != "Ed448":
            raise TypeError("invalid Ed448 key")
        k448 = Ed448PublicKey.from_public_bytes(raw)

        def v448(data, sig):
            try:
                k448.verify(sig, data)
                return True
            except InvalidSignature:
                return False
        return v448
    _need_crypto()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if kty == "EC":
        spec = _EC.get(jwk.get("crv"))
        if spec is None:
            raise TypeError("unsupported EC curve")
        curve = getattr(ec, spec[0])()
        kec = ec.EllipticCurvePublicNumbers(_b64u_int(jwk.get("x")), _b64u_int(jwk.get("y")), curve).public_key()
        size, hname = spec[1], spec[2]

        def vec(data, sig):
            if len(sig) != 2 * size:
                return False
            try:
                kec.verify(encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")), data,
                           ec.ECDSA(getattr(hashes, hname.upper())()))
                return True
            except InvalidSignature:
                return False
        return vec
    n = _b64u_int(jwk.get("n"))
    if n.bit_length() < 2048:
        raise TypeError("%s requires key modulusLength to be 2048 bits or larger" % alg)
    krsa = rsa.RSAPublicNumbers(_b64u_int(jwk.get("e")), n).public_key()

    def vrsa(data, sig):
        pad = padding.PSS(padding.MGF1(hashes.SHA256()), 32) if alg == "PS256" else padding.PKCS1v15()
        try:
            krsa.verify(sig, data, pad, hashes.SHA256())
            return True
        except InvalidSignature:
            return False
    return vrsa


def _sign_data(alg: str, key: Any, data: bytes) -> bytes:
    """Sign with a 32-byte Ed25519 seed, a private JWK dict, or a `cryptography` private key object."""
    if isinstance(key, (bytes, bytearray)):
        if alg != "EdDSA" or len(key) != 32:
            raise TypeError("a raw key signs EdDSA only and must be a 32-byte Ed25519 seed")
        return ed25519.sign_secret(bytes(key), data)
    if isinstance(key, dict):
        if key.get("use") is not None and key.get("use") != "sig":
            raise TypeError("Invalid key for this operation, when present its use must be sig")
        if key.get("key_ops") is not None and "sign" not in key["key_ops"]:
            raise TypeError("Invalid key for this operation, when present its key_ops must include sign")
        if key.get("alg") is not None and key["alg"] != alg:
            raise TypeError("Invalid key for this operation, when present its alg must be %s" % alg)
        kty, crv = key.get("kty"), key.get("crv")
        if alg == "EdDSA" and kty == "OKP" and crv == "Ed25519":
            seed = decode_b64u_strict(key.get("d"), 32)
            if seed is None:
                raise TypeError("a private JWK needs d")
            return ed25519.sign_secret(seed, data)
        _need_crypto()
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
        if alg == "EdDSA" and kty == "OKP" and crv == "Ed448":
            raw = decode_b64u_strict(key.get("d"), 57)
            if raw is None:
                raise TypeError("a private JWK needs d")
            return Ed448PrivateKey.from_private_bytes(raw).sign(data)
        if alg in ("ES256", "ES384", "ES512") and kty == "EC" and _EC.get(crv, (None,))[0] and {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg] == crv:
            spec = _EC[crv]
            pubn = ec.EllipticCurvePublicNumbers(_b64u_int(key.get("x")), _b64u_int(key.get("y")), getattr(ec, spec[0])())
            priv = ec.EllipticCurvePrivateNumbers(_b64u_int(key.get("d")), pubn).private_key()
            return _sign_ec(priv, data, spec)
        if alg in ("PS256", "RS256") and kty == "RSA":
            if _b64u_int(key.get("n")).bit_length() < 2048:
                raise TypeError("%s requires key modulusLength to be 2048 bits or larger" % alg)
            pn = rsa.RSAPublicNumbers(_b64u_int(key.get("e")), _b64u_int(key.get("n")))
            priv = rsa.RSAPrivateNumbers(_b64u_int(key.get("p")), _b64u_int(key.get("q")), _b64u_int(key.get("d")), _b64u_int(key.get("dp")),
                                         _b64u_int(key.get("dq")), _b64u_int(key.get("qi")), pn).private_key()
            return _sign_rsa(priv, alg, data)
        raise TypeError("the key does not fit the algorithm %s" % alg)
    _need_crypto()
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519 as _ed, rsa
    if isinstance(key, _ed.Ed25519PrivateKey) and alg == "EdDSA":
        return key.sign(data)
    if isinstance(key, ed448.Ed448PrivateKey) and alg == "EdDSA":
        return key.sign(data)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        crv = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}.get(key.curve.name)
        if crv is not None and {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}.get(alg) == crv:
            return _sign_ec(key, data, _EC[crv])
    if isinstance(key, rsa.RSAPrivateKey) and alg in ("PS256", "RS256"):
        if key.key_size < 2048:
            raise TypeError("%s requires key modulusLength to be 2048 bits or larger" % alg)
        return _sign_rsa(key, alg, data)
    raise TypeError("the key does not fit the algorithm %s" % alg)


def _sign_ec(priv: Any, data: bytes, spec: Any) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(getattr(hashes, spec[2].upper())())))
    return r.to_bytes(spec[1], "big") + s.to_bytes(spec[1], "big")


def _sign_rsa(priv: Any, alg: str, data: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    pad = padding.PSS(padding.MGF1(hashes.SHA256()), 32) if alg == "PS256" else padding.PKCS1v15()
    return priv.sign(data, pad, hashes.SHA256())


# ---- DPoP proof: create / verify -----------------------------------------------------------------------------------

def create_dpop_proof(method: str, url: str, private_key: Any, public_jwk: Any, nonce: Optional[str] = None, ath: Optional[str] = None,
                      iat: Optional[Any] = None, jti: Optional[str] = None) -> str:
    """Build and sign a DPoP proof JWT (typ dpop+jwt, embedded public jwk, claims htm / htu / iat / jti / nonce / ath).
    `private_key`: a 32-byte Ed25519 seed, a private JWK dict, or a `cryptography` private key object."""
    pub = _to_public_jwk(public_jwk)
    alg = dpop_alg_for_jwk(pub)
    claims: Dict[str, Any] = {
        "htm": method.upper(),
        "htu": normalize_htu(url),
        "iat": _now_sec() if iat is None else iat,
        "jti": str(uuid.uuid4()) if jti is None else jti,
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if ath is not None:
        claims["ath"] = ath
    head = b64u(_utf8(_js_json({"typ": DPOP_JWT_TYP, "alg": alg, "jwk": pub})))
    body = b64u(_utf8(_js_json(claims)))
    signing_input = ("%s.%s" % (head, body)).encode("ascii")
    return "%s.%s.%s" % (head, body, b64u(_sign_data(alg, private_key, signing_input)))


def _has_set(seen: Any, jti: str) -> bool:
    h = getattr(seen, "has", None)
    return bool(h(jti)) if callable(h) else jti in seen


def verify_dpop_proof(proof: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a DPoP proof: signature under the embedded jwk, typ, htm / htu against the request, iat freshness, optional jkt,
    nonce, access-token and jti replay. Raises DpopVerificationError on any failure; returns {claims, jwk, jkt}.
    Options (snake_case): method, url, max_age_sec, expected_jkt, seen_jti, replay_store, require_replay_store, nonce_issuer,
    now_sec, expected_nonce, access_token. `seen_jti` is a set (or has / add object); `replay_store` has add_if_absent.
    An absent max_age_sec means DPOP_DEFAULT_MAX_AGE_SEC; a non-number or non-finite one is refused (it would disable the stale check)."""
    max_age = DPOP_DEFAULT_MAX_AGE_SEC if opts.get("max_age_sec") is None else opts["max_age_sec"]
    if isinstance(max_age, bool) or not isinstance(max_age, (int, float)) or not fin(max_age) or max_age < 0:
        raise DpopVerificationError("max_age", "max_age_sec must be a finite, non-negative number of seconds")
    if opts.get("require_replay_store") is not False and opts.get("replay_store") is None and opts.get("seen_jti") is None:
        raise DpopVerificationError("replay_store_required", "no replay store configured; replay cannot be detected")
    if not isinstance(proof, str) or _js_len(proof) > DPOP_MAX_PROOF_BYTES:
        raise DpopVerificationError("oversize", "proof is not a string or exceeds %d bytes" % DPOP_MAX_PROOF_BYTES)
    try:
        parsed = assert_canonical_compact_jws(proof)
    except Exception as e:  # noqa: BLE001 - one malformed refusal
        raise DpopVerificationError("malformed", "not a JWS: %s" % e) from None
    header = parsed["header"]
    if header.get("typ") != DPOP_JWT_TYP:
        raise DpopVerificationError("typ", "header typ must be '%s'" % DPOP_JWT_TYP)
    if "jwk" not in header:
        raise DpopVerificationError("no_jwk", "proof header has no embedded jwk")
    hj = header["jwk"]
    if isinstance(hj, dict) and any(m in hj for m in ("d", "p", "q", "dp", "dq", "qi", "k")):
        raise DpopVerificationError("private_jwk", "proof header jwk contains private key material")
    if isinstance(header.get("alg"), str) and header["alg"] in DPOP_ALLOWED_ALGS and not dpop_alg_matches_jwk(header["alg"], hj):
        raise DpopVerificationError("alg_jwk_mismatch", "alg '%s' does not match the embedded jwk key type" % header["alg"])

    try:
        jws_verify_compact(proof, parsed, DPOP_ALLOWED_ALGS, lambda alg, h: _jwk_verifier(h.get("jwk") if isinstance(h.get("jwk"), dict) else None, alg))
        payload = jwt_claims_check(header, parsed["payload"], typ=DPOP_JWT_TYP)
    except Exception as e:  # noqa: BLE001 - every JOSE / key / claims failure is one signature refusal
        raise DpopVerificationError("signature", "DPoP signature did not verify: %s" % e) from None
    jwk = hj

    htm, htu, iat, jti = payload.get("htm"), payload.get("htu"), payload.get("iat"), payload.get("jti")
    if not isinstance(htm, str):
        raise DpopVerificationError("htm", "htm is missing or not a string")
    if not isinstance(htu, str):
        raise DpopVerificationError("htu", "htu is missing or not a string")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)) or not fin(iat):
        raise DpopVerificationError("iat", "iat is missing or not a number")
    if not isinstance(jti, str) or len(jti) == 0:
        raise DpopVerificationError("jti", "jti is missing or empty")

    if htm != opts["method"].upper():
        raise DpopVerificationError("htm", "htm '%s' does not match request method" % htm)
    if htu != normalize_htu(opts["url"]):
        raise DpopVerificationError("htu", "htu '%s' does not match request URL" % htu)

    now = _now_sec() if opts.get("now_sec") is None else opts["now_sec"]
    if isinstance(now, bool) or not isinstance(now, (int, float)) or not fin(now):
        raise DpopVerificationError("now", "now_sec must be a finite number")
    if iat > now + DPOP_CLOCK_SKEW_SEC:
        raise DpopVerificationError("iat_future", "iat is in the future")
    if now - iat > max_age:
        raise DpopVerificationError("iat_stale", "proof is older than %ss" % max_age)

    jkt = jwk_thumbprint(jwk)
    if "expected_jkt" in opts and jkt != opts["expected_jkt"]:
        raise DpopVerificationError("jkt", "embedded key thumbprint does not match expected jkt")
    if "expected_nonce" in opts and payload.get("nonce") != opts["expected_nonce"]:
        raise DpopVerificationError("nonce", "proof nonce is missing or does not match the expected nonce")
    if opts.get("nonce_issuer") is not None and not opts["nonce_issuer"].check(payload.get("nonce"), now):
        raise DpopVerificationError("nonce", "proof nonce is missing, forged or expired")
    if "access_token" in opts and payload.get("ath") != ath_for(opts["access_token"]):
        raise DpopVerificationError("ath", "proof ath is missing or does not match the access token")

    if opts.get("seen_jti") is not None:
        if _has_set(opts["seen_jti"], jti):
            raise DpopVerificationError("jti_replay", "jti '%s' has already been seen" % jti)
        opts["seen_jti"].add(jti)
    if opts.get("replay_store") is not None:
        try:
            fresh = opts["replay_store"].add_if_absent("%s.%s" % (jkt, jti), iat + max_age + DPOP_CLOCK_SKEW_SEC, now)
        except Exception as e:  # noqa: BLE001
            raise DpopVerificationError("replay_store_error", "replay store failed: %s" % e) from None
        if fresh is not True:
            raise DpopVerificationError("jti_replay", "jti '%s' has already been seen" % jti)

    claims = dict(payload)
    claims.update({"htm": htm, "htu": htu, "iat": iat, "jti": jti})
    if isinstance(payload.get("nonce"), str):
        claims["nonce"] = payload["nonce"]
    if isinstance(payload.get("ath"), str):
        claims["ath"] = payload["ath"]
    return {"claims": claims, "jwk": jwk, "jkt": jkt}


# ---- RFC 8705 mTLS confirmation ---------------------------------------------------------------------------------

def _pem_to_der(pem: str) -> bytes:
    m = re.search(r"-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----", pem)
    body = re.sub(r"[^A-Za-z0-9+/=]", "", m.group(1) if m else pem).split("=", 1)[0]  # the platform decoder stops at the first padding character
    if len(body) % 4 == 1:
        body = body[:-1]
    import base64
    return base64.b64decode(body + "=" * (-len(body) % 4))


def mtls_cnf(cert_der_or_pem: Any) -> Dict[str, str]:
    """RFC 8705 section 3.1 confirmation: {"x5t#S256": b64u(sha256(DER))} of a certificate given as DER bytes or PEM text."""
    if isinstance(cert_der_or_pem, str):
        der = _pem_to_der(cert_der_or_pem)
    elif isinstance(cert_der_or_pem, (bytes, bytearray)):
        der = bytes(cert_der_or_pem)
    else:
        raise TypeError("certificate must be DER bytes or a PEM string")
    return {"x5t#S256": b64u(hashlib.sha256(der).digest())}


def _first_der_element(b: bytes) -> bytes:
    """The leading DER element: a certificate followed by stray bytes still parses (the platform reader ignores them)."""
    if len(b) >= 2 and b[0] == 0x30:
        if b[1] < 0x80:
            end = 2 + b[1]
        else:
            n = b[1] & 0x7F
            end = 2 + n + int.from_bytes(b[2:2 + n], "big") if 1 <= n <= 4 and len(b) >= 2 + n else len(b)
        return b[:end]
    return b


def mtls_thumbprint(cert_der_or_pem: Any) -> str:
    """The thumbprint of a certificate that PARSES as X.509. Raises DpopVerificationError(cert) otherwise."""
    try:
        _need_crypto()
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        import base64
        raw = cert_der_or_pem.encode("utf-8") if isinstance(cert_der_or_pem, str) else bytes(cert_der_or_pem)
        m = re.search(rb"-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----", raw)
        der_in = base64.b64decode(re.sub(rb"\s", b"", m.group(1)), validate=True) if m else raw
        der = x509.load_der_x509_certificate(_first_der_element(der_in)).public_bytes(Encoding.DER)
    except Exception as e:  # noqa: BLE001
        raise DpopVerificationError("cert", "not an X.509 certificate: %s" % e) from None
    return b64u(hashlib.sha256(der).digest())


def assert_mtls_bound(cert_der_or_pem: Any, cnf: Any) -> Dict[str, str]:
    """RFC 8705 section 3.1: the presented certificate must hash to the cnf's x5t#S256. Raises cert / x5t_missing / x5t."""
    want = cnf.get("x5t#S256") if isinstance(cnf, dict) else None
    if not isinstance(want, str) or len(want) == 0:
        raise DpopVerificationError("x5t_missing", "cnf has no 'x5t#S256' thumbprint")
    got = mtls_thumbprint(cert_der_or_pem)
    if not hmac.compare_digest(got.encode("utf-8"), want.encode("utf-8", "surrogatepass")):
        raise DpopVerificationError("x5t", "client certificate thumbprint does not match cnf x5t#S256")
    return {"x5t#S256": got}


# ---- PCActn <-> DPoP binding ---------------------------------------------------------------------------------------

def leaf_holder_jwk(p: Dict[str, Any]) -> Dict[str, Any]:
    """The OKP / Ed25519 JWK of the PCActn's bound holder key: the leaf of its capability chain."""
    chain = p["cap_chain"]
    if chain is None:
        raise TypeError("cap_chain is null")
    leaf: Any = chain[-1] if isinstance(chain, (list, str)) and len(chain) > 0 else None
    if leaf is None and not (isinstance(chain, list) and len(chain) > 0):
        raise DpopVerificationError("no_leaf", "PCActn capability chain is empty; no bound holder key")
    if leaf is None:
        raise TypeError("leaf hop is null")
    jwk: Dict[str, Any] = {"kty": "OKP", "crv": "Ed25519"}
    if isinstance(leaf, dict) and "holder" in leaf:
        jwk["x"] = leaf["holder"]
    return jwk


def bind_pca_to_dpop(p: Dict[str, Any]) -> Dict[str, str]:
    """The cnf {jkt} confirmation for a PCActn's bound holder key (RFC 9449 section 6)."""
    return {"jkt": jwk_thumbprint(leaf_holder_jwk(p))}


def assert_pca_dpop(p: Dict[str, Any], dpop_proof: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """A DPoP proof held by the PCActn's bound holder key, for the given HTTP target (verify with expected_jkt fixed to it)."""
    jkt = bind_pca_to_dpop(p)["jkt"]
    o: Dict[str, Any] = {
        "method": opts["method"], "url": opts["url"],
        "max_age_sec": DPOP_DEFAULT_MAX_AGE_SEC if opts.get("max_age_sec") is None else opts["max_age_sec"],
        "expected_jkt": jkt,
    }
    for k in ("seen_jti", "replay_store", "require_replay_store", "nonce_issuer", "now_sec", "expected_nonce", "access_token"):
        if opts.get(k) is not None:
            o[k] = opts[k]
    return verify_dpop_proof(dpop_proof, o)
