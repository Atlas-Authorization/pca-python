"""Compact-JWS building blocks shared by the SD-JWT, VC and WebAuthn ports.

Two layers, both mirroring the TypeScript reference:

* the canonical compact-JWS gate (one accepted spelling per token), the twin of the reference's strict-JWS module;
* a small JOSE-compatible JWT sign / verify (EdDSA through atlas_pca.ed25519; ES256/384/512, RS256/384/512 and
  PS256/384/512 through the optional ``cryptography`` package) with the same claim checks, in the same order, as the
  JOSE library the reference uses (``exp`` / ``nbf`` / ``aud`` / ``iat``, ``crit`` handling, algorithm allow-list).

Keys: EdDSA keys are raw bytes (a 32-byte seed to sign, a 32-byte public key to verify), a JWK dict, or a
``cryptography`` key object; the other algorithms take a JWK dict (public, EC / RSA) or a ``cryptography`` key object.
HMAC and ``none`` algorithms are never supported (refused).
"""
from __future__ import annotations

from ._fin import fin
import base64
import hashlib
import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from . import ed25519
from .pca import StrictJsonError, strict_parse

DEFAULT_MAX_JWS_BYTES = 64 * 1024
_B64U = re.compile(r"[A-Za-z0-9_-]*")  # always fullmatch
_UNSET = object()
UNSET = _UNSET


# ---- JS-compatible helpers ------------------------------------------------------------------------------------------

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode("ascii")


def node_b64url_decode(s: str) -> bytes:
    """Buffer.from(s, 'base64url'): both alphabets, invalid characters skipped, stops at '=', lenient trailing bits."""
    end = s.find("=")
    if end >= 0:
        s = s[:end]
    chars = [c for c in s if c.isascii() and (c.isalnum() or c in "+/-_")]
    if len(chars) % 4 == 1:
        chars.pop()
    t = "".join(chars).replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    return base64.b64decode(t)


def sha256_ascii_b64u(s: str) -> str:
    """base64url(SHA-256(input)) where the input is written with Node's 'ascii' encoding (low byte of each UTF-16 unit)."""
    units = s.encode("utf-16-le", "surrogatepass")
    return b64u(hashlib.sha256(units[0::2]).digest())


def truthy(v: Any) -> bool:
    """JavaScript truthiness of a JSON value ([] and {} are truthy)."""
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return not (v == 0 or v != v)
    if isinstance(v, str):
        return v != ""
    return True


def is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def is_plain_object(v: Any) -> bool:
    return isinstance(v, dict)


def js_to_string(v: Any) -> str:
    """String(v) for a JSON value."""
    if isinstance(v, str):
        return v
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if is_number(v):
        return js_num(v)
    if isinstance(v, list):
        return ",".join("" if x is None else js_to_string(x) for x in v)
    return "[object Object]"


def js_num(v: Any) -> str:
    """ECMAScript Number::toString for a finite number (JSON.stringify renders non-finite as null)."""
    if isinstance(v, int):
        if abs(v) <= 2 ** 53:
            return str(v)
        try:
            v = float(v)
        except OverflowError:  # an int beyond the double range is the infinity the reference reads
            v = math.inf if v > 0 else -math.inf
    if v != v or v in (math.inf, -math.inf):
        return "null"
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    m, _, e = repr(abs(v)).partition("e")
    exp10 = int(e) if e else 0
    ip, _, fp = m.partition(".")
    allds = ip + fp
    lz = len(allds) - len(allds.lstrip("0"))
    digits = allds.lstrip("0").rstrip("0")
    n = len(ip) + exp10 - lz
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        ex = n - 1
        es = ("+" if ex >= 0 else "-") + str(abs(ex))
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + body


_ESC = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x0C: "\\f", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}


def _js_str(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if o in _ESC:
            out.append(_ESC[o])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)  # well-formed JSON.stringify escapes lone surrogates
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def js_json(v: Any) -> str:
    """JSON.stringify(v): insertion order kept, compact, JS number formatting."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _js_str(v)
    if isinstance(v, (int, float)):
        return js_num(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(js_json(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(_js_str(str(k)) + ":" + js_json(x) for k, x in v.items()) + "}"
    raise TypeError("js_json: unsupported type %s" % type(v).__name__)


def js_json_bytes(v: Any) -> bytes:
    return js_json(v).encode("utf-8")


def _no_constant(name: str) -> Any:
    raise ValueError("invalid JSON constant " + name)


def js_json_parse(text: str) -> Any:
    """JSON.parse: duplicate keys keep the last value, NaN / Infinity refused."""
    return json.loads(text, parse_constant=_no_constant)


def js_json_parse_no_duplicates(text: str, neg_zero: bool = False) -> Any:
    """JSON.parse that refuses a duplicate member at any depth (keys compared after unescaping; message ``duplicate key "k"``): the signer and a
    verifier could otherwise read different claims from the same bytes. Numbers and everything else stay as the sender wrote them;
    ``neg_zero`` reads the integer literal ``-0`` as the float -0.0, as JSON.parse does (Python would read it as 0)."""
    def pairs_hook(pairs: Any) -> dict:
        seen: set = set()
        for k, _v in pairs:
            if k in seen:
                raise ValueError("duplicate key %s" % json.dumps(k))
            seen.add(k)
        return dict(pairs)

    if neg_zero:
        return json.loads(text, parse_constant=_no_constant, object_pairs_hook=pairs_hook, parse_int=lambda t: -0.0 if t == "-0" else int(t))
    return json.loads(text, parse_constant=_no_constant, object_pairs_hook=pairs_hook)


# ---- canonical compact-JWS gate -------------------------------------------------------------------------------------

class CanonicalJwsError(ValueError):
    def __init__(self, reason: str, detail: Optional[str] = None):
        super().__init__("non-canonical compact JWS: %s%s" % (reason, " (%s)" % detail if detail else ""))
        self.reason = reason


def decode_canonical_base64url(seg: str) -> bytes:
    if _B64U.fullmatch(seg) is None:
        raise CanonicalJwsError("bad-character")
    if len(seg) % 4 == 1:
        raise CanonicalJwsError("non-canonical-base64url", "impossible length")
    raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    if b64u(raw) != seg:
        raise CanonicalJwsError("non-canonical-base64url")
    return raw


def _parse_json_bytes(b: bytes) -> Any:
    if len(b) >= 3 and b[0] == 0xEF and b[1] == 0xBB and b[2] == 0xBF:
        raise CanonicalJwsError("bom")
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        raise CanonicalJwsError("bad-utf8") from None
    try:
        return strict_parse(text)
    except StrictJsonError as e:
        raise CanonicalJwsError("bad-json", str(e)) from None


def decode_canonical_json_segment(seg: str) -> Any:
    """A canonical base64url segment holding one strict-JSON document (any JSON type); used for SD-JWT disclosures."""
    return _parse_json_bytes(decode_canonical_base64url(seg))


def _as_object(v: Any) -> Dict[str, Any]:
    if not isinstance(v, dict):
        raise CanonicalJwsError("not-an-object")
    return v


def assert_canonical_compact_jws(token: Any, parts: int = 3, max_bytes: int = DEFAULT_MAX_JWS_BYTES,
                                 payload: str = "json") -> Dict[str, Any]:
    """Raises CanonicalJwsError unless `token` is the one canonical spelling of a compact JWS (parts=3) / JWE (parts=5).
    Returns {"segments", "header", "payload"?}."""
    if not isinstance(token, str):
        raise CanonicalJwsError("not-a-string")
    if len(token.encode("utf-16-le", "surrogatepass")) // 2 > max_bytes:
        raise CanonicalJwsError("too-long")
    segments = token.split(".")
    if len(segments) != parts:
        raise CanonicalJwsError("bad-segment-count", "%d != %d" % (len(segments), parts))
    raws: List[bytes] = []
    for i, seg in enumerate(segments):
        if seg == "":
            if parts == 5 and i == 1:
                raws.append(b"")
                continue
            raise CanonicalJwsError("empty-segment", "segment %d" % i)
        raws.append(decode_canonical_base64url(seg))
    out: Dict[str, Any] = {"segments": segments, "header": _as_object(_parse_json_bytes(raws[0]))}
    if parts == 3 and payload == "json":
        out["payload"] = _as_object(_parse_json_bytes(raws[1]))
    return out


def assert_canonical_jws_segments(protected_b64u: Any, signature_b64u: Any, max_bytes: int = DEFAULT_MAX_JWS_BYTES) -> Dict[str, Any]:
    """Gate for the protected + signature segments of a flattened / detached JWS (the payload travels out of band)."""
    if not isinstance(protected_b64u, str) or not isinstance(signature_b64u, str):
        raise CanonicalJwsError("not-a-string")
    if len(protected_b64u) + len(signature_b64u) > max_bytes:
        raise CanonicalJwsError("too-long")
    if protected_b64u == "" or signature_b64u == "":
        raise CanonicalJwsError("empty-segment")
    header = _as_object(_parse_json_bytes(decode_canonical_base64url(protected_b64u)))
    decode_canonical_base64url(signature_b64u)
    return header


def is_canonical_compact_jws(token: Any, **kw: Any) -> bool:
    try:
        assert_canonical_compact_jws(token, **kw)
        return True
    except CanonicalJwsError:
        return False


# ---- JOSE-compatible keys, signing, verification --------------------------------------------------------------------

class JoseError(Exception):
    """A refusal from the JOSE layer (bad header, algorithm not allowed, bad key, signature or claim failure). `code` is the reference
    library's stable error code when it has one."""
    code: Any = None

    def __init__(self, *args: Any, code: Any = None) -> None:
        super().__init__(*args)
        if code is not None:
            self.code = code


class OsslNotEnoughDataError(JoseError):
    """The reference runtime's OpenSSL error for a private key whose DER is shorter than its declared length."""
    code = "ERR_OSSL_ASN1_NOT_ENOUGH_DATA"


class JwsInvalidError(JoseError):
    """The reference JOSE library's ERR_JWS_INVALID (a malformed JWS header member)."""
    code = "ERR_JWS_INVALID"


class JoseNotSupportedError(JoseError):
    """The reference JOSE library's ERR_JOSE_NOT_SUPPORTED."""
    code = "ERR_JOSE_NOT_SUPPORTED"


_ALGS = {
    "EdDSA": None,
    "ES256": ("secp256r1", "sha256", 32), "ES384": ("secp384r1", "sha384", 48), "ES512": ("secp521r1", "sha512", 66),
    "RS256": ("rsa", "sha256", 0), "RS384": ("rsa", "sha384", 0), "RS512": ("rsa", "sha512", 0),
    "PS256": ("rsa-pss", "sha256", 0), "PS384": ("rsa-pss", "sha384", 0), "PS512": ("rsa-pss", "sha512", 0),
}
_CURVES = {"P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1"}


def _crypto() -> Any:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise JoseError("this algorithm needs the 'cryptography' package (pip install cryptography)") from None
    return True


def _b64int(s: Any) -> int:
    if not isinstance(s, str):
        raise JoseError("JWK member must be a string")
    return int.from_bytes(node_b64url_decode(s), "big")


def _is_jwk(k: Any) -> bool:
    return isinstance(k, dict) and isinstance(k.get("kty"), str)


def _jwk_matches(alg: str, k: dict) -> None:
    if "use" in k and k["use"] != "sig":
        raise JoseError("Invalid key for this operation, when present its use must be sig")
    if "key_ops" in k:
        ops = k["key_ops"]
        if not (isinstance(ops, list) and "verify" in ops):
            raise JoseError("Invalid key for this operation, when present its key_ops must include verify")
    if "alg" in k and k["alg"] != alg:
        raise JoseError("Invalid key for this operation, when present its alg must be " + alg)


def public_key_from_jwk(jwk: dict, alg: str) -> Any:
    """A verification key from a PUBLIC JWK: raw 32 bytes for Ed25519, a ``cryptography`` public key otherwise."""
    if not _is_jwk(jwk) or "d" in jwk:
        raise JoseError("JSON Web Key for this operation be a public JWK")
    kty = jwk["kty"]
    if kty == "OKP":
        if jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
            raise JoseError("unsupported OKP key")
        x = node_b64url_decode(jwk["x"])
        if len(x) != 32:
            raise JoseError("invalid Ed25519 public key")
        return x
    _crypto()
    if kty == "EC":
        from cryptography.hazmat.primitives.asymmetric import ec
        curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}.get(jwk.get("crv"))
        if curve is None:
            raise JoseError("unsupported EC curve")
        try:
            return ec.EllipticCurvePublicNumbers(_b64int(jwk.get("x")), _b64int(jwk.get("y")), curve()).public_key()
        except ValueError:
            raise JoseError("invalid EC public key") from None
    if kty == "RSA":
        from cryptography.hazmat.primitives.asymmetric import rsa
        try:
            return rsa.RSAPublicNumbers(_b64int(jwk.get("e")), _b64int(jwk.get("n"))).public_key()
        except ValueError:
            raise JoseError("invalid RSA public key") from None
    raise JoseError('Unsupported "kty" (Key Type) Parameter value')


def _verify_key(alg: str, key: Any) -> Any:
    """Normalize a caller key to a verification key valid for `alg` (raw Ed25519 bytes or a ``cryptography`` public key)."""
    if alg not in _ALGS:
        raise JoseError('Unsupported "alg" value for a JSON Web Signature Algorithm')
    if isinstance(key, (bytes, bytearray)):
        if alg != "EdDSA":
            raise JoseError("Invalid key for this operation: raw bytes are only an Ed25519 public key")
        if len(key) != 32:
            raise JoseError("invalid Ed25519 public key")
        return bytes(key)
    if isinstance(key, dict):
        if not _is_jwk(key):
            raise JoseError("Invalid key for this operation")
        _jwk_matches(alg, key)
        key = public_key_from_jwk(key, alg)
    if isinstance(key, (bytes, bytearray)):
        key = bytes(key)
    elif key is None or isinstance(key, (str, int, float, list)):
        raise JoseError("Invalid key for this operation")
    else:
        _crypto()
        if hasattr(key, "public_key") and callable(key.public_key):
            key = key.public_key()
    if alg == "EdDSA":
        if isinstance(key, bytes):
            return key
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if isinstance(key, Ed25519PublicKey):
            return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        raise JoseError("Invalid key for this operation: EdDSA needs an Ed25519 key")
    if isinstance(key, bytes):
        raise JoseError("Invalid key for this operation")
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    kind = _ALGS[alg][0]
    if kind.startswith("secp"):
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != kind:
            raise JoseError("Invalid key for this operation: %s needs an EC %s key" % (alg, kind))
    elif not isinstance(key, rsa.RSAPublicKey):
        raise JoseError("Invalid key for this operation: %s needs an RSA key" % alg)
    elif key.key_size < 2048:
        raise JoseError("%s requires key modulusLength to be 2048 bits or larger" % alg)
    return key


def _hash(name: str) -> Any:
    from cryptography.hazmat.primitives import hashes
    return {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}[name]()


def jws_verify(alg: str, key: Any, signature: bytes, data: bytes) -> bool:
    """Signature check only (no claims). Raises JoseError for an unusable key / algorithm; False for a bad signature."""
    k = _verify_key(alg, key)
    if alg == "EdDSA":
        return ed25519.verify(k, data, bytes(signature))
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    kind, h, size = _ALGS[alg]
    try:
        if kind.startswith("secp"):
            if len(signature) != 2 * size:
                return False
            r, s = int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
            if r == 0 or s == 0:
                return False
            k.verify(encode_dss_signature(r, s), data, ec.ECDSA(_hash(h)))
        elif kind == "rsa":
            k.verify(bytes(signature), data, padding.PKCS1v15(), _hash(h))
        else:
            k.verify(bytes(signature), data, padding.PSS(padding.MGF1(_hash(h)), _hash(h).digest_size), _hash(h))
        return True
    except (InvalidSignature, ValueError):
        return False


def jws_sign(alg: str, key: Any, data: bytes) -> bytes:
    if alg == "none":
        raise JoseNotSupportedError("alg none is not supported either by JOSE or your javascript runtime")
    if alg not in _ALGS:
        raise JoseError('Unsupported "alg" value for a JSON Web Signature Algorithm')
    if alg == "EdDSA":
        seed = None
        if isinstance(key, (bytes, bytearray)) and len(key) == 32:
            seed = bytes(key)
        elif isinstance(key, dict) and key.get("kty") == "OKP" and key.get("crv") == "Ed25519" and "d" in key:
            seed = node_b64url_decode(key["d"]) if isinstance(key["d"], str) else None
            if seed is not None and len(seed) != 32:
                seed = None
        elif key is not None and not isinstance(key, (str, int, float, list, dict, bytes, bytearray)):
            _crypto()
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            if isinstance(key, Ed25519PrivateKey):
                return key.sign(data)
        if seed is None and isinstance(key, (bytes, bytearray)) and len(key) < 32:
            raise OsslNotEnoughDataError("error:0680008E:asn1 encoding routines::not enough data")
        if seed is None:
            raise JoseError("Invalid key for this operation: EdDSA needs an Ed25519 private key")
        return ed25519.sign_secret(seed, data)
    _crypto()
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    kind, h, size = _ALGS[alg]
    if kind.startswith("secp"):
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != kind:
            raise JoseError("Invalid key for this operation")
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(_hash(h))))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise JoseError("Invalid key for this operation")
    if key.key_size < 2048:
        raise JoseError("%s requires key modulusLength to be 2048 bits or larger" % alg)
    if kind == "rsa":
        return key.sign(data, padding.PKCS1v15(), _hash(h))
    return key.sign(data, padding.PSS(padding.MGF1(_hash(h)), _hash(h).digest_size), _hash(h))


def sign_jwt(payload: dict, header: dict, key: Any) -> str:
    """SignJWT(payload).setProtectedHeader(header).sign(key): JSON in insertion order, compact."""
    alg = header.get("alg") if isinstance(header, dict) else None
    if not isinstance(alg, str) or not alg:
        raise JwsInvalidError('JWS "alg" (Algorithm) Header Parameter missing or invalid')
    if "crit" in header:
        raise JoseError("crit is not supported when signing")
    prot = b64u(js_json_bytes(header))
    body = b64u(js_json_bytes(payload))
    sig = jws_sign(alg, key, (prot + "." + body).encode("ascii"))
    return prot + "." + body + "." + b64u(sig)


_SECS_RE = re.compile(
    r"([+-])? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?",
    re.IGNORECASE)
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 86400 * 365.25}


def secs(s: str) -> float:
    m = _SECS_RE.fullmatch(s)
    if m is None or (m.group(4) and m.group(1)):
        raise TypeError("Invalid time period format")
    value = float(m.group(2))
    u = m.group(3).lower()
    k = "y" if u.startswith("y") else "w" if u.startswith("w") else "d" if u.startswith("d") else "h" if u.startswith("h") else (
        "m" if u.startswith("m") else "s")
    n = math.floor(value * _UNIT[k] + 0.5)
    return -n if (m.group(1) == "-" or m.group(4) == "ago") else n


def epoch_of_ms(ms: Any) -> float:
    """epoch(new Date(ms)): an out-of-range clock is an Invalid Date, whose epoch is NaN (every time comparison false)."""
    if not is_number(ms):
        raise TypeError("clock must be a number of milliseconds")
    t = float(ms)
    if not fin(t) or abs(t) > 8.64e15:
        return math.nan
    return math.floor(math.trunc(t) / 1000)


def _audience_matches(aud_payload: Any, aud_option: list) -> bool:
    if isinstance(aud_payload, str):
        return any(isinstance(a, str) and a == aud_payload for a in aud_option)
    if isinstance(aud_payload, list):
        return any(isinstance(p, str) and any(isinstance(a, str) and a == p for a in aud_option) for p in aud_payload)
    return False


def jwt_verify(jwt: Any, key: Any, algorithms: Any = _UNSET, audience: Any = _UNSET, now_ms: Any = _UNSET,
               clock_tolerance: Any = _UNSET) -> Tuple[dict, dict]:
    """jose jwtVerify(jwt, key, {algorithms, audience, currentDate, clockTolerance}) -> (payload, protected_header).
    Raises JoseError (or TypeError for a malformed option) on any refusal."""
    if not isinstance(jwt, str):
        raise JoseError("Compact JWS must be a string or Uint8Array", code="ERR_JWS_INVALID")
    parts = jwt.split(".")
    if len(parts) != 3:
        raise JoseError("Invalid Compact JWS", code="ERR_JWS_INVALID")
    prot, pay, sig = parts
    parsed: Any = {}
    if prot:
        try:
            parsed = js_json_parse(node_b64url_decode(prot).decode("utf-8", "replace"))
        except (ValueError, RecursionError):
            raise JoseError("JWS Protected Header is invalid", code="ERR_JWS_INVALID") from None
    header = parsed if isinstance(parsed, dict) else {}
    b64 = True
    if "crit" in header:
        crit = header["crit"]
        if not isinstance(crit, list) or not crit or any(not isinstance(c, str) or c == "" for c in crit):
            raise JoseError('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present', code="ERR_JWS_INVALID")
        for p in crit:
            if p != "b64":
                raise JoseError('Extension Header Parameter "%s" is not recognized' % p, code="ERR_JOSE_NOT_SUPPORTED")
            if p not in header:
                raise JoseError('Extension Header Parameter "%s" is missing' % p, code="ERR_JWS_INVALID")
        b64 = header["b64"]
        if not isinstance(b64, bool):
            raise JoseError('The "b64" (base64url-encode payload) Header Parameter must be a boolean', code="ERR_JWS_INVALID")
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise JoseError('JWS "alg" (Algorithm) Header Parameter missing or invalid', code="ERR_JWS_INVALID")
    if algorithms is not _UNSET and algorithms is not None:
        if not isinstance(algorithms, list) or any(not isinstance(a, str) for a in algorithms):
            raise TypeError('"algorithms" option must be an array of strings')
        if alg not in algorithms:
            raise JoseError('"alg" (Algorithm) Header Parameter value not allowed', code="ERR_JOSE_ALG_NOT_ALLOWED")
    ok = jws_verify(alg, key, node_b64url_decode(sig), (prot + "." + pay).encode("utf-8"))
    if not ok:
        raise JoseError("signature verification failed", code="ERR_JWS_SIGNATURE_VERIFICATION_FAILED")
    if not b64:
        raise JoseError("JWTs MUST NOT use unencoded payload", code="ERR_JWT_INVALID")
    try:
        payload = js_json_parse(node_b64url_decode(pay).decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        payload = None
    if not isinstance(payload, dict):
        raise JoseError("JWT Claims Set must be a top-level JSON object", code="ERR_JWT_INVALID")
    if audience is not _UNSET and "aud" not in payload:
        raise JoseError('missing required "aud" claim', code="ERR_JWT_CLAIM_VALIDATION_FAILED")
    if audience is not _UNSET and truthy(audience):
        opt = [audience] if isinstance(audience, str) else audience
        if not isinstance(opt, list):
            raise TypeError("audience option must be a string or an array of strings")
        if not _audience_matches(payload.get("aud"), opt):
            raise JoseError('unexpected "aud" claim value', code="ERR_JWT_CLAIM_VALIDATION_FAILED")
    if clock_tolerance is _UNSET or clock_tolerance is None:
        tol = 0
        if clock_tolerance is None:
            raise TypeError("Invalid clockTolerance option type")
    elif isinstance(clock_tolerance, str):
        tol = secs(clock_tolerance)
    elif is_number(clock_tolerance):
        tol = clock_tolerance
    else:
        raise TypeError("Invalid clockTolerance option type")
    if now_ms is _UNSET:
        import time
        now = math.floor(time.time())
    else:
        now = epoch_of_ms(now_ms)
    if "iat" in payload and not is_number(payload["iat"]):
        raise JoseError('"iat" claim must be a number', code="ERR_JWT_CLAIM_VALIDATION_FAILED")
    if "nbf" in payload:
        if not is_number(payload["nbf"]):
            raise JoseError('"nbf" claim must be a number', code="ERR_JWT_CLAIM_VALIDATION_FAILED")
        if payload["nbf"] > now + tol:
            raise JoseError('"nbf" claim timestamp check failed', code="ERR_JWT_CLAIM_VALIDATION_FAILED")
    if "exp" in payload:
        if not is_number(payload["exp"]):
            raise JoseError('"exp" claim must be a number', code="ERR_JWT_CLAIM_VALIDATION_FAILED")
        if payload["exp"] <= now - tol:
            raise JoseError('"exp" claim timestamp check failed', code="ERR_JWT_EXPIRED")
    return payload, header


def key_x(k: Any) -> Optional[str]:
    """The `x` member of a key as base64url (a JWK's x, raw Ed25519 bytes, or a cryptography public key), else None."""
    if isinstance(k, (bytes, bytearray)):
        return b64u(bytes(k))
    if isinstance(k, dict):
        return k["x"] if isinstance(k.get("x"), str) else None
    if k is None or isinstance(k, (str, int, float, list)):
        return None
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        pub = k.public_key() if hasattr(k, "public_key") and callable(k.public_key) else k
        if isinstance(pub, Ed25519PublicKey):
            return b64u(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        if isinstance(pub, ec.EllipticCurvePublicKey):
            n = pub.public_numbers()
            return b64u(n.x.to_bytes((pub.curve.key_size + 7) // 8, "big"))
    except ImportError:
        pass
    return None
