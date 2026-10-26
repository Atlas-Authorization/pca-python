"""Shared plumbing of the native hardware-attestation verifiers: the report_data binding, JavaScript-faithful JSON /
base64 helpers (the conformance vectors pin the reference's exact reason strings) and the `cryptography` glue.

Only `cryptography` (an optional dependency, extra `attest`) is imported lazily; everything else is the standard library.
"""
import base64
import binascii
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

ATTEST_BIND_DOMAIN = b"atlas-pca/attest-bind/v1\x00"
_MAX_SAFE = 9007199254740991


class JsError(Exception):
    """A JavaScript exception whose message the reference embeds in a reason string."""


# ------------------------------------------------------------------------------------------------ the binding


def _utf8(s: str) -> bytes:
    # a lone surrogate encodes as U+FFFD in JavaScript
    return re.sub("[\ud800-\udfff]", "�", s).encode("utf-8")


def _lp(s: str) -> bytes:
    b = _utf8(s)
    return len(b).to_bytes(4, "big") + b


def _expected_parts(exp: Any) -> Tuple[Any, Any, Any, Any]:
    if not isinstance(exp, dict):
        return None, None, None, None
    g = exp.get
    return (
        g("holder_pub", g("holderPub")),
        g("grant_ref", g("grantRef")),
        g("epoch"),
        g("nonce"),
    )


def attestation_binding(exp: Any) -> bytes:
    """SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)), the report_data / quote-bound value.

    Raises TypeError with the reference's message on a malformed expected binding."""
    holder, grant, epoch, nonce = _expected_parts(exp)
    if not isinstance(exp, dict) or not isinstance(holder, str) or len(holder) == 0:
        raise TypeError("binding: holderPub required")
    if not isinstance(grant, str) or len(grant) == 0:
        raise TypeError("binding: grantRef required")
    if not isinstance(nonce, str) or len(nonce) == 0:
        raise TypeError("binding: nonce required")
    ep = _safe_nonneg_int(epoch)
    if ep is None:
        raise TypeError("binding: epoch must be a non-negative safe integer")
    return hashlib.sha512(ATTEST_BIND_DOMAIN + _lp(holder) + _lp(grant) + ep.to_bytes(8, "big") + _lp(nonce)).digest()


def _safe_nonneg_int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if 0 <= v <= _MAX_SAFE else None
    if isinstance(v, float) and v.is_integer() and 0 <= v <= _MAX_SAFE:
        return int(v)
    return None


def attestation_challenge_sha256(exp: Any) -> bytes:
    """The 32-byte SPDM challenge that carries the PCA binding: SHA-256(attestationBinding(expected))."""
    return hashlib.sha256(attestation_binding(exp)).digest()


# ------------------------------------------------------------------------------------------------ JS-faithful helpers


def to_hex(b: bytes) -> str:
    return bytes(b).hex()


def is_num(v: Any) -> bool:
    """A JSON number (typeof 'number' and finite)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and v == v and v not in (float("inf"), float("-inf"))


def is_int(v: Any) -> bool:
    return is_num(v) and (isinstance(v, int) or float(v).is_integer())


def js_str(v: Any) -> str:
    """String(v) for the values that reach a reason text."""
    if v is None:
        return "undefined"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    return str(v)


def node_b64decode(s: str) -> bytes:
    """Node's lenient Buffer.from(s, 'base64' | 'base64url'): both alphabets, illegal characters skipped, stops at '='."""
    out: List[str] = []
    for ch in s:
        if ch == "=":
            break
        if ch == "-":
            ch = "+"
        elif ch == "_":
            ch = "/"
        if ("A" <= ch <= "Z") or ("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in "+/":
            out.append(ch)
    t = "".join(out)
    if len(t) % 4 == 1:
        t = t[:-1]
    t += "=" * ((4 - len(t) % 4) % 4)
    try:
        return base64.b64decode(t)
    except (binascii.Error, ValueError):
        return b""


def js_trim(s: str) -> str:
    return s.strip(" \t\n\r\x0b\x0c ﻿                　")


def js_number(s: str) -> float:
    """Number(string) for the values the reference converts (a measurement index)."""
    t = js_trim(s)
    if t == "":
        return 0.0
    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", t):
            return float(int(t, 16))
        if re.fullmatch(r"0[oO][0-7]+", t):
            return float(int(t[2:], 8))
        if re.fullmatch(r"0[bB][01]+", t):
            return float(int(t[2:], 2))
        if re.fullmatch(r"[+-]?(Infinity)", t):
            return float("-inf") if t.startswith("-") else float("inf")
        if re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?", t):
            return float(t)
    except (ValueError, OverflowError):
        pass
    return float("nan")


def big_int(v: Any) -> int:
    """BigInt(v) for a decimal string or an integer (JavaScript's SyntaxError text on anything else)."""
    if v is None:
        raise JsError("Cannot convert null to a BigInt")
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, str):
        t = js_trim(v)
        if t == "":
            return 0
        try:
            if re.fullmatch(r"[+-]?\d+", t):
                return int(t)
            if re.fullmatch(r"0[xX][0-9a-fA-F]+", t):
                return int(t, 16)
            if re.fullmatch(r"0[oO][0-7]+", t):
                return int(t[2:], 8)
            if re.fullmatch(r"0[bB][01]+", t):
                return int(t[2:], 2)
        except ValueError:
            pass
        raise JsError("Cannot convert %s to a BigInt" % v)
    raise JsError("Cannot convert %s to a BigInt" % js_str(v))


def _reject_constant(name: str) -> Any:
    raise ValueError("constant " + name)


_SPECIAL_JSON = ("NaN", "Infinity", "undefined", "[object Object]")
_LITERALS = ("null", "true", "false")


def _v8_json_message(text: str, pos: int) -> str:
    n = len(text)
    if pos >= n:
        return "Unexpected end of JSON input"
    if text in _SPECIAL_JSON:
        return '"%s" is not valid JSON' % text
    ch = text[pos]
    if ch == '"':
        return "Unexpected string in JSON at position %d" % pos
    if ch.isdigit() or ch == "-":
        return "Unexpected number in JSON at position %d" % pos
    ctx = 10
    if n < 2 * ctx + 1:
        return "Unexpected token '%s', \"%s\" is not valid JSON" % (ch, text)
    if pos < ctx:
        return "Unexpected token '%s', \"%s\"... is not valid JSON" % (ch, text[: pos + ctx])
    if pos < n - ctx:
        return "Unexpected token '%s', ...\"%s\"... is not valid JSON" % (ch, text[pos - ctx : pos + ctx])
    return "Unexpected token '%s', ...\"%s\" is not valid JSON" % (ch, text[pos - ctx :])


def js_json_loads(text: str) -> Any:
    """JSON.parse. Raises JsError carrying a V8-style message (common cases: end of input, unexpected token)."""
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as e:
        stripped = text.lstrip(" \t\n\r")
        if stripped == "":
            raise JsError("Unexpected end of JSON input")
        lead = len(text) - len(stripped)
        for lit in _LITERALS:
            if lit[0] == stripped[0]:
                k = 0
                while k < len(lit) and lead + k < len(text) and text[lead + k] == lit[k]:
                    k += 1
                if k < len(lit):
                    raise JsError(_v8_json_message(text, lead + k))
        pos = getattr(e, "pos", 0)
        if getattr(e, "msg", "") == "Extra data":
            raise JsError("Unexpected non-whitespace character after JSON at position %d" % pos)
        raise JsError(_v8_json_message(text, pos))


# ------------------------------------------------------------------------------------------------ strict JWS segments


class CanonicalJwsError(Exception):
    def __init__(self, reason: str, detail: Optional[str] = None) -> None:
        super().__init__("non-canonical compact JWS: %s%s" % (reason, " (%s)" % detail if detail else ""))


_B64U = re.compile(r"[A-Za-z0-9_-]*")


def decode_canonical_b64url(seg: str) -> bytes:
    """One strictly canonical unpadded base64url segment (the single accepted spelling of a signature / segment)."""
    if not _B64U.fullmatch(seg):
        raise CanonicalJwsError("bad-character")
    if len(seg) % 4 == 1:
        raise CanonicalJwsError("non-canonical-base64url", "impossible length")
    raw = base64.urlsafe_b64decode(seg + "=" * ((4 - len(seg) % 4) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != seg:
        raise CanonicalJwsError("non-canonical-base64url")
    return raw


# ------------------------------------------------------------------------------------------------ PEM / lenient decode

_PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")


def pem_blocks(pem: str) -> List[str]:
    return _PEM_BLOCK.findall(pem)


def pem_to_der(pem: str) -> bytes:
    m = re.search(r"-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----", pem)
    if not m or not m.group(1):
        raise ValueError("pemToDer: no certificate found")
    return node_b64decode(re.sub(r"\s+", "", m.group(1)))


def is_hex(s: str) -> bool:
    return len(s) > 0 and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s) is not None


def decode_claim_bytes(value: str) -> Optional[bytes]:
    """A byte-carrying claim: hex (optionally 0x-prefixed), else base64url, else base64; None when it decodes to nothing."""
    trimmed = js_trim(value)
    hx = trimmed[2:] if trimmed.startswith(("0x", "0X")) else trimmed
    if is_hex(hx):
        return bytes.fromhex(hx)
    out = node_b64decode(trimmed)
    return out if len(out) > 0 else None


# ------------------------------------------------------------------------------------------------ the cryptography glue


class _Crypto:
    pass


_crypto_ns: Optional[_Crypto] = None


def crypto() -> _Crypto:
    """The `cryptography` primitives (loaded lazily; the base package stays dependency-free)."""
    global _crypto_ns
    if _crypto_ns is None:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
        except ImportError as e:  # pragma: no cover - exercised only without the extra
            raise ImportError("the native attestation verifiers need the 'cryptography' package: pip install 'atlas-pca[attest]'") from e
        ns = _Crypto()
        ns.InvalidSignature = InvalidSignature  # type: ignore[attr-defined]
        ns.hashes, ns.serialization = hashes, serialization  # type: ignore[attr-defined]
        ns.ec, ns.padding, ns.rsa, ns.utils = ec, padding, rsa, utils  # type: ignore[attr-defined]
        _crypto_ns = ns
    return _crypto_ns


def hash_alg(name: str) -> Any:
    h = crypto().hashes
    return {"sha1": h.SHA1, "sha224": h.SHA224, "sha256": h.SHA256, "sha384": h.SHA384, "sha512": h.SHA512}[name]()


def load_public_key(spki_der: bytes) -> Any:
    return crypto().serialization.load_der_public_key(bytes(spki_der))


def key_type(key: Any) -> str:
    """Node's asymmetricKeyType: 'ec', 'rsa' or another lowercase name."""
    c = crypto()
    if isinstance(key, c.ec.EllipticCurvePublicKey):
        return "ec"
    if isinstance(key, c.rsa.RSAPublicKey):
        return "rsa"
    return type(key).__name__.lower().replace("publickey", "").replace("_", "").strip("_") or "unknown"


_NODE_CURVE = {"secp256r1": "prime256v1"}
_JWK_CURVE = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def node_curve(key: Any) -> Optional[str]:
    """OpenSSL's name of an EC key's curve (prime256v1, secp384r1, ...), None for a non-EC key."""
    if key_type(key) != "ec":
        return None
    n = key.curve.name
    return _NODE_CURVE.get(n, n)


def jwk_curve(key: Any) -> Optional[str]:
    if key_type(key) != "ec":
        return None
    n = key.curve.name
    return _JWK_CURVE.get(n, n)


def spki_of(key: Any) -> bytes:
    c = crypto()
    return key.public_bytes(c.serialization.Encoding.DER, c.serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_sha(key: Any, algo: str) -> str:
    return hashlib.new(algo, spki_of(key)).hexdigest()


def ec_point(key: Any, curve: str) -> bytes:
    """The uncompressed SEC1 point of an EC key; raises TypeError unless it is an EC key on exactly `curve` ('P-256' | 'P-384')."""
    coord = {"P-256": 32, "P-384": 48}[curve]
    t = key_type(key)
    if t != "ec":
        raise TypeError("public key is not EC (got %s)" % t)
    if jwk_curve(key) != curve:
        raise TypeError("public key is not on %s (got %s)" % (curve, jwk_curve(key)))
    nums = key.public_numbers()
    return b"\x04" + nums.x.to_bytes(coord, "big") + nums.y.to_bytes(coord, "big")


def ec_key_from_point(curve: str, point: bytes) -> Any:
    """Validate and load an uncompressed (or compressed) SEC1 point; ValueError off the curve."""
    c = crypto()
    cv = c.ec.SECP256R1() if curve == "P-256" else c.ec.SECP384R1()
    return c.ec.EllipticCurvePublicKey.from_encoded_point(cv, bytes(point))


def ecdsa_verify_der(key: Any, sig_der: bytes, data: bytes, hash_name: str) -> bool:
    c = crypto()
    if key_type(key) != "ec":
        return False
    try:
        key.verify(bytes(sig_der), bytes(data), c.ec.ECDSA(hash_alg(hash_name)))
        return True
    except (c.InvalidSignature, ValueError, TypeError):
        return False


def ecdsa_verify_raw(key: Any, sig: bytes, data: bytes, hash_name: str) -> bool:
    """ECDSA over an IEEE P1363 signature (r || s, equal halves)."""
    if key_type(key) != "ec":
        return False
    half = (key.key_size + 7) // 8
    if len(sig) != 2 * half:
        return False
    r, s = int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big")
    if r == 0 or s == 0:
        return False
    return ecdsa_verify_der(key, crypto().utils.encode_dss_signature(r, s), data, hash_name)


def rsa_pkcs1_verify(key: Any, sig: bytes, data: bytes, hash_name: str) -> bool:
    c = crypto()
    if key_type(key) != "rsa":
        return False
    try:
        key.verify(bytes(sig), bytes(data), c.padding.PKCS1v15(), hash_alg(hash_name))
        return True
    except (c.InvalidSignature, ValueError, TypeError):
        return False


def to_ms(v: float) -> int:
    return int(v)


def result(ok: bool, **kw: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": ok}
    out.update(kw)
    return out


# ------------------------------------------------------------------------------------------------ compact JWS (MAA / GCP)


def as_str(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def as_str_list(v: Any) -> Optional[List[str]]:
    if not isinstance(v, list):
        return None
    out: List[str] = []
    for x in v:
        if not isinstance(x, str):
            return None
        out.append(x)
    return out


def first_string(rec: Dict[str, Any], keys: Any) -> Optional[str]:
    """The first present, non-empty string claim across candidate keys."""
    for k in keys:
        v = as_str(rec.get(k))
        if v is not None and len(v) > 0:
            return v
    return None


def parse_jws(token: Any, fn: str) -> Dict[str, Any]:
    """A compact JWS into {header, payload, signingInput, signature}. Raises TypeError (the reference's messages); verifies nothing."""
    if not isinstance(token, str) or len(token) == 0:
        raise TypeError("%s: empty token" % fn)
    parts = token.split(".")
    if len(parts) != 3:
        raise TypeError("%s: a compact JWS has exactly three dot-separated parts" % fn)
    h, p, s = parts
    if not h or not p or len(s) == 0:
        raise TypeError("%s: empty JWS segment" % fn)
    try:
        header_obj = js_json_loads(decode_canonical_b64url(h).decode("utf-8", "replace"))
        payload_obj = js_json_loads(decode_canonical_b64url(p).decode("utf-8", "replace"))
    except (JsError, CanonicalJwsError) as e:
        raise TypeError("%s: malformed JSON segment: %s" % (fn, e))
    if not isinstance(header_obj, dict):
        raise TypeError("%s: header is not a JSON object" % fn)
    if not isinstance(payload_obj, dict):
        raise TypeError("%s: payload is not a JSON object" % fn)
    alg = as_str(header_obj.get("alg"))
    if not alg:
        raise TypeError("%s: header has no alg" % fn)
    header: Dict[str, Any] = {"alg": alg}
    for k in ("kid", "jku", "typ"):
        if as_str(header_obj.get(k)) is not None:
            header[k] = header_obj[k]
    x5c = as_str_list(header_obj.get("x5c"))
    if x5c is not None:
        header["x5c"] = x5c
    try:
        signature = decode_canonical_b64url(s)
    except CanonicalJwsError as e:
        raise TypeError("%s: malformed signature segment: %s" % (fn, e))
    if len(signature) == 0:
        raise TypeError("%s: empty signature" % fn)
    return {"header": header, "payload": payload_obj, "signingInput": ("%s.%s" % (h, p)).encode("utf-8"), "signature": signature}


def transform_binding(binding: bytes, mode: Any) -> bytes:
    if mode == "sha256":
        return hashlib.sha256(binding).digest()
    if mode == "sha512":
        return hashlib.sha512(binding).digest()
    return binding


def js_num_str(v: Any) -> str:
    """A JavaScript number as a template literal renders it (integers without a fraction)."""
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    return str(v)
