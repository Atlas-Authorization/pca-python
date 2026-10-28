"""Reference verifier for the CORE PCActn checks, wire format v2 (strict normative profile).

Byte-matches @atlasauth/pca and the format-2 conformance vectors (packages/pca/conformance).
"""
import base64
import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union

from . import ed25519
from . import pq_backends
from .mldsa import ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES

PCACTN_VERSION = 2
SIG_DOMAIN = b"atlas-pca/actn/v2\x00"
CAP_DOMAIN = b"atlas-pca/cap/v1\x00"
DEFAULT_REVERSIBILITY_CLASS = "reversible"
MAX_CHAIN_DEPTH = 16
MAX_JSON_DEPTH = 32
MAX_JSON_CHARS = 1 << 20
# Shared hard caveat caps (all PCA verifiers): per-hop cumulative list, and the sum over every hop of a chain.
MAX_CAVEATS_PER_HOP = 256
MAX_CAVEATS_PER_CHAIN = 1024
CAVEAT_LIMIT_REASON = "chain exceeds caveat limit (max %d per hop, %d per chain)" % (MAX_CAVEATS_PER_HOP, MAX_CAVEATS_PER_CHAIN)
# Shared raw wire-size cap of a PCActn JSON document (UTF-8 bytes), checked before any parsing.
MAX_ARTIFACT_BYTES = 524288
ARTIFACT_SIZE_REASON = "artifact exceeds size limit (max %d bytes)" % MAX_ARTIFACT_BYTES
MAX_DECIMAL_DIGITS = 15
MAX_LIFETIME_MS = 3_600_000
MAX_SKEW_MS = 60_000
MAX_AUD_LEN = 256
MAX_NONCE_LEN = 128
MAX_SAFE = 2**53 - 1

_B64U_ALPHABET = re.compile(r"[A-Za-z0-9_-]*")  # always used with fullmatch


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def decode_b64u_strict(s: Any, length: Optional[int] = None) -> Optional[bytes]:
    """Strict RFC 4648 s5: alphabet A-Za-z0-9-_ only, no padding/whitespace, len%4 != 1, zero trailing bits.
    Returns the bytes, or None when invalid (or when `length` is given and the decoded size differs)."""
    if not isinstance(s, str) or not s.isascii() or _B64U_ALPHABET.fullmatch(s) is None or len(s) % 4 == 1:
        return None
    if length is not None and len(s) != -(-length * 4 // 3):
        return None
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None
    if b64u(raw) != s:  # non-canonical trailing bits
        return None
    if length is not None and len(raw) != length:
        return None
    return raw


def unb64u(s: str) -> bytes:
    raw = decode_b64u_strict(s)
    if raw is None:
        raise ValueError("bad base64url")
    return raw


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ---- strict JSON profile -------------------------------------------------------------

class StrictJsonError(ValueError):
    pass


_NUM = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX4 = re.compile(r"[0-9a-fA-F]{4}")


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def strict_parse(text: str) -> Any:
    """Hand-written RFC 8259 parser, the PCA strict profile (see conformance README s2/s3). Raises StrictJsonError."""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("utf-8")  # no BOM stripping: a BOM then fails as an unexpected token
        except UnicodeDecodeError:
            raise StrictJsonError("invalid UTF-8")
    if not isinstance(text, str):
        raise StrictJsonError("input is not a string")
    if len(text.encode("utf-8", "surrogatepass")) > MAX_JSON_CHARS:
        raise StrictJsonError("input too large")
    n = len(text)
    pos = [0]

    def err(m):
        raise StrictJsonError("%s (at offset %d)" % (m, pos[0]))

    def ws():
        i = pos[0]
        while i < n and text[i] in " \t\n\r":
            i += 1
        pos[0] = i

    def parse_string() -> str:
        i = pos[0] + 1
        out: List[str] = []
        while True:
            if i >= n:
                pos[0] = i
                err("unterminated string")
            c = text[i]
            if c == '"':
                i += 1
                break
            if ord(c) < 0x20:
                pos[0] = i
                err("raw control character in string")
            if c == "\\":
                i += 1
                e = text[i] if i < n else ""
                simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
                if e in simple and e != "":
                    out.append(simple[e])
                    i += 1
                elif e == "u":
                    h = text[i + 1:i + 5]
                    if not _HEX4.fullmatch(h):
                        pos[0] = i
                        err("bad \\u escape")
                    cp = int(h, 16)
                    i += 5
                    if 0xD800 <= cp <= 0xDBFF:
                        h2 = text[i + 2:i + 6]
                        if text[i:i + 2] == "\\u" and _HEX4.fullmatch(h2) and 0xDC00 <= int(h2, 16) <= 0xDFFF:
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (int(h2, 16) - 0xDC00)
                            i += 6
                        else:
                            pos[0] = i
                            err("lone surrogate in string")
                    elif 0xDC00 <= cp <= 0xDFFF:
                        pos[0] = i
                        err("lone surrogate in string")
                    out.append(chr(cp))
                else:
                    pos[0] = i
                    err("unknown escape")
                continue
            if 0xD800 <= ord(c) <= 0xDFFF:
                pos[0] = i
                err("lone surrogate in string")
            out.append(c)
            i += 1
        pos[0] = i
        return "".join(out)

    def parse_number():
        m = _NUM.match(text, pos[0])
        if not m:
            err("bad number")
        lex = m.group(0)
        pos[0] += len(lex)
        if "e" in lex or "E" in lex:
            err("exponent form is not allowed (use a plain decimal)")
        if lex == "-0":
            err("negative zero is not allowed")
        if "." in lex:
            if lex.endswith("0"):
                err("trailing fractional zero is not canonical")
            digits = lex.replace("-", "").replace(".", "").lstrip("0")
            if len(digits) > MAX_DECIMAL_DIGITS:
                err("more than %d significant digits" % MAX_DECIMAL_DIGITS)
            v = float(lex)
            if v != 0 and abs(v) < 1e-6:
                err("non-integer magnitude below 1e-6 is not allowed")
            return v
        absn = lex[1:] if lex.startswith("-") else lex
        if len(absn) > 16 or int(absn) > MAX_SAFE:
            err("integer outside the safe range (|n| > 2^53-1)")
        return int(lex)

    def parse_value(depth: int):
        ws()
        if pos[0] >= n:
            err("unexpected end of input")
        ch = text[pos[0]]
        if ch == "{":
            if depth > MAX_JSON_DEPTH:
                err("nesting too deep")
            pos[0] += 1
            o: Dict[str, Any] = {}
            ws()
            if pos[0] < n and text[pos[0]] == "}":
                pos[0] += 1
                return o
            while True:
                ws()
                if pos[0] >= n or text[pos[0]] != '"':
                    err("expected a string key")
                k = parse_string()
                if k in o:
                    err("duplicate key")
                ws()
                if pos[0] >= n or text[pos[0]] != ":":
                    err('expected ":"')
                pos[0] += 1
                o[k] = parse_value(depth + 1)
                ws()
                c = text[pos[0]] if pos[0] < n else ""
                if c == ",":
                    pos[0] += 1
                    continue
                if c == "}":
                    pos[0] += 1
                    return o
                err('expected "," or "}"')
        if ch == "[":
            if depth > MAX_JSON_DEPTH:
                err("nesting too deep")
            pos[0] += 1
            a: List[Any] = []
            ws()
            if pos[0] < n and text[pos[0]] == "]":
                pos[0] += 1
                return a
            while True:
                a.append(parse_value(depth + 1))
                ws()
                c = text[pos[0]] if pos[0] < n else ""
                if c == ",":
                    pos[0] += 1
                    continue
                if c == "]":
                    pos[0] += 1
                    return a
                err('expected "," or "]"')
        if ch == '"':
            return parse_string()
        if ch == "-" or "0" <= ch <= "9":
            return parse_number()
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if text.startswith(lit, pos[0]):
                pos[0] += len(lit)
                return val
        err("unexpected token")

    v = parse_value(1)
    ws()
    if pos[0] < n:
        err("trailing characters after the JSON value")
    return v


# ---- canonicalization ----------------------------------------------------------------

def _utf8_key(s: str) -> bytes:
    return s.encode("utf-8", "surrogatepass")


def _is_integral(v) -> bool:
    return isinstance(v, int) or (isinstance(v, float) and math.isfinite(v) and v == math.trunc(v))


def strict_number_error(v) -> Optional[str]:
    """Strict-profile check of one number; returns an error string or None."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return "not a number"
    if isinstance(v, float):
        if not math.isfinite(v):
            return "non-finite number"
        if v == 0 and math.copysign(1.0, v) < 0:
            return "negative zero"
    if _is_integral(v):
        return None if abs(int(v)) <= MAX_SAFE else "integer outside the safe range (|n| > 2^53-1)"
    if abs(v) < 1e-6:
        return "non-integer magnitude below 1e-6"
    s = _plain(v)
    if "e" in s.lower():
        return "non-integer number needs an exponent form"
    digits = s.replace("-", "").replace(".", "").lstrip("0")
    if len(digits) > MAX_DECIMAL_DIGITS:
        return "non-integer number has more than %d significant digits" % MAX_DECIMAL_DIGITS
    return None


def _plain(v: float) -> str:
    """Shortest round-trip decimal, without an exponent (== ECMAScript Number::toString for 1e-6 <= |v| < 1e21)."""
    r = repr(v)
    if "e" in r or "E" in r:
        return format(Decimal(r), "f")
    return r


def _num(v, strict: bool) -> str:
    if strict:
        e = strict_number_error(v)
        if e:
            raise TypeError("canonicalize: " + e)
    if isinstance(v, int):
        return str(v)
    if math.isnan(v) or math.isinf(v):
        raise TypeError("canonicalize: non-finite number")
    if v == 0:
        return "0"
    if v == math.trunc(v) and abs(v) < 1e21:
        return str(int(v))
    return _plain(v)


_ESC = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x0C: "\\f", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}


def _str(s: str, strict: bool) -> str:
    if strict and _has_surrogate(s):
        raise TypeError("canonicalize: lone surrogate in string")
    out = []
    for c in s:
        o = ord(c)
        if o in _ESC:
            out.append(_ESC[o])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def _ser(v: Any, strict: bool, depth: int) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _str(v, strict)
    if isinstance(v, (int, float)):
        return _num(v, strict)
    if isinstance(v, (list, tuple, dict)):
        if strict and depth > MAX_JSON_DEPTH:
            raise TypeError("canonicalize: nesting too deep")
        if isinstance(v, dict):
            for k in v:
                if not isinstance(k, str):
                    raise TypeError("canonicalize: non-string key")
            keys = sorted(v.keys(), key=_utf8_key)
            return "{" + ",".join(_str(k, strict) + ":" + _ser(v[k], strict, depth + 1) for k in keys) + "}"
        return "[" + ",".join(_ser(x, strict, depth + 1) for x in v) + "]"
    raise TypeError("canonicalize: unsupported type %s" % type(v).__name__)


def canonicalize(v: Any) -> str:
    """Lenient canonical JSON (capability content addressing): keys sorted bytewise over UTF-8, compact."""
    return _ser(v, False, 1)


def canonicalize_strict(v: Any) -> str:
    """STRICT canonical JSON of a signed PCActn body (wire v2). Raises TypeError on any violation."""
    return _ser(v, True, 1)


def canonical_bytes(v: Any) -> bytes:
    return canonicalize(v).encode("utf-8", "surrogatepass")


def canonical_bytes_strict(v: Any) -> bytes:
    return canonicalize_strict(v).encode("utf-8")


def hash_canonical(v: Any) -> str:
    """base64url(sha256(STRICT canonical(v))), like the reference `hashCanonical` (hash.ts canonicalBytes is
    canonicalizeStrict): every protocol digest (capability / grant hash, hop body digest, caveat comparison, params and
    conditions digests, Merkle leaves) is depth-capped (MAX_JSON_DEPTH), safe-integer-only and surrogate-free. Raises
    TypeError on an out-of-profile value; the verifiers turn that into a refusal (a lenient digest would accept a
    correctly signed out-of-profile hop that the reference refuses)."""
    return b64u(sha256(canonical_bytes_strict(v)))


# ---- Merkle --------------------------------------------------------------------------

def _leaf_hash(leaf: Any) -> bytes:
    return sha256(b"\x00" + canonical_bytes_strict(leaf))


def _node_hash(l: bytes, r: bytes) -> bytes:
    return sha256(b"\x01" + l + r)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _build(hs: List[bytes]) -> bytes:
    if len(hs) == 1:
        return hs[0]
    k = _split(len(hs))
    return _node_hash(_build(hs[:k]), _build(hs[k:]))


def merkle_root(leaves: List[Any]) -> str:
    if not leaves:
        raise ValueError("merkle_root: empty leaf set")
    return b64u(_build([_leaf_hash(x) for x in leaves]))


def _path_shape(index: int, size: int) -> List[str]:
    """Sibling sides (bottom-up) of the RFC 6962 audit path for leaf `index` in a tree of `size` leaves."""
    shape: List[str] = []
    while size > 1:
        k = _split(size)
        if index < k:
            shape.append("R")
            size = k
        else:
            shape.append("L")
            index -= k
            size -= k
    shape.reverse()
    return shape


def _is_safe_int(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, float):
        if not (math.isfinite(v) and v == math.trunc(v)) or (v == 0 and math.copysign(1.0, v) < 0):
            return False
        v = int(v)
    return isinstance(v, int) and abs(v) <= MAX_SAFE


def verify_inclusion(root: Any, proof: Any, leaf: Any) -> bool:
    try:
        if not isinstance(proof, dict) or not isinstance(proof.get("path"), list):
            return False
        index, size = proof.get("index"), proof.get("size")
        if not _is_safe_int(index) or not _is_safe_int(size):
            return False
        index, size = int(index), int(size)
        if size < 1 or index < 0 or index >= size:
            return False
        shape = _path_shape(index, size)
        if len(shape) != len(proof["path"]):
            return False
        h = _leaf_hash(leaf)
        for i, step in enumerate(proof["path"]):
            side = step.get("side")
            if side != shape[i]:
                return False
            sib = decode_b64u_strict(step.get("hash"), 32)
            if sib is None:
                return False
            h = _node_hash(sib, h) if side == "L" else _node_hash(h, sib)
        return b64u(h) == root
    except Exception:
        return False


def params_digest(params: Any = None) -> str:
    return hash_canonical({} if params is None else params)


EMPTY_PARAMS_DIGEST = params_digest()


def conditions_digest(pre: Any = None, post: Any = None) -> str:
    return hash_canonical({"pre": pre, "post": post})


def _plan_leaf(node_id: Any, action: dict, cond: str) -> dict:
    if node_id is None:
        raise ValueError("missing node_id")
    pd = action.get("params_digest")
    rc = action.get("reversibility_class")
    return {
        "node_id": node_id,
        "verb": action["verb"],
        "resource": action["resource"],
        "params_digest": EMPTY_PARAMS_DIGEST if pd is None else pd,
        "reversibility_class": DEFAULT_REVERSIBILITY_CLASS if rc is None else rc,
        "conditions": cond,
    }


# ---- keys / capability chain ---------------------------------------------------------

def _verify_b64u(pub: Any, msg: bytes, sig: Any) -> bool:
    pk, sg = decode_b64u_strict(pub, 32), decode_b64u_strict(sig, 64)
    if pk is None or sg is None:
        return False
    return ed25519.verify(pk, msg, sg)


# ---- B4 post-quantum crypto-agility (mirrors packages/pca/src/pq.ts) -----------------

ED25519_SIGNATURE_BYTES = 64
UNSUPPORTED_SUITE = "unsupported_suite"
# The closed TS suite registry (SIG_SUITES in pq.ts), in registry order.
REGISTERED_SUITES = (
    "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
    "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s",
    "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "fn-dsa-1024", "less-cat1", "hybrid-ed25519-less-cat1",
)
# Suite capability (packages/pca/conformance/SUITES.md): every suite this verifier can implement (pq_backends: ML-DSA via
# dilithium-py or OpenSSL >= 3.5, SLH-DSA via OpenSSL >= 3.5, LESS via the patched reference C of sdks/pca-less-c built as a
# shared library; pure mode, empty context). LESS's signature length is variable (pq_backends.sig_len_ok).
# suite name -> (sig byte length, needs pq_pk, needs pq_sig, PQ key type or None, nested). `alg` absent == "ed25519".
# nested: the PQ half signs msg || the Ed25519 signature bytes (SUF-CMA). A registered suite outside this table
# (fn-dsa-512 / fn-dsa-1024: no trustworthy Python implementation) or one whose
# backend is missing at runtime fails closed with the distinct reason `unsupported_suite: <alg>`.
_SIG_SUITES = {
    "ed25519": (ED25519_SIGNATURE_BYTES, False, False, None, False),
    "ml-dsa-65": (ML_DSA_65_SIGNATURE_BYTES, True, False, "ML-DSA-65", False),
    "hybrid-ed25519-ml-dsa-65": (ED25519_SIGNATURE_BYTES, True, True, "ML-DSA-65", False),
    "hybrid-nested-ed25519-ml-dsa-65": (ED25519_SIGNATURE_BYTES, True, True, "ML-DSA-65", True),
    "slh-dsa-sha2-128f": (17088, True, False, "SLH-DSA-SHA2-128f", False),
    "hybrid-ed25519-slh-dsa-sha2-128f": (ED25519_SIGNATURE_BYTES, True, True, "SLH-DSA-SHA2-128f", False),
    "ml-dsa-87": (4627, True, False, "ML-DSA-87", False),
    "hybrid-ed25519-ml-dsa-87": (ED25519_SIGNATURE_BYTES, True, True, "ML-DSA-87", False),
    "slh-dsa-sha2-256s": (29792, True, False, "SLH-DSA-SHA2-256s", False),
    "hybrid-ed25519-slh-dsa-sha2-256s": (ED25519_SIGNATURE_BYTES, True, True, "SLH-DSA-SHA2-256s", False),
    "less-cat1": (1329, True, False, "LESS-cat1", False),
    "hybrid-ed25519-less-cat1": (ED25519_SIGNATURE_BYTES, True, True, "LESS-cat1", False),
}
_ABSENT = object()


def suite_available(alg: Any) -> bool:
    """True iff this verifier can verify `alg` in this runtime (its PQ backend, if any, is usable)."""
    s = _SIG_SUITES.get(alg) if isinstance(alg, str) else None
    return s is not None and (s[3] is None or pq_backends.available(s[3]))


def supported_suites() -> List[str]:
    """The capability manifest: the registered suites this verifier can verify in this runtime, in registry order."""
    return [a for a in REGISTERED_SUITES if suite_available(a)]


def _pq_lens(suite: str):
    kt = _SIG_SUITES[suite][3]
    return pq_backends.KEY_TYPES[kt] if kt is not None else (0, 0)


def _pq_sig_ok(v: Any, key_type: str) -> bool:
    """Canonical base64url whose decoded length is a signature length of `key_type` (fixed, or LESS's range)."""
    b = decode_b64u_strict(v)
    return b is not None and pq_backends.sig_len_ok(key_type, len(b))


def _resolve_suite(p: dict):
    """Return the suite name, or None (fail-closed) for an unknown/non-string alg. _ABSENT means 'alg' absent."""
    alg = p.get("alg", _ABSENT)
    if alg is _ABSENT:
        return "ed25519", None
    if not isinstance(alg, str):
        return None, "'alg' must be a string"
    if suite_available(alg):
        return alg, None
    if alg in REGISTERED_SUITES:
        return None, "%s: %s" % (UNSUPPORTED_SUITE, alg)
    return None, "unknown signature alg '%s'" % alg


def validate_signature_wire(p: dict) -> Optional[str]:
    """Validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. None when well-formed, else a short reason."""
    suite, err = _resolve_suite(p)
    if suite is None:
        return err
    sig_bytes, needs_pk, needs_sig, key_type = _SIG_SUITES[suite][:4]
    pk_len, pq_sig_len = _pq_lens(suite)
    if not (_pq_sig_ok(p.get("sig"), key_type) if key_type is not None and not needs_sig
            else decode_b64u_strict(p.get("sig"), sig_bytes) is not None):
        return "'sig' is not canonical base64url (%d bytes) for alg '%s'" % (sig_bytes, suite)
    if needs_pk:
        if decode_b64u_strict(p.get("pq_pk"), pk_len) is None:
            return "'pq_pk' is not canonical base64url (%d bytes)" % pk_len
    elif "pq_pk" in p:
        return "'pq_pk' must be absent for alg '%s'" % suite
    if needs_sig:
        if not _pq_sig_ok(p.get("pq_sig"), key_type):
            return "'pq_sig' is not canonical base64url (%d bytes)" % pq_sig_len
    elif "pq_sig" in p:
        return "'pq_sig' must be absent for alg '%s'" % suite
    return None


def validate_share_signature_wire(s: dict) -> Optional[str]:
    """Per-suite wire check of a threshold share's `alg`/`sig`/`pq_sig` (0.4.1). Same lengths as the leaf, except that a
    share's `pq_pk` is NOT judged here: it is an optional echo, checked against the signer set by `verify_threshold_share`."""
    suite, err = _resolve_suite(s)
    if suite is None:
        return err
    sig_bytes, _, needs_sig, key_type = _SIG_SUITES[suite][:4]
    pq_sig_len = _pq_lens(suite)[1]
    if not (_pq_sig_ok(s.get("sig"), key_type) if key_type is not None and not needs_sig
            else decode_b64u_strict(s.get("sig"), sig_bytes) is not None):
        return "'sig' is not canonical base64url (%d bytes) for alg '%s'" % (sig_bytes, suite)
    if needs_sig:
        if not _pq_sig_ok(s.get("pq_sig"), key_type):
            return "'pq_sig' is not canonical base64url (%d bytes) for alg '%s'" % (pq_sig_len, suite)
    elif "pq_sig" in s:
        return "'pq_sig' must be absent for alg '%s'" % suite
    return None


def _pq_verify_b64u(key_type: str, pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    pk_len = pq_backends.KEY_TYPES[key_type][0]
    pk = decode_b64u_strict(pk_b64u, pk_len)
    sg = decode_b64u_strict(sig_b64u)
    if pk is None or sg is None or not pq_backends.sig_len_ok(key_type, len(sg)):
        return False
    return pq_backends.verify(key_type, pk, msg, sg)


def _ml_dsa65_verify_b64u(pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    return _pq_verify_b64u("ML-DSA-65", pk_b64u, msg, sig_b64u)


class _PinnedPq:
    """An opaque PQ verification key (R3-01 choke point). Instances are minted ONLY by `_resolve_pq_key`, so the low-level
    PQ verification (`_verify_suite`) cannot be reached with a key read straight off the artifact being verified."""

    __slots__ = ("key", "source")
    _MINT = object()

    def __init__(self, key: str, source: str, token: object = None) -> None:
        if token is not _PinnedPq._MINT:
            raise TypeError("_PinnedPq is minted only by _resolve_pq_key")
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "source", source)

    def __setattr__(self, name, value):  # immutable
        raise AttributeError("_PinnedPq is immutable")


def _resolve_pq_key(identity: Any, artifact_pk: Any, *, holder_pq: Any = None, pq_pins: Any = None,
                    trusted_pk: Any = None) -> Optional[_PinnedPq]:
    """THE choke point (R3-01), mirroring `resolvePqVerifyKey` in packages/pca/src/pq.ts. Returns the key to verify under,
    or None (REFUSE) when no verifier-side authority vouches for the artifact's `pq_pk`:
      1. `trusted_pk`: a key the verifier itself holds (the stored grant). Used as is.
      2. `pq_pins[identity]` (own entry only): the artifact's pq_pk MUST equal the pin; a differing pin is a refusal.
      3. `holder_pq`: the artifact's pq_pk must hash to the signer's committed `holder_pq` (F-2).
    Natives have no `allowUnboundPq`: an artifact's own key is never enough."""
    if isinstance(trusted_pk, str) and trusted_pk != "":
        return _PinnedPq(trusted_pk, "trusted", _PinnedPq._MINT)
    if not isinstance(artifact_pk, str) or artifact_pk == "":
        return None
    if isinstance(pq_pins, dict) and isinstance(identity, str) and identity in pq_pins:
        return _PinnedPq(artifact_pk, "pin", _PinnedPq._MINT) if pq_pins[identity] == artifact_pk else None
    if isinstance(holder_pq, str) and holder_pq_commitment(artifact_pk) == holder_pq:
        return _PinnedPq(artifact_pk, "holder-commitment", _PinnedPq._MINT)
    return None


def _ml_dsa65_verify_pinned(pq: Optional[_PinnedPq], msg: bytes, sig_b64u: Any) -> bool:
    if not isinstance(pq, _PinnedPq):
        return False
    return _ml_dsa65_verify_b64u(pq.key, msg, sig_b64u)


def _verify_suite(p: dict, holder: Any, msg: bytes, pq: Optional[_PinnedPq]) -> bool:
    """Verify `p`'s signature(s) under its suite. The PQ half verifies ONLY under `pq` (a `_PinnedPq`), never under
    `p["pq_pk"]`. FAIL-CLOSED: unknown alg / missing key / invalid -> False."""
    suite, _ = _resolve_suite(p)
    if suite is None:
        return False
    _, _, needs_sig, key_type, nested = _SIG_SUITES[suite]
    sig = p.get("sig")
    if key_type is None:
        return _verify_b64u(holder, msg, sig)
    if not isinstance(pq, _PinnedPq):
        return False
    if not needs_sig:  # pure PQ: `sig` is the PQ signature
        return _pq_verify_b64u(key_type, pq.key, msg, sig)
    # hybrid: the cheap Ed25519 half first (R6-API-04), then the PQ `pq_sig` (nested: over msg || Ed25519 sig bytes)
    if not _verify_b64u(holder, msg, sig):
        return False
    pq_msg = msg
    if nested:
        ed_sig = decode_b64u_strict(sig, ED25519_SIGNATURE_BYTES)
        if ed_sig is None:
            return False
        pq_msg = msg + ed_sig
    return _pq_verify_b64u(key_type, pq.key, pq_msg, p.get("pq_sig"))


def verify_leaf_suite(p: dict, holder: Any, msg: bytes) -> bool:
    """Verify a signature under the ARTIFACT'S OWN `pq_pk`. Only for surfaces whose key is authorised elsewhere (threshold
    shares, the `pq_artifact` conformance primitives): it proves nothing about who issued `p`. The chain and the PCActn
    leaf never call it; they resolve their key through `_resolve_pq_key`. TOTAL: malformed input -> False."""
    try:
        if not isinstance(p, dict) or not isinstance(msg, (bytes, bytearray)):
            return False
        return _verify_suite(p, holder, bytes(msg), _resolve_pq_key(None, p.get("pq_pk"), trusted_pk=p.get("pq_pk")))
    except Exception:  # noqa: BLE001 - totality on hostile input
        return False


def cap_hash(c: dict) -> str:
    return hash_canonical(c)


def _body_of(c: dict) -> dict:
    body = {"issuer": c.get("issuer"), "holder": c.get("holder"), "caveats": c.get("caveats"), "parent": c.get("parent")}
    if "holder_pq" in c:
        body["holder_pq"] = c["holder_pq"]
    return body


def _signable_hop_body(c: dict):
    """bodyOf + the suite fields (`alg`, `pq_pk`) bound in for a non-default suite (so a downgrade or ML-DSA
    key-swap breaks the hop digest), byte-identical to _body_of for ed25519. Mirrors signableBody in
    capability.ts. Returns (body, None), or (None, reason) for an unknown `alg` (fail-closed)."""
    suite, err = _resolve_suite(c)
    if suite is None:
        return None, err
    body = _body_of(c)
    if suite != "ed25519":
        body["alg"] = suite
        needs_pk = _SIG_SUITES[suite][1]
        if needs_pk and isinstance(c.get("pq_pk"), str):
            body["pq_pk"] = c["pq_pk"]
    return body, None


def _check_sig(c: dict, signer: Any, label: str, pq: Optional[_PinnedPq] = None) -> Optional[str]:
    # Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
    body, err = _signable_hop_body(c)
    if body is None:
        return "%s: %s" % (label, err)
    try:
        digest = hash_canonical(body)
    except Exception:
        return label + ": malformed body"
    if digest != c.get("body_digest") or c.get("id") != c.get("body_digest"):
        return label + ": body digest mismatch"
    try:
        msg = CAP_DOMAIN + unb64u(c["body_digest"])
    except Exception:
        return label + ": bad signature (not signed by expected key)"
    # Suite-agile hop verification (mirrors verifyWithSuite): ed25519 == _verify_b64u(signer, msg, sig);
    # hybrid requires BOTH the Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`);
    # pure ml-dsa-65 verifies `sig` under `pq_pk`. The PQ key is the resolved `pq` (never the hop's own pq_pk).
    if not _verify_suite(c, signer, msg, pq):
        return label + ": bad signature (not signed by expected key)"
    return None


HOLDER_PQ_DOMAIN = b"atlas-pca/holder-pq/v1\0"


def holder_pq_commitment(pq_pk: str) -> str:
    return b64u(sha256(HOLDER_PQ_DOMAIN + pq_pk.encode("utf-8")))


def _suite_policy_error(alg: Any, label: str, allowed) -> Optional[str]:
    """allowedSuites policy (absent `alg` == ed25519). `allowed` None == no policy; [] refuses everything."""
    if allowed is None:
        return None
    a = "ed25519" if alg is None else alg
    if isinstance(a, str) and a in allowed:
        return None
    return "%s: signature suite '%s' is not allowed by this verifier's suite policy" % (label, a)


def pq_binding_error(alg: Any, pq_pk: Any, committed: Any, label: str) -> Optional[str]:
    """F-2: a PQ-carrying suite is accepted only under a pq_pk the signer's holder committed to (holder_pq)."""
    a = "ed25519" if alg is None else alg
    if not isinstance(a, str) or a not in _SIG_SUITES or not _SIG_SUITES[a][1]:
        return None
    if not isinstance(committed, str):
        return "%s: suite '%s' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)" % (label, a)
    if not isinstance(pq_pk, str) or holder_pq_commitment(pq_pk) != committed:
        return "%s: pq_pk does not match the signer's committed holder_pq (F-2)" % label
    return None


def artifact_too_large(text: Union[str, bytes, bytearray]) -> bool:
    """True when the raw PCActn document exceeds MAX_ARTIFACT_BYTES (UTF-8 bytes). O(1) for bytes and for clearly small/large strs."""
    if isinstance(text, (bytes, bytearray)):
        return len(text) > MAX_ARTIFACT_BYTES
    if len(text) > MAX_ARTIFACT_BYTES:  # bytes >= chars
        return True
    if len(text) * 4 <= MAX_ARTIFACT_BYTES:  # bytes <= 4 * chars (surrogatepass: 3 per lone surrogate)
        return False
    return len(text.encode("utf-8", "surrogatepass")) > MAX_ARTIFACT_BYTES


def caveat_limit_exceeded(chain: list) -> bool:
    """Reads raw list sizes only, so it runs before any hashing or signature work."""
    total = 0
    for c in chain:
        cv = c.get("caveats") if isinstance(c, dict) else None
        n = len(cv) if isinstance(cv, list) else 0
        if n > MAX_CAVEATS_PER_HOP:
            return True
        total += n
        if total > MAX_CAVEATS_PER_CHAIN:
            return True
    return False


ROOT_PQ_PIN_REASON = ("hop 0: root suite '%s' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant "
                      "(policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)")
ROOT_PQ_PIN_MISMATCH_REASON = ("hop 0: root suite '%s': the server-side PQ pin for the root issuer (policy.pqPins) does not match "
                               "the stored grant's pq_pk (fail closed)")


def _resolve_root_pq(root: dict, pq_pins: Any, trusted_root: Any):
    """The root hop has no parent holding a `holder_pq` commitment, so a non-ed25519 root's PQ key must come from a
    verifier-side authority: the verifier's stored copy of this very grant (`trusted_root`, same content hash) or a pin for
    `root.issuer`. Returns (key_or_None, reason_or_None); mirrors `rootPq` in capability.ts.
    The decision is keyed on the REGISTERED suite (resolveSigAlg in the reference), not on whether this runtime has its
    backend: a PQ root without a verifier-side authority gets the pin reason on every host; a root that passes it is still
    refused fail-closed (unsupported_suite) at the signature check when the backend is missing."""
    alg = root.get("alg", "ed25519")
    if not isinstance(alg, str) or alg not in REGISTERED_SUITES or alg == "ed25519":
        return None, None
    suite = alg
    pk = root.get("pq_pk")
    trusted = None
    if trusted_root is not None and isinstance(pk, str):
        try:
            if cap_hash(trusted_root) == cap_hash(root):
                trusted = pk
        except Exception:
            trusted = None
    # 0.4.2 fail closed: with the stored grant AND a pin for the issuer, both must agree (the grant never overrides a pin).
    issuer = root.get("issuer")
    if trusted is not None and isinstance(pq_pins, dict) and isinstance(issuer, str) and issuer in pq_pins and pq_pins[issuer] != pk:
        return None, ROOT_PQ_PIN_MISMATCH_REASON % suite
    key = _resolve_pq_key(root.get("issuer"), pk, pq_pins=pq_pins, trusted_pk=trusted)
    if key is None:
        return None, ROOT_PQ_PIN_REASON % suite
    return key, None


_OPTIONAL_STR_HOP_FIELDS = ("alg", "pq_pk", "pq_sig", "holder_pq", "parent")


def _hop_well_typed(c: Any) -> bool:
    """Mirrors `wellTyped` in capability.ts: a hop is an object whose id/issuer/holder/body_digest/sig are strings, whose
    optional alg/pq_pk/pq_sig/holder_pq/parent are absent or strings (JSON null is NOT absent), and whose caveats are a list
    of objects each carrying a string `type`. A correctly SIGNED but ill-typed hop is refused like in the reference."""
    if not isinstance(c, dict):
        return False
    for k in ("id", "issuer", "holder", "body_digest", "sig"):
        if not isinstance(c.get(k), str):
            return False
    for k in _OPTIONAL_STR_HOP_FIELDS:
        if k in c and not isinstance(c[k], str):
            return False
    cv = c.get("caveats")
    return isinstance(cv, list) and all(isinstance(x, dict) and isinstance(x.get("type"), str) for x in cv)


def verify_chain(chain: list, expected_root_issuer: Optional[str] = None, allowed_suites=None, pq_pins=None, trusted_root=None):
    """Returns (ok, reason). A non-ed25519 (pure-PQ or hybrid) ROOT is accepted only if `pq_pins[root.issuer]` equals the
    root's `pq_pk`, or `trusted_root` is the root itself (the verifier's own stored grant); otherwise it is refused (R4-01).
    TOTAL (R6-05): a malformed chain (non-object hop, missing or wrong-typed field, ...) is a (False, reason) verdict,
    never an exception."""
    try:
        return _verify_chain_unchecked(chain, expected_root_issuer, allowed_suites, pq_pins, trusted_root)
    except Exception as e:  # noqa: BLE001 - totality: any residual fault on hostile input is a refusal
        return False, "malformed capability chain: %s" % type(e).__name__


def _verify_chain_unchecked(chain, expected_root_issuer, allowed_suites, pq_pins, trusted_root):
    if not isinstance(chain, list) or not chain:
        return False, "empty chain"
    if len(chain) > MAX_CHAIN_DEPTH:
        return False, "chain too long (max %d hops)" % MAX_CHAIN_DEPTH
    if caveat_limit_exceeded(chain):
        return False, CAVEAT_LIMIT_REASON
    root = chain[0]
    if not _hop_well_typed(root):
        return False, "hop 0: malformed capability"
    if "parent" in root:
        return False, "hop 0: root must not have a parent"
    if expected_root_issuer is not None and root.get("issuer") != expected_root_issuer:
        return False, "hop 0: root issuer is not the expected principal"
    err = _suite_policy_error(root.get("alg"), "hop 0", allowed_suites)
    if err:
        return False, err
    root_pq, err = _resolve_root_pq(root, pq_pins, trusted_root)
    if err:
        return False, err
    err = _check_sig(root, root.get("issuer"), "hop 0", root_pq)
    if err:
        return False, err
    for i in range(1, len(chain)):
        parent, c, label = chain[i - 1], chain[i], "hop %d" % i
        if not _hop_well_typed(c):
            return False, label + ": malformed capability"
        if c.get("parent") != cap_hash(parent):
            return False, label + ": broken parent link"
        if c.get("issuer") != parent.get("holder"):
            return False, label + ": issuer is not the parent's bound holder"
        err = _suite_policy_error(c.get("alg"), label, allowed_suites)
        if err:
            return False, err
        err = pq_binding_error(c.get("alg"), c.get("pq_pk"), parent.get("holder_pq"), label)
        if err:
            return False, err
        err = _check_sig(c, parent.get("holder"), label,
                         _resolve_pq_key(parent.get("holder"), c.get("pq_pk"), holder_pq=parent.get("holder_pq")))
        if err:
            return False, err
        pc, cc = parent["caveats"], c["caveats"]
        if len(cc) < len(pc):
            return False, label + ": drops parent caveat(s)"
        for j in range(len(pc)):
            if hash_canonical(cc[j]) != hash_canonical(pc[j]):
                return False, "%s: caveat %d altered or reordered" % (label, j)
    return True, None




# ---- wire format v2 ------------------------------------------------------------------

PCACTN_REQUIRED_FIELDS = (
    "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness",
    "counter", "risk_claim", "aud", "iat", "exp", "sig",
)
PCACTN_OPTIONAL_FIELDS = (
    "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding",
    "threshold", "zk_compliance", "bond_ref",
    # B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
    "alg", "pq_pk", "pq_sig",
    # Intent Layer M2 (additive, SIGNED): the `envelope.intent` binding (see validate_intent_wire).
    "intent",
    # Intent Layer v2 (additive, SIGNED): the session member (see validate_intent_session_wire, conformance rule 13).
    "intent_session",
    # Consistency token (additive, SIGNED): the `fresh_at` member (see atlas_pca.fresh_at).
    "fresh_at",
)
_KNOWN = frozenset(PCACTN_REQUIRED_FIELDS + PCACTN_OPTIONAL_FIELDS)


def _is_str(v) -> bool:
    return isinstance(v, str)


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _blen(s: str) -> int:
    return len(s.encode("utf-8", "surrogatepass"))


def _unknown(o: dict, allowed) -> Optional[str]:
    for k in o:
        if k not in allowed:
            return k
    return None


def validate_wire_v2(p: Any) -> Optional[str]:
    """Return None when `p` is a well-formed v2 PCActn, else a short reason. Never raises."""
    try:
        if not isinstance(p, dict):
            return "PCActn is not an object"
        k = _unknown(p, _KNOWN)
        if k is not None:
            return "unknown field '%s'" % k
        for k in PCACTN_REQUIRED_FIELDS:
            if k not in p:
                return "missing field '%s'" % k
        body = {k: v for k, v in p.items() if k not in ("sig", "threshold", "pq_sig")}
        try:
            canonicalize_strict(body)
        except Exception as e:
            return str(e)

        for f in ("ver", "counter", "iat", "exp"):
            if not _is_safe_int(p[f]):
                return "'%s' must be a safe integer" % f
        aud = p["aud"]
        if not _is_str(aud) or not aud or _blen(aud) > MAX_AUD_LEN:
            return "'aud' must be a non-empty string"
        if "nonce" in p and (not _is_str(p["nonce"]) or not p["nonce"] or _blen(p["nonce"]) > MAX_NONCE_LEN):
            return "'nonce' must be a non-empty string"
        # B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite (absent `alg` == classical 64-byte sig).
        sig_err = validate_signature_wire(p)
        if sig_err is not None:
            return sig_err
        if decode_b64u_strict(p["grant_ref"], 32) is None:
            return "'grant_ref' is not canonical base64url (32 bytes)"

        a = p["action"]
        if not isinstance(a, dict):
            return "'action' must be an object"
        k = _unknown(a, ("verb", "resource", "params_digest", "reversibility_class"))
        if k is not None:
            return "unknown field 'action.%s'" % k
        if not (_is_str(a.get("verb")) and _is_str(a.get("resource")) and _is_str(a.get("reversibility_class"))):
            return "action.verb/resource/reversibility_class must be strings"
        if decode_b64u_strict(a.get("params_digest"), 32) is None:
            return "'action.params_digest' is not canonical base64url (32 bytes)"

        pl = p["plan"]
        if not isinstance(pl, dict):
            return "'plan' must be an object"
        k = _unknown(pl, ("root", "inclusion_proof", "node_id", "conditions_digest"))
        if k is not None:
            return "unknown field 'plan.%s'" % k
        if decode_b64u_strict(pl.get("root"), 32) is None:
            return "'plan.root' is not canonical base64url (32 bytes)"
        if not _is_str(pl.get("node_id")):
            return "'plan.node_id' must be a string"
        if "conditions_digest" in pl and decode_b64u_strict(pl["conditions_digest"], 32) is None:
            return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)"
        ip = pl.get("inclusion_proof")
        if not isinstance(ip, dict):
            return "'plan.inclusion_proof' must be an object"
        k = _unknown(ip, ("index", "size", "path"))
        if k is not None:
            return "unknown field 'plan.inclusion_proof.%s'" % k
        if not _is_safe_int(ip.get("index")):
            return "'plan.inclusion_proof.index' must be a safe integer"
        if not _is_safe_int(ip.get("size")):
            return "'plan.inclusion_proof.size' must be a safe integer"
        if not isinstance(ip.get("path"), list):
            return "'plan.inclusion_proof.path' must be an array"
        for i, st in enumerate(ip["path"]):
            if not isinstance(st, dict):
                return "proof step %d must be an object" % i
            k = _unknown(st, ("side", "hash"))
            if k is not None:
                return "unknown field 'path[%d].%s'" % (i, k)
            if st.get("side") not in ("L", "R"):
                return "proof step %d: side must be 'L' or 'R'" % i
            if decode_b64u_strict(st.get("hash"), 32) is None:
                return "proof step %d: hash is not canonical base64url (32 bytes)" % i

        chain = p["cap_chain"]
        if not isinstance(chain, list):
            return "'cap_chain' must be an array"
        for i, c in enumerate(chain):
            if not isinstance(c, dict):
                return "cap_chain[%d] must be an object" % i
            k = _unknown(c, ("id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig", "holder_pq"))
            if k is not None:
                return "unknown field 'cap_chain[%d].%s'" % (i, k)
            for f in ("id", "issuer", "holder", "body_digest"):
                if decode_b64u_strict(c.get(f), 32) is None:
                    return "cap_chain[%d].%s is not canonical base64url (32 bytes)" % (i, f)
            # B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the leaf.
            # Absent `alg` asserts the classical 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical).
            hop_sig_err = validate_signature_wire(c)
            if hop_sig_err is not None:
                return "cap_chain[%d]: %s" % (i, hop_sig_err)
            if "parent" in c and decode_b64u_strict(c["parent"], 32) is None:
                return "cap_chain[%d].parent is not canonical base64url (32 bytes)" % i
            if "holder_pq" in c and decode_b64u_strict(c["holder_pq"], 32) is None:
                return "cap_chain[%d].holder_pq is not canonical base64url (32 bytes)" % i
            cv = c.get("caveats")
            if not isinstance(cv, list) or not all(isinstance(x, dict) and _is_str(x.get("type")) for x in cv):
                return "cap_chain[%d].caveats must be an array of {type,...} objects" % i

        at = p["attestation"]
        if not isinstance(at, dict) or not _is_safe_int(at.get("epoch")):
            return "'attestation' must be an object with an integer 'epoch'"
        if not all(_is_str(at.get(f)) for f in ("quote_digest", "model_id", "measurement", "operator")):
            return "attestation string fields must be strings"
        pv = p["provenance"]
        if not (isinstance(pv, dict) and _is_str(pv.get("causal_hash")) and _is_num(pv.get("taint_level"))
                and isinstance(pv.get("trusted_refs"), list) and all(_is_str(x) for x in pv["trusted_refs"])):
            return "'provenance' is malformed"
        fr = p["freshness"]
        if not (isinstance(fr, dict) and _is_safe_int(fr.get("epoch")) and _is_str(fr.get("beacon_ref"))
                and _is_str(fr.get("accumulator_witness"))):
            return "'freshness' is malformed"
        rc = p["risk_claim"]
        if not (isinstance(rc, dict) and _is_num(rc.get("r")) and isinstance(rc.get("inputs"), dict)):
            return "'risk_claim' is malformed"

        if "caution" in p and not (_is_num(p["caution"]) and 0 <= p["caution"] <= 1):
            return "'caution' must be a number in [0,1]"
        if "rationale_commitment" in p and decode_b64u_strict(p["rationale_commitment"], 32) is None:
            return "'rationale_commitment' is not canonical base64url (32 bytes)"
        if "tool_binding" in p and decode_b64u_strict(p["tool_binding"], 32) is None:
            return "'tool_binding' is not canonical base64url (32 bytes)"
        if "progress_step" in p and not isinstance(p["progress_step"], dict):
            return "'progress_step' must be an object"
        if "intent" in p:
            intent_err = validate_intent_wire(p["intent"])
            if intent_err is not None:
                return intent_err
        if "intent_session" in p:
            session_err = validate_intent_session_wire(p["intent_session"])
            if session_err is not None:
                return session_err
        if "fresh_at" in p:
            from .fresh_at import validate_fresh_at_wire  # deferred: fresh_at imports this module
            fresh_err = validate_fresh_at_wire(p["fresh_at"])
            if fresh_err is not None:
                return fresh_err
        if "prohibition_evidence" in p and not isinstance(p["prohibition_evidence"], (dict, list)):
            return "'prohibition_evidence' must be an object or array"
        if "threshold" in p:
            th = p["threshold"]
            if not isinstance(th, dict) or not isinstance(th.get("shares"), list):
                return "'threshold' must be {shares:[...]}"
            for i, s in enumerate(th["shares"]):
                if not isinstance(s, dict) or not _is_str(s.get("role")):
                    return "threshold.shares[%d] is malformed" % i
                if decode_b64u_strict(s.get("publicKey"), 32) is None:
                    return "threshold.shares[%d].publicKey is not canonical base64url (32 bytes)" % i
                # 0.4.1: the share signature is validated PER SUITE (it used to be a fixed 64 bytes, so a pure post-quantum
                # share could never be carried): `alg` absent == ed25519 (64-byte `sig`, no `pq_sig`), else the suite's lengths.
                share_err = validate_share_signature_wire(s)
                if share_err is not None:
                    return "threshold.shares[%d]: %s" % (i, share_err)
        return None
    except Exception as e:
        return "malformed: %s" % e


# ---- Intent Layer M2: the signed `envelope.intent` binding -------------------------------------------------------
#
# Normative rules: packages/pca/src/intent-binding.ts and conformance/README.md "Intent binding". The optional top-level
# `intent` slot is SIGNED (part of the canonical body). When present it is an object with EXACTLY the members below
# (else `wire` fails). The `intent` check runs after `counter_format` and is reported iff the PCActn carries `intent` OR the
# verifier's intent policy is ACTIVE; otherwise the verdict is the pre-M2 one.

INTENT_GOAL_PREFIX = "pca-intent:v1:"
# Intent Layer v2 session grants (G_0 and the delta grants D_k): `pca-intent:v2:<session>:<map_digest>` (rule 13).
INTENT_GOAL_V2_PREFIX = "pca-intent:v2:"
INTENT_GOAL_V3_PREFIX = "pca-intent:v3:"  # goal binding v3: the signed Goal IR + the compiled policy
# Intent Layer v2 session grants over a COMMITTED map (rule 19): `pca-intent:v2c:<session>:<map_commit>`.
INTENT_GOAL_V2C_PREFIX = "pca-intent:v2c:"
MAP_FORM_COMMIT = "commit"
INTENT_GOAL_COMMIT_DOMAIN = "atlas-pca/goal/v1\x00"
PPM_ONE = 1_000_000
MAX_INTENT_GOAL_SALT_LEN = 128
ENVELOPE_INTENT_FIELDS = ("ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm")


def validate_intent_wire(v: Any) -> Optional[str]:
    """Wire validation of the `intent` slot. None = well-formed, else a short reason. Never raises."""
    if not isinstance(v, dict):
        return "'intent' must be an object"
    for k in v:
        if k not in ENVELOPE_INTENT_FIELDS:
            return "unknown field 'intent.%s'" % k
    for k in ENVELOPE_INTENT_FIELDS:
        if k not in v:
            return "missing field 'intent.%s'" % k
    if decode_b64u_strict(v["ref"], 32) is None:
        return "'intent.ref' is not canonical base64url (32 bytes)"
    if decode_b64u_strict(v["map_digest"], 32) is None:
        return "'intent.map_digest' is not canonical base64url (32 bytes)"
    gs = v["goal_salt"]
    if not _is_str(gs) or gs == "" or _blen(gs) > MAX_INTENT_GOAL_SALT_LEN:
        return "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)"
    fp = v["fidelity_ppm"]
    if not _is_safe_int(fp) or not (0 <= fp <= PPM_ONE):
        return "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]"
    rr = v["residual_risk_ppm"]
    if not _is_safe_int(rr) or rr < 0:
        return "'intent.residual_risk_ppm' must be a non-negative safe integer"
    return None


def intent_goal(ref: str, map_digest: Optional[str] = None) -> str:
    """The goal string that binds a grant to an intent statement (and optionally an Intent Map)."""
    return INTENT_GOAL_PREFIX + ref + (":" + map_digest if map_digest else "")


def intent_goal_commit(ref: str, map_digest: str, goal_salt: str, session: Optional[str] = None,
                       map_form: Optional[str] = None) -> str:
    """The goal commitment an `envelope.intent` claims the root grant carries. With `session` (Intent Layer v2, rule 13
    amends rule 12 step 2) the goal is `"pca-intent:v2:" + session + ":" + map_digest` instead of the v1 goal; with
    `map_form` "commit" too (rule 19, a committed map) it is `"pca-intent:v2c:" + session + ":" + map_digest`."""
    if session is not None:
        goal = (INTENT_GOAL_V2C_PREFIX if map_form == MAP_FORM_COMMIT else INTENT_GOAL_V2_PREFIX) + session + ":" + map_digest
    else:
        goal = intent_goal(ref, map_digest)
    return hash_canonical({"d": INTENT_GOAL_COMMIT_DOMAIN, "goal": goal, "salt": goal_salt})


def is_approved_goal_ref(v: Any) -> bool:
    """A well-formed `approved_goal`: a closed object of exactly `goal_digest` and `policy_digest`, both canonical
    base64url of 32 bytes."""
    return (isinstance(v, dict) and len(v) == 2 and decode_b64u_strict(v.get("goal_digest"), 32) is not None
            and decode_b64u_strict(v.get("policy_digest"), 32) is not None)


def intent_goal_v3(ref: Any) -> str:
    """The goal v3 string `pca-intent:v3:<goal_digest>:<policy_digest>`. Raises ValueError on a malformed digest: never
    commit to garbage."""
    if not is_approved_goal_ref(ref):
        raise ValueError("intent_goal_v3: goal_digest and policy_digest must be canonical base64url (32 bytes)")
    return INTENT_GOAL_V3_PREFIX + ref["goal_digest"] + ":" + ref["policy_digest"]


def intent_goal_commit_v3(ref: Any, goal_salt: str) -> str:
    """The goal v3 commitment for a salt (the same domain and hash as :func:`intent_goal_commit`)."""
    return hash_canonical({"d": INTENT_GOAL_COMMIT_DOMAIN, "goal": intent_goal_v3(ref), "salt": goal_salt})


_MISSING = object()


def intent_policy_active(policy: Any) -> bool:
    """True iff the policy is active: `require` is exactly True, a threshold key or `approved_goal` is present."""
    return isinstance(policy, dict) and (
        policy.get("require") is True or "min_fidelity_ppm" in policy or "max_residual_risk_ppm" in policy
        or "approved_goal" in policy)


def root_goal_commit(grant: Any) -> Optional[str]:
    """The root grant's goal commitment: the FIRST `envelope` caveat's string `goal_commit`, else None."""
    if not isinstance(grant, dict) or not isinstance(grant.get("caveats"), list):
        return None
    for c in grant["caveats"]:
        if isinstance(c, dict) and c.get("type") == "envelope":
            gc = c.get("goal_commit")
            return gc if isinstance(gc, str) else None
    return None


def decide_intent_binding(intent: Any, grant: Any, policy: Any = None, session: Optional[str] = None,
                          map_form: Optional[str] = None) -> "tuple[str, Optional[str]]":
    """The `intent` check (rules 0-4). `intent` is the wire-validated slot (None when absent). `session` is the
    wire-valid `intent_session.session` of the PCActn (Intent Layer v2: the v2 goal opens the commitment), else None;
    `map_form` its `intent_session.map_form` (rule 19: "commit" selects the v2c goal).
    Returns ("absent", None), ("pass", None) or ("fail", reason). Never raises."""
    active = intent_policy_active(policy)
    if intent is None and not active:
        return "absent", None
    try:
        # A threshold is valid iff its NUMERIC VALUE is a safe integer >= 0 (int, or an integral float such as 950000.0 /
        # 1e6; not bool, -0.0, NaN/Inf, a fraction or > 2^53-1). Unset bounds are None. Only an active policy has keys.
        pol = policy if active else {}
        lo = pol["min_fidelity_ppm"] if "min_fidelity_ppm" in pol else None
        hi = pol["max_residual_risk_ppm"] if "max_residual_risk_ppm" in pol else None
        if ("min_fidelity_ppm" in pol and not (_is_safe_int(lo) and lo >= 0)) or \
                ("max_residual_risk_ppm" in pol and not (_is_safe_int(hi) and hi >= 0)):
            return "fail", "intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)"
        v3 = pol.get("approved_goal", _MISSING)
        if v3 is not _MISSING and not is_approved_goal_ref(v3):
            return "fail", "intent policy misconfigured: approved_goal digests must be canonical base64url (32 bytes) (fail closed)"
        if intent is None:
            return "fail", "this verifier requires an intent binding but the PCActn carries none"
        commit = root_goal_commit(grant)
        if commit is None:
            return "fail", "the root grant carries no envelope goal commitment to bind the intent to"
        if v3 is not _MISSING:
            if intent_goal_commit_v3(v3, intent["goal_salt"]) != commit:
                return "fail", "the root grant's goal commitment does not open to the approved goal and compiled policy (v3)"
        elif intent_goal_commit(intent["ref"], intent["map_digest"], intent["goal_salt"], session, map_form) != commit:
            return "fail", "intent ref / map_digest / goal_salt do not open the root grant's goal commitment"
        if lo is not None and intent["fidelity_ppm"] < int(lo):
            return "fail", "intent fidelity %d ppm is below the policy minimum %d" % (intent["fidelity_ppm"], int(lo))
        if hi is not None and intent["residual_risk_ppm"] > int(hi):
            return "fail", "intent residual risk %d ppm exceeds the policy maximum %d" % (intent["residual_risk_ppm"], int(hi))
        return "pass", None
    except Exception as e:  # noqa: BLE001 - fail closed
        return "fail", "intent binding error (fail closed): %s" % e


# ---- JS object semantics shared by the Intent Layer v2 rules ----------------------------------------------------------

_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")


def _js_keys(o: dict) -> List[str]:
    """`Object.keys(o)` order: canonical array-index keys ("0".."4294967294", no leading zeros) ascending by value, then
    the other keys in insertion order (JSON text order). Only the first-failure reason can depend on it."""
    idx, rest = [], []
    for k in o:
        if isinstance(k, str) and _ARRAY_INDEX.fullmatch(k) and int(k) <= 4294967294:
            idx.append(k)
        else:
            rest.append(k)
    idx.sort(key=int)
    return idx + rest


def _js_nonneg_int(v: Any) -> bool:
    """TS `Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0)` (a bool is not a number; 5.0 is the number 5)."""
    return _is_safe_int(v) and v >= 0


def _b32(v: Any) -> bool:
    return decode_b64u_strict(v, 32) is not None


# ---- Intent Layer v2: the signed PCActn member `intent_session` (wire, rule 13) ---------------------------------------

MAX_SESSION_SEQ = 2_147_483_647
MAX_IS_ACC = 16
MAX_IS_FACTS = 16
MAX_IS_PROV_PATHS = 32
MAX_IS_PROV_REFS = 8
MAX_IS_CLASSES = 8
MAX_IS_LABELS = 16
MAX_IS_STRING_BYTES = 256
INTENT_SESSION_FIELDS = ("session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels",
                         "map_form")
ACC_ID_RE = re.compile(r"[A-Za-z0-9_]{1,64}")  # always used with fullmatch
_PROV_PATH_RE = re.compile(r"action\.params\.[A-Za-z0-9_]{1,64}")  # always used with fullmatch


def _short_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0 and not _has_surrogate(v) and _blen(v) <= MAX_IS_STRING_BYTES


def _digest_list_error(v: Any, name: str, mx: int) -> Optional[str]:
    if not isinstance(v, list) or len(v) > mx:
        return "'intent_session.%s' must be an array of at most %d digests" % (name, mx)
    for x in v:
        if not _b32(x):
            return "'intent_session.%s' entries must be canonical base64url (32 bytes)" % name
    if len(set(v)) != len(v):
        return "'intent_session.%s' entries must be distinct" % name
    return None


def validate_intent_session_wire(v: Any) -> Optional[str]:
    """Wire validation of `intent_session` (part of the terminal `wire` check; mirrors validateIntentSessionWire).
    Closed member set INTENT_SESSION_FIELDS; required `session`, `root`, `schema` (canonical base64url, 32 bytes each)
    and `seq` (safe integer in [0, 2^31-1]); optional `acc` (<= 16 objects {id, post, receipt?}, distinct ids, post a
    non-negative safe integer, receipt a 32-byte digest), `facts` / `classes` / `labels` (<= 16 / 8 / 16 distinct
    32-byte digests), `offer_set` (32-byte digest), `prov` (<= 32 entries `action.params.<name>` -> 1..8 non-empty
    strings of at most 256 UTF-8 bytes, no lone surrogates). None = well-formed, else a short reason. Never raises."""
    if not isinstance(v, dict):
        return "'intent_session' must be an object"
    for k in _js_keys(v):
        if k not in INTENT_SESSION_FIELDS:
            return "unknown field 'intent_session.%s'" % k
    for k in ("session", "root", "seq", "schema"):
        if k not in v:
            return "missing field 'intent_session.%s'" % k
    for k in ("session", "root", "schema"):
        if not _b32(v[k]):
            return "'intent_session.%s' is not canonical base64url (32 bytes)" % k
    if not _js_nonneg_int(v["seq"]) or v["seq"] > MAX_SESSION_SEQ:
        return "'intent_session.seq' must be a safe integer in [0, 2147483647]"
    if "acc" in v:
        acc = v["acc"]
        if not isinstance(acc, list) or len(acc) > MAX_IS_ACC:
            return "'intent_session.acc' must be an array of at most %d entries" % MAX_IS_ACC
        ids = set()
        for i, a in enumerate(acc):
            if not isinstance(a, dict):
                return "'intent_session.acc[%d]' must be an object" % i
            for k in _js_keys(a):
                if k not in ("id", "post", "receipt"):
                    return "unknown field 'intent_session.acc[%d].%s'" % (i, k)
            aid = a.get("id")
            if not isinstance(aid, str) or ACC_ID_RE.fullmatch(aid) is None:
                return "'intent_session.acc[%d].id' must match [A-Za-z0-9_]{1,64}" % i
            if aid in ids:
                return "'intent_session.acc' ids must be distinct"
            ids.add(aid)
            if not _js_nonneg_int(a.get("post")):
                return "'intent_session.acc[%d].post' must be a non-negative safe integer" % i
            if "receipt" in a and not _b32(a["receipt"]):
                return "'intent_session.acc[%d].receipt' is not canonical base64url (32 bytes)" % i
    if "facts" in v:
        e = _digest_list_error(v["facts"], "facts", MAX_IS_FACTS)
        if e:
            return e
    if "offer_set" in v and not _b32(v["offer_set"]):
        return "'intent_session.offer_set' is not canonical base64url (32 bytes)"
    if "prov" in v:
        prov = v["prov"]
        if not isinstance(prov, dict) or len(prov) > MAX_IS_PROV_PATHS:
            return "'intent_session.prov' must be an object of at most %d entries" % MAX_IS_PROV_PATHS
        for path in _js_keys(prov):
            refs = prov[path]
            if _PROV_PATH_RE.fullmatch(path) is None:
                return "'intent_session.prov' key '%s' is not action.params.<name>" % path
            if not isinstance(refs, list) or len(refs) == 0 or len(refs) > MAX_IS_PROV_REFS or not all(_short_str(x) for x in refs):
                return "'intent_session.prov.%s' must be 1..%d non-empty strings of at most %d UTF-8 bytes" % (
                    path, MAX_IS_PROV_REFS, MAX_IS_STRING_BYTES)
    if "classes" in v:
        e = _digest_list_error(v["classes"], "classes", MAX_IS_CLASSES)
        if e:
            return e
    if "labels" in v:
        e = _digest_list_error(v["labels"], "labels", MAX_IS_LABELS)
        if e:
            return e
    if "map_form" in v and not (isinstance(v["map_form"], str) and v["map_form"] == MAP_FORM_COMMIT):
        return "'intent_session.map_form' must be \"commit\" when present"
    return None


# ---- Intent Layer v2: the session grant caveat {type: "intent_session", session, seq, root, prev?} (rule 13) ----------

INTENT_SESSION_CAVEAT = "intent_session"


def intent_session_caveat_error(c: Any) -> Optional[str]:
    """Shape of an `intent_session` grant caveat: exactly {type, session, seq, root, prev?}, prev present iff seq > 0
    (mirrors intentSessionCaveatError). None = well-formed. Never raises."""
    if not isinstance(c, dict) or c.get("type") != INTENT_SESSION_CAVEAT:
        return "not an intent_session caveat"
    for k in _js_keys(c):
        if k not in ("type", "session", "seq", "root", "prev"):
            return "intent_session caveat: unknown member '%s'" % k
    if not _b32(c.get("session")) or not _b32(c.get("root")):
        return "intent_session caveat: session and root must be canonical base64url (32 bytes)"
    seq = c.get("seq")
    if not _js_nonneg_int(seq) or seq > MAX_SESSION_SEQ:
        return "intent_session caveat: seq must be a safe integer in [0, 2147483647]"
    if (seq == 0) != ("prev" not in c):
        return "intent_session caveat: prev is present exactly when seq > 0"
    if "prev" in c and not _b32(c["prev"]):
        return "intent_session caveat: prev must be canonical base64url (32 bytes)"
    return None


def grant_session_caveat(grant: Any) -> Optional[dict]:
    """The FIRST caveat of `grant` whose type is `intent_session` (as is), else None."""
    if not isinstance(grant, dict) or not isinstance(grant.get("caveats"), list):
        return None
    for c in grant["caveats"]:
        if isinstance(c, dict) and isinstance(c.get("type"), str) and c["type"] == INTENT_SESSION_CAVEAT:
            return c
    return None


# ---- PCActn --------------------------------------------------------------------------

def threshold_message(p: dict) -> bytes:
    """SIG_DOMAIN || sha256(strictCanonical(pcactn without `sig`, `threshold` and `pq_sig`))."""
    body = {k: v for k, v in p.items() if k not in ("sig", "threshold", "pq_sig")}
    return SIG_DOMAIN + sha256(canonical_bytes_strict(body))


SHARE_DOMAIN_PREFIX = "atlas-pca/share/"
SIGNER_SET_DOMAIN = b"atlas-pca/signerset/v1\x00"
SHARE_SUITE_TAG = "\x00atlas-pca/share-suite/v1\x00"


def signer_set_hash(signer_set: Any) -> Optional[bytes]:
    """`sha256("atlas-pca/signerset/v1\\0" || canonical(sort_by(role, publicKey)[{publicKey, role[, pq_pk]}]))`.
    `pq_pk` is carried ONLY when registered (ed25519-only sets hash byte-identically to pre-agility). None on a
    malformed set (fail-closed)."""
    if not isinstance(signer_set, list) or not signer_set:
        return None
    rows = []
    for e in signer_set:
        if not isinstance(e, dict) or not isinstance(e.get("role"), str) or not isinstance(e.get("publicKey"), str):
            return None
        row = {"publicKey": e["publicKey"], "role": e["role"]}
        if isinstance(e.get("pq_pk"), str):
            row["pq_pk"] = e["pq_pk"]
        rows.append(row)
    rows.sort(key=lambda r: (r["role"].encode("utf-8"), r["publicKey"].encode("utf-8")))
    return sha256(SIGNER_SET_DOMAIN + canonical_bytes_strict(rows))


def share_suite_tag(alg: Any) -> bytes:
    """Empty for ed25519 / absent / unknown, else `SHARE_SUITE_TAG || suite` (a PQ/hybrid share cannot be stripped
    back to ed25519, nor a classical share relabelled hybrid)."""
    if alg is None or not isinstance(alg, str) or alg == "ed25519" or alg not in _SIG_SUITES:
        return b""
    return (SHARE_SUITE_TAG + alg).encode("utf-8")


def share_message(role: str, thr_msg: bytes, signer_set_hash: bytes, t: int, alg: Any = None) -> bytes:
    """v2.1 bound threshold-share message:
    `"atlas-pca/share/<role>\\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte) [|| suite tag]`."""
    return ((SHARE_DOMAIN_PREFIX + role + "\x00").encode("utf-8") + sha256(thr_msg) + signer_set_hash + bytes([t])
            + share_suite_tag(alg))


THRESHOLD_ROLES = frozenset(("agent", "guardian", "principal"))
# Registered PQ public-key lengths of every suite (ml-dsa-65/87, slh-dsa-sha2-128f/256s, fn-dsa-512/1024, less-cat1): a
# signer-set `pq_pk` must decode to one of them even when this verifier does not implement that suite (set validity
# must agree with the reference).
PQ_PK_LENGTHS = frozenset((1952, 2592, 32, 64, 897, 1793, 97484))


def _signer_registry(signer_set: Any) -> Optional[dict]:
    """Validate the WHOLE signer set exactly like the reference (`verifyThreshold` / Threshold.dfy BuildReg) and return
    {role: (publicKey, pq_pk_or_None)}, or None if the set is malformed (R6-03): every entry is an object with a known
    role and a canonical 32-byte base64url publicKey; a PRESENT pq_pk (JSON null is present) is canonical base64url of a
    registered PQ key length; one key per role, one role per key; a duplicate (role, key) entry only with the same pq_pk."""
    if not isinstance(signer_set, list):
        return None
    reg: dict = {}
    roles_of_key: dict = {}
    for e in signer_set:
        if not isinstance(e, dict):
            return None
        role, pk = e.get("role"), e.get("publicKey")
        if not isinstance(role, str) or role not in THRESHOLD_ROLES or decode_b64u_strict(pk, 32) is None:
            return None
        pq = None
        if "pq_pk" in e:
            pq = e["pq_pk"]
            raw = decode_b64u_strict(pq) if isinstance(pq, str) else None
            if raw is None or len(raw) not in PQ_PK_LENGTHS:
                return None
        if role in reg:
            if reg[role] != (pk, pq):
                return None  # two keys for one role, or the same key with a conflicting pq_pk
            continue
        if roles_of_key.get(pk, role) != role:
            return None  # one key under two roles
        reg[role] = (pk, pq)
        roles_of_key[pk] = role
    return reg


def verify_threshold_share(entry: Any) -> bool:
    """v2.1 threshold-share binding, SIGNER-SET PINNED (R5-A1). The signer set is `entry["signer_set"]` (the
    verifier's own set), validated AS A WHOLE first (R6-03, `_signer_registry`); the signer-set hash is RECOMPUTED
    from it. `t` must be 1, 2 or 3 (R6-04). The share must be for the one key the set registers for `role` (a share's
    own `publicKey`/`pq_pk` never vouch for themselves); a role that registers a `pq_pk` needs a PQ / hybrid share
    (R6-02), verified ONLY under the registered `pq_pk`. The signed bytes carry the share-suite tag.
    TOTAL and FAIL-CLOSED (R6-05): any malformed input -> False, never an exception."""
    try:
        return _verify_threshold_share(entry)
    except Exception:  # noqa: BLE001 - totality on hostile input
        return False


def _verify_threshold_share(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    role = entry.get("role")
    t = entry.get("t")
    share = entry.get("share")
    # `bool` is an `int` subclass; a boolean `t` is malformed. An integral float equal to 1/2/3 is accepted (JS number).
    if isinstance(t, bool) or not isinstance(t, (int, float)) or t not in (1, 2, 3):
        return False
    t = int(t)
    if not isinstance(role, str) or role not in THRESHOLD_ROLES:
        return False
    if not isinstance(share, dict) or share.get("role") != role or not isinstance(share.get("publicKey"), str):
        return False
    thr_msg = decode_b64u_strict(entry.get("threshold_message"))
    if thr_msg is None:
        return False
    reg = _signer_registry(entry.get("signer_set"))
    if reg is None or role not in reg:
        return False
    reg_pk, reg_pq = reg[role]
    if share["publicKey"] != reg_pk:
        return False
    ssh = signer_set_hash(entry["signer_set"])
    if ssh is None:
        return False
    suite = _resolve_suite(share)[0]
    if suite is None:
        return False
    # A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering none has
    # nothing it could equal). The key used is always the registered one.
    if "pq_pk" in share and (reg_pq is None or share["pq_pk"] != reg_pq):
        return False
    if suite == "ed25519":
        # R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share; an ed25519-only share is refused
        # (otherwise an Ed25519 break would still forge the role).
        if reg_pq is not None:
            return False
    else:
        # PQ key = the signer set's registered pq_pk, never the share's own
        if reg_pq is None:
            return False
        share = dict(share, pq_pk=reg_pq)
    msg = share_message(role, thr_msg, ssh, t, share.get("alg"))
    return verify_leaf_suite(share, share.get("publicKey"), msg)


def verify_artifact_suite(artifact: dict) -> bool:
    """Verify a post-quantum transparency/authority artifact signature over its `message` under the artifact's
    suite (`alg`, default ed25519; Ed25519 public key in `ed_pub`, lattice/hash key in `pq_pk`). Routes through
    the SAME suite-agile seam as the leaf. FAIL-CLOSED: unknown/unimplemented suite or malformed input -> False."""
    if not isinstance(artifact, dict):
        return False
    msg = decode_b64u_strict(artifact.get("message"))
    if msg is None:
        return False
    return verify_leaf_suite(artifact, artifact.get("ed_pub"), msg)


CHECK_ORDER = ("wire", "version", "audience", "validity", "chain", "plan_inclusion", "leaf_signature", "counter_format")


@dataclass
class Verdict:
    allow: bool
    checks: Dict[str, bool] = field(default_factory=dict)
    reason: Optional[str] = None
    #: Every reason, in order: the first failure (``reason``), then one for EACH further failing intent-v2 check (the
    #: escalate-class ones). ``decision_of`` reads the whole list, so a multi-check escalation stays an escalation.
    reasons: List[str] = field(default_factory=list)
    #: Rule 21 compatibility mode in effect (``model_polarity: "legacy"`` and a grant reads a model-derived path in ``where``):
    #: the verdict is reported ``degraded`` in the assurance report and refused by any ``require_assurance``.
    legacy_model_polarity: bool = False


def verify_pcactn_core(p: Union[dict, str, bytes], grant: dict, now: Optional[int] = None,
                       audience: Optional[str] = None, allowed_suites=None,
                       intent_policy: Optional[dict] = None, intent_v2: Optional[dict] = None,
                       fresh_at: Optional[dict] = None) -> Verdict:
    """Verify a v2 PCActn. `p` is a parsed object OR raw JSON text/bytes (which goes through the strict profile;
    a parse failure is a `wire` failure). `audience` is this verifier's own id; omitting it fails closed.
    `now` is epoch milliseconds (default: wall clock). Never raises (R6-05: TOTAL on any input, including the
    pre-wire parse of hostile bytes). `intent_policy` (Intent Layer M2) is an optional dict
    {"require": bool, "min_fidelity_ppm": int, "max_residual_risk_ppm": int} (all optional); the `intent` check is
    reported iff the PCActn carries `intent` or the policy is active (`require` is True or a threshold key is set).
    `intent_v2` (Intent Layer v2, rules 13-19) is the verifier state + policy dict (TS IntentV2Context: `policy`, `params`,
    `schema: {docs, keys}`, `session: {root, grants, revocation: {epoch, revoked}, revocation_last}`, `layers`,
    `acc: {state, monitors, receipts, last_seq, sequencer_keys, keyset_versions}`, `map: {disclosure}`,
    `wb: {artifacts, policy}`); the v2 checks `schema`, `intent_session`, `layers`, `accumulators`, `map`, `facts`,
    `provenance`, `classes` follow `intent`, each reported only under its condition (see
    atlas_pca.intent_v2.decide_intent_v2), and `allow` requires every reported one.
    `fresh_at` is the consistency-token policy `{signer, scope, local: {revocation_epoch, ledger_tree_size, budget_version,
    policy_revision, policy_digest}, max_token_age_ms?, require?, side_carried?}` (see atlas_pca.fresh_at): the `fresh_at` check
    follows the intent checks and is reported only when the PCActn carries the member, a side-carried token is read (`side_carried`
    key present, read only when there is no member) or the policy requires one; a PCActn with the member and no policy is refused."""
    try:
        return _verify_pcactn_core_unchecked(p, grant, now, audience, allowed_suites, intent_policy, intent_v2, fresh_at)
    except Exception as e:  # noqa: BLE001 - totality: a residual fault on hostile input is a wire refusal
        return Verdict(False, {"wire": False}, "wire: malformed input (%s)" % type(e).__name__)


def _verify_pcactn_core_unchecked(p, grant, now, audience, allowed_suites, intent_policy=None, intent_v2=None,
                                  fresh_at=None) -> Verdict:
    if isinstance(p, (str, bytes, bytearray)):
        if artifact_too_large(p):  # FIRST: before any parsing
            return Verdict(False, {"wire": False}, "wire: %s" % ARTIFACT_SIZE_REASON)
        try:
            p = strict_parse(p)
        except StrictJsonError as e:
            return Verdict(False, {"wire": False}, "wire: %s" % e)
    wire = validate_wire_v2(p)
    if wire is not None:
        return Verdict(False, {"wire": False}, "wire: %s" % wire)
    if now is None:
        now = int(time.time() * 1000)

    checks: Dict[str, bool] = {name: False for name in CHECK_ORDER}
    checks["wire"] = True
    reason: List[Optional[str]] = [None]
    v2_checks: List[dict] = []
    legacy = [False]

    def fail(name: str, why: str) -> None:
        checks[name] = False
        if reason[0] is None:
            reason[0] = "%s: %s" % (name, why)

    try:
        if p["ver"] == PCACTN_VERSION:
            checks["version"] = True
        else:
            fail("version", "unsupported ver %r (this verifier requires %d)" % (p["ver"], PCACTN_VERSION))

        if audience is not None and p["aud"] == audience:
            checks["audience"] = True
        else:
            fail("audience", "aud does not match this resource server / instance")

        iat, exp = int(p["iat"]), int(p["exp"])
        if not exp > iat:
            fail("validity", "exp must be greater than iat")
        elif exp - iat > MAX_LIFETIME_MS:
            fail("validity", "lifetime exceeds %d ms" % MAX_LIFETIME_MS)
        elif iat > now + MAX_SKEW_MS:
            fail("validity", "iat is in the future (clock skew)")
        elif now > exp:
            fail("validity", "the PCActn has expired")
        else:
            checks["validity"] = True

        chain = p["cap_chain"]
        if not chain:
            fail("chain", "empty chain")
        elif len(chain) > MAX_CHAIN_DEPTH:
            fail("chain", "chain too long (max %d hops)" % MAX_CHAIN_DEPTH)  # before any signature work
        elif caveat_limit_exceeded(chain):
            fail("chain", CAVEAT_LIMIT_REASON)  # before any hashing or signature work
        elif cap_hash(chain[0]) != cap_hash(grant):
            fail("chain", "chain root is not the grant")
        else:
            ok, why = verify_chain(chain, grant.get("issuer"), allowed_suites, trusted_root=grant)  # chain[0] == grant was checked above
            if ok:
                checks["chain"] = True
            else:
                fail("chain", why or "invalid")

        # grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
        # ROOT capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed
        # on an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
        root_cap = chain[0] if isinstance(chain, list) and chain and isinstance(chain[0], dict) else None
        root_id = root_cap.get("id") if root_cap is not None else None
        gref = p.get("grant_ref")
        if isinstance(gref, str) and gref != "" and isinstance(root_id, str) and gref == root_id:
            checks["grant_ref_bound"] = True
        else:
            fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain")

        plan = p["plan"]
        cond = plan["conditions_digest"] if "conditions_digest" in plan else conditions_digest()
        leaf = _plan_leaf(plan["node_id"], p["action"], cond)
        if verify_inclusion(plan["root"], plan["inclusion_proof"], leaf):
            checks["plan_inclusion"] = True
        else:
            fail("plan_inclusion", "action is not a node of the committed plan")

        leaf_err = None
        if chain:
            leaf_err = _suite_policy_error(p.get("alg"), "leaf", allowed_suites) or \
                pq_binding_error(p.get("alg"), p.get("pq_pk"), chain[-1].get("holder_pq"), "leaf")
        if leaf_err is not None:
            fail("leaf_signature", leaf_err)
        elif chain and _verify_suite(p, chain[-1].get("holder"), threshold_message(p),
                                     _resolve_pq_key(chain[-1].get("holder"), p.get("pq_pk"), holder_pq=chain[-1].get("holder_pq"))):
            checks["leaf_signature"] = True
        else:
            fail("leaf_signature", "signature does not verify under the leaf holder key")

        c = p["counter"]
        if _is_safe_int(c) and c >= 0:
            checks["counter_format"] = True
        else:
            fail("counter_format", "missing or not a non-negative safe integer")

        # Intent Layer M2: `intent` check (present iff the PCActn carries `intent` or the policy is active).
        # Intent Layer v2 (rule 13 amends rule 12 step 2): a wire-valid `intent_session` makes the goal the v2 session goal.
        session = p["intent_session"]["session"] if "intent_session" in p else None
        map_form = p["intent_session"].get("map_form") if "intent_session" in p else None  # rule 19: the v2c goal
        status, why = decide_intent_binding(p.get("intent"), grant, intent_policy, session, map_form)
        if status == "pass":
            checks["intent"] = True
        elif status == "fail":
            fail("intent", why)
        # Intent Layer v2: `schema` (14), `intent_session` (13), `layers` (V5), `accumulators` (15), `map` (19), then the W-B unit
        # `facts` / `provenance` / `classes` (16-18); each reported only under its condition (see intent_v2.py).
        from .intent_v2 import decide_intent_v2  # deferred: intent_v2 imports this module
        v2_decision = decide_intent_v2(p, grant, intent_v2, now)
        legacy[0] = v2_decision.get("legacy_model_polarity") is True
        v2_checks.extend(v2_decision["checks"])
        for c in v2_checks:
            if c["ok"]:
                checks[c["name"]] = True
            else:
                fail(c["name"], c.get("reason") or "rejected")
        # Consistency token: `fresh_at` (right after the intent checks; a failing escalate-class reason folds into `reasons`).
        from .fresh_at import ABSENT, decide_fresh_at  # deferred: fresh_at imports this module
        fa = decide_fresh_at(p["fresh_at"] if "fresh_at" in p else ABSENT, fresh_at, now)
        if fa["status"] == "pass":
            checks["fresh_at"] = True
        elif fa["status"] == "fail":
            fail("fresh_at", fa["reason"])
            v2_checks.append({"name": "fresh_at", "ok": False, "reason": fa["reason"]})
    except Exception as e:  # malformed input never raises; it simply denies
        if reason[0] is None:
            reason[0] = "malformed PCActn: %s" % e
    from .decision import fold_v2_reasons  # deferred: decision imports predicates, which must not import this module
    allow = all(checks.values())
    return Verdict(allow=allow, checks=checks, reason=reason[0],
                   reasons=[] if allow else fold_v2_reasons([] if reason[0] is None else [reason[0]], v2_checks),
                   legacy_model_polarity=legacy[0])


# ---- policy layer: caveat evaluation (0.4.1) -----------------------------------------------------------------------
#
# The core verifier (verify_pcactn_core, the 9 checks) treats caveats as opaque and does NOT evaluate them. A resource
# server that enforces a grant's caveats calls evaluate_caveats(policy_caveats(grant, chain), ctx) with its own action
# context. 0.4.1 (security, mirrors the TypeScript policy layer): caveats placed on the ROOT grant outside the envelope
# are evaluated exactly like the caveats delegation hops append.

ENVELOPE_CAVEAT = "envelope"
REVERSIBILITY_ORDER = ("reversible", "rate_limited", "irreversible")


def policy_caveats(grant: Any, chain: Any) -> Any:
    """Every caveat the policy layer evaluates for an action under `grant` delegated along `chain` (root first):
    `grant["caveats"]` without its FIRST `envelope` caveat (order kept), then the caveats the hops appended
    (`leaf["caveats"][len(grant["caveats"]):]`, leaf = the last chain element). A non-list `grant["caveats"]` is
    returned as is (None when the grant is not an object); `evaluate_caveats` refuses it (fail closed). Never raises."""
    cs = grant.get("caveats") if isinstance(grant, dict) else None
    if not isinstance(cs, list):
        return cs
    root = list(cs)
    for i, c in enumerate(root):
        if isinstance(c, dict) and isinstance(c.get("type"), str) and c.get("type") == ENVELOPE_CAVEAT:
            del root[i]
            break
    leaf = chain[-1] if isinstance(chain, list) and chain else None
    if isinstance(leaf, dict) and isinstance(leaf.get("caveats"), list):
        root.extend(leaf["caveats"][len(cs):])
    return root


def _fin(x: Any) -> Optional[float]:
    """The value as a finite IEEE double (the reference's JSON number), or None: bools, strings, NaN, +-inf and
    integers beyond the double range are not finite numbers."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    try:
        f = float(x)
    except (OverflowError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _max_spend_satisfied(cv: dict, ctx: dict) -> bool:
    lim = _fin(cv.get("usd"))
    if lim is None or lim < 0:
        return False
    action = ctx.get("action")
    if not isinstance(action, dict):
        return False
    params = action.get("params")
    if not isinstance(params, dict) or "amount" not in params:
        return False
    amount = _fin(params["amount"])
    if amount is None or amount < 0:
        return False
    if "currency" in params:
        cur = params["currency"]
        if not isinstance(cur, str) or cur not in ("usd", "USD"):
            return False
    return amount <= lim


def _caveat_satisfied(cv: Any, ctx: Any) -> bool:
    if not isinstance(cv, dict) or not isinstance(ctx, dict):
        return False
    t = cv.get("type")
    if t == "max_spend":
        return _max_spend_satisfied(cv, ctx)
    now = _fin(ctx.get("now"))
    if now is None:
        return False
    if t == "expires":
        at = _fin(cv.get("at"))
        return at is not None and now < at
    if t == "not_before":
        at = _fin(cv.get("at"))
        return at is not None and now >= at
    if t == "rate":
        mx, per = _fin(cv.get("max")), _fin(cv.get("per_secs"))
        times = ctx.get("recent_action_times")
        if mx is None or per is None or per <= 0 or not isinstance(times, list):
            return False
        lo = now - per * 1000
        n = 0
        for x in times:
            tv = _fin(x)
            if tv is not None and lo < tv <= now:
                n += 1
        return n < mx
    if t == "max_blast_radius":
        mx, br = _fin(cv.get("max")), _fin(ctx.get("blast_radius"))
        return mx is not None and br is not None and br <= mx
    if t == "reversibility_max":
        lim, cur = cv.get("class"), ctx.get("reversibility_class")
        if not isinstance(lim, str) or not isinstance(cur, str):
            return False
        if lim not in REVERSIBILITY_ORDER or cur not in REVERSIBILITY_ORDER:
            return False
        return REVERSIBILITY_ORDER.index(cur) <= REVERSIBILITY_ORDER.index(lim)
    if t == "delegation_depth":
        mx, d = _fin(cv.get("max")), _fin(ctx.get("delegation_depth"))
        return mx is not None and d is not None and d <= mx
    if t == "budget_alloc":
        lim = _fin(cv.get("limit"))
        return lim is not None and lim >= 0
    if t == INTENT_SESSION_CAVEAT:
        # Intent Layer v2 session binding (rule 13): no per-action constraint here; satisfied iff well-formed.
        return intent_session_caveat_error(cv) is None
    return False  # envelope, note, resource_prefix, predicates, tool_schema, unknown: fail closed


def evaluate_caveats(caveats: Any, ctx: Any) -> "tuple[bool, list]":
    """Evaluate a caveat list against `ctx` = {now (ms), delegation_depth?, blast_radius?, reversibility_class?,
    recent_action_times?, action: {verb, resource, reversibility_class, params}}. Returns (ok, failed): ok iff every
    caveat is satisfied; `failed` lists the unsatisfied caveats' `type` (``"<malformed>"`` when it is not a string), in
    order. A non-list => (False, ["<malformed caveats>"]). Built-in types: max_spend {usd} (needs action.params.amount,
    currency absent or "usd"/"USD"), expires, not_before, rate, max_blast_radius, reversibility_max, delegation_depth,
    budget_alloc, intent_session (Intent Layer v2: satisfied iff well-formed; needs a finite `now` like every type but
    max_spend); every other type is unsatisfied. Total: never raises."""
    if not isinstance(caveats, list):
        return False, ["<malformed caveats>"]
    failed = []
    for cv in caveats:
        try:
            ok = _caveat_satisfied(cv, ctx)
        except Exception:
            ok = False
        if not ok:
            t = cv.get("type") if isinstance(cv, dict) else None
            failed.append(t if isinstance(t, str) else "<malformed>")
    return not failed, failed


# ---- the PCA-Action header (0.4.1: strict) --------------------------------------------------------------------------

class PcaHeaderError(ValueError):
    """A `PCA-Action` header value that is not strict unpadded base64url of UTF-8 text."""

    code = "invalid_pca_header"


def decode_pca_header(value: Any) -> str:
    """`PCA-Action` header value -> the PCActn JSON text. STRICT: non-empty, unpadded RFC 4648 s5 alphabet only, no
    whitespace anywhere (nothing is trimmed), length mod 4 != 1, zero unused trailing bits, then strict UTF-8 (invalid,
    overlong, surrogate and truncated sequences refused; a leading BOM is kept). Raises PcaHeaderError otherwise."""
    if not isinstance(value, str) or not value:
        raise PcaHeaderError("PCA-Action header is empty")
    raw = decode_b64u_strict(value)
    if raw is None:
        raise PcaHeaderError("PCA-Action header is not strict unpadded base64url")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PcaHeaderError("PCA-Action header does not decode to UTF-8 text") from None
