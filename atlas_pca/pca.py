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
from .mldsa import ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, ml_dsa65_verify

PCACTN_VERSION = 2
SIG_DOMAIN = b"atlas-pca/actn/v2\x00"
CAP_DOMAIN = b"atlas-pca/cap/v1\x00"
DEFAULT_REVERSIBILITY_CLASS = "reversible"
MAX_CHAIN_DEPTH = 16
MAX_JSON_DEPTH = 32
MAX_JSON_CHARS = 1 << 20
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
    return b64u(sha256(canonical_bytes(v)))


# ---- Merkle --------------------------------------------------------------------------

def _leaf_hash(leaf: Any) -> bytes:
    return sha256(b"\x00" + canonical_bytes(leaf))


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
# suite name -> (sig byte length, needs pq_pk, needs pq_sig). `alg` absent == "ed25519".
_SIG_SUITES = {
    "ed25519": (ED25519_SIGNATURE_BYTES, False, False),
    "ml-dsa-65": (ML_DSA_65_SIGNATURE_BYTES, True, False),
    "hybrid-ed25519-ml-dsa-65": (ED25519_SIGNATURE_BYTES, True, True),
}
_ABSENT = object()


def _resolve_suite(p: dict):
    """Return the suite name, or None (fail-closed) for an unknown/non-string alg. _ABSENT means 'alg' absent."""
    alg = p.get("alg", _ABSENT)
    if alg is _ABSENT:
        return "ed25519", None
    if not isinstance(alg, str):
        return None, "'alg' must be a string"
    if alg not in _SIG_SUITES:
        return None, "unknown signature alg '%s'" % alg
    return alg, None


def validate_signature_wire(p: dict) -> Optional[str]:
    """Validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. None when well-formed, else a short reason."""
    suite, err = _resolve_suite(p)
    if suite is None:
        return err
    sig_bytes, needs_pk, needs_sig = _SIG_SUITES[suite]
    if decode_b64u_strict(p.get("sig"), sig_bytes) is None:
        return "'sig' is not canonical base64url (%d bytes) for alg '%s'" % (sig_bytes, suite)
    if needs_pk:
        if decode_b64u_strict(p.get("pq_pk"), ML_DSA_65_PUBLIC_KEY_BYTES) is None:
            return "'pq_pk' is not canonical base64url (%d bytes)" % ML_DSA_65_PUBLIC_KEY_BYTES
    elif "pq_pk" in p:
        return "'pq_pk' must be absent for alg '%s'" % suite
    if needs_sig:
        if decode_b64u_strict(p.get("pq_sig"), ML_DSA_65_SIGNATURE_BYTES) is None:
            return "'pq_sig' is not canonical base64url (%d bytes)" % ML_DSA_65_SIGNATURE_BYTES
    elif "pq_sig" in p:
        return "'pq_sig' must be absent for alg '%s'" % suite
    return None


def _ml_dsa65_verify_b64u(pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    pk = decode_b64u_strict(pk_b64u, ML_DSA_65_PUBLIC_KEY_BYTES)
    sg = decode_b64u_strict(sig_b64u, ML_DSA_65_SIGNATURE_BYTES)
    if pk is None or sg is None:
        return False
    return ml_dsa65_verify(pk, msg, sg)


def verify_leaf_suite(p: dict, holder: Any, msg: bytes) -> bool:
    """Verify the leaf signature under the PCActn's suite. FAIL-CLOSED: unknown alg / missing / invalid -> False."""
    suite, _ = _resolve_suite(p)
    if suite is None:
        return False
    sig = p.get("sig")
    if suite == "ed25519":
        return _verify_b64u(holder, msg, sig)
    if suite == "ml-dsa-65":
        return _ml_dsa65_verify_b64u(p.get("pq_pk"), msg, sig)
    if suite == "hybrid-ed25519-ml-dsa-65":
        return _verify_b64u(holder, msg, sig) and _ml_dsa65_verify_b64u(p.get("pq_pk"), msg, p.get("pq_sig"))
    return False


def cap_hash(c: dict) -> str:
    return hash_canonical(c)


def _body_of(c: dict) -> dict:
    return {"issuer": c.get("issuer"), "holder": c.get("holder"), "caveats": c.get("caveats"), "parent": c.get("parent")}


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
        _, needs_pk, _ = _SIG_SUITES[suite]
        if needs_pk and isinstance(c.get("pq_pk"), str):
            body["pq_pk"] = c["pq_pk"]
    return body, None


def _check_sig(c: dict, signer: Any, label: str) -> Optional[str]:
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
    # pure ml-dsa-65 verifies `sig` under `pq_pk`. verify_leaf_suite dispatches on the hop's `alg`.
    if not verify_leaf_suite(c, signer, msg):
        return label + ": bad signature (not signed by expected key)"
    return None


def verify_chain(chain: list, expected_root_issuer: Optional[str] = None):
    """Returns (ok, reason)."""
    if not isinstance(chain, list) or not chain:
        return False, "empty chain"
    if len(chain) > MAX_CHAIN_DEPTH:
        return False, "chain too long (max %d hops)" % MAX_CHAIN_DEPTH
    root = chain[0]
    if "parent" in root:
        return False, "hop 0: root must not have a parent"
    if expected_root_issuer is not None and root.get("issuer") != expected_root_issuer:
        return False, "hop 0: root issuer is not the expected principal"
    err = _check_sig(root, root.get("issuer"), "hop 0")
    if err:
        return False, err
    for i in range(1, len(chain)):
        parent, c, label = chain[i - 1], chain[i], "hop %d" % i
        if c.get("parent") != cap_hash(parent):
            return False, label + ": broken parent link"
        if c.get("issuer") != parent.get("holder"):
            return False, label + ": issuer is not the parent's bound holder"
        err = _check_sig(c, parent.get("holder"), label)
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
            k = _unknown(c, ("id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig"))
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
                if decode_b64u_strict(s.get("sig"), 64) is None:
                    return "threshold.shares[%d].sig is not canonical base64url (64 bytes)" % i
        return None
    except Exception as e:
        return "malformed: %s" % e


# ---- PCActn --------------------------------------------------------------------------

def threshold_message(p: dict) -> bytes:
    """SIG_DOMAIN || sha256(strictCanonical(pcactn without `sig`, `threshold` and `pq_sig`))."""
    body = {k: v for k, v in p.items() if k not in ("sig", "threshold", "pq_sig")}
    return SIG_DOMAIN + sha256(canonical_bytes_strict(body))


SHARE_DOMAIN_PREFIX = "atlas-pca/share/"


def share_message(role: str, thr_msg: bytes, signer_set_hash: bytes, t: int) -> bytes:
    """v2.1 bound threshold-share message:
    `"atlas-pca/share/<role>\\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte)`."""
    return (SHARE_DOMAIN_PREFIX + role + "\x00").encode("utf-8") + sha256(thr_msg) + signer_set_hash + bytes([t])


def verify_threshold_share(entry: dict) -> bool:
    """v2.1 agent-leaf threshold-share binding. Recompute the role/signerSetHash/t-bound share message
    (`share_message`) and verify the share signature over it under the share's suite (`share.alg`, default
    ed25519). FAIL-CLOSED: any missing/malformed field, a non-string role, an out-of-range `t`, or an invalid
    signature -> False. The PRE-v2.1 bare agent share (signed over the bare `thresholdMessage`) and a
    cross-signer-set replay therefore do NOT verify against the recomputed bound message, so both return False.
    Mirrors `verify_threshold_share` in the Rust/Java reference verifiers."""
    if not isinstance(entry, dict):
        return False
    role = entry.get("role")
    t = entry.get("t")
    share = entry.get("share")
    # `bool` is an `int` subclass; a boolean `t` is malformed, not a byte count.
    if not isinstance(role, str) or isinstance(t, bool) or not isinstance(t, int) or not 0 <= t <= 255:
        return False
    if not isinstance(share, dict):
        return False
    thr_msg = decode_b64u_strict(entry.get("threshold_message"))
    ssh = decode_b64u_strict(entry.get("signer_set_hash"), 32)
    if thr_msg is None or ssh is None:
        return False
    msg = share_message(role, thr_msg, ssh, t)
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


CHECK_ORDER = ("wire", "version", "audience", "validity", "chain", "plan_inclusion", "leaf_signature", "counter")


@dataclass
class Verdict:
    allow: bool
    checks: Dict[str, bool] = field(default_factory=dict)
    reason: Optional[str] = None


def verify_pcactn_core(p: Union[dict, str, bytes], grant: dict, now: Optional[int] = None,
                       audience: Optional[str] = None) -> Verdict:
    """Verify a v2 PCActn. `p` is a parsed object OR raw JSON text/bytes (which goes through the strict profile;
    a parse failure is a `wire` failure). `audience` is this verifier's own id; omitting it fails closed.
    `now` is epoch milliseconds (default: wall clock). Never raises."""
    if isinstance(p, (str, bytes, bytearray)):
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
        elif cap_hash(chain[0]) != cap_hash(grant):
            fail("chain", "chain root is not the grant")
        else:
            ok, why = verify_chain(chain, grant.get("issuer"))
            if ok:
                checks["chain"] = True
            else:
                fail("chain", why or "invalid")

        plan = p["plan"]
        cond = plan["conditions_digest"] if "conditions_digest" in plan else conditions_digest()
        leaf = _plan_leaf(plan["node_id"], p["action"], cond)
        if verify_inclusion(plan["root"], plan["inclusion_proof"], leaf):
            checks["plan_inclusion"] = True
        else:
            fail("plan_inclusion", "action is not a node of the committed plan")

        if chain and verify_leaf_suite(p, chain[-1].get("holder"), threshold_message(p)):
            checks["leaf_signature"] = True
        else:
            fail("leaf_signature", "signature does not verify under the leaf holder key")

        c = p["counter"]
        if _is_safe_int(c) and c >= 0:
            checks["counter"] = True
        else:
            fail("counter", "not a non-negative safe integer")
    except Exception as e:  # malformed input never raises; it simply denies
        if reason[0] is None:
            reason[0] = "malformed PCActn: %s" % e
    return Verdict(allow=all(checks.values()), checks=checks, reason=reason[0])
