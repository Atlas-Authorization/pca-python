"""SCITT transparency receipts for Proof-Carrying Authority: RFC 9943 Signed Statements and RFC 9942 COSE Receipts over an
RFC 9162 SHA-256 Merkle log, with a strict deterministic CBOR codec (RFC 8949 4.2.1) sufficient for COSE_Sign1. Port of the
TypeScript reference (@atlasauth/pca-scitt).

Keys: EdDSA takes a raw 32-byte seed (signing) or raw 32-byte public key (verifying); ES256 (ECDSA P-256) and any key held as an
object take DER bytes (PKCS#8 / SPKI) or a `cryptography` key object, imported lazily. Everything fails closed."""
from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, List, Optional, Union

from . import ed25519
from .pca import MAX_SAFE, b64u, canonical_bytes_strict, decode_b64u_strict

# ---- RFC 9162 Merkle tree -------------------------------------------------------------------------------------------


def _sha(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def empty_root() -> bytes:
    return _sha()


def _raw(b: Any) -> bytes:
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise TypeError("expected bytes")
    return bytes(b)


def leaf_hash(entry: bytes) -> bytes:
    """SHA-256(0x00 || entry)."""
    return _sha(b"\x00", _raw(entry))


def node_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right)."""
    return _sha(b"\x01", _raw(left), _raw(right))


def _split_point(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def tree_hash(leaf_hashes: List[bytes]) -> bytes:
    """MTH over already-hashed leaves (RFC 9162 2.1.1)."""
    n = len(leaf_hashes)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaf_hashes[0]
    k = _split_point(n)
    return node_hash(tree_hash(leaf_hashes[:k]), tree_hash(leaf_hashes[k:]))


def _safe_int(v: Any) -> Optional[int]:
    """`Number.isSafeInteger` as an int (None when it is not one); negative zero is an integer here, callers refuse it."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if abs(v) <= MAX_SAFE else None
    if isinstance(v, float) and v == v and v not in (float("inf"), float("-inf")) and v == int(v) and abs(v) <= MAX_SAFE:
        return int(v)
    return None


def _neg_zero(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and str(v).startswith("-")


def inclusion_path(leaf_hashes: List[bytes], index: Any) -> List[bytes]:
    """Inclusion path for leaf `index` (RFC 9162 2.1.3.1), bottom-up."""
    n = len(leaf_hashes)
    i = _safe_int(index)
    if i is None or i < 0 or i >= n:
        raise ValueError("rfc9162: leaf index out of range")
    if n == 1:
        return []
    k = _split_point(n)
    if i < k:
        return inclusion_path(leaf_hashes[:k], i) + [tree_hash(leaf_hashes[k:])]
    return inclusion_path(leaf_hashes[k:], i - k) + [tree_hash(leaf_hashes[:k])]


def root_from_inclusion_path(leaf: bytes, index: Any, size: Any, path: List[bytes]) -> Optional[bytes]:
    """Recompute the root from a leaf hash and its path (RFC 9162 2.1.3.2); None for an invalid (index, size, path)."""
    i, n = _safe_int(index), _safe_int(size)
    if i is None or n is None or i < 0 or _neg_zero(index) or n < 1 or i >= n:
        return None
    if len(leaf) != 32 or any(len(p) != 32 for p in path):
        return None
    fn, sn, r = i, n - 1, bytes(leaf)
    for p in path:
        if sn == 0:
            return None
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def verify_inclusion_path(leaf: bytes, index: Any, size: Any, path: List[bytes], root: bytes) -> bool:
    computed = root_from_inclusion_path(leaf, index, size, path)
    return computed is not None and computed == bytes(root)


def _subproof(m: int, d: List[bytes], complete: bool) -> List[bytes]:
    n = len(d)
    if not 0 < m <= n:
        raise ValueError("consistency subproof: size out of range")  # outside 1..n the recursion never meets m == n
    if m == n:
        return [] if complete else [tree_hash(d)]
    k = _split_point(n)
    if m <= k:
        return _subproof(m, d[:k], complete) + [tree_hash(d[k:])]
    return _subproof(m - k, d[k:], False) + [tree_hash(d[:k])]


def consistency_path(leaf_hashes: List[bytes], m: Any) -> List[bytes]:
    """Consistency proof between the first `m` leaves and all of `leaf_hashes` (RFC 9162 2.1.4.1)."""
    i = _safe_int(m)
    if i is None or i < 1 or i > len(leaf_hashes):
        raise ValueError("rfc9162: consistency size out of range")
    return _subproof(i, leaf_hashes, True)


def _i32(x: int) -> int:
    """ECMAScript ToInt32 (the reference tests `first & (first - 1)` with a 32-bit bitwise AND)."""
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x >= (1 << 31) else x


def verify_consistency_path(first: Any, second: Any, first_root: bytes, second_root: bytes, path: List[bytes]) -> bool:
    """RFC 9162 2.1.4.2. A proof from an empty tree is rejected."""
    a, b = _safe_int(first), _safe_int(second)
    if a is None or b is None or a < 1 or b < a:
        return False
    if len(first_root) != 32 or len(second_root) != 32 or any(len(p) != 32 for p in path):
        return False
    if a == b:
        return len(path) == 0 and bytes(first_root) == bytes(second_root)
    if len(path) == 0:
        return False
    nodes = [bytes(p) for p in path]
    if (_i32(a) & _i32(a - 1)) == 0:  # first is an exact power of two
        nodes.insert(0, bytes(first_root))
    fn, sn = a - 1, b - 1
    while (fn & 1) == 1:
        fn >>= 1
        sn >>= 1
    fr = sr = nodes[0]
    for c in nodes[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == bytes(first_root) and sr == bytes(second_root)


# ---- deterministic CBOR ---------------------------------------------------------------------------------------------


class CborTag:
    """A CBOR tagged value (major type 6)."""

    def __init__(self, tag: int, value: Any) -> None:
        self.tag = tag
        self.value = value

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, CborTag) and self.tag == other.tag and self.value == other.value

    def __repr__(self) -> str:
        return "CborTag(%r, %r)" % (self.tag, self.value)


# A CBOR map is a dict with int or str keys. A CBOR value is int, str, bytes, bool, None, list, dict or CborTag.


def _is_int(n: Any) -> bool:
    if isinstance(n, bool):
        return False
    if isinstance(n, int):
        return abs(n) <= MAX_SAFE
    return isinstance(n, float) and n == n and n not in (float("inf"), float("-inf")) and n == int(n) and abs(n) <= MAX_SAFE and not _neg_zero(n)


def _well_formed(s: str) -> bool:
    return not any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _head(major: int, arg: int) -> bytes:
    mt = major << 5
    if arg < 24:
        return bytes([mt | arg])
    if arg < 0x100:
        return bytes([mt | 24, arg])
    if arg < 0x10000:
        return bytes([mt | 25]) + struct.pack(">H", arg)
    if arg < 0x100000000:
        return bytes([mt | 26]) + struct.pack(">I", arg)
    return bytes([mt | 27]) + struct.pack(">Q", arg)


def _encode_key(k: Any) -> bytes:
    if isinstance(k, float) and k == 0:
        k = 0  # a JS Map stores the key -0 as +0
    if isinstance(k, (int, float)) and not isinstance(k, bool):
        if not _is_int(k):
            raise TypeError("cbor: bad integer map key")
        k = int(k)
        return _head(0, k) if k >= 0 else _head(1, -1 - k)
    if not isinstance(k, str):
        raise TypeError("cbor: bad map key")
    if not _well_formed(k):
        raise TypeError("cbor: text string contains a lone surrogate")
    b = k.encode("utf-8")
    return _head(3, len(b)) + b


def encode(v: Any) -> bytes:
    """Deterministically encode a CBOR value. Raises TypeError on anything outside the supported profile."""
    if v is None:
        return b"\xf6"
    if v is False:
        return b"\xf4"
    if v is True:
        return b"\xf5"
    if isinstance(v, (int, float)):
        if not _is_int(v):
            raise TypeError("cbor: only safe-integer numbers are supported")
        n = int(v)
        return _head(0, n) if n >= 0 else _head(1, -1 - n)
    if isinstance(v, str):
        if not _well_formed(v):
            raise TypeError("cbor: text string contains a lone surrogate")
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return _head(2, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, dict):
        entries = sorted(((_encode_key(k), encode(val)) for k, val in v.items()), key=lambda e: e[0])
        for i in range(1, len(entries)):
            if entries[i - 1][0] == entries[i][0]:
                raise TypeError("cbor: duplicate map key")
        return _head(5, len(v)) + b"".join(k + val for k, val in entries)
    if isinstance(v, CborTag):
        if not _is_int(v.tag) or v.tag < 0:
            raise TypeError("cbor: bad tag")
        return _head(6, int(v.tag)) + encode(v.value)
    raise TypeError("cbor: unsupported value")


class _Reader:
    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def _byte(self) -> int:
        if self.pos >= len(self.buf):
            raise ValueError("cbor: unexpected end of input")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def _bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ValueError("cbor: unexpected end of input")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def _uint(self, n: int) -> int:
        v = 0
        for _ in range(n):
            v = v * 256 + self._byte()
        if v > MAX_SAFE:
            raise ValueError("cbor: integer out of safe range")
        return v

    def _head(self):
        ib = self._byte()
        major, info = ib >> 5, ib & 0x1F
        if major == 7 and info >= 24:
            raise ValueError("cbor: unsupported simple/float value")
        if info < 24:
            return major, info
        for code, n, floor in ((24, 1, 24), (25, 2, 0x100), (26, 4, 0x10000), (27, 8, 0x100000000)):
            if info == code:
                arg = self._uint(n)
                if arg < floor:
                    raise ValueError("cbor: non-minimal integer")
                return major, arg
        raise ValueError("cbor: unsupported additional information (indefinite/reserved)")

    def value(self) -> Any:
        major, arg = self._head()
        if major == 0:
            return arg
        if major == 1:
            if abs(-1 - arg) > MAX_SAFE:
                raise ValueError("cbor: integer out of safe range")
            return -1 - arg
        if major == 2:
            return self._bytes(arg)
        if major == 3:
            try:
                return self._bytes(arg).decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("The encoded data was not valid for encoding utf-8") from None
        if major == 4:
            return [self.value() for _ in range(arg)]
        if major == 5:
            out: Dict[Any, Any] = {}
            prev: Optional[bytes] = None
            for _ in range(arg):
                start = self.pos
                key = self.value()
                if isinstance(key, bool) or not isinstance(key, (int, str)):
                    raise TypeError("cbor: map key must be int or text")
                kb = self.buf[start:self.pos]
                if prev is not None and prev >= kb:
                    raise ValueError("cbor: map keys not canonically ordered / duplicate")
                prev = kb
                out[key] = self.value()
            return out
        if major == 6:
            return CborTag(arg, self.value())
        if major == 7:
            if arg == 20:
                return False
            if arg == 21:
                return True
            if arg == 22:
                return None
            raise ValueError("cbor: unsupported simple/float value")
        raise ValueError("cbor: unsupported major type")


def decode(data: Any) -> Any:
    """Strictly decode ONE canonical CBOR value; the whole buffer must be consumed."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("cbor: input must be bytes")
    r = _Reader(bytes(data))
    v = r.value()
    if r.pos != len(r.buf):
        raise ValueError("cbor: trailing bytes")
    return v


# ---- COSE + SCITT constants -----------------------------------------------------------------------------------------

COSE_SIGN1_TAG = 18
HDR_ALG = 1
HDR_CONTENT_TYPE = 3
HDR_CWT_CLAIMS = 15
CWT_ISS = 1
CWT_SUB = 2
HDR_VDS = 395
HDR_VDS_PROOFS = 396
VDS_RFC9162_SHA256 = 1
PROOF_TYPE_INCLUSION = -1
DEFAULT_CONTENT_TYPE = "application/pca+json"

_ALG_LABEL = {"EdDSA": -8, "ES256": -7}
_UNSET: Any = object()

_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_HALF_N = _P256_N >> 1


def _alg_for_label(label: int) -> Optional[str]:
    return "EdDSA" if label == -8 else "ES256" if label == -7 else None


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_canonical_es256(sig: bytes) -> bool:
    """A 64-byte IEEE-P1363 signature with 0 < r < n and 0 < s <= n/2 (low-S)."""
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    return 0 < r < _P256_N and 0 < s <= _P256_HALF_N


# ---- signature suites (EdDSA, ES256) --------------------------------------------------------------------------------

def _crypto() -> Any:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise RuntimeError("this needs the 'cryptography' package (pip install 'atlas-pca[fast]')") from None


def _load_der(key: Any, private: bool) -> Any:
    _crypto()
    from cryptography.hazmat.primitives import serialization
    if isinstance(key, (bytes, bytearray)):
        return (serialization.load_der_private_key(bytes(key), None) if private else serialization.load_der_public_key(bytes(key)))
    return key


def _ed_public_raw(key: Any) -> bytes:
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return bytes(key)
    k = _load_der(key, False)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(k, Ed25519PublicKey):
        raise TypeError("not an Ed25519 public key")
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _ec_key(key: Any, private: bool) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec
    k = _load_der(key, private)
    if not isinstance(k, (ec.EllipticCurvePrivateKey if private else ec.EllipticCurvePublicKey)) or not isinstance(k.curve, ec.SECP256R1):
        raise TypeError("not a P-256 key")
    return k


def _sign_bytes(alg: str, key: Any, msg: bytes) -> bytes:
    if alg == "EdDSA":
        if isinstance(key, (bytes, bytearray)) and len(key) == 32:
            return ed25519.sign_secret(bytes(key), msg)
        k = _load_der(key, True)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if not isinstance(k, Ed25519PrivateKey):
            raise TypeError("not an Ed25519 private key")
        return k.sign(msg)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(_ec_key(key, True).sign(msg, ec.ECDSA(hashes.SHA256())))
    if s > _P256_HALF_N:  # low-S: a statement has exactly one valid signature form
        s = _P256_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_bytes(alg: str, key: Any, msg: bytes, sig: bytes, allow_high_s: bool = False) -> bool:
    if alg == "EdDSA":
        return ed25519.verify(_ed_public_raw(key), msg, sig)
    # ECDSA is malleable: a high-S variant would be a second, distinct Merkle leaf for the same statement.
    if not allow_high_s and not _is_canonical_es256(sig):
        return False
    if allow_high_s and len(sig) != 64:
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    pub = _ec_key(key, False)
    try:
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _sig_structure(protected_bytes: bytes, payload: bytes) -> bytes:
    """The COSE_Sign1 Sig_structure (RFC 9052 4.4), external_aad empty."""
    return encode(["Signature1", protected_bytes, b"", payload])


# ---- Signed Statements ----------------------------------------------------------------------------------------------

def sign_statement(payload: Any, alg: str, key: Any, issuer: str, subject: Any = _UNSET, content_type: Optional[str] = None) -> bytes:
    """Sign a PCActn / verdict as a COSE Signed Statement (COSE_Sign1) whose payload is the strict canonical JSON of `payload`."""
    label = _ALG_LABEL.get(alg) if isinstance(alg, str) else None
    prot: Dict[Any, Any] = {HDR_ALG: label, HDR_CONTENT_TYPE: DEFAULT_CONTENT_TYPE if content_type is None else content_type}
    claims: Dict[Any, Any] = {CWT_ISS: issuer}
    if subject is not _UNSET:
        claims[CWT_SUB] = subject
    prot[HDR_CWT_CLAIMS] = claims
    protected_bytes = encode(prot)  # an unsupported alg leaves a None label that no verifier accepts: refuse here
    if label is None:
        raise TypeError("cbor: unsupported value")
    payload_bytes = canonical_bytes_strict(payload)
    sig = _sign_bytes(alg, key, _sig_structure(protected_bytes, payload_bytes))
    return encode(CborTag(COSE_SIGN1_TAG, [protected_bytes, {}, payload_bytes, sig]))


def decode_cose_sign1(data: Any) -> Dict[str, Any]:
    """Decode and structurally validate a COSE_Sign1 (tag 18): protectedBytes, protectedMap, unprotected, payload (None when
    detached), signature. Raises on any deviation."""
    top = decode(data)
    if not isinstance(top, CborTag) or top.tag != COSE_SIGN1_TAG:
        raise TypeError("cose: not a COSE_Sign1 (tag 18)")
    arr = top.value
    if not isinstance(arr, list) or len(arr) != 4:
        raise TypeError("cose: malformed COSE_Sign1 array")
    protected_bytes, unprotected, payload, signature = arr
    if not isinstance(protected_bytes, bytes):
        raise TypeError("cose: protected must be a bstr")
    if not isinstance(unprotected, dict):
        raise TypeError("cose: unprotected must be a map")
    if not isinstance(payload, bytes) and payload is not None:
        raise TypeError("cose: payload must be a bstr or nil")
    if not isinstance(signature, bytes):
        raise TypeError("cose: signature must be a bstr")
    if len(protected_bytes) == 0:
        pm: Dict[Any, Any] = {}
    else:
        pm = decode(protected_bytes)
        if not isinstance(pm, dict):
            raise TypeError("cbor: expected a map")
    return {"protectedBytes": protected_bytes, "protectedMap": pm, "unprotected": unprotected, "payload": payload, "signature": signature}


def _alg_of(protected_map: Dict[Any, Any]) -> str:
    if HDR_ALG not in protected_map:
        raise TypeError("cose: missing alg header")
    label = protected_map[HDR_ALG]
    alg = _alg_for_label(label) if _is_num(label) else None
    if alg is None:
        raise TypeError("cose: unsupported alg")
    return alg


def check_statement(statement: Any, public_key: Any, allow_high_s: Any = False) -> Dict[str, Any]:
    """Verify a Signed Statement and say WHY it failed (malformed / missing alg header / unsupported alg / detached payload /
    non-canonical signature (high-S) / bad signature). Never raises."""
    try:
        s = decode_cose_sign1(statement)
    except Exception as e:  # noqa: BLE001 - every malformed input is a refusal
        return {"ok": False, "reason": "malformed: %s" % e}
    if s["payload"] is None:
        return {"ok": False, "reason": "detached payload"}
    try:
        alg = _alg_of(s["protectedMap"])
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "missing alg header" if "missing" in str(e) else "unsupported alg"}
    try:
        msg = _sig_structure(s["protectedBytes"], s["payload"])
        if _verify_bytes(alg, public_key, msg, s["signature"], allow_high_s is True):
            return {"ok": True}
        if alg == "ES256" and not _is_canonical_es256(s["signature"]) and _verify_bytes(alg, public_key, msg, s["signature"], True):
            return {"ok": False, "reason": "non-canonical signature (high-S)"}
        return {"ok": False, "reason": "bad signature"}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "bad signature"}


def verify_statement(statement: Any, public_key: Any, allow_high_s: Any = False) -> bool:
    return check_statement(statement, public_key, allow_high_s)["ok"]


def statement_payload(statement: Any) -> bytes:
    """The canonical payload bytes carried by a Signed Statement. Raises on a malformed or detached statement."""
    payload = decode_cose_sign1(statement)["payload"]
    if payload is None:
        raise TypeError("cose: statement payload is detached")
    return payload


def statement_leaf(statement: bytes) -> str:
    """The b64u leaf a statement occupies in the transparency log."""
    return b64u(bytes(statement))


# ---- inclusion proof codec (RFC 9162) -------------------------------------------------------------------------------

def sibling_sides(index: Any, size: Any) -> List[str]:
    """Sibling sides (leaf -> root) for `index` in a tree of `size` leaves (RFC 6962 split)."""
    out: List[str] = []
    idx, n = index, size
    while n > 1:
        k = _split_point(n)
        if idx < k:
            out.append("R")
            n = k
        else:
            out.append("L")
            idx -= k
            n -= k
    out.reverse()
    return out


def encode_inclusion_proof(proof: Any) -> bytes:
    sibs: List[Any] = []
    for step in proof["path"]:
        h = decode_b64u_strict(step["hash"], 32)
        if not h:
            raise TypeError("scitt: proof step hash is not a 32-byte b64u hash")
        sibs.append(h)
    return encode([proof["size"], proof["index"], sibs])


def decode_inclusion_proof(data: Any) -> Dict[str, Any]:
    """Decode an RFC 9162 inclusion proof into {index, size, path: [{side, hash}]} (sides re-derived)."""
    v = decode(data)
    if not isinstance(v, list) or len(v) != 3:
        raise TypeError("scitt: malformed inclusion proof")
    size, index, sibs = v
    if not _is_num(size) or not _is_num(index):
        raise TypeError("scitt: proof size/index must be integers")
    if _safe_int(size) is None or _safe_int(index) is None or size < 1 or index < 0 or index >= size:
        raise ValueError("scitt: proof size/index out of range")
    if not isinstance(sibs, list):
        raise TypeError("scitt: inclusion path must be an array")
    sides = sibling_sides(index, size)
    if len(sibs) != len(sides):
        raise ValueError("scitt: inclusion path length does not match (index,size)")
    path = []
    for h, side in zip(sibs, sides):
        if not isinstance(h, bytes) or len(h) != 32:
            raise TypeError("scitt: inclusion path entry must be a 32-byte bstr")
        path.append({"side": side, "hash": b64u(h)})
    return {"index": index, "size": size, "path": path}


# ---- COSE Receipts (RFC 9942) ---------------------------------------------------------------------------------------

def build_receipt(root: Any, proof: Any, alg: str, key: Any, issuer: Any = _UNSET) -> bytes:
    """A signed COSE Receipt for `proof` against ledger root `root` (b64u, 32 bytes); the payload is detached (nil)."""
    root_bytes = decode_b64u_strict(root, 32)
    if not root_bytes:
        raise TypeError("scitt: tree root is not a 32-byte b64u hash")
    label = _ALG_LABEL.get(alg) if isinstance(alg, str) else None
    prot: Dict[Any, Any] = {HDR_ALG: label, HDR_VDS: VDS_RFC9162_SHA256}
    if issuer is not _UNSET:
        prot[HDR_CWT_CLAIMS] = {CWT_ISS: issuer}
    protected_bytes = encode(prot)
    if label is None:
        raise TypeError("cbor: unsupported value")
    unprotected = {HDR_VDS_PROOFS: {PROOF_TYPE_INCLUSION: [encode_inclusion_proof(proof)]}}
    sig = _sign_bytes(alg, key, _sig_structure(protected_bytes, root_bytes))
    return encode(CborTag(COSE_SIGN1_TAG, [protected_bytes, unprotected, None, sig]))


def _proof_hashes(proof: Any) -> List[bytes]:
    out = []
    for step in proof["path"]:
        h = decode_b64u_strict(step["hash"], 32)
        if not h:
            raise TypeError("scitt: proof step hash is not a 32-byte b64u hash")
        out.append(h)
    return out


def _decode_receipt(receipt: Any) -> Dict[str, Any]:
    cose = decode_cose_sign1(receipt)
    vds = cose["protectedMap"].get(HDR_VDS)
    if not (_is_num(vds) and vds == VDS_RFC9162_SHA256):
        raise TypeError("scitt: receipt is not RFC9162_SHA256")
    if cose["payload"] is not None and len(cose["payload"]) != 32:
        raise TypeError("scitt: receipt payload (root) must be 32 bytes")
    proofs = cose["unprotected"].get(HDR_VDS_PROOFS)
    if not isinstance(proofs, dict):
        raise TypeError("scitt: missing verifiable-data-structure-proofs")
    inclusion = proofs.get(PROOF_TYPE_INCLUSION)
    if not isinstance(inclusion, list) or len(inclusion) < 1:
        raise TypeError("scitt: missing inclusion proof")
    first = inclusion[0]
    if not isinstance(first, bytes):
        raise TypeError("scitt: inclusion proof must be a bstr")
    return {"cose": cose, "proof": decode_inclusion_proof(first)}


_ABSENT: Any = object()


def verify_receipt(receipt: Any, statement: Any, tree_root: Optional[str] = None, verification_key: Any = _ABSENT,
                   statement_key: Any = _ABSENT, allow_high_s: Any = False) -> bool:
    """Verify a COSE Receipt for a Signed Statement; fail closed (never raises). At least one anchor (`tree_root` and/or
    `verification_key`) is required; the inclusion proof must bind the EXACT statement bytes to the receipt's root; a given
    `statement_key` also verifies the statement's own signature. A key that is passed is always checked: None or an empty
    key is refused, never skipped (only an omitted key means "no key")."""
    try:
        if tree_root is None and verification_key is _ABSENT:
            return False  # no anchor
        dec = _decode_receipt(receipt)
        proof, cose = dec["proof"], dec["cose"]
        root = root_from_inclusion_path(leaf_hash(statement), proof["index"], proof["size"], _proof_hashes(proof))
        if root is None:
            return False
        if cose["payload"] is not None and b64u(cose["payload"]) != b64u(root):
            return False
        high = allow_high_s is True
        if verification_key is not _ABSENT:
            alg = _alg_of(cose["protectedMap"])
            if not _verify_bytes(alg, verification_key, _sig_structure(cose["protectedBytes"], root), cose["signature"], high):
                return False
        if tree_root is not None and tree_root != b64u(root):
            return False
        if statement_key is not _ABSENT and not verify_statement(statement, statement_key, high):
            return False
        return True
    except Exception:  # noqa: BLE001 - fail closed
        return False


def verify_consistency_proof(proof: Any, old_root: Any, new_root: Any) -> bool:
    """Verify an RFC 9942 / RFC 9162 consistency proof `[old size, new size, [+ bstr]]` between two pinned roots (b64u)."""
    try:
        v = decode(proof)
        if not isinstance(v, list) or len(v) != 3:
            return False
        old_size, new_size, path = v
        if not _is_num(old_size) or not _is_num(new_size) or not isinstance(path, list):
            return False
        if not all(isinstance(h, bytes) for h in path):
            return False
        r1, r2 = decode_b64u_strict(old_root, 32), decode_b64u_strict(new_root, 32)
        if not r1 or not r2:
            return False
        return verify_consistency_path(old_size, new_size, r1, r2, path)
    except Exception:  # noqa: BLE001
        return False
