"""RFC 9497 OPRF / VOPRF / POPRF on ristretto255-SHA512 plus the PCA private-revocation and private-rate-limit layer
(the TypeScript reference, @atlasauth/pca-oprf).

Group arithmetic is libsodium's ristretto255 (atlas_pca.ratchet_group, via pysodium; needs the `ristretto` extra and the system
libsodium). Scalars cross the API as Python ints, which are not constant time.

Native-stricter: the reference silently routes any mode other than 'oprf' through the verifiable path in blind_evaluate and
skips proof verification in finalize for anything but 'voprf'; here an unknown mode (or 'poprf' on the non-POPRF entry
points) is refused.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Callable, Dict, Optional, Set, Tuple

from . import ratchet_group as _g
from .ratchet_group import Point, _decode_ristretto

ORDER = _g.L
ELEMENT_BYTES = 32
SCALAR_BYTES = 32
OUTPUT_BYTES = 64
SUITE_ID = "ristretto255-SHA512"
MODE = {"oprf": 0x00, "voprf": 0x01, "poprf": 0x02}
_MAX_FRAMED = 0xFFFF
_BASE = _g.G


# ---- plumbing

def _bytes(v: Any, what: str, max_len: Optional[int] = None) -> bytes:
    if not isinstance(v, (bytes, bytearray)):
        raise TypeError("%s: expected bytes" % what)
    if max_len is not None and len(v) > max_len:
        raise ValueError("%s: %d bytes exceeds the %d-byte limit (RFC 9497 2-byte length framing)" % (what, len(v), max_len))
    return bytes(v)


def _i2osp(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")  # OverflowError when it does not fit


def _context(mode: Any) -> bytes:
    if mode not in MODE:
        raise ValueError("unknown OPRF mode %r" % (mode,))
    return b"OPRFV1-" + _i2osp(MODE[mode], 1) + b"-" + SUITE_ID.encode()


def _require_server_modes(mode: Any) -> str:
    if mode not in ("oprf", "voprf"):
        raise ValueError("mode must be 'oprf' or 'voprf', got %r" % (mode,))
    return mode


def _mul(pt: Point, k: int) -> Point:
    # the reference's multiply() rejects 0 and anything >= the group order
    if not 1 <= k < ORDER:
        raise ValueError("expected valid scalar: 1 <= n < %d, got %d" % (ORDER, k))
    return _g.mul(pt, k)


def _mul_unsafe(pt: Point, k: int) -> Point:
    if not 0 <= k < ORDER:
        raise ValueError("expected valid scalar: 0 <= n < %d, got %d" % (ORDER, k))
    return _g.mul(pt, k)


def _is_identity(p: Point) -> bool:
    return _g.equals(p, _g.ZERO)


def _base_mult(k: int) -> Point:
    return _mul(_BASE, k % ORDER)


def _expand_message_xmd(msg: bytes, dst: bytes) -> bytes:
    """RFC 9380 expand_message_xmd with SHA-512 for the 64-byte output every suite step needs (a single block)."""
    if len(dst) > 255:
        dst = hashlib.sha512(b"H2C-OVERSIZE-DST-" + dst).digest()
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha512(bytes(128) + msg + (64).to_bytes(2, "big") + b"\x00" + dst_prime).digest()
    return hashlib.sha512(b0 + b"\x01" + dst_prime).digest()


def _hash_to_scalar_dst(data: bytes, dst: bytes) -> int:
    return int.from_bytes(_expand_message_xmd(data, dst), "little") % ORDER


def _hash_to_scalar(data: bytes, mode: str) -> int:
    return _hash_to_scalar_dst(data, b"HashToScalar-" + _context(mode))


def _scalar_invert(s: int) -> int:
    v = s % ORDER
    if v == 0:
        raise ValueError("scalarInvert: inverse of zero")
    return pow(v, ORDER - 2, ORDER)


# ---- (de)serialisation

def serialize_element(p: Point) -> bytes:
    return _g.to_raw_bytes(p)


def deserialize_element(b: Any) -> Point:
    raw = _bytes(b, "DeserializeElement")
    p = _decode_ristretto(raw)
    if _is_identity(p):
        raise ValueError("DeserializeElement: identity element is not a valid input")
    return p


def serialize_scalar(s: int) -> bytes:
    return (s % ORDER).to_bytes(SCALAR_BYTES, "little")


def deserialize_scalar(b: Any) -> int:
    raw = _bytes(b, "DeserializeScalar")
    if len(raw) != SCALAR_BYTES:
        raise ValueError("DeserializeScalar: expected %d bytes, got %d" % (SCALAR_BYTES, len(raw)))
    n = int.from_bytes(raw, "little")
    if n >= ORDER:
        raise ValueError("DeserializeScalar: non-canonical scalar (value >= group order)")
    return n


def hash_to_group(data: Any, mode: str) -> Point:
    msg = _bytes(data, "HashToGroup")
    return _g.hash_to_curve(_expand_message_xmd(msg, b"HashToGroup-" + _context(mode)))


def random_scalar() -> int:
    for _ in range(8):
        s = _g.rand_scalar()
        if s != 0:
            return s
    raise RuntimeError("randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue")


# ---- keys (server-secret: gated)

def derive_key_pair(seed: Any, info: Any, mode: str) -> Dict[str, bytes]:
    _g.require_prover()
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != SCALAR_BYTES:
        raise ValueError("DeriveKeyPair: seed must be exactly %d bytes" % SCALAR_BYTES)
    info = _bytes(info, "DeriveKeyPair(info)")
    dst = b"DeriveKeyPair" + _context(mode)
    derive_input = bytes(seed) + _i2osp(len(info), 2) + info
    for counter in range(256):
        sk = _hash_to_scalar_dst(derive_input + bytes([counter]), dst)
        if sk != 0:
            return {"secret_key": serialize_scalar(sk), "public_key": serialize_element(_base_mult(sk))}
    raise RuntimeError("DeriveKeyPair: failed to derive a non-zero key after 256 attempts")


def random_key_pair() -> Dict[str, bytes]:
    _g.require_prover()
    sk = random_scalar()
    return {"secret_key": serialize_scalar(sk), "public_key": serialize_element(_base_mult(sk))}


def public_key_for(secret_key: Any) -> bytes:
    _g.require_prover()
    return serialize_element(_base_mult(deserialize_scalar(secret_key)))


# ---- DLEQ proofs (RFC 9497 section 2.2.1)

def _composites_seed(b_ser: bytes, mode: str) -> bytes:
    seed_dst = b"Seed-" + _context(mode)
    return hashlib.sha512(_i2osp(len(b_ser), 2) + b_ser + _i2osp(len(seed_dst), 2) + seed_dst).digest()


def _composite_coefficient(seed: bytes, index: int, c_ser: bytes, d_ser: bytes, mode: str) -> int:
    transcript = (
        _i2osp(len(seed), 2) + seed + _i2osp(index, 2) + _i2osp(len(c_ser), 2) + c_ser
        + _i2osp(len(d_ser), 2) + d_ser + b"Composite"
    )
    return _hash_to_scalar(transcript, mode)


def _composites(b: Point, c: Point, d: Point, mode: str) -> Tuple[Point, Point]:
    seed = _composites_seed(serialize_element(b), mode)
    coeff = _composite_coefficient(seed, 0, serialize_element(c), serialize_element(d), mode)
    return _mul_unsafe(c, coeff), _mul_unsafe(d, coeff)


def _challenge(b: Point, m: Point, z: Point, t2: Point, t3: Point, mode: str) -> int:
    parts = b""
    for p in (b, m, z, t2, t3):
        ser = serialize_element(p)
        parts += _i2osp(len(ser), 2) + ser
    return _hash_to_scalar(parts + b"Challenge", mode)


def _generate_proof(k: int, a: Point, b: Point, c: Point, d: Point, mode: str, fixed_randomness: Any = None) -> bytes:
    m, _ = _composites(b, c, d, mode)
    z = _mul(m, k % ORDER)
    r = random_scalar() if fixed_randomness is None else deserialize_scalar(fixed_randomness)
    t2 = _mul(a, r)
    t3 = _mul(m, r)
    cc = _challenge(b, m, z, t2, t3, mode)
    s = (r - cc * k) % ORDER
    return serialize_scalar(cc) + serialize_scalar(s)


def _verify_proof(a: Point, b: Point, c: Point, d: Point, proof: Any, mode: str) -> bool:
    proof = _bytes(proof, "proof")
    if len(proof) != 2 * SCALAR_BYTES:
        return False
    cc = deserialize_scalar(proof[:SCALAR_BYTES])
    s = deserialize_scalar(proof[SCALAR_BYTES:])
    m, z = _composites(b, c, d, mode)
    t2 = _g.add(_mul_unsafe(a, s), _mul_unsafe(b, cc))
    t3 = _g.add(_mul_unsafe(m, s), _mul_unsafe(z, cc))
    expected = _challenge(b, m, z, t2, t3, mode)
    return (expected - cc) % ORDER == 0


def _finalize_hash(data: bytes, issued: bytes) -> bytes:
    return hashlib.sha512(_i2osp(len(data), 2) + data + _i2osp(len(issued), 2) + issued + b"Finalize").digest()


def _finalize_hash_poprf(data: bytes, info: bytes, issued: bytes) -> bytes:
    return hashlib.sha512(
        _i2osp(len(data), 2) + data + _i2osp(len(info), 2) + info + _i2osp(len(issued), 2) + issued + b"Finalize"
    ).digest()


# ---- OPRF / VOPRF

def blind(data: Any, mode: str = "oprf", fixed_blind: Any = None) -> Dict[str, bytes]:
    """Client step 1. The blind is the client's secret; pure Python is not constant time, so keep this off shared hosts' hot paths."""
    data = _bytes(data, "Blind(input)", _MAX_FRAMED)
    r = random_scalar() if fixed_blind is None else deserialize_scalar(fixed_blind)
    element = hash_to_group(data, mode)
    if _is_identity(element):
        raise ValueError("Blind: input maps to identity")
    return {"blind": serialize_scalar(r), "blinded_element": serialize_element(_mul(element, r))}


def blind_evaluate(
    secret_key: Any, blinded_element: Any, mode: str = "oprf", public_key: Any = None, fixed_proof_randomness: Any = None
) -> Dict[str, bytes]:
    _g.require_prover()
    _require_server_modes(mode)
    sk = deserialize_scalar(secret_key)
    r = deserialize_element(blinded_element)
    evaluated = _mul(r, sk)
    if mode == "oprf":
        return {"evaluated_element": serialize_element(evaluated)}
    pk = _base_mult(sk) if public_key is None else deserialize_element(public_key)
    proof = _generate_proof(sk, _BASE, pk, r, evaluated, "voprf", fixed_proof_randomness)
    return {"evaluated_element": serialize_element(evaluated), "proof": proof}


def finalize(
    data: Any,
    blind_scalar: Any,
    evaluated_element: Any,
    mode: str = "oprf",
    proof: Any = None,
    public_key: Any = None,
    blinded_element: Any = None,
) -> bytes:
    data = _bytes(data, "Finalize(input)", _MAX_FRAMED)
    _require_server_modes(mode)
    r = deserialize_scalar(blind_scalar)
    evaluated = deserialize_element(evaluated_element)
    if mode == "voprf":
        if proof is None or public_key is None or blinded_element is None:
            raise ValueError("Finalize(voprf): proof, publicKey and blindedElement are required")
        pk = deserialize_element(public_key)
        blinded = deserialize_element(blinded_element)
        if not _verify_proof(_BASE, pk, blinded, evaluated, proof, "voprf"):
            raise ValueError("Finalize(voprf): DLEQ proof verification failed")
    n = _mul(evaluated, _scalar_invert(r))
    return _finalize_hash(data, serialize_element(n))


def evaluate(secret_key: Any, data: Any, mode: str = "oprf") -> bytes:
    _g.require_prover()
    data = _bytes(data, "Evaluate(input)", _MAX_FRAMED)
    _require_server_modes(mode)
    sk = deserialize_scalar(secret_key)
    element = hash_to_group(data, mode)
    if _is_identity(element):
        raise ValueError("Evaluate: input maps to identity")
    return _finalize_hash(data, serialize_element(_mul(element, sk)))


# ---- POPRF (the public input `info` is bound into the evaluation)

def _poprf_info_scalar(info: Any) -> int:
    info = _bytes(info, "info", _MAX_FRAMED)
    return _hash_to_scalar(b"Info" + _i2osp(len(info), 2) + info, "poprf")


def blind_poprf(data: Any, info: Any, public_key: Any, fixed_blind: Any = None) -> Dict[str, bytes]:
    data = _bytes(data, "Blind(input)", _MAX_FRAMED)
    m = _poprf_info_scalar(info)
    tweaked = _g.add(_base_mult(m), deserialize_element(public_key))
    if _is_identity(tweaked):
        raise ValueError("Blind(poprf): tweaked key is identity")
    base = blind(data, "poprf", fixed_blind)
    return dict(base, tweaked_key=serialize_element(tweaked))


def blind_evaluate_poprf(secret_key: Any, blinded_element: Any, info: Any, fixed_proof_randomness: Any = None) -> Dict[str, bytes]:
    _g.require_prover()
    sk = deserialize_scalar(secret_key)
    t = (sk + _poprf_info_scalar(info)) % ORDER
    if t == 0:
        raise ValueError("BlindEvaluate(poprf): inverse of zero (bad info/key)")
    blinded = deserialize_element(blinded_element)
    evaluated = _mul(blinded, _scalar_invert(t))
    tweaked_key = _base_mult(t)
    proof = _generate_proof(t, _BASE, tweaked_key, evaluated, blinded, "poprf", fixed_proof_randomness)
    return {"evaluated_element": serialize_element(evaluated), "proof": proof}


def finalize_poprf(
    data: Any, blind_scalar: Any, evaluated_element: Any, info: Any, proof: Any, blinded_element: Any, tweaked_key: Any
) -> bytes:
    data = _bytes(data, "Finalize(input)", _MAX_FRAMED)
    info = _bytes(info, "info", _MAX_FRAMED)
    r = deserialize_scalar(blind_scalar)
    evaluated = deserialize_element(evaluated_element)
    blinded = deserialize_element(blinded_element)
    tweaked = deserialize_element(tweaked_key)
    if not _verify_proof(_BASE, tweaked, evaluated, blinded, proof, "poprf"):
        raise ValueError("Finalize(poprf): DLEQ proof verification failed")
    n = _mul(evaluated, _scalar_invert(r))
    return _finalize_hash_poprf(data, info, serialize_element(n))


def evaluate_poprf(secret_key: Any, data: Any, info: Any) -> bytes:
    _g.require_prover()
    data = _bytes(data, "Evaluate(input)", _MAX_FRAMED)
    sk = deserialize_scalar(secret_key)
    t = (sk + _poprf_info_scalar(info)) % ORDER
    if t == 0:
        raise ValueError("Evaluate(poprf): inverse of zero (bad info/key)")
    element = hash_to_group(data, "poprf")
    if _is_identity(element):
        raise ValueError("Evaluate(poprf): input maps to identity")
    return _finalize_hash_poprf(data, _bytes(info, "info"), serialize_element(_mul(element, _scalar_invert(t))))


def to_hex(b: Any) -> str:
    return _bytes(b, "toHex").hex()


def bytes_equal(a: Any, b: Any) -> bool:
    a, b = _bytes(a, "bytesEqual"), _bytes(b, "bytesEqual")
    return len(a) == len(b) and hmac.compare_digest(a, b)


# ---- PCA layer: private revocation (does my capability id appear in the revoked set, without telling the service which id?)

def _encode_strict(s: Any, what: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("%s must be a string" % what)
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("%s contains an unpaired surrogate (ill-formed UTF-16)" % what) from None


def build_revocation_set(secret_key: Any, revoked_cap_ids: Any, mode: str = "oprf") -> Dict[str, Any]:
    """{"outputs": set of hex PRF outputs, "mode", "public_key" (voprf only)}."""
    _require_server_modes(mode)
    outputs: Set[str] = set()
    for cap_id in revoked_cap_ids:
        outputs.add(to_hex(evaluate(secret_key, _encode_strict(cap_id, "capability id"), mode)))
    out: Dict[str, Any] = {"outputs": outputs, "mode": mode}
    if mode == "voprf":
        out["public_key"] = public_key_for(secret_key)
    return out


def make_revocation_evaluator(secret_key: Any, mode: str = "oprf") -> Callable[[bytes], Dict[str, bytes]]:
    _require_server_modes(mode)
    public_key = public_key_for(secret_key) if mode == "voprf" else None
    return lambda blinded: blind_evaluate(secret_key, blinded, mode, public_key)


def is_revoked_private(cap_id: Any, blind_eval: Callable[[bytes], Dict[str, bytes]], revoked_set: Dict[str, Any]) -> bool:
    data = _encode_strict(cap_id, "capability id")
    mode = revoked_set["mode"]
    b = blind(data, mode)
    res = blind_eval(b["blinded_element"])
    if mode == "voprf":
        pk = revoked_set.get("public_key")
        if res.get("proof") is None or pk is None:
            raise ValueError("isRevokedPrivate(voprf): missing DLEQ proof or service public key")
        out = finalize(data, b["blind"], res["evaluated_element"], "voprf", res["proof"], pk, b["blinded_element"])
    else:
        out = finalize(data, b["blind"], res["evaluated_element"], "oprf")
    return to_hex(out) in revoked_set["outputs"]


# ---- PCA layer: private rate limiting (a per-window POPRF token the service cannot link to the identifier)

def rate_token(secret_key: Any, identifier: Any, window: Any) -> bytes:
    return evaluate_poprf(secret_key, _encode_strict(identifier, "identifier"), _encode_strict(window, "window"))


def rate_token_hex(secret_key: Any, identifier: Any, window: Any) -> str:
    return to_hex(rate_token(secret_key, identifier, window))


def make_rate_evaluator(secret_key: Any) -> Callable[[bytes, str], Dict[str, bytes]]:
    return lambda blinded, window: blind_evaluate_poprf(secret_key, blinded, _encode_strict(window, "window"))


def private_rate_token(identifier: Any, window: Any, blind_eval: Callable[[bytes, str], Dict[str, bytes]], public_key: Any) -> bytes:
    data = _encode_strict(identifier, "identifier")
    info = _encode_strict(window, "window")
    b = blind_poprf(data, info, public_key)
    res = blind_eval(b["blinded_element"], window)
    if res.get("proof") is None:
        raise ValueError("privateRateToken: POPRF blind-evaluation did not return a DLEQ proof")
    return finalize_poprf(data, b["blind"], res["evaluated_element"], info, res["proof"], b["blinded_element"], b["tweaked_key"])


class RateWindowCounter:
    def __init__(self, limit: Any) -> None:
        ok = (isinstance(limit, int) and not isinstance(limit, bool)) or (isinstance(limit, float) and limit == limit and limit == int(limit))
        if not ok or limit < 1:
            raise TypeError("RateWindowCounter: limit must be a positive integer")
        self._limit = limit
        self._counts: Dict[str, int] = {}

    def hit(self, token: bytes) -> Dict[str, Any]:
        key = to_hex(token)
        count = self._counts.get(key, 0) + 1
        self._counts[key] = count
        return {"count": count, "allowed": count <= self._limit}

    def count(self, token: bytes) -> int:
        return self._counts.get(to_hex(token), 0)

    def reset(self) -> None:
        self._counts.clear()
