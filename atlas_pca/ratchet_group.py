"""Prime-order group layer of the homomorphic risk accumulator: ristretto255 (RFC 9496) over the Edwards arithmetic of
atlas_pca.ed25519, Pedersen generators G and H, scalar helpers and the Fiat-Shamir transcript hash.

Mirrors the TypeScript reference (@atlasauth/pca-ratchet). Pure Python and NOT constant time: the accumulator is a
verifier-side check, and provers are expected to run where timing is not observable."""
"""Prime-order group layer of the homomorphic risk accumulator: ristretto255 (RFC 9496) over libsodium (via pysodium), Pedersen
generators G and H, scalar helpers and the Fiat-Shamir transcript hash.

Mirrors the TypeScript reference (@atlasauth/pca-ratchet). A Point is its canonical 32-byte ristretto255 encoding, so equality is
byte equality. All group and scalar arithmetic is libsodium's (constant time); scalars cross the API as Python ints, which are
not constant time, so a caller that must hide a scalar from a local timing observer should not hold it in this layer."""
import hashlib
from typing import List

from ._sodium_path import prefer_bundled
from .pca import b64u, decode_b64u_strict

with prefer_bundled():  # the libsodium shipped in the wheel when there is one, else the system's
    import pysodium as _s

L = 2**252 + 27742317777372353535851937790883648493
Point = bytes

ZERO: Point = bytes(32)
G: Point = _s.crypto_scalarmult_ristretto255_base((1).to_bytes(32, "little"))


def _decode_ristretto(s: bytes) -> Point:
    if len(s) != 32 or s[31] & 0x80 or not _s.crypto_core_ristretto255_is_valid_point(bytes(s)):  # RFC 9496: bit 255 must be clear (not every libsodium checks it)
        raise ValueError("ristretto255: invalid encoding")
    return bytes(s)


def hash_to_curve(b: bytes) -> Point:
    """RFC 9496 one-way map from 64 uniform bytes."""
    if len(b) != 64:
        raise ValueError("hash_to_curve: need 64 bytes")
    return _s.crypto_core_ristretto255_from_hash(bytes(b))


H: Point = hash_to_curve(hashlib.sha512(b"atlas-pca-ratchet/pedersen-generator-H/v1").digest())


def mod(x: int) -> int:
    return x % L


def _sc(k: int) -> bytes:
    return (k % L).to_bytes(32, "little")


def scalar_add(a: int, b: int) -> int:
    return int.from_bytes(_s.crypto_core_ristretto255_scalar_add(_sc(a), _sc(b)), "little")


def scalar_sub(a: int, b: int) -> int:
    return int.from_bytes(_s.crypto_core_ristretto255_scalar_sub(_sc(a), _sc(b)), "little")


def scalar_mul(a: int, b: int) -> int:
    return int.from_bytes(_s.crypto_core_ristretto255_scalar_mul(_sc(a), _sc(b)), "little")


def mul(pt: Point, k: int) -> Point:
    # libsodium refuses an identity result (zero scalar or identity point); the reference returns the identity
    if k % L == 0 or pt == ZERO:
        return ZERO
    return _s.crypto_scalarmult_ristretto255(_sc(k), pt)


def add(a: Point, b: Point) -> Point:
    return _s.crypto_core_ristretto255_add(a, b)


def sub(a: Point, b: Point) -> Point:
    return _s.crypto_core_ristretto255_sub(a, b)


def equals(a: Point, b: Point) -> bool:
    """Ristretto equality: encodings are canonical, so bytes compare."""
    return a == b


def allow_insecure_prover(allow: bool = True) -> None:
    """Kept for callers written against the pure-Python backend; libsodium is constant time, so nothing is gated."""


def require_prover() -> None:
    """No-op: the libsodium backend needs no opt-in."""


def rand_scalar() -> int:
    while True:
        s = int.from_bytes(_s.crypto_core_ristretto255_scalar_random(), "little")
        if s != 0:
            return s


def number_to_bytes_le(n: int, length: int) -> bytes:
    if n < 0:
        raise ValueError("number_to_bytes_le: negative")
    return n.to_bytes(length, "little")  # OverflowError when it does not fit


def bytes_to_number_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def to_raw_bytes(pt: Point) -> bytes:
    return pt


def encode_point(pt: Point) -> str:
    return b64u(pt)


def decode_point(s: str) -> Point:
    raw = decode_b64u_strict(s, 32)
    if raw is None:
        raise ValueError("decode_point: not a canonical 32-byte base64url string")
    return _decode_ristretto(raw)


def encode_scalar(k: int) -> str:
    return b64u(number_to_bytes_le(k % L, 32))


def decode_scalar(s: str) -> int:
    """Strict: canonical base64url, exactly 32 bytes, value < L (a reduced scalar would make every proof malleable)."""
    raw = decode_b64u_strict(s, 32)
    if raw is None:
        raise ValueError("decode_scalar: not a canonical 32-byte base64url string")
    v = int.from_bytes(raw, "little")
    if v >= L:
        raise ValueError("decode_scalar: non-canonical scalar (>= L)")
    return v


def hash_to_scalar(parts: List[bytes]) -> int:
    """Length-prefixed (4-byte big-endian) transcript, SHA-512, reduced mod L."""
    buf = b"".join(len(p).to_bytes(4, "big") + bytes(p) for p in parts)
    return int.from_bytes(hashlib.sha512(buf).digest(), "little") % L


def utf8(s: str) -> bytes:
    return s.encode("utf-8")
