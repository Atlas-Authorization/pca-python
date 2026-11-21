"""A small prime-order group for the base oblivious transfer: Ed25519 (twisted Edwards, q = 2^255 - 19) in its prime-order subgroup (order L).
The group law (add, subtract, scalar multiplication, subgroup test) is libsodium's Ed25519 core, called through the handle pysodium loads (as in
frost) on the compressed encoding; nothing of it is written out here. What remains in Python ints is only the public coordinate codec (affine
normalisation, RFC 8032 x-recovery) and the on-curve predicate, which touch no secret. Every point received across the OT trust boundary is
validated (on curve, non-identity, [L]P = O)."""

from __future__ import annotations

import ctypes
import hashlib
from dataclasses import dataclass
from typing import Callable, Tuple

from . import ed25519 as _ed
from .frost import _sodium

Q = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, Q - 2, Q)) % Q
_SQRT_M1 = pow(2, (Q - 1) >> 2, Q)
TAG_SCHNORR = b"atlas-pca-mpc/schnorr-dlog"


class PointValidationError(Exception):
    """A received point fails on-curve / subgroup / identity validation."""


@dataclass
class Point:
    """A curve point in extended coordinates (X:Y:Z:T): x = X/Z, y = Y/Z, T = XY/Z."""

    x: int
    y: int
    z: int
    t: int


@dataclass
class SchnorrProof:
    u: Point
    z: int


def _mod_q(v: int) -> int:
    return v % Q


def _pow_q(b: int, e: int) -> int:
    return pow(b % Q, e, Q)


def _inv_q(a: int) -> int:
    return _pow_q(a, Q - 2)


def _le32(s: int) -> bytes:
    return (s & ((1 << 256) - 1)).to_bytes(32, "little")


class Ec:
    Q = Q
    L = L
    D = _D
    SQRT_M1 = _SQRT_M1
    Point = Point
    SchnorrProof = SchnorrProof
    PointValidationError = PointValidationError
    TAG_SCHNORR = TAG_SCHNORR

    @staticmethod
    def from_affine(x: int, y: int) -> Point:
        x = _mod_q(x)
        y = _mod_q(y)
        return Point(x, y, 1, _mod_q(x * y))

    @staticmethod
    def le32(s: int) -> bytes:
        return _le32(s)

    @staticmethod
    def _binary(sub: bool, p1: Point, p2: Point) -> Point:
        r = ctypes.create_string_buffer(32)
        a = Ec.compress_point(p1)
        b = Ec.compress_point(p2)
        fn = _sodium().crypto_core_ed25519_sub if sub else _sodium().crypto_core_ed25519_add
        if fn(r, a, b) != 0:
            raise PointValidationError("point is not on the curve")
        return Ec.decompress_point(r.raw)

    @staticmethod
    def add_points(p1: Point, p2: Point) -> Point:
        """Public group addition P + Q (complete on the subgroup)."""
        return Ec._binary(False, p1, p2)

    @staticmethod
    def sub(p1: Point, p2: Point) -> Point:
        return Ec._binary(True, p1, p2)

    @staticmethod
    def dbl(p: Point) -> Point:
        return Ec.add_points(p, p)

    @staticmethod
    def neg(p: Point) -> Point:
        return Ec.sub(IDENTITY, p)

    @staticmethod
    def mul(k: int, p: Point) -> Point:
        """[k]P with k reduced mod L (k = 0 or P = identity is the identity). P must lie in the prime-order subgroup (libsodium refuses torsion)."""
        s = k % L
        if s == 0 or Ec.identity(p):
            return IDENTITY
        r = ctypes.create_string_buffer(32)
        if _sodium().crypto_scalarmult_ed25519_noclamp(r, _le32(s), Ec.compress_point(p)) != 0:
            raise PointValidationError("scalar multiplication refused: point not in the prime-order subgroup")
        return Ec.decompress_point(r.raw)

    @staticmethod
    def mul_base(k: int) -> Point:
        s = k % L
        if s == 0:
            return IDENTITY
        r = ctypes.create_string_buffer(32)
        if _sodium().crypto_scalarmult_ed25519_base_noclamp(r, _le32(s)) != 0:
            raise RuntimeError("ed25519 base multiplication failed")
        return Ec.decompress_point(r.raw)

    @staticmethod
    def to_affine(p: Point) -> Tuple[int, int]:
        """Affine (x, y) of a point (identity is (0, 1))."""
        zinv = _inv_q(p.z)
        return _mod_q(p.x * zinv), _mod_q(p.y * zinv)

    @staticmethod
    def equal(a: Point, b: Point) -> bool:
        return _mod_q(a.x * b.z) == _mod_q(b.x * a.z) and _mod_q(a.y * b.z) == _mod_q(b.y * a.z)

    @staticmethod
    def fe_bytes(a: int) -> bytes:
        return _le32(_mod_q(a))

    @staticmethod
    def encode_point(p: Point) -> bytes:
        """Canonical 64-byte affine encoding x || y (little-endian field elements), the OT key-derivation input."""
        x, y = Ec.to_affine(p)
        return Ec.fe_bytes(x) + Ec.fe_bytes(y)

    @staticmethod
    def compress_point(p: Point) -> bytes:
        """Canonical 32-byte compressed encoding (little-endian y, sign of x in bit 255)."""
        x, y = Ec.to_affine(p)
        out = bytearray(Ec.fe_bytes(y))
        out[31] |= (x & 1) << 7
        return bytes(out)

    @staticmethod
    def decompress_point(data: bytes) -> Point:
        """Decodes a canonical compressed encoding (RFC 8032 5.1.3 x-recovery)."""
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise PointValidationError("decompressPoint: expected 32 bytes")
        sign = (data[31] >> 7) & 1
        y = int.from_bytes(bytes(data), "little") & ((1 << 255) - 1)
        if y >= Q:
            raise PointValidationError("decompressPoint: non-canonical y (>= q)")
        y2 = _mod_q(y * y)
        u = _mod_q(y2 - 1)
        v = _mod_q(_D * y2 + 1)
        v3 = _mod_q(v * v * v)
        v7 = _mod_q(v3 * v3 * v)
        x = _mod_q(u * v3 * _pow_q(u * v7, (Q - 5) >> 3))
        vx2 = _mod_q(v * x * x)
        if vx2 == _mod_q(u):
            pass  # x is correct as-is
        elif vx2 == _mod_q(-u):
            x = _mod_q(x * _SQRT_M1)
        else:
            raise PointValidationError("decompressPoint: not on curve")
        if x == 0 and sign == 1:
            raise PointValidationError("decompressPoint: non-canonical sign")
        if (x & 1) != sign:
            x = _mod_q(Q - x)
        return Ec.from_affine(x, y)

    @staticmethod
    def on_curve(p: Point) -> bool:
        """Whether the extended coordinates lie on the curve (projectively, no inversion)."""
        if _mod_q(p.z) == 0:
            return False
        if _mod_q(p.t * p.z) != _mod_q(p.x * p.y):
            return False
        x2 = _mod_q(p.x * p.x)
        y2 = _mod_q(p.y * p.y)
        z2 = _mod_q(p.z * p.z)
        return _mod_q((y2 - x2) * z2) == _mod_q(z2 * z2 + _mod_q(_D * x2) * y2)

    @staticmethod
    def identity(p: Point) -> bool:
        return Ec.equal(p, IDENTITY)

    @staticmethod
    def prime_order(p: Point) -> bool:
        """The cofactor check [L]P = O (true for the identity too)."""
        if not Ec.on_curve(p):
            return False
        if Ec.identity(p):
            return True
        # the group law decides: libsodium 1.0.20 and older accept a mixed-order point through is_valid_point
        b = Ec.compress_point(p)
        return _ed.is_safe_point_bytes(b) and _sodium().crypto_core_ed25519_is_valid_point(b) == 1

    @staticmethod
    def in_subgroup(p: Point) -> bool:
        """A valid non-identity point of the prime-order subgroup."""
        return Ec.on_curve(p) and not Ec.identity(p) and Ec.prime_order(p)

    @staticmethod
    def assert_in_subgroup(p: Point, label: str = "point") -> bool:
        if not Ec.on_curve(p):
            raise PointValidationError("%s: not on curve" % label)
        if Ec.identity(p):
            raise PointValidationError("%s: identity element (forbidden here)" % label)
        if not Ec.prime_order(p):
            raise PointValidationError("%s: not in the prime-order subgroup (small-order/cofactor)" % label)
        return True

    @staticmethod
    def schnorr_challenge(s: Point, u: Point, ctx: bytes) -> int:
        h = hashlib.sha512(TAG_SCHNORR + len(ctx).to_bytes(4, "big") + bytes(ctx) + Ec.encode_point(BASE) + Ec.encode_point(s)
                           + Ec.encode_point(u)).digest()
        return int.from_bytes(h, "big") % L

    @staticmethod
    def schnorr_prove(y: int, s: Point, rnd: Callable[[], int], ctx: bytes) -> SchnorrProof:
        """Fiat-Shamir Schnorr proof of knowledge of y with S = y*B: commitment U = r*B and z = r + e*y. ``rnd`` returns a scalar."""
        if ctx is None or len(ctx) == 0:
            raise ValueError("schnorrProve: a non-empty session binding is required")
        r = rnd() % L
        if r == 0:
            raise RuntimeError("schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof")
        u = Ec.mul_base(r)
        e = Ec.schnorr_challenge(s, u, ctx)
        return SchnorrProof(u, (r + e * (y % L)) % L)

    @staticmethod
    def schnorr_verify(s: Point, proof: SchnorrProof, ctx: bytes) -> bool:
        if ctx is None or len(ctx) == 0:
            return False
        if proof.z < 0 or proof.z >= L:
            return False
        try:
            if not Ec.in_subgroup(proof.u):
                return False
            e = Ec.schnorr_challenge(s, proof.u, ctx)
            return Ec.equal(Ec.mul_base(proof.z), Ec.add_points(proof.u, Ec.mul(e, s)))
        except PointValidationError:
            return False


IDENTITY = Point(0, 1, 1, 0)
BASE = Ec.from_affine(15112221349535400772501151409588531511454012693041857206046113283949847762202,
                      46316835694926478169428394003475163141307993866256225615783033603165251855960)
Ec.IDENTITY = IDENTITY
Ec.BASE = BASE


def mod_fq(x: int) -> int:
    """Canonical representative of `x` in [0, q)."""
    return x % Q
