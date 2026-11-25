"""Thin helpers over supranational blst (through ctypes) shared by the pairing packages (bbs, abe): points as G1 / G2 objects,
scalar arithmetic mod r on int, RFC 9380 expand_message_xmd (SHA-256), strict canonical decoders and the GT group (a small shim
over blst's public API, native/pca_gt.c). No pairing, field or curve arithmetic is implemented here.

The library is bound lazily; a missing one raises ImportError-derived Bls12LibraryMissing (never a "bad input" result). Point it at
the shared library with PCA_BLST_LIB (blst built together with the shim: see the pairing workflow), or put libblst on the loader path.

shortcut: scalar-field add/mul/inverse is Python int arithmetic, which is not constant time. Point multiplication (the expensive,
key-dependent part) is blst's constant-time implementation; upgrade to blst's scalar functions if a deployment needs the scalar
steps constant time as well.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os

from ._native_lib import bundled as _bundled
import threading
from typing import List, Optional, Sequence

R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
GT_BYTES = 576

_P = ctypes.c_void_p
_SZ = ctypes.c_size_t
_B = ctypes.c_bool
_I = ctypes.c_int
# name -> (argument types, return type)
_FUNCS = {
    "blst_scalar_from_bendian": ([_P, _P], None),
    "blst_p1_mult": ([_P, _P, _P, _SZ], None),
    "blst_p1_add_or_double": ([_P, _P, _P], None),
    "blst_p1_cneg": ([_P, _B], None),
    "blst_p1_compress": ([_P, _P], None),
    "blst_p1_uncompress": ([_P, _P], _I),
    "blst_p1_from_affine": ([_P, _P], None),
    "blst_p1_to_affine": ([_P, _P], None),
    "blst_p1_is_inf": ([_P], _B),
    "blst_p1_affine_in_g1": ([_P], _B),
    "blst_p1_affine_on_curve": ([_P], _B),
    "blst_hash_to_g1": ([_P, _P, _SZ, _P, _SZ, _P, _SZ], None),
    "blst_p1_generator": ([], _P),
    "blst_p2_mult": ([_P, _P, _P, _SZ], None),
    "blst_p2_add_or_double": ([_P, _P, _P], None),
    "blst_p2_cneg": ([_P, _B], None),
    "blst_p2_compress": ([_P, _P], None),
    "blst_p2_uncompress": ([_P, _P], _I),
    "blst_p2_from_affine": ([_P, _P], None),
    "blst_p2_to_affine": ([_P, _P], None),
    "blst_p2_is_inf": ([_P], _B),
    "blst_p2_affine_in_g2": ([_P], _B),
    "blst_p2_affine_on_curve": ([_P], _B),
    "blst_p2_generator": ([], _P),
    "blst_hash_to_g2": ([_P, _P, _SZ, _P, _SZ, _P, _SZ], None),
    "blst_core_verify_pk_in_g1": ([_P, _P, _B, _P, _SZ, _P, _SZ, _P, _SZ], _I),
    "blst_pairing_sizeof": ([], _SZ),
    "blst_pairing_init": ([_P, _B, _P, _SZ], None),
    "blst_pairing_aggregate_pk_in_g1": ([_P, _P, _P, _P, _SZ, _P, _SZ], _I),
    "blst_pairing_commit": ([_P], None),
    "blst_pairing_finalverify": ([_P, _P], _B),
    "blst_miller_loop": ([_P, _P, _P], None),
    "blst_fp12_finalverify": ([_P, _P], _B),
}
# the GT shim (native/pca_gt.c), present only in a library built with it
_GT_FUNCS = {
    "pca_gt_mul": ([_P, _P, _P], _I),
    "pca_gt_pow": ([_P, _P, _P], _I),
    "pca_gt_is_element": ([_P], _I),
    "pca_gt_pairing": ([_P, _P, _P, _SZ], _I),
}


class Bls12LibraryMissing(ImportError):
    """libblst (or its GT shim) could not be loaded."""


_lock = threading.Lock()
_lib: Optional[ctypes.CDLL] = None
_gt_bound = False


def _bind(lib: ctypes.CDLL, funcs: dict) -> None:
    for name, (args, ret) in funcs.items():
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, ret


def lib() -> ctypes.CDLL:
    global _lib
    if _lib is not None:
        return _lib
    with _lock:
        if _lib is None:
            names = []
            if os.environ.get("PCA_BLST_LIB"):
                names.append(os.environ["PCA_BLST_LIB"])
            names.extend(n for n in (_bundled("libpca_gt.so", "libpca_gt.dylib", "libpca_gt.dll"),) if n)
            found = ctypes.util.find_library("blst")
            names += [n for n in (found, "libblst.so", "libblst.dylib", "blst.dll") if n]
            last: Optional[Exception] = None
            for n in names:
                try:
                    cand = ctypes.CDLL(n)
                    _bind(cand, _FUNCS)
                    _lib = cand
                    break
                except (OSError, AttributeError) as e:
                    last = e
            if _lib is None:
                raise Bls12LibraryMissing(
                    "BLS12-381 needs a built libblst (supranational/blst; abe also needs the GT shim, set PCA_BLST_LIB): %s" % last
                )
    return _lib


def gt_lib() -> ctypes.CDLL:
    global _gt_bound
    lb = lib()
    with _lock:
        if not _gt_bound:
            try:
                _bind(lb, _GT_FUNCS)
            except AttributeError as e:
                raise Bls12LibraryMissing("abe needs the GT shim (native/pca_gt.c) built into the library: %s" % e) from e
            _gt_bound = True
    return lb


def _buf(n: int):
    lib()
    return ctypes.create_string_buffer(n)


def _addr(b):
    """ctypes buffers pass straight to c_void_p parameters; keeping the object (not an int) keeps it alive for the call."""
    return b


def _inp(b) -> bytes:
    return bytes(b)


def mod(x: int) -> int:
    return x % R


def add(a: int, b: int) -> int:
    return (a + b) % R


def sub(a: int, b: int) -> int:
    return (a - b) % R


def mul(a: int, b: int) -> int:
    return (a * b) % R


def inv(x: int) -> int:
    """Fermat inverse x^(r-2) mod r (fixed public exponent); raises on zero."""
    v = x % R
    if v == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(v, R - 2, R)


def i2osp(n: int, length: int) -> bytes:
    """I2OSP: non-negative integer to fixed-length big-endian octets; raises when it does not fit."""
    if n < 0 or n.bit_length() > 8 * length:
        raise ValueError("integer does not fit %d octets" % length)
    return n.to_bytes(length, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(bytes(b), "big")


def expand_message_xmd(msg: bytes, dst: bytes, length: int) -> bytes:
    """expand_message_xmd with SHA-256 (RFC 9380 5.3.1); the DST must be at most 255 octets."""
    msg = bytes(msg)
    dst = dst.encode("utf-8") if isinstance(dst, str) else bytes(dst)
    ell = (length + 31) // 32
    if length < 0 or ell > 255 or length > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd: invalid length or DST")
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha256(b"\0" * 64 + msg + length.to_bytes(2, "big") + b"\0" + dst_prime).digest()
    bi = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    out = bytearray(bi)
    for i in range(2, ell + 1):
        bi = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, bi)) + bytes([i]) + dst_prime).digest()
        out += bi
    return bytes(out[:length])


def scalar(s: int):
    """blst_scalar (32 bytes) for a value in [0, r)."""
    p = _buf(32)
    lib().blst_scalar_from_bendian(_addr(p), _inp(i2osp(s % R, 32)))
    return p


class Point:
    """A point in G1 or G2 (a blst Jacobian point). Immutable: every operation returns a new point."""

    TAG = ""
    NAME = ""
    GROUP = 0
    SIZE = 0
    AFFINE = 0
    COMPRESSED = 0

    def __init__(self, buf=None):
        self.buf = buf if buf is not None else _buf(self.SIZE)

    @classmethod
    def _call(cls, name: str, *args):
        return getattr(lib(), "blst_%s_%s" % (cls.TAG, name))(*args)

    def __add__(self, other: "Point") -> "Point":
        out = type(self)()
        self._call("add_or_double", _addr(out.buf), _addr(self.buf), _addr(other.buf))
        return out

    def __neg__(self) -> "Point":
        out = self.dup()
        self._call("cneg", _addr(out.buf), True)
        return out

    def __sub__(self, other: "Point") -> "Point":
        return self + (-other)

    def __mul__(self, k: int) -> "Point":
        """k * P, the identity when k is zero mod r."""
        v = k % R
        out = type(self)()
        if v == 0:
            return out
        self._call("mult", _addr(out.buf), _addr(self.buf), _addr(scalar(v)), 255)
        return out

    __rmul__ = __mul__

    def dup(self) -> "Point":
        out = type(self)()
        ctypes.memmove(out.buf, self.buf, self.SIZE)
        return out

    def is_inf(self) -> bool:
        return bool(self._call("is_inf", _addr(self.buf)))

    def compress(self) -> bytes:
        out = _buf(self.COMPRESSED)
        self._call("compress", _addr(out), _addr(self.buf))
        return out.raw

    def affine(self):
        a = _buf(self.AFFINE)
        self._call("to_affine", _addr(a), _addr(self.buf))
        return a

    def __eq__(self, other) -> bool:
        return isinstance(other, type(self)) and self.compress() == other.compress()

    def __hash__(self) -> int:
        return hash(self.compress())

    @classmethod
    def decode(cls, data: bytes) -> "Point":
        """Strict compressed decoding: compression flag set, canonical, on curve, in the prime-order subgroup. The identity is
        allowed (check it separately). Raises ValueError otherwise."""
        if not isinstance(data, (bytes, bytearray)) or len(data) != cls.COMPRESSED or (data[0] & 0x80) == 0:
            raise ValueError("not a %d-byte compressed %s point" % (cls.COMPRESSED, cls.NAME))
        data = bytes(data)
        aff = _buf(cls.AFFINE)
        if cls._call("uncompress", _addr(aff), _inp(data)) != 0:
            raise ValueError("invalid %s encoding" % cls.NAME)
        if not (cls._call("affine_on_curve", _addr(aff)) and cls._call("affine_in_g%d" % cls.GROUP, _addr(aff))):
            raise ValueError("invalid %s encoding" % cls.NAME)
        pt = cls()
        cls._call("from_affine", _addr(pt.buf), _addr(aff))
        if pt.compress() != data:
            raise ValueError("non-canonical %s encoding" % cls.NAME)
        return pt


class G1(Point):
    TAG, NAME, GROUP, SIZE, AFFINE, COMPRESSED = "p1", "G1", 1, 144, 96, 48

    @classmethod
    def generator(cls) -> "G1":
        g = cls()
        ctypes.memmove(g.buf, lib().blst_p1_generator(), cls.SIZE)
        return g

    @classmethod
    def hash_to(cls, msg: bytes, dst: bytes) -> "G1":
        """RFC 9380 hash_to_curve (SSWU_RO) into G1."""
        out = cls()
        m = bytes(msg)
        d = dst.encode("utf-8") if isinstance(dst, str) else bytes(dst)
        lib().blst_hash_to_g1(_addr(out.buf), _inp(m), len(m), _inp(d), len(d), None, 0)
        return out


class G2(Point):
    TAG, NAME, GROUP, SIZE, AFFINE, COMPRESSED = "p2", "G2", 2, 288, 192, 96

    @classmethod
    def generator(cls) -> "G2":
        g = cls()
        ctypes.memmove(g.buf, lib().blst_p2_generator(), cls.SIZE)
        return g


    @classmethod
    def hash_to(cls, msg: bytes, dst: bytes) -> "G2":
        """RFC 9380 hash_to_curve (SSWU_RO) into G2."""
        out = cls()
        m = bytes(msg)
        d = dst.encode("utf-8") if isinstance(dst, str) else bytes(dst)
        lib().blst_hash_to_g2(_addr(out.buf), _inp(m), len(m), _inp(d), len(d), None, 0)
        return out


def core_verify(pk: G1, sig: G2, msg: bytes, dst: bytes) -> bool:
    """blst's CoreVerify (hash-to-curve, signature subgroup-checked, identity public key refused) for pk in G1, signature in G2."""
    m = bytes(msg)
    d = dst.encode("utf-8") if isinstance(dst, str) else bytes(dst)
    return lib().blst_core_verify_pk_in_g1(_addr(pk.affine()), _addr(sig.affine()), True, _inp(m), len(m), _inp(d), len(d), None, 0) == 0


def aggregate_verify(pks: Sequence[G1], msgs: Sequence[bytes], sig: G2, dst: bytes) -> bool:
    """Draft 3.1.1 AggregateVerify over (pk, msg) pairs by blst's pairing context: one shared final exponentiation. The caller
    guarantees pairwise-distinct messages and validated keys."""
    d = dst.encode("utf-8") if isinstance(dst, str) else bytes(dst)  # blst keeps the pointer: hold d until finalverify
    ctx = _buf(lib().blst_pairing_sizeof())
    lib().blst_pairing_init(_addr(ctx), True, _inp(d), len(d))
    for i, (pk, m) in enumerate(zip(pks, msgs)):
        m = bytes(m)
        if lib().blst_pairing_aggregate_pk_in_g1(_addr(ctx), _addr(pk.affine()), _addr(sig.affine()) if i == 0 else None, _inp(m), len(m), None, 0) != 0:
            return False
    lib().blst_pairing_commit(_addr(ctx))
    ok = bool(lib().blst_pairing_finalverify(_addr(ctx), None))
    del d
    return ok


def pairing_eq(a: G1, x: G2, b: G1, y: G2) -> bool:
    """e(a, x) == e(b, y), by blst's pairing."""
    l, r = _buf(576), _buf(576)
    lib().blst_miller_loop(_addr(l), _addr(x.affine()), _addr(a.affine()))
    lib().blst_miller_loop(_addr(r), _addr(y.affine()), _addr(b.affine()))
    return bool(lib().blst_fp12_finalverify(_addr(l), _addr(r)))


class Gt:
    """The pairing target group GT as 576-byte strings (12 Fp coordinates, 48-byte big-endian each), through the shim."""

    BYTES = GT_BYTES

    @staticmethod
    def mul(a: bytes, b: bytes) -> bytes:
        out = _buf(GT_BYTES)
        if gt_lib().pca_gt_mul(_addr(out), _inp(a), _inp(b)) == 0:
            raise ValueError("not a canonical GT encoding")
        return out.raw

    @staticmethod
    def pow(a: bytes, k: int) -> bytes:
        """a^(k mod r)."""
        out = _buf(GT_BYTES)
        if gt_lib().pca_gt_pow(_addr(out), _inp(a), _inp(i2osp(k % R, 32))) == 0:
            raise ValueError("not a canonical GT encoding")
        return out.raw

    @staticmethod
    def is_element(a) -> bool:
        """Canonical encoding of an element of the order-r subgroup other than the identity."""
        return isinstance(a, (bytes, bytearray)) and len(a) == GT_BYTES and gt_lib().pca_gt_is_element(_inp(a)) == 1

    @staticmethod
    def pairing(p: G1, q: G2) -> bytes:
        return Gt.pairing_product([p], [q])

    @staticmethod
    def pairing_product(g1: Sequence[G1], g2: Sequence[G2]) -> bytes:
        """prod e(g1[i], g2[i]) with one shared final exponentiation; raises on an identity point."""
        n = len(g1)
        if n == 0 or n != len(g2):
            raise ValueError("pairing product needs equal, non-empty point lists")
        if any(p.is_inf() for p in g1) or any(q.is_inf() for q in g2):
            raise ValueError("pairing is not defined for the identity")
        out = _buf(GT_BYTES)
        ok = gt_lib().pca_gt_pairing(
            _addr(out), _inp(b"".join(p.compress() for p in g1)), _inp(b"".join(q.compress() for q in g2)), n
        )
        if ok == 0:
            raise ValueError("invalid pairing input")
        return out.raw
