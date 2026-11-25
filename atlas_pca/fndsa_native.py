"""Real FN-DSA (Falcon) backend for ``atlas_pca.fndsa`` through ctypes over ``libfndsa``.

Every lattice operation is the small C library ``libfndsa`` (pca_fndsa.h), built from the flagship's crate with ``cargo build --features capi``
(Thomas Pornin's fn-dsa 0.4.0). FIPS 206 is not final: this is a draft best guess pinned in lockstep with the TypeScript reference, so keys and
signatures interoperate with it and with nothing that implements the earlier round-3 Falcon. Point ``ATLAS_PCA_LIBFNDSA`` at the library, or
install it where ``ctypes.util.find_library("fndsa")`` finds it. A missing or mismatched library raises ``FnDsaBackendMissing``; it never verifies.

    from atlas_pca.fndsa import set_falcon_backend
    from atlas_pca.fndsa_native import native_backend
    set_falcon_backend(native_backend())
"""
from __future__ import annotations

import ctypes as C
import ctypes.util
import os

from ._native_lib import bundled
import threading
from typing import Dict, Optional, Tuple

from .fndsa import (FN_DSA_1024_PUBLIC_KEY_BYTES, FN_DSA_1024_SIGNATURE_BYTES, FN_DSA_512_PUBLIC_KEY_BYTES, FN_DSA_512_SIGNATURE_BYTES,
                    FalconBackend, FnDsaBackendMissing)

SEED_BYTES = 32
MESSAGE_CAP = 8192
_TAGS = {"fn-dsa-512": 512, "fn-dsa-1024": 1024}
_SK_BYTES = {"fn-dsa-512": 1345, "fn-dsa-1024": 2369}
_PK_BYTES = {"fn-dsa-512": FN_DSA_512_PUBLIC_KEY_BYTES, "fn-dsa-1024": FN_DSA_1024_PUBLIC_KEY_BYTES}
_SIG_BYTES = {"fn-dsa-512": FN_DSA_512_SIGNATURE_BYTES, "fn-dsa-1024": FN_DSA_1024_SIGNATURE_BYTES}
_BY_SK = {v: k for k, v in _SK_BYTES.items()}
_BY_PK = {v: k for k, v in _PK_BYTES.items()}

_B = C.POINTER(C.c_ubyte)
_SZ = C.c_size_t
_PROTOS = {
    "fndsa_len_vk": ([C.c_int32], C.c_ssize_t), "fndsa_len_sk": ([C.c_int32], C.c_ssize_t), "fndsa_len_sig": ([C.c_int32], C.c_ssize_t),
    "fndsa_len_seed": ([], _SZ), "fndsa_cap_msg": ([], _SZ),
    "fndsa_c_keygen": ([C.c_int32, _B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
    "fndsa_c_sign": ([C.c_int32, _B, _SZ, _B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
    "fndsa_c_verify": ([C.c_int32, _B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
}
_lib = None
_lock = threading.Lock()


def _load() -> "C.CDLL":
    global _lib
    with _lock:
        if _lib is not None:
            return _lib
        path = os.environ.get("ATLAS_PCA_LIBFNDSA") or bundled("libfndsa.so", "libfndsa.dylib", "fndsa.dll") or ctypes.util.find_library("fndsa")
        if not path:
            raise FnDsaBackendMissing("libfndsa not found: set ATLAS_PCA_LIBFNDSA to the library built from the flagship's crate (cargo build --features capi)")
        try:
            lib = C.CDLL(path)
            for name, (args, res) in _PROTOS.items():
                fn = getattr(lib, name)
                fn.argtypes, fn.restype = args, res
        except (OSError, AttributeError) as e:
            raise FnDsaBackendMissing("libfndsa could not be loaded: %s" % e) from e
        # the sizes this module hard-codes must be the ones the library was built with, or nothing is safe
        for variant, tag in _TAGS.items():
            if (lib.fndsa_len_vk(tag), lib.fndsa_len_sk(tag), lib.fndsa_len_sig(tag)) != (_PK_BYTES[variant], _SK_BYTES[variant], _SIG_BYTES[variant]):
                raise FnDsaBackendMissing("libfndsa reports different sizes for %s" % variant)
        if lib.fndsa_len_seed() != SEED_BYTES or lib.fndsa_cap_msg() != MESSAGE_CAP:
            raise FnDsaBackendMissing("libfndsa reports a different seed length or message cap")
        _lib = lib
        return lib


def available() -> bool:
    """True when libfndsa can be loaded."""
    try:
        _load()
        return True
    except FnDsaBackendMissing:
        return False


def _in(b: bytes):
    return (C.c_ubyte * len(b)).from_buffer_copy(b) if len(b) else None


def _bytes(name: str, v) -> bytes:
    if not isinstance(v, (bytes, bytearray)):
        raise TypeError("fndsa_native: %s must be bytes" % name)
    return bytes(v)


def _tag(variant) -> int:
    if not isinstance(variant, str) or variant not in _TAGS:
        raise ValueError("fndsa_native: unknown FN-DSA variant %r" % (variant,))
    return _TAGS[variant]


def keygen(variant: str, seed: bytes) -> Tuple[bytes, bytes]:
    """Deterministic (sk, vk) from a 32-byte seed."""
    tag, seed = _tag(variant), _bytes("seed", seed)
    if len(seed) != SEED_BYTES:
        raise ValueError("fndsa_native: seed must be %d bytes" % SEED_BYTES)
    lib = _load()
    sk, vk = (C.c_ubyte * _SK_BYTES[variant])(), (C.c_ubyte * _PK_BYTES[variant])()
    rc = lib.fndsa_c_keygen(tag, _in(seed), len(seed), sk, len(sk), vk, len(vk))
    if rc != 0:
        raise RuntimeError("fndsa_native: keygen refused (%d)" % rc)
    return bytes(sk), bytes(vk)


def sign(variant: str, sk: bytes, msg: bytes, seed: Optional[bytes] = None) -> bytes:
    """Signature over a raw message. ``seed`` is for known-answer tests only; by default 32 fresh bytes come from os.urandom."""
    tag, sk, msg = _tag(variant), _bytes("sk", sk), _bytes("msg", msg)
    if len(sk) != _SK_BYTES[variant]:
        raise ValueError("fndsa_native: secret key must be %d bytes for %s" % (_SK_BYTES[variant], variant))
    if len(msg) > MESSAGE_CAP:
        raise ValueError("fndsa_native: message over %d bytes" % MESSAGE_CAP)
    seed = os.urandom(SEED_BYTES) if seed is None else _bytes("seed", seed)
    if len(seed) != SEED_BYTES:
        raise ValueError("fndsa_native: seed must be %d bytes" % SEED_BYTES)
    lib = _load()
    out = (C.c_ubyte * _SIG_BYTES[variant])()
    rc = lib.fndsa_c_sign(tag, _in(sk), len(sk), _in(msg), len(msg), _in(seed), len(seed), out, len(out))
    if rc != 0:
        raise RuntimeError("fndsa_native: sign failed (%d)" % rc)
    return bytes(out)


def verify(variant: str, pk: bytes, msg: bytes, sig: bytes) -> bool:
    """True only when the library returns 0; any bad length, oversize message or nonzero return is False."""
    tag = _tag(variant)
    pk, msg, sig = _bytes("pk", pk), _bytes("msg", msg), _bytes("sig", sig)
    if len(pk) != _PK_BYTES[variant] or len(sig) != _SIG_BYTES[variant] or len(msg) > MESSAGE_CAP:
        return False
    return _load().fndsa_c_verify(tag, _in(pk), len(pk), _in(sig), len(sig), _in(msg), len(msg)) == 0


def native_backend() -> FalconBackend:
    """A FalconBackend over libfndsa (raises FnDsaBackendMissing now if the library is absent). The variant follows the key length;
    keygen() draws a fresh fn-dsa-512 pair from os.urandom (use ``keygen(variant, seed)`` for 1024)."""
    _load()

    def _verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        variant = _BY_PK.get(len(pk))
        return variant is not None and verify(variant, pk, msg, sig)

    def _sign(sk: bytes, msg: bytes) -> bytes:
        variant = _BY_SK.get(len(sk))
        if variant is None:
            raise ValueError("fndsa_native: unrecognised FN-DSA secret-key length")
        return sign(variant, sk, msg)

    def _keygen() -> Dict[str, bytes]:
        sk, vk = keygen("fn-dsa-512", os.urandom(SEED_BYTES))
        return {"pk": vk, "sk": sk}

    def _sign_seeded(variant: str, sk: bytes, msg: bytes, seed: bytes) -> bytes:
        return sign(variant, sk, msg, seed)

    def _keygen_seeded(variant: str, seed: bytes) -> Dict[str, bytes]:
        sk, vk = keygen(variant, seed)
        return {"pk": vk, "sk": sk}

    return FalconBackend(_verify, _sign, _keygen, _sign_seeded, _keygen_seeded)
