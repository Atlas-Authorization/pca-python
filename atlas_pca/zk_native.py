"""Groth16 pairing check and prover for ``atlas_pca.zk`` through ctypes over ``libpcazk`` (pca_zk.h).

The library is the flagship's ``pca-zk`` crate built with ``cargo build --features capi`` (arkworks; BN254 and BLS12-381; the circom
witness wasm runs on an embedded interpreter). It is an opt-in native module: the platform wheels carry it in ``atlas_pca/_native``;
otherwise point ``ATLAS_PCA_LIBPCAZK`` at the library or install it where ``ctypes.util.find_library("pcazk")`` finds it. A missing or
mismatched library raises ``ZkBackendMissing``; it never reports a proof as invalid, and never as valid.

Inputs are the snarkjs JSON objects (decimal-string field elements, G1 ``[x, y, "1"]``, G2 ``[[x0, x1], [y0, y1], ["1", "0"]]``)."""
from __future__ import annotations

import ctypes as C
import ctypes.util
import json
import os
import threading
from typing import Any, Optional, Tuple

from ._native_lib import bundled

CURVE_BN254 = 0
CURVE_BLS12_381 = 1
CURVE_FROM_KEY = 2  # verify only, snarkjs-compatible mode only: the library reads the curve from the key's own name (snarkjs' getCurveFromName)
FLAG_SNARKJS_COMPAT = 1  # accept what snarkjs' groth16.verify accepts (the reference behaviour); 0 is strict
SEED_BYTES = 32
_VALID, _INVALID = 1, 0


class ZkBackendMissing(RuntimeError):
    """libpcazk could not be found or loaded, or is not the library this module binds."""


class ZkProveError(RuntimeError):
    """The prover refused: ``code`` is the library's negative return (-3 prove, -4 witness, -5 zkey, -6 input, -2 internal)."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


_PROTOS = {
    "pca_zk_version": ([], C.c_char_p),
    "pca_zk_reason_text": ([C.c_int32], C.c_char_p),
    "pca_zk_verify": ([C.c_int32, C.c_uint32, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.POINTER(C.c_int32)],
                      C.c_int32),
    "pca_zk_prove": ([C.c_int32, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t,
                      C.POINTER(C.c_void_p), C.POINTER(C.c_size_t)], C.c_int32),
    "pca_zk_free": ([C.c_void_p, C.c_size_t], None),
}
_lib = None
_lock = threading.Lock()


def _load() -> "C.CDLL":
    global _lib
    with _lock:
        if _lib is not None:
            return _lib
        path = os.environ.get("ATLAS_PCA_LIBPCAZK") or bundled("libpcazk.so", "libpcazk.dylib", "pcazk.dll") or ctypes.util.find_library("pcazk")
        if not path:
            raise ZkBackendMissing("libpcazk not found: set ATLAS_PCA_LIBPCAZK to the library built from the flagship's crate (cargo build --features capi)")
        try:
            lib = C.CDLL(path)
            for name, (args, res) in _PROTOS.items():
                fn = getattr(lib, name)
                fn.argtypes, fn.restype = args, res
        except (OSError, AttributeError) as e:
            raise ZkBackendMissing("libpcazk could not be loaded: %s" % e) from e
        if not lib.pca_zk_version():
            raise ZkBackendMissing("libpcazk reports no version")
        _lib = lib
        return lib


def available() -> bool:
    """True when libpcazk can be loaded."""
    try:
        _load()
        return True
    except ZkBackendMissing:
        return False


def version() -> str:
    return _load().pca_zk_version().decode("ascii")


def _json(v: Any) -> bytes:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _curve(curve: int, strict: bool = True, may_read_key: bool = False) -> int:
    if isinstance(curve, bool) or curve not in (CURVE_BN254, CURVE_BLS12_381) + ((CURVE_FROM_KEY,) if may_read_key and not strict else ()):
        raise ValueError("zk_native: unknown curve %r" % (curve,))
    return curve


def verify_with_reason(curve: int, vkey: Any, proof: Any, public_signals: Any, strict: bool = False) -> Tuple[bool, str]:
    """(verdict, reason) of a snarkjs Groth16 proof under `vkey`. The default mode accepts exactly what the reference verifier accepts;
    ``strict=True`` also requires protocol groth16 on key and proof, the curve tags to match and nPublic / IC to equal the signal count.
    The field, group and subgroup checks are on in both modes. Raises on a usage error, never returns a verdict for one."""
    lib = _load()
    k, p, s = _json(vkey), _json(proof), _json(public_signals)
    reason = C.c_int32(-1)
    rc = lib.pca_zk_verify(_curve(curve, strict, True), 0 if strict else FLAG_SNARKJS_COMPAT, k, len(k), p, len(p), s, len(s), C.byref(reason))
    if rc not in (_VALID, _INVALID):
        raise RuntimeError("zk_native: pca_zk_verify failed (%d)" % rc)
    return rc == _VALID, (lib.pca_zk_reason_text(reason.value) or b"unknown").decode("ascii", "replace")


def verify(curve: int, vkey: Any, proof: Any, public_signals: Any, strict: bool = False) -> bool:
    return verify_with_reason(curve, vkey, proof, public_signals, strict)[0]


def prove(curve: int, wasm: bytes, zkey: bytes, circuit_input: Any, seed: Optional[bytes] = None) -> dict:
    """``{"proof": ..., "publicSignals": [...]}`` for the circom witness wasm, the snarkjs zkey and the circuit's input object. `seed`
    (32 bytes) makes the blinding deterministic and is for tests only; leave it None for operating-system randomness. The whole zkey is
    held in memory. Raises ``ZkProveError`` when the witness does not satisfy the circuit or an artifact is malformed."""
    for name, v in (("wasm", wasm), ("zkey", zkey)):
        if not isinstance(v, (bytes, bytearray)):
            raise TypeError("zk_native: %s must be bytes" % name)
    if seed is not None and (not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_BYTES):
        raise ValueError("zk_native: seed must be %d bytes" % SEED_BYTES)
    lib = _load()
    inp = _json(circuit_input)
    out, out_len = C.c_void_p(), C.c_size_t(0)
    rc = lib.pca_zk_prove(_curve(curve), bytes(wasm), len(wasm), bytes(zkey), len(zkey), inp, len(inp),
                          bytes(seed) if seed is not None else None, SEED_BYTES if seed is not None else 0, C.byref(out), C.byref(out_len))
    try:
        text = C.string_at(out.value, out_len.value) if out.value else b""
    finally:
        if out.value:
            lib.pca_zk_free(out, out_len)
    if rc != 0:
        raise ZkProveError(rc, "zk_native: proving failed (%d): %s" % (rc, text.decode("utf-8", "replace") or "no detail"))
    return json.loads(text.decode("utf-8"))


__all__ = ["CURVE_BN254", "CURVE_BLS12_381", "CURVE_FROM_KEY", "ZkBackendMissing", "ZkProveError", "available", "version", "verify", "verify_with_reason", "prove"]
