"""Homomorphic risk gate (BFV on Microsoft SEAL), wire-compatible with the TypeScript package (node-seal 5.1.x bundles SEAL 4.1.x).

BFV is never reimplemented here: this binds SEAL's own C export API (native/src/seal/c, the one SEAL.NET binds) through ctypes, so the
optional native library ``libsealc`` (built from the pinned SEAL tag) is the only extra requirement. Point ``ATLAS_PCA_LIBSEALC`` at it, or
install it where ``ctypes.util.find_library("sealc")`` finds it. Every SEAL object crosses the API as the base64 of its SEAL native stream.
"""

from __future__ import annotations

import base64
import ctypes as C
import ctypes.util
import os

from ._native_lib import bundled
import re
import struct
from dataclasses import dataclass
from typing import List, Optional, Sequence

POLY_MODULUS_DEGREE = 8192
PLAIN_MODULUS_BITS = 30
PLAIN_MODULUS = 1073692673
SIGNED_BOUND = PLAIN_MODULUS // 2
RISK_DIM = 6
_MIN_NOISE_BUDGET_BITS = 16
_BFV, _TC128, _COMPR_NONE, _COMPR_ZSTD = 1, 128, 0, 2
_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

_P = C.c_void_p
_PP = C.POINTER(C.c_void_p)
_U64, _I64, _U8P = C.c_uint64, C.c_int64, C.POINTER(C.c_uint8)
_PROTOS = {
    "EncParams_Create1": [C.c_uint8, _PP], "EncParams_Destroy": [_P], "EncParams_SetPolyModulusDegree": [_P, _U64],
    "EncParams_SetCoeffModulus": [_P, _U64, _PP], "EncParams_SetPlainModulus1": [_P, _P],
    "CoeffModulus_BFVDefault": [_U64, C.c_int, C.POINTER(_U64), _PP], "CoeffModulus_Create1": [_U64, _U64, C.POINTER(C.c_int), _PP],
    "Modulus_Destroy": [_P], "Modulus_Value": [_P, C.POINTER(_U64)],
    "SEALContext_Create": [_P, C.c_bool, C.c_int, _PP], "SEALContext_Destroy": [_P], "SEALContext_ParametersSet": [_P, C.POINTER(C.c_bool)],
    "BatchEncoder_Create": [_P, _PP], "BatchEncoder_Destroy": [_P], "BatchEncoder_Encode2": [_P, _U64, C.POINTER(_I64), _P],
    "BatchEncoder_Decode2": [_P, _P, C.POINTER(_U64), C.POINTER(_I64), _P], "BatchEncoder_GetSlotCount": [_P, C.POINTER(_U64)],
    "KeyGenerator_Create1": [_P, _PP], "KeyGenerator_Destroy": [_P], "KeyGenerator_SecretKey": [_P, _PP],
    "KeyGenerator_CreatePublicKey": [_P, C.c_bool, _PP], "KeyGenerator_CreateRelinKeys": [_P, C.c_bool, _PP],
    "KeyGenerator_CreateGaloisKeysAll": [_P, C.c_bool, _PP],
    "PublicKey_Create1": [_PP], "PublicKey_Destroy": [_P], "PublicKey_SaveSize": [_P, C.c_uint8, C.POINTER(_I64)],
    "PublicKey_Save": [_P, _U8P, _U64, C.c_uint8, C.POINTER(_I64)], "PublicKey_Load": [_P, _P, _U8P, _U64, C.POINTER(_I64)],
    "SecretKey_Create1": [_PP], "SecretKey_Destroy": [_P], "SecretKey_SaveSize": [_P, C.c_uint8, C.POINTER(_I64)],
    "SecretKey_Save": [_P, _U8P, _U64, C.c_uint8, C.POINTER(_I64)], "SecretKey_Load": [_P, _P, _U8P, _U64, C.POINTER(_I64)],
    "KSwitchKeys_Create1": [_PP], "KSwitchKeys_Destroy": [_P], "KSwitchKeys_SaveSize": [_P, C.c_uint8, C.POINTER(_I64)],
    "KSwitchKeys_Save": [_P, _U8P, _U64, C.c_uint8, C.POINTER(_I64)], "KSwitchKeys_Load": [_P, _P, _U8P, _U64, C.POINTER(_I64)],
    "Ciphertext_Create1": [_P, _PP], "Ciphertext_Create2": [_P, _PP], "Ciphertext_Destroy": [_P],
    "Ciphertext_SaveSize": [_P, C.c_uint8, C.POINTER(_I64)], "Ciphertext_Save": [_P, _U8P, _U64, C.c_uint8, C.POINTER(_I64)],
    "Ciphertext_Load": [_P, _P, _U8P, _U64, C.POINTER(_I64)],
    "Plaintext_Create1": [_P, _PP], "Plaintext_Destroy": [_P],
    "Encryptor_Create": [_P, _P, _P, _PP], "Encryptor_Encrypt": [_P, _P, _P, _P], "Encryptor_Destroy": [_P],
    "Decryptor_Create": [_P, _P, _PP], "Decryptor_Destroy": [_P], "Decryptor_Decrypt": [_P, _P, _P],
    "Decryptor_InvariantNoiseBudget": [_P, _P, C.POINTER(C.c_int)],
    "Evaluator_Create": [_P, _PP], "Evaluator_Destroy": [_P], "Evaluator_Negate": [_P, _P, _P], "Evaluator_Add": [_P, _P, _P, _P],
    "Evaluator_AddPlain": [_P, _P, _P, _P], "Evaluator_MultiplyPlain": [_P, _P, _P, _P, _P],
    "Evaluator_RotateRows": [_P, _P, C.c_int, _P, _P, _P], "Evaluator_RotateColumns": [_P, _P, _P, _P, _P],
}
_lib = None


def _load():
    global _lib
    if _lib is None:
        path = os.environ.get("ATLAS_PCA_LIBSEALC") or bundled("libsealc.so", "libsealc.dylib", "sealc.dll") or ctypes.util.find_library("sealc")
        if not path:
            raise RuntimeError("libsealc not found: build it from the pinned SEAL tag and set ATLAS_PCA_LIBSEALC")
        lib = C.CDLL(path)
        for name, args in _PROTOS.items():
            fn = getattr(lib, name)
            fn.argtypes, fn.restype = args, C.c_long
        _lib = lib
    return _lib


def _call(name: str, *args) -> None:
    hr = getattr(_load(), name)(*args)
    if hr < 0:  # SEAL's HRESULT convention: negative is failure, S_FALSE (1) is success
        raise RuntimeError(f"seal {name} failed: 0x{hr & 0xFFFFFFFF:08x}")


class _Scope:
    """Releases native handles in reverse order on every exit path."""

    def __init__(self) -> None:
        self._fns: list = []

    def make(self, create: str, destroy: str, *args) -> int:
        h = C.c_void_p()
        _call(create, *args, C.byref(h))
        self._fns.append((destroy, h.value))
        return h.value

    def adopt(self, destroy: str, handle: int) -> int:
        self._fns.append((destroy, handle))
        return handle

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        for destroy, h in reversed(self._fns):
            getattr(_load(), destroy)(h)
        self._fns = []


@dataclass(frozen=True)
class FheRiskPolicy:
    """The public gate policy: fixed-point weights, kappa-weighted weights and the budget bound (scale S, budget at S^2)."""

    scale: int
    dim: int
    weights_scaled: Sequence[int]
    kappa_weights_scaled: Sequence[int]
    budget_scaled: int
    kappa: float = 1.0


@dataclass(frozen=True)
class FheKeyset:
    secret_key: str
    public_key: str
    relin_keys: str
    galois_keys: str


@dataclass(frozen=True)
class EncryptedGate:
    enc_risk_raw: str
    enc_slack: str


@dataclass(frozen=True)
class Verdict:
    r_scaled: int
    slack: int
    admit: bool


def assert_seal_blob(blob: str, what: str) -> bytes:
    """Reject anything that is not a well-formed SEAL stream envelope (magic, header size, compression mode, declared size == length)."""
    if not isinstance(blob, str) or len(blob) < 24 or len(blob) % 4 != 0 or not _B64.match(blob):
        raise ValueError(f"{what}: not a serialized SEAL object (bad encoding)")
    b = base64.b64decode(blob, validate=True)
    if len(b) < 16 or b[0] != 0x5E or b[1] != 0xA1 or b[2] != 16 or b[5] > 2 or b[6] != 0 or b[7] != 0:
        raise ValueError(f"{what}: not a serialized SEAL object (bad header)")
    (size,) = struct.unpack("<Q", b[8:16])
    if size != len(b):
        raise ValueError(f"{what}: truncated or padded SEAL object (declared {size} bytes, got {len(b)})")
    return b


def require_policy(p: FheRiskPolicy) -> None:
    """The policy crosses a trust boundary: validate every coefficient exactly as the policy builder would have produced it."""
    if not isinstance(p, FheRiskPolicy):
        raise TypeError("policy must be an FheRiskPolicy")
    ints = [p.scale, p.dim, p.budget_scaled, *p.weights_scaled, *p.kappa_weights_scaled]
    if any(isinstance(v, bool) or not isinstance(v, int) for v in ints):
        raise ValueError("policy coefficients must be integers")
    if p.scale <= 0:
        raise ValueError("policy.scale must be a positive integer")
    if any(abs(v) >= SIGNED_BOUND for v in [p.budget_scaled, *p.weights_scaled, *p.kappa_weights_scaled]):
        raise ValueError("policy coefficients must be integers with |value| < SIGNED_BOUND")
    if p.dim != RISK_DIM:
        raise ValueError(f"policy.dim must be {RISK_DIM}")
    if len(p.weights_scaled) != RISK_DIM or len(p.kappa_weights_scaled) != RISK_DIM:
        raise ValueError(f"policy weight vectors must have length {RISK_DIM}")


class _Ctx:
    def __init__(self, s: _Scope) -> None:
        parms = s.make("EncParams_Create1", "EncParams_Destroy", C.c_uint8(_BFV))
        _call("EncParams_SetPolyModulusDegree", parms, POLY_MODULUS_DEGREE)
        n = _U64(0)
        _call("CoeffModulus_BFVDefault", POLY_MODULUS_DEGREE, _TC128, C.byref(n), None)
        coeffs = (C.c_void_p * n.value)()
        _call("CoeffModulus_BFVDefault", POLY_MODULUS_DEGREE, _TC128, C.byref(n), coeffs)
        for m in coeffs:
            s.adopt("Modulus_Destroy", m)
        _call("EncParams_SetCoeffModulus", parms, n.value, coeffs)
        bits, plain = C.c_int(PLAIN_MODULUS_BITS), C.c_void_p()
        _call("CoeffModulus_Create1", POLY_MODULUS_DEGREE, 1, C.byref(bits), C.byref(plain))
        s.adopt("Modulus_Destroy", plain.value)
        live = _U64(0)
        _call("Modulus_Value", plain, C.byref(live))
        if live.value != PLAIN_MODULUS:
            raise RuntimeError(f"plain modulus drift: live {live.value} != documented {PLAIN_MODULUS}")
        _call("EncParams_SetPlainModulus1", parms, plain)
        self.context = s.make("SEALContext_Create", "SEALContext_Destroy", parms, True, _TC128)
        ok = C.c_bool(False)
        _call("SEALContext_ParametersSet", self.context, C.byref(ok))
        if not ok.value:
            raise RuntimeError("SEAL rejected the BFV parameters")
        self.encoder = s.make("BatchEncoder_Create", "BatchEncoder_Destroy", self.context)
        sc = _U64(0)
        _call("BatchEncoder_GetSlotCount", self.encoder, C.byref(sc))
        self.slots = sc.value


_KINDS = {"public": "PublicKey", "secret": "SecretKey", "keys": "KSwitchKeys", "cipher": "Ciphertext"}


def _new(s: _Scope, kind: str) -> int:
    t = _KINDS[kind]
    return s.make(f"{t}_Create1", f"{t}_Destroy") if kind != "cipher" else s.make("Ciphertext_Create1", "Ciphertext_Destroy", None)


def _load_obj(ctx: _Ctx, s: _Scope, kind: str, blob: str, what: str) -> int:
    raw = assert_seal_blob(blob, what)
    buf = (C.c_uint8 * len(raw)).from_buffer_copy(raw)
    p, used = _new(s, kind), _I64(0)
    _call(f"{_KINDS[kind]}_Load", p, ctx.context, buf, len(raw), C.byref(used))
    return p


def _save_obj(kind: str, p: int, compr: int = _COMPR_ZSTD) -> str:
    t, size = _KINDS[kind], _I64(0)
    _call(f"{t}_SaveSize", p, compr, C.byref(size))
    buf, n = (C.c_uint8 * size.value)(), _I64(0)
    _call(f"{t}_Save", p, buf, size.value, compr, C.byref(n))
    return base64.b64encode(bytes(buf[: n.value])).decode("ascii")


def _encode(ctx: _Ctx, s: _Scope, values: Sequence[int]) -> int:
    slots = (_I64 * ctx.slots)(*values)
    pt = s.make("Plaintext_Create1", "Plaintext_Destroy", None)
    _call("BatchEncoder_Encode2", ctx.encoder, ctx.slots, slots, pt)
    return pt


def keygen() -> FheKeyset:
    """Generate the key material (the secret key stays with the policy owner)."""
    with _Scope() as s:
        ctx = _Ctx(s)
        gen = s.make("KeyGenerator_Create1", "KeyGenerator_Destroy", ctx.context)
        skh = C.c_void_p()  # a view of the generator's own key: destroying it would free the key twice
        _call("KeyGenerator_SecretKey", gen, C.byref(skh))
        sk = skh.value
        pk = s.make("KeyGenerator_CreatePublicKey", "PublicKey_Destroy", gen, False)
        rk = s.make("KeyGenerator_CreateRelinKeys", "KSwitchKeys_Destroy", gen, False)
        gk = s.make("KeyGenerator_CreateGaloisKeysAll", "KSwitchKeys_Destroy", gen, False)
        return FheKeyset(_save_obj("secret", sk), _save_obj("public", pk), _save_obj("keys", rk), _save_obj("keys", gk))


def encrypt_risk_inputs(public_key: str, inputs_scaled: Sequence[int]) -> str:
    """BFV-encrypt the quantized risk-input vector (length 6, each a non-negative integer below the signed bound)."""
    if len(inputs_scaled) != RISK_DIM:
        raise ValueError(f"inputs_scaled must have length {RISK_DIM}")
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 or v >= SIGNED_BOUND for v in inputs_scaled):
        raise ValueError("each scaled input must be a non-negative integer below the signed bound")
    with _Scope() as s:
        ctx = _Ctx(s)
        pk = _load_obj(ctx, s, "public", public_key, "publicKey")
        enc = s.make("Encryptor_Create", "Encryptor_Destroy", ctx.context, pk, None)
        pt, ct = _encode(ctx, s, inputs_scaled), _new(s, "cipher")
        _call("Encryptor_Encrypt", enc, pt, ct, None)
        return _save_obj("cipher", ct)


def eval_risk_gate(public_key: str, galois_keys: str, enc_inputs: str, policy: FheRiskPolicy) -> EncryptedGate:
    """Evaluate the gate blind with the reference's operation order (multiplyPlain, sumElements, negate, addPlain). Never builds a decryptor."""
    require_policy(policy)
    with _Scope() as s:
        ctx = _Ctx(s)
        gk = _load_obj(ctx, s, "keys", galois_keys, "galoisKeys")
        pk = _load_obj(ctx, s, "public", public_key, "publicKey")
        ev = s.make("Evaluator_Create", "Evaluator_Destroy", ctx.context)
        enc = s.make("Encryptor_Create", "Encryptor_Destroy", ctx.context, pk, None)
        x = _load_obj(ctx, s, "cipher", enc_inputs, "encInputs")

        def total(prod: int) -> int:
            temp = s.make("Ciphertext_Create2", "Ciphertext_Destroy", prod)
            dest = _new(s, "cipher")
            _call("Evaluator_RotateColumns", ev, temp, gk, dest, None)
            _call("Evaluator_Add", ev, temp, dest, temp)
            steps = POLY_MODULUS_DEGREE // 4
            while steps >= 1:
                _call("Evaluator_RotateRows", ev, temp, steps, gk, dest, None)
                _call("Evaluator_RotateColumns", ev, dest, gk, dest, None)
                _call("Evaluator_Add", ev, temp, dest, temp)
                steps //= 2
            return temp

        def dot(coeffs: Sequence[int]) -> int:
            # SEAL refuses multiplyPlain by an all-zero plaintext (transparent result): the dot product is then a fresh encryption of zero.
            if all(c == 0 for c in coeffs):
                ct = _new(s, "cipher")
                _call("Encryptor_Encrypt", enc, _encode(ctx, s, []), ct, None)
                return ct
            prod = _new(s, "cipher")
            _call("Evaluator_MultiplyPlain", ev, x, _encode(ctx, s, coeffs), prod, None)
            return total(prod)

        risk_raw = dot(policy.weights_scaled)
        kappa_risk = dot(policy.kappa_weights_scaled)
        neg, slack = _new(s, "cipher"), _new(s, "cipher")
        _call("Evaluator_Negate", ev, kappa_risk, neg)
        _call("Evaluator_AddPlain", ev, neg, _encode(ctx, s, [policy.budget_scaled]), slack)
        return EncryptedGate(_save_obj("cipher", risk_raw), _save_obj("cipher", slack))


def decrypt_verdict(secret_key: str, enc_risk_raw: str, enc_slack: str, policy: FheRiskPolicy) -> Verdict:
    """Decrypt the gate outputs and read the verdict; fails closed when the noise budget is exhausted (wrong key, corrupt or foreign ciphertext)."""
    require_policy(policy)
    with _Scope() as s:
        ctx = _Ctx(s)
        sk = _load_obj(ctx, s, "secret", secret_key, "secretKey")
        dec = s.make("Decryptor_Create", "Decryptor_Destroy", ctx.context, sk)
        cts = [_load_obj(ctx, s, "cipher", enc_risk_raw, "encRiskRaw"), _load_obj(ctx, s, "cipher", enc_slack, "encSlack")]
        for ct in cts:
            nb = C.c_int(0)
            _call("Decryptor_InvariantNoiseBudget", dec, ct, C.byref(nb))
            if nb.value < _MIN_NOISE_BUDGET_BITS:
                raise ValueError("decrypt_verdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)")

        def first(ct: int) -> int:
            pt = s.make("Plaintext_Create1", "Plaintext_Destroy", None)
            _call("Decryptor_Decrypt", dec, ct, pt)
            n = _U64(ctx.slots)  # the C export rejects a null destination: size the buffer from the slot count and check the count after
            out = (_I64 * ctx.slots)()
            _call("BatchEncoder_Decode2", ctx.encoder, pt, C.byref(n), out, None)
            if n.value != ctx.slots:
                raise RuntimeError("seal BatchEncoder_Decode2 returned an unexpected slot count")
            return int(out[0])

        raw, slack = first(cts[0]), first(cts[1])
        return Verdict(min(max(raw, 0), policy.scale * policy.scale), slack, slack >= 0)


def canonical_cipher(blob: str) -> str:
    """Re-save a base64 SEAL ciphertext uncompressed, for byte comparison independent of the zstd build."""
    with _Scope() as s:
        ctx = _Ctx(s)
        return _save_obj("cipher", _load_obj(ctx, s, "cipher", blob, "ciphertext"), _COMPR_NONE)
