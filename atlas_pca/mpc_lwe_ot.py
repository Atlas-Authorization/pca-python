"""Post-quantum endemic (Masny-Rindal) base OT for the MPC package: Kyber-768 K-PKE (the audited pqc_kyber reference) through ctypes.

The recommended post-quantum, maliciously-secure base OT of the TypeScript package. The receiver places a real key's offset-by-oracle point at its
choice slot and a uniform ring vector at the other, so the sender's effective key for the other slot is uniform and its ciphertext is
unrecoverable; the chosen-message form pads and commits each message and aborts on any inconsistency. Nothing lattice-related is implemented here:
every K-PKE and ring operation is the small C library ``liblweot`` (pca_lwe_ot.h, built from the flagship's crate with ``cargo build --features
capi``). Point ``ATLAS_PCA_LIBLWEOT`` at it, or install it where ``ctypes.util.find_library("lweot")`` finds it. The receiver's real key pair is the
FIPS 203 K-PKE.KeyGen(d), the derivation the reference uses, so every receiver message matches it byte for byte.
"""

from __future__ import annotations

import ctypes as C
import ctypes.util
import hmac
import os

from ._native_lib import bundled
import secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, List, Optional, Sequence, Tuple

PK_BYTES, SK_BYTES, CT_BYTES, TVEC_BYTES, SYM_BYTES, HASHIN_CAP = 1184, 1152, 1088, 1152, 32, 4096
ENDEMIC_SECRET_BYTES = SYM_BYTES

_TAG_SID = b"atlas-pca-mpc/endemic-lwe-ot-sid"
_TAG_HPK = b"atlas-pca-mpc/endemic-lwe-ot-hpk"
_TAG_N = b"atlas-pca-mpc/endemic-lwe-ot-N"
_TAG_PAD = b"atlas-pca-mpc/endemic-lwe-ot-pad"
_TAG_COMMIT = b"atlas-pca-mpc/endemic-lwe-ot-commit"


class EndemicAbort(Exception):
    """The endemic base OT aborted: malformed input, or a sender ciphertext failing its commitment."""


# ---- the C library ---------------------------------------------------------------------------------------------------------------------

_B = C.POINTER(C.c_ubyte)
_SZ = C.c_size_t
_PROTOS = {
    "lweot_len_pk": ([], _SZ), "lweot_len_sk": ([], _SZ), "lweot_len_ct": ([], _SZ), "lweot_len_tvec": ([], _SZ),
    "lweot_len_sym": ([], _SZ), "lweot_hashin_cap": ([], _SZ),
    "lweot_kpke_keygen_fips203": ([_B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
    "lweot_kpke_keygen": ([_B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
    "lweot_kpke_enc": ([_B, _SZ, _B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
    "lweot_kpke_dec": ([_B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
    "lweot_ring_add": ([_B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
    "lweot_ring_sub": ([_B, _SZ, _B, _SZ, _B, _SZ], C.c_int32),
    "lweot_hash_to_ring": ([_B, _SZ, _B, _SZ], C.c_int32),
}
_lib = None


def _load() -> "C.CDLL":
    global _lib
    if _lib is not None:
        return _lib
    path = os.environ.get("ATLAS_PCA_LIBLWEOT") or bundled("liblweot.so", "liblweot.dylib", "lweot.dll") or ctypes.util.find_library("lweot")
    if not path:
        raise RuntimeError("liblweot not found: set ATLAS_PCA_LIBLWEOT to the library built from the flagship's crate (cargo build --features capi)")
    try:
        lib = C.CDLL(path)
        for name, (args, res) in _PROTOS.items():
            fn = getattr(lib, name)
            fn.argtypes, fn.restype = args, res
    except (OSError, AttributeError) as e:
        raise RuntimeError("liblweot could not be loaded: %s" % e) from e
    # the sizes this module hard-codes must be the ones the library was built with, or nothing is safe
    got = (lib.lweot_len_pk(), lib.lweot_len_sk(), lib.lweot_len_ct(), lib.lweot_len_tvec(), lib.lweot_len_sym(), lib.lweot_hashin_cap())
    if got != (PK_BYTES, SK_BYTES, CT_BYTES, TVEC_BYTES, SYM_BYTES, HASHIN_CAP):
        raise RuntimeError("liblweot reports different Kyber-768 sizes: %r" % (got,))
    _lib = lib
    return lib


def available() -> bool:
    """True when liblweot can be loaded."""
    try:
        _load()
        return True
    except RuntimeError:
        return False


def _in(b: bytes, n: int, what: str):
    if not isinstance(b, (bytes, bytearray)) or len(b) != n:
        raise ValueError("lattice: %s must be exactly %d bytes" % (what, n))
    buf = (C.c_ubyte * n).from_buffer_copy(bytes(b))
    return buf, n


def _out(n: int):
    return (C.c_ubyte * n)()


def _ok(rc: int, op: str) -> None:
    if rc != 0:
        raise RuntimeError("lattice: %s refused (%d)" % (op, rc))


def kpke_keygen(seed: bytes) -> Tuple[bytes, bytes]:
    """(public key, secret key) of Kyber-768 K-PKE, deterministic in the 32-byte seed."""
    s, sn = _in(seed, SYM_BYTES, "seed")
    pk, sk = _out(PK_BYTES), _out(SK_BYTES)
    _ok(_load().lweot_kpke_keygen(s, sn, pk, PK_BYTES, sk, SK_BYTES), "keygen")
    return bytes(pk), bytes(sk)


def kpke_keygen_fips203(seed: bytes) -> Tuple[bytes, bytes]:
    """(public key, secret key) exactly as FIPS 203 Algorithm 13 derives K-PKE.KeyGen(d): the derivation the endemic receiver uses."""
    s, sn = _in(seed, SYM_BYTES, "seed")
    pk, sk = _out(PK_BYTES), _out(SK_BYTES)
    _ok(_load().lweot_kpke_keygen_fips203(s, sn, pk, PK_BYTES, sk, SK_BYTES), "keygen (FIPS 203)")
    return bytes(pk), bytes(sk)


def kpke_enc(public_key: bytes, message: bytes, coins: bytes) -> bytes:
    p, pn = _in(public_key, PK_BYTES, "public key")
    m, mn = _in(message, SYM_BYTES, "message")
    c, cn = _in(coins, SYM_BYTES, "coins")
    ct = _out(CT_BYTES)
    _ok(_load().lweot_kpke_enc(p, pn, m, mn, c, cn, ct, CT_BYTES), "enc")
    return bytes(ct)


def kpke_dec(secret_key: bytes, ciphertext: bytes) -> bytes:
    s, sn = _in(secret_key, SK_BYTES, "secret key")
    c, cn = _in(ciphertext, CT_BYTES, "ciphertext")
    msg = _out(SYM_BYTES)
    _ok(_load().lweot_kpke_dec(s, sn, c, cn, msg, SYM_BYTES), "dec")
    return bytes(msg)


def ring_add(a: bytes, b: bytes) -> bytes:
    x, xn = _in(a, TVEC_BYTES, "a")
    y, yn = _in(b, TVEC_BYTES, "b")
    o = _out(TVEC_BYTES)
    _ok(_load().lweot_ring_add(x, xn, y, yn, o, TVEC_BYTES), "ring add")
    return bytes(o)


def ring_sub(a: bytes, b: bytes) -> bytes:
    x, xn = _in(a, TVEC_BYTES, "a")
    y, yn = _in(b, TVEC_BYTES, "b")
    o = _out(TVEC_BYTES)
    _ok(_load().lweot_ring_sub(x, xn, y, yn, o, TVEC_BYTES), "ring sub")
    return bytes(o)


def hash_to_ring(data: bytes) -> bytes:
    """SHAKE128 then the FIPS 203 SampleNTT sampler: a uniform ring vector. At most 4096 input bytes."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > HASHIN_CAP:
        raise ValueError("lattice: hash input must be at most %d bytes" % HASHIN_CAP)
    buf = (C.c_ubyte * max(len(data), 1)).from_buffer_copy(bytes(data) or b"\0")
    o = _out(TVEC_BYTES)
    _ok(_load().lweot_hash_to_ring(buf, len(data), o, TVEC_BYTES), "hash to ring")
    return bytes(o)


# ---- randomness ------------------------------------------------------------------------------------------------------------------------

class OtRandom:
    """The CSPRNG-backed default; ``bytes(n)`` returns n random bytes."""

    def bytes(self, n: int) -> bytes:
        return secrets.token_bytes(n)


class SplitMix64(OtRandom):
    """A deterministic SplitMix64 stream (reproducible tests only)."""

    def __init__(self, seed: int):
        self._s = seed & 0xFFFFFFFFFFFFFFFF

    def _next(self) -> int:
        m = 0xFFFFFFFFFFFFFFFF
        self._s = (self._s + 0x9E3779B97F4A7C15) & m
        z = self._s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & m
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & m
        return z ^ (z >> 31)

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            v = self._next()
            for _ in range(8):
                if len(out) < n:
                    out.append(v & 0xFF)
                v >>= 8
        return bytes(out)


# ---- the protocol ----------------------------------------------------------------------------------------------------------------------

def _u32(x: int) -> bytes:
    return (x & 0xFFFFFFFF).to_bytes(4, "big")


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("endemic-ot: XOR length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def session_id(rn: bytes) -> bytes:
    """``sid = H(TAG || rn)``: binds every oracle query to this receiver nonce."""
    return sha256(_TAG_SID + rn).digest()


def _hpk(sid: bytes, i: int, other: bytes) -> bytes:
    return hash_to_ring(_TAG_HPK + sid + _u32(i) + other)


def pad(sid: bytes, index: int, slot: int, payload: bytes, length: int) -> bytes:
    """The pad for a slot: SHA-256 in counter mode over ``TAG || sid || i || slot || ctr || payload``."""
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out += sha256(_TAG_PAD + sid + _u32(index) + bytes([slot & 1]) + _u32(ctr) + payload).digest()
        ctr += 1
    return bytes(out[:length])


def _commit(sid: bytes, i: int, slot: int, msg: bytes, pd: bytes) -> bytes:
    return sha256(_TAG_COMMIT + sid + _u32(i) + bytes([slot & 1]) + msg + pd).digest()


@dataclass(frozen=True)
class ReceiverMessage:
    rn: bytes
    points: List[Tuple[bytes, bytes]]
    rhos: List[bytes]


@dataclass(frozen=True)
class ReceiverState:
    choices: List[int]
    secret_keys: List[bytes]
    rhos: List[bytes]
    rn: bytes
    sid: bytes


@dataclass(frozen=True)
class SenderMessage:
    ciphertexts: List[Tuple[bytes, bytes]]
    sender_pads: List[Tuple[bytes, bytes]]


@dataclass(frozen=True)
class Transcript:
    rn: bytes
    points: List[Tuple[bytes, bytes]]
    rhos: List[bytes]
    ciphertexts: List[Tuple[bytes, bytes]]
    encrypted: List[Tuple[bytes, bytes]]
    commitments: List[Tuple[bytes, bytes]]


def receive(choices: Sequence[int], rng: Optional[OtRandom] = None) -> Tuple[ReceiverMessage, ReceiverState]:
    """Receiver round: a real key pair per choice, a uniform vector for the other slot, and ``C = t_real - Hpk(sid, i, N)`` at the choice slot."""
    rng = rng or OtRandom()
    rn = rng.bytes(SYM_BYTES)
    sid = session_id(rn)
    points: List[Tuple[bytes, bytes]] = []
    rhos: List[bytes] = []
    sks: List[bytes] = []
    kept: List[int] = []
    for i, ch in enumerate(choices):
        c = ch & 1
        pk, sk = kpke_keygen_fips203(rng.bytes(SYM_BYTES))
        n_slot = hash_to_ring(_TAG_N + sid + _u32(i) + rng.bytes(SYM_BYTES))
        c_point = ring_sub(pk[:TVEC_BYTES], _hpk(sid, i, n_slot))
        points.append((c_point, n_slot) if c == 0 else (n_slot, c_point))
        rhos.append(pk[TVEC_BYTES:])
        sks.append(sk)
        kept.append(c)
    return ReceiverMessage(rn, points, rhos), ReceiverState(kept, sks, rhos, rn, sid)


def _validate(m: ReceiverMessage) -> None:
    ok = lambda b, n: isinstance(b, (bytes, bytearray)) and len(b) == n  # noqa: E731
    if not ok(getattr(m, "rn", None), SYM_BYTES):
        raise EndemicAbort("endemic LWE OT: malformed session nonce")
    if not isinstance(m.points, (list, tuple)) or not isinstance(m.rhos, (list, tuple)) or len(m.points) != len(m.rhos):
        raise EndemicAbort("endemic LWE OT: points/rhos length mismatch")
    for i, (pt, rho) in enumerate(zip(m.points, m.rhos)):
        if not isinstance(pt, (list, tuple)) or len(pt) != 2 or not ok(pt[0], TVEC_BYTES) or not ok(pt[1], TVEC_BYTES):
            raise EndemicAbort("endemic LWE OT: malformed point pair at index %d" % i)
        if not ok(rho, PK_BYTES - TVEC_BYTES):
            raise EndemicAbort("endemic LWE OT: malformed rho at index %d" % i)


def send_random(message: ReceiverMessage, rng: Optional[OtRandom] = None,
                tamper: Optional[Callable[[list], None]] = None) -> SenderMessage:
    """Sender round (random-OT form): encrypt a fresh payload under each slot's effective key and output both pads. ``tamper`` is test-only."""
    rng = rng or OtRandom()
    _validate(message)
    sid = session_id(message.rn)
    cts: list = []
    pads: List[Tuple[bytes, bytes]] = []
    for i, ((p0, p1), rho) in enumerate(zip(message.points, message.rhos)):
        pk0 = ring_add(p0, _hpk(sid, i, p1)) + rho
        pk1 = ring_add(p1, _hpk(sid, i, p0)) + rho
        r0, r1 = rng.bytes(SYM_BYTES), rng.bytes(SYM_BYTES)
        ct0 = kpke_enc(pk0, r0, rng.bytes(SYM_BYTES))
        ct1 = kpke_enc(pk1, r1, rng.bytes(SYM_BYTES))
        cts.append([ct0, ct1])
        pads.append((pad(sid, i, 0, r0, ENDEMIC_SECRET_BYTES), pad(sid, i, 1, r1, ENDEMIC_SECRET_BYTES)))
    if tamper is not None:
        tamper(cts)
    return SenderMessage([(a, b) for a, b in cts], pads)


def recover_random(state: ReceiverState, sm: SenderMessage) -> List[bytes]:
    """Receiver recovery (random-OT form): decrypt only the chosen ciphertext."""
    cts = getattr(sm, "ciphertexts", None)
    if not isinstance(cts, (list, tuple)) or len(cts) != len(state.choices):
        raise EndemicAbort("endemic LWE OT: ciphertext count does not match the transfer count")
    for i, ct in enumerate(cts):
        if (not isinstance(ct, (list, tuple)) or len(ct) != 2 or not isinstance(ct[0], (bytes, bytearray)) or not isinstance(ct[1], (bytes, bytearray))
                or len(ct[0]) != CT_BYTES or len(ct[1]) != CT_BYTES):
            raise EndemicAbort("endemic LWE OT: malformed ciphertext pair at index %d" % i)
    return [pad(state.sid, i, c & 1, kpke_dec(state.secret_keys[i], cts[i][c & 1]), ENDEMIC_SECRET_BYTES) for i, c in enumerate(state.choices)]


def base_ot(messages: Sequence[Tuple[bytes, bytes]], choices: Sequence[int], rng: Optional[OtRandom] = None,
            sender_rng: Optional[OtRandom] = None, tamper_encrypted: Optional[Callable[[list], None]] = None) -> Tuple[List[bytes], Transcript]:
    """In-process chosen-message endemic base OT; returns (received, transcript). ``rng`` is the receiver's stream (and the sender's unless
    ``sender_rng`` is given); ``tamper_encrypted`` (test-only) corrupts the padded messages on the wire."""
    if len(messages) != len(choices):
        raise ValueError("endemic_base_ot: messages/choices length mismatch")
    rrng = rng or OtRandom()
    srng = sender_rng or rrng
    msg, state = receive(choices, rrng)
    sid = state.sid
    cts, enc, com = [], [], []
    for i, (m0, m1) in enumerate(messages):
        if len(m0) != len(m1):
            raise ValueError("endemic_base_ot (index %d): the two messages must be equal length" % i)
        (p0, p1), rho = msg.points[i], msg.rhos[i]
        r0, r1 = srng.bytes(SYM_BYTES), srng.bytes(SYM_BYTES)
        ct0 = kpke_enc(ring_add(p0, _hpk(sid, i, p1)) + rho, r0, srng.bytes(SYM_BYTES))
        ct1 = kpke_enc(ring_add(p1, _hpk(sid, i, p0)) + rho, r1, srng.bytes(SYM_BYTES))
        cts.append((ct0, ct1))
        pad0, pad1 = pad(sid, i, 0, r0, len(m0)), pad(sid, i, 1, r1, len(m1))
        enc.append([_xor(m0, pad0), _xor(m1, pad1)])
        com.append((_commit(sid, i, 0, m0, pad0), _commit(sid, i, 1, m1, pad1)))
    if tamper_encrypted is not None:
        tamper_encrypted(enc)
    received: List[bytes] = []
    for i, ch in enumerate(choices):
        c = ch & 1
        payload = kpke_dec(state.secret_keys[i], cts[i][c])
        e = enc[i][c]
        pd = pad(sid, i, c, payload, len(e))
        m = _xor(e, pd)
        if not hmac.compare_digest(_commit(sid, i, c, m, pd), com[i][c]):
            raise EndemicAbort("endemic base OT (index %d): sender ciphertext inconsistent with its commitment; aborting" % i)
        received.append(m)
    return received, Transcript(msg.rn, msg.points, msg.rhos, cts, [(a, b) for a, b in enc], com)


def with_endemic_base_ot() -> Callable[[list, list, OtRandom], List[bytes]]:
    """The endemic base OT as a pluggable base OT: ``(messages, choices, rng) -> received``, for ``mpc_ot.OtChannel(rng, base_ot_fn)`` and
    ``compose_secure_malicious(..., base_ot_fn=...)``. The rng only needs ``bytes(n)`` (the OT stack's own source qualifies)."""
    return lambda messages, choices, rng: base_ot([(m[0], m[1]) for m in messages], choices, rng)[0]
