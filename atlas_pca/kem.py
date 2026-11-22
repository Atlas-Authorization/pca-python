"""Hybrid post-quantum key encapsulation: X25519 + ML-KEM-768 and -1024 through a custom HKDF-SHA256 combiner, the X-Wing KEM
(draft-connolly-cfrg-xwing-kem-09, SHA3-256 combiner) and the FIPS 203 section 7.2 / 7.3 key checks for imported ML-KEM keys.

Each family establishes a 32-byte shared secret and ships no cipher: use the result as the key of an AEAD you already trust. Every input is
length-checked and fails closed (ValueError / TypeError). ML-KEM comes from OpenSSL >= 3.5 through ctypes (atlas_pca.mpc_libcrypto: seeded key
generation, derandomised encapsulation, expanded decapsulation-key import), X25519 from libsodium through pysodium (an all-zero shared secret,
the result of a low-order point, is refused), SHA3 / SHAKE from hashlib and HKDF from the standard library's HMAC."""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Any, Optional

from ._hkdf import hkdf_sha256
from .mpc_libcrypto import MlKem1024, MlKem768Level, MlKemLevel, shake256
from .pca import b64u, decode_b64u_strict

_X25519_LEN = 32
_MLKEM_PK_LEN = 1184
_MLKEM_CT_LEN = 1088
_SS_LEN = 32

HYBRID_PUBLIC_KEY_LEN = _X25519_LEN + _MLKEM_PK_LEN  # 1216
HYBRID_CIPHERTEXT_LEN = _X25519_LEN + _MLKEM_CT_LEN  # 1120
HYBRID_SHARED_SECRET_LEN = _SS_LEN
HYBRID_KEM_SUITE = "x25519-ml-kem-768"

XWING_SUITE = "xwing"
XWING_SEED_LEN = 32
XWING_SECRET_KEY_LEN = XWING_SEED_LEN
XWING_PUBLIC_KEY_LEN = _MLKEM_PK_LEN + _X25519_LEN  # 1216
XWING_CIPHERTEXT_LEN = _MLKEM_CT_LEN + _X25519_LEN  # 1120
XWING_SHARED_SECRET_LEN = _SS_LEN
XWING_ESEED_LEN = 64
XWING_LABEL = bytes([0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C])  # ASCII \.//^\

HYBRID1024_PUBLIC_KEY_LEN = _X25519_LEN + 1568  # 1600
HYBRID1024_CIPHERTEXT_LEN = _X25519_LEN + 1568  # 1600
HYBRID1024_SHARED_SECRET_LEN = _SS_LEN
HYBRID1024_KEM_SUITE = "x25519-ml-kem-1024"


@dataclass(frozen=True)
class HybridKemKeyPair:
    public_key: bytes  # X25519 public (32) || ML-KEM encapsulation key
    secret_key: bytes  # X25519 secret (32) || expanded ML-KEM decapsulation key


@dataclass(frozen=True)
class HybridEncapsulation:
    ciphertext: bytes  # ephemeral X25519 public (32) || ML-KEM ciphertext
    shared_secret: bytes


@dataclass(frozen=True)
class XWingKeyPair:
    secret_key: bytes  # the 32-byte seed
    public_key: bytes  # pk_M || pk_X


@dataclass(frozen=True)
class XWingEncapsulation:
    ciphertext: bytes  # ct_M || ct_X
    shared_secret: bytes


# ---- primitives -----------------------------------------------------------------------------------------------------------------

_lib: Any = None


def _sodium() -> Any:
    global _lib
    if _lib is None:
        try:
            from ._sodium_path import prefer_bundled
            with prefer_bundled():
                import pysodium
        except ImportError as e:
            raise RuntimeError("the hybrid KEM needs libsodium through pysodium") from e
        lib = pysodium.sodium
        if lib.sodium_init() < 0:
            raise RuntimeError("libsodium failed to initialise")
        _lib = lib
    return _lib


def _x25519_base(secret: bytes) -> bytes:
    q = ctypes.create_string_buffer(32)
    if _sodium().crypto_scalarmult_curve25519_base(q, bytes(secret)) != 0:
        raise ValueError("x25519: public key derivation refused")
    return q.raw


def _x25519(secret: bytes, peer: bytes) -> bytes:
    """The X25519 shared secret; a low-order peer point (an all-zero result) is refused."""
    q = ctypes.create_string_buffer(32)
    if _sodium().crypto_scalarmult_curve25519(q, bytes(secret), bytes(peer)) != 0 or q.raw == bytes(32):
        raise ValueError("x25519: degenerate shared secret (low-order point)")
    return q.raw


def _bytes(v: Any, who: str) -> bytes:
    if not isinstance(v, (bytes, bytearray, memoryview)):
        raise TypeError("%s: expected bytes" % who)
    return bytes(v)


def _cat(*parts: bytes) -> bytes:
    return b"".join(parts)


def _reduced(ek: bytes, k: int) -> bool:
    """FIPS 203 7.2 modulus check: every 12-bit coefficient of the 384*k-byte t part is below q = 3329."""
    for i in range(0, 384 * k, 3):
        a, b, c = ek[i], ek[i + 1], ek[i + 2]
        if (a | ((b & 0x0F) << 8)) >= 3329 or ((b >> 4) | (c << 4)) >= 3329:
            return False
    return True


def _require_reduced(ek: bytes, k: int, who: str) -> None:
    if not _reduced(ek, k):
        raise ValueError("%s: ML-KEM encapsulation key fails the FIPS 203 modulus check" % who)


# ---- hybrid X25519 + ML-KEM -----------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Suite:
    level: MlKemLevel
    domain: bytes
    pk_len: int
    ct_len: int


_S768 = _Suite(MlKem768Level, b"atlas-pca/kem/x25519-ml-kem-768/v1\0", HYBRID_PUBLIC_KEY_LEN, HYBRID_CIPHERTEXT_LEN)
_S1024 = _Suite(MlKem1024, b"atlas-pca/kem/x25519-ml-kem-1024/v1\0", HYBRID1024_PUBLIC_KEY_LEN, HYBRID1024_CIPHERTEXT_LEN)


def _combine(s: _Suite, ss_mlkem: bytes, ss_x: bytes, eph_pub: bytes, recip_x: bytes) -> bytes:
    return hkdf_sha256(_cat(ss_mlkem, ss_x, eph_pub, recip_x), None, s.domain, _SS_LEN)


def _hybrid_keygen(s: _Suite, rng: bytes) -> HybridKemKeyPair:
    """rng = X25519 secret (32) || ML-KEM seed d (32) || z (32): the draw order of the randomised entry point."""
    rng = _bytes(rng, "hybrid keygen")
    if len(rng) != 96:
        raise ValueError("hybrid keygen: the random stream must be 96 bytes")
    x, dz = rng[:32], rng[32:]
    pair = s.level.keygen(dz)
    return HybridKemKeyPair(_cat(_x25519_base(x), pair.public_key), _cat(x, s.level.secret_key_bytes(pair.secret_key)))


def _hybrid_encapsulate(s: _Suite, public_key: Any, rng: bytes, who: str) -> HybridEncapsulation:
    """rng = ephemeral X25519 secret (32) || ML-KEM message m (32)."""
    pk = _bytes(public_key, who)
    if len(pk) != s.pk_len:
        raise ValueError("%s: public key must be %d bytes (got %d)" % (who, s.pk_len, len(pk)))
    if len(rng) != 64:
        raise ValueError("%s: the random stream must be 64 bytes" % who)
    recip_x, recip_ml = pk[:_X25519_LEN], pk[_X25519_LEN:]
    eph_priv, m = rng[:32], rng[32:]
    eph_pub = _x25519_base(eph_priv)
    ss_x = _x25519(eph_priv, recip_x)
    _require_reduced(recip_ml, s.level.k, who)
    enc = s.level.encapsulate(recip_ml, m)
    return HybridEncapsulation(_cat(eph_pub, enc.cipher_text), _combine(s, enc.shared_secret, ss_x, eph_pub, recip_x))


def _hybrid_decapsulate(s: _Suite, ciphertext: Any, secret_key: Any, who: str) -> bytes:
    ct = _bytes(ciphertext, who)
    sk = _bytes(secret_key, who)
    if len(ct) != s.ct_len:
        raise ValueError("%s: ciphertext must be %d bytes (got %d)" % (who, s.ct_len, len(ct)))
    if len(sk) <= _X25519_LEN:
        raise ValueError("%s: malformed secret key" % who)
    if len(sk) != _X25519_LEN + s.level.DK_BYTES:
        raise ValueError("%s: secret key must be %d bytes (got %d)" % (who, _X25519_LEN + s.level.DK_BYTES, len(sk)))
    eph_pub, mlkem_ct = ct[:_X25519_LEN], ct[_X25519_LEN:]
    x_priv = sk[:_X25519_LEN]
    ss_x = _x25519(x_priv, eph_pub)
    ss_mlkem = s.level.decapsulate(mlkem_ct, s.level.import_secret_key(sk[_X25519_LEN:]))
    return _combine(s, ss_mlkem, ss_x, eph_pub, _x25519_base(x_priv))


def hybrid_kem_keygen() -> HybridKemKeyPair:
    """A hybrid X25519 + ML-KEM-768 recipient key pair."""
    return _hybrid_keygen(_S768, os.urandom(96))


def hybrid_encapsulate(recipient_public_key: bytes) -> HybridEncapsulation:
    """Encapsulate to a recipient public key: the ciphertext to send and the shared secret to keep."""
    return _hybrid_encapsulate(_S768, recipient_public_key, os.urandom(64), "hybrid_encapsulate")


def hybrid_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Recover the shared secret with the recipient secret key."""
    return _hybrid_decapsulate(_S768, ciphertext, secret_key, "hybrid_decapsulate")


def hybrid_kem1024_keygen() -> HybridKemKeyPair:
    """A hybrid X25519 + ML-KEM-1024 recipient key pair (NIST category 5)."""
    return _hybrid_keygen(_S1024, os.urandom(96))


def hybrid_encapsulate1024(recipient_public_key: bytes) -> HybridEncapsulation:
    return _hybrid_encapsulate(_S1024, recipient_public_key, os.urandom(64), "hybrid_encapsulate1024")


def hybrid_decapsulate1024(ciphertext: bytes, secret_key: bytes) -> bytes:
    return _hybrid_decapsulate(_S1024, ciphertext, secret_key, "hybrid_decapsulate1024")


# ---- X-Wing (draft-connolly-cfrg-xwing-kem-09) -----------------------------------------------------------------------------------

def _xwing_expand(seed: Any):
    """SHAKE256(seed, 96) = d (32) || z (32) || sk_X (32): (ML-KEM key pair from d || z, sk_X, pk_X)."""
    seed = _bytes(seed, "xwing")
    if len(seed) != XWING_SEED_LEN:
        raise ValueError("xwing: seed must be %d bytes (got %d)" % (XWING_SEED_LEN, len(seed)))
    expanded = shake256(seed, 96)
    pair = MlKem768Level.keygen(expanded[:64])
    x_secret = expanded[64:]
    return pair, x_secret, _x25519_base(x_secret)


def _xwing_combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(_cat(ss_m, ss_x, ct_x, pk_x, XWING_LABEL)).digest()


def xwing_keygen(seed: Optional[bytes] = None) -> XWingKeyPair:
    """An X-Wing key pair; without `seed` a fresh 32-byte seed is drawn from the system CSPRNG. The secret key is the seed."""
    sk = os.urandom(XWING_SEED_LEN) if seed is None else _bytes(seed, "xwing_keygen")
    pair, _x_secret, x_pub = _xwing_expand(sk)
    return XWingKeyPair(sk, _cat(pair.public_key, x_pub))


def xwing_encapsulate_derand(recipient_public_key: bytes, eseed: bytes) -> XWingEncapsulation:
    """Derandomised encapsulation: eseed (64 bytes) = ML-KEM message m (32) || X25519 ephemeral secret (32)."""
    pk = _bytes(recipient_public_key, "xwing_encapsulate_derand")
    es = _bytes(eseed, "xwing_encapsulate_derand")
    if len(pk) != XWING_PUBLIC_KEY_LEN:
        raise ValueError("xwing_encapsulate_derand: public key must be %d bytes (got %d)" % (XWING_PUBLIC_KEY_LEN, len(pk)))
    if len(es) != XWING_ESEED_LEN:
        raise ValueError("xwing_encapsulate_derand: eseed must be %d bytes (got %d)" % (XWING_ESEED_LEN, len(es)))
    pk_m, pk_x = pk[:_MLKEM_PK_LEN], pk[_MLKEM_PK_LEN:]
    m, ek_x = es[:32], es[32:]
    _require_reduced(pk_m, 3, "xwing_encapsulate_derand")
    enc = MlKem768Level.encapsulate(pk_m, m)
    ct_x = _x25519_base(ek_x)
    ss_x = _x25519(ek_x, pk_x)
    return XWingEncapsulation(_cat(enc.cipher_text, ct_x), _xwing_combiner(enc.shared_secret, ss_x, ct_x, pk_x))


def xwing_encapsulate(recipient_public_key: bytes) -> XWingEncapsulation:
    """Encapsulate to an X-Wing public key with fresh randomness."""
    return xwing_encapsulate_derand(recipient_public_key, os.urandom(XWING_ESEED_LEN))


def xwing_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Recover the shared secret with the 32-byte seed secret key."""
    ct = _bytes(ciphertext, "xwing_decapsulate")
    if len(ct) != XWING_CIPHERTEXT_LEN:
        raise ValueError("xwing_decapsulate: ciphertext must be %d bytes (got %d)" % (XWING_CIPHERTEXT_LEN, len(ct)))
    pair, x_secret, x_pub = _xwing_expand(secret_key)
    ct_m, ct_x = ct[:_MLKEM_CT_LEN], ct[_MLKEM_CT_LEN:]
    ss_m = MlKem768Level.decapsulate(ct_m, pair.secret_key)
    ss_x = _x25519(x_secret, ct_x)
    return _xwing_combiner(ss_m, ss_x, ct_x, x_pub)


# ---- b64url wire form ------------------------------------------------------------------------------------------------------------

def _encode(v: Any) -> str:
    return b64u(_bytes(v, "encode"))


def _decode(s: Any) -> bytes:
    raw = decode_b64u_strict(s)
    if raw is None:
        raise ValueError("invalid base64url")
    return raw


encode_hybrid_public_key = _encode
decode_hybrid_public_key = _decode
encode_hybrid_ciphertext = _encode
decode_hybrid_ciphertext = _decode
encode_xwing_public_key = _encode
decode_xwing_public_key = _decode
encode_xwing_ciphertext = _encode
decode_xwing_ciphertext = _decode


# ---- FIPS 203 7.2 / 7.3 checks for imported keys ----------------------------------------------------------------------------------

def _level_k(level: Any) -> int:
    if isinstance(level, float) and level.is_integer():
        level = int(level)
    if isinstance(level, bool) or not isinstance(level, (int, str)) or str(level) not in ("768", "1024"):
        raise ValueError("unknown ML-KEM level")
    return 3 if str(level) == "768" else 4


def ml_kem_encapsulation_key_check(level: Any, ek: Any) -> bool:
    """FIPS 203 7.2 type and modulus check of an encapsulation key: False for a wrong length or a non-reduced coefficient; an unknown level raises."""
    k = _level_k(level)
    if not isinstance(ek, (bytes, bytearray)) or len(ek) != 384 * k + 32:
        return False
    return _reduced(bytes(ek), k)


def ml_kem_decapsulation_key_check(level: Any, dk: Any) -> bool:
    """FIPS 203 7.3 check of a decapsulation key: length, embedded H(ek), and the embedded key's modulus check. An unknown level raises."""
    k = _level_k(level)
    if not isinstance(dk, (bytes, bytearray)) or len(dk) != 768 * k + 96:
        return False
    dk = bytes(dk)
    ek, h = dk[384 * k:768 * k + 32], dk[768 * k + 32:768 * k + 64]
    return hmac.compare_digest(hashlib.sha3_256(ek).digest(), h) and _reduced(ek, k)
