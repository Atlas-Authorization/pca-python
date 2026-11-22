"""The per-suite post-quantum public surface (the TypeScript ``pq``): size constants, deterministic key generation from a seed, raw and
base64url verification, public-key encoders, the pinned-key and well-formed-key guards, suite signing helpers, the LESS backend probe and
LAMPS composite signatures (ML-DSA-65 + Ed25519). Backends: OpenSSL >= 3.5 through ctypes (ML-DSA, SLH-DSA), ``dilithium-py`` (ML-DSA), the
registered FN-DSA backend (:mod:`atlas_pca.fndsa`) and the ``pca-less-c`` library (LESS); a suite without a backend raises ``UnsupportedSuite``
on keygen and signs nothing, and its verify returns False (never raises). A key pair is an :mod:`atlas_pca.agent` key-pair object
(``public``, ``public_bytes``, ``sign(msg)``)."""
from typing import Any, Dict, Optional

from . import pq_backends
from .agent import PqKeyPair, UnsupportedSuite, generate_pq_keypair
from .ed25519 import verify as _ed_verify
from .pca import _SIG_SUITES, PQ_PK_LENGTHS, PinnedPqKey, b64u, decode_b64u_strict, sha256
from .pq_backends import LESS_SEED_BYTES, LESS_SECRET_KEY_BYTES, LESS_SIGNATURE_STEP_BYTES

import hashlib

__all__ = ["ML_DSA_65_SEED_BYTES", "ML_DSA_87_SEED_BYTES", "SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES", "SLH_DSA_SHA2_128F_SECRET_KEY_BYTES",
           "SLH_DSA_SHA2_128F_SIGNATURE_BYTES", "SLH_DSA_SHA2_128F_SEED_BYTES", "SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES",
           "SLH_DSA_SHA2_256S_SECRET_KEY_BYTES", "SLH_DSA_SHA2_256S_SIGNATURE_BYTES", "SLH_DSA_SHA2_256S_SEED_BYTES",
           "FN_DSA_512_SECRET_KEY_BYTES", "FN_DSA_1024_SECRET_KEY_BYTES", "FN_DSA_SEED_BYTES", "LESS_CAT1_SIGNATURE_STEP_BYTES", "LESS_SEED_BYTES",
           "COMPOSITE_PREFIX", "COMPOSITE_LABEL", "COMPOSITE_SIGNATURE_BYTES", "ml_dsa65_keygen", "ml_dsa87_keygen", "ml_dsa87_sign",
           "ml_dsa87_verify_b64u", "slh_dsa128f_keygen", "slh_dsa128f_sign", "slh_dsa128f_verify", "slh_dsa128f_verify_b64u", "slh_dsa256s_keygen",
           "slh_dsa256s_sign", "slh_dsa256s_verify", "slh_dsa256s_verify_b64u", "fn_dsa512_keygen", "fn_dsa512_sign", "fn_dsa512_verify",
           "fn_dsa512_verify_b64u", "fn_dsa1024_keygen", "fn_dsa1024_sign", "fn_dsa1024_verify", "fn_dsa1024_verify_b64u", "less_cat1_verify_b64u",
           "encode_ml_dsa_public_key", "encode_ml_dsa87_public_key", "encode_slh_dsa_public_key", "encode_slh_dsa256s_public_key",
           "encode_fn_dsa_public_key", "encode_less_public_key", "is_known_sig_alg", "is_pinned_pq_key", "is_well_formed_pq_public_key",
           "suite_pq_public_key", "suite_keys_of", "sign_suite_artifact", "is_less_backend_active", "less_backend_status",
           "composite_representative", "composite_sign", "composite_verify"]

ML_DSA_65_SEED_BYTES = 32
ML_DSA_87_SEED_BYTES = 32
SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_128F_SECRET_KEY_BYTES, SLH_DSA_SHA2_128F_SIGNATURE_BYTES, SLH_DSA_SHA2_128F_SEED_BYTES = 32, 64, 17088, 48
SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_256S_SECRET_KEY_BYTES, SLH_DSA_SHA2_256S_SIGNATURE_BYTES, SLH_DSA_SHA2_256S_SEED_BYTES = 64, 128, 29792, 96
FN_DSA_512_SECRET_KEY_BYTES, FN_DSA_1024_SECRET_KEY_BYTES, FN_DSA_SEED_BYTES = 1345, 2369, 32
LESS_CAT1_SIGNATURE_STEP_BYTES = LESS_SIGNATURE_STEP_BYTES
COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025"  # draft-ietf-lamps-pq-composite-sigs
COMPOSITE_LABEL = "COMPSIG-MLDSA65-Ed25519-SHA512"  # id-MLDSA65-Ed25519-SHA512 (OID 1.3.6.1.5.5.7.6.48)
COMPOSITE_SIGNATURE_BYTES = 3309 + 64  # ML-DSA-65 signature then the Ed25519 signature


def ml_dsa65_keygen(seed: bytes) -> Any:
    """Deterministic ML-DSA-65 key pair from a 32-byte seed (FIPS 204)."""
    return generate_pq_keypair("ML-DSA-65", bytes(seed))


def ml_dsa87_keygen(seed: bytes) -> Any:
    return generate_pq_keypair("ML-DSA-87", bytes(seed))


def slh_dsa128f_keygen(seed: bytes) -> Any:
    """Deterministic SLH-DSA-SHA2-128f key pair from a 48-byte seed (SK.seed || SK.prf || PK.seed)."""
    return generate_pq_keypair("SLH-DSA-SHA2-128f", bytes(seed))


def slh_dsa256s_keygen(seed: bytes) -> Any:
    return generate_pq_keypair("SLH-DSA-SHA2-256s", bytes(seed))


def fn_dsa512_keygen(seed: bytes) -> Any:
    """FN-DSA-512 key pair from a 32-byte seed. Raises ``UnsupportedSuite`` when no FN-DSA backend is registered."""
    return generate_pq_keypair("FN-DSA-512", bytes(seed))


def fn_dsa1024_keygen(seed: bytes) -> Any:
    return generate_pq_keypair("FN-DSA-1024", bytes(seed))


def _sign(kp: Any, msg: bytes, family: str) -> bytes:
    if not hasattr(kp, "sign") or getattr(kp, "family", family) != family:
        raise TypeError("a %s key pair is required" % family)
    return kp.sign(bytes(msg))


def ml_dsa87_sign(kp: Any, msg: bytes) -> bytes:
    """ML-DSA-87 signature (deterministic) with a key pair from :func:`ml_dsa87_keygen`."""
    return _sign(kp, msg, "ML-DSA-87")


def slh_dsa128f_sign(kp: Any, msg: bytes) -> bytes:
    return _sign(kp, msg, "SLH-DSA-SHA2-128f")


def slh_dsa256s_sign(kp: Any, msg: bytes) -> bytes:
    return _sign(kp, msg, "SLH-DSA-SHA2-256s")


def fn_dsa512_sign(kp: Any, msg: bytes) -> bytes:
    return _sign(kp, msg, "FN-DSA-512")


def fn_dsa1024_sign(kp: Any, msg: bytes) -> bytes:
    return _sign(kp, msg, "FN-DSA-1024")


def _verify(family: str, pk: Any, msg: Any, sig: Any) -> bool:
    return pq_backends.verify(family, pk, msg, sig)


def _verify_b64u(family: str, pk_b64u: Any, msg: Any, sig_b64u: Any) -> bool:
    try:
        pk, sg = decode_b64u_strict(pk_b64u, pq_backends.KEY_TYPES[family][0]), decode_b64u_strict(sig_b64u)
        return pk is not None and sg is not None and _verify(family, pk, msg, sg)
    except Exception:  # noqa: BLE001
        return False


def slh_dsa128f_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Raw verify. Never raises; a wrong length or malformed input returns False."""
    return _verify("SLH-DSA-SHA2-128f", pk, msg, sig)


def slh_dsa128f_verify_b64u(pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    return _verify_b64u("SLH-DSA-SHA2-128f", pk_b64u, msg, sig_b64u)


def slh_dsa256s_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    return _verify("SLH-DSA-SHA2-256s", pk, msg, sig)


def slh_dsa256s_verify_b64u(pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    return _verify_b64u("SLH-DSA-SHA2-256s", pk_b64u, msg, sig_b64u)


def ml_dsa87_verify_b64u(pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    return _verify_b64u("ML-DSA-87", pk_b64u, msg, sig_b64u)


def fn_dsa512_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    return _verify("FN-DSA-512", pk, msg, sig)


def fn_dsa512_verify_b64u(pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    return _verify_b64u("FN-DSA-512", pk_b64u, msg, sig_b64u)


def fn_dsa1024_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    return _verify("FN-DSA-1024", pk, msg, sig)


def fn_dsa1024_verify_b64u(pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    return _verify_b64u("FN-DSA-1024", pk_b64u, msg, sig_b64u)


def less_cat1_verify_b64u(pk_b64u: Any, msg: bytes, sig_b64u: Any) -> bool:
    """LESS cat-1 verify over base64url key and signature; False when the C library is absent or the input malformed."""
    return _verify_b64u("LESS-cat1", pk_b64u, msg, sig_b64u)


def encode_ml_dsa_public_key(pk: bytes) -> str:
    return b64u(bytes(pk))


encode_ml_dsa87_public_key = encode_slh_dsa_public_key = encode_slh_dsa256s_public_key = encode_fn_dsa_public_key = encode_less_public_key = \
    encode_ml_dsa_public_key


def is_known_sig_alg(x: Any) -> bool:
    """True for a registered signature suite name."""
    return isinstance(x, str) and x in _SIG_SUITES


def is_pinned_pq_key(x: Any) -> bool:
    """True for a key minted by the verifier's own pin resolution (never for a key read from an artifact)."""
    return isinstance(x, PinnedPqKey)


def is_well_formed_pq_public_key(pq: Any) -> bool:
    """Canonical base64url of the public-key length of some registered PQ suite."""
    if not isinstance(pq, str):
        return False
    raw = decode_b64u_strict(pq)
    return raw is not None and len(raw) in PQ_PK_LENGTHS


def suite_pq_public_key(alg: Any, pq: Any) -> Optional[str]:
    """The ``pq_pk`` a suite binds into its signed body: the base64url public key of `pq` for a PQ-carrying suite, else None."""
    spec = _SIG_SUITES.get(alg) if isinstance(alg, str) else None
    if spec is None or not spec[1] or pq is None:
        return None
    return getattr(pq, "public", None)


def suite_keys_of(ed: Any, pq: Any = None, alg: Optional[str] = None) -> Dict[str, Any]:
    """The key material of one signer: ``{"ed": ..., "pq": ..., "alg"?}``."""
    out: Dict[str, Any] = {"ed": ed, "pq": pq}
    if alg is not None:
        out["alg"] = alg
    return out


def sign_suite_artifact(alg: Any, ed: Any, pq: Any, msg: bytes) -> Dict[str, str]:
    """The signature fields of an artifact signed under `alg`: ``sig`` (and ``alg``, ``pq_pk``, ``pq_sig`` for a non-default suite). Raises on
    an unknown alg or missing key material."""
    from .agent import sign_with_suite
    parts = sign_with_suite(alg, ed, pq, msg)
    if not alg or alg == "ed25519":
        return {"sig": parts["sig"]}
    out = {"sig": parts["sig"], "alg": alg}
    pk = suite_pq_public_key(alg, pq)
    if pk is not None:
        out["pq_pk"] = pk
    if "pq_sig" in parts:
        out["pq_sig"] = parts["pq_sig"]
    return out


def is_less_backend_active() -> bool:
    """True when the pca-less-c library is loaded."""
    return pq_backends._libless() is not None


def less_backend_status() -> Dict[str, Any]:
    """``{"available": True}`` or ``{"available": False, "reason"}``. Never raises."""
    return {"available": True} if is_less_backend_active() else \
        {"available": False, "reason": "the pca-less-c library (libatlas_less) is not loaded (set ATLAS_PCA_LIBLESS or build sdks/pca-less-c)"}


# ---- LAMPS composite signatures (ML-DSA-65 + Ed25519) ------------------------------------------------------------------------

def _ctx(ctx: Any) -> bytes:
    return b"" if ctx is None else ctx.encode("utf-8") if isinstance(ctx, str) else bytes(ctx)


def composite_representative(message: bytes, ctx: Any = None) -> bytes:
    """``M' = Prefix || Label || len(ctx) || ctx || SHA-512(message)``. Raises when `ctx` exceeds 255 bytes."""
    c = _ctx(ctx)
    if len(c) > 255:
        raise ValueError("compositeRepresentative: ctx exceeds 255 bytes")
    return COMPOSITE_PREFIX.encode() + COMPOSITE_LABEL.encode() + bytes([len(c)]) + c + hashlib.sha512(bytes(message)).digest()


def composite_sign(ed25519_secret: Any, ml_dsa: Any, message: bytes, ctx: Any = None) -> bytes:
    """A composite signature ``mldsa_sig || ed25519_sig`` (3373 bytes) over the representative. `ed25519_secret` is a :class:`KeyPair`; `ml_dsa`
    an ML-DSA-65 key pair from :func:`ml_dsa65_keygen`."""
    m = composite_representative(message, ctx)
    return _sign(ml_dsa, m, "ML-DSA-65") + ed25519_secret.sign(m)


def composite_verify(ed25519_pub: bytes, ml_dsa_pub: bytes, message: bytes, signature: bytes, ctx: Any = None) -> bool:
    """FAIL-CLOSED: a wrong total length, a `ctx` over 255 bytes or either half failing returns False; BOTH halves must verify. Never raises."""
    try:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != COMPOSITE_SIGNATURE_BYTES:
            return False
        m = composite_representative(message, ctx)
        ml_ok = pq_backends.verify("ML-DSA-65", ml_dsa_pub, m, bytes(signature[:3309]))
        return ml_ok and bool(_ed_verify(bytes(ed25519_pub), m, bytes(signature[3309:])))
    except Exception:  # noqa: BLE001
        return False
