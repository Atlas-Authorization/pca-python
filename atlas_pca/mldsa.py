"""B4 post-quantum primitive: ML-DSA-65 (FIPS-204, CRYSTALS-Dilithium category 3) signature verification.

Mirrors `mlDsa65Verify` in packages/pca/src/pq.ts (which uses @noble/post-quantum's ml_dsa65). Uses the
pure-Python `dilithium-py` library (ML_DSA_65), pure mode with an empty context. Public key 1952 bytes,
signature 3309 bytes. Never raises; a wrong length / malformed input / missing library returns False.
"""
try:  # dilithium-py >= 1.0 implements FIPS-204 final (ML-DSA), interoperable with @noble/post-quantum.
    from dilithium_py.ml_dsa import ML_DSA_65 as _ML_DSA_65
except Exception:  # pragma: no cover - library unavailable
    _ML_DSA_65 = None

ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309


def ml_dsa65_available() -> bool:
    """True iff an ML-DSA-65 backend is importable."""
    return _ML_DSA_65 is not None


def ml_dsa65_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify an ML-DSA-65 signature over raw bytes (empty context). False on any error."""
    if _ML_DSA_65 is None:
        return False
    if len(pk) != ML_DSA_65_PUBLIC_KEY_BYTES or len(sig) != ML_DSA_65_SIGNATURE_BYTES:
        return False
    try:
        return bool(_ML_DSA_65.verify(pk, msg, sig))
    except Exception:
        return False
