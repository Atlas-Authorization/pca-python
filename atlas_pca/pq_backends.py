"""Post-quantum signature primitives behind the suite dispatch (packages/pca/conformance/SUITES.md).

Every primitive is PURE mode with an EMPTY context (= @noble/post-quantum in packages/pca/src/pq.ts) and exact lengths:

  * ML-DSA-65 / ML-DSA-87 (FIPS 204): the pure-Python `dilithium-py` (extra `pq`), else OpenSSL >= 3.5 libcrypto.
  * SLH-DSA-SHA2-128f / SLH-DSA-SHA2-256s (FIPS 205): OpenSSL >= 3.5 libcrypto. There is no well-maintained, audited
    pure-Python FIPS 205 implementation, so this binds the system libcrypto through ctypes: a raw public key
    (EVP_PKEY_new_raw_public_key_ex) and the one-shot EVP_DigestVerify (pure, empty context: OpenSSL's defaults).
  * LESS-cat1 (less-252-45; a NIST additional-signature round-2 candidate, not a standard): the patched reference C of
    sdks/pca-less-c, built as a shared library (`sdks/pca-less-c/build.sh`) and bound through ctypes. The signature is
    variable-length (1,153..1,329 bytes in steps of 16; `sig_len_ok`).

libcrypto discovery: ATLAS_PCA_LIBCRYPTO (one path, or several separated by os.pathsep) first, then common OpenSSL 3
locations and `ctypes.util.find_library("crypto")`. A library counts only if its provider really builds an ML-DSA-65 key
(no version-number gate); each key type is then probed the same way. `available(t)` is the runtime capability the suite
manifest (`supported_suites()`) is built from; a missing backend makes its suites `unsupported_suite`, never a silent
False. Never raises; a wrong length / unavailable backend / malformed input returns False.

libatlas_less discovery: ATLAS_PCA_LIBLESS (one path, or several separated by os.pathsep) first, then the in-repository build
(`sdks/pca-less-c/build/`) and `ctypes.util.find_library("atlas_less")`. A library counts only if it reports the
less-252-45 sizes (public key 97,484 bytes, signature 1,153..1,329 bytes).
"""
import ctypes
import ctypes.util
import glob
import os
from typing import Dict, Optional

from .mldsa import ml_dsa65_available, ml_dsa65_verify

try:  # dilithium-py >= 1.0 (FIPS 204 final)
    from dilithium_py.ml_dsa import ML_DSA_87 as _ML_DSA_87
except Exception:  # pragma: no cover - library unavailable
    _ML_DSA_87 = None

# OpenSSL key type -> (public key bytes, signature bytes).
KEY_TYPES = {
    "ML-DSA-65": (1952, 3309),
    "ML-DSA-87": (2592, 4627),
    "SLH-DSA-SHA2-128f": (32, 17088),
    "SLH-DSA-SHA2-256s": (64, 29792),
    "LESS-cat1": (97484, 1329),  # signature: the MAXIMUM; any length sig_len_ok accepts
}
LESS_SIGNATURE_MIN_BYTES = 1153
LESS_SIGNATURE_STEP_BYTES = 16


def sig_len_ok(key_type: str, n: int) -> bool:
    """`n` is a signature length of `key_type`: its fixed length, or (LESS-cat1) 1,153..1,329 in steps of 16."""
    lens = KEY_TYPES.get(key_type)
    if lens is None:
        return False
    if key_type == "LESS-cat1":
        return LESS_SIGNATURE_MIN_BYTES <= n <= lens[1] and (lens[1] - n) % LESS_SIGNATURE_STEP_BYTES == 0
    return n == lens[1]

_lib = None
_tried = False
_probed: Dict[str, bool] = {}


def _candidates():
    env = os.environ.get("ATLAS_PCA_LIBCRYPTO") or ""
    paths = [p for p in env.split(os.pathsep) if p]
    for pat in ("/opt/homebrew/opt/openssl@3/lib/libcrypto*.dylib", "/opt/homebrew/lib/libcrypto*.dylib",
                "/usr/local/opt/openssl@3/lib/libcrypto*.dylib", "/usr/lib/libcrypto.so.3",
                "/usr/lib/x86_64-linux-gnu/libcrypto.so.3", "/usr/lib/aarch64-linux-gnu/libcrypto.so.3",
                "/lib/x86_64-linux-gnu/libcrypto.so.3"):
        paths.extend(sorted(glob.glob(pat)))
    found = ctypes.util.find_library("crypto")
    if found:
        paths.append(found)
    return paths


def _bind(path: str):
    lib = ctypes.CDLL(path)
    vp, sz, cp = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p
    lib.EVP_PKEY_new_raw_public_key_ex.restype = vp
    lib.EVP_PKEY_new_raw_public_key_ex.argtypes = [vp, cp, cp, cp, sz]
    lib.EVP_MD_CTX_new.restype = vp
    lib.EVP_MD_CTX_new.argtypes = []
    lib.EVP_DigestVerifyInit_ex.restype = ctypes.c_int
    lib.EVP_DigestVerifyInit_ex.argtypes = [vp, vp, cp, vp, cp, vp, vp]
    lib.EVP_DigestVerify.restype = ctypes.c_int
    lib.EVP_DigestVerify.argtypes = [vp, cp, sz, cp, sz]
    lib.EVP_PKEY_free.restype = None
    lib.EVP_PKEY_free.argtypes = [vp]
    lib.EVP_MD_CTX_free.restype = None
    lib.EVP_MD_CTX_free.argtypes = [vp]
    return lib


def _builds(lib, key_type: str) -> bool:
    try:
        n = KEY_TYPES[key_type][0]
        k = lib.EVP_PKEY_new_raw_public_key_ex(None, key_type.encode(), None, bytes(n), n)
        if not k:
            return False
        lib.EVP_PKEY_free(k)
        return True
    except Exception:  # noqa: BLE001
        return False


def _libcrypto():
    global _lib, _tried
    if _tried:
        return _lib
    _tried = True
    for path in _candidates():
        try:
            lib = _bind(path)
        except Exception:  # noqa: BLE001 - missing file / symbols (OpenSSL < 3.0): try the next one
            continue
        if _builds(lib, "ML-DSA-65"):  # OpenSSL < 3.5 has no ML-DSA: never report it available
            _lib = lib
            return _lib
    return None


def _openssl_available(key_type: str) -> bool:
    if key_type not in _probed:
        lib = _libcrypto()
        _probed[key_type] = lib is not None and _builds(lib, key_type)
    return _probed[key_type]


def _openssl_verify(key_type: str, pk: bytes, msg: bytes, sig: bytes) -> bool:
    lib = _libcrypto()
    if lib is None or not _openssl_available(key_type):
        return False
    pkey = lib.EVP_PKEY_new_raw_public_key_ex(None, key_type.encode(), None, pk, len(pk))
    if not pkey:
        return False
    try:
        ctx = lib.EVP_MD_CTX_new()
        if not ctx:
            return False
        try:
            if lib.EVP_DigestVerifyInit_ex(ctx, None, None, None, None, pkey, None) != 1:
                return False
            return lib.EVP_DigestVerify(ctx, sig, len(sig), msg, len(msg)) == 1
        finally:
            lib.EVP_MD_CTX_free(ctx)
    finally:
        lib.EVP_PKEY_free(pkey)


_less = None
_less_tried = False


def _less_candidates():
    env = os.environ.get("ATLAS_PCA_LIBLESS") or ""
    paths = [p for p in env.split(os.pathsep) if p]
    repo_build = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pca-less-c", "build")
    for name in ("libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll"):
        paths.append(os.path.join(repo_build, name))
    found = ctypes.util.find_library("atlas_less")
    if found:
        paths.append(found)
    return paths


def _libless():
    global _less, _less_tried
    if _less_tried:
        return _less
    _less_tried = True
    sz, cp = ctypes.c_size_t, ctypes.c_char_p
    for path in _less_candidates():
        if os.sep in path and not os.path.exists(path):
            continue
        try:
            lib = ctypes.CDLL(path)
            for f in ("atlas_less_cat1_public_key_bytes", "atlas_less_cat1_signature_min_bytes", "atlas_less_cat1_signature_max_bytes"):
                getattr(lib, f).restype = sz
                getattr(lib, f).argtypes = []
            lib.atlas_less_cat1_verify.restype = ctypes.c_int
            lib.atlas_less_cat1_verify.argtypes = [cp, sz, cp, sz, cp, sz]
            sizes = (lib.atlas_less_cat1_public_key_bytes(), lib.atlas_less_cat1_signature_min_bytes(),
                     lib.atlas_less_cat1_signature_max_bytes())
        except Exception:  # noqa: BLE001 - missing file / symbols: try the next one
            continue
        if sizes == (KEY_TYPES["LESS-cat1"][0], LESS_SIGNATURE_MIN_BYTES, KEY_TYPES["LESS-cat1"][1]):
            _less = lib
            return _less
    return None


def available(key_type: str) -> bool:
    """True iff a backend for `key_type` is usable in this runtime."""
    if key_type == "LESS-cat1":
        return _libless() is not None
    if key_type == "ML-DSA-65" and ml_dsa65_available():
        return True
    if key_type == "ML-DSA-87" and _ML_DSA_87 is not None:
        return True
    return key_type in KEY_TYPES and _openssl_available(key_type)


def verify(key_type: str, pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a `key_type` signature over raw bytes (pure, empty context). Exact lengths; never raises."""
    try:
        lens: Optional[tuple] = KEY_TYPES.get(key_type)
        if lens is None or not isinstance(pk, (bytes, bytearray)) or not isinstance(sig, (bytes, bytearray)):
            return False
        if len(pk) != lens[0] or not sig_len_ok(key_type, len(sig)) or not isinstance(msg, (bytes, bytearray)):
            return False
        pk, msg, sig = bytes(pk), bytes(msg), bytes(sig)
        if key_type == "LESS-cat1":
            lib = _libless()
            return lib is not None and lib.atlas_less_cat1_verify(pk, len(pk), msg, len(msg), sig, len(sig)) == 1
        if key_type == "ML-DSA-65" and ml_dsa65_available():
            return ml_dsa65_verify(pk, msg, sig)
        if key_type == "ML-DSA-87" and _ML_DSA_87 is not None:
            return bool(_ML_DSA_87.verify(pk, msg, sig))
        return _openssl_verify(key_type, pk, msg, sig)
    except Exception:  # noqa: BLE001 - totality on hostile input
        return False
