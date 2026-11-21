"""FN-DSA (Falcon) suite registry, wire framing and the Ed25519+FN-DSA hybrid leaf composition (the TypeScript reference,
@atlasauth/pca-fndsa).

Like the reference this module carries NO Falcon arithmetic: the primitive is a pluggable backend (set_falcon_backend), so the
framing, lengths and hybrid fail-closed rules are testable without one and verification refuses until a backend is installed.
Real primitive: ``atlas_pca.fndsa_native.native_backend()`` is a ctypes backend over libfndsa (Pornin's fn-dsa 0.4.0 through a small C
library; set ATLAS_PCA_LIBFNDSA). FIPS 206 is not final, so this is a draft best guess pinned in lockstep with the TypeScript reference and
interoperates with it byte for byte. The optional liboqs ``oqs_backend`` is a clearly separate, NON-interoperable route: liboqs's
"Falcon-padded-512/1024" are the round-3 Falcon, which shares the 666/1280-byte signature lengths but is a different scheme, so its signatures
and keys will not verify against fn-dsa. It verifies only by default; signing needs allow_sign=True (its signer uses floating point and is not
advertised as constant time on every build).
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional

from . import ed25519 as _ed
from .pca import ED25519_SIGNATURE_BYTES, _verify_b64u, b64u, decode_b64u_strict, threshold_message

FN_DSA_512_PUBLIC_KEY_BYTES = 897
FN_DSA_512_SIGNATURE_BYTES = 666
FN_DSA_1024_PUBLIC_KEY_BYTES = 1793
FN_DSA_1024_SIGNATURE_BYTES = 1280

_VARIANT_PK_BYTES = {"fn-dsa-512": FN_DSA_512_PUBLIC_KEY_BYTES, "fn-dsa-1024": FN_DSA_1024_PUBLIC_KEY_BYTES}
_VARIANT_SIG_BYTES = {"fn-dsa-512": FN_DSA_512_SIGNATURE_BYTES, "fn-dsa-1024": FN_DSA_1024_SIGNATURE_BYTES}


@dataclass(frozen=True)
class FnDsaSuite:
    alg: str
    variant: str
    has_ed25519: bool
    sig_bytes: int
    needs_pq_pk: bool
    pq_pk_bytes: int
    needs_pq_sig: bool
    pq_sig_bytes: int
    fn_sig_bytes: int


def _suite(alg: str, variant: str, hybrid: bool) -> FnDsaSuite:
    pk, sig = _VARIANT_PK_BYTES[variant], _VARIANT_SIG_BYTES[variant]
    return FnDsaSuite(alg, variant, hybrid, ED25519_SIGNATURE_BYTES if hybrid else sig, True, pk, hybrid, sig if hybrid else 0, sig)


FN_DSA_SUITES: Mapping[str, FnDsaSuite] = {
    "fn-dsa-512": _suite("fn-dsa-512", "fn-dsa-512", False),
    "fn-dsa-1024": _suite("fn-dsa-1024", "fn-dsa-1024", False),
    "hybrid-ed25519-fn-dsa-512": _suite("hybrid-ed25519-fn-dsa-512", "fn-dsa-512", True),
    "hybrid-ed25519-fn-dsa-1024": _suite("hybrid-ed25519-fn-dsa-1024", "fn-dsa-1024", True),
}


def is_known_fndsa_alg(x: Any) -> bool:
    return isinstance(x, str) and x in FN_DSA_SUITES


def resolve_fndsa_alg(alg: Any) -> Optional[FnDsaSuite]:
    return FN_DSA_SUITES[alg] if is_known_fndsa_alg(alg) else None


def is_fndsa_variant(v: Any) -> bool:
    return isinstance(v, str) and v in _VARIANT_PK_BYTES


# ---- backend seam

class FalconBackend:
    """verify(pk, msg, sig) -> bool is required; sign(sk, msg) -> bytes and keygen() -> {"pk", "sk"} are optional."""

    def __init__(self, verify: Callable[[bytes, bytes, bytes], bool], sign: Optional[Callable[[bytes, bytes], bytes]] = None,
                 keygen: Optional[Callable[[], Dict[str, bytes]]] = None,
                 sign_seeded: Optional[Callable[[str, bytes, bytes, bytes], bytes]] = None,
                 keygen_seeded: Optional[Callable[[str, bytes], Dict[str, bytes]]] = None) -> None:
        """`sign_seeded(variant, sk, msg, seed32)` and `keygen_seeded(variant, seed32) -> {"pk", "sk"}` are the optional
        deterministic forms the agent-side signer uses (seeded keys, a caller-supplied signing seed)."""
        self.verify, self.sign, self.keygen = verify, sign, keygen
        self.sign_seeded, self.keygen_seeded = sign_seeded, keygen_seeded


class FnDsaBackendMissing(RuntimeError):
    """No FN-DSA backend is installed (or the optional library behind oqs_backend is absent)."""


NO_FN_DSA_BACKEND_MESSAGE = "no FN-DSA backend registered: supply one via set_falcon_backend() (for example fndsa_native.native_backend())"


def _no_backend(*_a: Any) -> Any:
    raise FnDsaBackendMissing(NO_FN_DSA_BACKEND_MESSAGE)


_DEFAULT_BACKEND = FalconBackend(_no_backend, _no_backend, _no_backend)
_current: FalconBackend = _DEFAULT_BACKEND


def set_falcon_backend(backend: FalconBackend) -> None:
    global _current
    _current = backend


def get_falcon_backend() -> FalconBackend:
    return _current


def reset_falcon_backend() -> None:
    global _current
    _current = _DEFAULT_BACKEND


def oqs_backend(allow_sign: bool = False) -> FalconBackend:
    """A backend over liboqs-python's padded Falcon (round-3 Falcon, see the module note). The variant follows the public-key length."""
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001 - ImportError, or the liboqs shared library failing to load
        raise FnDsaBackendMissing("oqs_backend needs the optional `liboqs-python` package and the liboqs shared library") from e
    names = {FN_DSA_512_PUBLIC_KEY_BYTES: "Falcon-padded-512", FN_DSA_1024_PUBLIC_KEY_BYTES: "Falcon-padded-1024"}
    enabled = set(oqs.get_enabled_sig_mechanisms())
    for n in names.values():
        if n not in enabled:
            raise FnDsaBackendMissing("the installed liboqs does not enable %s" % n)

    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        name = names.get(len(pk))
        if name is None:
            return False
        with oqs.Signature(name) as s:
            return bool(s.verify(msg, sig, pk))

    def sign(sk: bytes, msg: bytes) -> bytes:
        # liboqs picks the variant by secret-key length: Falcon-512 is 1281 bytes, Falcon-1024 is 2305
        name = {1281: "Falcon-padded-512", 2305: "Falcon-padded-1024"}.get(len(sk))
        if name is None:
            raise ValueError("oqs_backend: unrecognised FN-DSA secret-key length")
        with oqs.Signature(name, secret_key=bytes(sk)) as s:
            return bytes(s.sign(msg))

    return FalconBackend(verify, sign if allow_sign else None)


def _is_bytes(v: Any) -> bool:
    return isinstance(v, (bytes, bytearray))


def fndsa_sign(variant: Any, sk: Any, msg: Any) -> bytes:
    if not is_fndsa_variant(variant):
        raise ValueError("fndsaSign: unknown FN-DSA variant %r" % (variant,))
    if not _is_bytes(sk) or len(sk) == 0:
        raise TypeError("fndsaSign: secret key must be a non-empty byte string")
    if not _is_bytes(msg):
        raise TypeError("fndsaSign: message must be bytes")
    backend = _current
    if not callable(backend.sign):
        raise RuntimeError("fndsaSign: FN-DSA backend is verify-only (no sign())")
    sig = backend.sign(bytes(sk), bytes(msg))
    expected = _VARIANT_SIG_BYTES[variant]
    if not _is_bytes(sig) or len(sig) != expected:
        raise RuntimeError("fndsaSign: FN-DSA backend returned a bad signature; expected padded %d bytes for '%s'" % (expected, variant))
    return bytes(sig)


def fndsa_verify(variant: Any, pk: Any, msg: Any, sig: Any) -> bool:
    """False for any length / type violation (before the backend is consulted); a backend that raises propagates."""
    if not is_fndsa_variant(variant):
        return False
    if not _is_bytes(pk) or len(pk) != _VARIANT_PK_BYTES[variant]:
        return False
    if not _is_bytes(sig) or len(sig) != _VARIANT_SIG_BYTES[variant]:
        return False
    if not _is_bytes(msg):
        return False
    return _current.verify(bytes(pk), bytes(msg), bytes(sig)) is True


# ---- hybrid leaf composition

FN_DSA_LEAF_DOMAIN = b"atlas-pca/fn-dsa/leaf/v1\x00"


def _utf8(s: str) -> bytes:
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def fndsa_leaf_message(leaf: Any, alg: str, pq_pk_b64u: str) -> bytes:
    """threshold_message(leaf) || domain || alg || 0x00 || the base64url FN-DSA public key text (alg and key are bound)."""
    if not isinstance(alg, str) or not isinstance(pq_pk_b64u, str):
        raise TypeError("fndsaLeafMessage: alg and pq_pk must be strings")
    return threshold_message(leaf) + FN_DSA_LEAF_DOMAIN + _utf8(alg) + b"\x00" + _utf8(pq_pk_b64u)


def sign_pca_with_fndsa(alg: Any, leaf: Any, fn_dsa: Any, ed_secret: Any = None) -> Dict[str, str]:
    """{"sig", "alg", "pq_pk"[, "pq_sig"]}. fn_dsa is {"pk": bytes, "sk": bytes}; hybrid suites also need the Ed25519 seed."""
    suite = resolve_fndsa_alg(alg)
    if suite is None:
        raise ValueError("signPcaWithFndsa: unknown FN-DSA alg %r" % (alg,))
    pk = fn_dsa.get("pk") if isinstance(fn_dsa, dict) else None
    sk = fn_dsa.get("sk") if isinstance(fn_dsa, dict) else None
    if not _is_bytes(pk) or len(pk) != suite.pq_pk_bytes:
        raise TypeError("signPcaWithFndsa: '%s' requires a %d-byte FN-DSA public key" % (suite.alg, suite.pq_pk_bytes))
    if not _is_bytes(sk) or len(sk) == 0:
        raise TypeError("signPcaWithFndsa: '%s' requires FN-DSA secret-key material" % suite.alg)
    pq_pk = b64u(bytes(pk))
    msg = fndsa_leaf_message(leaf, suite.alg, pq_pk)
    fn_sig = fndsa_sign(suite.variant, sk, msg)
    if not suite.has_ed25519:
        return {"sig": b64u(fn_sig), "alg": suite.alg, "pq_pk": pq_pk}
    if not _is_bytes(ed_secret):
        raise TypeError("signPcaWithFndsa: '%s' requires edSecret (Ed25519 leaf-holder secret key)" % suite.alg)
    return {"sig": b64u(_ed.sign_secret(bytes(ed_secret), msg)), "alg": suite.alg, "pq_pk": pq_pk, "pq_sig": b64u(fn_sig)}


def verify_pca_fndsa(alg: Any, leaf: Any, holder: Any = None, pq_pk: Any = None, sig: Any = None, pq_sig: Any = None) -> bool:
    """Fail closed. A hybrid needs BOTH the Ed25519 half and the FN-DSA half; every length/encoding check runs before the backend."""
    suite = resolve_fndsa_alg(alg)
    if suite is None:
        return False
    if not isinstance(pq_pk, str):
        return False
    pk = decode_b64u_strict(pq_pk, suite.pq_pk_bytes)
    if pk is None:
        return False
    msg = fndsa_leaf_message(leaf, suite.alg, pq_pk)
    if not suite.has_ed25519:
        if not isinstance(sig, str):
            return False
        fn_sig = decode_b64u_strict(sig, suite.sig_bytes)
        if fn_sig is None:
            return False
        return fndsa_verify(suite.variant, pk, msg, fn_sig)
    if not isinstance(holder, str) or not isinstance(sig, str):
        return False
    if decode_b64u_strict(sig, suite.sig_bytes) is None:
        return False
    ed_ok = _verify_b64u(holder, msg, sig)
    if not isinstance(pq_sig, str):
        return False
    fn_sig = decode_b64u_strict(pq_sig, suite.pq_sig_bytes)
    if fn_sig is None:
        return False
    pq_ok = fndsa_verify(suite.variant, pk, msg, fn_sig)
    return ed_ok and pq_ok


# ---- deterministic mock backend: TEST ONLY (anyone can forge its signatures; never register it in production)

_MOCK_SK_TAG = b"atlas-pca/fn-dsa/mock-sk/v1\x00"


def hash_kat(seed: bytes, out_len: int) -> bytes:
    if out_len < 0:
        raise ValueError("Invalid typed array length: %d" % out_len)
    seed = bytes(seed)
    out = b""
    counter = 0
    while len(out) < out_len:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:out_len]


def _sig_len_for_pk(n: int) -> Optional[int]:
    if n == FN_DSA_512_PUBLIC_KEY_BYTES:
        return FN_DSA_512_SIGNATURE_BYTES
    if n == FN_DSA_1024_PUBLIC_KEY_BYTES:
        return FN_DSA_1024_SIGNATURE_BYTES
    return None


def _derive_mock_sig(pk: bytes, msg: bytes) -> Optional[bytes]:
    n = _sig_len_for_pk(len(pk))
    return None if n is None else hash_kat(b"fn-dsa/mock-sig/v1\x00" + pk + msg, n)


def mock_keypair(variant: Any, seed: Any = "default") -> Dict[str, bytes]:
    if not is_fndsa_variant(variant):
        raise ValueError("mockKeypair: unknown FN-DSA variant %r" % (variant,))
    seed_bytes = _utf8("%s/%s" % (variant, seed)) if isinstance(seed, str) else _utf8(variant + "/") + bytes(seed)
    pk = hash_kat(seed_bytes, _VARIANT_PK_BYTES[variant])
    return {"pk": pk, "sk": _MOCK_SK_TAG + pk}


def register_test_backend(vectors: Optional[List[Dict[str, bytes]]] = None) -> FalconBackend:
    """TEST ONLY: installs a hash-derived backend (optionally with explicit known-answer vectors that take precedence)."""
    table: Dict[str, bytes] = {}
    for v in vectors or []:
        table[b64u(v["pk"]) + "|" + b64u(v["msg"])] = bytes(v["sig"])

    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        expected = table.get(b64u(pk) + "|" + b64u(msg))
        if expected is None:
            expected = _derive_mock_sig(pk, msg)
        if expected is None:
            return False
        return len(sig) == len(expected) and hmac.compare_digest(bytes(sig), expected)

    def sign(sk: bytes, msg: bytes) -> bytes:
        if len(sk) <= len(_MOCK_SK_TAG) or not hmac.compare_digest(bytes(sk[: len(_MOCK_SK_TAG)]), _MOCK_SK_TAG):
            raise ValueError("mock FN-DSA backend: secret key was not minted by mock_keypair()")
        pk = bytes(sk[len(_MOCK_SK_TAG):])
        known = table.get(b64u(pk) + "|" + b64u(msg))
        if known is not None:
            return known
        derived = _derive_mock_sig(pk, msg)
        if derived is None:
            raise ValueError("mock FN-DSA backend: public key length matches no FN-DSA variant")
        return derived

    backend = FalconBackend(verify, sign, lambda: mock_keypair("fn-dsa-512"))
    set_falcon_backend(backend)
    return backend
