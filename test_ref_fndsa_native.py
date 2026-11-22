"""Real-primitive FN-DSA through libfndsa (atlas_pca.fndsa_native): byte-for-byte replay of the cross-implementation known-answer file, plus
refusals and the hybrid framing. Needs libfndsa (ATLAS_PCA_LIBFNDSA); with ATLAS_PCA_LIBFNDSA_REQUIRED=1 its absence fails instead of skipping."""
import hashlib
import json
import os

import pytest

from atlas_pca import fndsa as F
from atlas_pca import fndsa_native as N

if not N.available():
    if os.environ.get("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1":
        raise RuntimeError("libfndsa must load (ATLAS_PCA_LIBFNDSA)")
    pytest.skip("libfndsa not available", allow_module_level=True)

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-data", "ref-fndsa-kat.json")) as fh:
    KAT = json.load(fh)
H = bytes.fromhex


def shake_seed(label):
    return hashlib.shake_256(label.encode()).digest(32)
VARIANTS = ("fn-dsa-512", "fn-dsa-1024")


def flip(b, i=0):
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]


@pytest.fixture(autouse=True)
def _backend():
    F.set_falcon_backend(N.native_backend())
    yield
    F.reset_falcon_backend()


def test_kat_has_cases():
    assert len(KAT["wasm_signed"]) > 0 and len(KAT["c_signed"]) > 0


@pytest.mark.parametrize("c", KAT["wasm_signed"])
def test_wasm_signed_byte_exact(c):
    v, vk, msg, sig = c["variant"], H(c["vk"]), H(c["msg"]), H(c["sig"])
    sk, got_vk = N.keygen(v, shake_seed(c["keygen_seed_label"]))
    assert got_vk == vk
    assert N.sign(v, sk, msg, shake_seed(c["sign_seed_label"])) == sig
    assert N.verify(v, vk, msg, sig)
    assert F.fndsa_verify(v, vk, msg, sig)


@pytest.mark.parametrize("c", KAT["c_signed"])
def test_c_signed_verifies(c):
    assert N.verify(c["variant"], H(c["vk"]), H(c["msg"]), H(c["sig"]))


def test_tampering_is_refused():
    c = next(x for x in KAT["c_signed"] if x["msg"])  # a signed empty message must not be the case under test
    v, vk, msg, sig = c["variant"], H(c["vk"]), H(c["msg"]), H(c["sig"])
    assert not N.verify(v, vk, msg, flip(sig, 10))
    assert not N.verify(v, vk, msg + b"x", sig)
    assert not N.verify(v, flip(vk, 5), msg, sig)
    assert not N.verify(v, vk, msg, sig[:-1])
    assert not N.verify(v, vk[:-1], msg, sig)
    assert not N.verify(v, vk, b"\x00" * (N.MESSAGE_CAP + 1), sig)
    assert not N.verify(v, vk, b"", sig)


def test_refusals_before_the_library():
    with pytest.raises(ValueError):
        N.keygen("fn-dsa-768", bytes(32))
    with pytest.raises(ValueError):
        N.keygen("fn-dsa-512", bytes(31))
    with pytest.raises(TypeError):
        N.keygen("fn-dsa-512", None)
    sk, vk = N.keygen("fn-dsa-512", bytes(32))
    with pytest.raises(ValueError):
        N.sign("fn-dsa-512", sk[:-1], b"m")
    with pytest.raises(ValueError):
        N.sign("fn-dsa-512", sk, b"\x00" * (N.MESSAGE_CAP + 1))
    with pytest.raises(ValueError):
        N.sign("fn-dsa-768", sk, b"m")
    with pytest.raises(TypeError):
        N.sign("fn-dsa-512", sk, None)
    with pytest.raises(ValueError):
        N.sign("fn-dsa-512", sk, b"m", bytes(5))
    with pytest.raises(ValueError):
        N.verify("fn-dsa-768", vk, b"m", bytes(666))
    assert not N.verify("fn-dsa-512", vk, b"m", bytes(666))
    with pytest.raises(TypeError):
        N.verify("fn-dsa-512", None, b"m", bytes(666))


@pytest.mark.parametrize("v", VARIANTS)
def test_random_sign_round_trip(v):
    sk, vk = N.keygen(v, bytes(range(32)))
    s1, s2 = N.sign(v, sk, b"hello"), N.sign(v, sk, b"hello")
    assert s1 != s2  # fresh randomness per signature
    assert N.verify(v, vk, b"hello", s1) and N.verify(v, vk, b"hello", s2)
    assert N.verify(v, vk, b"", N.sign(v, sk, b""))
    assert not N.verify(v, vk, b"hellp", s1)
    assert N.verify(v, vk, b"m" * N.MESSAGE_CAP, N.sign(v, sk, b"m" * N.MESSAGE_CAP))


def test_backend_seam():
    be = F.get_falcon_backend()
    kp = be.keygen()
    sig = be.sign(kp["sk"], b"x")
    assert be.verify(kp["pk"], b"x", sig) is True
    assert be.verify(kp["pk"][:-1], b"x", sig) is False
    with pytest.raises(ValueError):
        be.sign(b"\x00" * 10, b"x")


@pytest.mark.parametrize("alg", sorted(F.FN_DSA_SUITES))
def test_framing_round_trip(alg):
    suite = F.FN_DSA_SUITES[alg]
    sk, vk = N.keygen(suite.variant, bytes([7]) * 32)
    leaf = {"agent": "a", "n": 1}
    ed_seed = bytes([9]) * 32
    signed = F.sign_pca_with_fndsa(alg, leaf, {"pk": vk, "sk": sk}, ed_seed if suite.has_ed25519 else None)
    holder = None
    if suite.has_ed25519:
        from atlas_pca import ed25519 as ed
        from atlas_pca.pca import b64u
        holder = b64u(ed.public_key(ed_seed))
    assert F.verify_pca_fndsa(alg, leaf, holder, signed["pq_pk"], signed["sig"], signed.get("pq_sig"))
    assert not F.verify_pca_fndsa(alg, {"agent": "b", "n": 1}, holder, signed["pq_pk"], signed["sig"], signed.get("pq_sig"))
