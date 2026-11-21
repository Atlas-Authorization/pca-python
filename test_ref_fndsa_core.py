"""Core suite dispatch for fn-dsa-512 / fn-dsa-1024 (pca.verify_leaf_suite, validate_signature_wire): no backend -> deny / unsupported_suite;
libfndsa registered -> the known-answer signatures verify through the core. Needs libfndsa for the backend half
(ATLAS_PCA_LIBFNDSA; ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping)."""
import json
import os

import pytest

from atlas_pca import fndsa as F
from atlas_pca import fndsa_native as N
from atlas_pca import pca

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-data", "ref-fndsa-kat.json")) as fh:
    KAT = json.load(fh)["c_signed"]
H = bytes.fromhex
b64u = pca.b64u


def leaf(c, **kw):
    p = {"alg": c["variant"], "sig": b64u(H(c["sig"])), "pq_pk": b64u(H(c["vk"]))}
    p.update(kw)
    return p


@pytest.fixture(autouse=True)
def _clean():
    F.reset_falcon_backend()
    yield
    F.reset_falcon_backend()


@pytest.mark.parametrize("c", KAT)
def test_no_backend_denies(c):
    p = leaf(c)
    assert pca.validate_signature_wire(p) == "unsupported_suite: " + c["variant"]
    assert not pca.suite_available(c["variant"])
    assert pca.verify_leaf_suite(p, None, H(c["msg"])) is False


def test_registry_shape():
    for v, (sg, pk) in {"fn-dsa-512": (666, 897), "fn-dsa-1024": (1280, 1793)}.items():
        assert pca._SIG_SUITES[v][:4] == (sg, True, False, v.upper())
        assert pca.PQ_PK_LENGTHS >= {pk}


needs_lib = pytest.mark.skipif(not N.available() and os.environ.get("ATLAS_PCA_LIBFNDSA_REQUIRED") != "1", reason="libfndsa not available")


@needs_lib
@pytest.mark.parametrize("c", KAT)
def test_backend_verifies_and_refuses(c):
    assert N.available(), "libfndsa must load (ATLAS_PCA_LIBFNDSA)"
    F.set_falcon_backend(N.native_backend())
    msg, p = H(c["msg"]), leaf(c)
    assert pca.suite_available(c["variant"])
    assert pca.validate_signature_wire(p) is None
    assert pca.verify_leaf_suite(p, None, msg) is True
    assert pca.verify_leaf_suite(p, None, msg + b"x") is False
    sig = bytearray(H(c["sig"]))
    sig[10] ^= 1
    assert pca.verify_leaf_suite(leaf(c, sig=b64u(bytes(sig))), None, msg) is False
    vk = bytearray(H(c["vk"]))
    vk[5] ^= 1
    assert pca.verify_leaf_suite(leaf(c, pq_pk=b64u(bytes(vk))), None, msg) is False
    short = leaf(c, pq_pk=b64u(H(c["vk"])[:-1]))
    assert pca.validate_signature_wire(short) is not None
    assert pca.verify_leaf_suite(short, None, msg) is False
