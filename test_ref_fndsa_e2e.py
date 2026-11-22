"""FN-DSA end to end through the public sign and verify paths, replaying the shared PCActn fixture: with libfndsa registered the
agent-side signer reproduces `pcactn` byte for byte and every case verifies as `expect_allow`; with no backend every case denies.
Gated on ATLAS_PCA_LIBFNDSA; ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails (not skips) when the library is missing."""
import hashlib
import json
import os

import pytest

from atlas_pca import fndsa as F
from atlas_pca import fndsa_native as N
from atlas_pca.agent import UnsupportedSuite, generate_pq_keypair, keypair_from_seed, sign_pcactn, sign_with_suite
from atlas_pca.pca import verify_pcactn_core

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-data", "ref-fndsa-pcactn.json")) as fh:
    CASES = json.load(fh)["cases"]

if not N.available():
    if os.environ.get("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1":
        raise RuntimeError("libfndsa must load (ATLAS_PCA_LIBFNDSA)")
    LIB = False
else:
    LIB = True
needs_lib = pytest.mark.skipif(not LIB, reason="libfndsa not available")


def _seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()


@pytest.fixture
def backend():
    prev = F.get_falcon_backend()
    F.set_falcon_backend(N.native_backend())
    yield
    F.set_falcon_backend(prev)


@pytest.fixture
def no_backend():
    prev = F.get_falcon_backend()
    F.reset_falcon_backend()
    yield
    F.set_falcon_backend(prev)


def _verify(c):
    return verify_pcactn_core(c["pcactn"], c["grant"], now=c["now_epoch"], audience=c["audience"], insecure_skip_plan_root_check=True)


@needs_lib
@pytest.mark.parametrize("c", [c for c in CASES if c["name"].endswith("/valid")], ids=lambda c: c["alg"])
def test_sign_matches_fixture(backend, c):
    L = c["key_labels"]
    pq = generate_pq_keypair(c["alg"].upper(), _seed(L["fndsa_keygen"]), _seed(L["fndsa_sign_seed"]))
    assert pq.public == c["pq_pk"]
    signed = sign_pcactn(c["body"], keypair_from_seed(_seed(L["agent_ed25519"])), alg=c["alg"], pq=pq)
    assert json.loads(json.dumps(signed)) == c["pcactn"]


@needs_lib
@pytest.mark.parametrize("c", CASES, ids=lambda c: c["name"])
def test_verify_matches_expectation(backend, c):
    assert _verify(c).allow is c["expect_allow"]


@needs_lib
def test_random_sign_seed_round_trips(backend):
    for c in (c for c in CASES if c["name"].endswith("/valid")):
        pq = generate_pq_keypair(c["alg"].upper())
        a, b = pq.sign(b"m"), pq.sign(b"m")
        assert a != b and F.fndsa_verify(c["alg"], pq.public_bytes, b"m", a) and F.fndsa_verify(c["alg"], pq.public_bytes, b"m", b)


@pytest.mark.parametrize("c", CASES, ids=lambda c: c["name"])
def test_no_backend_denies(no_backend, c):
    v = _verify(c)
    assert v.allow is False
    if c["name"].endswith("/valid"):
        assert "unsupported_suite" in v.reason
        with pytest.raises(UnsupportedSuite):
            generate_pq_keypair(c["alg"].upper(), _seed(c["key_labels"]["fndsa_keygen"]))
        with pytest.raises(UnsupportedSuite):
            sign_with_suite(c["alg"], keypair_from_seed(_seed(c["key_labels"]["agent_ed25519"])), None, b"m")
