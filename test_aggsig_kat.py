"""Community-standard BLS12-381 vectors (ethereum/bls12-381-tests v0.1.2) for the PoP ciphersuite BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
(draft-irtf-cfrg-bls-signature has no vectors of its own), vendored in test-data with provenance; the same fixtures the TypeScript package
replays. Needs a built libblst through ctypes (PCA_BLST_LIB)."""
import glob
import json
import os
import re

import pytest

from atlas_pca import aggsig as A
from atlas_pca import bls12

try:
    bls12.lib()
except bls12.Bls12LibraryMissing:
    if os.environ.get("PCA_PAIRING_REQUIRED") == "1":
        raise
    pytest.skip("libblst not available (set PCA_BLST_LIB)", allow_module_level=True)

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-data", "ethereum-bls12-381-tests-v0.1.2")


def h(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def cases(d):
    out = []
    for p in sorted(glob.glob(os.path.join(ROOT, d, "*.json"))):
        with open(p, encoding="utf-8") as f:
            j = json.load(f)
        out.append((os.path.basename(p), j["input"], j["output"]))
    assert out, d
    return out


@pytest.fixture(scope="module", autouse=True)
def _insecure_signer():
    A.allow_insecure_bls_signer(True)
    yield
    A.allow_insecure_bls_signer(False)


@pytest.mark.parametrize("name,i,o", cases("sign"))
def test_sign(name, i, o):
    if o is None:
        with pytest.raises(ValueError):
            A.sign(h(i["privkey"]), h(i["message"]))
    else:
        assert A.sign(h(i["privkey"]), h(i["message"])) == h(o), name


@pytest.mark.parametrize("name,i,o", cases("verify"))
def test_verify(name, i, o):
    assert A.verify(h(i["pubkey"]), h(i["message"]), h(i["signature"])) is o, name


@pytest.mark.parametrize("name,i,o", cases("aggregate"))
def test_aggregate(name, i, o):
    sigs = [h(x) for x in i]
    if o is None:
        with pytest.raises(ValueError):
            A.aggregate(sigs)
    else:
        assert A.aggregate(sigs) == h(o), name


@pytest.mark.parametrize("name,i,o", cases("fast_aggregate_verify"))
def test_fast_aggregate_verify(name, i, o):
    assert A._raw_fast_aggregate_verify([h(x) for x in i["pubkeys"]], h(i["message"]), h(i["signature"])) is o, name


@pytest.mark.parametrize("name,i,o", cases("aggregate_verify"))
def test_aggregate_verify(name, i, o):
    assert A._raw_aggregate_verify([h(x) for x in i["pubkeys"]], [h(x) for x in i["messages"]], h(i["signature"])) is o, name


@pytest.mark.parametrize("name,i,o", cases("deserialization_G1"))
def test_key_validate(name, i, o):
    pk = i["pubkey"]
    # the fixtures test decoding and the subgroup; KeyValidate additionally rejects the identity (draft 2.5)
    assert A.key_validate(h(pk)) is (bool(o) and re.fullmatch(r"c0+", pk) is None), name


@pytest.mark.parametrize("name,i,o", cases("deserialization_G2"))
def test_malformed_signatures_never_verify(name, i, o):
    pk = h("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a")
    assert A.verify(pk, bytes(32), h(i["signature"])) is False, name


def test_pop_and_rogue_key():
    sk1 = h("263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3")
    sk2 = h("47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138")
    pk1, pk2, pop1 = A.public_key_of(sk1), A.public_key_of(sk2), A.pop_prove(sk1)
    assert A.pop_verify(pk1, pop1) and not A.pop_verify(pk2, pop1)
    assert not A.pop_verify(pk1, A.sign(sk1, pk1))  # domain separation both ways
    assert not A.verify(pk1, pk1, pop1)
