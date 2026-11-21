"""The official fixtures of draft-irtf-cfrg-bbs-signatures (ciphersuite BLS12-381-SHA-256; byte-identical across draft revisions -06
through -12), vendored in test-data with provenance, plus the RFC 9380 expand_message_xmd vector. Needs a built libblst."""
import json
import os

import pytest

from atlas_pca import bbs as B
from atlas_pca import bls12

try:
    bls12.lib()
except bls12.Bls12LibraryMissing:
    if os.environ.get("PCA_PAIRING_REQUIRED") == "1":
        raise
    pytest.skip("libblst not available (set PCA_BLST_LIB)", allow_module_level=True)

SUITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-data", "draft-irtf-cfrg-bbs-signatures", "bls12-381-sha-256")


def _load(rel):
    with open(os.path.join(SUITE, rel), encoding="utf-8") as fh:
        return json.load(fh)


def _h(s):
    return bytes.fromhex(s)


def _hs(xs):
    return [_h(s) for s in xs]


def _sc(n):
    return "%064x" % n


def test_expand_message_xmd_rfc9380():
    out = bls12.expand_message_xmd(b"", b"QUUX-V01-CS02-with-expander-SHA256-128", 0x20)
    assert out.hex() == "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"


def test_key_gen_and_sk_to_pk():
    k = _load("keypair.json")
    sk = B.key_gen(_h(k["keyMaterial"]), _h(k["keyInfo"]))
    assert B.sk_to_bytes(sk).hex() == k["keyPair"]["secretKey"]
    assert B.sk_to_pk(sk).hex() == k["keyPair"]["publicKey"]


def test_hash_to_scalar():
    f = _load("h2s.json")
    assert _sc(B.hash_to_scalar(_h(f["message"]), _h(f["dst"]))) == f["scalar"]


def test_map_message_to_scalar():
    for c in _load("MapMessageToScalarAsHash.json")["cases"]:
        assert _sc(B.map_message_to_scalar_as_hash(_h(c["message"]))) == c["scalar"]


def test_create_generators():
    f = _load("generators.json")
    gens = B.create_generators(len(f["MsgGenerators"]) + 1)
    assert gens[0].hex() == f["Q1"]
    for i, g in enumerate(f["MsgGenerators"]):
        assert gens[i + 1].hex() == g


@pytest.mark.parametrize("i", range(1, 11))
def test_sign_and_verify(i):
    f = _load("signature/signature%03d.json" % i)
    msgs = _hs(f["messages"])
    pk = _h(f["signerKeyPair"]["publicKey"])
    r = B.verify_detailed(pk, _h(f["signature"]), _h(f["header"]), msgs)
    if f["result"]["valid"]:
        assert r.ok, f["caseName"]
        assert B.sign(int(f["signerKeyPair"]["secretKey"], 16), pk, _h(f["header"]), msgs).hex() == f["signature"], f["caseName"]
    else:
        assert not r.ok, f["caseName"]
        assert r.reason == B.PAIRING_MISMATCH, f["caseName"]


@pytest.mark.parametrize("i", range(1, 16))
def test_proof_gen_and_verify(i):
    f = _load("proof/proof%03d.json" % i)
    name = f["caseName"]
    msgs = _hs(f["messages"])
    idx = f["disclosedIndexes"]
    disclosed = [msgs[k] if 0 <= k < len(msgs) else b"" for k in idx]
    pk = _h(f["signerPublicKey"])
    r = B.proof_verify_detailed(pk, _h(f["proof"]), _h(f["header"]), _h(f["presentationHeader"]), disclosed, idx)
    if f["result"]["valid"]:
        assert r.ok, name
        rs = f["trace"]["random_scalars"]
        scalars = [int(rs[k], 16) for k in ("r1", "r2", "e_tilde", "r1_tilde", "r3_tilde")] + [int(x, 16) for x in rs["m_tilde_scalars"]]
        regen = B.proof_gen(pk, _h(f["signature"]), _h(f["header"]), _h(f["presentationHeader"]), msgs, idx, scalars)
        assert regen.hex() == f["proof"], name
    else:
        assert not r.ok, name


def test_randomized_proof_verifies_and_tampering_fails():
    f = _load("signature/signature004.json")
    msgs = _hs(f["messages"])
    pk = _h(f["signerKeyPair"]["publicKey"])
    hdr = _h(f["header"])
    ph = b"\x01\x02\x03"
    idx = [0, 2]
    sig = _h(f["signature"])
    proof = B.proof_gen(pk, sig, hdr, ph, msgs, idx)
    dis = [msgs[0], msgs[2]]
    assert B.proof_verify(pk, proof, hdr, ph, dis, idx)
    assert not B.proof_verify(pk, proof, hdr, b"\x09", dis, idx)
    assert not B.proof_verify(pk, proof, hdr, ph, [msgs[0], msgs[1]], idx)
    bad = bytearray(proof)
    bad[-1] ^= 1
    assert not B.proof_verify(pk, bytes(bad), hdr, ph, dis, idx)
    assert proof != B.proof_gen(pk, sig, hdr, ph, msgs, idx)  # unlinkability: two proofs of one signature differ
