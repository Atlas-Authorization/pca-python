"""Differential replay of the BLS12-381 aggregation layer (atlas_pca.aggsig: PoP ciphersuite, key registry, aggregated capability
chain, witness cosignatures) against the TypeScript reference (@atlasauth/pca-aggsig) corpus. Runs on a built libblst through ctypes
(PCA_BLST_LIB or the loader path); the secret scalar is handled in Python ints, so the module opts in to signing. py_ecc, when
installed, is only an independent cross-check of the signatures."""
import os

import pytest

from atlas_pca import aggsig as A
from atlas_pca import bls12

try:
    bls12.lib()
except bls12.Bls12LibraryMissing:
    if os.environ.get("PCA_PAIRING_REQUIRED") == "1":
        raise
    pytest.skip("libblst not available (set PCA_BLST_LIB)", allow_module_level=True)
from base_oracle import load_ref, run  # noqa: E402

COUNT, CASES = load_ref("aggsig")


@pytest.fixture(scope="module", autouse=True)
def _insecure_signer():
    A.allow_insecure_bls_signer(True)
    yield
    A.allow_insecure_bls_signer(False)


def _reg_all(keys):
    """Register every {pk, pop} pair; None when any fails (the reference result is then {"registerFailed": true})."""
    out = []
    for k in keys:
        r = A.register_key(k["pk"], k["pop"])
        if not r["ok"]:
            return None
        out.append(r["key"])
    return out


def _registry(keys):
    reg = A.KeyRegistry()
    for k in keys:
        if not reg.register(k["pk"], k["pop"])["ok"]:
            break  # the reference harness stops at the first failure and keeps what it has
    return reg


def _register_key(pk, pop):
    r = A.register_key(pk, pop)
    return {"ok": True} if r["ok"] else {"ok": False, "reason": r["reason"]}


def _agg_verify(keys, msgs, agg):
    ks = _reg_all(keys)
    return {"registerFailed": True} if ks is None else A.aggregate_verify(ks, msgs, agg)


def _fast_verify(keys, msg, agg):
    ks = _reg_all(keys)
    return {"registerFailed": True} if ks is None else A.fast_aggregate_verify(ks, msg, agg)


def _verify_chain(chain, agg, keys, root):
    return A.verify_aggregated_chain(chain, agg, _registry(keys), root)


def _verify_witnesses(sth, keys, agg):
    ks = _reg_all(keys)
    return {"registerFailed": True} if ks is None else A.verify_aggregated_witness_cosignatures(sth, ks, agg)


MAP = {
    "publicKeyOf": A.public_key_of,
    "sign": A.sign,
    "popProve": A.pop_prove,
    "verify": A.verify,
    "keyValidate": A.key_validate,
    "registerKey": _register_key,
    "aggregate": A.aggregate,
    "aggregateVerify": _agg_verify,
    "fastAggregateVerify": _fast_verify,
    "mintBlsRoot": A.mint_bls_root,
    "chainDelegate": A.bls_delegate,
    "chainAttenuate": A.bls_attenuate,
    "capHash": A.cap_hash,
    "aggregateChainSignatures": A.aggregate_chain_signatures,
    "verifyAggregatedChain": _verify_chain,
    "cosignTreeHead": A.cosign_tree_head,
    "verifyWitnessCosignature": A.verify_witness_cosignature,
    "aggregateWitnessCosignatures": A.aggregate_witness_cosignatures,
    "verifyAggregatedWitnessCosignatures": _verify_witnesses,
}


def test_corpus_is_covered():
    assert COUNT == 552 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_secret_key_paths_refuse_without_the_opt_in():
    A.allow_insecure_bls_signer(False)
    try:
        with pytest.raises(RuntimeError):
            A.sign(bytes(31) + b"\x01", b"m")
    finally:
        A.allow_insecure_bls_signer(True)


def test_signatures_match_py_ecc():
    py_ecc = pytest.importorskip("py_ecc.bls")
    for n, msg in ((1, b""), (0x263DBD792F5B1BE47ED85F8938C0F29586AF0D3AC7B977F21C278FE1462040E3, b"agent capability"), (_R - 1, bytes(range(40)))):
        sk = n.to_bytes(32, "big")
        assert A.public_key_of(sk) == bytes(py_ecc.G2ProofOfPossession.SkToPk(n))
        assert A.sign(sk, msg) == bytes(py_ecc.G2ProofOfPossession.Sign(n, msg))
        assert A.pop_prove(sk) == bytes(py_ecc.G2ProofOfPossession.PopProve(n))


_R = A._R
