"""Differential replay of the PQ threshold step-up verifier (atlas_pca.pq_threshold: signed FROST group descriptor, ML-DSA-65
quorum, hybrid verdict) against the TypeScript reference (@atlasauth/pca-pq-threshold) corpus. Needs an ML-DSA-65 backend
(OpenSSL 3.5+ or the `pq` extra); the whole module skips without one."""
import pytest

from atlas_pca import ed25519 as ED, mldsa, pq_backends, pq_threshold as T
from base_oracle import load_ref, run

if not (pq_backends.available("ML-DSA-65") or mldsa.ml_dsa65_available()):
    pytest.skip("no ML-DSA-65 backend (OpenSSL 3.5+ or the pq extra)", allow_module_level=True)

COUNT, CASES = load_ref("pq-threshold")


@pytest.fixture(scope="module", autouse=True)
def _signers():
    ED.allow_insecure_signer(True)  # only matters when `cryptography` is absent
    yield
    ED.allow_insecure_signer(False)


def _issue(a):
    return T.issue_group_descriptor(a.get("authoritySeed"), a.get("groupPublicKey"), a.get("t"), a.get("participants"))


def _quorum(block, msg, pool, pq_t):
    return T.verify_pq_quorum(block, msg, T.normalize_pq_quorum_pool(pool), pq_t)


MAP = {
    "signerSetCommitment": T.signer_set_commitment,
    "issueGroupDescriptor": _issue,
    "verifyGroupDescriptor": T.verify_group_descriptor,
    "normalizePqQuorumPool": lambda pks: sorted(T.normalize_pq_quorum_pool(pks)),
    "pqQuorumRepresentative": T.pq_quorum_representative,
    "verifyPqQuorum": _quorum,
    "verifyHybridThreshold": T.verify_hybrid_threshold,
}


def test_corpus_is_covered():
    assert COUNT == 212 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
