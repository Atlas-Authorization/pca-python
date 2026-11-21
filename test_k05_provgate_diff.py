"""k05 differential oracle: build provenance as a K1 discharge (atlas_pca.provenance_gate: facts / policy shape, the gate,
RFC 9162 inclusion proofs, the leaf hash, the caveat builder) against the shared TS-generated testdata/k05-provgate.json.gz.
Inclusion cases travel as (leaf b64u, index, size, [proof b64u], root b64u)."""
import pytest

import importlib

G = importlib.import_module("atlas_pca.provenance_gate")  # the package re-exports provenance_gate() under this name
from k05_oracle import b64d, load, run

COUNT, CASES = load("provgate")


def _b(s):
    return b64d(s) if isinstance(s, str) else s


MAP = {
    "provenanceFactsError": G.provenance_facts_error,
    "provenancePolicyError": G.provenance_policy_error,
    "provenanceGate": G.provenance_gate,
    "verifyRfc9162Inclusion": lambda leaf, i, n, proof, root: G.verify_rfc9162_inclusion(_b(leaf), i, n, [_b(x) for x in proof], _b(root)),
    "rfc9162LeafHash": lambda d: G.rfc9162_leaf_hash(b64d(d)),
    "provenanceCaveat": lambda o: G.provenance_caveat(**o),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 4616 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
