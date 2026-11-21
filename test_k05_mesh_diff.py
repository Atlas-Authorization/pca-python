"""k05 differential oracle: the cross-domain agent mesh (atlas_pca.mesh) and the Merkle primitives it rests on
(ledger.verify_ledger_consistency, the revocation non-membership proof) against the shared TS-generated
testdata/k05-mesh.json.gz. The mesh verdict compares ok / reason / hop (hop -1 here = absent in the reference)."""
import pytest

from atlas_pca import mesh as M
from atlas_pca.intent_v2 import verify_non_membership
from atlas_pca.ledger import verify_ledger_consistency
from k05_oracle import load, run

COUNT, CASES = load("mesh")
_CAMEL = {"max_amount": "maxAmount", "expires_at": "expiresAt", "max_hops": "maxHops"}


def _verdict(p, t):
    v = M.verify_mesh_proof(p, t)
    out = {"ok": v.ok}
    if v.reason is not None:
        out["reason"] = v.reason
    if v.hop >= 0:
        out["hop"] = v.hop
    return out


def _effective(cs):
    e, why = M._effective(cs)
    if e is None:
        return {"error": why}
    return {_CAMEL.get(k, k): v for k, v in e.items() if v is not None}


MAP = {
    "verifyMeshProof": _verdict,
    "checkHeadAdvance": M.check_head_advance,
    "verifyLedgerConsistency": verify_ledger_consistency,
    "verifyNonMembership": verify_non_membership,
    "effectiveAuthority": _effective,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 16431 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
