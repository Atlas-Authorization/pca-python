"""k05 differential oracle: the caveat language v2 (atlas_pca.caveat_lang: discharges, narrow blocks, max_uses, derive,
spiffe_bound, K1 evaluation) and the K1 request headers (atlas_pca.server.presented_k1) against the shared TS-generated
testdata/k05-caveatlang.json.gz."""
import pytest

from atlas_pca import caveat_lang as K
from atlas_pca.server import presented_k1
from k05_oracle import load, run

COUNT, CASES = load("caveatlang")


def _caveats_k1(grant, chain, k1, context):
    allow, failed = K.evaluate_caveats_k1(grant, chain, k1, context)
    return {"allow": allow, "failed": failed}


def _presented(headers):
    try:
        return {"ok": True, "value": presented_k1(headers)}
    except Exception:  # noqa: BLE001 - the reference's projection: any refusal is {ok: false}
        return {"ok": False}


MAP = {
    "spiffeIdError": K.spiffe_id_error,
    "needsDischargeError": K.needs_discharge_error,
    "dischargeShapeError": K.discharge_shape_error,
    "narrowShapeError": K.narrow_shape_error,
    "maxUsesError": K.max_uses_error,
    "maxUsesSlotKey": K.max_uses_slot_key,
    "spiffeBoundError": K.spiffe_bound_error,
    "deriveError": K.derive_error,
    "evaluateDerive": K.evaluate_derive,
    "verifyDischarge": K.verify_discharge,
    "verifyNarrow": K.verify_narrow,
    "boundCaveats": K.bound_caveats,
    "evaluateK1": K.evaluate_k1,
    "evaluateCaveatsK1": _caveats_k1,
    "presentedK1": _presented,
}
SKIP = {
    "dischargeRequests": "the discharge-request builder is TS-only (no Python twin; the verifier side is evaluate_k1)",
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 16104 and set(CASES) == set(MAP) | set(SKIP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
