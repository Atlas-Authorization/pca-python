"""Differential replay: the review flow (attestation verdicts, status, queue, view, confirm) and pack transparency against the TypeScript reference."""
import pytest

from atlas_pca import actions as A
from atlas_pca import actions_review as RV
from atlas_pca import actions_transparency as TR
from atlas_pca import ed25519, scitt_log as L
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("actions-review-py")
CORE = A.CORE_REGISTRY


def _reg(rd):
    return CORE if rd is None else A.extend_registry(CORE, rd)


def _confirm(d, oo):
    o = {"registry": _reg(oo["regDefs"]), "reviewer": {"kid": oo["kid"], "secret": oo["seed"]}, "finalTraits": oo["finalTraits"], "ts": oo["ts"]}
    if oo.get("pins"):
        o["pins"] = oo["pins"]
    if oo.get("dismissed"):
        o["dismissed"] = oo["dismissed"]
    return RV.confirm_def(d, o)


def _append(packs, seed_reg, seed_log):
    svc = L.TransparencyService("EdDSA", seed_log, "ts")
    return [TR.append_pack_to_log(p, svc, {"alg": "EdDSA", "key": seed_reg, "issuer": "registry"}) for p in packs]


MAP = {
    "verifyAttestation": lambda d, p, rd: RV.verify_attestation_verdict(d, _reg(rd), p),
    "reviewStatus": lambda d, p, rd: RV.review_status(d, _reg(rd), p),
    "revertStale": lambda d, p, rd: RV.revert_stale(d, _reg(rd), p),
    "reviewPriority": lambda d: RV.review_priority(d, CORE),
    "reviewQueueOrder": lambda ds: [d["verb"] for d in RV.review_queue_order(ds, CORE)],
    "prepareReview": lambda d, *prev: RV.prepare_review(d, CORE, prev[0] if prev else None),
    "confirmDef": _confirm,
    "packStatementPayload": TR.pack_statement_payload,
    "appendPackToLog": _append,
    "verifyPackLogEntry": lambda p, e, kr, kl, r: TR.verify_pack_log_entry(p, e, {"registry": kr, "log": kl}, r),
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
