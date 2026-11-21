"""BFV risk gate on Microsoft SEAL (ctypes over libsealc): replay of the node-seal corpus plus a native round trip.

Needs libsealc (ATLAS_PCA_LIBSEALC) and, for the replay, the corpus the reference generates (PCA_FHE_SEAL_CORPUS). Both absent skips the
module; with PCA_FHE_SEAL_REQUIRED=1 (the FHE workflow) absence fails instead.
"""

import gzip
import json
import os

import pytest

from atlas_pca import fhe_seal as F

_REQUIRED = os.environ.get("PCA_FHE_SEAL_REQUIRED") == "1"
try:
    F._load()
except RuntimeError as e:  # no native library on this runner
    if _REQUIRED:
        raise
    pytest.skip(str(e), allow_module_level=True)


def _policy(kappa: float, budget: float) -> F.FheRiskPolicy:
    w = [0.25, 0.2, 0.2, 0.2, 0.1, 0.05]
    return F.FheRiskPolicy(1000, 6, [round(v * 1000) for v in w], [round(kappa * v * 1000) for v in w], round(budget * 1e6), kappa)


def test_replays_the_reference_ciphertexts_to_the_reference_results():
    path = os.environ.get("PCA_FHE_SEAL_CORPUS")
    if not path:
        if _REQUIRED:
            pytest.fail("PCA_FHE_SEAL_CORPUS must point at the node-seal corpus")
        pytest.skip("no corpus")
    with gzip.open(path, "rt") as f:
        corpus = json.load(f)
    assert corpus["seal"]["polyModulusDegree"] == F.POLY_MODULUS_DEGREE and corpus["seal"]["plainModulus"] == F.PLAIN_MODULUS
    assert len(corpus["cases"]) >= 6
    for c in corpus["cases"]:
        p = c["policy"]
        pol = F.FheRiskPolicy(p["scale"], p["dim"], p["weightsScaled"], p["kappaWeightsScaled"], p["budgetScaled"], p["kappa"])
        gate = F.eval_risk_gate(corpus["publicKey"], corpus["galoisKeys"], c["encInputs"], pol)
        # deterministic evaluation: byte-equal once both are re-saved uncompressed
        assert F.canonical_cipher(gate.enc_risk_raw) == F.canonical_cipher(c["encRiskRaw"]), c["name"]
        assert F.canonical_cipher(gate.enc_slack) == F.canonical_cipher(c["encSlack"]), c["name"]


@pytest.mark.parametrize("x,kappa,budget", [([100, 900, 100, 100, 100, 100], 1.0, 0.6), ([1000] * 6, 1.0, 0.5), ([0] * 6, 1.5, 0.25)])
def test_native_round_trip_matches_plaintext_arithmetic(x, kappa, budget):
    keys, pol = F.keygen(), _policy(kappa, budget)
    gate = F.eval_risk_gate(keys.public_key, keys.galois_keys, F.encrypt_risk_inputs(keys.public_key, x), pol)
    v = F.decrypt_verdict(keys.secret_key, gate.enc_risk_raw, gate.enc_slack, pol)
    raw = sum(w * i for w, i in zip(pol.weights_scaled, x))
    kr = sum(w * i for w, i in zip(pol.kappa_weights_scaled, x))
    assert (v.r_scaled, v.slack, v.admit) == (raw, pol.budget_scaled - kr, pol.budget_scaled - kr >= 0)


def test_all_zero_weights_evaluate_to_zero():
    keys = F.keygen()
    pol = F.FheRiskPolicy(1000, 6, [0] * 6, [0] * 6, 5000)
    gate = F.eval_risk_gate(keys.public_key, keys.galois_keys, F.encrypt_risk_inputs(keys.public_key, [5] * 6), pol)
    assert F.decrypt_verdict(keys.secret_key, gate.enc_risk_raw, gate.enc_slack, pol) == F.Verdict(0, 5000, True)


def test_wrong_key_fails_closed():
    a, b, pol = F.keygen(), F.keygen(), _policy(1.0, 0.6)
    gate = F.eval_risk_gate(a.public_key, a.galois_keys, F.encrypt_risk_inputs(a.public_key, [1, 2, 3, 4, 5, 6]), pol)
    with pytest.raises(ValueError, match="noise budget"):
        F.decrypt_verdict(b.secret_key, gate.enc_risk_raw, gate.enc_slack, pol)


def test_malformed_blobs_and_policies_are_refused():
    keys = F.keygen()
    good = F.encrypt_risk_inputs(keys.public_key, [1, 2, 3, 4, 5, 6])
    for bad in (good[:-8], good + "AAAA", "AAAA", "A" * 64):
        with pytest.raises(ValueError):
            F.assert_seal_blob(bad, "x")
    z = [0] * 6
    for pol in (F.FheRiskPolicy(1000, 5, z, z, 0), F.FheRiskPolicy(1000, 6, z, z, F.SIGNED_BOUND), F.FheRiskPolicy(0, 6, z, z, 0),
                F.FheRiskPolicy(1000, 6, [0] * 5, z, 0), F.FheRiskPolicy(1000, 6, z, z, 1.5)):
        with pytest.raises(ValueError):
            F.require_policy(pol)
    with pytest.raises(ValueError):
        F.encrypt_risk_inputs("x", [-1, 0, 0, 0, 0, 0])
