"""Differential replay of the attested orchestration harness (plan inclusion, taint fold, trust budget, signing, the mediator
measurement and the allowlisting verifier) against the TypeScript reference."""
import hashlib

import pytest

from atlas_pca import harness as H
from base_oracle import load_ref, run

COUNT, CASES = load_ref("harness")


def _consts():
    return {"HARNESS_VERSION": H.HARNESS_VERSION, "HARNESS_MODEL_ID": H.HARNESS_MODEL_ID, "ENFORCED_CHECKS": list(H.ENFORCED_CHECKS)}


def _scenario(spec):
    op = spec["opts"]
    t = [1_800_000_000_000]
    k = [0]

    def nonce():
        n = "n%d" % k[0]
        k[0] += 1
        return n

    try:
        h = H.Harness(grant=op["grant"], chain=op.get("chain"), agent_secret=hashlib.sha256(("atlas-pca-conformance/" + op["label"]).encode()).digest(),
                      plan=op["plan"], audience=op["audience"], budget=op["budget"], policy=op.get("policy"), base_risk=op.get("baseRisk"),
                      now=lambda: t[0], ttl_ms=op.get("ttlMs"), measurement_manifest=op.get("manifest"), nonce=nonce,
                      attestation=op.get("attestation"), allow_insecure_signer=True)
    except Exception:  # noqa: BLE001 - a refused construction is the reference's {$err}
        return {"$err": True}
    outs = []
    for st in spec["steps"]:
        if st["op"] == "now":
            t[0] = st["t"]
            outs.append(None)
            continue
        orc = st["oracle"]

        def propose(orc=orc):
            if orc["kind"] == "throw":
                raise Exception(orc["msg"])
            return orc["v"] if orc["kind"] == "bad" else orc["c"]

        outs.append(h.step(propose))
    return {"steps": outs, "budget": h.budget, "counter": h.counter, "planRoot": h.plan_root, "measurement": h.harness_measurement()}


MAP = {
    "consts": _consts,
    "computeHarnessMeasurement": H.compute_harness_measurement,
    "harnessAttest": lambda cfg, ctx: H.create_harness_attestation_verifier(cfg)(ctx),
    "harness": _scenario,
}


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    # JSON cannot carry an undefined argument: that case reaches Python as null, which the reference never saw
    run(CASES[fn], MAP[fn], skip=lambda c: "undefined argument" if c["name"].startswith("undefined-checks") else None)
