"""Replays the TS-reference oracle of the signing half of the action pin (testdata/ref-action-pin.json.gz, 111 cases): signing a registry document, an
evolution record (valid and every kind of invalid record), a registry key entry and a principal re-approval, plus the verify side over the documents the
oracle signs. Every fn has a handler and the totals are asserted; a reference refusal needs a native exception."""
import os

import pytest

from atlas_pca import actions_registry as R
from atlas_pca.pq_suites import ml_dsa65_keygen
from base_oracle import HERE, load, run

COUNT, CASES = load("action-pin", os.path.join(HERE, "testdata", "ref-action-pin.json.gz"))


def _nums(v):
    """{"$num": "NaN" | "Infinity" | "-Infinity"} is the number the generator passed."""
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": float("nan"), "Infinity": float("inf"), "-Infinity": float("-inf")}[v["$num"]]
        return {k: _nums(x) for k, x in v.items()}
    return [_nums(x) for x in v] if isinstance(v, list) else v


def _suite(s):
    if s is None:
        return None
    if s["alg"] == "ed25519" or "pqSeed" not in s:
        return {"alg": s["alg"]}
    return {"alg": s["alg"], "pq": ml_dsa65_keygen(s["pqSeed"])}


NAMES = ["ACTION_PIN_ON_NEW", "EVOLUTION_CLASSES", "EVOLUTION_DIFF_DOMAIN", "EVOLUTION_DOMAIN", "EVOLUTION_RECORD_KIND", "MAX_ESC_TIER", "MAX_EVOLUTION_STEPS",
         "REAPPROVAL_DOMAIN", "REAPPROVAL_KIND"]
HANDLERS = {
    "constants": lambda: {n: list(getattr(R, n)) if isinstance(getattr(R, n), tuple) else getattr(R, n) for n in NAMES},
    "signRegistryDoc": lambda d, b, k, s, su: R.sign_registry_doc(d, _nums(b), k, s, _suite(su)),
    "signEvolutionRecord": lambda r, k, s, su: R.sign_evolution_record(r, k, s, _suite(su)),
    "registryKeyOf": lambda k, s, su: R.registry_key_of(k, s, _suite(su)),
    "signReapproval": lambda a: R.sign_reapproval(a["grantId"], a["record"], a["principalSecret"]),
    "verifyRegistrySig": R.verify_registry_sig, "verifyEvolutionRecord": R.verify_evolution_record, "reapprovalValid": R.reapproval_valid,
}
TOTALS = {"signEvolutionRecord": 33, "verifyEvolutionRecord": 21, "signRegistryDoc": 20, "reapprovalValid": 17, "signReapproval": 8, "verifyRegistrySig": 6,
          "registryKeyOf": 5, "constants": 1}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 111 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert set(CASES["constants"][0]["out"]) == set(NAMES)
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 25


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_action_pin_replay(fn):
    assert run(CASES[fn], HANDLERS[fn]) == (TOTALS[fn], 0)
