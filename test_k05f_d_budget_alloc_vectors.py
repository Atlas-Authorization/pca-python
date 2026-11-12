"""Replays packages/pca/conformance/budget-alloc-vectors.json: budget_alloc monotonicity over a delegation chain's flattened caveat
list, byte for byte against the reference (`allocationsMonotone`)."""
import json
import os

import pytest

from atlas_pca.pca import allocations_monotone

_HERE = os.path.dirname(os.path.abspath(__file__))
_P = next(p for p in (os.path.join(_HERE, "conformance", "budget-alloc-vectors.json"),
                      os.path.join(_HERE, "conformance", "budget-alloc-vectors.json")) if os.path.exists(p))
with open(_P, encoding="utf-8") as f:
    CASES = json.load(f)["budget_alloc"]


def test_the_corpus_is_not_empty():
    assert len(CASES) >= 24


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_budget_alloc_vectors(case):
    ok, reason = allocations_monotone(case["caveats"])
    assert ok is case["expect"]["ok"]
    if not case["expect"]["ok"]:
        assert reason == case["expect"]["reason"]
    else:
        assert reason is None


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_limits_are_malformed(bad):
    ok, reason = allocations_monotone([{"type": "budget_alloc", "limit": bad}])
    assert ok is False and reason == "budget_alloc caveat 0: limit must be a finite number >= 0"


@pytest.mark.parametrize("bad", [None, {}, "x", 5, "__missing__"])
def test_a_leaf_whose_caveats_are_not_a_list_is_refused_by_the_chain_verifier(bad):
    """The standalone chain verifier never treats a missing or non-list `caveats` as an empty list (reference allocationsMonotone refuses it
    as `malformed caveats`): the hop is refused as a malformed capability before any signature or monotonicity work, and the control with
    `[]` is not refused for that reason."""
    from atlas_pca.agent import generate_keypair, mint_grant
    from atlas_pca.pca import verify_chain
    k = generate_keypair()
    env = {"goal_commit": "g", "predicates": [{"verb": "*", "resource": "*"}], "caveats": [], "agent_binding": {},
           "risk_policy": {"weights": {w: 0 for w in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta")}, "theta1": 1, "theta2": 1,
                           "kappa": 1, "lambda": 0, "rho": 0.5, "bMax": 1}}
    root = mint_grant(k, generate_keypair().public, env, "goal")["grant"]
    assert verify_chain([root], k.public) == (True, None)  # the signed control: a list of caveats
    forged = dict(root)
    if bad == "__missing__":
        del forged["caveats"]
    else:
        forged["caveats"] = bad
    ok, why = verify_chain([forged], k.public)
    assert ok is False and why == "hop 0: malformed capability"
    assert allocations_monotone(bad if bad != "__missing__" else None) == (False, "malformed caveats")
