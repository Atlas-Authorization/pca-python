"""mint_grant refuses a non-finite risk_policy number (TS risk.ts uses Number.isFinite): the message already said "finite" but inf and NaN passed."""
import math

import pytest

from atlas_pca.agent import DEFAULT_RISK_POLICY, generate_keypair, mint_grant

PRINCIPAL, AGENT = generate_keypair(), generate_keypair()


def mg(rp):
    env = {"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "agent_binding": {}, "risk_policy": rp}
    return mint_grant(PRINCIPAL, AGENT.public, env, "refund an order")


def test_the_default_policy_still_mints():
    assert mg(DEFAULT_RISK_POLICY)["grant"]


@pytest.mark.parametrize("bad", [math.inf, -math.inf, math.nan])
@pytest.mark.parametrize("key", ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"])
def test_a_non_finite_weight_is_refused(key, bad):
    rp = dict(DEFAULT_RISK_POLICY, weights=dict(DEFAULT_RISK_POLICY["weights"], **{key: bad}))
    with pytest.raises(ValueError) as e:
        mg(rp)
    assert str(e.value) == "mint_grant: risk_policy.weights.%s must be finite and >= 0" % key


@pytest.mark.parametrize("bad", [math.inf, -math.inf, math.nan])
@pytest.mark.parametrize("key", ["theta1", "theta2", "kappa", "lambda", "rho", "bMax"])
def test_a_non_finite_scalar_is_refused(key, bad):
    with pytest.raises(ValueError) as e:
        mg(dict(DEFAULT_RISK_POLICY, **{key: bad}))
    assert str(e.value) == "mint_grant: risk_policy.%s must be finite" % key
