"""Differential replay of the SPC expectation and CIBA approval details against the shared approval corpus of the TypeScript reference."""
import pytest

from atlas_pca import actions_approval_profiles as P
from base_oracle import load, run

COUNT, CASES = load("approval")

MAP = {"spcExpectation": P.spc_expectation, "cibaApprovalDetails": P.ciba_approval_details}


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
