"""Differential replay: trait selectors, policy decision and signed confirmation against the TypeScript reference."""
import pytest

from atlas_pca import ed25519

from atlas_pca import actions as A
from atlas_pca import actions_confirmation as C
from atlas_pca import actions_selector as S
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("actions-sel-conf")
CORE = A.CORE_REGISTRY


def _reg(reg_defs):
    return CORE if reg_defs is None else A.extend_registry(CORE, reg_defs)


MAP = {
    "selectorMatches": lambda s, c: bool(S.selector_matches(s, c)),
    "selectorMatchesFor": lambda s, m, c, z: bool(S.selector_matches_for(s, m, c, z)),
    "selectorHasNot": S.selector_has_not,
    "allowSelectorError": S.allow_selector_error,
    "policyDecision": S.policy_decision,
    "blankReason": C.blank_reason,
    "reviewMessage": C.review_message,
    "signReview": C.sign_review,
    "verbConfirmationError": lambda v, rd, pins: A.verb_confirmation_error(v, _reg(rd), False if pins is None else pins),  # JSON null is not undefined: it is bad pins
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
