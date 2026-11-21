"""Differential replay of the PCA explainer (atlas_pca.explain: cleanText, verification / decision / chain explanations and their
text renderers) against vectors generated from the TypeScript reference (@atlasauth/pca-explain). Explanations are compared as
their JSON (an absent member is a JavaScript undefined); a reference throw requires the port to raise."""
import pytest

from atlas_pca import explain as E
from base_oracle import load_ref, run

COUNT, CASES = load_ref("explain")

MAP = {
    "cleanText": E.clean_text,
    "explainVerification": E.explain_verification,
    "explainVerificationText": lambda *a: E.verification_to_text(E.explain_verification(*a)),
    "explainDecision": E.explain_decision,
    "explainDecisionText": lambda *a: E.decision_to_text(E.explain_decision(*a)),
    "explainChain": E.explain_chain,
    "explainChainText": lambda *a: E.chain_to_text(E.explain_chain(*a)),
    "consts": lambda: {"VERIFY_CHECK_ORDER": E.VERIFY_CHECK_ORDER, "MAX_TEXT": E.MAX_TEXT},
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 2107 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
