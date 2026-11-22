"""Differential replay: business rules (validation, compile, evaluate, explain, lint, diff, signed review) against the TypeScript reference."""
import pytest

from atlas_pca import ed25519

from atlas_pca import actions_rules as R
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("actions-rules-py")




MAP = {
    "resolveParamRef": R.resolve_param_ref,
    "moneyOf": R.money_of,
    "minorUnits": R.minor_units,
    "knownTimeZone": R.known_time_zone,
    "businessRulesError": R.business_rules_error,
    "businessRulesDigest": R.business_rules_digest,
    "compileBusinessRules": R.compile_business_rules,
    "clockAt": R.clock_at,
    "evaluateBusinessRules": R.evaluate_business_rules,
    "runRuleExamples": R.run_rule_examples,
    "formatMoney": R.format_money,
    "explainBusinessRules": R.explain_business_rules,
    "lintBusinessRules": R.lint_business_rules,
    "diffBusinessRules": R.diff_business_rules,
    "rulesReviewMessage": R.rules_review_message,
    "signRulesReview": R.sign_rules_review,
    "rulesReviewError": R.rules_review_error,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
