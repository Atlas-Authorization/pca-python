"""Differential replay of the policy bridge (atlas_pca.policy_bridge) against vectors generated from the TypeScript reference
(@atlasauth/pca-policy-bridge): Cedar / Rego / OpenFGA / strict-CEL translation of engine-checked corpora, hand-written constructs
and refusals, seeded mutations of both (hostile text), and deny-overrides-permit `decide`."""
import pytest

from atlas_pca import policy_bridge as B
from base_oracle import load_ref, run

COUNT, CASES = load_ref("policy-bridge")

MAP = {
    "cedarToPca": B.cedar_to_pca,
    "translateCedar": B.translate_cedar,
    "regoToPca": B.rego_to_pca,
    "openfgaToPca": B.openfga_to_pca,
    "decide": B.decide,
    "celToCondition": B.cel_to_condition,
    "celToPredicate": B.cel_to_predicate,
    "celConditionsToPca": B.cel_conditions_to_pca,
    "parseCel": B.parse_cel,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 4361 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
