"""Differential replay: schema verb/document, operation binding, risk, predicates, ontology, policy card, MCP annotations and the
explanation of an ActionDef against the TypeScript reference."""
import pytest

from atlas_pca import actions as A
from atlas_pca import actions_derive as DR
from atlas_pca import actions_effective as E
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-derive")
CORE = A.CORE_REGISTRY


def _opt(c):
    return lambda _d: c


def _reg(reg_defs):
    return CORE if reg_defs is None else A.extend_registry(CORE, reg_defs)


MAP = {
    "flattenParams": DR.flatten_params,
    "paramByRole": DR.param_by_role,
    "effectClass": DR.effect_class,
    "toSchemaVerb": lambda d, c: DR.to_schema_verb(d, CORE, _opt(c)),
    "toSchemaDoc": lambda ds, m, c, rd: DR.to_schema_doc(ds, _reg(rd), m, _opt(c)),
    "operationOf": lambda d, p: DR.operation_of(d, {"params": p}),
    "riskOf": lambda d, c, p, o: DR.risk_of(d, E.effective_with(d, CORE, _opt(c)), p, o),
    "resourceMatcher": DR.resource_matcher,
    "predicatesOf": DR.predicates_of,
    "toOntology": lambda ds, c: DR.to_ontology(ds, CORE, _opt(c)),
    "cardOf": lambda d, c: DR.card_of(d, E.effective_with(d, CORE, _opt(c)), CORE),
    "escalationOf": lambda d, c: DR.escalation_of(E.effective_with(d, CORE, _opt(c))),
    "mcpAnnotationsOf": lambda d, c: DR.mcp_annotations_of(d, E.effective_with(d, CORE, _opt(c))),
    "explainDef": lambda d, c: DR.explain_def(d, CORE, _opt(c)),
    "REVERSIBILITY_SCORE": lambda: DR.REVERSIBILITY_SCORE,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
