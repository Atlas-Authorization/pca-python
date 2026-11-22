"""Differential replay of the TypeScript reference (@atlasauth/pca-goal ontology): verb resolution, IR projection, the well-formedness
checker, template instantiation, slot typing, locale-aware amount parsing and the shipped ontology data."""
import pytest

from atlas_pca import goal_ontologies as OS
from atlas_pca import goal_ontology as O
from atlas_pca.analyzer_js import UNDEF
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("goal-ontology")


def _o(x):
    """A shipped ontology travels by name; a hand-written one inline."""
    return OS.shipped_ontology(x) if isinstance(x, str) and OS.shipped_ontology(x) is not None else x


FNS = {
    "shippedOntology": OS.shipped_ontology, "shippedCatalog": OS.shipped_catalog,
    "ontologyDigest": lambda o: O.ontology_digest(_o(o)),
    "resolveVerb": lambda o, w: O.resolve_verb(_o(o), w),
    "goalCcy": O.goal_ccy, "goalAnchors": O.goal_anchors,
    "toIrOntology": lambda o, op: O.to_ir_ontology(_o(o), op),
    "ontologyForGoal": lambda o, g, rels=None: O.ontology_for_goal(_o(o), g, rels),
    "checkOntology": lambda o: O.check_ontology(_o(o)),
    "instantiateTemplate": lambda o, tid, vals, opts: O.instantiate_template(_o(o), tid, vals, opts),
    "slotLits": lambda o, s, v: O.slot_lits(_o(o), s, UNDEF if v is None else v),
    "parseHumanAmount": O.parse_human_amount, "parseMoney": O.parse_money,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
