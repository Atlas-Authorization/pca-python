"""Differential replay of the TypeScript reference (@atlasauth/pca-goal selectors): the verbs of a class selector, role resolution,
expansion of a selector goal against the pinned catalog, selector typing, role keys, the policy card and the carrier form. The catalog
and ontology of a shipped domain travel by name and are resolved from the shipped data."""
import pytest

from atlas_pca import goal_ontologies as OS
from atlas_pca import goal_ontology as O
from atlas_pca import goal_selectors as S
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("goal-selectors-py")
COUNT_REF, BY_FN_REF = load_ref("goal-selectors-java")


def _ont(dom):
    return O.to_ir_ontology(OS.shipped_ontology(dom))


FNS = {
    "selCatalogOfDomain": S.sel_catalog_of_domain, "selCatalogDigest": S.sel_catalog_digest, "selGoalDigest": S.sel_goal_digest,
    "classVerbs": S.class_verbs, "allowClassVerbs": S.allow_class_verbs, "floatClassVerbs": S.float_class_verbs,
    "resolveRole": lambda dom, cat, verb, role: S.resolve_role(_ont(dom), cat, verb, role),
    "expandSelGoal": lambda sg, dom, cat: S.expand_sel_goal(sg, _ont(dom), cat),
    "selReasons": lambda sg, dom, cat: S.sel_reasons(sg, _ont(dom), cat),
    "withRoleParams": S.with_role_params, "selCarrier": S.sel_carrier, "encodeSelCatalog": S.encode_sel_catalog,
    "renderSelCard": lambda sg, dom, cat: S.render_sel_card(sg, _ont(dom), cat), "traitClosure": S.trait_closure,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])


# the second corpus: a hand-written catalog with confirmed verbs, the selector typing refusals and the catalog of a pack of defs
def _ref_ont(x):
    return O.to_ir_ontology(OS.shipped_ontology(x)) if isinstance(x, str) and OS.shipped_ontology(x) is not None else x


def _ref_cat(x):
    return OS.shipped_catalog(x) if isinstance(x, str) and OS.shipped_catalog(x) is not None else x


REF_FNS = {
    "selCatalogDigest": lambda c: S.sel_catalog_digest(_ref_cat(c)), "selGoalDigest": S.sel_goal_digest,
    "classVerbs": lambda c, a, n: S.class_verbs(_ref_cat(c), a, n), "allowClassVerbs": lambda c, a, n: S.allow_class_verbs(_ref_cat(c), a, n),
    "floatClassVerbs": lambda c, a, n: S.float_class_verbs(_ref_cat(c), a, n),
    "resolveRole": lambda o, c, v, r: S.resolve_role(_ref_ont(o), _ref_cat(c), v, r),
    "expandSelGoal": lambda sg, o, c: S.expand_sel_goal(sg, _ref_ont(o), _ref_cat(c)),
    "selReasons": lambda sg, o, c: S.sel_reasons(sg, _ref_ont(o), _ref_cat(c)),
    "compileSelGoal": lambda sg, o, c: S.compile_sel_goal(sg, _ref_ont(o), _ref_cat(c)),
    "withRoleParams": lambda a, c: S.with_role_params(a, _ref_cat(c)), "renderSelCard": lambda sg, o, c: S.render_sel_card(sg, _ref_ont(o), _ref_cat(c)),
    "selCarrier": S.sel_carrier, "encodeSelCatalog": lambda c: S.encode_sel_catalog(_ref_cat(c)), "traitClosure": S.trait_closure,
    "catalogOfDomain": S.sel_catalog_of_domain, "catalogOfDefs": lambda defs: S.sel_catalog_of_defs(defs),
}


def test_reference_corpus_every_function_is_covered():
    assert set(BY_FN_REF) == set(REF_FNS)


@pytest.mark.parametrize("fn", sorted(REF_FNS))
def test_matches_reference_corpus(fn):
    ran, _ = run(BY_FN_REF[fn], REF_FNS[fn])
    assert ran == len(BY_FN_REF[fn])
