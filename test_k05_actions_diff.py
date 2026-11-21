"""k05 differential oracle: the action kit (atlas_pca.actions: validate_def and its sub-checks, id patterns, the strict JSON
profile, trait registries, closure / floors, normalize, digests, effective, reviewer pins, the signed confirmation, rule 22
schema floors, pack roots / proofs) against the shared TS-generated testdata/k05-actions.json.gz."""
import pytest

from atlas_pca import actions as A
from k05_oracle import load, run

COUNT, CASES = load("actions")
CORE = A.CORE_REGISTRY


def reg_of(custom):
    return CORE if custom is None else A.extend_registry(CORE, custom)


MAP = {
    "validateDef": A.validate_def,
    "isRole": A.is_role,
    "isFormat": A.is_format,
    "isContextKey": A._is_context_key,
    "paramNameError": A.param_name_error,
    "jsonProfileError": A.json_profile_error,
    "idPatternError": A.id_pattern_error,
    "profileError": A.profile_error,
    "registryError": lambda defs, core: A.registry_error(defs, core=core),
    "closure": lambda custom, ids: A.closure(reg_of(custom), ids),
    "floorOf": lambda custom, ids: A.floor_of(reg_of(custom), ids),
    "topTraits": lambda custom: A.top_traits(reg_of(custom)),
    "traitsDigest": lambda custom: A.traits_digest(reg_of(custom)),
    "tablesDigest": A.tables_digest,
    "floorDecision": A.floor_decision,
    "worstReversibility": A.worst_reversibility,
    "sensitivityFloor": A.sensitivity_floor,
    "impliedFromFacts": lambda f: A.implied_from_facts(f["effects"], f["params"], f.get("scope"), f["worstRev"]),
    "normalize": A.normalize,
    "defDigest": A.def_digest,
    "declProfile": A.decl_profile,
    "hintTraits": A.hint_traits,
    "effective": lambda d, pins: A.effective(d, CORE, pins),
    "reviewerPinsError": A.reviewer_pins_error,
    "reviewMessage": A.review_message,
    "isConfirmed": lambda d, pins: A.verify_attestation(d, CORE, pins),
    "factsDigest": A.facts_digest,
    "schemaVerbFloorError": lambda v, pins: A.schema_verb_floor_error(v, CORE, pins),
    "schemaFloorError": lambda doc, pins: A.schema_floor_error(doc, pins),
    "packRoot": A.pack_root,
    "packProof": A.pack_proof,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 65203 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
