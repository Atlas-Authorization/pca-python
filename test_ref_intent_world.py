"""Differential replay of the verifier-filled outcome-space dimensions (world, provenance, classifier labels) against the
TypeScript reference (@atlasauth/pca-intent) vectors."""
from atlas_pca import intent_world as W
from base_oracle import load_ref, run

COUNT, CASES = load_ref("intent-world")

MAP = {
    "worldDim": W.world_dim,
    "excessDim": W.excess_dim,
    "optimalityCondition": W.optimality_condition,
    "provenanceDim": W.provenance_dim,
    "classifierDim": W.classifier_dim,
    "withDims": W.with_dims,
    "liftOutcome": W.lift_outcome,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn])
