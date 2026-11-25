"""Differential replay of the intent renderer, back-translation diff and boundary witnesses against the TypeScript
reference (@atlasauth/pca-intent) vectors."""
from atlas_pca import intent_render as R, intent_witnesses as W
from base_oracle import load_ref, run

COUNT, CASES = load_ref("intent-render")


def _oracle(mode):
    if mode == "agree":
        return lambda w: w["grantAllows"]
    if mode == "flip":
        return lambda w: not w["grantAllows"]
    if mode == "flip-boundary":
        return lambda w: (not w["grantAllows"]) if w["kind"] == "boundary" else w["grantAllows"]
    return lambda w: w["side"] == "inside" and w["kind"] != "unconstrained"


MAP = {
    "labelOf": R.label_of,
    "renderCondition": R.render_condition,
    "renderCaveat": R.render_caveat,
    "renderGrant": R.render_grant,
    "renderQuestion": R.render_question,
    "renderAction": R.render_action,
    "claimsOf": R.claims_of,
    "backTranslationDiff": R.back_translation_diff,
    "claimDiff": R.claim_diff,
    "boundaryWitnesses": W.boundary_witnesses,
    "checkWitnesses": lambda ws, mode: W.check_witnesses(ws, _oracle(mode)),
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn])
