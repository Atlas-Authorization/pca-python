"""Differential replay of the portable intent profiles (shape, signing, verification, succession, scope, standing rules,
veto cells, usability) against the TypeScript reference (@atlasauth/pca-intent) vectors."""
from atlas_pca import intent_profile as P
from atlas_pca.pca import decode_b64u_strict
from base_oracle import load_ref, run

COUNT, CASES = load_ref("intent-profile")


def _shape(p, opts=None):
    return P.intent_profile_shape_error(p, signed=not (isinstance(opts, dict) and opts.get("signed") is False))


MAP = {
    "signIntentProfile": lambda body, seed: P.sign_intent_profile(body, decode_b64u_strict(seed, 32)),
    "intentProfileShapeError": _shape,
    "verifyIntentProfile": P.verify_intent_profile,
    "intentProfileDigest": P.intent_profile_digest,
    "verifyProfileSuccession": P.verify_profile_succession,
    "profileApplies": P.profile_applies,
    "standingAdmits": P.standing_admits,
    "standingPermits": P.standing_permits,
    "profileVetoCells": P.profile_veto_cells,
    "profileCeiling": lambda p, u, vs, o: P.profile_ceiling(p, u)(vs, o),
    "profileUsable": P.profile_usable,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn])
