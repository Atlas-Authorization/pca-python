"""Differential oracle: the prohibition plane (atlas_pca.prohibitions) against the shared prohibitions corpus in testdata/.
Secrets travel as base64url of the 32-byte Ed25519 seed. Cases named `fn/x:` hold a value the canonical hash refuses (-0, an integer
beyond 2^53-1, a lone surrogate) and replay together, apart from the ordinary ones."""
import pytest

from atlas_pca import prohibitions as P
from k05_oracle import b64d, load, run

COUNT, CASES = load("prohibitions")


MAP = {
    "validateInvariant": P.validate_invariant,
    "validateConstitution": P.validate_constitution,
    "stateProblem": P.state_problem,
    "canonicalState": P.canonical_state,
    "stateDigest": P.state_digest,
    "tickState": P.tick_state,
    "emptyState": P.empty_state,
    "checkProhibitions": P.check_prohibitions,
    "advanceStateStrict": P.advance_state_strict,
    "proveSafety": P.prove_safety,
    "verifySafetyEvidence": P.verify_safety_evidence,
    "safetyBindingId": P.safety_binding_id,
    "signSafetyEvidence": lambda ev, sk, pub: P.sign_safety_evidence(ev, b64d(sk), pub),
    "verifySignedSafetyEvidence": P.verify_signed_safety_evidence,
    "checkAndAdvance": P.check_and_advance,
    "verifyConstitution": P.verify_constitution,
    "constitutionId": P.constitution_id,
    "whenAffirmative": P.when_affirmative,
}


def _exotic(c):
    return c["name"].split("/", 1)[1].startswith("x:")


def test_corpus_is_the_full_oracle():
    assert COUNT == 21781 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _ = run([c for c in CASES[fn] if not _exotic(c)], MAP[fn])
    assert ran > 0


def test_inputs_the_canonical_hash_refuses_match_the_reference():
    ran = 0
    for fn in sorted(MAP):
        sub = [c for c in CASES[fn] if _exotic(c)]
        if sub:
            ran += run(sub, MAP[fn])[0]
    assert ran > 0
