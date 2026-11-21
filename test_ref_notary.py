"""The notary attestation module (atlas_pca.notary) replayed against vectors generated from the TypeScript reference
(@atlasauth/pca-notary): body commitment, selective disclosure, PCActn binding, the attested_fact caveat and key rings."""
import hashlib

import pytest

from atlas_pca import ed25519, notary as N
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("notary")


def _notarize(inp, opts):
    """The reference replaces randomBytes with sha256("notary-oracle-salt/" + i)[:16], restarting at 0 on every call."""
    n = [0]

    def rb(k):
        d = hashlib.sha256(("notary-oracle-salt/%d" % n[0]).encode()).digest()[:k]
        n[0] += 1
        return d

    return N.notarize_response(inp["request"], inp["response"], opts["notaryKey"], observed_at=opts.get("observedAt"),
                               text_chunk_size=opts.get("textChunkSize"), random_bytes=rb)


MAP = {
    "constants": lambda: {"BODY_COMMIT_ALG": N.BODY_COMMIT_ALG, "ATTESTED_FACT_CAVEAT": N.ATTESTED_FACT_CAVEAT},
    "notaryMessage": N.notary_message,
    "notarizeResponse": _notarize,
    "discloseField": N.disclose_field,
    "verifyNotaryAttestation": N.verify_notary_attestation,
    "verifyDisclosedField": N.verify_disclosed_field,
    "factRef": N.fact_ref,
    "bindFactToPcActn": N.bind_fact_to_pc_actn,
    "factMatchesPcActn": N.fact_matches_pc_actn,
    "requireAttestedFact": lambda o: N.require_attested_fact(
        o["notary"], o["path"], o["equals"], **({"url": o["url"]} if "url" in o else {}),
        **({"bind_to_pc_actn": o["bindToPcActn"]} if "bindToPcActn" in o else {})),
    "isAttestedFactCaveat": N.is_attested_fact_caveat,
    "notaryKeyUsable": N.notary_key_usable,
    "evaluateAttestedFactCaveat": N.evaluate_attested_fact_caveat,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 1752 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
