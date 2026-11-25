"""Differential replay of the dispute evidence bundle (atlas_pca.evidence: shape validation, normal form, commitments-only form,
digest, reference and anchor leaf, accumulator cap reader, trust-input validators) against vectors generated from the TypeScript
reference (@atlasauth/pca-evidence). A reference throw requires the port to raise; the trust validators' absent argument is the
no-argument case."""
import pytest

from atlas_pca import evidence as E
from base_oracle import load_ref, run

COUNT, CASES = load_ref("evidence")

MAP = {
    "bundleShapeError": E.bundle_shape_error,
    "normalizeBundle": E.normalize_bundle,
    "buildEvidenceBundle": E.build_evidence_bundle,
    "commitmentForm": E.commitment_form,
    "evidenceDigest": E.evidence_digest,
    "evidenceRef": E.evidence_ref,
    "evidenceAnchorCommit": E.evidence_anchor_commit,
    "anchorCommit": E.anchor_commit,
    "capOf": E.cap_of,
    "principalsTrustError": E.principals_trust_error,
    "accTrustError": E.acc_trust_error,
    "consts": lambda: {"EVIDENCE_DOMAIN": E.EVIDENCE_DOMAIN, "EVIDENCE_REPORT_DOMAIN": E.EVIDENCE_REPORT_DOMAIN,
                       "EVIDENCE_CONTENT_TYPE": E.EVIDENCE_CONTENT_TYPE},
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 1772 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
