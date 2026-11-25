"""Differential replay of atlas_pca.evidence.verify_evidence_bundle (the dispute evidence replay: findings, summary, report digest) against
vectors generated from the TypeScript reference (@atlasauth/pca-evidence) over the chargeback walkthrough and its tampered / re-trusted variants.
`trust.verifiers` members are constant verdicts the native ports return."""
from atlas_pca import evidence as E
from base_oracle import load_ref, run

COUNT, CASES = load_ref("evidence-bundle-py")


def verify(bundle, trust):
    if trust is not None and trust.get("verifiers") is not None:
        trust = dict(trust, verifiers={k: (lambda _a, _b, v=v: v) for k, v in trust["verifiers"].items()})
    return E.verify_evidence_bundle(bundle, trust)


def test_evidence_bundle_matches_reference():
    assert set(CASES) == {"verifyEvidenceBundle"}
    ran, _ = run(CASES["verifyEvidenceBundle"], verify)
    assert ran == COUNT
