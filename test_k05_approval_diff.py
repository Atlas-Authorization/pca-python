"""k05 differential oracle: the canonical approval render (atlas_pca.approval: shape, digest, challenge, binding words,
render, PSD2 linking, minor units, batches) against the shared TS-generated testdata/k05-approval.json.gz."""
import pytest

from atlas_pca import actions, approval as A
from k05_oracle import canon, load, run

COUNT, CASES = load("approval")


def _batch_eq(got, out, _c):
    """The reference returns the batch challenge as bytes ({"$bytes": b64url}); Python returns the b64url string."""
    ch = out.get("challenge")
    return canon(got) == canon(dict(out, challenge=ch["$bytes"]) if isinstance(ch, dict) else out)


MAP = {
    "approvalRenderShapeError": (A.approval_render_shape_error, {}),
    "approvalRenderDigest": (A.approval_render_digest, {}),
    "approvalChallengeB64u": (A.approval_challenge, {}),
    "bindingWords": (A.binding_words, {}),
    # no def here carries a signed confirmation: the TS render is always unreviewed
    "renderApproval": (lambda d, p: A.render_approval(d, p, False), {}),
    "validateDef": (actions.validate_def, {}),
    "psd2Linking": (A.psd2_linking, {}),
    "minorToDecimal": (A.minor_to_decimal, {}),
    "approvalBatch": (A.approval_batch, {"compare": _batch_eq}),
}
SKIP = {
    "spcExpectation": "the Secure Payment Confirmation profile is TS-only (no Python twin)",
    "cibaApprovalDetails": "the CIBA authorization_details profile is TS-only (no Python twin)",
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 4791 and set(CASES) == set(MAP) | set(SKIP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    run(CASES[fn], call, **kw)
