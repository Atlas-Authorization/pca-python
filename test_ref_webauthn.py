"""Differential replay of the WebAuthn / FIDO2 step-up co-sign verifier, COSE_Key reader and challenge derivation against
the TypeScript reference (@atlasauth/pca-webauthn)."""
import pytest

pytest.importorskip("cryptography")  # the dependency-free job has no cryptography; every other job replays this corpus

from atlas_pca import webauthn as W
from base_oracle import canon, load_ref, run

COUNT, CASES = load_ref("webauthn-py")

# these two reasons end in a runtime error message, which is the language's own
_LOOSE = ("public key could not be resolved:", "verification error (fail closed):")


def _verify(a, e):
    reg = []
    res = W.verify_assertion(a, dict(e, on_sign_count_regression=reg.append))
    return {"result": res, "regression": reg}


def _cmp_verify(got, out, _c):
    g, o = got["result"], out["result"]
    if canon(got["regression"]) != canon(out["regression"]) or g.get("ok") != o.get("ok"):
        return False
    if o.get("ok"):
        return canon(g) == canon(o)
    r = o["reason"]
    for p in _LOOSE:
        if r.startswith(p):
            return g["reason"].startswith(p)
    return g["reason"] == r


MAP = {
    "constants": (lambda: {"MAX_AUTHENTICATOR_DATA_BYTES": W.MAX_AUTHENTICATOR_DATA_BYTES, "MAX_CLIENT_DATA_BYTES": W.MAX_CLIENT_DATA_BYTES,
                           "MAX_SIGNATURE_BYTES": W.MAX_SIGNATURE_BYTES}, {}),
    "coseKeyToJwk": (W.cose_key_to_jwk, {}),
    "parseAuthenticatorData": (W.parse_authenticator_data, {}),
    "buildStepUpChallenge": (W.build_step_up_challenge, {}),
    "stepUpChallengeB64u": (W.step_up_challenge_b64u, {}),
    "buildApprovalChallenge": (W.build_approval_challenge, {}),
    "approvalChallengeForActn": (W.approval_challenge_for_actn, {}),
    "spcPaymentError": (W.spc_payment_error, {}),
    "verifyAssertion": (_verify, {"compare": _cmp_verify}),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    run(CASES[fn], call, **kw)
