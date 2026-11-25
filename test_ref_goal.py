"""Differential replay of the TypeScript reference (@atlasauth/pca-goal): token-tape codec, digests, canonical order, formatting,
policy card, reference semantics, policy digest, decision-to-effect binding and the signing envelope."""
import pytest

from atlas_pca import goal_binding as B
from atlas_pca import goal_card as CD
from atlas_pca import goal_codec as C
from atlas_pca import goal_compiler as CP
from atlas_pca import goal_digests as D
from atlas_pca import goal_fmt as F
from atlas_pca import goal_normalize as N
from atlas_pca import goal_refsem as R
from atlas_pca import goal_sign as S
from atlas_pca.ed25519 import allow_insecure_signer
from base_oracle import b64d, load_ref, run

COUNT, BY_FN = load_ref("goal")


@pytest.fixture(autouse=True, scope="module")
def _signer():
    allow_insecure_signer(True)
    yield
    allow_insecure_signer(False)


FNS = {
    "encodeGoal": C.encode_goal, "decodeGoal": C.decode_goal, "encodeOntology": C.encode_ontology, "encodeAct": C.encode_act,
    "encodeHist": C.encode_hist, "decodePolicy": C.decode_policy,
    "goalDigest": D.goal_digest, "nlDigest": D.nl_digest, "modelSetDigest": D.model_set_digest, "approvalDigest": D.approval_digest,
    "canonicalizeGoal": N.canonicalize_goal, "stable": N.stable,
    "fmtMoney": F.fmt_money, "fmtQuantity": F.fmt_quantity, "fmtValue": F.fmt_value, "fmtAct": F.fmt_act,
    "renderCard": CD.render_card, "renderCond": CD.cond,
    "refExplain": R.ref_explain, "refDecide": R.ref_decide,
    "canonicalPolicy": CP.canonical_policy, "policyDigest": CP.policy_digest,
    "actionDigest": B.action_digest, "bindDecision": B.bind_decision, "guardExecute": B.guard_execute,
    "claimGate": lambda base, mn, rep: B.claim_gate(base, mn, 0, rep), "goalCommit": B.goal_commit, "openCommit": B.open_commit,
    "signPayloadSeed": lambda kind, payload, seed: S.sign_payload(kind, payload, b64d(seed)),
    "signGoalArtifactSeed": lambda kind, body, seed: S.sign_goal_artifact(kind, body, b64d(seed)),
    "signerId": lambda seed: S.signer_id(b64d(seed)), "goalDomain": S.goal_domain,
    "verifyPayload": S.verify_payload, "verifyGoalArtifact": S.verify_goal_artifact,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
