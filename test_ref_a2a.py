"""The A2A adapter (atlas_pca.a2a, atlas_pca.a2a_card) replayed against vectors generated from the TypeScript reference
(@atlasauth/pca-a2a): tasks, signed and extended cards, RFC 8785, the A2A 1.0 schema, AUTH_REQUIRED, delegation, push tokens,
payment-mandate envelopes and signed receipts. Cases that would reach the full verifier are not in the corpus."""
import hashlib
import re

import pytest

from atlas_pca import a2a as A, a2a_card as C
from base_oracle import canon, load_ref, run

COUNT, CASES = load_ref("a2a")

_COLON = re.compile(r"^(signature \d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): ")


def _norm(r):
    """The reasons that quote the JOSE library or a runtime error are compared up to the first colon."""
    if isinstance(r, dict) and isinstance(r.get("reason"), str):
        m = _COLON.match(r["reason"])
        if m:
            return dict(r, reason=m.group(1))
    return r


def _eq(got, out, _c):
    return canon(_norm(got)) == canon(_norm(out))


def _seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()


def _ctx(x):
    return dict(x, context=(lambda _p, c=x["context"]: c)) if isinstance(x, dict) and "context" in x else x


MAP = {
    "constants": lambda: {"PCA_A2A_EXTENSION_URI": A.PCA_A2A_EXTENSION_URI, "TASK_STATE_AUTH_REQUIRED": A.TASK_STATE_AUTH_REQUIRED,
                          "TASK_STATE_INPUT_REQUIRED": A.TASK_STATE_INPUT_REQUIRED, "A2A_AP2_CONTEXT": list(A.A2A_AP2_CONTEXT),
                          "A2A_RECEIPT_DOMAIN": A.A2A_RECEIPT_DOMAIN, "RECEIPT_KEY": A.RECEIPT_KEY},
    "jcsBytes": C.jcs_bytes,
    "validateAgentCard1": C.validate_agent_card1,
    "attachPcaToA2ATask": A.attach_pca_to_a2a_task,
    "attachPcaToA2AMessage": A.attach_pca_to_a2a_message,
    "extractPca": A.extract_pca,
    "extractPcaFromMessage": A.extract_pca_from_message,
    "issueSignedAgentCard": lambda card, k, x=None: C.issue_signed_agent_card(card, k, x),
    "verifyAgentCard": C.verify_agent_card,
    "verifyA2ATask": A.verify_a2a_task,
    "middleware": lambda t, o=None: A.pca_a2a_middleware(o)(t),
    "resumeAuthRequired": A.resume_auth_required,
    "verifyA2ADelegation": A.verify_a2a_delegation,
    "a2aPaymentMandateFromPca": A.a2a_payment_mandate_from_pca,
    "pcaBindingFromA2APaymentMandate": A.pca_binding_from_a2a_payment_mandate,
    "verifyA2APaymentMandate": lambda m, p, x=None: A.verify_a2a_payment_mandate(m, p, _ctx(x)),
    "pcaExtensionDeclaration": A.pca_extension_declaration,
    "readPcaExtension": A.read_pca_extension,
    "clientOptsIntoPca": A.client_opts_into_pca,
    "isAuthRequired": A.is_auth_required,
    "authRequiredStatus": A.auth_required_status,
    "readAuthRequiredNeed": A.read_auth_required_need,
    "answerMessage": A.answer_message,
    "resumeGate": A.resume_gate_obj,
    "chainExtends": A.chain_extends,
    "checkChainExtension": A.check_chain_extension,
    "pcaPushToken": A.pca_push_token,
    "checkPushNotification": A.check_push_notification,
    "uniformTaskNotFound": A.uniform_task_not_found,
    "signTaskReceipt": lambda label, o: A.sign_task_receipt(_seed(label), o),
    "verifyTaskReceipt": A.verify_receipt,
    "receiptDigest": A.receipt_digest,
    "checkReceiptChain": lambda r, o: A.check_receipt_chain_result(r, o["signer"], o["taskId"], o["chainIds"]),
    "mayTriggerNext": lambda r, o: A.may_trigger_next(r, o["signer"], o["taskId"], o["chainIds"]),
    "attachReceipt": A.attach_receipt,
    "receiptOfPayload": A.receipt_of_payload,
    "extendedAgentCard": C.extended_agent_card,
}


def test_every_function_in_the_corpus_is_replayed():
    assert COUNT > 0 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn], compare=_eq)
