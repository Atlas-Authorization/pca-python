"""Differential replay of the payments port (atlas_pca.payments) against the TypeScript reference (@atlasauth/pca-payments):
mandate build, charge decision (the reference's recorded policy decision is fed back through the injected decider), charge
PCActn, Shared Payment Token limits, spend rails, Stripe Issuing adapter and agent network tokens."""
import pytest

from atlas_pca import ed25519
from atlas_pca import payments as P
from base_oracle import load_ref, run

COUNT, CASES = load_ref("payments")


@pytest.fixture(autouse=True, scope="module")
def _pure_signer():
    ed25519.allow_insecure_signer(True)  # throwaway test keys only
    yield
    ed25519.allow_insecure_signer(False)


def authorize_charge(m, c, g, rec):
    return P.authorize_charge(m, c, g, lambda _input: rec)


def verify_stripe_signature(rb, hd, sc, ns, tl=None):
    return P.verify_stripe_signature(rb, hd, sc, ns) if tl is None else P.verify_stripe_signature(rb, hd, sc, ns, tl)


def stripe_card_params(limits, names, cardholder, metadata):
    opts = {"categoryNames": names, "cardholder": cardholder}
    if metadata is not None:
        opts["metadata"] = metadata
    return P.stripe_card_params(limits, opts)


def stripe_issuing_webhook(raw, sig, secret, now_sec, approved):
    handler = P.create_stripe_issuing_webhook({"secret": secret, "nowSec": lambda: now_sec,
                                               "authorize": lambda a: {"approved": approved, "reasons": []}})
    return handler({"rawBody": raw, "signature": sig})


MAP = {
    "buildPaymentMandate": lambda p: P.build_payment_mandate(p, True),
    "mandatePredicates": P.mandate_predicates,
    "mandateCaveats": P.mandate_caveats,
    "mandateRiskPolicy": P.mandate_risk_policy,
    "autoSpendBound": P.auto_spend_bound,
    "isMinorUnits": P.is_minor_units,
    "isPlainId": P.is_plain_id,
    "chargeActionContext": P.charge_action_context,
    "chargeParams": P.charge_params,
    "chargePlanNode": P.charge_plan_node,
    "chargeDecideInput": P.charge_decide_input,
    "authorizeCharge": authorize_charge,
    "chargeToPCActn": lambda m, c, o: P.charge_to_pcactn(m, c, o, True),
    "settleCharge": P.settle_charge,
    "applyHumanCosign": P.apply_human_cosign,
    "sharedPaymentTokenLimits": P.shared_payment_token_limits,
    "railLimits": P.rail_limits,
    "categoriesFromTraits": P.categories_from_traits,
    "reconcileSettlement": P.reconcile_settlement,
    "verifyStripeSignature": verify_stripe_signature,
    "signStripePayload": P.sign_stripe_payload,
    "stripeCardParams": stripe_card_params,
    "stripeAuthorizationFromEvent": P.stripe_authorization_from_event,
    "stripeIssuingWebhook": stripe_issuing_webhook,
    "stripeSettlementFromTransaction": P.stripe_settlement_from_transaction,
    "tokenRefError": P.token_ref_error,
    "looksLikePan": P.looks_like_pan,
    "bindNetworkToken": lambda o: P.bind_network_token(o, True),
    "verifyNetworkTokenBinding": P.verify_network_token_binding,
    "bindingMessage": P.binding_message,
    "controlsFromLimits": P.controls_from_limits,
    "settlementMetadata": P.settlement_metadata,
    "reconcileNetworkSettlement": P.reconcile_network_settlement,
    "chargeWithNetworkToken": lambda b, m, c, o: P.charge_with_network_token(b, m, c, o, True),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 3144 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_rail_authorizer_declines_everything_but_an_auto_decision():
    from atlas_pca.payments import create_rail_authorizer

    authorize = create_rail_authorizer({"instruments": lambda i: None, "store": object(), "decide": lambda x: {}})
    assert authorize({"id": "a1", "instrumentId": "c", "amount": 5, "currency": "USD", "merchantId": "m"})["reasons"] == ["instrument_unknown"]
    assert authorize(None)["reasons"] == ["malformed_authorization"]
    assert authorize({"id": "a1", "instrumentId": "c", "amount": 0, "currency": "USD", "merchantId": "m"})["reasons"] == ["amount_not_positive_minor_units"]
