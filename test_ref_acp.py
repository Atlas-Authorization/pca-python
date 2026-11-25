"""ACP delegated payment tokens, x402 v1 and v2 (and its HTTP transport) and Stripe Shared Payment Granted Tokens
(atlas_pca.acp) replayed against vectors generated from the TypeScript reference (@atlasauth/pca-acp). Stores, verifiers and
settle steps are built from the specs the corpus names; a token that reaches the full proof verifier is not in the corpus."""
import re

import pytest

from atlas_pca import acp as A
from base_oracle import load_ref, run

COUNT, CASES = load_ref("acp")

_REASON = re.compile(r"^(token signature did not verify|bound proof failed to verify): .*$", re.S)


class _Store:
    def __init__(self, fn):
        self.claim = fn


def _store(spec):
    """The single-use store a spec names; any other value is passed through as is (and is not a store)."""
    if spec == "once":
        seen = set()

        def claim(jti, _exp):
            if jti in seen:
                return False
            seen.add(jti)
            return True
        return _Store(claim)
    if spec == "always":
        return _Store(lambda *_: True)
    if spec == "never":
        return _Store(lambda *_: False)
    if spec == "throw":
        def boom(*_):
            raise RuntimeError("store down")
        return _Store(boom)
    if spec == "truthy":
        return _Store(lambda *_: 1)
    return spec


def _norm(r):
    out = dict(r)
    if isinstance(out.get("reason"), str):
        out["reason"] = _REASON.sub(r"\1", out["reason"])
    if out.get("pcaResult"):
        out["pcaResult"] = {"allow": out["pcaResult"]["allow"]}
    return out


def _with_store(op):
    return dict(op, singleUse=_store(op["singleUse"])) if "singleUse" in op else op


def _verify_token(token, op, times=1):
    o2 = _with_store(op)
    rs = [_norm(A.verify_delegated_payment_token(token, o2)) for _ in range(times)]
    return rs[0] if times == 1 else rs


def _x402_verifier(payload, op, times=1):
    fn = A.acp_x402_verifier(_with_store(op))
    rs = [_norm(fn(payload)) for _ in range(times)]
    return rs[0] if times == 1 else rs


def _settle(payload, vspec, sspec=None):
    def verify(_p):
        if vspec == "throw":
            raise RuntimeError("verify down")
        return dict(vspec)
    o = {"verify": verify}
    if sspec == "echo":
        o["settle"] = lambda p, c: dict({"jti": c["jti"]}, **({"token": p["token"]} if "token" in p else {}))  # an undefined member is dropped
    elif sspec == "value":
        o["settle"] = lambda *_: "receipt-1"
    elif sspec == "throw":
        def boom(*_):
            raise RuntimeError("settle down")
        o["settle"] = boom
    elif sspec == "undef":
        o["settle"] = lambda *_: None
    return A.x402_settle(payload, o)


MAP = {
    "constants": lambda: {"v": A.ACP_DELEGATED_TOKEN_VERSION, "t": A.ACP_DELEGATED_TOKEN_TYPE, "s": A.SPEND_CAP_CAVEAT, "m": A.MERCHANT_ALLOW_CAVEAT,
                          "c": A.MERCHANT_CATEGORY_CAVEAT, "h": A.HUMAN_PRESENT_CAVEAT, "x1": A.X402_VERSION_1, "x2": A.X402_VERSION_2,
                          "sup": list(A.X402_SUPPORTED_VERSIONS), "pr": A.X402_V2_PAYMENT_REQUIRED_HEADER, "ps": A.X402_PAYMENT_SIGNATURE_HEADER,
                          "pe": A.X402_PAYMENT_RESPONSE_HEADER, "st": A.X402_HTTP_STATUS, "spt": A.STRIPE_SPT_OBJECT},
    "spendCapCaveat": A.spend_cap_caveat,
    "merchantAllowCaveat": A.merchant_allow_caveat,
    "merchantCategoryCaveat": A.merchant_category_caveat,
    "humanPresentCaveat": A.human_present_caveat,
    "extractPaymentAuthority": A.extract_payment_authority,
    "checkPaymentAuthority": A.check_payment_authority,
    "mintDelegatedPaymentToken": A.mint_delegated_payment_token,
    "verifyDelegatedPaymentToken": _verify_token,
    "x402Challenge": A.x402_challenge,
    "x402ChallengeV2": A.x402_challenge_v2,
    "x402Settle": _settle,
    "acpX402Verifier": _x402_verifier,
    "toAcpAllowance": A.to_acp_allowance,
    "resourceInfoProblems": A.resource_info_problems,
    "requirementV2Problems": A.requirement_v2_problems,
    "paymentRequiredV2Problems": A.payment_required_v2_problems,
    "paymentPayloadV2Problems": A.payment_payload_v2_problems,
    "settlementResponseProblems": A.settlement_response_problems,
    "stripeSptProblems": A.stripe_spt_problems,
    "encodePaymentRequiredHeader": A.encode_payment_required_header,
    "decodePaymentRequiredHeader": A.decode_payment_required_header,
    "encodePaymentSignatureHeader": A.encode_payment_signature_header,
    "decodePaymentSignatureHeader": A.decode_payment_signature_header,
    "encodePaymentResponseHeader": A.encode_payment_response_header,
    "decodePaymentResponseHeader": A.decode_payment_response_header,
    "x402Negotiate": A.x402_negotiate,
    "x402AcceptedMatches": A.x402_accepted_matches,
    "normalizeX402Payload": A.normalize_x402_payload,
    "readPaymentSignature": A.read_payment_signature,
    "x402SettlementResponse": A.x402_settlement_response,
    "x402PaymentSignatureHeaders": A.x402_payment_signature_headers,
    "parseStripeSpt": A.parse_stripe_spt,
    "stripeSptUsable": A.stripe_spt_usable,
    "stripeUsageLimitsFor": A.stripe_usage_limits_for,
    "stripeSptWithinClaims": A.stripe_spt_within_claims,
}


def test_every_function_in_the_corpus_is_replayed():
    assert COUNT > 0 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
