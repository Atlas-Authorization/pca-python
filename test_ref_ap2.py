"""Differential oracle: AP2 mandates as SD-JWT credentials (strict parsing, disclosure processing, ES256, mandate validators and minor units,
open-mandate constraint evaluation, delegation chains, purchases and the redeem ledger, PCA terms bridge, settlement payloads;
atlas_pca.ap2) against the vectors generated from the TypeScript reference (@atlasauth/pca-ap2).

Keys are derived from labels (d = sha256("atlas-pca-conformance/ap2/<label>")); ECDSA signatures are randomized, so every signing function is
compared with each signature segment replaced by "SIG"."""
import hashlib
import re

import pytest

pytest.importorskip("cryptography")

from atlas_pca import ap2 as A  # noqa: E402
from base_oracle import load_ref, run  # noqa: E402

COUNT, CASES = load_ref("ap2")
T0 = 1_800_000_000

_KEYS = {}


def key_for(label):
    if label not in _KEYS:
        from cryptography.hazmat.primitives.asymmetric import ec
        d = hashlib.sha256(("atlas-pca-conformance/ap2/%s" % label).encode()).digest()
        pub = ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1()).public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "d": A.b64u_encode(d), "x": A.b64u_encode(pub.x.to_bytes(32, "big")),
               "y": A.b64u_encode(pub.y.to_bytes(32, "big")), "kid": label}
        _KEYS[label] = A.ap2_key_pair_from_private_jwk(jwk)
    return _KEYS[label]


def priv_of(label):
    from cryptography.hazmat.primitives.asymmetric import ec
    d = hashlib.sha256(("atlas-pca-conformance/ap2/%s" % label).encode()).digest()
    pub = ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1()).public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "d": A.b64u_encode(d), "x": A.b64u_encode(pub.x.to_bytes(32, "big")),
            "y": A.b64u_encode(pub.y.to_bytes(32, "big")), "kid": label}


def counter_salt():
    n = [0]

    def salt():
        n[0] += 1
        return A.b64u_encode(("salt-%012d" % n[0]).encode())
    return salt


def strip_sig(t):
    return "~".join(re.sub(r"\.[A-Za-z0-9_-]+$", ".SIG", s) if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", s) else s for s in t.split("~"))


def mask_reason(s):
    return re.sub(r"invalid JSON \(.*\)\Z", "invalid JSON (*)", s, flags=re.S) if isinstance(s, str) else s


def resolver(m):
    return lambda h: m[h["kid"]] if isinstance(m, dict) and isinstance(h.get("kid"), str) and h["kid"] in m else None


def base_opts(c):
    o = {"resolveIssuerKey": resolver(c.get("issuerKeys")), "resolveMerchantKey": resolver(c.get("merchantKeys")),
         "expectedAudience": c.get("expectedAudience"), "expectedNonce": c.get("expectedNonce")}
    if c.get("now") is not None:
        o["now"] = c["now"]
    if c.get("clockSkewSeconds") is not None:
        o["clockSkewSeconds"] = c["clockSkewSeconds"]
    return o


def hop_out(h):
    return {"index": h["index"], "kind": h["kind"], "claims": h["claims"], "mandate": h["mandate"]}


def proj_chain(r):
    if not r["ok"]:
        out = {"ok": False, "reason": mask_reason(r["reason"])}
        if r.get("violations"):
            out["violations"] = r["violations"]
        return out
    out = {"ok": True, "hops": [hop_out(h) for h in r["hops"]]}
    if r.get("open"):
        out.update(open=r["open"], closed=r["closed"])
    if r.get("checkoutJwt"):
        out.update(checkoutJwt=r["checkoutJwt"], checkout=r["checkout"])
    if r.get("openHash"):
        out["openHash"] = r["openHash"]
    return out


def proj_purchase(r):
    if r["ok"]:
        return {"ok": True, "checkout": proj_chain(r["checkout"]), "payment": proj_chain(r["payment"])}
    return {"ok": False, "reason": mask_reason(r["reason"])}


def purch_opts_of(c):
    o = {"resolveIssuerKey": resolver(c.get("issuerKeys")), "resolveMerchantKey": resolver(c.get("merchantKeys")),
         "checkout": c.get("checkout"), "payment": c.get("payment")}
    for k in ("context", "now", "clockSkewSeconds"):
        if c.get(k) is not None:
            o[k] = c[k]
    return o


def dc(t, c):
    return proj_chain(A.verify_delegation_chain(t, base_opts(c)))


def verify_kb(h, prev, pm, op, label):
    v = A.verify_kb_hop(A.parse_sd_jwt_hop(h), {"hop": A.parse_sd_jwt_hop(prev), "mandate": pm}, op, label)
    return {"index": v["index"], "kind": v["kind"], "claims": v["claims"], "mandate": v["mandate"]}


def verify_checkout(t, c):
    return proj_chain(A.verify_checkout_chain(t, base_opts(c)))


def verify_payment(t, c):
    o = base_opts(c)
    o["openCheckoutHash"] = c.get("openCheckoutHash")
    for k in ("context", "expectedTransactionId"):
        if c.get(k) is not None:
            o[k] = c[k]
    return proj_chain(A.verify_payment_chain(t, o))


def redeem(a, b, c, spec):
    calls = []

    class Ledger:
        def reserve(self, h, t, amt):
            calls.append(["reserve", h, t, amt])
            if spec.get("mode") == "throw":
                raise RuntimeError("down")
            if spec.get("mode") == "replayed":
                return "replayed"
            if spec.get("mode") == "undefined":
                return None
            return spec["ctx"] if spec.get("ctx") is not None else {"totalAmount": 0, "totalUses": 0}

        def release(self, h, t):
            calls.append(["release", h, t])
            if spec.get("releaseThrows"):
                raise RuntimeError("release failed")

    r = A.redeem_purchase(a, b, purch_opts_of(c), None if spec == "none" else Ledger())
    return {"result": proj_purchase(r) if r["ok"] else {"ok": False, "reason": mask_reason(r["reason"])}, "calls": calls}


def mk_open_input(a):
    issuer = {"privateKey": key_for(a.get("issuerKey") or "issuer")["privateKey"]}
    if a.get("kid") is not None:
        issuer["kid"] = a["kid"]
    if a.get("x5c") is not None:
        issuer["x5c"] = a["x5c"]
    i = {"issuer": issuer, "agentJwk": a["agentJwk"] if a.get("agentJwk") is not None else key_for(a.get("agentKey") or "agent")["publicJwk"],
         "iat": a.get("iat"), "exp": a.get("exp"), "salt": counter_salt()}
    i["agentJwk"] = {k: v for k, v in i["agentJwk"].items() if k != "kid"} if a.get("agentJwk") is None else i["agentJwk"]
    for k in ("pca", "sdAlg", "typ"):
        if a.get(k) is not None:
            i[k] = a[k]
    return i


def open_pay(a):
    i = dict(mk_open_input(a), constraints=a.get("constraints"))
    for k in ("payee", "paymentAmount", "paymentInstrument", "pisp"):
        if a.get(k) is not None:
            i[k] = a[k]
    if a.get("executionDate") is not None:
        i["executionDate"] = a["executionDate"]
    return strip_sig(A.issue_open_payment_mandate(i))


def open_chk(a):
    return strip_sig(A.issue_open_checkout_mandate(dict(mk_open_input(a), constraints=a.get("constraints"))))


def present_hop_in(a):
    i = {"open": a.get("open"), "agentKey": key_for(a.get("agentKey") or "agent"), "aud": a.get("aud"), "nonce": a.get("nonce"), "iat": a.get("iat"),
         "salt": counter_salt()}
    for k in ("exp", "pca", "hashMode"):
        if a.get(k) is not None:
            i[k] = a[k]
    return i


def present_pay(a):
    i = dict(present_hop_in(a), transactionId=a.get("transactionId"), payee=a.get("payee"), paymentAmount=a.get("paymentAmount"),
             paymentInstrument=a.get("paymentInstrument"))
    for k in ("pisp", "executionDate", "riskData"):
        if a.get(k) is not None:
            i[k] = a[k]
    return strip_sig(A.present_closed_payment({k: v for k, v in i.items() if v is not None}))


def present_chk(a):
    return strip_sig(A.present_closed_checkout(dict(present_hop_in(a), checkoutJwt=a.get("checkoutJwt"))))


MERCH = {"id": "merchant_1", "name": "Demo Merchant", "website": "https://demo-merchant.example"}
MERCH2 = {"id": "merchant_2", "name": "Other Merchant"}


def from_in(a):
    return {"issuer": {"privateKey": key_for("issuer")["privateKey"], "kid": "issuer-1"},
            "agentJwk": {k: v for k, v in key_for("agent")["publicJwk"].items() if k != "kid"},
            "merchants": a["merchants"] if a.get("merchants") is not None else [MERCH, MERCH2],
            "iat": a["iat"] if a.get("iat") is not None else T0, **({"exp": a["exp"]} if a.get("exp") is not None else {}), "salt": counter_salt()}


def open_pay_from_pca(x):
    return strip_sig(A.open_payment_mandate_from_pca(x["mandate"], dict(from_in(x), checkoutReference=x["checkoutReference"] if x.get("checkoutReference") is not None else "REF")))


def open_chk_from_pca(x):
    items = x["lineItems"] if x.get("lineItems") is not None else [{"id": "line_1", "acceptable_items": [{"id": "sku-1", "title": "Widget"}], "quantity": 2}]
    return strip_sig(A.open_checkout_mandate_from_pca(x["mandate"], dict(from_in(x), lineItems=items)))


def bind(a):
    i = {"mandate": a["mandate"], "open": a["open"], "agentJwk": {k: v for k, v in key_for("agent")["publicJwk"].items() if k != "kid"},
         "agentSecret": hashlib.sha256(("atlas-pca-conformance/%s" % a["agentSeed"]).encode()).digest(), "audience": a["audience"], "counter": a["counter"],
         "transactionId": a["transactionId"], "payee": a["payee"], "amount": a["amount"], "instrumentId": a["instrumentId"], "now": a.get("now")}
    if a.get("category") is not None:
        i["category"] = a["category"]
    if a.get("cosign") is not None:
        i["cosign"] = lambda _built: a["cosign"]
    return A.build_pca_payment_binding(i)


def sd_jwt_args(a):
    return {"header": a["header"], "payload": a["payload"], "disclosures": a["disclosures"], "privateKey": key_for(a["key"])["privateKey"]}


def sign_args(a):
    return {"header": a["header"], "payload": a["payload"], "privateKey": key_for(a["key"])["privateKey"]}


def builder(alg, ops):
    b = A.disclosure_builder(alg, counter_salt())
    results = [b.element(op["value"]) if op["kind"] == "element" else b.property(op["name"], op["value"]) for op in ops]
    return {"results": results, "disclosures": b.disclosures}


def process(a, b=None, c=None):
    if isinstance(a, str):
        x = A.parse_sd_jwt_hop(a)
        return A.process_disclosures(x["payload"], x["disclosures"], x["sdAlg"])
    return A.process_disclosures(a, b, c)


PROBLEMS = {"openPaymentMandateProblems": A.open_payment_mandate_problems, "paymentMandateProblems": A.payment_mandate_problems,
            "openCheckoutMandateProblems": A.open_checkout_mandate_problems, "checkoutMandateProblems": A.checkout_mandate_problems}


def constants():
    return {"VCT_CHECKOUT": A.VCT_CHECKOUT, "VCT_CHECKOUT_OPEN": A.VCT_CHECKOUT_OPEN, "VCT_PAYMENT": A.VCT_PAYMENT, "VCT_PAYMENT_OPEN": A.VCT_PAYMENT_OPEN,
            "PCA_CLAIM": A.PCA_CLAIM, "FREQUENCIES": list(A.FREQUENCIES), "AP2_COMMIT": A.AP2_COMMIT, "PCA_BINDING_VERSION": A.PCA_BINDING_VERSION,
            "TYP_TERMINAL": list(A.TYP_TERMINAL), "TYP_INTERMEDIATE": list(A.TYP_INTERMEDIATE)}


def settle(backend):
    return lambda p, c=None: backend.settle(p, c)


MAP = {
    "b64uEncode": A.b64u_encode,
    "b64uDecode": A.b64u_decode,
    "parseJson": A.parse_json,
    "isSdAlg": A.is_sd_alg,
    "sdDigest": A.sd_digest,
    "assertP256Jwk": A.assert_p256_jwk,
    "jwkThumbprint": A.jwk_thumbprint,
    "ap2KeyPairFromPrivateJwk": lambda label, m: A.ap2_key_pair_from_private_jwk(dict(priv_of(label), **m))["publicJwk"],
    "parseSdJwtHop": lambda t: dict(A.parse_sd_jwt_hop(t)),
    "hopSdJwt": lambda t: A.hop_sd_jwt(A.parse_sd_jwt_hop(t)),
    "sdHashOf": lambda t, a=None: A.sd_hash_of(A.parse_sd_jwt_hop(t), a),
    "issuerJwtHashOf": lambda t, a=None: A.issuer_jwt_hash_of(A.parse_sd_jwt_hop(t), a),
    "processDisclosures": process,
    "splitChain": A.split_chain,
    "disclosureBuilder": builder,
    "parseJwt": lambda x, w: dict(A.parse_jwt(x, w)),
    "verifyJwtEs256": lambda x, j: A.verify_jwt_es256(A.parse_jwt(x, "jwt"), j),
    "verifyHopSignature": lambda t, j: A.verify_hop_signature(A.parse_sd_jwt_hop(t), j),
    "signSdJwt": lambda a: strip_sig(A.sign_sd_jwt(sd_jwt_args(a))),
    "signJwtEs256": lambda a: strip_sig(A.sign_jwt_es256(sign_args(a))),
    "currencyExponent": A.currency_exponent,
    "toMinorUnits": A.to_minor_units,
    "fromMinorUnits": A.from_minor_units,
    "openPaymentMandateProblems": A.open_payment_mandate_problems,
    "paymentMandateProblems": A.payment_mandate_problems,
    "openCheckoutMandateProblems": A.open_checkout_mandate_problems,
    "checkoutMandateProblems": A.checkout_mandate_problems,
    "assertValid": lambda k, v, w: A.assert_valid(v, PROBLEMS[k], w),
    "constants": constants,
    "merchantMatches": A.merchant_matches,
    "checkPaymentConstraints": A.check_payment_constraints,
    "projectCheckout": A.project_checkout,
    "checkoutTotal": A.checkout_total,
    "checkCheckoutConstraints": A.check_checkout_constraints,
    "verifyDelegationChain": dc,
    "verifyKbHop": verify_kb,
    "verifyCheckoutChain": verify_checkout,
    "verifyPaymentChain": verify_payment,
    "verifyPurchase": lambda a, b, c: proj_purchase(A.verify_purchase(a, b, purch_opts_of(c))),
    "redeemPurchase": redeem,
    "issueOpenPaymentMandate": open_pay,
    "issueOpenCheckoutMandate": open_chk,
    "presentClosedPayment": present_pay,
    "presentClosedCheckout": present_chk,
    "ap2BudgetMax": A.ap2_budget_max,
    "ap2BudgetReads": A.ap2_budget_reads,
    "riskRatio": A.risk_ratio,
    "pcaBindingNonce": A.pca_binding_nonce,
    "paymentConstraintsFromTerms": A.payment_constraints_from_terms,
    "pcaOpenClaim": A.pca_open_claim,
    "openPaymentMandateFromPca": open_pay_from_pca,
    "openCheckoutMandateFromPca": open_chk_from_pca,
    "toAtomicUnits": A.to_atomic_units,
    "x402Settlement": settle(A.x402_settlement),
    "stripeSptSettlement": settle(A.stripe_spt_settlement),
    "buildPcaPaymentBinding": bind,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _ = run(CASES[fn], MAP[fn])
    assert ran == len(CASES[fn])
