"""A closeness or tolerance test on an untrusted value is the negation of the positive condition: NaN, a missing value and a wrong type
refuse instead of passing (`abs(x - y) > tol` is False for NaN, and a missing or non-number claim has no difference at all)."""
import copy
import math

import pytest

from atlas_pca import intent_mapkit as M
from base_oracle import load_ref

BAD = [math.nan, None, "5", [], {}, True]


def _map():
    _, cases = load_ref("intent-map")
    omega, map_opts, obs, intent_ref, _seed = cases["mapScenario"][0]["args"]
    l = M.create_learner(omega, map_opts)
    for x in obs:
        l.observe({"verb": x["verb"], "values": x["values"]}, x["y"], x["source"], x.get("region"))
    return M.emit_intent_map(l, intent_ref)


def test_close2_is_false_for_nan_missing_and_wrong_type():
    assert M._close2(5, 6) and M._close2(5, 7) and not M._close2(5, 8)
    for bad in BAD:
        assert not M._close2(5, bad) and not M._close2(bad, 5)
    assert not M._close2(5, M._UNDEF)


def test_verify_intent_map_refuses_a_missing_or_non_numeric_claim():
    m = _map()
    assert M.verify_intent_map(copy.deepcopy(m))["ok"] is True
    for bad in BAD:
        t = copy.deepcopy(m)
        t["cells"][0]["p_ppm"] = bad
        assert M.verify_intent_map(t)["ok"] is False
    t = copy.deepcopy(m)
    del t["cells"][0]["p_ppm"]
    r = M.verify_intent_map(t)
    assert r["ok"] is False and "cell 0 differs" in r["problems"]
    k = next(k for k, v in m["metrics"].items() if isinstance(v, (int, float)) and not isinstance(v, bool))
    for bad in BAD + [None]:
        t = copy.deepcopy(m)
        t["metrics"][k] = bad
        assert M.verify_intent_map(t)["ok"] is False
    t = copy.deepcopy(m)
    del t["metrics"][k]
    assert M.verify_intent_map(t)["ok"] is False


def test_attestation_nonce_age_refuses_non_finite_clock_skew_and_max_age():
    from atlas_pca.attestation_soft import _nonce_age_reason as f
    assert f(1000, 1000, 10, 100) is None
    for bad in (math.nan,):
        assert f(1000, bad, 10, 100) is not None
        assert f(1000, 1000, bad, 100) is not None
        assert f(1000, 1000, 10, bad) is not None


def test_webhook_tolerance_refuses_nan_tolerance_and_clock():
    from atlas_pca import events as E
    secret = "whsec_0123456789abcdef0123456789"
    sig = E.sign_webhook(secret, "{}", 1000)
    assert E.verify_webhook(secret, "{}", sig, 300, 1000) is True
    assert E.verify_webhook(secret, "{}", sig, math.nan, 1000) is False
    assert E.verify_webhook(secret, "{}", sig, 300, math.nan) is False


def test_fraud_proof_decision_r_must_match_the_recomputation(monkeypatch):
    from atlas_pca import optimistic_adjudication as OA
    monkeypatch.setattr(OA, "decide", lambda snap: {"releaseGuardianShare": True, "r": 0.5, "requiredThreshold": {"optimisticAllowed": True}})
    claim = {"pcactn_digest": "d", "bond_ref": "b", "claimed_r": 0.1}
    mismatch = "proof decision does not match an independent recomputation"

    def verdict(**dec):
        proof = {"pcactn_digest": "d", "bond_ref": "b", "decision": dict({"releaseGuardianShare": True, "optimisticAllowed": True}, **dec)}
        return OA.verify_fraud_proof(claim, proof, {}, {})

    for bad in (math.nan, math.inf, "0.5", None, [], True):
        r = verdict(r=bad)
        assert r == {"fraudulent": False, "reason": mismatch}, bad
    assert verdict() == {"fraudulent": False, "reason": mismatch}  # r missing altogether
    assert verdict(r=0.5)["reason"] != mismatch  # an exact match proceeds to the judgement


def test_tree_head_freshness_window_must_be_finite():
    from atlas_pca.attest_allowlist_anchor import verify_allowlist_anchored as V
    mine = {"issuer": "ops", "version": 1, "digest": "A" * 64}
    ev = {"head": {"x": 1}, "entries": [], "proof": {}}
    trust = {"logKey": "k", "instanceId": "i", "principal": "p"}
    # a window that is not a finite number never admits: NaN made `now - timestamp > max_age` False
    for bad in (math.nan, math.inf, -math.inf, "5", [], True):
        assert V(mine, ev, trust, 1_800_000_000_000, max_head_age_ms=bad) == {"ok": False, "code": "stale-head"}, bad
        assert V(mine, ev, trust, 1_800_000_000_000, clock_skew_ms=bad) == {"ok": False, "code": "stale-head"}, bad
    assert V(mine, ev, trust, 1_800_000_000_000)["code"] == "bad-head"  # a finite window proceeds to the head checks
    assert V(mine, ev, trust, math.nan)["code"] == "bad-head" and V(mine, ev, trust, None)["code"] == "bad-head"


def test_maa_key_trust_refuses_a_non_finite_or_nan_policy_window():
    from atlas_pca.attest_maa_keys import create_maa_key_trust as C
    base = {"trustedIssuers": ["https://maa.example"]}

    def make(**policy):
        return C({"policy": dict(base, **policy), "fetch": lambda *a, **k: None, "store": None})

    make()
    make(maxStaleMs=math.inf)  # no cap is allowed; NaN is not
    for k in ("maxStaleMs", "maxNewKeysPerFetch", "maxInitialKeys"):
        for bad in (math.nan, "5", [], True):
            with pytest.raises(TypeError):
                make(**{k: bad})
    for k in ("ttlMs", "clockSkewMs"):
        for bad in (math.nan, math.inf, -math.inf, "5", True):
            with pytest.raises(TypeError):
                make(**{k: bad})


def test_dpop_iat_and_clock_refuse_nan_missing_and_wrong_type():
    import base64
    import hashlib
    from atlas_pca import dpop as D, ed25519
    seed = hashlib.sha256(b"failopen-dpop").digest()
    x = base64.urlsafe_b64encode(ed25519.public_key(seed)).rstrip(b"=").decode()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    url = "https://rs.example/r"
    base = {"method": "GET", "url": url, "require_replay_store": False, "now_sec": 1_800_000_000}

    def code(proof, **o):
        try:
            D.verify_dpop_proof(proof, dict(base, **o))
            return "ok"
        except D.DpopVerificationError as e:
            return e.code

    assert code(D.create_dpop_proof("GET", url, seed, jwk, iat=1_800_000_000)) == "ok"
    # NaN and Infinity are written as the tokens NaN / Infinity (not JSON): the proof is refused as malformed before any claim is read
    for bad in (math.nan, math.inf, -math.inf):
        assert code(D.create_dpop_proof("GET", url, seed, jwk, iat=bad)) == "malformed", bad
    # a present iat that is not a number is refused by jwt_claims_check inside the signature step ('"iat" claim must be a number'), reported as "signature"
    for bad in ("1800000000", True, [], {}):
        assert code(D.create_dpop_proof("GET", url, seed, jwk, iat=bad)) == "signature", bad
    fresh = D.create_dpop_proof("GET", url, seed, jwk, iat=1_800_000_000)
    for bad in (math.nan, math.inf, -math.inf, "1800000000", True):
        assert code(fresh, now_sec=bad) == "now", bad  # the clock itself
        assert code(fresh, max_age_sec=bad) == "max_age", bad
    assert code(fresh, now_sec=1_800_000_000 - 1000) == "iat_future" and code(fresh, now_sec=1_800_000_000 + 1000) == "iat_stale"
