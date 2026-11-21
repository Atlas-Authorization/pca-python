"""NaN, +Infinity and -Infinity never admit: a clock, age, spend, remaining or amount that is not finite refuses (or expires) at every
time, budget, amount, limit and quota comparison. Each test fails against a comparison that reads as the plain refusal (`now > exp`),
because that form is False for NaN and for the infinite value that lands on the admitting side."""
import math

import pytest

NONFINITE = [math.nan, math.inf, -math.inf]


# ---- ap2 -----------------------------------------------------------------------------------------------------------------------

def _ap2():
    return pytest.importorskip("atlas_pca.ap2")


@pytest.mark.parametrize("bad", NONFINITE)
def test_ap2_amount_range_refuses_nonfinite_amount(bad):
    A = _ap2()
    c = {"type": "payment.amount_range", "currency": "USD", "max": 1000}
    closed = {"payment_amount": {"currency": "USD", "amount": bad}}
    assert A.check_payment_constraints({"constraints": [c]}, closed, {"now": 0})  # -Infinity is below max and passed `amount > max`


@pytest.mark.parametrize("bad", NONFINITE)
def test_ap2_budget_refuses_nonfinite_spend(bad):
    A = _ap2()
    c = {"type": "payment.budget", "currency": "USD", "max": 10}
    closed = {"payment_amount": {"currency": "USD", "amount": bad}}
    ctx = {"totalAmount": 0, "totalUses": 0}
    assert A.check_payment_constraints({"constraints": [c]}, closed, {"now": 0, "context": ctx})  # a -Infinity spend passed `spend > max`


def _ap2_chain():
    A = _ap2()
    issuer, agent = A.generate_ap2_key_pair("issuer"), A.generate_ap2_key_pair("agent")
    token = A.issue_open_payment_mandate({
        "issuer": {"privateKey": issuer["privateKey"], "kid": "issuer"}, "agentJwk": agent["publicJwk"], "iat": 1_800_000_000, "exp": 1_800_001_000,
        "constraints": [{"type": "payment.reference", "conditional_transaction_id": "tx-1"}]})
    return A, token, {"resolveIssuerKey": lambda _h: issuer["publicJwk"], "expectedAudience": "aud", "expectedNonce": "n"}


@pytest.mark.parametrize("bad", NONFINITE)
def test_ap2_chain_times_refuse_nonfinite_clock_or_skew(bad):
    A, token, o = _ap2_chain()
    assert A.verify_delegation_chain(token, dict(o, now=1_800_000_010, clockSkewSeconds=60))["ok"] is True
    assert A.verify_delegation_chain(token, dict(o, now=bad, clockSkewSeconds=60))["ok"] is False  # -Infinity passed `now > exp + skew`, +Infinity `iat > now + skew`
    assert A.verify_delegation_chain(token, dict(o, now=1_800_000_010, clockSkewSeconds=bad))["ok"] is False


@pytest.mark.parametrize("freq", ["HOURLY", "", "daily", None, 5])
def test_ap2_unknown_recurrence_frequency_is_always_a_violation(freq):
    A = _ap2()
    cs = [{"type": "payment.amount_range", "currency": "USD", "max": 1000}, {"type": "payment.budget", "currency": "USD", "max": 100},
          {"type": "payment.agent_recurrence", "frequency": freq}]
    closed = {"payment_amount": {"currency": "USD", "amount": 10}}
    assert "unknown recurrence frequency" in A.check_payment_constraints({"constraints": cs}, closed, {"now": 1})  # no last-used date: it used to pass
    ctx = {"totalAmount": 0, "totalUses": 0}
    assert "unknown recurrence frequency" in A.check_payment_constraints({"constraints": cs}, closed, {"now": 1, "context": ctx})


# ---- ciba ----------------------------------------------------------------------------------------------------------------------

_SU = {"id": "su1", "verb": "stripe.payout", "resource": "acct:1", "params": {"amount": 80, "currency": "USD", "payee": "bob"}, "tier": 3,
       "reason": "r", "goalCommit": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", "goal": "pay suppliers", "lineage": {}, "r": 0.5, "requestedAt": 1}


@pytest.mark.parametrize("kind", ["memory", "durable"])
@pytest.mark.parametrize("bad", NONFINITE)
def test_ciba_nonfinite_clock_expires_sessions(kind, bad):
    from atlas_pca import ciba_store as S
    from atlas_pca import ciba_testing as T
    t = {"v": 1_000_000}
    now = lambda: t["v"]  # noqa: E731
    b = T.MemoryCibaBroker(now=now) if kind == "memory" else S.create_durable_ciba_broker(T.create_memory_approval_store(), now=now, decision_ttl_sec=100)
    ident = b.start(_SU)["auth_req_id"]
    assert b.poll(ident)["status"] == "pending"
    t["v"] = bad
    assert b.poll(ident)["status"] == "expired"  # a -Infinity clock stayed under expiresAt and kept the session live


# ---- dpop and signals replay stores, stream health -------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_replay_stores_refuse_nonfinite_clock(bad):
    from atlas_pca.dpop import InMemoryDpopReplayStore
    from atlas_pca.signals import InMemorySetReplayStore
    for s in (InMemoryDpopReplayStore(4), InMemorySetReplayStore(4)):
        assert s.add_if_absent("k", 200, 100) is True
        assert s.add_if_absent("k", 400, bad) is False  # +Infinity read every held entry as expired and let a replay through
        assert s.add_if_absent("n", bad, 100) is False


@pytest.mark.parametrize("bad", NONFINITE)
def test_stream_health_nonfinite_clock(bad):
    from atlas_pca.signals import StreamHealth
    h = StreamHealth({"min_verification_interval": 1})
    state = h.request_verification(100)
    assert state is not None and h.ack_verification(state, 101) is True
    assert h.revocation_fresh_within(60, 110) is True
    assert h.revocation_fresh_within(60, bad) is False  # -Infinity made now - lastVerified <= max true
    assert h.report(bad)["state"] == "degraded"
    assert h.request_verification(bad) is None
    s2 = h.request_verification(500)
    assert s2 is not None and h.ack_verification(s2, bad) is False


# ---- gnap interaction, explain ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_gnap_interaction_nonfinite_clock_reads_as_expired(bad):
    from atlas_pca import gnap as G
    clock = [1000]
    srv = G.InteractionServer({"grant_endpoint": "https://as.example/tx", "supports": ["redirect"],
                               "redirect_uri": lambda i: "https://as.example/i/%s" % i, "now": lambda: clock[0]})
    it = srv.start({"start": ["redirect"]})["interaction"]
    clock[0] = bad
    with pytest.raises(G.InteractionError) as e:
        srv.approve(it.id)  # -Infinity was never past expires_at
    assert e.value.code == "expired"


@pytest.mark.parametrize("bad", NONFINITE)
def test_explain_nonfinite_clock_is_a_validity_failure(bad):
    from atlas_pca import explain as X
    p = {"iat": 1000, "exp": 2000}
    fail = {"checks": {"validity": "fail"}}
    assert X.explain_verification(p, fail, {"now": 1500})["decisive"]["detail"] == "validity window invalid"
    assert X.explain_verification(p, fail, {"now": bad})["decisive"]["detail"] != "validity window invalid"  # a non-finite clock is pinpointed, not passed over


# ---- goal review ---------------------------------------------------------------------------------------------------------------

def _approved_goal():
    from atlas_pca import goal_review as R
    from atlas_pca.agent import KeyPair
    from atlas_pca.goal_digests import nl_digest
    from atlas_pca.goal_sign import signer_id
    from atlas_pca.pca import hash_canonical
    q = {"k": "q", "u": {"k": "money", "ccy": "USD"}}
    goal = {"v": 1, "principal": "p1", "ontDigest": "ont", "nlDigest": nl_digest("do the thing"), "sources": [],
            "grants": [{"gid": "refund-one", "verb": "refund", "res": {"k": "exact", "id": "ch_1"},
                        "cond": {"k": "cmp", "op": "lte", "l": {"k": "param", "path": "amount", "ty": q}, "r": {"k": "lit", "v": {"k": "q", "q": {"u": q["u"], "n": 4000}}}}}],
            "prohibits": [], "bounds": [], "validity": {"notBefore": 0, "notAfter": 9007199254740991, "maxIdle": 0},
            "deleg": {"maxDepth": 0, "narrowOnly": True, "mayTouch": []}, "escalateOn": [], "wildcardAck": [], "holes": []}
    sub = {"goal": goal, "ontology": {"verbs": [], "rels": []}, "instruction": "do the thing", "model_set": ["m-a"]}
    kernel = R.ReviewKernel(lambda g, _o: {"ok": True, "policy": {"n": len(g["grants"])}}, lambda p: hash_canonical({"d": "stub", "p": p}), lambda _p: [])
    key = KeyPair(bytes([5]) * 32, allow_insecure_signer=True)
    approval = R.approve_goal(sub, key, {"kernel": kernel, "now": 1_800_000_000_000})
    return R, sub, approval, {"kernel": kernel, "reviewers": [signer_id(key)]}


@pytest.mark.parametrize("bad", NONFINITE)
def test_goal_load_approved_goal_nonfinite_clock_refuses(bad):
    R, sub, approval, o = _approved_goal()
    assert R.load_approved_goal(sub, approval, dict(o, now=1_800_000_001_000))["ok"] is True
    assert R.load_approved_goal(sub, approval, dict(o, now=bad))["ok"] is False  # an infinite clock passed both the not-yet and expiry checks


# ---- payments ---------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_stripe_signature_refuses_nonfinite_tolerance_and_clock(bad):
    import hashlib
    import hmac
    from atlas_pca import payments as P
    body, secret, t = "{}", "whsec_x", 1_000
    sig = hmac.new(secret.encode(), ("%d.%s" % (t, body)).encode(), hashlib.sha256).hexdigest()
    header = "t=%d,v1=%s" % (t, sig)
    assert P.verify_stripe_signature(body, header, secret, t, 300) is True
    assert P.verify_stripe_signature(body, header, secret, t, bad) is False  # an infinite tolerance accepted any age
    assert P.verify_stripe_signature(body, header, secret, bad, 300) is False


@pytest.mark.parametrize("bad", NONFINITE)
def test_spt_limits_refuse_a_nonfinite_period_end(bad):
    from atlas_pca import payments as P
    m = {"terms": {"currency": "USD", "autoApproveThreshold": 100, "periodEnd": bad}, "budget": {"B": 1000}}
    with pytest.raises(TypeError, match="periodEnd must be an epoch-ms time"):
        P.shared_payment_token_limits(m, 5000)  # NaN read as a live period; +Infinity was emitted as expires_at: null (no expiry)


@pytest.mark.parametrize("cap", [math.nan, math.inf, -math.inf, -1, -0.0, 1.5, None, "5", True])
def test_acp_a_present_spend_cap_must_be_a_non_negative_integer(cap):  # a present null cap is refused; only an absent key is unbounded
    from atlas_pca import acp
    a = {"maxAmount": cap, "merchants": None, "categories": None, "humanPresentRequired": False}
    assert acp.check_payment_authority(a, {"amount": 1, "currency": "USD", "merchant": "m"}) == {
        "ok": False, "reason": "authorized spend cap is not a non-negative integer (fail closed)"}  # an infinite or negative cap was honoured


def test_acp_an_absent_spend_cap_is_unbounded():
    from atlas_pca import acp
    a = {"merchants": None, "categories": None, "humanPresentRequired": False}
    assert acp.check_payment_authority(a, {"amount": 1, "currency": "USD", "merchant": "m"})["ok"] is True


# ---- sdjwt, vc, wallet ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
@pytest.mark.parametrize("opt", ["now", "clock_tolerance_sec", "kb_max_age_sec"])
def test_sdjwt_refuses_nonfinite_clock_tolerance_or_window(bad, opt):
    from atlas_pca import sdjwt as S
    r = S.verify_pca_sd_jwt("x", {"issuer_key": None, opt: bad})
    assert r["ok"] is False and "finite" in r["reason"]  # before the guard the options flowed on into the date checks


@pytest.mark.parametrize("bad", NONFINITE)
def test_wallet_sliding_window_ignores_nonfinite_clock(bad):
    from atlas_pca.wallet import SlidingWindowCounter
    c = SlidingWindowCounter(1000)
    assert c.try_add(100, 5) is True
    assert c.count(bad) == 1  # an infinite clock pruned every recorded event
    try:
        added = c.try_add(bad, 5)
    except ValueError:  # NaN and -Infinity read as time going backwards
        added = False
    assert added is False
    assert c.count(150) == 1


# ---- webbotauth -------------------------------------------------------------------------------------------------------------------

def _signed_request():
    from atlas_pca import webbotauth as W
    from atlas_pca.agent import KeyPair
    seed = bytes([7]) * 32
    out = W.sign_request({"method": "GET", "url": "https://example.com/a", "key": KeyPair(seed, True), "keyid": "k", "created": 1000})
    req = {"method": "GET", "url": "https://example.com/a", "headers": out["headers"]}
    return W, req, W.ed25519.public_key(seed)


@pytest.mark.parametrize("bad", NONFINITE)
def test_webbotauth_refuses_nonfinite_clock_or_skew(bad):
    W, req, pub = _signed_request()
    ok = {"resolveKey": lambda kid: pub, "now": 1010}
    assert W.verify_signed_request(req, ok)["valid"] is True
    assert W.verify_signed_request(req, dict(ok, now=bad))["valid"] is False  # +Infinity passed `created > now + skew`, -Infinity `now > expires + skew`
    assert W.verify_signed_request(req, dict(ok, clockSkewSec=bad))["valid"] is False
    assert W.verify_signed_request(req, dict(ok, maxAgeSec=60, now=bad))["valid"] is False


@pytest.mark.parametrize("bad", NONFINITE)
def test_webbotauth_replay_cache_refuses_nonfinite_times(bad):
    from atlas_pca import webbotauth as W
    c = W.memory_replay_cache(4)
    assert c.claim("k", 200, 100) is True
    assert c.claim("k", 400, bad) is False  # +Infinity read the held claim as expired and re-admitted it
    assert c.claim("n", bad, 100) is False


# ---- agent native -------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_envelope_permits_refuses_nonfinite_hints(bad):
    from atlas_pca import agent_native as an
    def env(**h):
        return {"ok": True, "unsatisfiable": [], "scopes": None, "remainingBudgetHints": h}
    assert an.envelope_permits(env(expiresAt=100), "v", "r", 5) is True
    assert an.envelope_permits(env(expiresAt=bad), "v", "r", 5) is False  # an infinite expiry compared false against `now >= expiresAt`
    assert an.envelope_permits(env(notBefore=bad), "v", "r", 5) is False
    assert an.envelope_permits(env(delegationDepthRemaining=bad), "v", "r") is False  # +Infinity depth is not a depth
    assert an.envelope_permits(env(), "v", "r", bad) is False


# ---- attestation freshness ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_ocsp_response_refuses_nonfinite_clock_or_skew(bad):
    T = pytest.importorskip("test_base_kill_intel_ocsp_cert")
    assert T._v()["ok"] is True
    assert T._v(now=bad)["ok"] is False  # +Infinity passed the thisUpdate and producedAt future checks when the response has no nextUpdate bound
    assert T._v(skew=bad)["ok"] is False


@pytest.mark.parametrize("bad", NONFINITE)
def test_class_approval_and_allowlist_refuse_nonfinite_clock(bad):
    from atlas_pca.approvals import class_approval_covers
    a = {"grantedAt": 0, "ttlMs": 1000, "verbs": ["v"], "resource": "*"}
    assert class_approval_covers(a, "v", "r", 500) is True
    assert class_approval_covers(a, "v", "r", bad) is False  # an infinite clock compared outside neither bound
    assert class_approval_covers(dict(a, ttlMs=bad), "v", "r", 500) is False


# ---- natural-language policy approval ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_nl_load_approved_policy_nonfinite_clock_refuses(bad):
    from atlas_pca import nl as N
    from atlas_pca.agent import KeyPair
    draft = N.draft_policy_from_nl("do the thing", lambda _p: '{"permissions":{"stripe":["refund"]},"limits":{"refund":"$50/day"}}')
    seed = bytes([9]) * 32
    approval = N.approve_draft(draft, seed, {"now": 1_800_000_000_000})
    o = {"reviewers": [KeyPair(seed, allow_insecure_signer=True).public]}
    assert N.load_approved_policy(draft, approval, dict(o, now=1_800_000_001_000))["ok"] is True
    assert N.load_approved_policy(draft, approval, dict(o, now=bad))["ok"] is False  # an infinite clock passed both the not-yet and expiry checks


# ---- beacon, mesh, risk, bond ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_beacon_refuses_nonfinite_clock(bad):
    from atlas_pca import beacon as B
    from atlas_pca.agent import generate_keypair
    k = generate_keypair()
    b = B.issue_liveness_beacon(k, "inst", 1, 1_000_000)
    assert B.verify_liveness_beacon(b, [k.public], 1_001_000, "inst")["ok"] is True
    assert B.verify_liveness_beacon(b, [k.public], bad, "inst")["ok"] is False  # -Infinity was never past not_after, +Infinity never before issued_at


@pytest.mark.parametrize("bad", NONFINITE)
def test_mesh_proof_refuses_nonfinite_trust_clock(bad):
    import json
    import test_mesh as TM
    from atlas_pca import verify_mesh_proof
    with open(TM.FILE, encoding="utf-8") as f:
        v = next(x for x in json.load(f)["mesh"] if x["name"] == "action/at-expiry-boundary")  # a capability expiry equal to the action time
    assert verify_mesh_proof(v["proof"], v["trust"]).ok is True
    assert verify_mesh_proof(v["proof"], dict(v["trust"], now=bad)).ok is False  # an infinite clock never passed `now > expires_at` when it was -Infinity


@pytest.mark.parametrize("bad", NONFINITE)
def test_risk_budget_refuses_nonfinite_parent_or_node_budget(bad):
    from atlas_pca import risk as R
    assert R.sub_budget({"B": 10, "tau": 0}, 5)["ok"] is True
    assert R.sub_budget({"B": bad, "tau": 0}, 5)["ok"] is False  # an infinite or NaN parent budget lifted the allocation guard
    assert R.debit_consolidated({"B": 10, "tau": 0}, {"B": 10, "tau": 0}, 1)["ok"] is True
    assert R.debit_consolidated({"B": bad, "tau": 0}, {"B": 10, "tau": 0}, 1)["ok"] is False
    assert R.debit_consolidated({"B": 10, "tau": 0}, {"B": bad, "tau": 0}, 1)["ok"] is False
    assert R.debit_consolidated_path([{"B": 10}, {"B": bad}], 1)["ok"] is False


# ---- store conformance reference adapters --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_store_reference_adapter_refuses_live_key_on_nonfinite_clock(bad):
    from atlas_pca import store_conformance_runner as R
    c = R.in_memory_adapter().open()
    assert c.consume_once("k", 200, 100) is True
    assert c.consume_once("k", 400, 150) is False  # the key is live at 150
    assert c.consume_once("k", 400, bad) is False  # a NaN or -Infinity clock read the live key as lapsed and consumed it again


# ---- dlp, optimistic windows -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_dlp_nonfinite_taint_is_denied_under_an_unbounded_ceiling(bad):
    from atlas_pca.dlp import evaluate_dlp
    policy = {"classes": [{"name": "c", "resource": "*", "maxTaintForAuto": math.inf, "hardDenyAbove": math.inf}]}
    assert evaluate_dlp(policy, {"verb": "v", "resource": "r", "taint": 1})["outcome"] == "allow"
    assert evaluate_dlp(policy, {"verb": "v", "resource": "r", "taint": bad})["outcome"] == "deny"  # an infinite taint is not above an infinite ceiling


def test_optimistic_window_policy_nan_bounds_refuse():
    from atlas_pca.optimistic import claim_check
    ok = {"maxSkewMs": 10, "minWindowMs": 1, "maxWindowMs": 100}
    claim = {"pcactn_digest": "d", "claimed_r": 0.5, "issued_at": 100, "challenge_window_ms": 50, "reversibility_class": "reversible"}
    assert claim_check(claim, "d", "pub", 100, ok) == "signature"  # the window passes for a finite policy and the unsigned claim stops at the signature
    for k in ok:
        assert claim_check(claim, "d", "pub", 100, dict(ok, **{k: math.nan})) == "window"  # a NaN bound compared false and admitted any window


@pytest.mark.parametrize("bad", NONFINITE)
def test_claim_status_refuses_a_nonfinite_clock_or_window(bad):
    from atlas_pca.optimistic import claim_status, within_challenge_window
    c = {"issued_at": 100, "challenge_window_ms": 50}
    assert claim_status(c, 150) == "open" and claim_status(c, 151) == "finalized"
    with pytest.raises(ValueError):
        claim_status(c, bad)  # a non-finite clock used to read as finalized, which opens settlement
    with pytest.raises(ValueError):
        claim_status({"issued_at": 100, "challenge_window_ms": bad}, 150)
    assert within_challenge_window(c, bad) is False


# ---- agent card attestations, revocation age, replay and zk clocks ---------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_agentcard_attestation_refuses_nonfinite_clock(bad):
    from atlas_pca import agentcard as A
    a = {"issuer": "i", "subject": "s", "attests": {}, "validFrom": "2020-01-01T00:00:00Z", "validUntil": "2030-01-01T00:00:00Z", "signature": "x"}
    facts = {"id": "s", "selfAsserted": {}, "attestations": [a]}
    o = {"key": b"k"}  # an opaque key: the window is checked before any signature work
    assert A.verify_agent_facts(facts, dict(o, now=1_700_000_000_000))["attestations"][0]["reason"] == "signature did not verify: signature is malformed"  # the window passes
    r = A.verify_agent_facts(facts, dict(o, now=bad))["attestations"][0]
    assert r["ok"] is False and r["reason"] in ("attestation is not yet valid", "attestation has expired")


@pytest.mark.parametrize("bad", NONFINITE)
def test_revocation_age_refuses_nonfinite_clock(bad):
    from atlas_pca.intent_v2 import check_revocation_age
    assert check_revocation_age(1000, 2000, 5000)["ok"] is True
    assert check_revocation_age(1000, bad, math.inf)["ok"] is False  # -Infinity is never in the future and an infinite max age never stale


@pytest.mark.parametrize("bad", NONFINITE)
def test_connect_replay_prune_ignores_nonfinite_clock(bad):
    from atlas_pca import connect_replay as CR
    s = CR.InMemoryReplayStore()
    assert s.consume_once("k", 500, 100) is True
    assert s.prune(bad) == 0  # an infinite clock expired every live key
    assert s.consume_once("k", 500, 100) is False


# ---- derive caveat, derived risk, bond moves -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", NONFINITE)
def test_derive_count_with_a_nonfinite_clock_is_unknown(bad):
    from atlas_pca import caveat_lang as K
    c = {"defs": [{"name": "n", "kind": "count", "window_ms": 10}], "check": {"op": "gte", "a": {"ref": "n"}, "b": {"const": 2}}}
    h = [{"t": 95, "verb": "v", "resource": "r"}, {"t": 100, "verb": "v", "resource": "r"}]
    assert K.evaluate_derive(c, {"now": 100, "history": h}) is True
    assert K.evaluate_derive(c, {"now": bad, "history": h}) is None  # an unreadable clock under-counted (or over-counted) into a decided rate


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_derived_risk_with_a_nonfinite_kappa_is_the_worst_case(bad):
    from atlas_pca import actions_derive as DR
    d = {"params": {"amount": {"role": "money.amount"}}}
    eff = {"eff": {"blast_ppm": 500_000, "rev": "reversible"}}
    assert DR.risk_of(d, eff, {"amount": 10}, {"kappa": 100})["blastRadius"] == 0.1
    assert DR.risk_of(d, eff, {"amount": 10}, {"kappa": bad})["blastRadius"] == 1  # an infinite kappa made the blast radius 0


@pytest.mark.parametrize("bad", NONFINITE)
def test_bond_moves_refuse_a_nonfinite_balance(bad):
    from atlas_pca.bond_store import apply_bond_moves
    assert apply_bond_moves(lambda a: 5, [{"account": "a", "op": "credit", "amount": 1}]) == {"a": 6}
    with pytest.raises(ValueError):
        apply_bond_moves(lambda a: bad, [{"account": "a", "op": "credit", "amount": 1}])  # a NaN balance read as enough for a debit
    with pytest.raises(ValueError):
        apply_bond_moves(lambda a: bad, [{"account": "a", "op": "debit", "amount": 1}])


# ---- an int beyond the double range (a JSON integer such as 10**400) is no usable clock, amount or age: a refusal, never an OverflowError ----

HUGE = [10 ** 400, -(10 ** 400)]


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_ap2_amount_budget_and_chain_clock_refuse(bad):
    A = _ap2()
    closed = {"payment_amount": {"currency": "USD", "amount": bad}}
    rng = {"type": "payment.amount_range", "currency": "USD", "max": 1000}
    assert A.check_payment_constraints({"constraints": [rng]}, closed, {"now": 0})
    budget = {"type": "payment.budget", "currency": "USD", "max": 10}
    assert A.check_payment_constraints({"constraints": [budget]}, closed, {"now": 0, "context": {"totalAmount": 0, "totalUses": 0}})
    A, token, o = _ap2_chain()
    assert A.verify_delegation_chain(token, dict(o, now=1_800_000_010, clockSkewSeconds=60))["ok"] is True
    assert A.verify_delegation_chain(token, dict(o, now=bad, clockSkewSeconds=60))["ok"] is False
    assert A.verify_delegation_chain(token, dict(o, now=1_800_000_010, clockSkewSeconds=bad))["ok"] is False


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_nl_clock_refuses(bad):
    from atlas_pca import nl as N
    from atlas_pca.agent import KeyPair
    draft = N.draft_policy_from_nl("do the thing", lambda _p: '{"permissions":{"stripe":["refund"]},"limits":{"refund":"$50/day"}}')
    seed = bytes([9]) * 32
    approval = N.approve_draft(draft, seed, {"now": 1_800_000_000_000})
    o = {"reviewers": [KeyPair(seed, allow_insecure_signer=True).public]}
    assert N.load_approved_policy(draft, approval, dict(o, now=bad))["ok"] is False


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_beacon_clock_refuses(bad):
    from atlas_pca import beacon as B
    from atlas_pca.agent import generate_keypair
    k = generate_keypair()
    b = B.issue_liveness_beacon(k, "inst", 1, 1_000_000)
    assert B.verify_liveness_beacon(b, [k.public], bad, "inst")["ok"] is False


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_revocation_age_refuses(bad):
    from atlas_pca.intent_v2 import check_revocation_age
    assert check_revocation_age(1000, bad, 5000)["ok"] is False
    assert check_revocation_age(bad, 2000, 5000)["ok"] is False


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_clock_never_settles_a_stale_operation(bad):
    from atlas_pca import MemoryOperationStore, recover_operation
    s = MemoryOperationStore()
    s.create({"id": "a", "state": "pending", "startedAt": 1000.5})
    assert recover_operation(s, "a", older_than_ms=1, now=lambda: bad)["state"] == "pending"  # a huge clock must not age the claim
    assert recover_operation(s, "a", older_than_ms=bad, now=lambda: 5000.5)["state"] == "pending"
    assert recover_operation(s, "a", older_than_ms=1, now=lambda: 5000.5)["state"] == "aborted"


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_clock_prunes_a_chain_memo_fail_closed(bad):
    from atlas_pca.agent import DEFAULT_RISK_POLICY, delegate, keypair_from_seed, mint_grant
    from atlas_pca.chain_compact import ChainMemo
    p, h, h2 = (keypair_from_seed(bytes([i]) * 32, allow_insecure_signer=True) for i in (1, 2, 3))
    grant = mint_grant(p, h.public, {"predicates": [{"verb": "a", "resource": "b"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}, "g", salt="s")["grant"]
    memo = ChainMemo()
    memo.remember_verified([grant, delegate(grant, h, h2.public, [])], p.public, 1000)
    memo.prune(1001)
    assert memo.size == 1
    memo.prune(bad)
    assert memo.size == 0


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_envelope_hints_and_clock_refuse(bad):
    from atlas_pca import agent_native as an
    def env(**h):
        return {"ok": True, "unsatisfiable": [], "scopes": None, "remainingBudgetHints": h}
    assert an.envelope_permits(env(expiresAt=100), "v", "r", 5) is True
    assert an.envelope_permits(env(expiresAt=bad), "v", "r", 5) is False
    assert an.envelope_permits(env(notBefore=bad), "v", "r", 5) is False
    assert an.envelope_permits(env(delegationDepthRemaining=bad), "v", "r") is False
    assert an.envelope_permits(env(), "v", "r", bad) is False
    assert an.envelope_permits(env(maxSpendUsd=bad), "v", "r", None, {"amount": 1}) is False
    assert an.envelope_permits(env(maxSpendUsd=10), "v", "r", None, {"amount": bad}) is False


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_lease_clock_refuses(bad):
    from atlas_pca import agent_native as an
    lease = an.grant_lease({"cap_id": "c", "holder": "h", "now": 1000, "ttl_ms": 5000})
    assert an.lease_state(lease, 2000)["live"] is True
    assert an.lease_state(lease, bad)["live"] is False
    with pytest.raises(ValueError):
        an.grant_lease({"cap_id": "c", "holder": "h", "now": bad, "ttl_ms": 5000})
    with pytest.raises(ValueError):
        an.grant_lease({"cap_id": "c", "holder": "h", "now": 1000, "ttl_ms": 5000, "hard_expires_at": bad})


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_mesh_trust_clock_refuses(bad):
    import json
    import test_mesh as TM
    from atlas_pca import verify_mesh_proof
    with open(TM.FILE, encoding="utf-8") as f:
        v = next(x for x in json.load(f)["mesh"] if x["name"] == "action/at-expiry-boundary")
    assert verify_mesh_proof(v["proof"], v["trust"]).ok is True
    assert verify_mesh_proof(v["proof"], dict(v["trust"], now=bad)).ok is False


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_pca_period_end_refuses_the_open_mandate(bad):
    A = _ap2()
    o = {"issuer": "i", "agentJwk": {}, "iat": 1, "merchants": [], "checkoutReference": "r", "lineItems": []}
    for issue in (A.open_payment_mandate_from_pca, A.open_checkout_mandate_from_pca):
        with pytest.raises(A.Ap2Error):
            issue({"terms": {"periodEnd": bad}}, o)


# ---- an int beyond the double range through the shared finite check: replay stores, stream health, ciba, guardians, taint, oidc ----

@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_replay_stores_refuse_the_clock_or_expiry(bad):
    from atlas_pca.dpop import InMemoryDpopReplayStore
    from atlas_pca.signals import InMemorySetReplayStore
    for s in (InMemoryDpopReplayStore(4), InMemorySetReplayStore(4)):
        assert s.add_if_absent("k", 200, 100) is True
        assert s.add_if_absent("k", 400, bad) is False
        assert s.add_if_absent("n", bad, 100) is False


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_stream_health_clock_refuses(bad):
    from atlas_pca.signals import StreamHealth
    h = StreamHealth({"min_verification_interval": 1})
    state = h.request_verification(100)
    assert state is not None and h.ack_verification(state, 101) is True
    assert h.revocation_fresh_within(60, 110) is True
    assert h.revocation_fresh_within(60, bad) is False
    assert h.request_verification(bad) is None
    s2 = h.request_verification(500)
    assert s2 is not None and h.ack_verification(s2, bad) is False


@pytest.mark.parametrize("kind", ["memory", "durable"])
@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_ciba_clock_expires_sessions(kind, bad):
    from atlas_pca import ciba_store as S
    from atlas_pca import ciba_testing as T
    t = {"v": 1_000_000}
    now = lambda: t["v"]  # noqa: E731
    b = T.MemoryCibaBroker(now=now) if kind == "memory" else S.create_durable_ciba_broker(T.create_memory_approval_store(), now=now, decision_ttl_sec=100)
    ident = b.start(_SU)["auth_req_id"]
    assert b.poll(ident)["status"] == "pending"
    t["v"] = bad
    assert b.poll(ident)["status"] == "expired"


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_guardian_clock_window_or_heartbeat_is_down(bad):
    from atlas_pca.ha import live_guardians
    gs = {"guardians": [{"id": "g", "healthy": True, "lastSeen": 1000, "weight": 1}], "quorum": 1}
    assert [g["id"] for g in live_guardians(gs, 2000)] == ["g"]
    assert live_guardians(gs, bad) == []
    assert live_guardians(gs, 2000, {"staleMs": bad}) == []
    assert live_guardians({"guardians": [{"id": "g", "healthy": True, "lastSeen": bad, "weight": 1}], "quorum": 1}, 2000) == []


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_taint_bound_is_a_misconfiguration(bad):
    from atlas_pca import taint as T
    reg = T.InMemoryTrustedInputRegistry()
    reg.record_trusted("d-trusted")
    prov = {"causal_hash": "", "taint_level": 0, "trusted_refs": ["d-trusted"]}
    assert T.taint_gate(prov, reg, None, 0) == {"ok": True}
    assert T.taint_gate(prov, reg, None, bad) == {"ok": False, "reason": "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"}


@pytest.mark.parametrize("bad", HUGE)
@pytest.mark.parametrize("opt", ["cache_max_age_sec", "cooldown_sec", "max_bytes", "timeout_ms"])
def test_huge_int_oidc_jwks_option_is_refused(bad, opt):
    from atlas_pca import oidc
    with pytest.raises(TypeError):
        oidc.create_oidc_jwks({"jwks_uri": "https://idp.example/jwks", opt: bad})


# ---- an int beyond the double range at the infinity comparisons: connection expiry, need limits, schema numbers, expected harm ----

@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_vault_connection_expiry_is_refused(bad):
    from atlas_pca.connect import InMemoryConnectionStore, TokenVault
    v = TokenVault(store=InMemoryConnectionStore(), strict=False)
    args = ("agent", "github", "tok", 1_800_000_000_000, ["repo"], {"principal": "p"})
    assert v.put_connection(*args)["expiresAt"] == 1_800_000_000_000
    with pytest.raises(TypeError):
        v.put_connection("agent", "github", "tok", bad, ["repo"], {"principal": "p"})


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_need_limit_is_refused(bad):
    from atlas_pca.a2a import validate_need
    need = {"v": 1, "kind": "scope", "verb": "read", "resource": "doc:1"}
    assert validate_need(dict(need, limits={"calls": 5}))["ok"] is True
    assert validate_need(dict(need, limits={"calls": bad})) == {"ok": False, "code": "bad_field"}


@pytest.mark.parametrize("bad", HUGE)
@pytest.mark.parametrize("kind", ["number", "integer"])
def test_huge_int_is_no_schema_number_or_integer(bad, kind):
    from atlas_pca.schema import validate
    assert validate({"type": kind}, 5)["valid"] is True
    assert validate({"type": kind}, bad)["valid"] is False


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_expected_harm_is_unknown_harm(bad):
    from atlas_pca.wallet import friction_for
    assert friction_for({"expectedHarm": bad}) == {"tier": "device", "rules": ["harm-unknown"]}
    assert "harm-unknown" not in friction_for({"expectedHarm": 1})["rules"]


@pytest.mark.parametrize("bad", HUGE)
def test_huge_int_is_no_finite_number(bad):
    from atlas_pca.attest_eat_common import is_finite
    from atlas_pca.wallet_omega import is_finite_number
    for f in (is_finite, is_finite_number):
        assert f(5) is True and f(bad) is False
