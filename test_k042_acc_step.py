"""Kill tests for rule 15's per-accumulator step (_acc_step): accumulator order around wallet-held ones, a schema document
that is not an object, a verb whose params are not an object, the policy age bounds in seconds, and the key-set default."""
import test_mutation_kill_intent_v2 as T
from atlas_pca.intent_v2 import action_schema_digest, session_root_digest, suite_available


def _root(accs, schema_digest=None):
    over = {"accumulators": accs}
    if schema_digest is not None:
        over["schema"] = {"aud": T.AUD, "digest": schema_digest}
    return T._root_of(**over)


def test_wallet_accumulator_before_a_site_one_does_not_end_the_loop():
    S = _root([T.QUESTIONS, T.TRIP])
    R = session_root_digest(S)
    g = T._grant(root=R)
    ctx = T._ctx(session={"root": S, "grants": []}, acc={"state": {"trip_spend": {"sum": 0}}, "monitors": {}})
    ok = T._acc(T._pcactn(g, intent_session=T._is(root=R)), ctx, g)
    assert ok["ok"] is True
    d = T._decide(T._pcactn(g, intent_session=T._is(root=R)), g, ctx)
    assert d["env"]["acc"] == {"trip_spend": {"post": 38_900}}
    wrong = T._pcactn(g, intent_session=T._is(root=R, acc=[{"id": "trip_spend", "post": 1}]))
    assert T._acc(wrong, ctx, g)["reason"] == "claimed post 1 for 'trip_spend' differs from the verifier's 38900"
    nostate = T._ctx(session={"root": S, "grants": []}, acc={"state": {}, "monitors": {}})
    assert T._acc(T._pcactn(g, intent_session=T._is(root=R)), nostate, g)["reason"] == \
        "no state for site-local accumulator 'trip_spend'"


def test_a_schema_document_that_is_not_an_object_is_not_the_session_schema():
    dig = action_schema_digest(5)
    S = _root([T.TRIP], schema_digest=dig)
    R = session_root_digest(S)
    g = T._grant(root=R)
    ctx = T._ctx(session={"root": S, "grants": []}, schema={"docs": [5], "keys": T.KEYS},
                 acc={"state": {"trip_spend": {"sum": 0}}, "monitors": {}})
    p = T._pcactn(g, intent_session=T._is(root=R, schema=dig))
    assert T._acc(p, ctx, g)["reason"] == \
        "accumulator 'trip_spend' selects by accumulates_into but the session schema is not available"


def test_a_verb_without_object_params_in_the_session_schema_fails_closed():
    doc = {"verbs": [{"verb": "air.book"}]}
    dig = action_schema_digest(doc)
    keyed = dict(T.TRIP, id="per_offer", agg="count", sel={"verbs": ["air.book"]}, key="action.params.offer_id", domain_max=5)
    del keyed["unit"]
    S = _root([keyed], schema_digest=dig)
    R = session_root_digest(S)
    g = T._grant(root=R)
    ctx = T._ctx(session={"root": S, "grants": []}, schema={"docs": [doc], "keys": T.KEYS},
                 acc={"state": {"per_offer": {"count": 0}}, "monitors": {}})
    p = T._pcactn(g, intent_session=T._is(root=R, schema=dig, acc=[{"id": "per_offer", "post": 1}]))
    assert T._acc(p, ctx, g) == {"name": "accumulators", "ok": False,
                                 "reason": "accumulators error (fail closed): the verb's params must be an object"}


def test_policy_ages_are_seconds_to_the_millisecond():
    ks0 = T._keyset([{"kid": "s2", "pk": T._pub(T.SEQ), "not_before": 0}])
    sig_reason = ("the reservation receipt for 'trip_spend' is not signed by a key the session sequencer's root-signed key set "
                  "lists for its issue time")

    def run(rc, ks, policy):
        c = T._c_seq([rc], keys=[ks])
        c["policy"] = {"acc": policy}
        return T._acc(T._p_seq(rc), c, T.G_SEQ)

    old = T._receipt(issued_at=T.NOW - 2001, expires_at=T.NOW + 1000)
    assert run(old, ks0, {"max_receipt_age_s": 2})["reason"] == sig_reason
    ok = T._receipt(issued_at=T.NOW - 2000, expires_at=T.NOW + 1000)
    assert run(ok, ks0, {"max_receipt_age_s": 2})["ok"] is True
    stale = T._keyset(ks0["keys"], issued=T.NOW - 2001)
    assert run(T.RC, stale, {"max_keyset_age_s": 2})["reason"] == sig_reason
    fresh = T._keyset(ks0["keys"], issued=T.NOW - 2000)
    assert run(T.RC, fresh, {"max_keyset_age_s": 2})["ok"] is True


def test_absent_sequencer_keys_means_an_empty_list_not_a_malformed_one():
    rc = T._receipt(alg="no-such-suite")
    c = T._c_seq([rc])
    del c["acc"]["sequencer_keys"]
    r = T._acc(T._p_seq(rc), c, T.G_SEQ)
    assert r["reason"] == "the reservation receipt for 'trip_spend': receipt.alg: unsupported_suite: 'no-such-suite'"


def test_a_key_set_that_fails_a_key_check_does_not_hide_a_later_good_one():
    h = T.SEQ_ACC["holder"]
    rerr = T.V2.receipt_against_holder_error
    good = T.KS
    assert rerr(T.RC, h, [good], T.NOW) is None

    def ks(entry):
        return T._keyset([dict({"kid": "s2", "pk": T._pub(T.SEQ), "not_before": T.NOW - 1000}, **entry)])

    bads = {
        "kid not listed": T._keyset([{"kid": "s9", "pk": T._pub(T.SEQ), "not_before": 0}]),
        "other pk": ks({"pk": T._pub(T.STRANGER)}),
        "not yet valid": ks({"not_before": T.NOW + 1}),
        "retired before the receipt": ks({"not_after": T.NOW - 1}),
        "retired long ago": ks({"not_before": 0, "not_after": T.NOW - 100_000}),
        "other suite": ks({"alg": "hybrid-ed25519-ml-dsa-65"}),
    }
    hybrid = suite_available("hybrid-ed25519-ml-dsa-65")
    for name, bad in bads.items():
        alone = rerr(T.RC, h, [bad], T.NOW)
        if name == "other suite" and alone is not None and "unsupported_suite" in alone:
            # no key verifies and one entry's suite is not on this host: the first unsupported_suite reason is reported
            assert hybrid is not True, alone
        else:
            assert alone == "invalid", name
        assert rerr(T.RC, h, [bad, good], T.NOW) is None, name
        assert rerr(T.RC, h, [bad, bad, good], T.NOW) is None, name


def test_verify_session_root_reports_an_internal_error_as_a_malformed_root(monkeypatch):
    def boom(s):
        raise ValueError("boom")

    monkeypatch.setattr(T.V2, "session_root_shape_error", boom)
    assert T.verify_session_root(T.S0) == {"ok": False, "reason": "malformed session root: boom"}
