"""Prohibition engine (port of prohibitions.test.ts + prohibitions-one-document.test.ts): veto over permission, stateful invariants,
fail-closed matching, canonical state digests, the hash chain, signed constitutions and safety evidence."""
import math

from atlas_pca import ed25519
from atlas_pca.pca import b64u, hash_canonical
from atlas_pca.prohibitions import (
    advance_state, advance_state_strict, canonical_state, check_and_advance, check_prohibitions, compose_authority, constitution_id,
    empty_state, evidence_digest, prove_safety, safety_binding_id, sign_constitution, sign_safety_evidence, state_digest, state_problem,
    tick_state, validate_constitution, verify_constitution, verify_safety_evidence, verify_signed_safety_evidence, when_matches,
)
from atlas_pca.safe_regex import RegexBudget

SEED, SIGNER_SEED, OTHER_SEED = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
PRIN, SIGNER_PUB, OTHER_PUB = (b64u(ed25519.public_key(s)) for s in (SEED, SIGNER_SEED, OTHER_SEED))
DAY, NOW = 86_400, 1_700_000_000_000


def act(verb, resource="/r", params=None, env=None):
    out = {"action": {"verb": verb, "resource": resource}}
    if params is not None:
        out["action"]["params"] = params
    if env is not None:
        out["env"] = env
    return out


def constitution(invs):
    return {"version": 1, "principal": PRIN, "invariants": invs}


SPEND = {"id": "spend-day", "kind": "cap", "when": {"verb": "pay", "resource": "*"}, "amount": "action.params.usd", "max": 100, "window_secs": DAY}
NO_PROD_DELETE = {"id": "no-prod-delete-without-human", "kind": "never_unless", "when": {"verb": "delete", "resource": "/prod/*"},
                  "unless": [{"field": "env.human_approved", "op": "eq", "value": True}]}
NO_EXFIL = {"id": "no-pii-exfil", "kind": "never", "when": {"verb": ["export", "send"], "resource": "*", "where": [{"field": "action.params.contains_pii", "op": "eq", "value": True}]}}


def test_veto_over_permission():
    c = constitution([NO_PROD_DELETE, NO_EXFIL])
    a = act("delete", "/prod/db1", {}, {"human_approved": False})
    d = compose_authority(True, a, c, empty_state(NOW))
    assert (d["allow"], d["decidedBy"], d["prohibition"]["violated"]) == (False, "prohibition", ["no-prod-delete-without-human"])
    ok = act("delete", "/prod/db1", {}, {"human_approved": True})
    assert compose_authority(True, ok, c, empty_state(NOW))["allow"] is True
    out_of_plan = act("send", "/mail/x", {"contains_pii": True})
    assert compose_authority(False, out_of_plan, constitution([NO_EXFIL]), empty_state(NOW))["prohibition"]["violated"] == ["no-pii-exfil"]
    assert compose_authority(True, out_of_plan, constitution([NO_EXFIL]), empty_state(NOW))["allow"] is False
    benign = act("send", "/mail/x", {"contains_pii": False})
    assert compose_authority(False, benign, constitution([NO_EXFIL]), empty_state(NOW))["decidedBy"] == "permission"


def test_permitted_must_be_literally_true():
    c = constitution([NO_PROD_DELETE, SPEND])
    a = act("delete", "/prod/db1", {}, {"human_approved": False})
    for p in (True, False, 1, "yes", None):
        assert compose_authority(p, a, c, empty_state(NOW))["allow"] is False
    assert compose_authority(1, act("delete", "/staging/x"), c, empty_state(NOW))["decidedBy"] == "permission"


def test_daily_spend_cap_and_window_roll():
    c = constitution([SPEND])
    s = empty_state(NOW)

    def pay(usd):
        return act("pay", "/vendor/acme", {"usd": usd})

    for i, usd in enumerate([40, 40]):
        t = NOW + i * 1000
        s = {**s, "now": t}
        assert check_prohibitions(pay(usd), c, s)["ok"] is True
        s = advance_state(pay(usd), c, s, t)
    s = {**s, "now": NOW + 3000}
    r = check_prohibitions(pay(30), c, s)
    assert (r["ok"], r["violated"], r["reasons"]) == (False, ["spend-day"], ["spend-day: cap exceeded: 80 + 30 > 100"])
    assert check_prohibitions(pay(20), c, s)["ok"] is True
    assert check_prohibitions(pay(30), c, {**s, "now": NOW + (DAY + 10) * 1000})["ok"] is True


def test_cap_fails_closed_on_missing_negative_or_non_numeric_amount():
    c, s = constitution([SPEND]), empty_state(NOW)
    for params in (None, {}, {"usd": -5}, {"usd": "5"}, {"usd": True}):
        r = check_prohibitions(act("pay", "/v", params), c, s)
        assert r["ok"] is False and r["reasons"] == ["spend-day: amount unresolvable (fail closed)"]
    assert check_prohibitions(act("refund", "/v"), c, s)["ok"] is True


def test_rate_and_never_after():
    c = constitution([{"id": "rate", "kind": "rate", "when": {"verb": "send", "resource": "*"}, "max": 2, "window_secs": 60},
                      {"id": "lockdown", "kind": "never_after", "after": {"verb": "read", "resource": "/secrets/*"}, "forbid": {"verb": "send", "resource": "/net/*"}}])
    s, send = empty_state(NOW), act("send", "/net/out")
    for _ in range(2):
        assert check_prohibitions(send, c, s)["ok"] is True
        s = advance_state(send, c, s)
    r = check_prohibitions(send, c, s)
    assert (r["violated"], r["reasons"]) == (["rate"], ["rate: rate exceeded: 3 > 2 per 60s"])
    s = advance_state(act("read", "/secrets/key"), c, empty_state(NOW))
    assert check_prohibitions(send, c, s)["violated"] == ["lockdown"]
    assert check_prohibitions(act("read", "/pub/x"), c, s)["ok"] is True


def test_advance_state_is_pure():
    c, s = constitution([SPEND]), empty_state(NOW)
    before = repr(s)
    s2 = advance_state(act("pay", "/v", {"usd": 5}), c, s)
    assert repr(s) == before and len(s2["ledger"]["spend-day"]) == 1


def test_never_and_conservative_matching():
    c = constitution([NO_EXFIL])
    s = empty_state(NOW)
    assert check_prohibitions(act("export", "/r", {"contains_pii": True}), c, s)["ok"] is False
    assert check_prohibitions(act("export", "/r", {"contains_pii": False}), c, s)["ok"] is True
    assert check_prohibitions(act("read", "/r", {"contains_pii": True}), c, s)["ok"] is True
    assert check_prohibitions(act("export", "/r"), c, s)["ok"] is False
    assert check_prohibitions(act("export", "/r", {}), c, s)["ok"] is False
    assert check_prohibitions(act("export", "/r", {"contains_pii": "yes"}), c, s)["ok"] is True
    assert check_prohibitions(act("delete", "/prod/x"), constitution([NO_PROD_DELETE]), s)["ok"] is False
    assert check_prohibitions(act("delete", "/staging/x"), constitution([NO_PROD_DELETE]), s)["ok"] is True
    rx = constitution([{"id": "r", "kind": "never", "when": {"verb": "x", "resource": "re:/a/[^/]+"}}])
    assert check_prohibitions(act("x", "/a/" + "b" * 600), rx, s)["ok"] is False


def test_malformed_invariants_deny_everything():
    bad = [
        {"id": "u", "kind": "eventually_always", "when": {"verb": "x"}},
        {"id": "u", "kind": "never", "when": {"verb": ""}},
        {"id": "u", "kind": "never", "when": {"verb": "x", "where": [{"field": "action.verb", "op": "regex", "value": "."}]}},
        {"id": "u", "kind": "never", "when": {"verb": "x", "resource": "re:(a+)+"}},
        {"id": "u", "kind": "cap", "when": {"verb": "x"}, "amount": "env.x", "max": 1},
        {"id": "u", "kind": "cap", "when": {"verb": "x"}, "amount": "action.params.u", "max": math.inf},
        {"id": "u", "kind": "rate", "when": {"verb": "x"}, "max": 1.5, "window_secs": 1},
        {"id": "u", "kind": "never_unless", "when": {"verb": "x"}, "unless": []},
        {"kind": "never", "when": {"verb": "x"}},
        None,
    ]
    for inv in bad:
        c = constitution([inv])
        assert validate_constitution(c)
        r = check_prohibitions(act("anything", "/ok"), c, empty_state(NOW))
        assert (r["ok"], r["violated"]) == (False, ["<constitution>"])
        try:
            sign_constitution(c, SEED)
            raise AssertionError("signed a malformed constitution")
        except TypeError:
            pass


def test_exact_validation_messages():
    assert validate_constitution(None) == ["constitution not an object"]
    assert validate_constitution({"version": 2, "principal": "", "invariants": 5}) == ["unsupported version 2", "principal missing", "invariants not an array"]
    assert validate_constitution({"principal": "p", "invariants": []}) == ["unsupported version undefined"]
    assert validate_constitution({"version": None, "principal": "p", "invariants": []}) == ["unsupported version null"]
    assert validate_constitution(constitution([NO_EXFIL, NO_EXFIL])) == ["no-pii-exfil: duplicate id"]
    assert validate_constitution(constitution([{"id": "__proto__", "kind": "never", "when": {"verb": "x"}}])) == ["__proto__: forbidden id"]
    assert validate_constitution(constitution([{"id": "x" * 129, "kind": "never", "when": {"verb": "x"}}])) == ["%s: id too long" % ("x" * 129)]
    assert validate_constitution(constitution([{"id": "a", "kind": "zzz"}])) == ["a: unknown invariant kind zzz"]
    assert validate_constitution(constitution([{"id": "a", "kind": "rate", "when": {"verb": "x"}, "max": 10001, "window_secs": 1}])) == ["a: max must be an integer in [0,10000]"]
    assert validate_constitution(constitution([{"id": "a", "kind": "rate", "when": {"verb": "x"}, "max": -0.0, "window_secs": 1}])) == ["a: max must be an integer in [0,10000]"]
    assert validate_constitution(constitution([{"id": "a", "kind": "cap", "when": {"verb": "x"}, "amount": "action.x", "max": 1, "window_secs": 0}])) == ["a: bad window_secs"]
    assert validate_constitution(constitution([{"id": "a", "kind": "require_prior", "when": {"verb": "x"}}])) == ["a: prior: not an object"]
    many = constitution([{"id": "i%d" % i, "kind": "never", "when": {"verb": "x"}} for i in range(257)])
    assert validate_constitution(many) == ["too many invariants"]


def test_malformed_constitution_action_state():
    c = constitution([NO_EXFIL])
    assert check_prohibitions(act("a", "/b"), {**c, "version": 2}, empty_state(NOW))["ok"] is False
    assert check_prohibitions({"action": {"verb": 1}}, c, empty_state(NOW))["violated"] == ["<action>"]
    assert check_prohibitions(act("a", "/b"), c, {"now": math.nan})["violated"] == ["<state>"]
    assert check_prohibitions(None, None, None)["ok"] is False


def test_sign_verify_tamper():
    sc = sign_constitution(constitution([SPEND, NO_EXFIL]), SEED)
    assert sc["id"] == constitution_id(constitution([SPEND, NO_EXFIL]))
    assert verify_constitution(sc, PRIN) == {"ok": True}
    assert verify_constitution(sc, OTHER_PUB) == {"ok": False, "reason": "principal mismatch"}
    assert verify_constitution({**sc, "invariants": [{**SPEND, "max": 1e9}, NO_EXFIL]}) == {"ok": False, "reason": "id does not match content"}
    assert verify_constitution({**sc, "invariants": [SPEND]})["ok"] is False
    assert verify_constitution({**sc, "sig": None}) == {"ok": False, "reason": "bad signature"}
    other = sign_constitution({**constitution([]), "principal": OTHER_PUB}, OTHER_SEED)
    assert verify_constitution(other, PRIN)["ok"] is False
    assert verify_constitution(None)["ok"] is False


def test_per_action_evidence():
    c = constitution([SPEND, NO_PROD_DELETE, NO_EXFIL])
    s = advance_state(act("pay", "/v", {"usd": 60}), c, empty_state(NOW))
    a = act("pay", "/vendor/acme", {"usd": 30})
    e1 = prove_safety(a, c, s)
    assert e1 == prove_safety(*(__import__("json").loads(__import__("json").dumps(x)) for x in (a, c, s)))
    assert e1["ok"] is True and [x["id"] for x in e1["evaluated"]] == ["spend-day", "no-prod-delete-without-human", "no-pii-exfil"]
    assert verify_safety_evidence(e1, a, c, s) == {"ok": True}
    assert verify_safety_evidence({**e1, "state_digest": "x"}, a, c, s) == {"ok": False, "reason": "state digest mismatch"}
    assert verify_safety_evidence({**e1, "evaluated": e1["evaluated"][1:]}, a, c, s) == {"ok": False, "reason": "evidence does not reproduce"}
    assert verify_safety_evidence(e1, act("pay", "/vendor/acme", {"usd": 31}), c, s) == {"ok": False, "reason": "action digest mismatch"}
    assert verify_safety_evidence(e1, a, constitution([SPEND]), s) == {"ok": False, "reason": "constitution mismatch"}
    assert verify_safety_evidence({**e1, "v": 2}, a, c, s) == {"ok": False, "reason": "unsupported evidence version"}
    bad = act("pay", "/vendor/acme", {"usd": 99})
    real = prove_safety(bad, c, s)
    assert real["ok"] is False
    assert verify_safety_evidence(real, bad, c, s) == {"ok": False, "reason": "prohibition violated: spend-day"}
    forged = {**real, "ok": True, "violated": [], "evaluated": [{k: v for k, v in x.items() if k != "reason"} | {"result": "pass"} for x in real["evaluated"]]}
    assert verify_safety_evidence(forged, bad, c, s)["ok"] is False


def test_signed_bound_evidence():
    c = constitution([SPEND, NO_PROD_DELETE, NO_EXFIL])
    sc = sign_constitution(c, SEED)
    s = advance_state(act("pay", "/v", {"usd": 60}), c, empty_state(NOW))
    a = act("pay", "/vendor/acme", {"usd": 30})

    def signed(action=a, cons=c, state=s):
        return sign_safety_evidence(prove_safety(action, cons, state), SIGNER_SEED, SIGNER_PUB)

    def full(**over):
        d = {"signer": SIGNER_PUB, "action": a, "constitution": c, "state": s}
        d.update(over)
        return {k: v for k, v in d.items() if v is not None}

    se = signed()
    assert verify_signed_safety_evidence(se, full()) == {"ok": True}
    assert se["id"] == safety_binding_id(se["evidence"], SIGNER_PUB) == signed()["id"]
    assert verify_signed_safety_evidence({**se, "sig": ("B" if se["sig"][0] == "A" else "A") + se["sig"][1:]}, full())["reason"] == "bad signature"
    assert verify_signed_safety_evidence(se, {"signer": [SIGNER_PUB], "actionDigest": se["evidence"]["action_digest"],
                                              "constitutionId": se["evidence"]["constitution"], "stateDigest": state_digest(s)}) == {"ok": True}
    assert verify_signed_safety_evidence(signed(cons=sc), {"signer": SIGNER_PUB, "action": a, "constitution": sc, "state": s, "principal": PRIN})["ok"] is True
    assert verify_signed_safety_evidence(se, full(action=act("pay", "/vendor/acme", {"usd": 31})))["reason"] == "action digest mismatch (evidence bound to another action)"
    assert "constitution" in verify_signed_safety_evidence(se, full(constitution=constitution([SPEND])))["reason"]
    assert verify_signed_safety_evidence(se, full(state=advance_state(act("pay", "/v", {"usd": 1}), c, s)))["reason"] == "state digest mismatch (evidence bound to another state)"
    assert verify_signed_safety_evidence(se, full(state=empty_state(NOW)))["ok"] is False
    assert verify_signed_safety_evidence(se, full(signer=OTHER_PUB))["reason"] == "signer not trusted"
    assert verify_signed_safety_evidence(se, full(signer=[]))["reason"] == "no pinned signer"
    for k, msg in (("action", "unbound: action not specified"), ("constitution", "unbound: constitution not specified"), ("state", "unbound: state not specified")):
        assert verify_signed_safety_evidence(se, {kk: v for kk, v in full().items() if kk != k})["reason"] == msg
    assert verify_signed_safety_evidence(se, full(actionDigest="mismatch"))["reason"] == "expected action and digest disagree"
    assert verify_signed_safety_evidence({**se, "evidence": {**se["evidence"], "now": se["evidence"]["now"] + 1}}, full())["reason"] == "binding id mismatch"
    assert verify_signed_safety_evidence(None, full())["reason"] == "malformed input"
    assert verify_signed_safety_evidence(se, None)["reason"] == "malformed input"
    # a forged all-clear never verifies as an admit; honest violation evidence verifies only with requireOk false
    bad = act("pay", "/vendor/acme", {"usd": 99})
    real = prove_safety(bad, c, s)
    honest = sign_safety_evidence(real, SIGNER_SEED, SIGNER_PUB)
    ex = {"signer": SIGNER_PUB, "action": bad, "constitution": c, "state": s}
    assert verify_signed_safety_evidence(honest, ex)["reason"] == "prohibition violated: spend-day"
    assert verify_signed_safety_evidence(honest, {**ex, "requireOk": False}) == {"ok": True}
    lie = {**real, "ok": True, "violated": [], "evaluated": [{**x, "result": "pass"} for x in real["evaluated"]]}
    assert verify_signed_safety_evidence(sign_safety_evidence(lie, SIGNER_SEED, SIGNER_PUB), ex)["ok"] is False
    assert verify_signed_safety_evidence(sign_safety_evidence({**real, "ok": True}, SIGNER_SEED, SIGNER_PUB),
                                         {"signer": SIGNER_PUB, "actionDigest": real["action_digest"], "constitutionId": real["constitution"], "stateDigest": real["state_digest"]})["reason"] == "evidence verdict inconsistent with rows"
    ev = prove_safety(a, c, s)
    dropped = sign_safety_evidence({**ev, "evaluated": ev["evaluated"][1:]}, SIGNER_SEED, SIGNER_PUB)
    assert verify_signed_safety_evidence(dropped, {"signer": SIGNER_PUB, "actionDigest": ev["action_digest"], "constitution": c, "stateDigest": ev["state_digest"]})["reason"] == "evidence does not cover every invariant"
    assert verify_signed_safety_evidence(se, full(principal=PRIN))["reason"] == "principal pin requires a signed constitution"


def test_unbound_evidence_is_not_signable():
    c, s = constitution([SPEND]), empty_state(NOW)
    ev = prove_safety({"action": {"verb": "pay", "resource": "/v", "params": {"usd": float("nan")}}}, c, s)
    assert ev["ok"] is False and "<action>" in ev["violated"]
    for bad in (ev, {**prove_safety(act("pay", "/v", {"usd": 1}), c, s), "v": 9}):
        try:
            sign_safety_evidence(bad, SIGNER_SEED, SIGNER_PUB)
            raise AssertionError("signed")
        except TypeError:
            pass
    try:
        sign_safety_evidence(prove_safety(act("pay", "/v", {"usd": 1}), c, s), SIGNER_SEED, "")
        raise AssertionError("signed")
    except TypeError:
        pass
    bs = prove_safety(act("pay", "/v", {"usd": 1}), c, {"now": math.nan})
    assert bs["ok"] is False and "<state>" in bs["violated"] and evidence_digest(bs)


def test_require_approval_over_and_require_prior():
    inv = {"id": "big-pay", "kind": "require_approval_over", "when": {"verb": "pay"}, "amount": "action.params.usd", "threshold": 100,
           "approved": [{"field": "env.cfo_approved", "op": "eq", "value": True}]}
    c, s = constitution([inv]), empty_state(NOW)
    assert check_prohibitions(act("pay", "/v", {"usd": 100}), c, s)["ok"] is True
    r = check_prohibitions(act("pay", "/v", {"usd": 101}), c, s)
    assert (r["violated"], r["reasons"]) == (["big-pay"], ["big-pay: approval required over 100"])
    assert check_prohibitions(act("pay", "/v", {"usd": 101}, {"cfo_approved": True}), c, s)["ok"] is True
    assert check_prohibitions(act("pay", "/v", {"usd": 101}, {"cfo_approved": "true"}), c, s)["ok"] is False
    for params in (None, {}, {"usd": "5"}, {"usd": -1}):
        assert check_prohibitions(act("pay", "/v", params), c, s)["ok"] is False
    assert check_prohibitions(act("refund", "/v", {"usd": 1e9}), c, s)["ok"] is True
    rp = constitution([{"id": "review-first", "kind": "require_prior", "when": {"verb": "deploy"},
                        "prior": {"verb": "review", "where": [{"field": "action.params.passed", "op": "eq", "value": True}]}}])
    s, deploy = empty_state(NOW), act("deploy", "/prod")
    assert check_prohibitions(deploy, rp, s)["violated"] == ["review-first"]
    s = advance_state(act("review", "/pr/1", {"passed": False}), rp, s)
    assert s["latched"] == {}
    s = advance_state(act("review", "/pr/1"), rp, s)  # ambiguous prerequisite: NOT latched
    assert s["latched"] == {} and check_prohibitions(deploy, rp, s)["ok"] is False
    s = advance_state(act("review", "/pr/1", {"passed": True}), rp, s)
    assert s["latched"]["review-first"] == NOW and check_prohibitions(deploy, rp, s)["ok"] is True


def test_when_matches_cannot_evaluate_means_matched():
    ctx = act("export", "/r", {"n": 5, "s": "abc", "arr": [1, 2], "flag": True}, {"tenant": "a"})

    def m(c, a=ctx):
        return when_matches({"verb": "export", "where": [c]}, a)

    cases = [
        {"field": "action.params.missing", "op": "eq", "value": 1}, {"field": "action.params.n", "op": "eq"},
        {"field": "action.params.n", "op": "eq", "ref": "action.params.nope"}, {"field": "env.nope", "op": "ne", "value": 1},
        {"field": "subject.x", "op": "eq", "value": 1}, {"field": "bogus.root", "op": "eq", "value": 1},
        {"field": "action.params.n", "op": "in", "value": "notarray"}, {"field": "action.params.n", "op": "nin", "value": 5},
        {"field": "action.params.n", "op": "lt", "value": "str"}, {"field": "action.params.s", "op": "gt", "value": 3},
        {"field": "action.params.flag", "op": "gte", "value": True}, {"field": "action.params.n", "op": "prefix", "value": "a"},
        {"field": "action.params.s", "op": "prefix", "value": 1}, {"field": "action.params.n", "op": "explode", "value": 1},
        {"field": "", "op": "eq", "value": 1}, {"op": "eq", "value": 1}, None, "str",
    ]
    for c in cases:
        assert m(c) is True, c
        assert check_prohibitions(ctx, constitution([{"id": "v", "kind": "never", "when": {"verb": "export", "where": [c]}}]), empty_state(NOW))["ok"] is False
    no_params = act("export", "/r")
    assert m({"field": "action.params.n", "op": "eq", "value": 5}, no_params) is True
    assert m({"field": "action.params.n", "op": "exists", "value": False}, no_params) is True
    assert when_matches({"verb": "export"}, {"action": {"verb": 1}}) is True
    assert when_matches({"verb": ""}, ctx) is True and when_matches(None, ctx) is True
    assert when_matches({"verb": "export", "resource": "re:(a+)+"}, ctx) is True
    assert when_matches({"verb": "export", "resource": "re:("}, ctx) is True
    assert when_matches({"verb": "export", "where": "x"}, ctx) is True
    # cleanly evaluable conditions still evaluate normally
    assert m({"field": "action.params.n", "op": "eq", "value": 5}) is True
    assert m({"field": "action.params.n", "op": "eq", "value": 6}) is False
    assert m({"field": "action.params.n", "op": "in", "value": [1, 5]}) is True
    assert m({"field": "action.params.n", "op": "nin", "value": [1, 5]}) is False
    assert m({"field": "action.params.s", "op": "prefix", "value": "zz"}) is False
    assert m({"field": "action.params.zz", "op": "exists"}) is False
    assert m({"field": "action.params.zz", "op": "exists", "value": False}) is True


def test_redos_resources_are_rejected_and_veto():
    for re_ in ("re:(a+)+$", "re:(a|aa)+", "re:(.*a){10}", "re:(?=a)", "re:(a)\\1"):
        c = constitution([{"id": "r", "kind": "never", "when": {"verb": "x", "resource": re_}}])
        assert validate_constitution(c) == ["r: when: unsafe regex resource"]
        assert check_prohibitions(act("x", "/" + "a" * 40 + "!"), c, empty_state(NOW))["ok"] is False


def test_ambiguous_stateful_action_cannot_be_dodged():
    assert check_prohibitions(act("pay", "/v", {"usd": None}), constitution([SPEND]), empty_state(NOW))["ok"] is False
    rc = constitution([{"id": "r", "kind": "rate", "when": {"verb": "send", "where": [{"field": "action.params.ext", "op": "eq", "value": True}]}, "max": 1, "window_secs": 60}])
    s = advance_state(act("send", "/x"), rc, empty_state(NOW))
    assert len(s["ledger"]["r"]) == 1 and check_prohibitions(act("send", "/x"), rc, s)["violated"] == ["r"]
    assert check_prohibitions(act("send", "/x", {"ext": False}), rc, empty_state(NOW))["ok"] is True


def test_forged_future_or_negative_ledger_entries_are_refused():
    c = constitution([SPEND])
    for entry in ({"t": NOW + 1, "amount": 99}, {"t": NOW, "amount": -50}):
        r = check_prohibitions(act("pay", "/v", {"usd": 1}), c, {**empty_state(NOW), "ledger": {"spend-day": [entry]}})
        assert r["violated"] == ["<state>"]


def test_canonical_state_digest():
    a = {"now": NOW, "seq": 0, "parent": None, "ledger": {"x": [{"t": 1, "amount": 2}, {"t": 0, "amount": 5}], "y": []}, "latched": {"b": 1, "a": 2}}
    b = {"latched": {"a": 2, "b": 1}, "ledger": {"x": [{"amount": 5, "t": 0, "junk": 1}, {"amount": 2, "t": 1}]}, "parent": None, "seq": 0, "now": NOW, "extra": "ignored"}
    assert state_digest(a) == state_digest(b)
    assert canonical_state(a)["ledger"]["x"] == [{"t": 0, "amount": 5}, {"t": 1, "amount": 2}]
    c = constitution([SPEND])
    s = advance_state(act("pay", "/v", {"usd": 10}), c, empty_state(NOW))
    base = state_digest(s)
    variants = [{**s, "now": s["now"] + 1}, {**s, "seq": s["seq"] + 1}, {**s, "parent": "other"},
                {**s, "ledger": {"spend-day": [{"t": NOW, "amount": 9}]}}, {**s, "ledger": {"spend-day": []}}, {**s, "latched": {"z": NOW}}]
    assert all(state_digest(v) != base for v in variants)
    # an empty deadlines map is canonically identical to none; an open one is bound
    assert state_digest({**s, "deadlines": {}}) == base and state_digest({**s, "deadlines": {"d": 2}}) != base


def test_malformed_states():
    ok = empty_state(NOW)
    bad = [None, {**ok, "now": math.nan}, {**ok, "seq": -1}, {**ok, "seq": 1.5}, {**ok, "parent": 5}, {**ok, "parent": "p"}, {**ok, "seq": 2},
           {**ok, "ledger": {"a": "x"}}, {**ok, "ledger": {"a": [{"t": 1, "amount": -1}]}}, {**ok, "ledger": {"a": [{"t": NOW + 1, "amount": 1}]}},
           {**ok, "latched": {"a": NOW + 1}}, {**ok, "latched": {"a": "x"}}, {**ok, "ledger": {"__proto__": []}},
           {**ok, "ledger": {"a": [{"t": 1, "amount": 1}] * 10_001}}, {**ok, "deadlines": 3}, {**ok, "deadlines": {"a": 0}}, {**ok, "deadlines": {"a": 1.5}},
           {**ok, "deadlines": {"a": 1_000_001}}, {**ok, "seq": -0.0}]
    for b in bad:
        assert state_problem(b) is not None, b
        try:
            state_digest(b)
            raise AssertionError("digested")
        except TypeError:
            pass
    assert state_problem(ok) is None
    assert state_problem({**ok, "seq": 1, "parent": None}) == "malformed monitor state: missing chain link"
    assert state_problem({**ok, "parent": "p"}) == "malformed monitor state: genesis has a parent"


def test_tick_state():
    s = empty_state(NOW)
    assert tick_state(s, NOW + 5) == {"ok": True, "state": {**s, "now": NOW + 5}}
    assert tick_state(s, NOW - 1) == {"ok": False, "reason": "clock regression"}
    assert tick_state(s, math.nan) == {"ok": False, "reason": "clock regression"}
    assert tick_state({"now": math.nan}, NOW) == {"ok": False, "reason": "malformed monitor state"}


def test_advance_is_chained_and_deterministic():
    c = constitution([SPEND, {"id": "lock", "kind": "never_after", "after": {"verb": "read", "resource": "/s/*"}, "forbid": {"verb": "send"}}])

    def pay(usd):
        return act("pay", "/v", {"usd": usd})

    a = advance_state_strict(pay(5), c, empty_state(NOW))
    assert a == advance_state_strict(pay(5), c, empty_state(NOW))
    assert a["state"]["seq"] == 1
    assert a["state"]["parent"] == hash_canonical({"d": "atlas-pca/monitor-state-link/v1", "state": state_digest(empty_state(NOW)), "action": hash_canonical(pay(5))})
    a2 = advance_state_strict(pay(6), c, a["state"])
    assert a2["state"]["seq"] == 2 and a2["state"]["parent"] != a["state"]["parent"]
    x = advance_state(pay(2), c, advance_state(pay(1), c, empty_state(NOW), NOW + 10), NOW + 20)
    y = advance_state(pay(1), c, advance_state(pay(2), c, empty_state(NOW), NOW + 10), NOW + 20)
    assert sorted(e["amount"] for e in canonical_state(x)["ledger"]["spend-day"]) == [1, 2] and x["parent"] != y["parent"]


def test_advance_refuses_rather_than_under_counting():
    c = constitution([SPEND])
    s = empty_state(NOW)
    assert advance_state_strict(act("pay", "/v"), c, s) == {"ok": False, "reason": "spend-day: amount unresolvable"}
    assert advance_state_strict(act("pay", "/v", {"usd": 1}), c, s, NOW - 1) == {"ok": False, "reason": "clock regression"}
    assert advance_state_strict(act("pay", "/v", {"usd": 1}), c, {"now": math.nan})["ok"] is False
    assert advance_state_strict({"action": {"verb": 1}}, c, s) == {"ok": False, "reason": "malformed action"}
    assert advance_state_strict(act("pay", "/v", {"usd": 1}), constitution([{"kind": "x"}]), s)["ok"] is False
    assert advance_state(act("pay", "/v"), c, s) is s


def test_prune_merge_and_earliest_latch():
    c = constitution([SPEND, {"id": "lock", "kind": "never_after", "after": {"verb": "read", "resource": "/s/*"}, "forbid": {"verb": "send"}}])
    s0 = advance_state(act("pay", "/v", {"usd": 50}), c, empty_state(NOW))
    s1 = advance_state(act("pay", "/v", {"usd": 1}), c, s0, NOW + (DAY + 1) * 1000)
    assert s1["ledger"]["spend-day"] == [{"t": NOW + (DAY + 1) * 1000, "amount": 1}]
    life = constitution([{**{k: v for k, v in SPEND.items() if k != "window_secs"}, "max": 1e9}])
    big = {**empty_state(NOW), "ledger": {"spend-day": [{"t": NOW - 10_000 + i, "amount": 1} for i in range(10_000)]}}
    grown = advance_state_strict(act("pay", "/v", {"usd": 1}), life, big)
    led = grown["state"]["ledger"]["spend-day"]
    assert len(led) == 10_000 and sum(e["amount"] for e in led) == 10_001
    l1 = advance_state(act("read", "/s/k"), c, empty_state(NOW))
    assert advance_state(act("read", "/s/k"), c, l1, NOW + 5)["latched"]["lock"] == NOW
    rc = constitution([{"id": "r", "kind": "rate", "when": {"verb": "x"}, "max": 10_000, "window_secs": 1e9}])
    full = {**empty_state(NOW), "ledger": {"r": [{"t": NOW, "amount": 1}] * 10_000}}
    assert advance_state_strict(act("x", "/a"), rc, full) == {"ok": False, "reason": "r: rate ledger overflow"}


def test_check_and_advance():
    c = constitution([NO_PROD_DELETE, SPEND])
    s = empty_state(NOW)
    pay = act("pay", "/vendor/acme", {"usd": 40})
    r = check_and_advance(True, pay, c, s, {"expectedSeq": 0, "expectedStateDigest": state_digest(s)})
    assert r["allow"] is True and r["next"]["seq"] == 1 and r["evidence"]["state_digest"] == state_digest(s)
    assert verify_safety_evidence(r["evidence"], pay, c, s) == {"ok": True}
    denied = check_and_advance(False, pay, c, s)
    assert denied["next"] is s and denied["decidedBy"] == "permission"
    veto = check_and_advance(True, act("pay", "/v", {"usd": 500}), c, s)
    assert (veto["allow"], veto["decidedBy"]) == (False, "prohibition") and veto["next"] is s
    stale = check_and_advance(True, pay, c, s, {"expectedSeq": 1})
    assert (stale["allow"], stale["decidedBy"], stale["reason"]) == (False, "state", "stale state head (seq)")
    assert check_and_advance(True, pay, c, s, {"expectedStateDigest": "old"})["reason"] == "stale state head (digest)"
    assert check_and_advance(True, act("pay", "/v"), c, s)["allow"] is False
    assert check_and_advance(True, pay, c, {"now": math.nan})["allow"] is False
    res = check_and_advance(True, act("x", "r"), constitution([{"id": "n", "kind": "never", "when": {"verb": "x"}}]), s)
    assert res["evidence"]["evaluated"] == res["prohibition"]["evaluated"]
    assert res["evidence"]["evaluated"] is not res["prohibition"]["evaluated"] and res["evidence"]["evaluated"][0] is not res["prohibition"]["evaluated"][0]


def test_check_and_advance_is_one_regex_document():
    heavy = ".*" + "[^]{64}" * 24 + ".*"
    c = constitution([{"id": "n%d" % i, "kind": "never", "when": {"verb": "*", "resource": "re:" + heavy}} for i in range(8)])
    a = {"action": {"verb": "read", "resource": "a" * 512}, "env": {}}
    one = RegexBudget.request()
    one.run(lambda: check_prohibitions(a, c, empty_state(NOW)))
    caa = RegexBudget.request()
    res = caa.run(lambda: check_and_advance(True, a, c, empty_state(NOW)))
    assert res["allow"] is False
    assert (caa.steps, caa.evaluations, caa.chars) == (one.steps, one.evaluations, one.chars)


def test_long_scripted_session():
    c = constitution([SPEND, {"id": "rate", "kind": "rate", "when": {"verb": "send"}, "max": 3, "window_secs": 60},
                      {"id": "lock", "kind": "never_after", "after": {"verb": "read", "resource": "/secrets/*"}, "forbid": {"verb": "send", "resource": "/net/*"}},
                      {"id": "review", "kind": "require_prior", "when": {"verb": "deploy"}, "prior": {"verb": "review"}},
                      {"id": "big", "kind": "require_approval_over", "when": {"verb": "pay"}, "amount": "action.params.usd", "threshold": 60,
                       "approved": [{"field": "env.ok", "op": "eq", "value": True}]}])
    sc = sign_constitution(c, SEED)
    st = {"s": empty_state(NOW), "t": NOW}
    log = []

    def step(a, allow, dt=1000, violated=None):
        st["t"] += dt
        pre = tick_state(st["s"], st["t"])["state"]
        r = check_and_advance(True, a, sc, pre, {"expectedSeq": pre["seq"]})
        assert r["allow"] is allow, a
        if violated is not None:
            assert r["prohibition"]["violated"] == violated
        if allow:
            se = sign_safety_evidence(r["evidence"], SIGNER_SEED, SIGNER_PUB)
            assert verify_signed_safety_evidence(se, {"signer": SIGNER_PUB, "action": a, "constitution": sc, "state": pre, "principal": PRIN}) == {"ok": True}
            log.append((a, pre, se))
            st["s"] = r["next"]
        else:
            assert r["next"] is pre
            st["s"] = pre

    step(act("deploy", "/prod"), False, 1000, ["review"])
    step(act("review", "/pr/1"), True)
    step(act("deploy", "/prod"), True)
    step(act("pay", "/v", {"usd": 50}), True)
    step(act("pay", "/v", {"usd": 70}), False, 1000, ["spend-day", "big"])
    step(act("pay", "/v", {"usd": 40}), True)
    step(act("pay", "/v", {"usd": 20}), False, 1000, ["spend-day"])
    for _ in range(3):
        step(act("send", "/net/a"), True)
    step(act("send", "/net/a"), False, 1000, ["rate"])
    step(act("send", "/net/a"), True, 61_000)
    step(act("read", "/secrets/k"), True)
    step(act("send", "/net/a"), False, 1000, ["lock"])
    step(act("send", "/mail/a"), True)
    step(act("pay", "/v", {"usd": 5}), True, DAY * 1000)
    assert "lock" in st["s"]["latched"] and "review" in st["s"]["latched"]
    replay = empty_state(NOW)
    for a, pre, se in log:
        tk = tick_state(replay, pre["now"])["state"]
        assert state_digest(tk) == state_digest(pre) == se["evidence"]["state_digest"]
        replay = advance_state_strict(a, c, tk)["state"]
    assert replay["seq"] == len(log) and len({state_digest(p) for _, p, _ in log}) == len(log)
    first, last = log[0], log[-1]
    assert verify_signed_safety_evidence(first[2], {"signer": SIGNER_PUB, "action": first[0], "constitution": sc, "state": last[1]})["ok"] is False


def test_a_regex_that_javascript_would_reject_is_never_accepted_as_a_trigger():
    # new RegExp('^(?:' + src + ')$') throws for each of these; the safe-source gate refuses them first, with the same reason text TS gives
    # (checked against node over 1269 accepted sources: none throws)
    for src in ("[z-a]", "a{2,1}", "(?<n>a)(?<n>b)", "\\k<n>", "(a", "a)", "a**", "*", "+", "[a", "\\", "(?<n", "\\u{110000}"):
        c = constitution([{"id": "r", "kind": "never", "when": {"verb": "x", "resource": "re:" + src}}])
        assert validate_constitution(c) == ["r: when: unsafe regex resource"], src
        assert check_prohibitions(act("x", "/a"), c, empty_state(NOW))["ok"] is False


def test_non_ascii_texts_digests_and_lengths_match_the_reference():
    # expected values come from running the TypeScript reference on the same inputs
    p = "príncipe-ключ-\U0001f642"
    invs = [{"id": "ünï-cap", "kind": "cap", "when": {"verb": "pay"}, "amount": "action.params.usd", "max": 100, "window_secs": 60, "description": "dépense \U0001f642"},
            {"id": "\U0001f642rate", "kind": "rate", "when": {"verb": "x"}, "max": 1, "window_secs": 5},
            {"id": "nv", "kind": "never", "when": {"verb": "del"}},
            {"id": "big", "kind": "require_approval_over", "when": {"verb": "buy"}, "amount": "action.params.usd", "threshold": 5,
             "approved": [{"field": "env.ok", "op": "eq", "value": True}]}]
    assert validate_constitution({"version": 1, "principal": p, "invariants": invs + [{"id": "ü" * 129, "kind": "never", "when": {"verb": "x"}},
                                 {"id": "\U0001f642" * 65, "kind": "never", "when": {"verb": "x"}}, {"id": "zz", "kind": "wéird"}]}) == [
        "%s: id too long" % ("ü" * 129), "%s: id too long" % ("\U0001f642" * 65), "zz: unknown invariant kind wéird"]
    # 64 astral characters are 128 UTF-16 units (allowed); 65 are 130 (refused)
    assert validate_constitution(constitution([{"id": "\U0001f642" * 64, "kind": "never", "when": {"verb": "x"}}])) == []
    c = {"version": 1, "principal": p, "invariants": invs}
    s = empty_state(NOW)
    assert constitution_id(c) == "4X1Yj4-1T9q3Hw750Bcf5WeCK8wbC84m-NC-XGEg3hk"
    assert check_prohibitions(act("del", "/\U0001f642", {}), c, s)["reasons"] == ["nv: forbidden action"]
    assert check_prohibitions(act("buy", "/é", {"usd": 9}, {"ok": False}), c, s)["reasons"] == ["big: approval required over 5"]
    assert advance_state_strict(act("pay", "/é", {"usd": 60}), c, s)["ok"] is True


def test_signed_evidence_with_odd_rows_returns_the_reference_reason():
    # reasons below were produced by the TypeScript reference
    c = constitution([{"id": "n", "kind": "never", "when": {"verb": "x"}}])
    a, s = act("y"), empty_state(NOW)
    real = prove_safety(a, c, s)
    dig = {"signer": SIGNER_PUB, "actionDigest": real["action_digest"], "stateDigest": real["state_digest"]}

    def sign(ev):
        return sign_safety_evidence(ev, SIGNER_SEED, SIGNER_PUB)

    def w(inv):
        return {**c, "invariants": inv}

    def vs(se, ex):
        return verify_signed_safety_evidence(se, ex)

    def no(reason):
        return {"ok": False, "reason": reason}

    assert vs(sign({**real, "evaluated": [{"result": "pass"}]}), {**dig, "constitution": c}) == no("evidence does not cover every invariant")
    assert vs(sign({**real, "evaluated": ["x"]}), {**dig, "constitution": c}) == no("evidence verdict inconsistent with rows")
    assert vs(sign({**real, "evaluated": [None]}), {**dig, "constitution": c}) == no("evidence verdict inconsistent with rows")
    assert vs(sign({**real, "ok": False, "violated": ["v"], "evaluated": ["x"]}), {**dig, "constitution": c, "requireOk": False}) == {"ok": True}
    assert vs(sign({**real, "ok": False, "violated": ["v"], "evaluated": ["x"]}), {"signer": SIGNER_PUB, "action": a, "constitution": c, "state": s, "requireOk": False}) == no("evidence does not reproduce")
    assert vs(sign({**real, "evaluated": [{"result": "pass"}]}), {"signer": SIGNER_PUB, "action": a, "constitution": c, "state": s}) == no("evidence does not reproduce")
    # a malformed expected constitution never verifies (an id-less row must not "cover" an invariant without an id)
    for bad in ([5], [None], ["q"], [{"kind": "never", "when": {"verb": "x"}}], [{"id": "", "kind": "never", "when": {"verb": "x"}}]):
        con = w(bad)
        r = vs(sign({**real, "constitution": constitution_id(con), "evaluated": [{"result": "pass"}]}), {**dig, "constitution": con})
        assert r["ok"] is False and r["reason"].startswith("constitution malformed: "), bad
    assert vs(sign({**real, "evaluated": [{"id": 5, "result": "pass"}]}), {**dig, "constitution": c}) == no("malformed evidence")
