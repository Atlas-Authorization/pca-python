"""Mutation kill for the tail of the authorize pipeline: the risk / threshold / trust-budget hand-off, the replay and claim steps
(including the 0.4 key carry-over and budget conflicts), the pin writes, the passport / forbid / template / contract gates, the
conformance policy projection and the option forwarding of ``AuthorizeOptions``. Expected strings are the TypeScript reference's
(require-pca.ts, risk.ts, server/authorize.ts)."""
import copy
import importlib
import json
import os
import types

import pytest

import atlas_pca.beacon as BC
from atlas_pca.caveat_lang import K1_CAVEAT_TYPES
from atlas_pca.forbid_certificate import certify
from atlas_pca.pca import Verdict
from atlas_pca.revocation_staleness import RevocationStaleness
from prov_harness import calm_risk, prov

Z = importlib.import_module("atlas_pca.authorize")

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as _f:
    FIX = json.load(_f)
NOW, AUD = FIX["now"], FIX["audience"]
CASE = next(c for c in FIX["cases"] if c["name"] == "envelope-max-spend-within")
P0, OP, G = CASE["steps"][0]["pcactn"], CASE["steps"][0]["operation"], CASE["grant"]
HOLDER = P0["cap_chain"][-1]["holder"]
GID = G["id"]
COUNTER = P0["counter"]
SKEY = Z.state_key(GID, HOLDER, AUD)
LEGACY = Z.state_key(GID, HOLDER)
BUD = {"B": 9, "tau": 1, "asOf": 1}


def run(**kw):
    p = kw.pop("pcactn", None)
    p = copy.deepcopy(P0) if p is None else p
    grant = kw.pop("grant", None)
    opts = dict(operation=OP, audience=AUD, resolve_grant=lambda ref: G if grant is None else grant,
                state_store=Z.MemoryStateStore(), is_revoked=lambda _p, _g: False, now=NOW, plan="single-step", risk=calm_risk)
    opts.update(prov(OP))
    opts.update(kw)
    return Z.authorize(p, **opts)


def inject(monkeypatch):
    """The core accepts whatever PCActn is presented (to reach the stages behind it with odd shapes)."""
    base = Z.verify_pcactn_core(copy.deepcopy(P0), G, now=NOW, audience=AUD, insecure_skip_plan_root_check=True)
    v = Verdict(True, dict(base.checks), None, [])
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: v)
    return v


def inject_escalate(monkeypatch):
    base = Z.verify_pcactn_core(copy.deepcopy(P0), G, now=NOW, audience=AUD, insecure_skip_plan_root_check=True)
    checks = dict(base.checks)
    checks["provenance"] = False
    reason = "provenance: intent_required: q"
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: Verdict(False, dict(checks), reason, [reason]))


def stub_risk(monkeypatch, *, release=False, t=1, proof="cosign", budget="DEFAULT", r=0.5, reasons=()):
    """A canned risk decision (the call arguments are recorded)."""
    if budget == "DEFAULT":
        budget = BUD
    calls = []

    def fake(*a, **k):
        calls.append((a, k))
        return {"r": r, "reasons": list(reasons), "budget": None if budget is None else dict(budget), "release": release,
                "threshold": {"t": t, "proof": proof}}

    monkeypatch.setattr(Z, "decide_risk", fake)
    return calls


class RecStore(Z.MemoryStateStore):
    def __init__(self):
        super().__init__()
        self.claims = []

    def claim_budget(self, key, counter, budget_before, budget_after):
        self.claims.append((key, counter, budget_before, budget_after))
        return super().claim_budget(key, counter, budget_before, budget_after)


class Bare:
    """A store that cannot report its head (no ``last``)."""

    def __init__(self):
        self.claims = []

    def budget(self, key):
        return None

    def claim(self, key, counter):
        return Z.ClaimResult(True)

    def claim_budget(self, key, counter, budget_before, budget_after):
        self.claims.append((key, counter, budget_before, budget_after))
        return Z.ClaimResult(True)


class Contracts:
    def __init__(self, verdict=None, on_check=None):
        self.peeks, self.checks, self.verdict, self.on_check = [], [], verdict, on_check

    def peek(self, action):
        self.peeks.append(action)
        return {"allow": True}

    def check(self, action, advance):
        self.checks.append((action, advance))
        if self.on_check is not None:
            self.on_check()
        return self.verdict or {"allow": True}


# ---- risk decision inputs --------------------------------------------------------------------------------------------------------

def test_decide_risk_receives_every_input(monkeypatch):
    inject(monkeypatch)
    calls = stub_risk(monkeypatch)
    ctx = lambda _p: {"goal_node_id": "goalN", "age_horizon_ms": 777}  # noqa: E731
    run(context=ctx)
    env = Z.read_envelope(G)
    a, k = calls[-1]
    assert a[0] == env["risk_policy"]
    assert a[1] == Z.riskier(None, calm_risk(None, None, None))
    assert a[2] == {"B": env["risk_policy"]["bMax"], "tau": NOW, "asOf": NOW}
    assert a[3] == NOW and a[4] is True and len(a) == 5
    node = {"id": "n1", "verb": OP["verb"], "resource": OP["resource"], "params_digest": P0["action"]["params_digest"],
            "reversibility_class": "irreversible"}
    assert k == {"reversibility_class": "irreversible", "plan": [node], "node_id": "n1", "goal_node_id": "goalN",
                 "age_horizon_ms": 777, "r_floor": None}


def test_decide_risk_caution_floor_takes_real_numbers_only(monkeypatch):
    inject(monkeypatch)
    calls = stub_risk(monkeypatch)
    for caution, want in ((3, 3), (2.5, 2.5), (0, 0), (True, None), (False, None), ("3", None), (None, None)):
        p = copy.deepcopy(P0)
        p["caution"] = caution
        run(pcactn=p)
        got = calls[-1][1]["r_floor"]
        assert got == want and type(got) is type(want)
    p = copy.deepcopy(P0)
    p.pop("caution", None)
    run(pcactn=p)
    assert calls[-1][1]["r_floor"] is None


def test_decide_risk_budget_comes_from_the_store_the_carry_over_or_the_seed(monkeypatch):
    stored, carried = {"B": 4, "tau": 2, "asOf": 2}, {"B": 3, "tau": 5, "asOf": 5}
    calls = stub_risk(monkeypatch)
    s = RecStore()
    assert run(state_store=s).allow is True
    assert calls[-1][0][2] == {"B": Z.read_envelope(G)["risk_policy"]["bMax"], "tau": NOW, "asOf": NOW}
    assert s.claims == [(SKEY, COUNTER, None, BUD)]
    s = RecStore()
    s.put_budget(SKEY, stored)
    assert run(state_store=s).allow is True
    assert calls[-1][0][2] == stored
    assert s.claims == [(SKEY, COUNTER, stored, BUD)]
    s = RecStore()
    s.put_budget(LEGACY, carried)  # the 0.4 key carried over: nothing to compare with at the claim
    assert run(state_store=s).allow is True
    assert calls[-1][0][2] == carried
    assert s.claims == [(SKEY, COUNTER, None, BUD)]


def test_no_budget_at_all_decides_with_an_empty_one_and_stores_none(monkeypatch):
    calls = stub_risk(monkeypatch)
    s = RecStore()
    assert run(state_store=s, seed_budget=None).allow is True
    assert calls[-1][0][2] == {"B": 0, "tau": NOW, "asOf": NOW}
    assert s.claims == [(SKEY, COUNTER, None, None)]


def test_a_store_without_a_head_claims_on_the_legacy_key(monkeypatch):
    stub_risk(monkeypatch)
    s = Bare()
    assert run(state_store=s).allow is True
    assert s.claims == [(LEGACY, COUNTER, None, BUD)]


def test_adaptive_policy_is_asked_with_the_decision_time(monkeypatch):
    stub_risk(monkeypatch)
    seen = []
    r = run(adaptive_policy=lambda n: seen.append(n))
    assert r.allow is True and seen == [NOW]


# ---- threshold -------------------------------------------------------------------------------------------------------------------

def _thr(monkeypatch, hook, t=3, release=True):
    stub_risk(monkeypatch, release=release, t=t, proof="cosign")
    return run(threshold=hook)


def _thr_reasons(r):
    return [x for x in r.reasons if x.startswith("threshold")]


def test_threshold_hook_gets_the_pcactn_the_grant_and_the_required_threshold(monkeypatch):
    stub_risk(monkeypatch, release=True, t=3, proof="cosign")
    seen = []
    p = copy.deepcopy(P0)

    def hook(*a):
        seen.append(a)
        return {"enforced": True, "ok": True, "t": 3}

    r = run(pcactn=p, threshold=hook)
    assert len(seen) == 1 and seen[0][0] is p and seen[0][1] is G and seen[0][2] == {"t": 3, "proof": "cosign"}
    assert r.allow is True and r.checks["threshold"] == "pass" and _thr_reasons(r) == []


@pytest.mark.parametrize("t, called", [(1, False), (2, True), (3, True)])
def test_the_hook_runs_only_above_t_one(monkeypatch, t, called):
    seen = []

    def hook(*a):
        seen.append(a)
        return {"enforced": True, "ok": True, "t": t}

    r = _thr(monkeypatch, hook, t=t)
    assert bool(seen) is called
    assert r.allow is True and r.checks["threshold"] == ("pass" if called else "not-enforced")


def test_no_hook_when_the_decision_is_not_released(monkeypatch):
    seen = []
    r = _thr(monkeypatch, lambda *a: seen.append(a), t=3, release=False)
    assert seen == [] and r.checks["threshold"] == "not-enforced" and _thr_reasons(r) == []


NO_VERIFIER = "threshold: t=3 (cosign) required but no threshold verifier is enforced"


@pytest.mark.parametrize("hook", [None, lambda *a: None, lambda *a: "ok", lambda *a: [True],
                                  lambda *a: {"enforced": False, "ok": True, "t": 3}, lambda *a: {"ok": True, "t": 3},
                                  lambda *a: {"enforced": 1, "ok": True, "t": 3}, lambda *a: {"enforced": "yes", "ok": True, "t": 3}])
def test_an_unenforced_threshold_is_refused(monkeypatch, hook):
    r = _thr(monkeypatch, hook)
    assert r.allow is False and r.checks["threshold"] == "fail"
    assert _thr_reasons(r) == [NO_VERIFIER]
    assert "authorize" not in r.checks


@pytest.mark.parametrize("res", [{"enforced": True, "ok": False, "t": 3}, {"enforced": True, "t": 3}, {"enforced": True, "ok": "yes", "t": 3},
                                 {"enforced": True, "ok": None, "t": 3}])
def test_a_rejected_threshold_proof_is_refused(monkeypatch, res):
    r = _thr(monkeypatch, lambda *a: res)
    assert r.allow is False and r.checks["threshold"] == "fail"
    assert _thr_reasons(r) == ["threshold: t=3 required and the threshold proof was rejected"]


BELOW = ("threshold: threshold hook enforced t=%s but the server requires t=3 (below the server-derived threshold; derive t from "
         "server-held data)")


@pytest.mark.parametrize("res, shown", [({"enforced": True, "ok": True, "t": 2}, "2"), ({"enforced": True, "ok": True, "t": 0}, "0"),
                                        ({"enforced": True, "ok": True}, "unreported"), ({"enforced": True, "ok": True, "t": None}, "unreported"),
                                        ({"enforced": True, "ok": True, "t": "3"}, "unreported"),
                                        ({"enforced": True, "ok": True, "t": 3.5}, "unreported"),
                                        ({"enforced": True, "ok": True, "t": True}, "unreported")])
def test_a_hook_that_enforced_less_than_the_server_requires_is_refused(monkeypatch, res, shown):
    r = _thr(monkeypatch, lambda *a: res)
    assert r.allow is False and r.checks["threshold"] == "fail"
    assert _thr_reasons(r) == [BELOW % shown]


@pytest.mark.parametrize("t_hook", [3, 4])
def test_a_hook_that_enforced_at_least_the_required_threshold_passes(monkeypatch, t_hook):
    r = _thr(monkeypatch, lambda *a: {"enforced": True, "ok": True, "t": t_hook})
    assert r.allow is True and r.checks["threshold"] == "pass" and _thr_reasons(r) == []


# ---- required checks --------------------------------------------------------------------------------------------------------------

def test_risk_inputs_are_a_required_check_only_when_asked_for():
    r = run()
    assert r.allow is True and "risk_inputs" not in r.checks
    r = run(require_risk_inputs=[])
    assert r.allow is True and "risk_inputs" not in r.checks
    r = run(require_risk_inputs=["blastRadius"])
    assert r.allow is True and r.checks["risk_inputs"] == "pass"
    assert not [x for x in r.checks if x.lower().startswith("xx") or x == "RISK_INPUTS"]
    r = run(require_risk_inputs=["nope"])
    assert r.allow is False and r.checks["risk_inputs"] == "fail"
    assert [x for x in r.reasons if x.startswith("risk_inputs")] == ["risk_inputs: required risk input(s) not supplied by the server: nope"]


# ---- replay -----------------------------------------------------------------------------------------------------------------------

def test_an_unreadable_store_keeps_the_replay_check_failed(monkeypatch):
    class Unreadable(Z.MemoryStateStore):
        def last(self, key):
            raise RuntimeError("down")

    r = run(state_store=Unreadable())
    assert r.allow is False and r.checks["replay"] == "fail"
    assert [x for x in r.reasons if x.startswith("replay")] == ["replay: the replay store failed (fail closed)"]


def test_a_store_that_answers_for_a_key_the_proof_has_no_stream_for_changes_nothing(monkeypatch):
    inject(monkeypatch)

    class AnyLast(Z.MemoryStateStore):
        def last(self, key):
            return 100

    r = run(state_store=AnyLast(), grant=dict(G, id=5))
    assert r.allow is False and r.checks["replay"] == "pass"
    assert not [x for x in r.reasons if "last seen" in x]


def test_a_replayed_counter_on_the_legacy_key_is_refused_before_any_state_is_written(monkeypatch):
    stub_risk(monkeypatch)
    for last in (COUNTER, COUNTER + 3):
        store = Z.MemoryStateStore()
        store.claim(LEGACY, last)
        c = Contracts()
        r = run(state_store=store, contracts=c)
        assert r.allow is False and r.checks["replay"] == "fail"
        assert [x for x in r.reasons if x.startswith("replay")] == ["replay: %s is not greater than last seen %s (replay)" % (COUNTER, last)]
        assert c.checks == []
    store = Z.MemoryStateStore()
    store.claim(LEGACY, COUNTER - 1)
    c = Contracts()
    r = run(state_store=store, contracts=c)
    assert r.allow is True and len(c.checks) == 1 and store.last(SKEY) == COUNTER


class LateLegacy(Z.MemoryStateStore):
    """Reports nothing until ``late`` is set; then only the 0.4 key reports ``value``."""

    def __init__(self, value):
        super().__init__()
        self.value, self.late = value, False

    def last(self, key):
        return self.value if self.late and key == LEGACY else None


@pytest.mark.parametrize("value", [COUNTER, COUNTER + 4])
def test_the_claim_refuses_a_counter_that_is_not_above_the_carried_one(monkeypatch, value):
    stub_risk(monkeypatch)
    store = LateLegacy(value)
    r = run(state_store=store, contracts=Contracts(on_check=lambda: setattr(store, "late", True)))
    assert r.allow is False and r.checks["replay"] == "fail"
    assert [x for x in r.reasons if x.startswith("replay")] == ["replay: %s is not greater than last seen %s (replay)" % (COUNTER, value)]
    assert store.last(SKEY) is None


def test_the_claim_goes_ahead_above_the_carried_counter_and_refuses_a_junk_one(monkeypatch):
    stub_risk(monkeypatch)
    store = LateLegacy(COUNTER - 1)
    r = run(state_store=store, contracts=Contracts(on_check=lambda: setattr(store, "late", True)))
    assert r.allow is True
    store = LateLegacy("bad")
    r = run(state_store=store, contracts=Contracts(on_check=lambda: setattr(store, "late", True)))
    assert r.allow is False
    assert [x for x in r.reasons if x.startswith("replay")] == ["replay: the replay store failed (fail closed)"]


class Scripted(Z.MemoryStateStore):
    def __init__(self, result):
        super().__init__()
        self.result, self.n = result, 0

    def claim_budget(self, key, counter, budget_before, budget_after):
        self.n += 1
        return self.result


def test_a_budget_conflict_is_retried_then_refused(monkeypatch):
    stub_risk(monkeypatch)
    want = "replay: concurrent state update for this holder kept conflicting (fail closed, retry the request)"
    for retries, calls in ((0, 1), (2, 3), (3, 4)):
        s = Scripted(Z.ClaimResult(False, None, "conflict"))
        r = run(state_store=s, claim_retries=retries)
        assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"replay": "fail"}, want)
        assert s.n == calls
    s = Scripted(Z.ClaimResult(False, None, "conflict"))
    assert run(state_store=s).reason == want and s.n == 4


@pytest.mark.parametrize("result, text", [
    ((False, 7), "%s is not greater than last seen 7 (replay)" % COUNTER),
    (Z.ClaimResult(False, 7, "replay"), "%s is not greater than last seen 7 (replay)" % COUNTER),
    ((False,), "%s was already claimed (replay)" % COUNTER),
    (Z.ClaimResult(False), "%s was already claimed (replay)" % COUNTER),
    (None, "the replay store failed (fail closed)"),
])
def test_a_refused_claim_reports_what_the_store_says(monkeypatch, result, text):
    stub_risk(monkeypatch)
    r = run(state_store=Scripted(result))
    assert r.allow is False and r.checks["replay"] == "fail"
    assert [x for x in r.reasons if x.startswith("replay")] == ["replay: " + text]


# ---- the escalation branch reads the head again -----------------------------------------------------------------------------------

class FlakyHead(Z.MemoryStateStore):
    """The first read fails; later reads report ``value`` for the audience key only."""

    def __init__(self, value):
        super().__init__()
        self.value, self.calls = value, 0

    def last(self, key):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("down")
        return self.value if key == SKEY else None


@pytest.mark.parametrize("value, replay", [(COUNTER, True), (COUNTER + 10, True), (COUNTER - 1, False)])
def test_a_replayed_counter_found_on_the_second_read_is_a_deny_not_an_escalation(monkeypatch, value, replay):
    inject_escalate(monkeypatch)
    stub_risk(monkeypatch)
    store = FlakyHead(value)
    store.put_budget(SKEY, dict(BUD))
    r = run(state_store=store)
    if replay:
        assert r.decision == "deny" and r.allow is False and r.escalation is None and r.checks["replay"] == "fail"
        assert "replay: %s is not greater than last seen %s (replay)" % (COUNTER, value) in r.reasons
    else:
        assert r.decision == "escalate" and r.escalation is not None
        assert not [x for x in r.reasons if "last seen" in x]


def test_a_head_that_cannot_be_read_does_not_bind_an_answer(monkeypatch):
    inject_escalate(monkeypatch)
    stub_risk(monkeypatch)

    class Unreadable(Z.MemoryStateStore):
        def last(self, key):
            raise RuntimeError("down")

    store = Unreadable()
    store.put_budget(SKEY, dict(BUD))  # the stored budget means the first read is not needed
    r = run(state_store=store, escalation_answer={"junk": 1}, escalation_principals=["pk"], insecure_unbound_approval=True)
    assert r.decision == "escalate"
    assert not [x for x in r.reasons if x.startswith("escalation:")]


# ---- contracts ---------------------------------------------------------------------------------------------------------------------

def test_the_contract_is_checked_and_advanced_with_the_operation(monkeypatch):
    stub_risk(monkeypatch)
    c = Contracts()
    r = run(contracts=c)
    act = {"action": {"verb": OP["verb"], "resource": OP["resource"], "params": OP["params"]}}
    assert r.allow is True
    assert c.peeks == [act] and c.checks == [(act, True)]


def test_a_contract_that_refuses_at_the_check_denies_before_the_claim(monkeypatch):
    stub_risk(monkeypatch)
    store = Z.MemoryStateStore()
    r = run(state_store=store, contracts=Contracts({"allow": False, "reason": "R1", "violated": ["a", "b"]}))
    assert r.allow is False and r.checks["contract"] == "fail"
    assert [x for x in r.reasons if x.startswith("contract")] == ["contract: R1 (a,b)"]
    assert store.last(SKEY) is None


def test_contract_action_projection():
    assert Z._contract_action({"verb": "v", "resource": "r", "params": {"a": 1}, "extra": 1}) == \
        {"action": {"verb": "v", "resource": "r", "params": {"a": 1}}}
    assert Z._contract_action("x") == {"action": {"verb": None, "resource": None, "params": None}}


def test_contract_refusal_text():
    assert Z._contract_refusal({"allow": True, "reason": "R"}) is None
    r = Z._contract_refusal({"allow": False, "reason": "R", "violated": ["a", "b"]})
    assert (r.allow, r.status, r.checks, r.reason, r.reasons) == (False, 403, {"contract": "fail"}, "contract: R (a,b)", ["contract: R (a,b)"])
    for c in ({"allow": False, "reason": "R"}, {"allow": False, "reason": "R", "violated": None}, {"allow": False, "reason": "R", "violated": []}):
        assert Z._contract_refusal(c).reason == "contract: R"
    assert Z._contract_refusal({"allow": False}).reason == "contract: None"


# ---- pins --------------------------------------------------------------------------------------------------------------------------

def _beacon_setup(monkeypatch, seq=3):
    inject(monkeypatch)
    monkeypatch.setattr(BC, "verify_liveness_beacon", lambda *a: {"ok": True})
    monkeypatch.setattr(BC, "beacon_ref", lambda b: "REF")
    p = copy.deepcopy(P0)
    p["freshness"] = {"beacon_ref": "REF"}
    return p, (lambda ref, pc: {"beacon": {"seq": seq}, "issuers": ["i1"], "instance": "inst"})


def test_a_passing_beacon_raises_its_pin(monkeypatch):
    p, hook = _beacon_setup(monkeypatch)
    store = Z.MemoryStateStore()
    r = run(pcactn=p, beacon=hook, state_store=store)
    assert r.allow is True and r.checks["beacon"] == "pass"
    assert store.pin("%s:beacon" % GID) == 3


def test_a_beacon_pin_that_cannot_be_stored_denies(monkeypatch):
    p, hook = _beacon_setup(monkeypatch)

    class NoPin(Z.MemoryStateStore):
        def raise_pin(self, key, value):
            raise RuntimeError("down")

    r = run(pcactn=p, beacon=hook, state_store=NoPin())
    assert r.allow is False and r.checks["beacon"] == "fail"
    assert [x for x in r.reasons if x.startswith("beacon")] == ["beacon: the beacon pin could not be stored (fail closed)"]
    assert "authorize" not in r.checks


def _epoch_setup(monkeypatch):
    inject(monkeypatch)
    monkeypatch.setattr(Z, "check_revocation_state", lambda *a, **k: {"ok": True, "epoch": {"epoch": 9}})
    return dict(revocation_staleness=RevocationStaleness(), context=lambda _p: {"revocation_state": {"k": 1}})


def test_an_accepted_epoch_raises_its_pin(monkeypatch):
    kw = _epoch_setup(monkeypatch)
    store = Z.MemoryStateStore()
    r = run(state_store=store, **kw)
    assert r.allow is True and r.checks["freshness"] == "pass"
    assert store.pin("%s:epoch" % GID) == 9


def test_an_epoch_pin_that_cannot_be_stored_denies(monkeypatch):
    kw = _epoch_setup(monkeypatch)

    class NoPin(Z.MemoryStateStore):
        def raise_pin(self, key, value):
            raise RuntimeError("down")

    r = run(state_store=NoPin(), **kw)
    assert r.allow is False and r.checks["freshness"] == "fail"
    assert [x for x in r.reasons if x.startswith("freshness")] == ["freshness: the revocation epoch pin could not be stored (fail closed)"]
    assert "authorize" not in r.checks


# ---- the passport gate -------------------------------------------------------------------------------------------------------------

LEAF = "leaf-holder"
PC = {"cap_chain": [{"holder": LEAF}]}


def _passport_spy(monkeypatch, ret=None):
    calls = []

    def fake(*a, **k):
        calls.append((a, k))
        return ret

    monkeypatch.setattr("atlas_pca.passport.verify_passport", fake)
    return calls


def test_the_passport_verifier_gets_every_configured_value(monkeypatch):
    calls = _passport_spy(monkeypatch, "unknown_issuer")
    rp = {"trusted_issuers": ["i1"], "now": lambda: 123, "clock_skew_ms": 5, "max_evidence_age_ms": 77, "revoked": "R",
          "pq_pins": {"pq": "x"}, "attest": "AT", "default_verifier": "DV"}
    r = Z._passport_refusal(PC, rp, {"p": 1}, None)
    assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"passport": "fail"}, "passport: unknown_issuer")
    assert calls == [(({"p": 1}, ["i1"], 123), {"clock_skew_ms": 5, "max_evidence_age_ms": 77, "subject": LEAF, "revoked": "R",
                                                "pq_pins": {"pq": "x"}, "attest": "AT", "default_verifier": "DV"})]


def test_the_passport_verifier_defaults(monkeypatch):
    monkeypatch.setattr(Z, "time", types.SimpleNamespace(time=lambda: 1234.5678))
    calls = _passport_spy(monkeypatch)
    for rp in ({}, {"trusted_issuers": None}, {"trusted_issuers": []}, {"now": 5}, {"now": "x"}):
        assert Z._passport_refusal(PC, rp, "P", None) is None
        assert calls[-1] == (("P", [], 1234567), {"clock_skew_ms": None, "max_evidence_age_ms": None, "subject": LEAF, "revoked": None,
                                                  "pq_pins": None, "attest": None, "default_verifier": None})


def test_a_pcactn_without_a_readable_leaf_is_left_to_the_guard(monkeypatch):
    _passport_spy(monkeypatch, "never asked")
    for pc in ({"cap_chain": []}, {"cap_chain": ["x"]}, {"cap_chain": "abc"}, {"cap_chain": {"a": 1}}, {}, {"cap_chain": [{"holder": 5}]},
               {"cap_chain": [{}]}, [], None):
        assert Z._passport_refusal(pc, {"trusted_issuers": ["i"]}, "P", None) is None


def test_hardware_rooting_is_refused_without_verified_evidence(monkeypatch):
    _passport_spy(monkeypatch)
    r = Z._passport_refusal(PC, {"trusted_issuers": ["i"], "hardware": True}, {"passport": {"hardware_rooted": False}}, None)
    assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"passport": "fail"}, "passport: hardware_evidence_missing")
    assert Z._passport_refusal(PC, {"trusted_issuers": ["i"], "hardware": True}, {"passport": {"hardware_rooted": True}}, None) is None


# ---- the forbid gate ---------------------------------------------------------------------------------------------------------------

FP = {"id": "p1", "kind": "permit", "signer": "user", "when": {"verb": OP["verb"]}}
FF = {"id": "f1", "kind": "forbid", "signer": "org", "when": {"verb": OP["verb"], "resource": OP["resource"]}}
FCTX = {"action": {"verb": OP["verb"], "resource": OP["resource"], "params": OP["params"]}}


def _forbid(f, certificate=None, operation=OP, resolve=lambda ref: G):
    return Z._forbid_refusal(P0, f, operation, resolve, certificate)


def test_a_forbid_refusal_is_a_403_on_the_forbid_check():
    r = _forbid({"clauses": lambda op, g: [FP, FF]})
    assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"forbid": "fail"}, "forbid: deny by forbid f1")
    r = _forbid({"clauses": lambda op, g: []})
    assert (r.status, r.checks, r.reason) == (403, {"forbid": "fail"}, "forbid: deny by none")
    assert _forbid({"clauses": lambda op, g: [FP]}) is None


def test_the_clause_and_context_sources_see_the_operation_and_the_grant_of_the_proof():
    refs, ctxs, clauses = [], [], []

    def resolve(ref):
        refs.append(ref)
        return G

    f = {"clauses": lambda op, g: clauses.append((op, g)) or [FP], "context": lambda op: ctxs.append(op) or {}}
    assert _forbid(f, resolve=resolve) is None
    assert refs == [P0["grant_ref"]] and ctxs == [OP] and clauses == [(OP, G)]


def test_a_grant_that_cannot_be_resolved_reaches_the_clause_source_as_none():
    seen = []

    def boom(ref):
        raise RuntimeError("down")

    assert _forbid({"clauses": lambda op, g: seen.append(g) or [FP]}, resolve=boom) is None
    r = Z._forbid_refusal("not json", {"clauses": lambda op, g: seen.append(g) or [FP]}, OP, lambda ref: G, None)
    assert r is None and seen == [None, None]


def test_an_operation_that_is_not_an_object_is_refused_not_raised():
    for bad in (None, "x", 5, ["verb"]):
        r = _forbid({"clauses": lambda op, g: [FP]}, operation=bad)
        assert r.status == 403 and r.checks == {"forbid": "fail"} and r.reason.startswith("forbid: deny by ")


def test_a_missing_certificate_is_a_403():
    r = _forbid({"clauses": lambda op, g: [FP], "require_certificate": True})
    assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"forbid": "fail"}, "forbid: the call carries no certificate (fail closed)")


def test_a_certificate_that_does_not_entail_its_decision_is_a_403():
    f = {"clauses": lambda op, g: [FP], "require_certificate": True}
    bad = dict(certify([FP], FCTX), decision="deny")
    r = _forbid(f, bad)
    assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"forbid": "fail"},
                                                        "forbid: certificate refused (certificate table does not entail its decision)")
    other = certify([FP, {"id": "p2", "kind": "permit", "when": {"verb": "other"}}], FCTX)
    r = _forbid(f, other)
    assert (r.status, r.checks, r.reason) == (403, {"forbid": "fail"},
                                              "forbid: certificate refused (certificate does not match the recomputed decision)")
    assert _forbid(f, certify([FP], FCTX)) is None


def test_the_certificate_is_checked_under_the_precedence_of_the_gate():
    f_user, f_org = dict(FF, id="a-user", signer="user"), dict(FF, id="z-org", signer="org")
    forged = certify([FP, f_user, f_org], FCTX, ["org", "user"])
    f = {"clauses": lambda op, g: [FP], "require_certificate": True, "precedence": ["org", "user"]}
    r = _forbid(f, forged)
    assert r.reason == "forbid: certificate refused (certificate does not match the recomputed decision)"


def test_the_certificate_is_checked_under_the_permit_signers_of_the_gate():
    p_org = dict(FP, id="p2", signer="org")
    clauses = [FP, p_org]
    f = {"clauses": lambda op, g: clauses, "require_certificate": True, "permit_signers": ["org"]}
    assert _forbid(f, certify(clauses, FCTX, None, ["org"])) is None
    r = _forbid(f, certify(clauses, FCTX))
    assert r.status == 403 and r.reason == "forbid: certificate refused (certificate does not match the recomputed decision)"


# ---- the template gate -------------------------------------------------------------------------------------------------------------

def test_the_template_gate_resolves_the_grant_of_the_proof_and_reads_its_envelope(monkeypatch):
    refs, envs = [], []
    monkeypatch.setattr(Z, "read_envelope", lambda g: envs.append(g) or {"template_ref": {"x": 1}})
    monkeypatch.setattr("atlas_pca.policy_link.verify_linked_policy", lambda env, reg: {"ok": True})
    assert Z._template_refusal(P0, "REG", lambda ref: refs.append(ref) or G) is None
    assert refs == [P0["grant_ref"]] and envs == [G]


def test_the_template_refusals_are_403s_on_the_template_check(monkeypatch):
    monkeypatch.setattr(Z, "read_envelope", lambda g: None)
    r = Z._template_refusal(P0, "REG", lambda ref: G)
    assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"template": "fail"}, "template: the grant has no readable envelope")
    monkeypatch.setattr(Z, "read_envelope", lambda g: {})
    r = Z._template_refusal(P0, "REG", lambda ref: G)
    assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"template": "fail"}, "template: the grant carries no template_ref")
    monkeypatch.setattr(Z, "read_envelope", lambda g: {"template_ref": {}})
    monkeypatch.setattr("atlas_pca.policy_link.verify_linked_policy", lambda env, reg: {"ok": False, "reason": "why"})
    r = Z._template_refusal(P0, "REG", lambda ref: G)
    assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"template": "fail"}, "template: why")


# ---- the conformance policy projection ---------------------------------------------------------------------------------------------

def _pd(monkeypatch):
    calls = []
    monkeypatch.setattr(Z, "evaluate_predicates", lambda preds, ctx: {"allowed": True})

    def ev(lst, c, actx, call):
        calls.append((lst, c, actx, call))
        return True, []

    monkeypatch.setattr(Z, "evaluate_agent_caveats", ev)
    return calls


EMPTY = {"allow": True, "reasons": [], "failed": {"envelope": [], "root": [], "delegated": []}}


def test_policy_decision_without_a_context_or_chain(monkeypatch):
    calls = _pd(monkeypatch)
    env = Z.read_envelope(G)
    assert Z.policy_decision(G, None, None) == EMPTY
    assert [c[0] for c in calls] == [env["caveats"], [x for x in Z.root_caveats(G) if not Z.is_k1_caveat(x)], []]
    for lst, c, actx, call in calls:
        assert c == {"now": None, "action": None} and actx == {"action": None} and call == {"tool": "", "args": {}}
    for ctx in ("junk", 5, ["action"]):
        assert Z.policy_decision(G, None, ctx) == EMPTY


def test_policy_decision_hands_the_context_to_the_caveat_evaluator(monkeypatch):
    calls = _pd(monkeypatch)
    ctx = {"now": 5, "action": "weird", "blast_radius": 2, "recent_action_times": [1], "reversibility_class": "reversible", "other": 1}
    assert Z.policy_decision(G, None, ctx) == EMPTY
    for lst, c, actx, call in calls:
        assert c == {"now": 5, "action": "weird", "blast_radius": 2, "recent_action_times": [1], "reversibility_class": "reversible"}
        assert actx == {"action": "weird"} and call == {"tool": "", "args": {}}


@pytest.mark.parametrize("action, call", [
    ({"verb": 5, "params": "p"}, {"tool": "", "args": {}}),
    ({"verb": "v", "params": "p"}, {"tool": "v", "args": {}}),
    ({"verb": 5, "params": {"a": 1}}, {"tool": "", "args": {"a": 1}}),
    ({"verb": "v", "params": {"a": 1}}, {"tool": "v", "args": {"a": 1}}),
    ({}, {"tool": "", "args": {}}),
    ("v", {"tool": "", "args": {}}),
    (None, {"tool": "", "args": {}}),
])
def test_policy_decision_tool_call_projection(monkeypatch, action, call):
    calls = _pd(monkeypatch)
    assert Z.policy_decision(G, None, {"action": action}) == EMPTY
    assert [c[3] for c in calls] == [call] * 3


def test_policy_decision_delegated_caveats_are_the_leaf_extras_without_k1(monkeypatch):
    calls = _pd(monkeypatch)
    k1 = {"type": K1_CAVEAT_TYPES[0]}
    leaf = list(G["caveats"]) + [{"type": "cx"}, k1]
    out = Z.policy_decision(G, [{"caveats": leaf}], {"now": 1})
    assert out == EMPTY
    assert calls[2][0] == [{"type": "cx"}]
    assert calls[2][1] == {"now": 1, "action": None, "delegation_depth": 0}
    out = Z.policy_decision(G, [{}, {"caveats": leaf}], {"now": 1})
    assert calls[5][0] == [{"type": "cx"}] and calls[5][1]["delegation_depth"] == 1


@pytest.mark.parametrize("chain", [["x"], [{}], [{"caveats": None}], [{"caveats": "junk"}], [None]])
def test_policy_decision_a_leaf_without_caveats_has_no_extras(monkeypatch, chain):
    calls = _pd(monkeypatch)
    assert Z.policy_decision(G, chain, {}) == EMPTY
    assert calls[2][0] == [] and calls[2][1]["delegation_depth"] == 0


def test_policy_decision_root_caveats_drop_k1_types(monkeypatch):
    calls = _pd(monkeypatch)
    g = copy.deepcopy(G)
    g["caveats"].append({"type": K1_CAVEAT_TYPES[0]})
    assert Z.policy_decision(g, [{"caveats": list(g["caveats"])}], {}) == EMPTY
    root = Z.root_caveats(g)
    want = [x for x in root if not Z.is_k1_caveat(x)]
    assert len(want) < len(root)
    assert calls[1][0] == want and calls[2][0] == []


# ---- AuthorizeOptions --------------------------------------------------------------------------------------------------------------

def test_multi_instance_refuses_only_a_process_scoped_store():
    base = dict(is_revoked=lambda a, b: False)
    with pytest.raises(ValueError) as e:
        Z.AuthorizeOptions(state_store=Z.MemoryStateStore(), multi_instance=True, **base)
    assert str(e.value) == "AuthorizeOptions: " + Z.MULTI_INSTANCE_ERROR

    class NoScope:
        pass

    class Shared:
        scope = "shared"

    Z.AuthorizeOptions(state_store=Z.MemoryStateStore(), multi_instance=False, **base)
    Z.AuthorizeOptions(state_store=Z.MemoryStateStore(), multi_instance=1, **base)
    Z.AuthorizeOptions(state_store=Z.MemoryStateStore(), **base)
    Z.AuthorizeOptions(state_store=NoScope(), multi_instance=True, **base)
    Z.AuthorizeOptions(state_store=Shared(), multi_instance=True, **base)
    Z.AuthorizeOptions(state_store=None, multi_instance=True, **base)


def test_revocation_staleness_needs_a_store_with_both_pins():
    class OnlyPin:
        def pin(self, key):
            return None

    class OnlyRaise:
        def raise_pin(self, key, value):
            return None

    class Neither:
        pass

    rs = RevocationStaleness()
    for store in (OnlyPin(), OnlyRaise(), Neither()):
        with pytest.raises(ValueError) as e:
            Z.AuthorizeOptions(state_store=store, revocation_staleness=rs)
        assert str(e.value) == "AuthorizeOptions: " + Z.PIN_STORE_ERROR
    Z.AuthorizeOptions(state_store=Z.MemoryStateStore(), revocation_staleness=rs)
    Z.AuthorizeOptions(state_store=None, revocation_staleness=rs)
    Z.AuthorizeOptions(state_store=Neither())


def test_options_run_forwards_every_configured_value(monkeypatch):
    got = []
    monkeypatch.setattr(Z, "authorize", lambda pc, **k: got.append(k) or "R")
    s = {n: object() for n in ("resolve_principal", "require_passport", "require_linked_template", "require_risk_inputs", "threshold",
                               "seed_budget", "enforce_freshness", "enforce_taint", "beacon", "adaptive_policy", "contracts", "forbid", "risk")}
    s.update(pq_pins={"issuer": "key"}, claim_retries=9, multi_instance=False, require_verified_principal=True)
    o = Z.AuthorizeOptions(state_store=Z.MemoryStateStore(), is_revoked=lambda a, b: False, **s)
    passport, cert = object(), object()
    assert o.run(object(), operation={}, audience="A", resolve_grant=None, passport=passport, forbid_certificate=cert) == "R"
    for name, value in s.items():
        assert got[0][name] is value, name
    assert got[0]["passport"] is passport and got[0]["forbid_certificate"] is cert
