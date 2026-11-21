"""Mutation kill for the middle of the authorize pipeline: the options forwarded to the core, principal resolution, the revocation
epoch pin, the liveness beacon, the server risk inputs, the trust budget (context / stored / carried-over / seeded) and the
blast-radius hand-off. Expected strings and merge rules are the TypeScript reference's (require-pca.ts, risk.ts, beacons.ts)."""
import copy
import importlib
import json
import math
import os

import pytest

import atlas_pca.beacon as BC
from atlas_pca.pca import Verdict
from atlas_pca.revocation_staleness import RevocationStaleness
from prov_harness import CALM_RISK, calm_risk, prov

Z = importlib.import_module("atlas_pca.authorize")

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as _f:
    FIX = json.load(_f)
NOW, AUD = FIX["now"], FIX["audience"]
CASE = next(c for c in FIX["cases"] if c["name"] == "envelope-max-spend-within")
P0, OP, G = CASE["steps"][0]["pcactn"], CASE["steps"][0]["operation"], CASE["grant"]
HOLDER = P0["cap_chain"][-1]["holder"]
GID = G["id"]


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
    """The core accepts whatever PCActn is presented, to reach the stages behind it."""
    base = Z.verify_pcactn_core(copy.deepcopy(P0), G, now=NOW, audience=AUD, insecure_skip_plan_root_check=True)
    v = Verdict(True, dict(base.checks), None, [])
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: v)
    return v


def spy_on(monkeypatch, name, ret=None):
    calls = []
    real = getattr(Z, name)

    def f(*a, **k):
        calls.append((a, k))
        return real(*a, **k) if ret is None else ret

    monkeypatch.setattr(Z, name, f)
    return calls


# ---- the options forwarded to the core ------------------------------------------------------------------------------------------

def test_the_core_receives_the_freshness_and_taint_options(monkeypatch):
    base = Z.verify_pcactn_core(copy.deepcopy(P0), G, now=NOW, audience=AUD, insecure_skip_plan_root_check=True)
    v = Verdict(True, dict(base.checks), None, [])
    seen = []
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: seen.append(k) or v)
    fresh, taint = {"f": 1}, {"t": 2}
    run(enforce_freshness=fresh, enforce_taint=taint)
    assert seen[0]["enforce_freshness"] is fresh
    assert seen[0]["enforce_taint"] is taint


# ---- principal resolution -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("resolved", [["x"], "x", 5])
def test_a_truthy_non_mapping_resolution_is_an_unverified_principal(monkeypatch, resolved):
    inject(monkeypatch)
    r = run(resolve_principal=lambda pub, grant: resolved, require_verified_principal=True)
    assert "authorize" not in r.checks
    assert r.checks["principal"] == "fail"
    assert "principal: the grant issuer is not an enrolled, verified principal" in r.reasons
    r = run(resolve_principal=lambda pub, grant: resolved)
    assert "authorize" not in r.checks
    assert r.checks["principal"] == "not-enforced"


# ---- the revocation epoch pin ---------------------------------------------------------------------------------------------------

def _epoch_run(monkeypatch, state, store):
    inject(monkeypatch)
    calls = spy_on(monkeypatch, "check_revocation_state", {"ok": True, "epoch": 9})
    r = run(state_store=store, revocation_staleness=RevocationStaleness(), context=lambda _p: {"revocation_state": state})
    assert "authorize" not in r.checks
    return calls[-1][0][1], r


@pytest.mark.parametrize("state", [{"kind": "other"}, {"kind": "other", "last_accepted_epoch": 1}, {}, "junk", ["epoch"]])
def test_only_an_epoch_state_takes_the_stored_pin(monkeypatch, state):
    store = Z.MemoryStateStore()
    store.raise_pin("%s:epoch" % GID, 5)
    seen, _ = _epoch_run(monkeypatch, state, store)
    assert seen is state


def test_an_epoch_state_at_or_above_the_stored_pin_is_untouched(monkeypatch):
    for host_last in (5, 9):
        store = Z.MemoryStateStore()
        store.raise_pin("%s:epoch" % GID, 5)
        state = {"kind": "epoch", "last_accepted_epoch": host_last}
        seen, _ = _epoch_run(monkeypatch, state, store)
        assert seen is state


@pytest.mark.parametrize("extra", [{"last_accepted_epoch": 2}, {"last_accepted_epoch": None}, {"last_accepted_epoch": "5"}, {}])
def test_an_epoch_state_below_the_stored_pin_is_raised_to_it_keeping_its_other_fields(monkeypatch, extra):
    store = Z.MemoryStateStore()
    store.raise_pin("%s:epoch" % GID, 5)
    state = dict({"kind": "epoch", "proof": "p1"}, **extra)
    seen, _ = _epoch_run(monkeypatch, state, store)
    assert seen == {"kind": "epoch", "proof": "p1", "last_accepted_epoch": 5}
    assert seen is not state


def test_an_epoch_state_without_a_stored_pin_is_untouched(monkeypatch):
    state = {"kind": "epoch", "last_accepted_epoch": 2}
    seen, _ = _epoch_run(monkeypatch, state, Z.MemoryStateStore())
    assert seen is state


def test_an_unreadable_pin_denies_with_its_reason_and_never_asks_the_policy(monkeypatch):
    class BadPin(Z.MemoryStateStore):
        def pin(self, key):
            raise RuntimeError("down")

    inject(monkeypatch)
    calls = spy_on(monkeypatch, "check_revocation_state", {"ok": True, "epoch": 9})
    r = run(state_store=BadPin(), revocation_staleness=RevocationStaleness(),
            context=lambda _p: {"revocation_state": {"kind": "epoch", "last_accepted_epoch": 7}})
    assert calls == []
    assert "authorize" not in r.checks
    assert r.checks["freshness"] == "fail"
    assert "freshness: the revocation epoch pin could not be read (fail closed)" in r.reasons
    assert r.allow is False


# ---- the liveness beacon --------------------------------------------------------------------------------------------------------

def _beacon_run(monkeypatch, hook, *, store=None, ok=True, reason=None, freshness="REFERENCE", pcactn=None, grant=None):
    inject(monkeypatch)
    verified = []

    def fake_verify(*a):
        verified.append(a)
        out = {"ok": ok}
        if reason is not None:
            out["reason"] = reason
        return out

    monkeypatch.setattr(BC, "verify_liveness_beacon", fake_verify)
    monkeypatch.setattr(BC, "beacon_ref", lambda b: "REF")
    p = copy.deepcopy(P0) if pcactn is None else pcactn
    if freshness == "REFERENCE":
        p["freshness"] = {"beacon_ref": "REF"}
    elif freshness == "ABSENT":
        p.pop("freshness", None)
    else:
        p["freshness"] = freshness
    r = run(pcactn=p, beacon=hook, state_store=store if store is not None else Z.MemoryStateStore(), grant=grant)
    return r, verified, p


def _hook(seq=3, **kw):
    return lambda ref, p: dict({"beacon": {"seq": seq}, "issuers": ["i1"], "instance": "inst"}, **kw)


BIND = "beacon: PCActn freshness.beacon_ref does not bind the presented beacon"


def test_the_beacon_hook_receives_the_grant_ref_and_the_presented_pcactn(monkeypatch):
    seen = []
    p = copy.deepcopy(P0)

    def hook(ref, pc):
        seen.append((ref, pc))
        return None

    _beacon_run(monkeypatch, hook, pcactn=p)
    assert len(seen) == 1
    assert seen[0][0] == P0["grant_ref"]
    assert seen[0][1] is p


def test_the_beacon_is_verified_with_its_issuers_instance_scope_and_pins(monkeypatch):
    pins = {"x": "y"}
    b = {"seq": 3}
    _, verified, _ = _beacon_run(monkeypatch, lambda ref, p: {"beacon": b, "issuers": ["i1"], "instance": "inst", "pq_pins": pins})
    assert verified == [(b, ["i1"], NOW, "inst", GID, pins)]
    for issuers in (None, [], "ABSENT"):
        hook = (lambda ref, p: {"beacon": b}) if issuers == "ABSENT" else (lambda ref, p: {"beacon": b, "issuers": issuers})
        _, verified, _ = _beacon_run(monkeypatch, hook)
        assert verified == [(b, [], NOW, None, GID, None)]


@pytest.mark.parametrize("hook_result", [None, {}, {"beacon": None, "issuers": ["i1"]}, "text", 5, ["beacon"]])
def test_an_absent_or_malformed_beacon_answer_is_not_enforced(monkeypatch, hook_result):
    # the inner decision is not-enforced; a configured beacon is a REQUIRED check, so the verdict is the default-deny fail (as in the reference)
    r, verified, _ = _beacon_run(monkeypatch, lambda ref, p: hook_result)
    assert "authorize" not in r.checks
    assert r.allow is False and r.checks["beacon"] == "fail"
    assert verified == []
    assert [x for x in r.reasons if x.startswith("beacon")] == [
        "beacon: required check is not-enforced (default-deny: not enforced by this resource server)"]


@pytest.mark.parametrize("pin, host, seq, last", [
    (5, None, 3, 5), (None, 7, 3, 7), (5, 9, 3, 9), (9, 5, 3, 9), (5, 7, 6, 7), (5, "7", 4, 5), (5, 5.5, 4, 5),
])
def test_an_older_beacon_than_the_last_accepted_is_a_replay(monkeypatch, pin, host, seq, last):
    store = Z.MemoryStateStore()
    if pin is not None:
        store.raise_pin("%s:beacon" % GID, pin)
    extra = {} if host is None else {"last_accepted_seq": host}
    r, _, _ = _beacon_run(monkeypatch, _hook(seq, **extra), store=store)
    assert "authorize" not in r.checks
    assert r.checks["beacon"] == "fail"
    assert "beacon: beacon seq %s is older than the last accepted %s (replay)" % (seq, last) in r.reasons
    assert BIND not in r.reasons


@pytest.mark.parametrize("pin, host, seq", [(5, None, 5), (5, None, 6), (None, None, 0), (None, "7", 3), (None, 7.5, 3), (5, 2, 5), (5, 5, 5)])
def test_a_beacon_at_or_above_the_last_accepted_passes_when_bound(monkeypatch, pin, host, seq):
    store = Z.MemoryStateStore()
    if pin is not None:
        store.raise_pin("%s:beacon" % GID, pin)
    extra = {} if host is None else {"last_accepted_seq": host}
    r, _, _ = _beacon_run(monkeypatch, _hook(seq, **extra), store=store)
    assert "authorize" not in r.checks
    assert r.checks["beacon"] == "pass"
    assert not any(x.startswith("beacon") for x in r.reasons)


def test_the_host_supplied_last_accepted_seq_alone_is_enforced(monkeypatch):
    r, _, _ = _beacon_run(monkeypatch, _hook(2, last_accepted_seq=3))
    assert r.checks["beacon"] == "fail"
    assert "beacon: beacon seq 2 is older than the last accepted 3 (replay)" in r.reasons
    r, _, _ = _beacon_run(monkeypatch, _hook(3, last_accepted_seq=3))
    assert r.checks["beacon"] == "pass"


@pytest.mark.parametrize("reason, text", [("bad signature", "beacon: bad signature"), (None, "beacon: beacon rejected"),
                                          ("", "beacon: beacon rejected")])
def test_a_beacon_that_does_not_verify_is_rejected_with_its_reason(monkeypatch, reason, text):
    store = Z.MemoryStateStore()
    store.raise_pin("%s:beacon" % GID, 5)
    r, _, _ = _beacon_run(monkeypatch, _hook(3), store=store, ok=False, reason=reason)
    assert "authorize" not in r.checks
    assert r.checks["beacon"] == "fail"
    assert text in r.reasons
    assert not any(x.startswith("beacon: beacon seq") for x in r.reasons)
    assert BIND not in r.reasons


@pytest.mark.parametrize("freshness", [{"beacon_ref": "OTHER"}, {}, "junk", None, ["beacon_ref"], "ABSENT"])
def test_a_beacon_the_pcactn_does_not_bind_is_unbound(monkeypatch, freshness):
    r, _, _ = _beacon_run(monkeypatch, _hook(3), freshness=freshness)
    assert "authorize" not in r.checks
    assert r.checks["beacon"] == "fail"
    assert BIND in r.reasons


def test_a_grant_without_an_id_has_no_stored_beacon_pin(monkeypatch):
    grant = {k: v for k, v in G.items() if k != "id"}
    r, verified, _ = _beacon_run(monkeypatch, _hook(3), ok=False, reason="bad signature", grant=grant)
    assert "authorize" not in r.checks
    assert r.checks["beacon"] == "fail"
    assert "beacon: bad signature" in r.reasons
    assert verified == [({"seq": 3}, ["i1"], NOW, "inst", None, None)]


# ---- the server risk inputs -----------------------------------------------------------------------------------------------------

def test_host_risk_inputs_merge_with_the_context_keeping_the_riskier_value(monkeypatch):
    inject(monkeypatch)
    calls = spy_on(monkeypatch, "decide_risk")
    seen = []
    p = copy.deepcopy(P0)

    def hook(op, grant, pc):
        seen.append((op, grant, pc))
        return {"taint": 0.2, "semanticDistance": 0.3, "age": 0, "reversibility": 1}

    run(pcactn=p, risk=hook, context=lambda _p: {"risk": {"taint": 0.5, "semanticDistance": 0.1}})
    assert len(seen) == 1
    assert seen[0][0] == {"verb": OP["verb"], "resource": OP["resource"], "params": OP["params"]}
    assert seen[0][1] is G
    assert seen[0][2] is p
    assert calls[0][0][1] == {"taint": 0.5, "semanticDistance": 0.3, "age": 0, "reversibility": 1}


def test_a_context_risk_that_is_not_a_mapping_is_ignored(monkeypatch):
    inject(monkeypatch)
    calls = spy_on(monkeypatch, "decide_risk")
    r = run(context=lambda _p: {"risk": "junk"})
    assert "authorize" not in r.checks
    assert calls[0][0][1] == CALM_RISK
    r = run(risk=None, context=lambda _p: {"risk": ["junk"]}, require_risk_inputs=["taint"])
    assert "authorize" not in r.checks
    assert r.checks["risk_inputs"] == "fail"


# ---- the trust budget -----------------------------------------------------------------------------------------------------------

SEED = {"B": 1000, "tau": NOW, "asOf": NOW}
NO_BUDGET = ("budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must "
             "step-up / recharge")


def _budget_of(monkeypatch, **kw):
    inject(monkeypatch)
    calls = spy_on(monkeypatch, "decide_risk")
    r = run(**kw)
    assert "authorize" not in r.checks
    return calls[0][0][2], r


def test_the_default_seed_is_the_signed_bmax_stamped_now(monkeypatch):
    b, r = _budget_of(monkeypatch)
    assert b == SEED
    assert r.checks["budget"] == "pass"
    assert NO_BUDGET not in r.reasons


def test_a_grant_without_an_envelope_has_no_default_seed(monkeypatch):
    inject(monkeypatch)
    r = run(grant={"id": GID})
    assert "authorize" not in r.checks
    assert r.checks["budget"] == "not-enforced"
    assert NO_BUDGET in r.reasons


def test_no_seed_means_no_budget_and_the_worst_case_is_used(monkeypatch):
    b, r = _budget_of(monkeypatch, seed_budget=None)
    assert b == {"B": 0, "tau": NOW, "asOf": NOW}
    assert r.checks["budget"] == "not-enforced"
    assert NO_BUDGET in r.reasons


def test_a_seed_callable_gets_the_grant_and_now(monkeypatch):
    seen = []
    sb = {"B": 3, "tau": NOW, "asOf": NOW}
    b, r = _budget_of(monkeypatch, seed_budget=lambda g, n: seen.append((g, n)) or sb)
    assert seen == [(G, NOW)]
    assert seen[0][0] is G
    assert b == sb
    assert r.checks["budget"] == "pass"
    assert NO_BUDGET not in r.reasons


def test_a_seed_callable_is_not_asked_when_a_budget_exists(monkeypatch):
    seen = []
    cb = {"B": 5, "tau": NOW, "asOf": NOW}
    b, _ = _budget_of(monkeypatch, seed_budget=lambda g, n: seen.append(1) or {"B": 1}, context=lambda _p: {"budget": cb})
    assert seen == [] and b == cb


def test_the_context_budget_wins_over_the_stored_one(monkeypatch):
    cb = {"B": 5, "tau": NOW, "asOf": NOW}
    store = Z.MemoryStateStore()
    store.put_budget(Z.state_key(GID, HOLDER, AUD), {"B": 9, "tau": NOW, "asOf": NOW})
    b, r = _budget_of(monkeypatch, state_store=store, seed_budget=None, context=lambda _p: {"budget": cb})
    assert b == cb
    assert r.checks["budget"] == "pass"


def test_the_stored_budget_is_used_when_the_context_has_none(monkeypatch):
    sb = {"B": 9, "tau": NOW, "asOf": NOW}
    for ctx in ({}, {"budget": "junk"}, {"budget": None}):
        store = Z.MemoryStateStore()
        store.put_budget(Z.state_key(GID, HOLDER, AUD), sb)
        b, r = _budget_of(monkeypatch, state_store=store, seed_budget=None, context=lambda _p, c=ctx: c)
        assert b == sb
        assert r.checks["budget"] == "pass"


def test_a_non_mapping_context_budget_falls_back_to_the_seed(monkeypatch):
    b, _ = _budget_of(monkeypatch, context=lambda _p: {"budget": "junk"})
    assert b == SEED


def test_a_budget_under_the_legacy_key_is_carried_over_when_the_audience_key_has_no_state(monkeypatch):
    legacy = {"B": 7, "tau": NOW, "asOf": NOW}
    store = Z.MemoryStateStore()
    store.put_budget(Z.state_key(GID, HOLDER), legacy)
    b, r = _budget_of(monkeypatch, state_store=store, seed_budget=None)
    assert b == legacy
    assert r.checks["budget"] == "pass"


def test_a_legacy_budget_is_not_carried_once_the_audience_key_has_a_counter(monkeypatch):
    store = Z.MemoryStateStore()
    store.put_budget(Z.state_key(GID, HOLDER), {"B": 7, "tau": NOW, "asOf": NOW})
    store.claim(Z.state_key(GID, HOLDER, AUD), 1)
    b, r = _budget_of(monkeypatch, state_store=store, seed_budget=None)
    assert b == {"B": 0, "tau": NOW, "asOf": NOW}
    assert r.checks["budget"] == "not-enforced"


def test_only_the_exact_legacy_key_is_read_for_the_carry_over(monkeypatch):
    store = Z.MemoryStateStore()
    store.put_budget(Z.state_key(GID, "other-holder"), {"B": 7, "tau": NOW, "asOf": NOW})
    store.put_budget(Z.state_key("other-grant", HOLDER), {"B": 7, "tau": NOW, "asOf": NOW})
    store.put_budget("None:%s" % HOLDER, {"B": 7, "tau": NOW, "asOf": NOW})
    store.put_budget("%s:None" % GID, {"B": 7, "tau": NOW, "asOf": NOW})
    _, r = _budget_of(monkeypatch, state_store=store, seed_budget=None)
    assert r.checks["budget"] == "not-enforced"


class RecordingStore(Z.MemoryStateStore):
    def __init__(self):
        super().__init__()
        self.claims = []

    def claim_budget(self, key, counter, budget_before, budget_after):
        self.claims.append((key, counter, budget_before, budget_after))
        return super().claim_budget(key, counter, budget_before, budget_after)


def test_the_claim_compares_against_no_budget_for_a_carried_over_legacy_one():
    store = RecordingStore()
    store.put_budget(Z.state_key(GID, HOLDER), dict(SEED))
    run(state_store=store)
    assert store.claims[0][0] == Z.state_key(GID, HOLDER, AUD)
    assert store.claims[0][2] is None


def test_the_claim_compares_against_the_budget_stored_under_the_audience_key():
    store = RecordingStore()
    store.put_budget(Z.state_key(GID, HOLDER, AUD), dict(SEED))
    run(state_store=store)
    assert store.claims[0][2] == SEED


# ---- required risk inputs -------------------------------------------------------------------------------------------------------

def _inputs(monkeypatch, ctx_risk, required, **kw):
    inject(monkeypatch)
    r = run(risk=None, context=lambda _p: {"risk": ctx_risk}, require_risk_inputs=required, **kw)
    assert "authorize" not in r.checks
    return r


ALL_INPUTS = ["semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"]


def test_supplied_finite_inputs_pass(monkeypatch):
    r = _inputs(monkeypatch, dict(CALM_RISK), ALL_INPUTS)
    assert r.checks["risk_inputs"] == "pass"
    assert not any(x.startswith("risk_inputs") for x in r.reasons)
    r = _inputs(monkeypatch, {"taint": 1, "age": 0.0}, ["taint", "age"])
    assert r.checks["risk_inputs"] == "pass"


def test_missing_bool_text_and_non_finite_inputs_are_named_in_order(monkeypatch):
    ctx = {"taint": True, "age": "x", "confidence": math.nan, "reversibility": math.inf, "semanticDistance": 0.2}
    r = _inputs(monkeypatch, ctx, ["taint", "age", "confidence", "reversibility", "blastRadius", "semanticDistance"])
    assert r.checks["risk_inputs"] == "fail"
    assert "risk_inputs: required risk input(s) not supplied by the server: taint, age, confidence, reversibility, blastRadius" \
        in r.reasons
    r = _inputs(monkeypatch, {"taint": -math.inf}, ["taint"])
    assert r.checks["risk_inputs"] == "fail"
    assert "risk_inputs: required risk input(s) not supplied by the server: taint" in r.reasons


def test_an_empty_requirement_is_not_a_check(monkeypatch):
    r = _inputs(monkeypatch, {}, [])
    assert "risk_inputs" not in r.checks


def test_the_plan_geodesic_stands_in_for_semantic_distance_only(monkeypatch):
    r = _inputs(monkeypatch, {}, ["semanticDistance"])
    assert r.checks["risk_inputs"] == "pass"
    r = _inputs(monkeypatch, {}, ["semanticDistance"], plan=None)
    assert r.checks["risk_inputs"] == "fail"
    assert "risk_inputs: required risk input(s) not supplied by the server: semanticDistance" in r.reasons
    r = _inputs(monkeypatch, {}, ["blastRadius"])
    assert r.checks["risk_inputs"] == "fail"
    assert "risk_inputs: required risk input(s) not supplied by the server: blastRadius" in r.reasons
    r = _inputs(monkeypatch, {}, ["blastRadius", "semanticDistance", "taint"])
    assert "risk_inputs: required risk input(s) not supplied by the server: blastRadius, taint" in r.reasons


# ---- the blast radius handed to the caveats -------------------------------------------------------------------------------------

def _cctx(monkeypatch, ctx, risk):
    inject(monkeypatch)
    calls = spy_on(monkeypatch, "evaluate_agent_caveats")
    r = run(context=lambda _p: ctx, risk=risk)
    assert "authorize" not in r.checks
    return calls[0][0][1]


def test_the_context_blast_radius_wins_over_the_risk_input(monkeypatch):
    assert _cctx(monkeypatch, {"blast_radius": 0.4}, lambda o, g, p: {"blastRadius": 0.9})["blast_radius"] == 0.4
    assert _cctx(monkeypatch, {"blast_radius": 0.4}, None)["blast_radius"] == 0.4


def test_the_risk_input_blast_radius_is_used_when_the_context_has_none(monkeypatch):
    assert _cctx(monkeypatch, {}, lambda o, g, p: {"blastRadius": 0.7})["blast_radius"] == 0.7
    assert _cctx(monkeypatch, {}, lambda o, g, p: {"blastRadius": 0})["blast_radius"] == 0


def test_no_blast_radius_anywhere_leaves_the_key_out(monkeypatch):
    assert "blast_radius" not in _cctx(monkeypatch, {}, lambda o, g, p: {"taint": 0})
    assert "blast_radius" not in _cctx(monkeypatch, {}, None)
