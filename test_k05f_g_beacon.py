"""Dead-man liveness beacons (reference beacons.ts) and the authorize `beacon` check."""
import copy
import json

import pytest
from prov_harness import prov

import atlas_pca.pca as PCA
from atlas_pca import MemoryStateStore, authorize
from atlas_pca import beacon as B
from atlas_pca.agent import generate_keypair
from test_revocation_staleness import FIX, _case

NOW = FIX["now"]


def mk(seq=1, issuer=None, instance="inst", scope=None, at=None):
    k = issuer or generate_keypair()
    b = B.issue_liveness_beacon(k, instance, seq, NOW - 1000 if at is None else at, scope or B.GLOBAL_SCOPE)
    return k, b


def test_verify_accepts_and_rejects():
    k, b = mk()
    assert B.verify_liveness_beacon(b, [k.public], NOW, "inst")["ok"] is True
    assert B.verify_liveness_beacon(b, [generate_keypair().public], NOW, "inst")["ok"] is False
    assert B.verify_liveness_beacon(b, [k.public], NOW, "other")["ok"] is False
    assert B.verify_liveness_beacon(b, [k.public], b["not_after"] + 1, "inst")["ok"] is False
    t = copy.deepcopy(b)
    t["seq"] = 2
    assert B.verify_liveness_beacon(t, [k.public], NOW, "inst")["ok"] is False


def test_ref_is_stable_and_binding():
    _k, b = mk()
    assert B.beacon_ref(b) == B.beacon_ref(copy.deepcopy(b))
    t = copy.deepcopy(b)
    t["seq"] = 9
    assert B.beacon_ref(t) != B.beacon_ref(b)


def test_decision_table():
    assert B.beacon_decision(False, False, False, False) == "not-enforced"
    assert B.beacon_decision(True, False, False, False) == "rejected"
    assert B.beacon_decision(True, True, True, False) == "replayed"
    assert B.beacon_decision(True, True, False, False) == "unbound"
    assert B.beacon_decision(True, True, False, True) == "pass"


def run(monkeypatch, store, hook, bind=None):
    c = _case()
    s = c["steps"][0]
    p = json.loads(json.dumps(s["pcactn"]))
    if bind is not None:
        p["freshness"]["beacon_ref"] = bind
    monkeypatch.setattr(PCA, "_verify_suite", lambda *a, **k: True)
    r = authorize(p, operation=s["operation"], audience=FIX["audience"], resolve_grant=lambda ref: c["grant"], state_store=store,
                  is_revoked=lambda pp, g: False, now=NOW, plan="single-step", beacon=hook, **prov(s["operation"]))
    return r, c["grant"]["id"]


def hook_for(b, issuers, **kw):
    return lambda ref, p: dict(beacon=b, issuers=issuers, instance="inst", **kw)


def test_authorize_beacon_paths(monkeypatch):
    c = _case()
    gid = c["grant"]["id"]
    k, b = mk(seq=5, scope=gid)
    store = MemoryStateStore()
    r, _ = run(monkeypatch, store, hook_for(b, [k.public]), bind=B.beacon_ref(b))
    assert r.checks.get("beacon") == "pass", r.reasons
    assert store.pin("%s:beacon" % gid) == 5
    # replay: an older beacon than the pin
    _k2, old = mk(seq=3, issuer=k, scope=gid)
    r, _ = run(monkeypatch, store, hook_for(old, [k.public]), bind=B.beacon_ref(old))
    assert r.allow is False and r.checks["beacon"] == "fail"
    assert any("older than the last accepted 5 (replay)" in x for x in r.reasons)
    # unbound
    _k3, n = mk(seq=6, issuer=k, scope=gid)
    r, _ = run(monkeypatch, store, hook_for(n, [k.public]), bind="x")
    assert r.checks["beacon"] == "fail" and any("does not bind the presented beacon" in x for x in r.reasons)
    assert store.pin("%s:beacon" % gid) == 5
    # absent beacon freezes
    r, _ = run(monkeypatch, store, lambda ref, p: None)
    assert r.allow is False and r.checks["beacon"] != "pass"
    # untrusted issuer
    r, _ = run(monkeypatch, store, hook_for(n, [generate_keypair().public]), bind=B.beacon_ref(n))
    assert r.allow is False and r.checks["beacon"] == "fail"


def adaptive_run(monkeypatch, adp):
    c = _case()
    s = c["steps"][0]
    p = json.loads(json.dumps(s["pcactn"]))
    p["caution"] = 0.5  # a signed risk floor (the signature check is stubbed): r = 0.5 under the grant's own thresholds
    monkeypatch.setattr(PCA, "_verify_suite", lambda *a, **k: True)
    return authorize(p, operation=s["operation"], audience=FIX["audience"], resolve_grant=lambda ref: c["grant"], state_store=MemoryStateStore(),
                     is_revoked=lambda pp, g: False, now=NOW, plan="single-step", adaptive_policy=adp, **prov(s["operation"]))


def test_adaptive_policy_only_narrows(monkeypatch):
    from atlas_pca.risk import DEFAULT_RISK_POLICY as P
    assert not any("adaptive" in x for x in adaptive_run(monkeypatch, lambda now: None).reasons)
    assert not any("adaptive" in x for x in adaptive_run(monkeypatch, lambda now: dict(P, theta1=0.9, theta2=0.95)).reasons)
    r = adaptive_run(monkeypatch, lambda now: dict(P, kappa=0))
    assert r.allow is False and r.checks["adaptive"] == "fail" and any("adaptive: invalid policy (risk_policy.kappa must be > 0)" in x for x in r.reasons)
    r = adaptive_run(monkeypatch, lambda now: dict(P, theta1=0.1, theta2=0.2))
    assert r.allow is False and r.checks["adaptive"] == "fail"
    assert any("adaptive: tightened policy requires threshold t=" in x for x in r.reasons)


def test_contracts_option_peeks_then_advances(monkeypatch):
    from test_k05g_contracts import PRIN, SC
    from atlas_pca.contract_enforcer import ContractEnforcer
    from atlas_pca.atomic_kv import MemoryAtomicKv
    c = _case()
    s = c["steps"][0]
    monkeypatch.setattr(PCA, "_verify_suite", lambda *a, **k: True)

    def go(clauses_contract, kv):
        e = ContractEnforcer.open(kv, clauses_contract, PRIN, now=lambda: 1_700_000_000_000)
        p = json.loads(json.dumps(s["pcactn"]))
        return authorize(p, operation=s["operation"], audience=FIX["audience"], resolve_grant=lambda ref: c["grant"], state_store=MemoryStateStore(),
                         is_revoked=lambda pp, g: False, now=NOW, plan="single-step", contracts=e, **prov(s["operation"])), e

    verb = s["operation"]["verb"]
    from test_k05g_contracts import SEED
    from atlas_pca.contracts import CONTRACT_VERSION, sign_contract
    bad = sign_contract({"version": CONTRACT_VERSION, "principal": PRIN, "clauses": [{"id": "no-it", "kind": "never", "p": {"verb": verb}}]}, SEED)
    r, _e = go(bad, MemoryAtomicKv())
    assert r.allow is False and r.checks["contract"] == "fail" and r.reason.startswith("contract: ") and "(no-it)" in r.reason
    ok = sign_contract({"version": CONTRACT_VERSION, "principal": PRIN, "clauses": [{"id": "no-del", "kind": "never", "p": {"verb": "zzz-other"}}]}, SEED)
    kv = MemoryAtomicKv()
    r, e = go(ok, kv)
    assert r.allow is True and e.state()["state"]["seq"] == 1
