"""Pipeline and grants parity (the TypeScript reference: pcactn.ts:549-555 and 835-841, server/verify.ts:531, capability.ts:174-193,
require-pca.ts:292, pca-grants/src/blueprint.ts:202-205, pca-need.ts:69, a2a-auth.ts:273-278, pca-store-conformance retry-after-timeout)."""
import sys
import threading
import time

import pytest

from atlas_pca import a2a as N
from atlas_pca import blueprint as B
from atlas_pca import break_glass as BG
from atlas_pca import lease as L
from atlas_pca import require_pca
from atlas_pca.agent import DEFAULT_RISK_POLICY, Agent, _sign_body, delegate, generate_keypair, mint_grant
from atlas_pca.pca import (BOND_UNSUPPORTED, allocations_monotone, b64u, canonical_bytes_strict, threshold_message,
                           verify_chain, verify_pcactn_core)
from test_k05_kill_authz import Z as AZ, run as authorize_fixture

ENV = {"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "agent_binding": {}, "risk_policy": DEFAULT_RISK_POLICY}


class _World:
    def __init__(self):
        self.principal, self.agent = generate_keypair(), generate_keypair()
        self.grant = mint_grant(self.principal, self.agent.public, ENV, "refund an order")["grant"]

    def signed(self, **extra):
        p = dict(Agent(self.agent, self.grant, "rs").act("refund", "orders/1", {"a": 1}).pcactn, **extra)
        p.pop("sig", None)
        p["sig"] = b64u(self.agent.sign(threshold_message(p)))
        return p


def _header(p):
    return {"PCA-Action": b64u(canonical_bytes_strict(p))}


# ---- A bond_ref ------------------------------------------------------------------------------------------------------------

def test_bond_reason_text():
    assert BOND_UNSUPPORTED == "bond: unsupported: the PCActn carries a feature this verifier does not implement"


def test_authorize_denies_a_bond_nothing_else_refuses(monkeypatch):
    assert authorize_fixture().allow is True
    real = verify_pcactn_core
    # the signature is not the subject: the core sees the signed fixture, the pipeline sees the bond_ref
    monkeypatch.setattr(AZ, "verify_pcactn_core", lambda p, *a, **k: real({x: v for x, v in p.items() if x != "bond_ref"}, *a, **k))
    claims = []
    store = AZ.MemoryStateStore()
    claim = store.claim
    monkeypatch.setattr(store, "claim", lambda *a: claims.append(a) or claim(*a))
    from test_k05_kill_authz import P0
    r = authorize_fixture(pcactn=dict(P0, bond_ref="b"), state_store=store)
    assert (r.allow, r.decision, r.status, r.reasons) == (False, "deny", 403, [BOND_UNSUPPORTED])
    assert r.checks["bond"] == "unsupported" and r.reason == BOND_UNSUPPORTED
    assert claims == []  # refused before the replay state is written


def test_the_core_alone_reports_no_refusal_for_a_bond():
    w = _World()
    assert verify_pcactn_core(w.signed(bond_ref="b"), w.grant, audience="rs").allow is True


def test_signature_only_guard_denies_a_bond():
    w = _World()
    guard = require_pca(audience="rs", resolve_grant=lambda ref: w.grant, signature_only=True)
    ok = guard(_header(w.signed()), None)
    assert ok.ok is True and ok.status == 200
    r = guard(_header(w.signed(bond_ref="b")), None)
    assert (r.ok, r.status, r.error) == (False, 403, BOND_UNSUPPORTED)
    assert r.www_authenticate and "insufficient_authority" in r.www_authenticate and "bond" not in r.www_authenticate


# ---- B budget_alloc -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("caveats,want", [
    ([], (True, None)),
    ([{"type": "expires", "at": 1}, "x", None], (True, None)),
    ([{"type": "budget_alloc", "limit": 10}, {"type": "budget_alloc", "limit": 10}, {"type": "budget_alloc", "limit": 4}], (True, None)),
    ([{"type": "budget_alloc", "limit": 0}], (True, None)),
    ([{"type": "budget_alloc", "limit": 5}, {"type": "ttl"}, {"type": "budget_alloc", "limit": 5.5}],
     (False, "budget_alloc caveat 2: allocation 5.5 widens the parent's carried allocation 5 (monotone: a child can only allocate <= its parent)")),
    ([{"type": "budget_alloc", "limit": 10}, {"type": "budget_alloc", "limit": 100}],
     (False, "budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)")),
    ([{"type": "x"}, {"type": "budget_alloc", "limit": -1}], (False, "budget_alloc caveat 1: limit must be a finite number >= 0")),
    ([{"type": "budget_alloc"}], (False, "budget_alloc caveat 0: limit must be a finite number >= 0")),
    ([{"type": "budget_alloc", "limit": "3"}], (False, "budget_alloc caveat 0: limit must be a finite number >= 0")),
    ([{"type": "budget_alloc", "limit": True}], (False, "budget_alloc caveat 0: limit must be a finite number >= 0")),
    ([{"type": "budget_alloc", "limit": float("inf")}], (False, "budget_alloc caveat 0: limit must be a finite number >= 0")),
    ([{"type": "budget_alloc", "limit": float("nan")}], (False, "budget_alloc caveat 0: limit must be a finite number >= 0")),
    (None, (False, "malformed caveats")),
    ({}, (False, "malformed caveats")),
])
def test_allocations_monotone(caveats, want):
    assert allocations_monotone(caveats) == want


def test_chain_refuses_a_widening_allocation():
    w = _World()
    sub = generate_keypair()
    parent = delegate(w.grant, w.agent, sub.public, [{"type": "budget_alloc", "limit": 10}])
    ok = delegate(parent, sub, generate_keypair().public, [{"type": "budget_alloc", "limit": 10}])
    assert verify_chain([w.grant, parent, ok], w.principal.public) == (True, None)
    bad = delegate(parent, sub, generate_keypair().public, [{"type": "budget_alloc", "limit": 100}])
    assert verify_chain([w.grant, parent, bad], w.principal.public) == (
        False, "budget_alloc caveat 2: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)")


# ---- C zk_compliance ---------------------------------------------------------------------------------------------------------

ZK = "zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)"


def test_core_and_signature_only_refuse_a_carried_zk_proof():
    w = _World()
    assert verify_pcactn_core(w.signed(), w.grant, audience="rs").allow is True
    v = verify_pcactn_core(w.signed(zk_compliance={"v": 1}), w.grant, audience="rs")
    assert v.allow is False and v.reason == ZK and v.checks["zk_compliance"] is False
    guard = require_pca(audience="rs", resolve_grant=lambda ref: w.grant, signature_only=True)
    r = guard(_header(w.signed(zk_compliance={"v": 1})), None)
    assert (r.ok, r.status, r.error) == (False, 403, ZK)


# ---- D allowed_suites ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("signature_only", [True, False])
def test_guard_forwards_allowed_suites(monkeypatch, signature_only):
    w = _World()
    seen = []
    real = verify_pcactn_core

    def spy(*a, **k):
        seen.append(k.get("allowed_suites"))
        return real(*a, **k)
    monkeypatch.setattr(sys.modules["atlas_pca.server"], "verify_pcactn_core", spy)
    monkeypatch.setattr(AZ, "verify_pcactn_core", spy)
    op = {"verb": "refund", "resource": "orders/1", "params": {"a": 1}}
    opts = AZ.AuthorizeOptions(state_store=AZ.MemoryStateStore(), is_revoked=lambda _p, _g: False)
    kw = {"signature_only": True} if signature_only else {"operation": lambda h, b: op, "authorize": opts}
    guard = require_pca(audience="rs", resolve_grant=lambda ref: w.grant, allowed_suites=["ml-dsa-65"], **kw)
    r = guard(_header(w.signed()), None)
    assert seen == [["ml-dsa-65"]] and r.ok is False
    seen.clear()
    require_pca(audience="rs", resolve_grant=lambda ref: w.grant, **kw)(_header(w.signed()), None)
    assert seen == [None]


# ---- F runtime_pins ------------------------------------------------------------------------------------------------------------

OP = generate_keypair()
BK = generate_keypair()


def _bp(status="active", epoch=1, **over):
    b = dict(dict(v=1, id="bp1", key=BK.public, ceiling=[], epoch=epoch, status=status, issued_at=1, operator=OP.public), **over)
    return dict(b, sig=_sign_body(OP, B.AGENT_BLUEPRINT_DOMAIN, b))


CHAIN = [{"issuer": "root", "holder": BK.public}, {"issuer": BK.public, "holder": "inst"}]


def test_pinned_blueprint_is_accepted_then_denies():
    pins = [{"runtime_measurement": "m"}, {"model_id": "a", "weights_digest": "b", "operator": "c", "spiffe_id": "d"}]
    rec = _bp(runtime_pins=pins)
    assert B.verify_blueprint(rec) is True
    # the pins are signed content
    assert B.verify_blueprint(dict(rec, runtime_pins=[{"model_id": "other"}])) is False
    reg = B.BlueprintRegistry([OP.public])
    assert reg.accept(rec) == {"ok": True, "replaced": True}
    for mode in ("any", "require"):
        assert B.check_blueprints(CHAIN, reg, 2, mode) == {"decision": "deny", "code": "admission_required", "blueprint": "bp1"}
    # a group kill carrying pins
    kill = _bp(status="disabled", epoch=2, runtime_pins=pins)
    assert reg.accept(kill) == {"ok": True, "replaced": True}
    assert B.check_blueprints(CHAIN, reg, 2, "any") == {"decision": "deny", "code": "blueprint_disabled", "blueprint": "bp1"}
    # status, expiry and depth come first; the ceiling after
    r2 = B.BlueprintRegistry([OP.public], store={BK.public: _bp(runtime_pins=pins, expires_at=2)})
    assert B.check_blueprints(CHAIN, r2, 2, "any")["code"] == "blueprint_expired"
    r3 = B.BlueprintRegistry([OP.public], store={BK.public: _bp(runtime_pins=pins, ceiling=[{"type": "x"}])})
    assert B.check_blueprints(CHAIN, r3, 2, "any")["code"] == "admission_required"


@pytest.mark.parametrize("pins", [[], "x", None, 5, [{}], ["x"], [{"nope": "a"}], [{"model_id": 5}], [{"model_id": ""}], [{"model_id": "a" * 257}],
                                  [{"model_id": "a"}] * 17])
def test_malformed_pins_are_refused(pins):
    assert B.verify_blueprint(_bp(runtime_pins=pins)) is False


def test_pin_bounds():
    assert B.verify_blueprint(_bp(runtime_pins=[{"model_id": "a" * 256}] * 16)) is True


# ---- G registry locks: the lock is held through the whole read-modify-write ----------------------------------------------------------

def _race(fns):
    out = [None] * len(fns)
    start = threading.Barrier(len(fns))

    def go(i):
        start.wait()
        out[i] = fns[i]()
    ts = [threading.Thread(target=go, args=(i,)) for i in range(len(fns))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out


class _SlowDict(dict):
    """Yields the GIL between the read and the write of a read-modify-write, so an unlocked registry loses the race every time."""

    def get(self, *a):
        v = super().get(*a)
        time.sleep(0.01)
        return v


def test_blueprint_accept_is_atomic():
    reg = B.BlueprintRegistry([OP.public], store=_SlowDict())
    a, b = _bp(), _bp(status="disabled")  # same epoch, different content: a fork
    rs = _race([lambda: reg.accept(a), lambda: reg.accept(b)])
    assert sorted(r["ok"] for r in rs) == [False, True]
    assert next(r for r in rs if not r["ok"]) == {"ok": False, "code": "epoch_fork"}


def test_lease_accept_is_atomic():
    key = generate_keypair()
    body = dict(v=1, lease_id="L", path="p", grant_ref="g", holder="agent", requester="alice", approvers=["bob"], justification_digest="j",
                seq=1, issued_at=1000, renewed_at=1000, expires_at=2000, max_ttl=10000, authority=key.public)
    a = dict(body, sig=_sign_body(key, L.LEASE_DOMAIN, {k: body[k] for k in L._BODY_KEYS}))
    other = dict(body, justification_digest="k")
    b = dict(other, sig=_sign_body(key, L.LEASE_DOMAIN, {k: other[k] for k in L._BODY_KEYS}))
    reg = L.LeaseRegistry({"authorities": [key.public]})
    reg.leases = _SlowDict()
    rs = _race([lambda: reg.accept(a), lambda: reg.accept(b)])
    assert sorted(r["ok"] for r in rs) == [False, True]
    assert next(r for r in rs if not r["ok"]) == {"ok": False, "code": "lease_fork"}


def test_break_glass_budget_is_atomic():
    reg = BG.BreakGlassRegistry({"authorities": [], "reviewers": []})

    class SlowUses(list):
        def __len__(self):
            time.sleep(0.005)
            return super().__len__()
    reg.holders["h"] = {"i": {"rec": {"issued_at": 0, "expires_at": 100, "max_uses": 1, "review_within": 10}, "uses": SlowUses(), "review": None}}
    rs = _race([lambda: reg.use("i", "h", "d", 1, True) for _ in range(4)])
    assert sum(1 for r in rs if r["decision"] == "allow") == 1
    assert sum(1 for r in rs if r.get("code") == "budget_exhausted") == 3
    assert reg.uses("h", "i") == [{"n": 1, "action_digest": "d", "at": 1}]


# ---- H, I -----------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("scope,ok", [
    ("a﻿b", False), ("a b", False), ("a\tb", False), ("a b", False), ("a b", False), ("a　b", False), ("a b", False),
    ("a\u0085b", True), ("a\x1cb", True), ("a᠎b", True), ("a​b", True), ("ab", True)])
def test_scope_whitespace_is_js(scope, ok):
    r = N.validate_need({"v": 1, "kind": "scope", "verb": "v", "resource": "r", "scopes": [scope]})
    assert r["ok"] is ok and (ok or r == {"ok": False, "code": "bad_field"})


def test_push_token_compare_is_constant_time(monkeypatch):
    seen = []
    real = N.hmac.compare_digest

    def spy(a, b):
        seen.append((a, b))
        return real(a, b)
    monkeypatch.setattr(N.hmac, "compare_digest", spy)
    chain = ["c"]
    salt = "s" * 16
    want = N.push_token("t", chain, salt)
    assert N.check_push("t", chain, salt, want, {"task": {"id": "t"}}) == {"ok": True}
    assert seen == [(want.encode(), want.encode())]
    assert N.check_push("t", chain, salt, want[:-1] + "\ud800", {"task": {"id": "t"}}) == {"ok": False, "reason": "token_mismatch"}  # no raise
    assert N.check_push("t", chain, salt, want + "x", {"task": {"id": "t"}}) == {"ok": False, "reason": "token_mismatch"}


def test_empty_merkle_inputs_raise_instead_of_recursing():
    from atlas_pca.actions import _subroot
    from atlas_pca.agent import commit_plan
    from atlas_pca.intent_map import _tree_root
    from atlas_pca.pca import _build

    with pytest.raises(ValueError, match="^merkleRoot: empty leaf set$"):
        commit_plan([])
    for fn in (_build, _subroot, _tree_root):
        with pytest.raises(IndexError):
            fn([])
        assert fn([b"x"]) == b"x"


@pytest.mark.parametrize("policy", [None, True, 0, 1.5, "x", []])
def test_lease_ceiling_check_only_reads_an_object_policy(policy):
    assert L.LeaseRegistry(policy).policy == policy


@pytest.mark.parametrize("bad", [None, 0, -1, 1.5, "1", True])
def test_lease_ceiling_refused(bad):
    with pytest.raises(ValueError, match="^LeaseRegistry: maxTtlCeiling must be a positive integer$"):
        L.LeaseRegistry({"maxTtlCeiling": bad})


# ---- the 0.5 upgrade of the replay key: a counter spent under the 0.4 key stays spent (require-pca.ts:736) --------------------
def _replay_keys():
    from test_k05_kill_authz import AUD, G, P0

    holder = P0["cap_chain"][-1]["holder"]
    return "%s:%s" % (G["id"], holder), AZ.state_key(G["id"], holder, AUD), P0["counter"]


def test_a_counter_spent_under_the_old_key_stays_spent():
    legacy, _key, counter = _replay_keys()
    for spent in (counter, counter + 1):
        store = AZ.MemoryStateStore()
        store.claim(legacy, spent)
        r = authorize_fixture(state_store=store)
        assert r.allow is False and r.checks["replay"] == "fail"
        assert r.reasons == ["replay: %s is not greater than last seen %s (replay)" % (counter, spent)]


def test_an_unspent_counter_moves_to_the_audience_key():
    legacy, key, counter = _replay_keys()
    store = AZ.MemoryStateStore()
    store.claim(legacy, counter - 1)
    assert authorize_fixture(state_store=store).allow is True
    assert store.last(key) == counter and store.last(legacy) == counter - 1  # the old key is never written again
    # state on the audience key decides from then on, whatever the old key holds
    assert authorize_fixture(state_store=store).checks["replay"] == "fail"
    store = AZ.MemoryStateStore()
    store.claim(legacy, counter + 5)
    store.claim(key, counter - 1)
    assert authorize_fixture(state_store=store).allow is True


def test_a_store_that_cannot_read_stays_on_the_old_key():
    legacy, _key, counter = _replay_keys()
    seen = []

    class ClaimOnly:
        def claim(self, key, c):
            seen.append((key, c))
            return True

    assert authorize_fixture(state_store=ClaimOnly()).allow is True
    assert seen == [(legacy, counter)]


@pytest.mark.parametrize("bad", ["1", 1.5])
def test_a_malformed_old_counter_fails_closed(bad):
    legacy, _key, _counter = _replay_keys()

    class Odd(AZ.MemoryStateStore):
        def last(self, key):
            return bad if key == legacy else None

    r = authorize_fixture(state_store=Odd())
    assert r.allow is False and r.checks["replay"] == "fail"
    assert r.reasons == ["replay: the replay store failed (fail closed)"]


def test_a_read_failure_of_the_store_fails_closed():
    class Down(AZ.MemoryStateStore):
        def last(self, key):
            raise OSError("down")

    r = authorize_fixture(state_store=Down())
    assert r.allow is False and r.reasons == ["replay: the replay store failed (fail closed)"]
