"""k05 mutation-kill tests, group "stores", second file: every branch and bound of lease, break_glass, readside and
read_vault on records signed here. Expectations follow pca-grants/src/lease.ts, breakglass.ts, pca/src/readside.ts and
read-vault.ts. Deterministic, no network."""
import copy

import pytest

from atlas_pca import break_glass as BG
from atlas_pca import lease as L
from atlas_pca import read_vault as RV
from atlas_pca import readside as RS
from atlas_pca.agent import KeyPair, _sign_body, sign_aggregate_grant, sign_read_grant
from atlas_pca.pca import b64u, hash_canonical

KP = KeyPair(bytes([1]) * 32)
KP2 = KeyPair(bytes([2]) * 32)
_B32 = "A" * 43

# ===================================================================================================================== lease


def _body(**over):
    b = dict(v=1, lease_id="L9", path="db/x", grant_ref="g9", holder="agent", requester="alice", approvers=["bob"],
             justification_digest="j1", seq=1, issued_at=1000, renewed_at=1000, expires_at=2000, max_ttl=10000, authority=KP.public)
    b.update(over)
    return b


def _lease(key=KP, **over):
    b = _body(**over)
    b["authority"] = over.get("authority", key.public)
    b["sig"] = _sign_body(key, L.LEASE_DOMAIN, {k: b[k] for k in L._BODY_KEYS})
    return b


def _renew(seq=2, renewed_at=1500, expires_at=3000, justification_digest="j2", **over):
    return _lease(seq=seq, renewed_at=renewed_at, expires_at=expires_at, justification_digest=justification_digest, **over)


def _rev(key=KP, target="lease", value="L9", revoked_at=1000, **over):
    r = dict(v=1, target=target, value=value, revoked_at=revoked_at, authority=key.public)
    r.update(over)
    r["sig"] = _sign_body(key, L.LEASE_REVOKE_DOMAIN, {k: r[k] for k in L._REV_KEYS})
    return r


def _reg(**policy):
    return L.LeaseRegistry(dict({"authorities": [KP.public]}, **policy))


@pytest.mark.parametrize("over,want", [
    ({}, True), ({"v": 2}, False), ({"v": True}, False), ({"v": None}, False),
    ({"lease_id": "x" * 128}, True), ({"lease_id": "x" * 129}, False), ({"lease_id": ""}, False),
    ({"grant_ref": "x" * 256}, True), ({"grant_ref": "x" * 257}, False), ({"grant_ref": 1}, False),
    ({"holder": "x" * 128}, True), ({"holder": "x" * 129}, False),
    ({"requester": "x" * 128}, True), ({"requester": "x" * 129}, False),
    ({"authority": "x" * 128}, True), ({"authority": "x" * 129}, False),
    ({"justification_digest": "x" * 128}, True), ({"justification_digest": "x" * 129}, False),
    ({"path": "a"}, True), ({"path": "a_.-9"}, True), ({"path": "/".join("abcdefgh")}, True), ({"path": "/".join("abcdefghi")}, False),
    ({"path": "x" * 64}, True), ({"path": "x" * 65}, False), ({"path": "A"}, False), ({"path": "a/"}, False), ({"path": ""}, False),
    ({"path": "a\n"}, False), ({"path": 5}, False),
    ({"seq": 0}, False), ({"seq": True}, False), ({"seq": 1.5}, False), ({"issued_at": -1}, False), ({"expires_at": "x"}, False),
    ({"renewed_at": None}, False), ({"max_ttl": 0}, False), ({"max_ttl": 1}, True), ({"max_ttl": None}, False),
    ({"seq": 2, "renewed_at": 999}, False), ({"seq": 2, "renewed_at": 1000}, True), ({"seq": 2, "renewed_at": 1001}, True),
    ({"expires_at": 1000}, False), ({"expires_at": 1001}, True), ({"renewed_at": 1001}, False),
    ({"approvers": []}, True), ({"approvers": ["a"] * 16}, True), ({"approvers": ["a"] * 17}, False), ({"approvers": "bob"}, False),
    ({"approvers": [5]}, False), ({"approvers": ["x" * 128]}, True), ({"approvers": ["x" * 129]}, False),
])
def test_lease_well_formed(over, want):
    assert L._well_formed(_body(**over)) is want


def test_lease_not_an_object_and_cap():
    assert [L._well_formed(x) for x in (None, [], "x", {})] == [False] * 4
    assert L.lease_cap({"issued_at": 5, "max_ttl": 7}) == 12


def test_verify_lease_and_revocation_signatures():
    l = _lease()
    assert L.verify_lease(l) is True
    assert L.verify_lease(dict(l, holder="other")) is False
    assert L.verify_lease({k: v for k, v in l.items() if k != "sig"}) is False
    assert L.verify_lease(dict(l, sig=5)) is False
    assert L.verify_lease(dict(l, authority=KP2.public)) is False
    # signed under the revocation domain: no
    assert L.verify_lease(dict(l, sig=_sign_body(KP, L.LEASE_REVOKE_DOMAIN, {k: l[k] for k in L._BODY_KEYS}))) is False
    r = _rev()
    assert L.verify_lease_revocation(r) is True
    assert L.verify_lease_revocation(dict(r, value="other")) is False
    assert L.verify_lease_revocation(dict(r, sig=_sign_body(KP, L.LEASE_DOMAIN, {k: r[k] for k in L._REV_KEYS}))) is False


@pytest.mark.parametrize("over,want", [
    ({}, True), ({"v": 2}, False), ({"v": True}, False), ({"value": "x" * 256}, True), ({"value": "x" * 257}, False), ({"value": ""}, False),
    ({"authority": "x" * 128}, True), ({"authority": "x" * 129}, False), ({"revoked_at": -1}, False), ({"revoked_at": True}, False),
    ({"target": "grant", "value": "ANY value"}, True), ({"target": "prefix", "value": "a/b"}, True), ({"target": "prefix", "value": "A b"}, False),
    ({"target": "prefix", "value": "a\n"}, False), ({"target": "other"}, False), ({"target": None}, False),
])
def test_lease_revocation_well_formed(over, want):
    assert L._rev_well_formed(dict(dict(v=1, target="lease", value="L9", revoked_at=1, authority="a"), **over)) is want


def test_path_under_and_covers():
    assert [L.path_under("a/b", "a/b"), L.path_under("a/b/c", "a/b"), L.path_under("a/bc", "a/b"), L.path_under("a", "a/b")] == \
        [True, True, False, False]
    l = {"issued_at": 10, "lease_id": "L", "grant_ref": "G", "path": "a/b"}
    c = L._covers
    assert c({"revoked_at": 10, "target": "lease", "value": "L"}, l) is True
    assert c({"revoked_at": 9, "target": "lease", "value": "L"}, l) is False
    assert c({"revoked_at": 11, "target": "lease", "value": "G"}, l) is False
    assert c({"revoked_at": 10, "target": "grant", "value": "G"}, l) is True
    assert c({"revoked_at": 10, "target": "grant", "value": "L"}, l) is False
    assert c({"revoked_at": 10, "target": "prefix", "value": "a"}, l) is True
    assert c({"revoked_at": 10, "target": "prefix", "value": "ab"}, l) is False


def test_accept_refusals_before_the_seq_rules():
    reg = _reg()
    assert reg.accept(dict(_lease(), holder="x")) == {"ok": False, "code": "bad_record"}
    assert L.LeaseRegistry({}).accept(_lease()) == {"ok": False, "code": "unknown_authority"}
    assert reg.accept(_lease(key=KP2)) == {"ok": False, "code": "unknown_authority"}
    assert reg.accept(_lease(approvers=[])) == {"ok": False, "code": "sod", "reason": "0 approver(s), need 1"}
    assert reg.accept(_lease(approvers=["c"]), ["c"]) == {"ok": False, "code": "sod", "reason": "an approver appears in the holder's delegation chain"}
    assert _reg(minApprovals=2).accept(_lease())["reason"] == "1 approver(s), need 2"
    assert reg.accept(_lease(max_ttl=999)) == {"ok": False, "code": "over_max_ttl"}
    assert reg.accept(_lease(max_ttl=1000)) == {"ok": True, "replaced": True, "seq": 1}  # expires_at == the cap


def test_accept_ttl_ceiling():
    assert _reg(maxTtlCeiling=9999).accept(_lease()) == {"ok": False, "code": "ttl_ceiling"}
    assert _reg(maxTtlCeiling=10000).accept(_lease()) == {"ok": True, "replaced": True, "seq": 1}
    for bad in (0, -1, "x", 1.5, True, None, 2 ** 53):  # lease.ts:219: the constructor throws
        with pytest.raises(ValueError, match="^LeaseRegistry: maxTtlCeiling must be a positive integer$"):
            _reg(maxTtlCeiling=bad)
    assert _reg(maxTtlCeiling=1).accept(_lease()) == {"ok": False, "code": "ttl_ceiling"}


def test_accept_renewal_rules():
    reg = _reg()
    first = _lease()
    assert reg.accept(first) == {"ok": True, "replaced": True, "seq": 1}
    assert reg.accept(copy.deepcopy(first)) == {"ok": True, "replaced": False, "seq": 1}
    assert reg.accept(_lease(justification_digest="other")) == {"ok": False, "code": "lease_fork"}
    for over in ({"path": "db/y"}, {"grant_ref": "g0"}, {"holder": "h2"}, {"requester": "r2"}, {"max_ttl": 9999}, {"issued_at": 999}):
        assert reg.accept(_renew(**over)) == {"ok": False, "code": "renewal_mismatch"}, over
    multi = L.LeaseRegistry({"authorities": [KP.public, KP2.public]})
    multi.accept(first)
    assert multi.accept(_renew(key=KP2)) == {"ok": False, "code": "renewal_mismatch"}
    assert reg.accept(_renew(renewed_at=2000, expires_at=3000)) == \
        {"ok": False, "code": "expired_lease", "reason": "an expired lease cannot be renewed"}
    assert reg.accept(_renew(expires_at=2000)) == {"ok": False, "code": "not_extending"}
    assert reg.accept(_renew(justification_digest="j1")) == {"ok": False, "code": "stale_justification"}
    second = _renew(renewed_at=1999, expires_at=2001)
    assert reg.accept(second) == {"ok": True, "replaced": True, "seq": 2}
    assert reg.accept(first) == {"ok": False, "code": "stale_seq"}
    assert reg.accept(_renew(seq=3, renewed_at=1998, expires_at=4000, justification_digest="j3")) == {"ok": False, "code": "not_extending"}
    assert reg.get("L9") == second and reg.get("nope") is None
    entry = lambda r: {k: r[k] for k in ("seq", "renewed_at", "expires_at", "justification_digest")}  # noqa: E731
    assert reg.history("L9") == [entry(first), entry(second)] and reg.history("nope") == []
    h = reg.history("L9")
    h.clear()
    assert len(reg.history("L9")) == 2


def test_fresh_justification_policy():
    for fresh, want in ((False, {"ok": True, "replaced": True, "seq": 2}), (True, {"ok": False, "code": "stale_justification"})):
        reg = _reg(freshJustification=fresh)
        reg.accept(_lease())
        assert reg.accept(_renew(justification_digest="j1")) == want


def test_revoked_lease_cannot_register_and_revoke_counts():
    reg = _reg()
    assert reg.revoke(dict(_rev(), value="other")) == {"ok": False, "code": "bad_record"}
    assert L.LeaseRegistry({}).revoke(_rev()) == {"ok": False, "code": "unknown_authority"}
    assert reg.revoke(_rev(key=KP2)) == {"ok": False, "code": "unknown_authority"}
    reg.accept(_lease())
    reg.accept(_lease(lease_id="L8", path="db/y", grant_ref="g8"))
    assert reg.revoke(_rev(target="prefix", value="db")) == {"ok": True, "revoked": 2}
    r = _rev(target="grant", value="g8")
    assert reg.revoke(r) == {"ok": True, "revoked": 1}
    assert reg.revoke(copy.deepcopy(r)) == {"ok": True, "revoked": 1}
    assert len(reg.revocations) == 2
    assert reg.revoke(_rev(target="lease", value="zz")) == {"ok": True, "revoked": 0}
    reg2 = _reg()
    reg2.revoke(_rev(revoked_at=1000))
    assert reg2.accept(_lease()) == {"ok": False, "code": "revoked"}
    reg3 = _reg()
    reg3.revoke(_rev(revoked_at=999))
    assert reg3.accept(_lease()) == {"ok": True, "replaced": True, "seq": 1}


def test_check_lease_every_outcome():
    reg = _reg()
    first = _lease()
    second = _renew()
    for now in ("x", True, -1, None, 1.5):
        assert L.check_lease(first, reg, now) == {"decision": "deny", "code": "bad_input"}
    assert L.check_lease(dict(first, holder="x"), reg, 1500) == {"decision": "deny", "code": "bad_record"}
    assert L.check_lease(first, reg, 1500) == {"decision": "deny", "code": "unknown_lease", "lease_id": "L9"}
    reg.accept(first)
    reg.accept(second)
    no = lambda c: {"decision": "deny", "code": c, "lease_id": "L9"}  # noqa: E731
    assert L.check_lease(first, reg, 1500) == no("superseded")
    assert L.check_lease(second, reg, 1499) == no("not_yet_valid")
    yes = {"decision": "allow", "lease_id": "L9", "expires_at": 3000}
    assert L.check_lease(second, reg, 1500) == yes and L.check_lease(second, reg, 2999) == yes
    assert L.check_lease(second, reg, 3000) == no("expired")
    capped = _reg()
    c1 = _lease(max_ttl=1000)  # the cap and the expiry coincide: past_max_ttl is reported first
    capped.accept(c1)
    assert L.check_lease(c1, capped, 1999)["decision"] == "allow"
    assert L.check_lease(c1, capped, 2000) == no("past_max_ttl")
    reg.revoke(_rev())
    assert L.check_lease(second, reg, 1499) == no("revoked")

    class Boom:
        revocations = []

        def get(self, lid):
            raise RuntimeError("down")
    assert L.check_lease(first, Boom(), 1500) == no("store_unreachable")


def test_sod_order_of_checks():
    # one approver at a time: duplicate is seen before the second copy's own checks
    l = {"approvers": ["a", "a"], "requester": "r", "holder": "h"}
    assert L.sod_error(l) == "an approver is listed twice"
    assert L.sod_error({"approvers": ["r", "h"], "requester": "r", "holder": "h"}) == "the requester may not approve their own request"
    assert L.sod_error({"approvers": ["h", "r"], "requester": "r", "holder": "h"}) == "the holder may not approve its own lease"
    assert L.sod_error({"approvers": ["c"], "requester": "r", "holder": "h"}, {"eligibleApprovers": ["d"]}, ["c"]) == \
        "an approver appears in the holder's delegation chain"
    assert L.sod_error({"approvers": [], "requester": "r", "holder": "h"}, {"minApprovals": 0}) == "minApprovals must be a positive integer"


# =============================================================================================================== break_glass

REVIEWER = KeyPair(bytes([3]) * 32)
T0 = 1_000_000


def _bg_body(**over):
    b = dict(v=1, id="b1", holder="agent", grant_ref="g", reason_digest="why", max_uses=2, issued_at=T0, expires_at=T0 + 1000,
             review_within=500, notify_to="sec", authority=KP.public)
    b.update(over)
    return b


def _bg(key=KP, **over):
    b = _bg_body(**over)
    b["authority"] = key.public
    b["sig"] = _sign_body(key, BG.BREAK_GLASS_DOMAIN, {k: b[k] for k in BG._BODY_KEYS})
    return b


def _rv(key=REVIEWER, **over):
    r = dict(v=1, id="b1", outcome="justified", notes_digest="n", at=T0 + 1, reviewer=key.public)
    r.update(over)
    r["reviewer"] = key.public
    r["sig"] = _sign_body(key, BG.BREAK_GLASS_REVIEW_DOMAIN, {k: r[k] for k in BG._REV_KEYS})
    return r


def _bgreg(extra_reviewers=()):
    return BG.BreakGlassRegistry({"authorities": [KP.public], "reviewers": [REVIEWER.public] + list(extra_reviewers)})


def test_break_glass_constants():
    assert (BG.MAX_BREAK_GLASS_WINDOW_MS, BG.MAX_BREAK_GLASS_USES, BG.MAX_REVIEW_WITHIN_MS) == (86_400_000, 16, 2_592_000_000)


@pytest.mark.parametrize("over,want", [
    ({}, True), ({"v": 2}, False), ({"v": True}, False),
    ({"id": "x" * 128}, True), ({"id": "x" * 129}, False), ({"id": ""}, False), ({"holder": "x" * 128}, True), ({"holder": "x" * 129}, False),
    ({"grant_ref": "x" * 256}, True), ({"grant_ref": "x" * 257}, False), ({"reason_digest": "x" * 128}, True), ({"reason_digest": "x" * 129}, False),
    ({"notify_to": "x" * 256}, True), ({"notify_to": "x" * 257}, False), ({"authority": "x" * 128}, True), ({"authority": "x" * 129}, False),
    ({"max_uses": 0}, False), ({"max_uses": 1}, True), ({"max_uses": 16}, True), ({"max_uses": 17}, False), ({"max_uses": True}, False),
    ({"issued_at": None}, False), ({"expires_at": None}, False), ({"expires_at": T0}, False), ({"expires_at": T0 + 1}, True),
    ({"expires_at": T0 + 86_400_000}, True), ({"expires_at": T0 + 86_400_001}, False),
    ({"review_within": 0}, False), ({"review_within": 1}, True), ({"review_within": 2_592_000_000}, True), ({"review_within": 2_592_000_001}, False),
    ({"review_within": None}, False),
])
def test_break_glass_well_formed(over, want):
    assert BG._well_formed(_bg_body(**over)) is want


@pytest.mark.parametrize("over,want", [
    ({}, True), ({"v": 2}, False), ({"id": "x" * 128}, True), ({"id": "x" * 129}, False), ({"outcome": "unjustified"}, True), ({"outcome": "other"}, False),
    ({"outcome": None}, False), ({"notes_digest": "x" * 128}, True), ({"notes_digest": "x" * 129}, False), ({"at": -1}, False), ({"at": True}, False),
    ({"reviewer": "x" * 128}, True), ({"reviewer": "x" * 129}, False),
])
def test_break_glass_review_well_formed(over, want):
    assert BG._rv_well_formed(dict(dict(v=1, id="b", outcome="justified", notes_digest="n", at=1, reviewer="r"), **over)) is want


def test_break_glass_signatures():
    assert [BG._well_formed(x) for x in (None, [], {})] == [False] * 3
    assert BG.verify_break_glass(_bg()) is True and BG.verify_break_glass(dict(_bg(), holder="x")) is False
    assert BG.verify_break_glass({k: v for k, v in _bg().items() if k != "sig"}) is False
    assert BG.verify_break_glass_review(_rv()) is True and BG.verify_break_glass_review(dict(_rv(), notes_digest="x")) is False
    b = _bg_body()
    assert BG.verify_break_glass(dict(b, sig=_sign_body(KP, BG.BREAK_GLASS_REVIEW_DOMAIN, {k: b[k] for k in BG._BODY_KEYS}))) is False


def test_break_glass_accept():
    reg = _bgreg()
    g = _bg()
    for now in ("x", -1, True):
        assert reg.accept(g, now) == {"ok": False, "code": "bad_record"}
    assert reg.accept(dict(g, holder="x"), T0) == {"ok": False, "code": "bad_record"}
    assert reg.accept(_bg(key=KP2), T0) == {"ok": False, "code": "unknown_authority"}
    assert BG.BreakGlassRegistry({}).accept(g, T0) == {"ok": False, "code": "unknown_authority"}

    class Broken:
        def setdefault(self, *a):
            raise RuntimeError("down")
    down = _bgreg()
    down.holders = Broken()
    assert down.accept(g, T0) == {"ok": False, "code": "store_unreachable"}
    assert reg.accept(g, T0) == {"ok": True, "replaced": True}
    assert reg.accept(copy.deepcopy(g), T0) == {"ok": True, "replaced": False}
    assert reg.accept(_bg(reason_digest="other"), T0) == {"ok": False, "code": "id_conflict"}
    assert reg.use("b1", "agent", "a", T0, True)["decision"] == "allow"
    assert reg.accept(_bg(id="b2"), T0 + 499) == {"ok": True, "replaced": True}
    assert reg.accept(_bg(id="b3"), T0 + 500) == {"ok": False, "code": "holder_frozen"}
    assert reg.accept(_bg(id="b3", holder="someone-else"), T0 + 500) == {"ok": True, "replaced": True}


def test_break_glass_use_every_outcome():
    reg = _bgreg()
    g = _bg()
    reg.accept(g, T0)
    no = lambda c: {"decision": "deny", "code": c, "id": "b1"}  # noqa: E731
    bad = {"decision": "deny", "code": "bad_input"}
    for args in ((5, "agent", "a", T0, True), ("x" * 129, "agent", "a", T0, True), ("b1", 5, "a", T0, True), ("b1", "x" * 129, "a", T0, True),
                 ("b1", "agent", 5, T0, True), ("b1", "agent", "x" * 129, T0, True), ("b1", "agent", "a", "x", True), ("b1", "agent", "a", T0, 1),
                 ("b1", "agent", "a", T0, None)):
        assert reg.use(*args) == bad, args
    assert reg.use("nope", "agent", "a", T0, True) == {"decision": "deny", "code": "unknown_break_glass", "id": "nope"}
    assert reg.use("b1", "other", "a", T0, True) == no("unknown_break_glass")
    assert reg.use("b1", "agent", "a", T0 - 1, True) == no("not_yet_valid")
    assert reg.use("b1", "agent", "a", T0 + 1000, True) == no("expired")
    assert reg.use("b1", "agent", "a", T0, False) == no("not_notified")
    assert reg.uses("agent", "b1") == []
    assert reg.use("b1", "agent", "a", T0 + 10, True) == {"decision": "allow", "id": "b1", "use": 1, "remaining": 1, "review_due": T0 + 510}
    assert reg.use("b1", "agent", "b", T0 + 20, True) == {"decision": "allow", "id": "b1", "use": 2, "remaining": 0, "review_due": T0 + 510}
    assert reg.use("b1", "agent", "c", T0 + 30, True) == no("budget_exhausted")
    assert reg.use("b1", "agent", "c", T0 + 30, False) == no("budget_exhausted")  # budget is checked before the notification


def test_break_glass_use_freeze_revoked_and_faults(monkeypatch):
    reg = _bgreg()
    reg.accept(_bg(expires_at=T0 + 2000), T0)
    reg.use("b1", "agent", "a", T0, True)
    assert reg.use("b1", "agent", "a", T0 + 500, True) == {"decision": "deny", "code": "holder_frozen", "id": "b1"}
    assert reg.review(_rv(outcome="unjustified"), "agent", T0 + 600) == {"ok": True, "replaced": True}
    assert reg.use("b1", "agent", "a", T0 + 1, True)["code"] == "holder_frozen"
    # `revoked` sits behind the freeze check (the same record freezes its holder): reached through the seam
    monkeypatch.setattr(BG, "_frozen_in", lambda grants, now: False)
    assert reg.use("b1", "agent", "a", T0 + 1, True) == {"decision": "deny", "code": "revoked", "id": "b1"}
    monkeypatch.undo()

    class Broken:
        def get(self, *a):
            raise RuntimeError("down")
    reg.holders = Broken()
    assert reg.use("b1", "agent", "a", T0, True) == {"decision": "deny", "code": "store_unreachable", "id": "b1"}
    assert reg.frozen("agent", T0) is True
    assert reg.review(_rv(), "agent", T0 + 1) == {"ok": False, "code": "store_unreachable"}


def test_break_glass_review_every_outcome():
    reg = _bgreg()
    reg.accept(_bg(), T0)
    assert reg.review(dict(_rv(), notes_digest="x"), "agent", T0 + 9) == {"ok": False, "code": "bad_record"}
    assert reg.review(_rv(), 5, T0 + 9) == {"ok": False, "code": "bad_record"}
    assert reg.review(_rv(), "x" * 129, T0 + 9) == {"ok": False, "code": "bad_record"}
    assert reg.review(_rv(), "agent", "x") == {"ok": False, "code": "bad_record"}
    assert reg.review(_rv(key=KP2), "agent", T0 + 9) == {"ok": False, "code": "unknown_reviewer"}
    assert BG.BreakGlassRegistry({}).review(_rv(), "agent", T0 + 9) == {"ok": False, "code": "unknown_reviewer"}
    assert reg.review(_rv(id="nope"), "agent", T0 + 9) == {"ok": False, "code": "unknown_break_glass"}
    assert reg.review(_rv(), "other", T0 + 9) == {"ok": False, "code": "unknown_break_glass"}
    assert reg.review(_rv(), "agent", T0 + 9) == {"ok": False, "code": "nothing_to_review"}
    reg.use("b1", "agent", "a", T0 + 5, True)
    assert reg.review(_rv(at=T0 + 4), "agent", T0 + 9) == {"ok": False, "code": "bad_time"}
    assert reg.review(_rv(at=T0 + 10), "agent", T0 + 9) == {"ok": False, "code": "bad_time"}
    ok = _rv(at=T0 + 5)
    assert reg.review(ok, "agent", T0 + 5) == {"ok": True, "replaced": True}
    assert reg.review(copy.deepcopy(ok), "agent", T0 + 9) == {"ok": True, "replaced": False}
    assert reg.review(_rv(at=T0 + 6), "agent", T0 + 9) == {"ok": False, "code": "already_reviewed"}
    # the reviewer may be neither the holder nor the authority
    sod = BG.BreakGlassRegistry({"authorities": [KP.public], "reviewers": [KP.public, REVIEWER.public]})
    sod.accept(_bg(), T0)
    assert sod.review(_rv(key=KP), "agent", T0 + 9) == {"ok": False, "code": "sod"}
    sod.accept(_bg(holder=REVIEWER.public), T0)
    assert sod.review(_rv(), REVIEWER.public, T0 + 9) == {"ok": False, "code": "sod"}


def test_break_glass_frozen():
    reg = _bgreg()
    assert reg.frozen(5, T0) is True and reg.frozen("x" * 129, T0) is True and reg.frozen("agent", "x") is True
    assert reg.frozen("agent", T0) is False  # no grants
    reg.accept(_bg(), T0)
    assert reg.frozen("agent", T0 + 10_000) is False  # no uses
    reg.use("b1", "agent", "a", T0 + 1, True)
    assert reg.frozen("agent", T0 + 500) is False
    assert reg.frozen("agent", T0 + 501) is True
    assert reg.review(_rv(at=T0 + 1), "agent", T0 + 502) == {"ok": True, "replaced": True}
    assert reg.frozen("agent", T0 + 10_000) is False  # a late, justified review lifts it
    reg2 = _bgreg()
    reg2.accept(_bg(), T0)
    reg2.use("b1", "agent", "a", T0, True)
    reg2.review(_rv(at=T0, outcome="unjustified"), "agent", T0)
    assert reg2.frozen("agent", T0) is True


# ================================================================================================================== readside

SALT = "s" * 16
ENTRY = {"verb": "read", "resource_prefix": "res/", "purposes": ["audit"],
         "modes": {"a": "show", "b": "last4", "c": "bucket:10", "d": "hash", "e": "token", "z": "drop"}, "default_mode": "drop"}
SINKS = {"ok": {"allow": ["a"], "escalate": ["b"]}}
SINK_KEY = KeyPair(bytes([9]) * 32)


def _rg_body(**over):
    b = {"v": 1, "id": "g1", "principal": KP.public, "issued_at": 100, "expires_at": 200, "reads": [ENTRY], "caps": {}, "sinks": SINKS}
    b.update(over)
    return b


GRANT = sign_read_grant(KP, _rg_body())
GD = RS.read_grant_digest(GRANT["body"])


def _inp(**over):
    i = {"grant": GRANT, "principal": KP.public, "now": 150, "verb": "read", "resource": "res/1", "purpose": "audit",
         "schema": {"fields": {"f": "a"}, "required": []}, "record": {"f": "v"}, "tighten": {}, "salt": SALT, "counts": {}}
    i.update(over)
    return i


def _vd(p, v):
    return hash_canonical({"d": "atlas-pca/read-value/v1", "salt": SALT, "p": p, "v": v})


def _one(cls, v, **over):
    """Redact a single field of class `cls` and return (view value or the string 'ABSENT', its field record)."""
    r = RS.redact_read(_inp(schema={"fields": {"f": cls}, "required": []}, record={"f": v}, **over))
    assert r["decision"] == "allow", r
    return r["view"].get("f", "ABSENT"), r["fields"]["f"]


def test_mode_helpers():
    good = ("show", "last4", "hash", "token", "drop", "bucket:1", "bucket:999999999")
    assert all(RS._is_mode(m) for m in good)
    assert not any(RS._is_mode(m) for m in ("", "SHOW", "bucket:", "bucket:0", "bucket:01", "bucket:1000000000", "show\n", None, 5))
    assert [RS._rank(m) for m in ("show", "last4", "bucket:7", "token", "hash", "drop")] == [0, 1, 2, 3, 4, 5]


def test_redact_read_whole_result():
    fields = {"f_a": "a", "f_b": "b", "f_c": "c", "f_d": "d", "f_e": "e", "f_z": "z", "f_u": "other"}
    record = {"f_a": "plain", "f_b": "1234567", "f_c": 57, "f_d": "secret", "f_e": "tok-me", "f_z": "gone", "f_u": "gone2", "extra": 1}
    r = RS.redact_read(_inp(schema={"fields": fields, "required": ["f_a"]}, record=record, counts={"q": 5, "a": 1}))
    h = hash_canonical({"d": "atlas-pca/read-hash/v1", "salt": SALT, "c": "d", "v": "secret"})
    t = "tok_" + hash_canonical({"d": "atlas-pca/read-token/v1", "salt": SALT, "c": "e", "v": "tok-me"})[:22]
    assert r == {
        "decision": "allow", "code": None,
        "view": {"f_a": "plain", "f_b": "****4567", "f_c": 50, "f_d": h, "f_e": t},
        "fields": {
            "extra": {"class": "unclassified", "action": "dropped", "kind": None, "vd": _vd("extra", 1)},
            "f_a": {"class": "a", "action": "shown", "kind": None, "vd": _vd("f_a", "plain")},
            "f_b": {"class": "b", "action": "masked", "kind": "last4", "vd": _vd("f_b", "1234567")},
            "f_c": {"class": "c", "action": "masked", "kind": "bucket", "vd": _vd("f_c", 57)},
            "f_d": {"class": "d", "action": "masked", "kind": "hash", "vd": _vd("f_d", "secret")},
            "f_e": {"class": "e", "action": "masked", "kind": "token", "vd": _vd("f_e", "tok-me")},
            "f_u": {"class": "other", "action": "dropped", "kind": None, "vd": _vd("f_u", "gone2")},
            "f_z": {"class": "z", "action": "dropped", "kind": None, "vd": _vd("f_z", "gone")},
        },
        "labels": ["a", "b", "c", "d", "e"],
        "counts": {"q": 5, "a": 2, "b": 1, "c": 1, "d": 1, "e": 1},
    }
    assert list(r["fields"]) == sorted(r["fields"])


def test_mode_value_edges():
    dropped = {"action": "dropped", "kind": None}
    for cls, v in (("b", "1234"), ("b", 12345), ("b", "ab\U0001F600cd"), ("c", "x"), ("c", True), ("c", -5)):
        got, f = _one(cls, v)
        assert got == "ABSENT" and {k: f[k] for k in dropped} == dropped and f["class"] == cls, (cls, v)
    assert _one("b", "12345")[0] == "****2345"
    assert _one("c", 0)[0] == 0 and _one("c", 9)[0] == 0 and _one("c", 10)[0] == 10
    assert _one("a", False)[0] is False  # a false value is still shown
    assert _one("a", 0)[0] == 0


def test_tighten_only_ever_tightens():
    assert _one("a", "v", tighten={"a": "drop"})[0] == "ABSENT"
    got, f = _one("a", "v", tighten={"a": "last4"})
    assert got == "ABSENT" and f["action"] == "dropped"
    assert _one("a", "12345", tighten={"a": "last4"})[0] == "****2345"
    assert _one("d", "v", tighten={"d": "show"})[0] != "v"
    assert _one("c", 57, tighten={"c": "bucket:5"})[0] == 50  # the same rank keeps the grant's mode
    assert _one("a", "v", tighten={"other": "drop"})[0] == "v"


def test_default_mode_applies_to_an_unlisted_class():
    g = sign_read_grant(KP, _rg_body(reads=[dict(ENTRY, modes={}, default_mode="show")]))
    assert _one("anything", "v", grant=g)[0] == "v"


def test_redact_read_caps_and_required():
    g = sign_read_grant(KP, _rg_body(caps={"a": 2}))
    assert RS.redact_read(_inp(grant=g, counts={"a": 1}))["counts"] == {"a": 2}
    assert RS.redact_read(_inp(grant=g, counts={"a": 2})) == {"decision": "deny", "code": "read_cap", "view": {}, "fields": {}, "labels": [], "counts": {"a": 2}}
    assert RS.redact_read(_inp(schema={"fields": {"f": "z"}, "required": ["f"]}, counts={"a": 7})) == \
        {"decision": "escalate", "code": "required_dropped", "view": {}, "fields": {}, "labels": [], "counts": {"a": 7}}


@pytest.mark.parametrize("over", [{"verb": "other"}, {"resource": "xres/1"}, {"purpose": "other"}])
def test_redact_read_no_scope_keeps_the_counts(over):
    assert RS.redact_read(_inp(counts={"a": 1}, **over)) == \
        {"decision": "deny", "code": "no_read_scope", "view": {}, "fields": {}, "labels": [], "counts": {"a": 1}}


BAD_REQ = {"decision": "deny", "code": "bad_request", "view": {}, "fields": {}, "labels": [], "counts": {}}


@pytest.mark.parametrize("over", [
    {"principal": "x"}, {"now": "x"}, {"now": -1}, {"verb": ""}, {"verb": "v" * 129}, {"resource": "r" * 513}, {"purpose": "bad purpose"},
    {"purpose": "__proto__"}, {"salt": "s" * 15}, {"salt": 5}, {"schema": None}, {"schema": {"required": []}},
    {"schema": {"fields": {"f": "a"}, "required": "f"}}, {"schema": {"fields": {"f": "a"}, "required": [5]}},
    {"record": {"bad key": 1}}, {"record": {"f": 1.5}}, {"record": None}, {"tighten": None}, {"tighten": {"A": "show"}}, {"tighten": {"a": "nope"}},
    {"counts": None}, {"counts": {"A": 1}}, {"counts": {"a": -1}}, {"counts": {"a": True}},
])
def test_redact_read_bad_requests(over):
    assert RS.redact_read(_inp(**over)) == BAD_REQ


def test_redact_read_bounds_that_pass_validation():
    assert RS.redact_read(_inp(verb="v" * 128))["code"] == "no_read_scope"
    assert RS.redact_read(_inp(resource="r" * 512))["code"] == "no_read_scope"
    assert RS.redact_read(_inp(salt="\U0001F600" * 8))["decision"] == "allow"  # UTF-16 units, as the reference counts
    assert RS.redact_read(None) == BAD_REQ


@pytest.mark.parametrize("over,code", [
    ({"grant": None}, "bad_grant"), ({"grant": dict(GRANT, extra=1)}, "bad_grant"), ({"grant": {"body": {}, "sig": "x"}}, "bad_grant"),
    ({"principal": KP2.public}, "bad_signature"), ({"grant": {"body": GRANT["body"], "sig": "A" * 86}}, "bad_signature"),
    ({"now": 99}, "not_yet"), ({"now": 200}, "expired"),
])
def test_grade_grant_codes(over, code):
    r = RS.redact_read(_inp(**over))
    assert r == {"decision": "deny", "code": code, "view": {}, "fields": {}, "labels": [], "counts": {}}
    c = RS.check_sink({"grant": over.get("grant", GRANT), "principal": over.get("principal", KP.public), "now": over.get("now", 150),
                       "rs_signer": SINK_KEY.public, "sink": "ok", "receipts": []})
    assert c == {"decision": "deny", "code": code, "labels": []}


def test_grant_time_edges_pass():
    assert RS.redact_read(_inp(now=100))["decision"] == "allow" and RS.redact_read(_inp(now=199))["decision"] == "allow"


@pytest.mark.parametrize("over,want", [
    ({}, True), ({"v": True}, False), ({"v": 2}, False), ({"id": "bad id"}, False), ({"principal": "x"}, False), ({"issued_at": -1}, False), ({"expires_at": "x"}, False),
    ({"reads": []}, False), ({"reads": "x"}, False), ({"reads": [ENTRY] * 32}, True), ({"reads": [ENTRY] * 33}, False), ({"reads": [{}]}, False),
    ({"caps": None}, False), ({"caps": {"A": 1}}, False), ({"caps": {"a": -1}}, False), ({"caps": {"c%d" % i: 1 for i in range(32)}}, True),
    ({"caps": {"c%d" % i: 1 for i in range(33)}}, False),
    ({"sinks": None}, False), ({"sinks": {"s%d" % i: {"allow": [], "escalate": []} for i in range(16)}}, True),
    ({"sinks": {"s%d" % i: {"allow": [], "escalate": []} for i in range(17)}}, False),
    ({"sinks": {"bad id": {"allow": [], "escalate": []}}}, False), ({"sinks": {"s": 5}}, False), ({"sinks": {"s": {"allow": []}}}, False),
    ({"sinks": {"s": {"allow": ["b", "a"], "escalate": []}}}, False), ({"sinks": {"s": {"allow": [], "escalate": ["B"]}}}, False),
    ({"sinks": {"s": {"allow": ["a"], "escalate": ["a"]}}}, False), ({"sinks": {"s": {"allow": ["a"], "escalate": ["b"]}}}, True),
])
def test_valid_read_grant_body(over, want):
    assert RS.valid_read_grant_body(_rg_body(**over)) is want


@pytest.mark.parametrize("over,want", [
    ({"verb": "v" * 128}, True), ({"verb": "v" * 129}, False), ({"resource_prefix": "r" * 512}, True), ({"resource_prefix": "r" * 513}, False),
    ({"purposes": []}, False), ({"purposes": ["p%02d" % i for i in range(16)]}, True), ({"purposes": ["p%02d" % i for i in range(17)]}, False),
    ({"modes": None}, False), ({"modes": {"c%d" % i: "show" for i in range(32)}}, True), ({"modes": {"c%d" % i: "show" for i in range(33)}}, False),
    ({"modes": {"A": "show"}}, False), ({"modes": {"a": "nope"}}, False), ({"default_mode": "nope"}, False), ({"extra": 1}, False),
])
def test_valid_entry(over, want):
    assert RS._valid_entry(dict(ENTRY, **over)) is want


def test_receipt_shape_bounds():
    def rc(**over):
        r = {"v": 1, "grant": _B32, "verb": "v", "resource": "r", "purpose": "p", "seq": 0, "prev": None, "fields": {}, "labels": [],
             "issued_at": 1, "signer": _B32, "sig": "s"}
        r.update(over)
        return r
    v = RS._valid_read_receipt
    assert v(rc()) is True
    for over in ({"grant": "x"}, {"verb": "v" * 129}, {"resource": "r" * 513}, {"purpose": "bad p"}, {"seq": -1}, {"prev": "x"}, {"issued_at": -1},
                 {"signer": "x"}, {"sig": 5}, {"labels": ["B"]}, {"labels": ["b", "a"]}, {"labels": ["l%02d" % i for i in range(33)]}, {"fields": None}):
        assert v(rc(**over)) is False, over
    assert v(rc(labels=["l%02d" % i for i in range(32)], verb="v" * 128, resource="r" * 512)) is True
    assert v(dict(rc(), extra=1)) is False
    assert [v(x) for x in (None, [], {})] == [False] * 3


def _f(cls, action="shown"):
    return {"class": cls, "action": action, "kind": None, "vd": _B32}


def _rr(seq=0, prev=None, fields=None, labels=None, grant=GD, issued_at=120, key=SINK_KEY):
    r = {"v": 1, "grant": grant, "verb": "read", "resource": "res/1", "purpose": "audit", "seq": seq, "prev": prev,
         "fields": {"x": _f("a")} if fields is None else fields, "labels": ["a"] if labels is None else labels,
         "issued_at": issued_at, "signer": key.public}
    r["sig"] = _sign_body(key, RS.READ_RECEIPT_DOMAIN, {k: r[k] for k in RS._RR_KEYS})
    return r


def test_read_chain_labels():
    rl = lambda rs, now=150: RS.read_chain_labels(rs, SINK_KEY.public, GD, now)  # noqa: E731
    assert rl("x") == {"code": "bad_receipt", "at": 0} and rl(None) == {"code": "bad_receipt", "at": 0}
    assert rl([]) == {"labels": []}
    r0 = _rr(fields={"x": _f("c"), "y": _f("a"), "z": _f("q", "dropped")}, labels=["a", "c"])
    r1 = _rr(seq=1, prev=RS.read_receipt_ref(r0), fields={"x": _f("b")}, labels=["b"])
    assert rl([r0, r1]) == {"labels": ["a", "b", "c"]}
    assert rl([_rr(issued_at=150)]) == {"labels": ["a"]}
    bad0 = {"code": "bad_receipt", "at": 0}
    bad1 = {"code": "bad_receipt", "at": 1}
    assert rl([_rr(issued_at=151)]) == bad0
    assert rl([_rr(grant=_B32)]) == bad0
    assert rl([_rr(key=KP2)]) == bad0
    assert rl([dict(_rr(), sig=_rr(key=KP2)["sig"])]) == bad0
    assert rl([{}]) == bad0
    assert rl([_rr(seq=1, prev=_B32)]) == bad0
    assert rl([_rr(labels=[])]) == bad0  # an understated list
    assert rl([_rr(labels=["a", "b"])]) == bad0  # an overstated one
    assert rl([r0, r0]) == bad1
    assert rl([r0, _rr(seq=1, prev=_B32, fields={"x": _f("b")}, labels=["b"])]) == bad1


def test_check_sink_outcomes():
    def cs(receipts, **over):
        return RS.check_sink(dict({"grant": GRANT, "principal": KP.public, "now": 150, "rs_signer": SINK_KEY.public, "sink": "ok", "receipts": receipts}, **over))
    assert RS.check_sink(None) == {"decision": "deny", "code": "bad_request", "labels": []}
    assert cs([], rs_signer="x") == {"decision": "deny", "code": "bad_request", "labels": []}
    assert cs([], sink=5) == {"decision": "deny", "code": "bad_request", "labels": []}
    assert cs([], sink="nope") == {"decision": "deny", "code": "unknown_sink", "labels": []}
    assert cs("x") == {"decision": "deny", "code": "bad_receipt", "labels": []}
    assert cs([]) == {"decision": "allow", "code": None, "labels": []}
    assert cs([_rr()]) == {"decision": "allow", "code": None, "labels": ["a"]}
    both = _rr(fields={"x": _f("a"), "y": _f("b")}, labels=["a", "b"])
    assert cs([both]) == {"decision": "escalate", "code": "label_escalate", "labels": ["a", "b"]}
    flow = _rr(fields={"x": _f("b"), "y": _f("c")}, labels=["b", "c"])
    assert cs([flow]) == {"decision": "deny", "code": "label_flow", "labels": ["b", "c"]}


# ================================================================================================================ read_vault


def _det(**over):
    store = RV.memory_vault()
    store.put("t", {"cls": "a", "value": "V", "grant": GD, "exp": 200})
    d = {"grant": GRANT, "principal": KP.public, "now": 150, "sink": "ok", "token": "t", "store": store}
    d.update(over)
    return d


def _no(code):
    return {"decision": "deny", "code": code, "value": None}


def _stored(**e):
    s = RV.memory_vault()
    s.put("t", dict({"cls": "a", "value": "V", "grant": GD, "exp": 200}, **e))
    return s


def test_detokenize_every_outcome():
    d = RV.detokenize
    assert d(_det()) == {"decision": "allow", "code": None, "value": "V"}
    for over in ({"principal": "x"}, {"now": "x"}, {"now": -1}, {"token": 5}, {"sink": 5}):
        assert d(_det(**over)) == _no("bad_request"), over
    assert d(None) == _no("bad_request") and d(_det(store=None)) == _no("bad_request")
    for g in (None, dict(GRANT, extra=1), {"body": {}, "sig": "x"}):
        assert d(_det(grant=g)) == _no("bad_grant")
    assert d(_det(principal=KP2.public)) == _no("bad_signature")
    assert d(_det(grant={"body": GRANT["body"], "sig": "A" * 86})) == _no("bad_signature")
    assert d(_det(now=99)) == _no("not_yet") and d(_det(now=200)) == _no("expired")
    assert d(_det(now=100))["decision"] == "allow" and d(_det(now=199))["decision"] == "allow"
    assert d(_det(token="nope")) == _no("unknown_token")
    assert d(_det(store=_stored(grant="other"))) == _no("unknown_token")
    assert d(_det(store=_stored(exp=150))) == _no("expired")
    assert d(_det(store=_stored(exp=151)))["decision"] == "allow"
    assert d(_det(sink="nope")) == _no("unknown_sink")
    assert d(_det(store=_stored(cls="b"))) == {"decision": "escalate", "code": "label_escalate", "value": None}
    assert d(_det(store=_stored(cls="c"))) == _no("label_flow")


def test_vault_records_only_tokens_and_passes_a_refusal_through():
    s = RV.memory_vault()
    assert RV.redact_read_with_vault(_inp(now=99), s)["code"] == "not_yet"
    inp = _inp(schema={"fields": {"f": "a", "g": "e", "h": "d"}, "required": []}, record={"f": "v", "g": "w", "h": "x"})
    r = RV.redact_read_with_vault(inp, s)
    assert r == RS.redact_read(inp)
    assert s._m == {r["view"]["g"]: {"cls": "e", "value": "w", "grant": GD, "exp": 200}}
    assert s.get("nope") is None
    assert isinstance(RV.memory_vault(), RV.MemoryVault)


AG_RULES = [
    {"verb": "q.exact", "resource_prefix": "r/", "purposes": ["x"], "fns": ["count", "sum"], "min_group": 2, "clamp": 10, "epsilon_micro": 0, "dp": False},
    {"verb": "q.one", "resource_prefix": "r/", "purposes": ["x"], "fns": ["count"], "min_group": 1, "clamp": 10, "epsilon_micro": 0, "dp": False},
    {"verb": "q.dp", "resource_prefix": "r/", "purposes": ["x"], "fns": ["count", "sum"], "min_group": 1, "clamp": 3, "epsilon_micro": 500000, "dp": True},
    {"verb": "q.zero", "resource_prefix": "r/", "purposes": ["x"], "fns": ["count", "sum"], "min_group": 1, "clamp": 0, "epsilon_micro": 500000, "dp": True},
]
AG_BODY = {"v": 1, "id": "ag", "principal": KP.public, "issued_at": 100, "expires_at": 200, "rules": AG_RULES, "epsilon_budget_micro": 1_000_000, "max_queries": 2}
AG = sign_aggregate_grant(KP, AG_BODY)
AG_SALT = "a-per-read-secret-salt"


def _ag(**over):
    i = {"grant": AG, "principal": KP.public, "now": 150, "verb": "q.exact", "resource": "r/1", "purpose": "x", "fn": "sum", "values": [1, 20, -30],
         "salt": AG_SALT, "noise": "seeded", "state": RV.empty_aggregate_state()}
    i.update(over)
    return i


def _qd(verb, fn, n, s, resource="r/1", purpose="x"):
    return hash_canonical({"d": "atlas-pca/aggregate-query/v1", "g": RV.aggregate_grant_digest(AG_BODY), "verb": verb, "resource": resource,
                           "purpose": purpose, "fn": fn, "n": n, "s": s})


def test_aggregate_exact_answers_and_state():
    st = RV.empty_aggregate_state()
    assert st == {"spent_micro": 0, "queries": 0, "answered": {}}
    r = RV.aggregate_read(_ag(state=st))
    q = _qd("q.exact", "sum", 3, 1)
    assert r == {"decision": "allow", "code": None, "value": 1, "charged_micro": 0, "state": {"spent_micro": 0, "queries": 1, "answered": {q: 1}}}
    assert st == {"spent_micro": 0, "queries": 0, "answered": {}}  # the input state is never mutated
    again = RV.aggregate_read(_ag(state=r["state"]))
    assert again == {"decision": "allow", "code": None, "value": 1, "state": r["state"], "charged_micro": 0}
    c = RV.aggregate_read(_ag(fn="count", state=r["state"]))
    q2 = _qd("q.exact", "count", 3, 1)
    assert c == {"decision": "allow", "code": None, "value": 3, "charged_micro": 0, "state": {"spent_micro": 0, "queries": 2, "answered": {q: 1, q2: 3}}}
    assert RV._clamped([5, -5, 11, -11], 10) == 0 and RV._clamped([11], 10) == 10 and RV._clamped([-11], 10) == -10 and RV._clamped([], 1) == 0


def test_aggregate_refusals_keep_the_state():
    held = {"spent_micro": 1, "queries": 0, "answered": {}}

    def code(**over):
        r = RV.aggregate_read(_ag(state=held, **over))
        assert (r["decision"], r["value"], r["state"], r["charged_micro"]) == ("deny", None, held, 0), r
        return r["code"]
    for over in ({"principal": "x"}, {"now": "x"}, {"now": -1}, {"verb": "v" * 129}, {"verb": ""}, {"resource": "r" * 513}, {"purpose": "bad p"},
                 {"fn": "avg"}, {"fn": 5}, {"noise": "weak"}, {"noise": 5}, {"salt": "s" * 15}, {"salt": 5}, {"values": "x"}, {"values": [1.5]},
                 {"values": [True]}, {"values": [2 ** 53]}, {"values": [0] * 1_000_001}):
        assert code(**over) == "bad_request", str(over)[:80]
    for g in (None, dict(AG, extra=1), {"body": {}, "sig": "x"}):
        assert code(grant=g) == "bad_grant"
    assert code(principal=KP2.public) == "bad_signature"
    assert code(grant={"body": AG_BODY, "sig": "A" * 86}) == "bad_signature"
    assert code(now=99) == "not_yet" and code(now=200) == "expired"
    for over in ({"verb": "q.none"}, {"resource": "z/1"}, {"purpose": "y"}, {"verb": "q.one", "fn": "sum"}):
        assert code(**over) == "no_read_scope", over
    assert code(values=[1]) == "group_too_small"


def test_aggregate_bad_state_is_replaced_with_an_empty_one():
    empty = RV.empty_aggregate_state()
    for st in (None, 5, {}, {"spent_micro": -1, "queries": 0, "answered": {}}, {"spent_micro": 0, "queries": -1, "answered": {}},
               {"spent_micro": 0, "queries": 0, "answered": None}, {"spent_micro": 0, "queries": 0, "answered": {"q": 1.5}},
               {"spent_micro": 0, "queries": 0, "answered": {"q": True}}):
        assert RV.aggregate_read(_ag(state=st)) == {"decision": "deny", "code": "bad_request", "value": None, "state": empty, "charged_micro": 0}


def test_aggregate_edges_that_pass():
    assert RV.aggregate_read(_ag(values=[1, 2]))["value"] == 3  # min_group exactly
    assert RV.aggregate_read(_ag(now=100))["decision"] == "allow" and RV.aggregate_read(_ag(now=199))["decision"] == "allow"
    assert RV.aggregate_read(_ag(salt="s" * 16))["decision"] == "allow"
    assert RV.aggregate_read(_ag(salt="\U0001F600" * 8))["decision"] == "allow"  # UTF-16 units, as the reference counts
    assert RV.aggregate_read(_ag(verb="q.one", fn="count", values=[0] * 1_000_000))["value"] == 1_000_000
    assert RV.aggregate_read(_ag(resource="r/" + "x" * 510))["decision"] == "allow"


def test_aggregate_budgets_and_prior_answers():
    q = _qd("q.exact", "sum", 3, 1)
    capped = {"spent_micro": 0, "queries": 2, "answered": {}}
    assert RV.aggregate_read(_ag(state=capped))["code"] == "query_cap"
    assert RV.aggregate_read(_ag(state=dict(capped, queries=1)))["decision"] == "allow"
    prior = {"spent_micro": 0, "queries": 2, "answered": {q: 77}}  # a repeat is free even at the cap
    assert RV.aggregate_read(_ag(state=prior)) == {"decision": "allow", "code": None, "value": 77, "state": prior, "charged_micro": 0}
    assert RV.aggregate_read(_ag(verb="q.dp", state={"spent_micro": 500001, "queries": 0, "answered": {}}))["code"] == "epsilon_exhausted"
    r = RV.aggregate_read(_ag(verb="q.dp", state={"spent_micro": 500000, "queries": 0, "answered": {}}))
    assert (r["decision"], r["charged_micro"], r["state"]["spent_micro"], r["state"]["queries"]) == ("allow", 500000, 1_000_000, 1)
    # a query the budget cannot pay for when dp is off costs nothing
    assert RV.aggregate_read(_ag(state={"spent_micro": 1_000_000, "queries": 0, "answered": {}}))["charged_micro"] == 0


def _seed(q):
    return hash_canonical({"d": "atlas-pca/aggregate-noise/v1", "salt": AG_SALT, "q": q})


def test_aggregate_seeded_noise_is_the_exact_stream():
    # sum: clamp 3 -> s = 3, sensitivity 3 x 1e6; count: sensitivity 1 x 1e6
    r = RV.aggregate_read(_ag(verb="q.dp"))
    q = _qd("q.dp", "sum", 3, 1 + 3 - 3)
    assert r["value"] == 1 + RV.discrete_laplace(RV.seeded_draws(_seed(q)), 500000, 3_000_000)
    assert r["state"]["answered"] == {q: r["value"]} and r["charged_micro"] == 500000
    r = RV.aggregate_read(_ag(verb="q.dp", fn="count"))
    q = _qd("q.dp", "count", 3, 1)
    assert r["value"] == 3 + RV.discrete_laplace(RV.seeded_draws(_seed(q)), 500000, 1_000_000)
    # count needs no clamp; sum with clamp 0 has no sensitivity: the sampler refuses, and the state is NOT kept
    assert RV.aggregate_read(_ag(verb="q.zero", fn="count"))["decision"] == "allow"
    held = {"spent_micro": 1, "queries": 0, "answered": {}}
    assert RV.aggregate_read(_ag(verb="q.zero", fn="sum", state=held)) == \
        {"decision": "deny", "code": "bad_request", "value": None, "state": RV.empty_aggregate_state(), "charged_micro": 0}


def test_aggregate_secure_noise_uses_the_secure_source(monkeypatch):
    monkeypatch.setattr(RV, "secure_draws", lambda: RV.seeded_draws("fixed"))
    r = RV.aggregate_read(_ag(verb="q.dp", fn="count", noise="secure"))
    assert r["value"] == 3 + RV.discrete_laplace(RV.seeded_draws("fixed"), 500000, 1_000_000)


def test_secure_draws_seed(monkeypatch):
    asked = []

    def bytes_(n):
        asked.append(n)
        return b"\x07" * n
    monkeypatch.setattr(RV.secrets, "token_bytes", bytes_)
    d = RV.secure_draws()
    assert asked == [32] and isinstance(d, RV.SeededDraws)
    assert d._seed == b64u(b"\x07" * 32)


def test_valid_grant_body_keys():
    assert RV.valid_aggregate_grant_body(AG_BODY) is True
    for over in ({"id": "bad id"}, {"principal": "x"}, {"issued_at": -1}, {"expires_at": "x"}, {"rules": "x"}, {"epsilon_budget_micro": -1}, {"max_queries": -1},
                 {"extra": 1}):
        assert RV.valid_aggregate_grant_body(dict(AG_BODY, **over)) is False, over
    assert RV.valid_aggregate_grant_body(None) is False
    assert RV._valid_rule(None) is False
    assert RV.aggregate_grant_digest(AG_BODY) == hash_canonical({"d": "atlas-pca/aggregate-grant-ref/v1", "g": AG_BODY})


# ---- the sampler


class _Script:
    """A draw source replaying a script, recording every bound it was asked for."""

    def __init__(self, *draws):
        self.draws, self.bounds = list(draws), []

    def uniform(self, n):
        self.bounds.append(n)
        return self.draws.pop(0)


def test_uniform_bounds_and_rejection(monkeypatch):
    d = RV.seeded_draws("seed")
    assert d.uniform(1) == 0
    assert 0 <= d.uniform(2 ** 47) < 2 ** 47
    for bad in (0, -1, 2 ** 47 + 1, True, 1.5, "1"):
        with pytest.raises(RV.SamplerRangeError) as e:
            d.uniform(bad)
        assert str(e.value) == "uniform: bad bound"
    assert RV._MAX_STEPS == 100_000 and RV._TWO48 == 2 ** 48
    # n = 3: the limit is 2^48 - 1; that value and above are rejected, one below is reduced
    d = RV.seeded_draws("seed")
    feed = [2 ** 48 - 1, 2 ** 48 - 2]
    monkeypatch.setattr(d, "_next48", lambda: feed.pop(0))
    assert d.uniform(3) == (2 ** 48 - 2) % 3 and feed == []
    monkeypatch.setattr(RV, "_MAX_STEPS", 4)
    calls = []

    def always_high():
        calls.append(1)
        return 2 ** 48 - 1
    monkeypatch.setattr(d, "_next48", always_high)
    with pytest.raises(RV.SamplerRangeError) as e:
        d.uniform(3)
    assert str(e.value) == "uniform: no draw" and len(calls) == 4


def test_seeded_stream_blocks():
    raw = RV.decode_b64u_strict(hash_canonical({"d": "atlas-pca/dp-stream/v1", "seed": "s", "i": 0}), 32)
    raw2 = RV.decode_b64u_strict(hash_canonical({"d": "atlas-pca/dp-stream/v1", "seed": "s", "i": 1}), 32)
    d = RV.seeded_draws("s")
    want = [int.from_bytes(raw[k * 6:k * 6 + 6], "big") for k in range(5)] + [int.from_bytes(raw2[:6], "big")]
    assert [d._next48() for _ in range(6)] == want


def test_bern_exp_small(monkeypatch):
    d = _Script(5)  # k = 1: not below num: stops at an odd k
    assert RV._bern_exp_small(d, 5, 10) is True and d.bounds == [10]
    d = _Script(4, 5)  # k = 2: an even k
    assert RV._bern_exp_small(d, 5, 10) is False and d.bounds == [10, 20]
    d = _Script(4, 4, 5)
    assert RV._bern_exp_small(d, 5, 10) is True and d.bounds == [10, 20, 30]
    monkeypatch.setattr(RV, "_MAX_STEPS", 2)
    d = _Script(0, 0)
    with pytest.raises(RV.SamplerRangeError) as e:
        RV._bern_exp_small(d, 1, 10)
    assert str(e.value) == "bernoulli: no termination" and d.bounds == [10, 20]


def test_discrete_laplace_paths(monkeypatch):
    for s, t in ((0, 1), (1, 0), (True, 1), (1, True), (1.5, 1), (1, 1.5), (-1, 1)):
        with pytest.raises(RV.SamplerRangeError) as e:
            RV.discrete_laplace(_Script(), s, t)
        assert str(e.value) == "laplace: bad parameters"
    # u = 2, accept (uniform(3) = 2, not below 2); v = 0 (0 < 1, then 1 at k = 2: an even stop); positive
    d = _Script(2, 2, 0, 1, 0)
    assert RV.discrete_laplace(d, 1, 3) == 2 and d.bounds == [3, 3, 1, 2, 2]
    # the same, negative
    assert RV.discrete_laplace(_Script(2, 2, 0, 1, 1), 1, 3) == -2
    # v = 1 (5 at k = 1: an odd stop, then the even stop); y = (u + t v) // s floors
    d = _Script(2, 2, 5, 0, 1, 0)
    assert RV.discrete_laplace(d, 2, 3) == (2 + 3) // 2 and d.bounds == [3, 3, 1, 1, 2, 2]
    # a rejected u retries: uniform(10) = 1 is below u = 2 at k = 1, 3 at k = 2 stops even: false
    d = _Script(2, 1, 3, 4, 4, 0, 1, 0)
    assert RV.discrete_laplace(d, 1, 10) == 4 and d.bounds == [10, 10, 20, 10, 10, 1, 2, 2]
    # negative zero is resampled: u = 0, y = 0, negative; then a positive 0
    d = _Script(0, 0, 0, 1, 1, 0, 0, 0, 1, 0)
    assert RV.discrete_laplace(d, 1, 3) == 0 and d.draws == []


def test_discrete_laplace_limits(monkeypatch):
    monkeypatch.setattr(RV, "_MAX_STEPS", 2)

    class Always:
        def __init__(self, v):
            self.v = v

        def uniform(self, n):
            return self.v
    with pytest.raises(RV.SamplerRangeError) as e:
        RV.discrete_laplace(Always(5), 1, 10)  # u = 5 accepted; every geometric draw says go on: v passes the bound
    assert str(e.value) == "laplace: no termination"
    d = _Script(2, 1, 3, 2, 1, 3)  # both outer rounds reject u
    with pytest.raises(RV.SamplerRangeError) as e:
        RV.discrete_laplace(d, 1, 10)
    assert str(e.value) == "laplace: no sample" and d.draws == []
