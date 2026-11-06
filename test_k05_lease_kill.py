"""Lease kill tests of the 0.5 full mutation baseline: _well_formed's holder/requester and expiry rules on a real signed
record, sod_error's exact reasons, the registry history entry, idempotent revocation, and the fail-closed
store_unreachable paths (a registry without authorities never raises; a store fault in accept is a refusal)."""
import copy

from atlas_pca import lease as M
from test_lease_vectors import DOC

R0 = DOC["records"][0]
REV = next(DOC["revocations"][st["revocation"]] for s in DOC["scenarios"] for st in s["steps"]
           if st["op"] == "revoke" and st["expect"].get("ok"))


def test_well_formed_rules():
    assert M._well_formed(R0) is True
    for over in ({"holder": 5}, {"requester": 5}, {"lease_id": ""}, {"seq": 2, "renewed_at": R0["expires_at"]},
                 {"seq": 2, "renewed_at": R0["issued_at"] + 1, "expires_at": R0["issued_at"] + 1},
                 {"renewed_at": R0["issued_at"] - 1}, {"seq": 1, "renewed_at": R0["issued_at"] + 1}):
        assert M._well_formed(dict(R0, **over)) is False, over
    assert M._well_formed(dict(R0, seq=2, renewed_at=R0["issued_at"] + 1)) is True


def test_sod_reasons():
    l = {"approvers": ["bob"], "requester": "alice", "holder": "agent"}
    assert M.sod_error(l, {"minApprovals": 0}) == "minApprovals must be a positive integer"
    assert M.sod_error(l, {"minApprovals": -1}) == "minApprovals must be a positive integer"
    assert M.sod_error(l, {"minApprovals": 1.5}) == "minApprovals must be a positive integer"
    assert M.sod_error({"approvers": ["bob", "bob"], "requester": "alice", "holder": "agent"}) == "an approver is listed twice"
    assert M.sod_error({"approvers": ["alice"], "requester": "alice", "holder": "agent"}) == "the requester may not approve their own request"


def test_history_entry_and_store_fault():
    reg = M.LeaseRegistry({"authorities": [DOC["authority"]]})
    assert reg.accept(R0) == {"ok": True, "replaced": True, "seq": 1}
    assert reg.leases[R0["lease_id"]]["history"] == [{"seq": 1, "renewed_at": R0["renewed_at"], "expires_at": R0["expires_at"],
                                                      "justification_digest": R0["justification_digest"]}]
    def boom(*_a):
        raise RuntimeError("store down")
    reg._accept = boom
    assert reg.accept(R0) == {"ok": False, "code": "store_unreachable"}


def test_revoke_is_idempotent_and_needs_authorities():
    reg = M.LeaseRegistry({"authorities": [REV["authority"]]})
    assert reg.revoke(copy.deepcopy(REV)) == {"ok": True, "revoked": 0}
    assert reg.revoke(copy.deepcopy(REV)) == {"ok": True, "revoked": 0}
    assert len(reg.revocations) == 1
    assert M.LeaseRegistry({}).revoke(REV) == {"ok": False, "code": "unknown_authority"}
