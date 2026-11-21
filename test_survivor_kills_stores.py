"""Exact-result kills for break-glass, lease, blueprint stores, the forbid-wins certificate and the taint gate: every
fail-closed refusal is compared whole, every pinned key is read back from the store, and every defaulted argument is exercised."""
import collections

import pytest

import test_k05_kill_stores_grants as S
import test_k05_lease_kill as LK
import test_k05f_g_taint as TT
from atlas_pca import blueprint as BP
from atlas_pca import break_glass as BG
from atlas_pca import forbid_certificate as FC
from atlas_pca import lease as L
from atlas_pca import taint as T
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.pca import hash_canonical

T0 = S.T0


# ===================================================================================================== break_glass

def _policy():
    return {"authorities": [S.KP.public], "reviewers": [S.REVIEWER.public]}


def test_break_glass_pins_its_shard_count_under_the_meta_key():
    reg = S._bgreg()
    assert reg.accept(S._bg(), T0) == {"ok": True, "replaced": True}
    assert reg.kv.get("breakglass/meta") == {"v": 1, "shards": BG.DEFAULT_LEASE_SHARDS}
    wide = BG.BreakGlassRegistry(_policy(), MemoryAtomicKv(), shards=3)
    wide.accept(S._bg(), T0)
    assert wide.kv.get("breakglass/meta") == {"v": 1, "shards": 3}


def test_a_store_pinned_to_another_shard_count_refuses_everything():
    kv = MemoryAtomicKv()
    kv.update("breakglass/meta", lambda _p: {"v": 1, "shards": BG.DEFAULT_LEASE_SHARDS + 1})
    reg = BG.BreakGlassRegistry(_policy(), kv)
    assert reg.accept(S._bg(), T0) == {"ok": False, "code": "store_unreachable"}
    assert reg.use("b1", "agent", "a", T0, True) == {"decision": "deny", "code": "store_unreachable", "id": "b1"}
    assert reg.review(S._rv(), "agent", T0 + 9) == {"ok": False, "code": "store_unreachable"}
    assert reg.frozen("agent", T0) is True
    assert reg.uses("agent", "b1") == []


def test_use_by_another_holder_of_the_same_shard_is_wrong_holder():
    reg = BG.BreakGlassRegistry(_policy(), MemoryAtomicKv(), shards=1)
    reg.accept(S._bg(), T0)
    assert reg.use("b1", "other", "a", T0, True) == {"decision": "deny", "code": "wrong_holder", "id": "b1"}
    assert reg.use("b1", "agent", "a", T0, True)["decision"] == "allow"


def _entry(holder, review=None):
    e = {"rec": {"holder": holder, "review_within": 100}, "uses": []}
    if review is not None:
        e["review"] = review
    return e


def test_frozen_in_skips_other_holders_and_keeps_looking():
    bad = {"outcome": "unjustified"}
    assert BG._frozen_in({"o": _entry("other", bad), "t": _entry("target")}, "target", T0) is False
    assert BG._frozen_in({"o": _entry("other"), "t": _entry("target", bad)}, "target", T0) is True
    assert BG._frozen_in({"o": _entry("other", bad), "t": _entry("target", bad)}, "target", T0) is True


# ========================================================================================================== lease

def test_shard_of_is_the_first_four_bytes_big_endian_of_sha256():
    assert [L.shard_of("L1", n) for n in (7, 16, 4096)] == [6, 6, 1430]
    assert [L.shard_of("lease-a", n) for n in (7, 16, 4096)] == [0, 15, 2703]
    assert [L.shard_of("agent", n) for n in (7, 16, 4096)] == [1, 10, 3162]
    assert [L.shard_of("été", n) for n in (7, 16, 4096)] == [3, 4, 3172]


def test_the_default_clock_is_wall_clock_milliseconds(monkeypatch):
    monkeypatch.setattr(L.time, "time", lambda: 1234.5678)
    reg = L.LeaseRegistry({"authorities": []}, MemoryAtomicKv())
    now = reg._clock()
    assert now == 1234567 and type(now) is int


def test_lease_pins_its_shard_count_under_the_meta_key():
    reg = L.LeaseRegistry({"authorities": [LK.DOC["authority"]]}, MemoryAtomicKv())
    assert reg.accept(LK.R0) == {"ok": True, "replaced": True, "seq": 1}
    assert reg.kv.get("lease/meta") == {"v": 1, "shards": L.DEFAULT_LEASE_SHARDS}


def test_a_store_pinned_to_another_shard_count_raises_on_every_read():
    kv = MemoryAtomicKv()
    kv.update("lease/meta", lambda _p: {"v": 1, "shards": L.DEFAULT_LEASE_SHARDS + 1})
    reg = L.LeaseRegistry({"authorities": [LK.DOC["authority"]]}, kv)
    for call in (reg.get, reg.history, reg.lookup):
        with pytest.raises(RuntimeError) as e:
            call("L1")
        assert str(e.value) == "shard count mismatch"
    assert reg.accept(LK.R0) == {"ok": False, "code": "store_unreachable"}


@pytest.mark.parametrize("i", [True, False, -1, 16, 17, "1", 1.0, None])
def test_shard_revocations_refuses_anything_but_a_real_shard_index(i):
    reg = L.LeaseRegistry({"authorities": []}, MemoryAtomicKv())
    with pytest.raises(ValueError) as e:
        reg.shard_revocations(i)
    assert str(e.value) == "no such shard"


def test_shard_revocations_returns_the_list_of_a_valid_index():
    reg = L.LeaseRegistry({"authorities": []}, MemoryAtomicKv())
    assert reg.shard_revocations(0) == [] and reg.shard_revocations(15) == []


def _revoked_sigs(reg):
    return {r["sig"] for i in range(reg.shard_count) for r in reg.shard_revocations(i)}


def test_a_revocation_is_pruned_once_its_ceiling_window_has_passed():
    rev = LK.REV
    ceiling = 1000
    stale = L.LeaseRegistry({"authorities": [rev["authority"]], "maxTtlCeiling": ceiling}, MemoryAtomicKv(),
                            clock=lambda: rev["revoked_at"] + ceiling + 1)
    assert stale.revoke(dict(rev)) == {"ok": True, "revoked": 0}
    assert _revoked_sigs(stale) == set()
    edge = L.LeaseRegistry({"authorities": [rev["authority"]], "maxTtlCeiling": ceiling}, MemoryAtomicKv(),
                           clock=lambda: rev["revoked_at"] + ceiling)
    assert edge.revoke(dict(rev)) == {"ok": True, "revoked": 0}
    assert _revoked_sigs(edge) == {rev["sig"]}


# ====================================================================================================== blueprint

def test_the_memory_store_keeps_its_own_copy_of_a_record():
    st = BP.MemoryBlueprintStore()
    b = {"key": "k", "epoch": 1, "ceiling": [{"type": "t"}]}
    st.put(b)
    b["ceiling"].append({"type": "u"})
    b["ceiling"][0]["type"] = "changed"
    assert st.get("k")["ceiling"] == [{"type": "t"}]
    assert st.max_epoch() == 1


class _Half:
    def __init__(self, **names):
        for n, v in names.items():
            setattr(self, n, v)


@pytest.mark.parametrize("kv", [None, {}, {"get": 1}, 5, _Half(get=lambda k: None), _Half(update=lambda k, f: None),
                                _Half(get=5, update=lambda k, f: None), _Half(get=lambda k: None, update=5)])
def test_the_kv_blueprint_store_needs_a_real_kv(kv):
    with pytest.raises(TypeError) as e:
        BP.KvBlueprintStore(kv)
    assert str(e.value) == "KvBlueprintStore: a key-value store with get and update is required"


def test_the_kv_blueprint_store_layout_and_epoch_high_water_mark():
    kv = MemoryAtomicKv()
    st = BP.KvBlueprintStore(kv)
    assert st.max_epoch() == 0
    st.put({"key": "k", "epoch": 5})
    assert kv.get("blueprint/rec/k") == {"key": "k", "epoch": 5} and st.get("k") == {"key": "k", "epoch": 5}
    assert kv.get("blueprint/max_epoch") == 5
    st.put({"key": "k2", "epoch": 3})
    assert st.max_epoch() == 5
    st.put({"key": "k3", "epoch": 5})
    assert st.max_epoch() == 5
    st.put({"key": "k4", "epoch": 9})
    assert st.max_epoch() == 9 and kv.get("blueprint/max_epoch") == 9


@pytest.mark.parametrize("store", [None, _Half(), _Half(get=lambda k: None, put=lambda b: None), _Half(get=lambda k: None, max_epoch=lambda: 0),
                                   _Half(put=lambda b: None, max_epoch=lambda: 0), _Half(get=5, put=5, max_epoch=5),
                                   _Half(get=lambda k: None, put=lambda b: None, max_epoch=0)])
def test_the_registry_needs_a_complete_store(store):
    with pytest.raises(TypeError) as e:
        BP.BlueprintRegistry(["op"], store)
    assert str(e.value) == "BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintStore is for tests and single-process use)"
    BP.BlueprintRegistry(["op"], _Half(get=lambda k: None, put=lambda b: None, max_epoch=lambda: 0))


def test_the_admission_hook_is_called_with_the_instance_key_and_the_blueprint():
    bp = {"id": "bp1", "key": "BPK", "status": "active", "ceiling": [], "runtime_pins": [{"model_id": "m"}], "epoch": 1, "operator": "op"}
    store = BP.MemoryBlueprintStore()
    store.put(bp)
    reg = BP.BlueprintRegistry(["op"], store)
    chain = [{"issuer": "root", "holder": "BPK"}, {"issuer": "BPK", "holder": "inst"}]
    seen = []

    def admitted(holder, b):
        seen.append((holder, b))
        return True
    assert BP.check_blueprints(chain, reg, T0, "require", admitted=admitted) == {"decision": "allow", "governed": ["bp1"]}
    assert seen == [("inst", bp)]
    assert BP.check_blueprints(chain, reg, T0, "require", admitted=lambda h, b: b is not None and h == "inst" and "yes") == {
        "decision": "deny", "code": "not_admitted", "blueprint": "bp1"}


# ============================================================================================== forbid certificate

CTX = {"action": {"verb": "v", "resource": "/x"}}
FORBIDS = [{"id": "a-forbid", "kind": "forbid", "signer": "user", "when": {"verb": "v"}},
           {"id": "b-forbid", "kind": "forbid", "signer": "org", "when": {"verb": "v"}}]
PERMITS = [{"id": "p1", "kind": "permit", "signer": "user", "when": {"verb": "v"}},
           {"id": "p2", "kind": "permit", "signer": "org", "when": {"verb": "v"}}]


def test_certify_orders_forbids_by_precedence_then_id():
    plain = FC.certify(FORBIDS, CTX)
    assert plain["winner"] == {"kind": "forbid", "id": "a-forbid"} and plain["shadowed"] == ["b-forbid"]
    ranked = FC.certify(FORBIDS, CTX, ["org"])
    assert ranked["winner"] == {"kind": "forbid", "id": "b-forbid"} and ranked["shadowed"] == ["a-forbid"]


def test_certify_drops_permits_of_other_signers_and_lists_each_signer():
    cert = FC.certify(PERMITS, CTX, None, ["org"])
    assert cert == {"v": 1, "kind": "forbid-wins", "policy": hash_canonical(PERMITS), "action": hash_canonical(CTX), "decision": "allow",
                    "winner": {"kind": "permit", "id": "p2"}, "shadowed": [],
                    "clauses": [{"id": "p1", "kind": "permit", "signer": "user", "value": "false"},
                                {"id": "p2", "kind": "permit", "signer": "org", "value": "true"}]}
    assert FC.certify(PERMITS, CTX)["winner"] == {"kind": "permit", "id": "p1"}
    assert FC.certify(PERMITS, CTX, ["org"])["winner"] == {"kind": "permit", "id": "p1"}  # precedence never filters permits


def test_certify_of_a_malformed_policy_has_no_rows():
    cert = FC.certify("not a list", CTX)
    assert cert["clauses"] == [] and cert["winner"] == {"kind": "malformed", "id": None} and cert["decision"] == "deny"


def test_check_recomputes_with_the_same_precedence_and_permit_signers():
    cert = FC.certify(FORBIDS, CTX, ["org"])
    assert FC.check_forbid_certificate(cert, FORBIDS, CTX, ["org"]) == {"ok": True}
    assert FC.check_forbid_certificate(cert, FORBIDS, CTX) == {"ok": False, "reason": "certificate table does not entail its decision"}
    assert FC.check_forbid_certificate(cert, FORBIDS, CTX, ["user"]) == {"ok": False, "reason": "certificate table does not entail its decision"}
    cert2 = FC.certify(PERMITS, CTX, None, ["org"])
    assert FC.check_forbid_certificate(cert2, PERMITS, CTX, None, ["org"]) == {"ok": True}
    assert FC.check_forbid_certificate(cert2, PERMITS, CTX) == {"ok": False, "reason": "certificate does not match the recomputed decision"}
    assert FC.check_forbid_certificate(cert2, PERMITS, CTX, ["org"], ["org"]) == {"ok": True}
    assert FC.check_forbid_certificate(cert2, PERMITS, CTX, None, ["user"]) == {"ok": False, "reason": "certificate does not match the recomputed decision"}


def test_check_fails_closed_on_a_fault(monkeypatch):
    cert = FC.certify(FORBIDS, CTX)

    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr(FC, "certificate_consistent", boom)
    assert FC.check_forbid_certificate(cert, FORBIDS, CTX) == {"ok": False, "reason": "certificate check error (fail closed)"}


def test_only_a_real_dict_context_carries_an_action():
    class Lookalike:
        def get(self, key, default=None):
            return {"verb": "v", "resource": "/x"} if key == "action" else default
    r = FC.decide_clauses([], Lookalike())
    assert r["decision"] == "deny" and r["witness"]["winner"] == {"kind": "malformed", "id": None} and r["values"] == []
    assert FC.decide_clauses([], collections.UserDict(CTX))["witness"]["winner"] == {"kind": "malformed", "id": None}
    assert FC.decide_clauses([], CTX)["witness"]["winner"] == {"kind": "none", "id": None}


# ================================================================================================================ taint

def test_a_provenance_without_trusted_refs_is_a_valid_empty_lineage():
    r = T.compute_taint({}, TT.reg())
    assert r == {"taint": 1.0, "label": {"kind": "agent"}, "refs": [], "valid": True}


def test_the_resource_graph_vouches_for_first_party_refs():
    g = TT.Graph("g1")
    r = T.compute_taint(TT.prov("g1"), TT.reg(), g)
    assert r["refs"] == [{"ref": "g1", "label": {"kind": "first_party"}}] and r["label"] == {"kind": "first_party"} and r["taint"] == 0.25
    assert T.compute_taint(TT.prov("g1"), TT.reg())["label"] == {"kind": "agent", "id": "g1"}
    assert T.taint_gate(TT.prov("g1"), TT.reg(), g, 0.25) == {"ok": True}
    assert T.taint_gate(TT.prov("g1"), TT.reg(), g, 0) == {"ok": False, "reason": "information-flow taint 0.25 exceeds policy max 0"}
    assert T.taint_gate(TT.prov("g1"), TT.reg(), None, 0.25)["ok"] is False


def test_the_gate_has_a_default_reason_for_an_invalid_lineage_without_one(monkeypatch):
    for t in ({"valid": False}, {"valid": False, "reason": ""}, {"valid": False, "reason": None}):
        monkeypatch.setattr(T, "compute_taint", lambda *a, _t=t: _t)
        assert T.taint_gate(None, None, None, 1) == {"ok": False, "reason": "provenance lineage is not server-verifiable (fail closed)"}
    monkeypatch.setattr(T, "compute_taint", lambda *a: {"valid": False, "reason": "own reason"})
    assert T.taint_gate(None, None, None, 1) == {"ok": False, "reason": "own reason"}


def test_the_gate_fails_closed_with_the_fault_text(monkeypatch):
    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(T, "compute_taint", boom)
    assert T.taint_gate(TT.prov("d-trusted"), TT.reg(), None, 1) == {"ok": False, "reason": "taint gate error (fail closed): boom"}


def test_the_gate_admits_exactly_the_ranks_up_to_the_bound():
    r = TT.reg()
    for ref, taint in (("d-trusted", 0), ("d-first", 0.25), ("d-tool", 0.5), ("d-web", 0.75), ("zz", 1)):
        for mx in (0, 0.24, 0.25, 0.49, 0.5, 0.74, 0.75, 0.99, 1, 5):
            assert T.taint_gate(TT.prov(ref), r, None, mx)["ok"] is (taint <= mx), (ref, mx)
