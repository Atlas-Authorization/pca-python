"""Durable state for leases, break-glass grants and blueprints (reference lease.ts / breakglass.ts / blueprint.ts): every registry REQUIRES a
store; the shared scenarios give the same answers when every step runs on a NEW registry over the same store (nothing lives in the
process); a throwing store is `store_unreachable`; the shard count is pinned in the store; lease revocations are pruned past the TTL ceiling."""
import json
import os
import threading

import pytest

from atlas_pca.atomic_kv import MemoryAtomicKv, SqliteAtomicKv
from atlas_pca.blueprint import BlueprintRegistry, KvBlueprintStore, MemoryBlueprintStore, check_blueprints
from atlas_pca.break_glass import BreakGlassRegistry
from atlas_pca.lease import DEFAULT_LEASE_SHARDS, LeaseRegistry, check_lease, shard_of

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    for p in (os.path.join(_HERE, "conformance", name), os.path.join(_HERE, "conformance", name)):
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(name)


LD, BD, PD = _load("lease-vectors.json"), _load("break-glass-vectors.json"), _load("blueprint-vectors.json")


class DownKv:
    def get(self, key):
        raise RuntimeError("down")

    def update(self, key, fn):
        raise RuntimeError("down")


# ---- a store is required -----------------------------------------------------------------------------------------------------

class Half:
    def get(self, key):
        return None


@pytest.mark.parametrize("bad", [None, {}, object(), "kv", 5, Half()])
def test_a_registry_without_a_working_store_is_refused(bad):
    with pytest.raises(TypeError) as e:
        LeaseRegistry({"authorities": []}, bad)
    assert str(e.value) == "LeaseRegistry: a durable key-value store is required (MemoryAtomicKv() is for tests and single-process use)"
    with pytest.raises(TypeError) as e:
        BreakGlassRegistry({"authorities": [], "reviewers": []}, bad)
    assert str(e.value) == "BreakGlassRegistry: a durable key-value store is required (MemoryAtomicKv() is for tests and single-process use)"
    with pytest.raises(TypeError) as e:
        BlueprintRegistry(["op"], bad)
    assert str(e.value) == "BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintStore is for tests and single-process use)"


def test_the_constructors_take_no_store_by_default():
    for make in (lambda: LeaseRegistry({"authorities": []}), lambda: BreakGlassRegistry({"authorities": [], "reviewers": []}),
                 lambda: BlueprintRegistry(["op"])):
        with pytest.raises(TypeError):
            make()


@pytest.mark.parametrize("n", [0, -1, 4097, True, 1.5, "16"])
def test_the_shard_count_is_validated(n):
    with pytest.raises(ValueError) as e:
        LeaseRegistry({"authorities": []}, MemoryAtomicKv(), shards=n)
    assert str(e.value) == "LeaseRegistry: shards must be an integer from 1 to 4096"
    with pytest.raises(ValueError) as e:
        BreakGlassRegistry({"authorities": [], "reviewers": []}, MemoryAtomicKv(), shards=n)
    assert str(e.value) == "BreakGlassRegistry: shards must be an integer from 1 to 4096"


def test_the_shard_bounds_are_inclusive():
    for n in (1, 4096):
        assert LeaseRegistry({"authorities": []}, MemoryAtomicKv(), shards=n).shard_count == n
        BreakGlassRegistry({"authorities": [], "reviewers": []}, MemoryAtomicKv(), shards=n)
    assert LeaseRegistry({"authorities": []}, MemoryAtomicKv()).shard_count == DEFAULT_LEASE_SHARDS == 16


def test_the_shard_of_an_id_is_stable():
    assert shard_of("L1", 16) == shard_of("L1", 16)
    assert 0 <= shard_of("L1", 4096) < 4096
    import hashlib
    assert shard_of("abc", 16) == int.from_bytes(hashlib.sha256(b"abc").digest()[:4], "big") % 16


# ---- nothing lives in the process: every step on a NEW registry over the same store ---------------------------------------------------

@pytest.mark.parametrize("s", LD["scenarios"], ids=[s["name"] for s in LD["scenarios"]])
def test_lease_scenarios_survive_a_new_registry_per_step(s):
    kv = MemoryAtomicKv()
    for st in s["steps"]:
        reg = LeaseRegistry({"authorities": [LD["authority"]], **s.get("policy", {})}, kv)
        exp = st["expect"]
        if st["op"] == "accept":
            got = reg.accept(LD["records"][st["record"]], st.get("chain", []))
            assert [got.get(k) for k in ("ok", "code", "replaced", "seq")] == [exp.get(k) for k in ("ok", "code", "replaced", "seq")]
        elif st["op"] == "revoke":
            got = reg.revoke(LD["revocations"][st["revocation"]])
            assert [got.get(k) for k in ("ok", "code", "revoked")] == [exp.get(k) for k in ("ok", "code", "revoked")]
        else:
            assert check_lease(LD["records"][st["record"]], reg, st["now"]) == exp


@pytest.mark.parametrize("s", BD["scenarios"], ids=[s["name"] for s in BD["scenarios"]])
def test_break_glass_scenarios_survive_a_new_registry_per_step(s):
    kv = MemoryAtomicKv()
    for st in s["steps"]:
        reg = BreakGlassRegistry({"authorities": [BD["authority"]], "reviewers": [BD["reviewer"], *s.get("extra_reviewers", [])]}, kv)
        if st["op"] == "accept":
            got = reg.accept(BD["grants"][st["grant"]], st["now"])
        elif st["op"] == "use":
            got = reg.use(st["id"], st["holder"], st["action_digest"], st["now"], st["notified"])
        elif st["op"] == "review":
            got = reg.review(BD["reviews"][st["review"]], st["holder"], st["now"])
        else:
            got = reg.frozen(st["holder"], st["now"])
        assert got == st["expect"]


@pytest.mark.parametrize("s", PD["scenarios"], ids=[s["name"] for s in PD["scenarios"]])
def test_blueprint_scenarios_survive_a_new_registry_per_step_over_a_kv_store(s):
    kv = MemoryAtomicKv()
    for st in s["steps"]:
        reg = BlueprintRegistry([PD["operator"]], KvBlueprintStore(kv))
        if st["op"] == "accept":
            got = reg.accept(PD["records"][st["record"]])
        else:
            o = st["opts"]
            adm = o.get("admitted")
            hook = None if adm is None else (lambda key, bp, a=adm: True if a == "all" else False if a == "none" else key in a)
            got = check_blueprints(st["chain"], reg, o["now"], o["mode"], o.get("minEpoch"), admitted=hook)
        assert got == st["expect"]


def test_a_sqlite_store_survives_a_restart(tmp_path):
    path = str(tmp_path / "s.db")
    first = LeaseRegistry({"authorities": [LD["authority"]]}, SqliteAtomicKv(path))
    assert first.accept(LD["records"][0])["ok"] is True
    assert first.revoke(LD["revocations"][0])["ok"] is True
    second = LeaseRegistry({"authorities": [LD["authority"]]}, SqliteAtomicKv(path))
    assert check_lease(LD["records"][0], second, 1800000200000) == {"decision": "deny", "code": "revoked", "lease_id": "L1"}


# ---- a failing store -----------------------------------------------------------------------------------------------------------------

def test_a_throwing_store_is_store_unreachable_everywhere():
    lr = LeaseRegistry({"authorities": [LD["authority"]]}, DownKv())
    assert lr.accept(LD["records"][0]) == {"ok": False, "code": "store_unreachable"}
    assert lr.revoke(LD["revocations"][0]) == {"ok": False, "code": "store_unreachable"}
    assert check_lease(LD["records"][0], lr, 1800000200000) == {"decision": "deny", "code": "store_unreachable", "lease_id": "L1"}
    g = BD["grants"][0]
    br = BreakGlassRegistry({"authorities": [BD["authority"]], "reviewers": [BD["reviewer"]]}, DownKv())
    assert br.accept(g, g["issued_at"]) == {"ok": False, "code": "store_unreachable"}
    assert br.use(g["id"], g["holder"], "a", g["issued_at"], True) == {"decision": "deny", "code": "store_unreachable", "id": g["id"]}
    assert br.frozen(g["holder"], g["issued_at"]) is True


def test_a_shard_count_that_differs_from_the_stored_one_is_refused():
    kv = MemoryAtomicKv()
    assert LeaseRegistry({"authorities": [LD["authority"]]}, kv, shards=16).accept(LD["records"][0])["ok"] is True
    other = LeaseRegistry({"authorities": [LD["authority"]]}, kv, shards=8)
    assert other.accept(LD["records"][0]) == {"ok": False, "code": "store_unreachable"}
    assert other.revoke(LD["revocations"][0]) == {"ok": False, "code": "store_unreachable"}
    assert check_lease(LD["records"][0], other, 1800000200000)["code"] == "store_unreachable"


def test_a_revocation_of_a_prefix_is_written_to_every_shard_and_of_a_lease_to_one():
    kv = MemoryAtomicKv()
    reg = LeaseRegistry({"authorities": [LD["authority"]]}, kv)
    reg.accept(LD["records"][0])
    assert reg.revoke(LD["revocations"][1])["ok"] is True  # prefix db/prod
    assert all(len(reg.shard_revocations(i)) == 1 for i in range(reg.shard_count))
    kv2 = MemoryAtomicKv()
    reg2 = LeaseRegistry({"authorities": [LD["authority"]]}, kv2)
    reg2.revoke(LD["revocations"][0])  # lease L1
    assert [i for i in range(16) if reg2.shard_revocations(i)] == [shard_of("L1", 16)]
    with pytest.raises(ValueError):
        reg2.shard_revocations(16)
    with pytest.raises(ValueError):
        reg2.shard_revocations(-1)


# ---- F5: revocation pruning with a clock ---------------------------------------------------------------------------------------------------

def _pruning_registry(now):
    return LeaseRegistry({"authorities": [LD["authority"]], "maxTtlCeiling": 3_600_000}, MemoryAtomicKv(), clock=lambda: now[0])


def test_a_revocation_at_exactly_revoked_at_plus_the_ceiling_is_kept():
    revoked_at = LD["revocations"][1]["revoked_at"]
    now = [revoked_at]
    reg = _pruning_registry(now)
    assert reg.revoke(LD["revocations"][1])["ok"] is True  # prefix db/prod: every shard
    target = shard_of("L3", 16)  # L3 (db/production) is not under db/prod
    assert len(reg.shard_revocations(target)) == 1
    now[0] = revoked_at + 3_600_000
    assert reg.accept(LD["records"][18])["ok"] is True
    assert len(reg.shard_revocations(target)) == 1


def test_a_revocation_past_the_horizon_is_pruned_from_the_shard_that_is_written():
    revoked_at = LD["revocations"][1]["revoked_at"]
    now = [revoked_at]
    reg = _pruning_registry(now)
    assert reg.revoke(LD["revocations"][1])["ok"] is True
    target = shard_of("L3", 16)
    now[0] = revoked_at + 3_600_000 + 1
    assert reg.accept(LD["records"][18])["ok"] is True
    assert reg.shard_revocations(target) == []
    other = (target + 1) % 16
    assert len(reg.shard_revocations(other)) == 1  # a shard nobody wrote still holds it


def test_without_a_ceiling_nothing_is_pruned():
    now = [0]
    reg = LeaseRegistry({"authorities": [LD["authority"]]}, MemoryAtomicKv(), clock=lambda: now[0])
    reg.revoke(LD["revocations"][1])
    now[0] = 10 ** 18
    reg.revoke(LD["revocations"][2])
    assert len(reg.shard_revocations(0)) == 2


def test_a_ceiling_must_be_a_positive_integer():
    for bad in (0, -1, 1.5, True, "5"):
        with pytest.raises(ValueError) as e:
            LeaseRegistry({"authorities": [], "maxTtlCeiling": bad}, MemoryAtomicKv())
        assert str(e.value) == "LeaseRegistry: maxTtlCeiling must be a positive integer"


# ---- concurrency: one atomic update per operation ------------------------------------------------------------------------------------------

def test_two_concurrent_renewals_of_one_lease_have_exactly_one_winner():
    kv = MemoryAtomicKv()
    LeaseRegistry({"authorities": [LD["authority"]]}, kv).accept(LD["records"][0])
    out = []
    barrier = threading.Barrier(2)

    def go(rec):
        reg = LeaseRegistry({"authorities": [LD["authority"]]}, kv)
        barrier.wait()
        out.append(reg.accept(rec))

    ts = [threading.Thread(target=go, args=(LD["records"][i],)) for i in (1, 4)]  # two different seq-2 renewals
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(r["ok"] for r in out) == [False, True]
    assert next(r for r in out if not r["ok"])["code"] == "lease_fork"


# ---- blueprint stores ------------------------------------------------------------------------------------------------------------------------

def test_the_blueprint_stores_hold_the_highest_epoch():
    for store in (MemoryBlueprintStore(), KvBlueprintStore(MemoryAtomicKv())):
        assert store.max_epoch() == 0 and store.get("k") is None
        store.put({"key": "k", "epoch": 5})
        store.put({"key": "j", "epoch": 3})
        assert store.max_epoch() == 5 and store.get("k") == {"key": "k", "epoch": 5}
        store.put({"key": "k", "epoch": 4})
        assert store.max_epoch() == 5  # never lowered
    with pytest.raises(TypeError):
        KvBlueprintStore(object())


def test_a_kv_blueprint_store_put_keeps_the_stored_record_unless_the_epoch_is_higher():
    st = KvBlueprintStore(MemoryAtomicKv())
    st.put({"key": "bp", "epoch": 5, "id": "first"})
    st.put({"key": "bp", "epoch": 3, "id": "older"})
    assert st.get("bp")["id"] == "first"
    st.put({"key": "bp", "epoch": 5, "id": "same-epoch"})
    assert st.get("bp")["id"] == "first"
    st.put({"key": "bp", "epoch": 6, "id": "newer"})
    assert st.get("bp")["id"] == "newer"
    st.put({"key": "other", "epoch": 1, "id": "x"})
    assert st.get("other")["id"] == "x" and st.max_epoch() == 6


def test_concurrent_accepts_over_a_shared_kv_never_lower_a_record():
    kv = MemoryAtomicKv()
    recs = {e: dict(PD["records"][0], epoch=e) for e in range(1, 65)}
    stores = [KvBlueprintStore(kv) for _ in range(4)]

    def go(i):
        for e in range(64 - i, 0, -4):  # each thread puts its own epochs, newest first, straight to the shared store
            stores[i].put(recs[e])

    ts = [threading.Thread(target=go, args=(i,)) for i in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert stores[0].get(recs[1]["key"])["epoch"] == 64 and stores[0].max_epoch() == 64


def test_a_blueprint_store_is_copied_not_shared():
    st = MemoryBlueprintStore()
    rec = {"key": "k", "epoch": 1, "ceiling": []}
    st.put(rec)
    rec["epoch"] = 99
    got = st.get("k")
    got["ceiling"].append(1)
    assert st.get("k") == {"key": "k", "epoch": 1, "ceiling": []}


def test_an_admission_hook_that_raises_is_a_store_unreachable_denial():
    reg = BlueprintRegistry([PD["operator"]], MemoryBlueprintStore())
    pinned = next(i for i, r in enumerate(PD["records"]) if "runtime_pins" in r and r["status"] == "active")
    assert reg.accept(PD["records"][pinned])["ok"] is True
    key = PD["records"][pinned]["key"]
    chain = [{"issuer": "principal", "holder": key}, {"issuer": key, "holder": "inst1"}]

    def boom(k, bp):
        raise RuntimeError("down")
    assert check_blueprints(chain, reg, 1800000000000, "require", None, None, boom) == {"decision": "deny", "code": "store_unreachable"}
    assert check_blueprints(chain, reg, 1800000000000, "require", None, None, lambda k, bp: 1)["code"] == "not_admitted"  # only True admits
