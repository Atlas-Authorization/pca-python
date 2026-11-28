"""Differential oracle: the durable stores against the TypeScript reference (ref-core-stores-java): the ledger store, the stored ledger with
its checkpoint verification, the bond store, the budget ledger with signed releases and aggregate admission, and the mesh witness. Every
failure is compared by its stable code (``RangeError`` for an argument error)."""
import hashlib

from atlas_pca.agent import keypair_from_seed
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.bond_store import KvBondStore
from atlas_pca.budget_ledger import (KvBudgetLedger, admit_aggregate_action, anchor_release, release_commit, release_digest, scope_key,
                                     settle_aggregate, sign_release, start_aggregate, verify_release)
from atlas_pca.ledger_store import KvLedgerStore, StoredLedger
from atlas_pca.store_errors import code_of
from base_oracle import load_ref, run
from test_ref_core_mesh import _witness_script


def _key(label):
    return keypair_from_seed(hashlib.sha256(("atlas-pca-conformance/" + label).encode("utf-8")).digest(), allow_insecure_signer=True)


def _script(ops, f):
    out = []
    for op in ops:
        try:
            out.append(f(op))
        except Exception as e:  # noqa: BLE001 - the reference records a thrown error as {"$err": code}
            out.append({"$err": code_of(e)})
    return out


def _ledger_store(ops):
    kv = MemoryAtomicKv()
    s = KvLedgerStore(kv)

    def f(op):
        k = op[0]
        if k == "size":
            return s.size()
        if k == "read":
            return s.read(op[1], op[2])
        if k == "append":
            return s.append(op[1], op[2])
        if k == "cpCount":
            return s.checkpoint_count()
        if k == "cps":
            return s.checkpoints(op[1])
        if k == "appendCp":
            return s.append_checkpoint(op[1], op[2])
        if k == "kvSet":
            kv.set("pca-ledger-store/v1", op[1])
            return None
        raise ValueError("op")
    return _script(ops, f)


def _stored_ledger(ops):
    kv = MemoryAtomicKv()
    store = KvLedgerStore(kv)
    handles, calls = {}, [0]
    gkey = _key("stored-ledger-guardian")

    def clock():
        t = 1_800_000_000_000 + 1000 * calls[0]
        calls[0] += 1
        return t

    def f(op):
        head = op[0]
        if head == "open":
            g = _key("other") if len(op) > 2 and op[2] == "other-key" else gkey
            h = StoredLedger.open(store, g, op[3] if len(op) > 3 and op[3] is not None else "inst", "pr", clock)
            handles[op[1]] = h
            return {"size": h.size, "guardian": h.guardian}
        if head == "kvSet":
            kv.set("pca-ledger-store/v1", op[1])
            return None
        if head == "kvGet":
            return kv.get("pca-ledger-store/v1")
        h, k = handles[head], op[1]
        if k == "append":
            return h.append(op[2])
        if k == "checkpoint":
            return h.checkpoint()
        if k == "catchUp":
            h.catch_up()
            return None
        if k == "head":
            return h.head()
        if k == "size":
            return h.size
        if k == "incl":
            return h.inclusion_proof(op[2])
        if k == "consFrom":
            return h.consistency_proof_from(op[2])
        if k == "commits":
            return h.commits()
        if k == "latest":
            return h.latest_checkpoint()
        if k == "chain":
            return h.checkpoint_chain()
        if k == "guardian":
            return h.guardian
        raise ValueError("op")
    return _script(ops, f)


def _bond_store(ops):
    kv = MemoryAtomicKv()
    s = KvBondStore(kv)

    def f(op):
        k = op[0]
        if k == "read":
            return s.read(op[1], op[2])
        if k == "commit":
            return s.commit(op[1], op[2])
        if k == "deposit":
            return s.deposit(op[1], op[2])
        if k == "kvSet":
            kv.set("pca-bond-store/v1", op[1])
            return None
        if k == "kvGet":
            return kv.get("pca-bond-store/v1")
        raise ValueError("op")
    return _script(ops, f)


def _budget_ledger(ops):
    rkey = _key("release-signer")
    kv = MemoryAtomicKv()
    ledger = [None]
    log = KvLedgerStore(MemoryAtomicKv())

    def f(op):
        k = op[0]
        if k == "new":
            ledger[0] = KvBudgetLedger(kv, op[1])
            return ledger[0].durable
        if k == "snapshot":
            return ledger[0].snapshot(op[1])
        if k == "reserve":
            return ledger[0].reserve(op[1], op[2])
        if k == "start":
            return ledger[0].start(op[1], op[2])
        if k == "commit":
            return ledger[0].commit(op[1], op[2])
        if k == "release":
            return ledger[0].release(op[1], op[2], op[3])
        if k == "expire":
            return ledger[0].expire(op[1], op[2])
        if k == "signRelease":
            return sign_release(op[1], op[2], op[3], op[4], rkey)
        if k == "verifyRelease":
            return verify_release(op[1], rkey.public if op[2] == "signer" else op[2])
        if k == "releaseCommit":
            return [release_digest(op[1]), release_commit(op[1])]
        if k == "anchor":
            return [anchor_release(log, op[1]), log.size()]
        if k == "scopeKey":
            return scope_key(op[1], op[2])
        if k == "kvSet":
            kv.set(op[1], op[2])
            return None
        if k == "admit":
            ad = op[1]
            allow = ad["allow"]
            r = admit_aggregate_action(ledger[0], ad["ids"], ad["accumulators"], None, ad["event"], lambda state: {"allow": allow, "state": state},
                                       ad.get("expiresAt"), ad.get("maxAttempts"))
            return r
        if k == "startAgg":
            return start_aggregate(ledger[0], op[1])
        if k == "settleAgg":
            return settle_aggregate(ledger[0], op[1], op[2], None)
        raise ValueError("op")
    return _script(ops, f)


_CASES = load_ref("core-stores-java")[1]
_MAP = {"ledgerStore": _ledger_store, "storedLedger": _stored_ledger, "bondStore": _bond_store, "budgetLedger": _budget_ledger, "meshWitness": _witness_script}


def test_every_function_is_covered():
    assert set(_CASES) == set(_MAP)


def test_matches_the_reference():
    for fn in sorted(_MAP):
        ran, _ = run(_CASES[fn], _MAP[fn])
        assert ran == len(_CASES[fn]), fn
