"""The store-conformance helper: it passes the stores this package ships and FAILS stores that are broken (a guard that has
never failed proves nothing)."""
import time

from atlas_pca import (ClaimResult, MemoryOperationStore, MemoryStateStore, SqliteStateStore, run_operation_store_conformance,
                       run_state_store_conformance, sqlite_operation_store)


def statuses(report):
    return {r.test: r.status for r in report.results}


class RacyStateStore:
    """claim = read, wait, write: two callers both read the old value and both win."""

    def __init__(self, shared):
        self.d, self.shared = shared, None

    def claim(self, key, counter):
        last = self.d.get(key)
        time.sleep(0.002)
        if last is not None and counter <= last:
            return ClaimResult(False, last)
        self.d[key] = counter
        return ClaimResult(True)


class VolatileStateStore(MemoryStateStore):
    """A 'durable' store that loses claims when its handle is dropped."""


def test_memory_store_passes_as_process_local():
    shared = MemoryStateStore()
    r = run_state_store_conformance(lambda: shared, durable=False, shared=False)
    assert r.ok, r.render()
    assert statuses(r) == {"claim-sequence": "pass", "claim-burst": "pass", "claim-concurrent": "skip",
                           "claim-durability": "skip", "crash-after-claim": "skip"}


def test_sqlite_store_passes_every_test(tmp_path):
    path = str(tmp_path / "replay.db")
    r = run_state_store_conformance(lambda: SqliteStateStore(path))
    assert r.ok, r.render()
    assert set(statuses(r).values()) == {"pass"}


def test_a_racy_store_fails_the_burst():
    data = {}
    r = run_state_store_conformance(lambda: RacyStateStore(data), durable=False, shared=False)
    assert not r.ok and statuses(r)["claim-burst"] == "fail"
    assert "want exactly 1" in next(x for x in r.results if x.test == "claim-burst").note


def test_a_store_that_forgets_claims_across_handles_fails_durability_and_crash():
    r = run_state_store_conformance(lambda: MemoryStateStore())  # a fresh store per handle, declared durable and shared
    s = statuses(r)
    assert not r.ok and s["claim-concurrent"] == "fail" and s["claim-durability"] == "fail" and s["crash-after-claim"] == "fail"


def test_a_store_without_claim_is_reported():
    r = run_state_store_conformance(lambda: object())
    assert not r.ok and all(x.status == "fail" for x in r.results if x.test in ("claim-sequence", "claim-burst"))


def test_operation_stores_pass(tmp_path):
    shared = MemoryOperationStore()
    r = run_operation_store_conformance(lambda: shared, durable=False, shared=False)
    assert r.ok, r.render()
    assert statuses(r)["cross-handle"] == "skip" and statuses(r)["durability"] == "skip"
    path = str(tmp_path / "ops.db")
    r = run_operation_store_conformance(lambda: sqlite_operation_store(path))
    assert r.ok and set(statuses(r).values()) == {"pass"}, r.render()


class AliasingStore(MemoryOperationStore):
    def get(self, id):
        return self._m.get(id)  # hands out the stored record itself


class NonAtomicStore(MemoryOperationStore):
    def create(self, record):
        cur = self._m.get(record["id"])
        time.sleep(0.002)
        if cur is not None:
            return dict(cur)
        self._m[record["id"]] = dict(record)
        return None


class LooseCasStore(MemoryOperationStore):
    def transition(self, id, from_state, next_record):
        cur = self._m.get(id)
        if cur is None:
            return False
        time.sleep(0.002)
        self._m[id] = dict(next_record, id=id)  # ignores the compare
        return True


def test_broken_operation_stores_fail():
    for cls, test in ((AliasingStore, "copies"), (NonAtomicStore, "create-race"), (LooseCasStore, "semantics")):
        s = cls()
        r = run_operation_store_conformance(lambda s=s: s, durable=False, shared=False)
        assert not r.ok and statuses(r)[test] == "fail", (cls.__name__, r.render())
