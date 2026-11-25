"""The store-conformance helper: it passes the stores this package ships and FAILS stores that are broken (a guard that has
never failed proves nothing)."""
import threading
import time

from atlas_pca import (ClaimResult, MemoryOperationStore, MemoryStateStore, SqliteStateStore, run_operation_store_conformance,
                       run_state_store_conformance, sqlite_operation_store)


def statuses(report):
    return {r.test: r.status for r in report.results}


class Rendezvous:
    """The racers of a racy double meet between their read and their write: every racer reads, then waits until a partner on the same
    key has read too (racers pair off in arrival order: the kit's retry race has two racers and its bursts sixteen, so a barrier of a
    fixed size would not fit both), and only then do the two write, so a pair always loses an update whatever the scheduler or the
    machine speed does (a wall-clock sleep let a late racer run alone). A call from the thread that built the double is serial setup
    and never waits. A racer left without a partner for 30 s records the failure in ``broken`` and raises; the test asserts it is empty."""

    def __init__(self):
        self.owner = threading.current_thread()
        self.mu = threading.Lock()
        self.pending = {}
        self.broken = []

    def meet(self, key):
        if threading.current_thread() is self.owner:
            return
        with self.mu:
            partner = self.pending.pop(key, None)
            if partner is not None:
                partner.set()
                return
            mine = threading.Event()
            self.pending[key] = mine
        if mine.wait(30):
            return
        with self.mu:
            if self.pending.get(key) is mine:
                del self.pending[key]
        self.broken.append("no partner reached the rendezvous on %s" % key)
        raise AssertionError(self.broken[-1])


class RacyStateStore:
    """claim = read, meet a partner, write: two callers both read the old value and both win."""

    def __init__(self, shared, meet):
        self.d, self.meet, self.shared = shared, meet, None

    def claim(self, key, counter):
        last = self.d.get(key)
        self.meet.meet(key)
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
                           "claim-durability": "skip", "crash-after-claim": "skip", "retry-after-timeout": "pass"}


def test_sqlite_store_passes_every_test(tmp_path):
    path = str(tmp_path / "replay.db")
    r = run_state_store_conformance(lambda: SqliteStateStore(path))
    assert r.ok, r.render()
    assert set(statuses(r).values()) == {"pass"}


def test_a_racy_store_fails_the_burst():
    data, meet = {}, Rendezvous()
    r = run_state_store_conformance(lambda: RacyStateStore(data, meet), durable=False, shared=False)
    assert not meet.broken, "the racers did not all reach the rendezvous"
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
    """create = check, meet a partner, put: two callers both see the id absent and both create it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.meet = Rendezvous()

    def create(self, record):
        cur = self._m.get(record["id"])
        self.meet.meet(record["id"])
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
        assert not getattr(s, "meet", Rendezvous()).broken, (cls.__name__, "the racers did not all reach the rendezvous")
        assert not r.ok and statuses(r)[test] == "fail", (cls.__name__, r.render())
