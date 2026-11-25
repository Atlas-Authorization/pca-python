"""The atomic key/value conformance kit (backend of the lease, break-glass and blueprint registries) passes on the bundled stores."""
import threading

from atlas_pca import run_atomic_kv_conformance
from atlas_pca.atomic_kv import MemoryAtomicKv, SqliteAtomicKv


def test_the_memory_store_passes_as_a_process_local_store():
    shared = MemoryAtomicKv()
    rep = run_atomic_kv_conformance(lambda: shared, durable=False, shared=False)
    assert rep.ok, rep.render()
    assert {r.test: r.status for r in rep.results} == {"semantics": "pass", "copies": "pass", "increments": "pass", "cross-handle": "skip",
                                                       "durability": "skip"}


def test_the_sqlite_store_passes_everything(tmp_path):
    path = str(tmp_path / "kit.db")
    rep = run_atomic_kv_conformance(lambda: SqliteAtomicKv(path))
    assert rep.ok, rep.render()
    assert all(r.status == "pass" for r in rep.results), rep.render()


def test_a_store_that_loses_updates_fails_the_kit():
    racers = 16

    class Racy:
        """A read-modify-write whose racers rendezvous between the read and the write: every racing caller reads and computes from the
        same previous value, waits at a barrier until all ``racers`` have, and only then do they write, so the lost update always
        happens whatever the scheduler or the machine speed does (a wall-clock sleep let a late racer run alone). Calls from the thread
        that built the store are serial setup: they never wait and install a fresh barrier. A racer that cannot rendezvous is recorded
        in ``broken`` and the test fails on it."""

        def __init__(self):
            self.m = {}
            self.owner = threading.current_thread()
            self.round = threading.Barrier(racers)
            self.broken = []

        def get(self, key):
            return self.m.get(key)

        def update(self, key, fn):
            prev = self.m.get(key)
            nxt = fn(prev)
            if threading.current_thread() is self.owner:
                self.round = threading.Barrier(racers)
            else:
                try:
                    self.round.wait(timeout=30)
                except threading.BrokenBarrierError as e:
                    self.broken.append(e)
                    raise
            if nxt is not None:
                self.m[key] = nxt
            return self.m.get(key)

    shared = Racy()
    rep = run_atomic_kv_conformance(lambda: shared, durable=False, threads=racers)
    assert not shared.broken, "the racers did not all reach the rendezvous"
    assert not rep.ok
    assert {r.test for r in rep.failures()} >= {"increments"}


def test_a_handle_without_the_methods_fails():
    rep = run_atomic_kv_conformance(lambda: object(), durable=False, shared=False)
    assert not rep.ok and {r.test: r.status for r in rep.results} == {"semantics": "fail", "copies": "fail", "increments": "fail", "cross-handle": "skip", "durability": "skip"}
