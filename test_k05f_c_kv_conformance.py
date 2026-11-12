"""The atomic key/value conformance kit (backend of the lease, break-glass and blueprint registries) passes on the bundled stores."""
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
    class Racy:
        def __init__(self):
            self.m = {}

        def get(self, key):
            return self.m.get(key)

        def update(self, key, fn):
            import time
            prev = self.m.get(key)
            time.sleep(0.001)
            nxt = fn(prev)
            if nxt is not None:
                self.m[key] = nxt
            return self.m.get(key)

    shared = Racy()
    rep = run_atomic_kv_conformance(lambda: shared, durable=False)
    assert not rep.ok
    assert {r.test for r in rep.failures()} >= {"increments"}


def test_a_handle_without_the_methods_fails():
    rep = run_atomic_kv_conformance(lambda: object(), durable=False, shared=False)
    assert not rep.ok and {r.test: r.status for r in rep.results} == {"semantics": "fail", "copies": "fail", "increments": "fail", "cross-handle": "skip", "durability": "skip"}
