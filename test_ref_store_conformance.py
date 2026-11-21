"""Differential replay of the TypeScript reference (@atlasauth/pca-store-conformance): the register model, the budgeted linearizability
search and per-key checker, the history parser, the workload PRNG, report folding and the check inventories of the profiles; plus native
runs of the kit against good and bad reference stores (a checker that passes everything is worthless).

In the vectors a non-finite number is the object {"$num": "Infinity" | "-Infinity"} (an operation with an unknown outcome has ret
Infinity); a report's JSON text is compared as text."""
import copy
import threading
import time

import pytest

from atlas_pca import store_conformance_model as M
from atlas_pca import store_conformance_profiles as P
from atlas_pca import store_conformance_runner as R
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("store-conformance")


def num(v):
    """{"$num": ...} -> the non-finite number, recursively."""
    if isinstance(v, list):
        return [num(x) for x in v]
    if isinstance(v, dict):
        if len(v) == 1 and isinstance(v.get("$num"), str):
            return {"Infinity": float("inf"), "-Infinity": float("-inf")}.get(v["$num"], float("nan"))
        return {k: num(x) for k, x in v.items()}
    return v


def with_ops(fn):
    return lambda ops, *rest: fn(num(ops), *rest)


def inventory(profile):
    mk = lambda **kw: P.MeshWitnessStoreAdapter("x", lambda: None, **kw)  # noqa: E731
    keep = lambda cs: [{"name": c.name, "claim": c.claim, "needs": c.needs} for c in cs]  # noqa: E731
    if profile == "lease":
        return keep(P.GUARDIAN_LEASE_CHECKS)
    if profile == "ledger":
        return keep(P.LEDGER_CHECKS)
    if profile == "budget":
        return keep(P.BUDGET_CHECKS)
    if profile == "bond":
        return keep(P.BOND_CHECKS)
    kw = {}
    if "+reopen" in profile:
        kw["reopen"] = lambda s: s
    if "+damage" in profile:
        kw["damage"] = lambda s: None
    return [c.name for c in P.mesh_witness_store_cases(mk(**kw))]


def inventory_equal(got, out, case):
    if isinstance(out, list) and out and isinstance(out[0], str):
        return got == out
    return got == out


def fold(x):
    return M.overall(x["tests"] if isinstance(x, dict) else [{"status": s} for s in x])


MAP = {
    "step": lambda s, op: M.step(num(s), num(op)),
    "overlappingTrues": with_ops(M.overlapping_trues),
    "prune": with_ops(M.prune),
    "fastCheck": with_ops(M.fast_check),
    "search": with_ops(M.search_linearizable),
    "decideKey": with_ops(M.decide_key),
    "minimize": with_ops(M.minimize),
    "formatOps": with_ops(M.format_ops),
    "checkKey": with_ops(M.check_key),
    "checkHistory": with_ops(M.check_history),
    "deletion": lambda ops, i: (lambda d: M.deletion(d, d[i]))(num(ops)),
    "parseHistory": M.parse_history,
    "prng": lambda seed, ns: (lambda r: [r(n) for n in ns])(M.prng(seed)),
    "overall": lambda x: fold(num(x)),
    "formatReport": lambda r, k: M.format_report(num(r), k),
    "reportJson": lambda r: M.report_json(num(r)),
    "inventory": inventory,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(MAP), sorted(set(BY_FN) ^ set(MAP))
    assert COUNT > 2000


@pytest.mark.parametrize("fn", sorted(MAP))
def test_replay(fn):
    ran, _ = run(BY_FN[fn], MAP[fn], compare=inventory_equal if fn == "inventory" else None)
    assert ran == len(BY_FN[fn])


# ---- native runs of the kit -----------------------------------------------------------------------------------------------------------

SMALL = {"clients": 4, "durationMs": 150, "rounds": 6, "revisitKeys": 24, "opTimeoutMs": 2000}


def statuses(report):
    return {(t["test"], t["kind"]): t["status"] for t in report["tests"]}


def test_good_stores_pass():
    for a in (R.in_memory_adapter(), R.durable_file_adapter()):
        r = R.run_conformance(a, SMALL)
        assert r["status"] == "pass", R.format_report(r)
    assert statuses(R.run_conformance(R.in_memory_adapter(), SMALL))[("durability", "consume")] == "skip"


def test_a_non_strict_counter_is_flagged():
    r = R.run_conformance(R.non_strict_counter_adapter(), {**SMALL, "tests": ["burst"], "values": 1})
    assert r["status"] == "fail", R.format_report(r)


def test_a_volatile_store_is_flagged_by_durability():
    r = R.run_conformance(R.volatile_adapter(), {**SMALL, "tests": ["durability"]})
    assert r["status"] == "fail", R.format_report(r)


def test_an_evicting_store_is_flagged_by_retention():
    r = R.run_conformance(R.evicting_adapter(4), {**SMALL, "tests": ["retention"], "revisitKeys": 40})
    assert r["status"] == "fail", R.format_report(r)


def test_a_read_then_write_store_is_flagged():
    r = R.run_conformance(R.read_then_write_adapter(), {**SMALL, "tests": ["burst"], "clients": 8, "rounds": 30})
    assert r["status"] == "fail", R.format_report(r)


def test_the_crash_test_is_reported_as_skipped():
    assert statuses(R.run_conformance(R.in_memory_adapter(), {**SMALL, "tests": ["crash"]}))[("crash", "advance")] == "skip"


class MemLease:
    def __init__(self, shared):
        self.shared = shared

    def read(self):
        with self.shared["lock"]:
            return dict(self.shared["rec"]) if self.shared["rec"] else None

    def now(self):
        return int(time.time() * 1000)

    def cas(self, expected, nxt):
        with self.shared["lock"]:
            cur = self.shared["rec"]
            same = (cur is None and expected is None) or (cur is not None and expected is not None and all(cur[k] == expected[k] for k in ("holder", "epoch", "expiresAt")))
            if not same or nxt["epoch"] < (cur["epoch"] if cur else 0):
                return False
            self.shared["rec"] = dict(nxt)
            return True


def lease_adapter(durable=True):
    def create():
        shared = {"rec": None, "lock": threading.Lock()}
        return P.StoreHandle(MemLease(shared), lambda: MemLease(shared), crash=lambda: MemLease(shared))
    return P.ProfileAdapter("in-memory lease store", create, durable)


def test_a_correct_lease_store_passes_the_lease_profile():
    r = P.run_guardian_lease_store_conformance(lease_adapter())
    assert r["status"] == "pass", P.format_lease_report(r)
    assert not [c for c in r["checks"] if c["status"] == "skip"]
    assert {c["status"] for c in P.run_guardian_lease_store_conformance(lease_adapter(False))["checks"]} == {"pass", "skip"}


def test_a_lease_store_without_compare_and_swap_is_flagged():
    class NoCas(MemLease):
        def cas(self, expected, nxt):
            with self.shared["lock"]:
                self.shared["rec"] = dict(nxt)
                return True

    def create():
        shared = {"rec": None, "lock": threading.Lock()}
        return P.StoreHandle(NoCas(shared), lambda: NoCas(shared))

    r = P.run_guardian_lease_store_conformance(P.ProfileAdapter("BAD no cas", create, True), only=["wrong-expected-record-never-writes", "racing-acquirers-have-one-winner"])
    assert r["status"] == "fail", P.format_lease_report(r)


class MemMesh:
    def __init__(self, backing):
        self.b = backing

    def load(self):
        if self.b.get("damaged"):
            raise ValueError("damaged storage")
        return copy.deepcopy(self.b.get("state"))

    def save(self, state):
        self.b["state"] = copy.deepcopy(state)


def test_mesh_witness_store_cases():
    backings = []

    def make():
        backings.append({})
        return MemMesh(backings[-1])

    ok = P.MeshWitnessStoreAdapter("memory", make, reopen=lambda s: MemMesh(s.b), damage=lambda s: s.b.update(damaged=True))
    r = P.run_mesh_witness_store_conformance(ok)
    assert r["status"] == "pass" and len(r["checks"]) == 10, r

    class Aliasing(MemMesh):
        def load(self):
            return self.b.get("state")

    bad = P.MeshWitnessStoreAdapter("aliasing", lambda: Aliasing({}))
    assert P.run_mesh_witness_store_conformance(bad)["status"] == "fail"
