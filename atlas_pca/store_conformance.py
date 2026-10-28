"""A reusable conformance helper for the stores behind ``authorize``: run the replay / counter and operation-record contracts
against YOUR store. Pass a factory that opens a handle on the backend (one handle = one verifier instance's connection to the
shared backend) and read the report.

    from atlas_pca import run_state_store_conformance, run_operation_store_conformance

    report = run_state_store_conformance(lambda: MyStateStore(dsn))     # claim(key, counter) -> ClaimResult
    assert report.ok, report.render()

The state-store profile runs the store's ``claim(key, counter)`` as the replay invariant "a counter goes from unconsumed to
consumed at most once, however many copies arrive":

* ``claim-sequence``    strict increase on one key; replays and older counters refused (with ``last_counter``); keys independent;
* ``claim-burst``       N threads race one (key, counter) on ONE handle, every round, then the next counter: exactly one wins;
* ``claim-concurrent``  the same race spread over K handles (a store only an in-process lock can serialise fails here);
* ``claim-durability``  a claim survives closing every handle and ``restart()``;
* ``crash-after-claim`` the instance dies after the admission (``crash()`` when given): the same counter stays consumed and the
  next one is admitted.

The operation-store profile checks ``create`` (atomic create-if-absent), ``transition`` (a compare-and-set on the state),
``get`` (a copy, never an alias) and durability. A declared ``durable=False`` / ``shared=False`` (a process-local store) skips
the tests that need them; everything else is a failure, never a skip. Tests run with real threads on this machine's scheduler:
a racy store is caught with overwhelming probability per round, so run it more than once for a store you wrote."""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class

    test: str
    status: str  # pass | fail | skip
    note: str = ""


@dataclass
class ConformanceReport:
    name: str
    results: List[TestResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when nothing failed and at least one test passed."""
        return all(r.status != "fail" for r in self.results) and any(r.status == "pass" for r in self.results)

    def failures(self) -> List[TestResult]:
        return [r for r in self.results if r.status == "fail"]

    def render(self) -> str:
        return "\n".join("%-4s %s%s" % (r.status, r.test, (": " + r.note) if r.note else "") for r in self.results)


class _Skip(Exception):
    pass


def _race(n: int, fn: Callable[[int], Any]) -> List[Any]:
    """Run fn(i) in n threads released together; returns the results in order (an exception is returned as a value)."""
    gate, out = threading.Barrier(n), [None] * n

    def go(i: int) -> None:
        try:
            gate.wait(timeout=60)
            out[i] = fn(i)
        except BaseException as e:  # noqa: BLE001 - a store that raises under load is reported, not hidden
            out[i] = e

    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return out


def _check_no_errors(rs: List[Any]) -> None:
    errs = [r for r in rs if isinstance(r, BaseException)]
    if errs:
        raise AssertionError("%d of %d concurrent calls raised: %r" % (len(errs), len(rs), errs[0]))


def _close(h: Any) -> None:
    c = getattr(h, "close", None)
    if callable(c):
        c()


def _run(report: ConformanceReport, name: str, fn: Callable[[], Optional[str]]) -> None:
    try:
        note = fn()
        report.results.append(TestResult(name, "pass", note or ""))
    except _Skip as s:
        report.results.append(TestResult(name, "skip", str(s)))
    except AssertionError as e:
        report.results.append(TestResult(name, "fail", str(e)))
    except Exception as e:  # noqa: BLE001
        report.results.append(TestResult(name, "fail", "%s: %s" % (type(e).__name__, e)))


# ---- replay / counter store -----------------------------------------------------------------------------------------------

def _claimed(r: Any) -> bool:
    return r is True or (isinstance(r, tuple) and len(r) >= 1 and r[0] is True)


def run_state_store_conformance(open_store: Callable[[], Any], *, durable: bool = True, shared: bool = True,
                                crash: Optional[Callable[[], None]] = None, restart: Optional[Callable[[], None]] = None,
                                teardown: Optional[Callable[[], None]] = None, threads: int = 16, rounds: int = 5,
                                handles: int = 4, name: str = "state store") -> ConformanceReport:
    """Run the replay-store contract (see the module doc). `open_store()` returns a handle with ``claim(key, counter)``;
    ``durable=False`` / ``shared=False`` declare a process-local store (its durability and cross-handle tests are skipped).
    `crash()` kills the backend / instance abruptly and `restart()` brings it back (both optional); `teardown()` runs last."""
    report = ConformanceReport(name)
    run = uuid.uuid4().hex[:12]
    opened: List[Any] = []

    def handle() -> Any:
        h = open_store()
        opened.append(h)
        if not callable(getattr(h, "claim", None)):
            raise AssertionError("the store has no claim(key, counter)")
        return h

    def sequence() -> None:
        s, k, other = handle(), "seq:%s" % run, "seq-other:%s" % run
        assert _claimed(s.claim(k, 1)), "first claim of counter 1 refused"
        r = s.claim(k, 1)
        assert not _claimed(r), "counter 1 claimed twice"
        assert isinstance(r, tuple) and len(r) > 1 and r[1] == 1, "a refused claim must report last_counter=1, got %r" % (r,)
        assert _claimed(s.claim(k, 5)), "a larger counter (a gap) must be admitted"
        assert not _claimed(s.claim(k, 3)), "an older counter was admitted after 5"
        assert not _claimed(s.claim(k, 5)), "counter 5 claimed twice"
        assert _claimed(s.claim(other, 1)), "another key must be independent"

    def burst() -> str:
        s, k = handle(), "burst:%s" % run
        for c in range(1, rounds + 1):
            rs = _race(threads, lambda i, c=c: s.claim(k, c))
            _check_no_errors(rs)
            wins = sum(1 for r in rs if _claimed(r))
            assert wins == 1, "round %d: %d of %d concurrent claims of counter %d were admitted (want exactly 1)" % (c, wins, threads, c)
        return "%d rounds x %d threads" % (rounds, threads)

    def concurrent() -> str:
        if not shared:
            raise _Skip("the adapter declares shared=False (a process-local store)")
        hs, k = [handle() for _ in range(handles)], "conc:%s" % run
        for c in range(1, rounds + 1):
            rs = _race(threads, lambda i, c=c: hs[i % handles].claim(k, c))
            _check_no_errors(rs)
            wins = sum(1 for r in rs if _claimed(r))
            assert wins == 1, "round %d: %d of %d claims over %d handles were admitted (want exactly 1)" % (c, wins, threads, handles)
        return "%d rounds x %d threads over %d handles" % (rounds, threads, handles)

    def durability() -> None:
        if not durable:
            raise _Skip("the adapter declares durable=False (state dies with the process)")
        k = "dur:%s" % run
        assert _claimed(handle().claim(k, 7)), "claim refused"
        for h in opened:
            _close(h)
        if restart is not None:
            restart()
        r = handle().claim(k, 7)
        assert not _claimed(r), "counter 7 was admitted again after the handles were closed (the claim was not durable)"
        assert _claimed(handle().claim(k, 8)), "the next counter must be admitted after a restart"

    def crash_after_claim() -> None:
        if not durable:
            raise _Skip("the adapter declares durable=False (state dies with the process)")
        k = "crash:%s" % run
        first = handle()
        assert _claimed(first.claim(k, 1)), "claim refused"
        # the instance dies right after the admission, before its handler ran: no close, no cleanup
        if crash is not None:
            crash()
        if restart is not None:
            restart()
        again = handle()
        assert not _claimed(again.claim(k, 1)), "the proof admitted before the crash was admitted again"
        assert _claimed(again.claim(k, 2)), "the next counter must be admitted after the crash"

    try:
        _run(report, "claim-sequence", sequence)
        _run(report, "claim-burst", burst)
        _run(report, "claim-concurrent", concurrent)
        _run(report, "claim-durability", durability)
        _run(report, "crash-after-claim", crash_after_claim)
    finally:
        for h in opened:
            try:
                _close(h)
            except Exception:  # noqa: BLE001
                pass
        if teardown is not None:
            teardown()
    return report


# ---- operation-record store -----------------------------------------------------------------------------------------------

def _record(i: str, state: str = "pending") -> dict:
    return {"id": i, "state": state, "verb": "v", "resource": "/r", "params_digest": "d", "reversibility": "reversible", "startedAt": 1}


def run_operation_store_conformance(open_store: Callable[[], Any], *, durable: bool = True, shared: bool = True,
                                    restart: Optional[Callable[[], None]] = None, teardown: Optional[Callable[[], None]] = None,
                                    threads: int = 16, rounds: int = 5, handles: int = 4,
                                    name: str = "operation store") -> ConformanceReport:
    """Run the operation-store contract: ``create(record) -> None | existing``, ``get(id)``, ``transition(id, from, next) ->
    bool`` (see :class:`atlas_pca.OperationStore`)."""
    report = ConformanceReport(name)
    run = uuid.uuid4().hex[:12]
    opened: List[Any] = []

    def handle() -> Any:
        h = open_store()
        opened.append(h)
        for m in ("create", "get", "transition"):
            if not callable(getattr(h, m, None)):
                raise AssertionError("the store has no %s()" % m)
        return h

    def semantics() -> None:
        s, i = handle(), "op-sem:%s" % run
        assert s.get(i) is None, "get of an unknown id must be None"
        assert s.create(_record(i)) is None, "create of a new id must return None"
        again = s.create(dict(_record(i), verb="other"))
        assert isinstance(again, dict) and again.get("verb") == "v", "create of an existing id must return the existing record unchanged"
        assert s.transition("nope:%s" % run, "pending", _record("nope")) is False, "transition of an unknown id must be False"
        assert s.transition(i, "executing", _record(i, "executing")) is False, "transition from the wrong state must be False"
        assert s.get(i)["state"] == "pending", "a refused transition changed the record"
        assert s.transition(i, "pending", dict(_record(i, "executing"), executingAt=2)) is True
        assert s.get(i)["state"] == "executing" and s.get(i).get("executingAt") == 2
        assert s.transition(i, "pending", _record(i, "aborted")) is False, "the old state must no longer match"

    def copies() -> None:
        s, i = handle(), "op-copy:%s" % run
        s.create(_record(i))
        got = s.get(i)
        got["state"] = "committed"
        assert s.get(i)["state"] == "pending", "get must return a copy, not the stored record"
        mine = _record(i + "-b")
        s.create(mine)
        mine["state"] = "failed"
        assert s.get(i + "-b")["state"] == "pending", "create must store a copy of the record it was given"

    def create_race() -> str:
        s = handle()
        for r in range(rounds):
            i = "op-create:%s:%d" % (run, r)
            rs = _race(threads, lambda n, i=i: s.create(_record(i)))
            _check_no_errors(rs)
            wins = sum(1 for x in rs if x is None)
            assert wins == 1, "round %d: %d of %d concurrent creates reported 'created' (want exactly 1)" % (r, wins, threads)
        return "%d rounds x %d threads" % (rounds, threads)

    def transition_race() -> str:
        s = handle()
        for r in range(rounds):
            i = "op-cas:%s:%d" % (run, r)
            s.create(_record(i))
            rs = _race(threads, lambda n, i=i: s.transition(i, "pending", dict(_record(i, "executing"), executingAt=n)))
            _check_no_errors(rs)
            wins = sum(1 for x in rs if x is True)
            assert wins == 1, "round %d: %d of %d concurrent pending->executing transitions succeeded (want exactly 1)" % (r, wins, threads)
        return "%d rounds x %d threads" % (rounds, threads)

    def cross_handle() -> str:
        if not shared:
            raise _Skip("the adapter declares shared=False (a process-local store)")
        hs = [handle() for _ in range(handles)]
        i = "op-shared:%s" % run
        rs = _race(threads, lambda n: hs[n % handles].create(_record(i)))
        _check_no_errors(rs)
        assert sum(1 for x in rs if x is None) == 1, "creates over %d handles: not exactly one 'created'" % handles
        rs = _race(threads, lambda n: hs[n % handles].transition(i, "pending", dict(_record(i, "executing"), executingAt=n)))
        _check_no_errors(rs)
        assert sum(1 for x in rs if x is True) == 1, "transitions over %d handles: not exactly one success" % handles
        return "over %d handles" % handles

    def durability() -> None:
        if not durable:
            raise _Skip("the adapter declares durable=False (state dies with the process)")
        i = "op-dur:%s" % run
        h = handle()
        h.create(_record(i))
        h.transition(i, "pending", dict(_record(i, "executing"), executingAt=3))
        for x in opened:
            _close(x)
        if restart is not None:
            restart()
        got = handle().get(i)
        assert got is not None and got["state"] == "executing" and got.get("executingAt") == 3, "the record did not survive closing every handle"

    try:
        _run(report, "semantics", semantics)
        _run(report, "copies", copies)
        _run(report, "create-race", create_race)
        _run(report, "transition-race", transition_race)
        _run(report, "cross-handle", cross_handle)
        _run(report, "durability", durability)
    finally:
        for h in opened:
            try:
                _close(h)
            except Exception:  # noqa: BLE001
                pass
        if teardown is not None:
            teardown()
    return report
