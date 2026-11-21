"""The linearizability conformance run for replay / counter stores (port of the TypeScript reference, @atlasauth/pca-store-conformance):
history recording, the workloads (same-key bursts, a windowed concurrent run, a retention run, a durability run), the reference
adapters (good ones the kit must pass, bad ones it MUST flag) and the run itself with a text or JSON report. Checking is
:mod:`atlas_pca.store_conformance_model`.

A store adapter is a :class:`StoreAdapter`: ``open()`` returns one client on the shared backend (one simulated verifier instance) with
``consume_once(key, retain_until_ms, now_ms) -> bool`` and / or ``advance(stream_key, counter) -> bool`` and optionally ``close()``.
The contract: ``consume_once`` is true iff there is no live record for ``key`` (live = its stored horizon is ``>= now_ms``), then records
``retain_until_ms``; ``advance`` is true iff the counter is strictly greater than the stored one, then stores it; both are atomic across
every client, durable and fail closed (raise when they cannot decide).

The multi-process crash test (child processes killed with SIGKILL, :mod:`atlas_pca.store_conformance_crash`) runs when ``opts["crash"]``
names the adapter module (``{"module": path, "options": {...}, "processes", "killEveryMs"}``); otherwise it is reported as skipped. Operation options use the reference's spelling (``clients``, ``durationMs``, ``windowMs``, ``spread``, ``values``,
``retentionMs``, ``opTimeoutMs``, ``rounds``, ``revisitKeys``, ``namespace``, ``seed``, ``budget``, ``minimize``, ``minimizeLimit``)."""
from __future__ import annotations

import math
import os
import random
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from ._fin import fin
from .store_conformance_model import (
    check_history,
    format_ops,
    format_report,
    overall,
    prng,
    report_json,
)

ALL_TESTS = ("burst", "concurrent", "retention", "durability", "crash")


def clock() -> float:
    """Wall-clock milliseconds with sub-millisecond resolution."""
    return time.time() * 1000.0


class StoreAdapter:
    """``name``, ``open()`` and optionally ``capabilities`` (``consumeOnce`` / ``advance`` / ``durable`` flags; durable defaults to true:
    a replay store that forgets on restart resurrects nonces), ``restart()``, ``crash()`` and ``teardown()``."""

    def __init__(self, name: str, open: Callable[[], Any], capabilities: Optional[dict] = None, restart: Optional[Callable[[], Any]] = None,  # noqa: A002
                 crash: Optional[Callable[[], Any]] = None, teardown: Optional[Callable[[], Any]] = None) -> None:
        self.name, self.open = name, open
        self.capabilities = capabilities or {}
        self.restart, self.crash, self.teardown = restart, crash, teardown


# ---- recording ---------------------------------------------------------------------------------------------------------------

class MemoryRecorder:
    """The invocation is recorded BEFORE the request leaves the client and the response after it completes. An operation that errors or
    times out keeps an open-ended interval (``ret = inf``, outcome unknown)."""

    def __init__(self) -> None:
        self.ops: List[dict] = []
        self._lock = threading.Lock()

    def invoke(self, client: str, kind: str, key: str, lo: Any, w: Any) -> dict:
        op = {"client": client, "kind": kind, "key": key, "lo": lo, "w": w, "call": clock(), "ret": math.inf, "res": "unknown"}
        with self._lock:
            self.ops.append(op)
        return op

    def complete(self, op: dict, result: Any) -> None:
        if result == "unknown":
            return
        op["ret"] = clock()
        op["res"] = "true" if result else "false"


class FileRecorder:
    """Appends ``i`` / ``r`` lines to ``path`` (one ``write`` per event, so a killed process leaves its operations pending);
    ``proc`` must be unique per process incarnation. Read back with ``parse_history``."""

    def __init__(self, path: str, proc: str) -> None:
        self._fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        self._proc, self._seq, self._ids = proc, 0, {}
        self._lock = threading.Lock()

    def invoke(self, client: str, kind: str, key: str, lo: Any, w: Any) -> dict:
        import json
        op = {"client": client, "kind": kind, "key": key, "lo": lo, "w": w, "call": clock(), "ret": math.inf, "res": "unknown"}
        with self._lock:
            self._seq += 1
            self._ids[id(op)] = self._seq
            os.write(self._fd, (json.dumps(["i", self._proc, self._seq, op["call"], client, kind, key, lo, w]) + "\n").encode("utf-8"))
        return op

    def complete(self, op: dict, result: Any) -> None:
        import json
        with self._lock:
            os.write(self._fd, (json.dumps(["r", self._proc, self._ids.get(id(op)), clock(), "unknown" if result == "unknown" else str(bool(result)).lower()]) + "\n").encode("utf-8"))

    def close(self) -> None:
        os.close(self._fd)


# ---- workloads -----------------------------------------------------------------------------------------------------------------

def random_namespace() -> str:
    return "pcasc-%x-%s" % (int(time.time() * 1000), "%06x" % random.getrandbits(24))


def settle(fn: Callable[[], Any], timeout_ms: float) -> Any:
    """Settle ``fn()`` as a definite boolean, or ``"unknown"`` on an exception, a timeout or a non-boolean answer."""
    box: List[Any] = []

    def run() -> None:
        try:
            box.append(("ok", fn()))
        except BaseException as e:  # noqa: BLE001
            box.append(("err", e))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout_ms / 1000.0)
    if t.is_alive() or not box or box[0][0] != "ok" or not isinstance(box[0][1], bool):
        return "unknown"
    return box[0][1]


def perform(c: Any, client: str, kind: str, key: str, value: Any, ctx: dict) -> Any:
    """Record and perform one operation. For ``advance``, ``value`` is the counter; for ``consume`` it is ignored."""
    now = int(time.time() * 1000)
    lo = now if kind == "consume" else value
    w = now + ctx["retentionMs"] if kind == "consume" else value
    op = ctx["rec"].invoke(client, kind, key, lo, w)
    r = settle((lambda: c.consume_once(key, w, now)) if kind == "consume" else (lambda: c.advance(key, value)), ctx["opTimeoutMs"])
    ctx["rec"].complete(op, r)
    return r


def _parallel(fns: List[Callable[[], Any]]) -> List[Any]:
    """Run every callable in its own thread, released together; an exception is returned as a value."""
    gate, out = threading.Barrier(len(fns)) if fns else None, [None] * len(fns)

    def go(i: int) -> None:
        try:
            gate.wait(timeout=60)
            out[i] = fns[i]()
        except BaseException as e:  # noqa: BLE001
            out[i] = e

    ts = [threading.Thread(target=go, args=(i,), daemon=True) for i in range(len(fns))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out


def open_clients(adapter: StoreAdapter, n: int) -> List[Any]:
    return [adapter.open() for _ in range(n)]


def close_clients(clients: List[Any]) -> None:
    for c in clients:
        close = getattr(c, "close", None)
        if callable(close):
            close()


def _defaults(o: dict) -> dict:
    def g(k: str, d: Any) -> Any:
        return o[k] if o.get(k) is not None else d

    return {"clients": g("clients", 16), "durationMs": g("durationMs", 2000), "windowMs": g("windowMs", 5), "spread": g("spread", 3),
            "values": g("values", 20), "retentionMs": g("retentionMs", 600_000), "opTimeoutMs": g("opTimeoutMs", 5000), "rounds": g("rounds", 20),
            "revisitKeys": g("revisitKeys", 500), "namespace": g("namespace", random_namespace()), "seed": g("seed", random.getrandbits(31))}


def _unknown(ops: List[dict]) -> int:
    return len([o for o in ops if o["res"] == "unknown"])


def drive_windowed(c: Any, client: str, kind: str, ctx: dict, namespace: str, window_ms: Any, spread: int, values: int, origin: float,
                   deadline: float, rand: Callable[[int], int], now: Optional[Callable[[], float]] = None) -> None:
    """The client loop of the concurrent run: until ``deadline``, pick one of the ``spread`` keys of the current window (all clients compute
    the same window from ``origin``) and operate on it."""
    now = now or clock
    while now() < deadline:
        win = int(math.floor((now() - origin) / window_ms))
        key = "%s:%s:%d:%d" % (namespace, kind, win, rand(spread))
        perform(c, client, kind, key, rand(values), ctx)


def run_burst(adapter: StoreAdapter, kind: str, opts: Optional[dict] = None) -> dict:
    """``rounds`` times: every client fires one operation at the SAME fresh key at once."""
    o = _defaults(opts or {})
    rand = prng(o["seed"])
    rec = MemoryRecorder()
    ctx = {"rec": rec, "retentionMs": o["retentionMs"], "opTimeoutMs": o["opTimeoutMs"]}
    clients = open_clients(adapter, o["clients"])
    try:
        for r in range(o["rounds"]):
            key = "%s:%s:burst:%d" % (o["namespace"], kind, r)
            vals = [rand(o["values"]) for _ in clients]
            _parallel([(lambda c=c, i=i, v=v: perform(c, "c%d" % i, kind, key, v, ctx)) for i, (c, v) in enumerate(zip(clients, vals))])
    finally:
        close_clients(clients)
    return {"ops": rec.ops, "errors": _unknown(rec.ops)}


def run_concurrent(adapter: StoreAdapter, kind: str, opts: Optional[dict] = None) -> dict:
    """Every client loops on the windowed keys for ``durationMs``."""
    o = _defaults(opts or {})
    rec = MemoryRecorder()
    ctx = {"rec": rec, "retentionMs": o["retentionMs"], "opTimeoutMs": o["opTimeoutMs"]}
    clients = open_clients(adapter, o["clients"])
    origin = clock()
    try:
        _parallel([(lambda c=c, i=i: drive_windowed(c, "c%d" % i, kind, ctx, o["namespace"], o["windowMs"], o["spread"], o["values"], origin,
                                                    origin + o["durationMs"], prng(o["seed"] + i))) for i, c in enumerate(clients)])
    finally:
        close_clients(clients)
    return {"ops": rec.ops, "errors": _unknown(rec.ops)}


def run_retention(adapter: StoreAdapter, kind: str, opts: Optional[dict] = None) -> dict:
    """Write ``revisitKeys`` distinct keys (consume once / advance to 1), then revisit every one while it is still live (same counter): each
    revisit must answer false. Catches early pruning and capacity eviction of live records."""
    o = _defaults(opts or {})
    rec = MemoryRecorder()
    ctx = {"rec": rec, "retentionMs": o["retentionMs"], "opTimeoutMs": o["opTimeoutMs"]}
    clients = open_clients(adapter, o["clients"])
    keys = ["%s:%s:keep:%d" % (o["namespace"], kind, i) for i in range(o["revisitKeys"])]
    try:
        for ps in ("write", "revisit"):
            for i in range(0, len(keys), len(clients)):
                _parallel([(lambda c=c, j=j: perform(c, "%s-c%d" % (ps, j), kind, keys[i + j], 1, ctx)) for j, c in enumerate(clients) if i + j < len(keys)])
    finally:
        close_clients(clients)
    return {"ops": rec.ops, "errors": _unknown(rec.ops)}


def run_durability(adapter: StoreAdapter, kind: str, opts: Optional[dict] = None) -> dict:
    """Consume a key / advance a stream to 7, close the client, ``restart()`` the backend when the adapter can, open a new client and read
    back: the key must stay consumed and the counter must not go backwards (7 refused, 8 accepted)."""
    o = _defaults(opts or {})
    rec = MemoryRecorder()
    ctx = {"rec": rec, "retentionMs": o["retentionMs"], "opTimeoutMs": o["opTimeoutMs"]}
    key = "%s:%s:durable" % (o["namespace"], kind)
    before = adapter.open()
    try:
        perform(before, "before-restart", kind, key, 7, ctx)
    finally:
        close_clients([before])
    if adapter.restart:
        adapter.restart()
    after = adapter.open()
    try:
        perform(after, "after-restart", kind, key, 7, ctx)
        if kind == "advance":
            perform(after, "after-restart", kind, key, 8, ctx)
    finally:
        close_clients([after])
    return {"ops": rec.ops, "errors": _unknown(rec.ops),
            "note": "backend restarted between write and read" if adapter.restart else "no restart() hook: clients closed and re-opened only"}


# ---- reference adapters --------------------------------------------------------------------------------------------------------

def _lock_store(capacity: Optional[int] = None, strict: bool = True, yield_between: bool = False) -> Callable[[], dict]:
    """A process-local replay / counter store; the knobs reproduce the real mistakes of the bad adapters."""
    seen: Dict[str, Any] = {}
    counters: Dict[str, Any] = {}
    lock = threading.Lock()

    def evict(m: dict) -> None:
        while capacity is not None and len(m) > capacity:
            del m[next(iter(m))]

    def open_() -> dict:
        def consume_once(k: str, r: Any, now: Any) -> bool:
            if yield_between:
                until = seen.get(k)
                time.sleep(0.001)  # a real sleep always hands the interpreter to the other clients (sleep(0) did not on every platform)
                if until is not None and not (fin(now) and until < now):
                    return False
                seen[k] = r
                return True
            with lock:
                until = seen.get(k)
                if until is not None and not (fin(now) and until < now):
                    return False
                seen[k] = r
                evict(seen)
                return True

        def advance(k: str, c: Any) -> bool:
            if yield_between:
                last = counters.get(k)
                time.sleep(0.001)  # a real sleep always hands the interpreter to the other clients (sleep(0) did not on every platform)
                if last is not None and not (c > last):
                    return False
                counters[k] = c
                return True
            with lock:
                last = counters.get(k)
                if last is not None and (c < last if not strict else not (c > last)):
                    return False
                counters[k] = c
                evict(counters)
                return True

        return {"consume_once": consume_once, "advance": advance}

    return open_


class _Client:
    def __init__(self, fns: dict) -> None:
        for k, v in fns.items():
            setattr(self, k, v)


def in_memory_adapter() -> StoreAdapter:
    """GOOD for ONE process: a lock-protected store. Not durable (declared)."""
    o = _lock_store()
    return StoreAdapter("in-memory (lock-protected dict)", lambda: _Client(o()), {"durable": False})


def durable_file_adapter(directory: Optional[str] = None) -> StoreAdapter:
    """GOOD: a crash-safe file store (SQLite through ``SqliteAtomicKv``), one handle per client, atomic ``update``."""
    from .atomic_kv import SqliteAtomicKv

    d = directory or tempfile.mkdtemp(prefix="pcasc-durable-")
    path = os.path.join(d, "state.sqlite")

    def open_() -> Any:
        kv = SqliteAtomicKv(path)

        def consume_once(key: str, retain_until: Any, now: Any) -> bool:
            if not (fin(now, retain_until) and retain_until >= now):
                raise ValueError("consume_once: retain_until_ms is before now_ms")
            first = [False]

            def fn(prev: Any) -> Any:
                if isinstance(prev, (int, float)) and not isinstance(prev, bool) and not (fin(now) and prev < now):
                    return None
                first[0] = True
                return retain_until  # any old horizon is < now <= retain_until here, so the new one is the larger

            kv.update("n:" + key, fn)
            return first[0]

        def advance(key: str, counter: Any) -> bool:
            ok = [False]

            def fn(prev: Any) -> Any:
                if isinstance(prev, (int, float)) and not isinstance(prev, bool) and not (counter > prev):
                    return None
                ok[0] = True
                return counter

            kv.update("c:" + key, fn)
            return ok[0]

        return _Client({"consume_once": consume_once, "advance": advance, "close": kv.close})

    # everything is on disk and every client re-opens the file: a restart loses nothing by construction
    return StoreAdapter("durable file store (%s)" % d, open_, {"durable": True}, restart=lambda: None)


def read_then_write_adapter() -> StoreAdapter:
    """BAD: read, then write after a yield (no transaction / no compare-and-set). Two clients both read "absent"."""
    o = _lock_store(yield_between=True)
    return StoreAdapter("BAD read-then-write (a yield between check and set)", lambda: _Client(o()), {"durable": False})


def volatile_adapter() -> StoreAdapter:
    """BAD: claims durability but keeps state in process memory, so a restart forgets every consumed key and counter."""
    holder = {"o": _lock_store()}
    return StoreAdapter("BAD volatile (state lost on restart)", lambda: _Client(holder["o"]()), {"durable": True},
                        restart=lambda: holder.__setitem__("o", _lock_store()))


def evicting_adapter(capacity: Any = 64) -> StoreAdapter:
    """BAD: a bounded cache that evicts the oldest record when full, LIVE or not (capacity eviction / early prune)."""
    cap = int(capacity)
    o = _lock_store(capacity=cap)
    return StoreAdapter("BAD evicting cache (capacity %d, evicts live records)" % cap, lambda: _Client(o()), {"durable": False})


def non_strict_counter_adapter() -> StoreAdapter:
    """BAD: a counter that accepts a value EQUAL to the last one (``>=`` instead of ``>``), so one counter is accepted twice."""
    o = _lock_store(strict=False)
    return StoreAdapter("BAD non-strict counter (accepts an equal value)",
                        lambda: _Client({"advance": o()["advance"]}), {"durable": False, "consumeOnce": False})


#: Built-in adapters by name; each takes the options dict.
REFERENCE_ADAPTERS: Dict[str, Callable[[dict], StoreAdapter]] = {
    "in-memory": lambda o: in_memory_adapter(),
    "durable-file": lambda o: durable_file_adapter(o.get("dir")),
    "bad-read-then-write": lambda o: read_then_write_adapter(),
    "bad-volatile": lambda o: volatile_adapter(),
    "bad-evicting": lambda o: evicting_adapter(o.get("capacity", 64)),
    "bad-non-strict-counter": lambda o: non_strict_counter_adapter(),
}


# ---- the run ---------------------------------------------------------------------------------------------------------------------

def detect_kinds(adapter: StoreAdapter) -> List[str]:
    """Which operations the adapter implements: declared capabilities win, else what its first client exposes."""
    caps = adapter.capabilities or {}
    c = adapter.open()
    try:
        kinds: List[str] = []
        if caps["consumeOnce"] if caps.get("consumeOnce") is not None else callable(getattr(c, "consume_once", None)):
            kinds.append("consume")
        if caps["advance"] if caps.get("advance") is not None else callable(getattr(c, "advance", None)):
            kinds.append("advance")
        return kinds
    finally:
        close_clients([c])


def judge(test: str, kind: str, w: dict, opts: dict) -> dict:
    h = check_history(w["ops"], opts)
    definite = h["outcomes"]["true"] + h["outcomes"]["false"]
    status = "fail" if h["violations"] else "unresolved" if h["unresolved"] or definite == 0 else "pass"
    notes = [n for n in (w.get("note"), "no definite answer was observed (every call failed or timed out)" if definite == 0 else None) if n]
    out = {"test": test, "kind": kind, "status": status, "ops": h["ops"], "keys": h["keys"], "errors": w["errors"], "violations": h["violations"],
           "unresolved": len(h["unresolved"])}
    if notes:
        out["note"] = "; ".join(notes)
    return out


def _skip(test: str, kind: str, note: str) -> dict:
    return {"test": test, "kind": kind, "status": "skip", "ops": 0, "keys": 0, "errors": 0, "violations": [], "unresolved": 0, "note": note}


def run_test(adapter: StoreAdapter, test: str, kind: str, opts: Optional[dict] = None) -> dict:
    opts = opts or {}
    if test == "durability" and (adapter.capabilities or {}).get("durable") is False:
        return _skip(test, kind, "the adapter declares durable: false (only correct for one process whose lifetime covers the action lifetime)")
    if test == "crash" and not (opts.get("crash") or {}).get("module"):
        return _skip(test, kind, "needs the adapter module path (the crash test runs the adapter in child processes)")
    if test == "crash":
        from .store_conformance_crash import run_crash  # lazy: the harness imports this module

        w = run_crash(kind, {**opts, **opts["crash"]})
    else:
        w = {"burst": run_burst, "concurrent": run_concurrent, "retention": run_retention, "durability": run_durability}[test](adapter, kind, opts)
    return judge(test, kind, w, opts)


def run_conformance(adapter: StoreAdapter, opts: Optional[dict] = None) -> dict:
    """Every test for every operation the adapter implements, each history checked for linearizability. ``opts["tests"]`` selects tests."""
    opts = opts or {}
    kinds = detect_kinds(adapter)
    if not kinds:
        raise TypeError("%s: the client implements neither consume_once nor advance" % adapter.name)
    tests = [run_test(adapter, t, k, opts) for t in (opts.get("tests") or ALL_TESTS) for k in kinds]
    return {"adapter": adapter.name, "status": overall(tests), "tests": tests}


__all__ = ["ALL_TESTS", "REFERENCE_ADAPTERS", "FileRecorder", "MemoryRecorder", "StoreAdapter", "check_history", "clock", "detect_kinds",
           "drive_windowed", "durable_file_adapter", "evicting_adapter", "format_ops", "format_report", "in_memory_adapter", "judge", "non_strict_counter_adapter",
           "overall", "perform", "prng", "random_namespace", "read_then_write_adapter", "report_json", "run_burst", "run_concurrent", "run_conformance",
           "run_durability", "run_retention", "run_test", "settle", "volatile_adapter"]
