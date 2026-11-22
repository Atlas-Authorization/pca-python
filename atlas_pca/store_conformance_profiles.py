"""Conformance profiles for the stores behind the operational plane (port of the TypeScript reference, @atlasauth/pca-store-conformance):
guardian lease stores, transparency-log ledger stores, aggregate budget ledgers, bond-settlement stores and mesh-witness state stores.
Each profile is a list of checks, each one a single claim driven against YOUR store through an adapter; a check that fails raises with the
exact mismatch and the run reports it.

An adapter is a :class:`ProfileAdapter` (``name``, ``create()`` and an optional ``durable`` flag, default true: declare ``False`` ONLY for an
in-process store; the durability checks are then skipped and reported). ``create()`` returns a fresh, empty, isolated backend as a
:class:`StoreHandle`: ``store`` (the client), ``reopen()`` (another client on the SAME backend; after a restart this is how state is read
back), optionally ``crash()`` (kill the backend abruptly, then return a client on whatever survived) and ``close()``. Store methods are the
reference's, snake_cased where the reference camel-cases (``cas``, ``read``, ``now``; ``append``, ``size``, ``checkpoint_count``,
``append_checkpoint``; ``reserve``, ``snapshot``, ``commit``, ``release``, ``start``, ``expire``, ``durable``; ``read``, ``deposit``,
``commit``); records and plans are dicts with the reference's member names. Concurrency is real threads.

Not ported: the reference's own in-memory / durable-file / defective reference adapters of these profiles (they wrap the TypeScript store
implementations, which this SDK does not carry)."""
from __future__ import annotations

from ._fin import fin
import copy
import math
import threading
from typing import Any, Callable, Dict, List, Optional

from .store_conformance_runner import _parallel

_MAX_SAFE = 2 ** 53 - 1


class StoreHandle:
    def __init__(self, store: Any, reopen: Callable[[], Any], crash: Optional[Callable[[], Any]] = None, close: Optional[Callable[[], Any]] = None) -> None:
        self.store, self.reopen, self.crash, self.close = store, reopen, crash, close
        self.adapter_durable: Optional[bool] = None


class ProfileAdapter:
    def __init__(self, name: str, create: Callable[[], StoreHandle], durable: Optional[bool] = None) -> None:
        self.name, self.create, self.durable = name, create, durable


class Check:
    def __init__(self, name: str, claim: str, run: Callable[[StoreHandle], None], needs: Optional[str] = None) -> None:
        self.name, self.claim, self.run, self.needs = name, claim, run, needs


# ---- assertions ---------------------------------------------------------------------------------------------------------------

def _same(a: Any, b: Any) -> bool:
    """Strict deep equality: a bool is not a number, tuples are lists, objects compare by key set."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b or (a != a and b != b)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_same(a[k], b[k]) for k in a)
    return a == b


def _eq(got: Any, want: Any, msg: str = "") -> None:
    if not _same(got, want):
        raise AssertionError("%sexpected %r, got %r" % (msg + ": " if msg else "", want, got))


def _ok(cond: Any, msg: str = "") -> None:
    if not cond:
        raise AssertionError(msg or "assertion failed")


def _rejects(fn: Callable[[], Any], exc: type = Exception) -> None:
    try:
        fn()
    except exc:
        return
    raise AssertionError("expected an error, none was raised")


def _race(fns: List[Callable[[], Any]]) -> List[Any]:
    """Run every callable at once in its own thread; an exception is re-raised after all have finished."""
    out = _parallel(fns)
    for r in out:
        if isinstance(r, BaseException):
            raise r
    return out


def _background(fn: Callable[[], Any]) -> None:
    """Start ``fn`` without waiting for it; whatever it raises is dropped (an operation in flight at a crash)."""
    def go() -> None:
        try:
            fn()
        except BaseException:  # noqa: BLE001
            pass

    threading.Thread(target=go, daemon=True).start()


# ---- guardian lease stores ------------------------------------------------------------------------------------------------------
# The guardian lease helpers the profile drives: a lease store is ``read() -> record | None``, ``now() -> epoch ms`` and
# ``cas(expected | None, next) -> bool`` (replace iff the stored record equals ``expected``, atomically; ``next.epoch`` never below the stored one).

DEFAULT_LEASE_SKEW_MS = 1_000
MAX_LEASE_TTL_MS = 3_600_000
_MAX_HOLDER_LEN = 256


def _is_int(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x) and x == math.floor(x)


def _valid_record(r: Any) -> bool:
    return (isinstance(r, dict) and isinstance(r.get("holder"), str) and _is_int(r.get("epoch")) and abs(r["epoch"]) <= _MAX_SAFE and r["epoch"] >= 1
            and isinstance(r.get("expiresAt"), (int, float)) and not isinstance(r["expiresAt"], bool) and fin(r["expiresAt"]) and r["expiresAt"] >= 0)


def _lease_opts(holder: Any, o: Any) -> Optional[tuple]:
    if not isinstance(holder, str) or len(holder) == 0 or len(holder) > _MAX_HOLDER_LEN:
        return None
    o = o if isinstance(o, dict) else {}
    skew = o["skewMs"] if o.get("skewMs") is not None else DEFAULT_LEASE_SKEW_MS
    ttl = o.get("ttlMs")
    if not _is_int(ttl) or ttl < 2 or ttl > MAX_LEASE_TTL_MS:
        return None
    if not isinstance(skew, (int, float)) or isinstance(skew, bool) or not fin(skew) or skew < 0 or skew >= ttl:
        return None
    return ttl, skew


def _snapshot(store: Any) -> tuple:
    cur = store.read()
    now = store.now()
    if not isinstance(now, (int, float)) or isinstance(now, bool) or not fin(now) or (cur is not None and not _valid_record(cur)):
        raise RuntimeError("corrupt lease state")
    return cur, now


def _fail(reason: str, **extra: Any) -> dict:
    return {"ok": False, "reason": reason, **extra}


def acquire_lease(store: Any, holder: str, o: dict) -> dict:
    """Take the lease if it is free (never held, released, or expired past the skew). The epoch increments on every takeover."""
    p = _lease_opts(holder, o)
    if not p:
        return _fail("invalid")
    try:
        cur, now = _snapshot(store)
        if cur is not None and cur["expiresAt"] + p[1] > now and cur["expiresAt"] != 0:
            return _fail("held")
        nxt = {"holder": holder, "epoch": (cur["epoch"] if cur is not None else 0) + 1, "expiresAt": now + p[0]}
        return {"ok": True, "lease": nxt} if store.cas(cur, nxt) else _fail("lost-race")
    except Exception as e:  # noqa: BLE001
        return _fail("store-error", detail=str(e) or "unknown")


def renew_lease(store: Any, lease: dict, o: dict) -> dict:
    """Extend a lease the caller still holds; refused once the holder's own safe window has passed, or after any takeover."""
    p = _lease_opts(lease.get("holder"), o) if _valid_record(lease) else None
    if not p:
        return _fail("invalid")
    try:
        cur, now = _snapshot(store)
        if cur is None or cur["holder"] != lease["holder"] or cur["epoch"] != lease["epoch"]:
            return _fail("stale")
        if cur["expiresAt"] - p[1] <= now:
            return _fail("expired")
        nxt = {"holder": cur["holder"], "epoch": cur["epoch"], "expiresAt": now + p[0]}
        return {"ok": True, "lease": nxt} if store.cas(cur, nxt) else _fail("lost-race")
    except Exception as e:  # noqa: BLE001
        return _fail("store-error", detail=str(e) or "unknown")


def release_lease(store: Any, lease: dict) -> dict:
    """Give the lease up early (``expiresAt`` 0, epoch kept). Only the current holder at the current epoch can."""
    if not _valid_record(lease):
        return _fail("invalid")
    try:
        cur, _ = _snapshot(store)
        if cur is None or cur["holder"] != lease["holder"] or cur["epoch"] != lease["epoch"] or cur["expiresAt"] == 0:
            return _fail("stale")
        nxt = {"holder": cur["holder"], "epoch": cur["epoch"], "expiresAt": 0}
        return {"ok": True, "lease": nxt} if store.cas(cur, nxt) else _fail("lost-race")
    except Exception as e:  # noqa: BLE001
        return _fail("store-error", detail=str(e) or "unknown")


_LO = {"ttlMs": 600_000, "skewMs": 1_000}


def _won(s: Any, who: str) -> dict:
    r = acquire_lease(s, who, _LO)
    _ok(r["ok"], "acquire for %s failed: %s" % (who, "" if r["ok"] else r["reason"]))
    return r["lease"]


def _lease_empty(h: StoreHandle) -> None:
    _eq(h.store.read(), None)
    n = h.store.now()
    _ok(isinstance(n, (int, float)) and not isinstance(n, bool) and fin(n))


def _lease_first(h: StoreHandle) -> None:
    l = _won(h.store, "a")
    _eq(l["epoch"], 1)
    _eq(h.store.read(), l)
    _ok(l["expiresAt"] > h.store.now())


def _lease_wrong_expected(h: StoreHandle) -> None:
    s = h.store
    _eq(s.cas({"holder": "x", "epoch": 1, "expiresAt": 5}, {"holder": "y", "epoch": 2, "expiresAt": 9}), False)
    _eq(s.read(), None)
    l = _won(s, "a")
    _eq(s.cas(None, {"holder": "y", "epoch": 2, "expiresAt": 9}), False)
    _eq(s.read(), l)


def _lease_race(h: StoreHandle) -> None:
    clients = [h.store, h.reopen(), h.reopen(), h.reopen()]
    fns = []
    for i, c in enumerate(clients):
        fns.append(lambda c=c, i=i: acquire_lease(c, "h%da" % i, _LO))
        fns.append(lambda c=c, i=i: acquire_lease(c, "h%db" % i, _LO))
    rs = _race(fns)
    _eq(len([r for r in rs if r["ok"]]), 1)
    _eq((h.store.read() or {}).get("epoch"), 1)


def _lease_takeover(h: StoreHandle) -> None:
    a = _won(h.store, "a")
    _ok(release_lease(h.store, a)["ok"])
    _eq(_won(h.store, "b")["epoch"], 2)


def _lease_epoch_down(h: StoreHandle) -> None:
    s = h.store
    a = _won(s, "a")
    release_lease(s, a)
    b = _won(s, "b")
    try:
        ok = s.cas(b, {"holder": "z", "epoch": 1, "expiresAt": b["expiresAt"]})
    except Exception:  # noqa: BLE001
        ok = False
    _eq(ok, False)
    _eq(s.read(), b)


def _lease_stale(h: StoreHandle) -> None:
    s = h.store
    a = _won(s, "a")
    release_lease(s, a)
    b = _won(s, "b")
    _eq(renew_lease(s, a, _LO), {"ok": False, "reason": "stale"})
    _eq(release_lease(s, a), {"ok": False, "reason": "stale"})
    _eq(s.read(), b)


def _lease_reopen(h: StoreHandle) -> None:
    l = _won(h.store, "a")
    _eq(h.reopen().read(), l)


def _lease_crash(h: StoreHandle) -> None:
    a = _won(h.store, "a")
    release_lease(h.store, a)
    back = h.crash()
    _eq((back.read() or {}).get("epoch"), 1)
    _eq(_won(back, "b")["epoch"], 2)


GUARDIAN_LEASE_CHECKS: List[Check] = [
    Check("empty-store-has-no-lease", "a new store has no lease and a finite clock", _lease_empty),
    Check("first-acquire-is-epoch-1", "the first holder gets epoch 1 and an expiry from the store clock", _lease_first),
    Check("wrong-expected-record-never-writes", "cas with an expected record that is not the stored one returns false and changes nothing", _lease_wrong_expected),
    Check("racing-acquirers-have-one-winner", "many contenders at once: exactly one acquires, at epoch 1", _lease_race),
    Check("takeover-after-release-bumps-the-epoch", "a released lease is free at once and the next holder gets a strictly higher epoch", _lease_takeover),
    Check("epoch-never-goes-down", "cas refuses a record with a lower epoch even when the expected record matches", _lease_epoch_down),
    Check("stale-holder-cannot-renew-or-release", "after a takeover the old (holder, epoch) is refused as stale for renew and release", _lease_stale),
    Check("state-survives-reopen", "an acknowledged lease is there when another client opens the same backend", _lease_reopen, "durable"),
    Check("acknowledged-lease-survives-a-crash", "after an abrupt backend kill the lease and its epoch are still there, and the next epoch is higher", _lease_crash, "crash"),
]


# ---- ledger stores ---------------------------------------------------------------------------------------------------------------

def _cm(i: int) -> str:
    return "commit-%d-%s" % (i, "x" * 30)


def _cp(size: int, root: Optional[str] = None, prev: str = "") -> dict:
    return {"sth": {"instance_id": "i", "principal": "p", "size": size, "root": root if root is not None else "root-%d" % size, "prev_root": prev,
                    "timestamp": 1, "guardian": "g", "sig": "s"}}


def _range(a: int, b: int) -> List[str]:
    return [_cm(a + i) for i in range(b - a)]


def _all(s: Any) -> List[str]:
    return s.read(0, s.size())


def _append_retrying(s: Any, commit: str) -> int:
    """A writer that retries until its commit is in, the way a real client does."""
    while True:
        size = s.size()
        r = s.append(size, [commit])
        if r["outcome"] in ("appended", "replayed"):
            return size


def _led_empty(h: StoreHandle) -> None:
    s = h.store
    _eq(s.size(), 0)
    _eq(s.read(0, 0), [])
    _eq(s.checkpoint_count(), 0)
    _eq(s.checkpoints(0), [])


def _led_next_position(h: StoreHandle) -> None:
    s = h.store
    _eq(s.append(0, [_cm(0)]), {"outcome": "appended", "size": 1})
    _eq(s.append(1, [_cm(1), _cm(2)]), {"outcome": "appended", "size": 3})
    _eq(s.read(0, 3), _range(0, 3))
    _eq(s.read(1, 3), _range(1, 3))
    _eq(s.read(3, 3), [])


def _led_conflict(h: StoreHandle) -> None:
    s = h.store
    s.append(0, _range(0, 3))
    _eq(s.append(5, [_cm(9)]), {"outcome": "conflict", "size": 3})
    _eq(s.append(2, [_cm(9)]), {"outcome": "conflict", "size": 3})
    _eq(_all(s), _range(0, 3))


def _led_replay(h: StoreHandle) -> None:
    s = h.store
    s.append(0, _range(0, 3))
    _eq(s.append(0, _range(0, 3)), {"outcome": "replayed", "size": 3})
    _eq(s.append(1, _range(1, 3)), {"outcome": "replayed", "size": 3})
    _eq(s.append(0, [_cm(0), "other"]), {"outcome": "conflict", "size": 3})
    _eq(s.append(2, [_cm(2), _cm(3)]), {"outcome": "conflict", "size": 3})
    _eq(_all(s), _range(0, 3))


def _led_invalid(h: StoreHandle) -> None:
    s = h.store
    s.append(0, [_cm(0)])
    for bad in ([], [""], [_cm(1), 7], "x"):
        _rejects(lambda bad=bad: s.append(1, bad), ValueError)
    for bad in (-1, 1.5, math.nan):
        _rejects(lambda bad=bad: s.append(bad, [_cm(1)]), ValueError)
    _eq(_all(s), [_cm(0)])
    for f, t in ((-1, 1), (1, 0), (0, 2), (0.5, 1)):
        _rejects(lambda f=f, t=t: s.read(f, t), ValueError)


def _led_exact(h: StoreHandle) -> None:
    odd = ['a"b\\c', "gränt-\U0001F512- -\x01", "x" * 5000, "__proto__", " leading and trailing "]
    h.store.append(0, odd)
    _eq(_all(h.store), odd)


def _led_race_one(h: StoreHandle) -> None:
    clients = [h.store, h.reopen(), h.reopen(), h.reopen()]
    r = _race([(lambda i=i: clients[i % 4].append(0, [_cm(100 + i)])) for i in range(8)])
    _eq(len([x for x in r if x["outcome"] == "appended"]), 1)
    _eq(len([x for x in r if x["outcome"] == "conflict"]), 7)
    log = _all(h.store)
    _eq(len(log), 1)
    _ok(log[0] in _range(100, 108))


def _led_race_retry(h: StoreHandle) -> None:
    clients = [h.store, h.reopen(), h.reopen()]
    idx = _race([(lambda i=i: _append_retrying(clients[i % 3], _cm(200 + i))) for i in range(16)])
    _eq(len(set(idx)), 16)
    _eq(sorted(idx), list(range(16)))
    log = _all(h.store)
    _eq(sorted(log), sorted(_range(200, 216)))
    for i, p in enumerate(idx):
        _eq(log[p], _cm(200 + i))


def _led_batch(h: StoreHandle) -> None:
    s = h.store
    s.append(0, _range(0, 2))
    _eq(s.append(5, _range(10, 14))["outcome"], "conflict")
    _eq(_all(s), _range(0, 2))
    _eq(s.append(2, _range(10, 14)), {"outcome": "appended", "size": 6})
    _eq(_all(s), _range(0, 2) + _range(10, 14))


def _led_cp_count(h: StoreHandle) -> None:
    s = h.store
    s.append(0, _range(0, 6))
    _eq(s.append_checkpoint(0, _cp(2)), {"outcome": "appended", "count": 1})
    _eq(s.append_checkpoint(0, _cp(2)), {"outcome": "replayed", "count": 1})
    _eq(s.append_checkpoint(0, _cp(3))["outcome"], "conflict")
    _eq(s.append_checkpoint(2, _cp(3))["outcome"], "conflict")
    _eq(s.append_checkpoint(1, _cp(5, "root-5", "root-2")), {"outcome": "appended", "count": 2})
    _eq([c["sth"]["size"] for c in s.checkpoints(0)], [2, 5])
    _eq([c["sth"]["size"] for c in s.checkpoints(1)], [5])
    _eq(s.checkpoint_count(), 2)


def _led_cp_inside(h: StoreHandle) -> None:
    s = h.store
    s.append(0, _range(0, 4))
    _eq(s.append_checkpoint(0, _cp(5))["outcome"], "conflict")
    _eq(s.append_checkpoint(0, _cp(3))["outcome"], "appended")
    _eq(s.append_checkpoint(1, _cp(2))["outcome"], "conflict")
    _eq(s.append_checkpoint(1, _cp(3, "other-root"))["outcome"], "conflict")
    _eq(s.append_checkpoint(1, _cp(3))["outcome"], "appended")  # equal size, same root: allowed
    _eq(s.append_checkpoint(2, None)["outcome"], "conflict")
    _eq(s.checkpoint_count(), 2)


def _led_cp_race(h: StoreHandle) -> None:
    h.store.append(0, _range(0, 6))
    other = h.reopen()
    r = _race([lambda: h.store.append_checkpoint(0, _cp(2)), lambda: other.append_checkpoint(0, _cp(3)),
               lambda: h.store.append_checkpoint(0, _cp(4)), lambda: other.append_checkpoint(0, _cp(5))])
    _eq(len([x for x in r if x["outcome"] == "appended"]), 1)
    _eq(h.store.checkpoint_count(), 1)


def _led_snapshots(h: StoreHandle) -> None:
    s = h.store
    s.append(0, _range(0, 3))
    s.append_checkpoint(0, _cp(2))
    s.read(0, 3)[0] = "mutated"
    c = s.checkpoints(0)
    c[0]["sth"]["size"] = 99
    _eq(_all(s), _range(0, 3))
    _eq(s.checkpoints(0)[0]["sth"]["size"], 2)


def _led_reopen(h: StoreHandle) -> None:
    h.store.append(0, _range(0, 5))
    h.store.append_checkpoint(0, _cp(3))
    h.store.append(5, _range(5, 7))
    back = h.reopen()
    _eq(_all(back), _range(0, 7))
    _eq(back.checkpoints(0), [_cp(3)])
    _eq(back.append(7, [_cm(7)]), {"outcome": "appended", "size": 8})


def _led_crash(h: StoreHandle) -> None:
    h.store.append(0, _range(0, 3))
    h.store.append_checkpoint(0, _cp(2))
    _background(lambda: h.store.append(3, _range(3, 7)))
    back = h.crash()
    log = _all(back)
    _ok(len(log) in (3, 7), "log has %d entries" % len(log))  # the batch of four is whole or absent
    _eq(log, _range(0, len(log)))
    _eq(back.checkpoints(0), [_cp(2)])
    if len(log) == 3:
        _eq(back.append(3, _range(3, 7)), {"outcome": "appended", "size": 7})
    else:
        _eq(back.append(3, _range(3, 7)), {"outcome": "replayed", "size": 7})
    _eq(_all(back), _range(0, 7))


LEDGER_CHECKS: List[Check] = [
    Check("empty-store-is-empty", "a new store has no entries and no checkpoints, and reads of the empty range succeed", _led_empty),
    Check("append-assigns-the-next-position", "an append at the current length adds its commits in order at exactly those positions", _led_next_position),
    Check("append-at-another-position-conflicts-without-trace", "an append whose expected length is not the current length conflicts, reports the real length, and writes nothing", _led_conflict),
    Check("append-retry-is-a-replay", "repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts", _led_replay),
    Check("invalid-input-is-refused", "empty batches, empty or non-string commits and a bad expected length throw and write nothing", _led_invalid),
    Check("commit-strings-are-stored-exactly", "unicode, quotes, separators and long commits come back byte for byte", _led_exact),
    Check("racing-appends-at-one-position-have-one-winner", "clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch", _led_race_one),
    Check("racing-writers-with-retry-fill-every-position-once", "sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once", _led_race_retry),
    Check("a-batch-is-all-or-nothing", "a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit", _led_batch),
    Check("checkpoints-append-by-count-and-replay", "a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts", _led_cp_count),
    Check("checkpoints-stay-inside-the-log-and-never-go-back", "a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused", _led_cp_inside),
    Check("racing-checkpoints-have-one-winner", "checkpoints racing for one position: exactly one lands", _led_cp_race),
    Check("reads-are-snapshots", "mutating what a read returned cannot change the store", _led_snapshots),
    Check("state-survives-reopen", "every acknowledged append and checkpoint is visible to a new client after the backend restarts", _led_reopen, "durable"),
    Check("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch", _led_crash, "crash"),
]


# ---- budget ledgers -----------------------------------------------------------------------------------------------------------------

_CAP = 200
_K = "principal/alice"
_K2 = "principal/bob"


def _spend(**over: Any) -> dict:
    a = {"id": "spend", "agg": "sum", "val": "action.params.amount", "sel": {"verbs": ["pay"]}, "win": {"kind": "task"}, "key": None,
         "domain_max": _CAP, "holder": {"kind": "site_local"}, "scope": "principal"}
    a.update(over)
    return a


def _ev(i: str, amount: Any, t: Any = 1000) -> dict:
    return {"id": i, "verb": "pay", "resource": "r", "params": {"amount": amount}, "t": t}


def _req(i: str, amount: Any, **extra: Any) -> dict:
    return {"event": _ev(i, amount), "accumulators": [_spend()], **extra}


def _reserved_total(l: Any, key: str = _K) -> Any:
    return sum(e["params"]["amount"] for e in l.snapshot(key)["events"] if e["status"] != "released")


def _bud_empty(h: StoreHandle) -> None:
    _eq(h.store.snapshot(_K), {"version": 0, "events": []})


def _bud_cap(h: StoreHandle) -> None:
    l = h.store
    a = l.reserve(_K, _req("a", 150))
    _eq(a["outcome"], "reserved")
    _eq(a["post"] if a["outcome"] == "reserved" else None, {"spend": 150})
    b = l.reserve(_K, _req("b", 51))
    _eq([b["acc"], b["post"], b["cap"]] if b["outcome"] == "over_cap" else b, ["spend", 201, _CAP])
    _eq(l.reserve(_K, _req("c", 50))["outcome"], "reserved")
    _eq(_reserved_total(l), _CAP)


def _bud_refusal(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 150))
    before = l.snapshot(_K)
    _eq(l.reserve(_K, _req("b", 60))["outcome"], "over_cap")
    _eq(l.snapshot(_K), before)


def _bud_replay(h: StoreHandle) -> None:
    l = h.store
    first = l.reserve(_K, _req("a", 150))
    _eq(l.reserve(_K, _req("a", 150)), {"outcome": "replayed", "version": first["version"], "status": "reserved"})
    _eq(l.reserve(_K, _req("a", 10))["outcome"], "id_conflict")
    _eq(_reserved_total(l), 150)
    _eq(l.reserve(_K, _req("b", 50))["outcome"], "reserved")


def _bud_cas(h: StoreHandle) -> None:
    l = h.store
    _eq(l.reserve(_K, _req("a", 10, expectedVersion=0))["outcome"], "reserved")
    _eq(l.reserve(_K, _req("b", 10, expectedVersion=0)), {"outcome": "conflict", "version": 1})
    _eq(len(l.snapshot(_K)["events"]), 1)
    _eq(l.reserve(_K, _req("b", 10, expectedVersion=1))["outcome"], "reserved")
    _eq(l.reserve(_K, _req("a", 10, expectedVersion=0))["outcome"], "replayed")


def _bud_race_cap(h: StoreHandle) -> None:
    clients = [h.store, h.reopen(), h.reopen(), h.reopen()]
    rs = _race([(lambda i=i: clients[i % 4].reserve(_K, _req("r%d" % i, 30))) for i in range(40)])
    _eq(len([r for r in rs if r["outcome"] == "reserved"]), 6)
    _eq(len([r for r in rs if r["outcome"] == "over_cap"]), 34)
    _eq(_reserved_total(h.store), 180)
    _eq(len({e["id"] for e in h.store.snapshot(_K)["events"]}), 6)


def _bud_race_version(h: StoreHandle) -> None:
    clients = [h.store, h.reopen(), h.reopen()]
    rs = _race([(lambda i=i: clients[i % 3].reserve(_K, _req("v%d" % i, 1, expectedVersion=0))) for i in range(9)])
    _eq(len([r for r in rs if r["outcome"] == "reserved"]), 1)
    _eq(len([r for r in rs if r["outcome"] == "conflict"]), 8)
    _eq(len(h.store.snapshot(_K)["events"]), 1)


def _bud_race_retry(h: StoreHandle) -> None:
    clients = [h.store, h.reopen(), h.reopen()]

    def one(c: Any, i: int) -> str:
        while True:
            s = c.snapshot(_K)
            r = c.reserve(_K, _req("w%d" % i, 10, expectedVersion=s["version"]))
            if r["outcome"] != "conflict":
                return r["outcome"]

    out = _race([(lambda i=i: one(clients[i % 3], i)) for i in range(20)])
    _ok(all(o == "reserved" for o in out), ",".join(out))
    _eq(_reserved_total(h.store), _CAP)
    _eq(h.store.reserve(_K, _req("extra", 1))["outcome"], "over_cap")


def _bud_settle(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 10))
    l.reserve(_K, _req("b", 10))
    _eq(l.commit(_K, "ghost")["outcome"], "unknown")
    _eq(l.release(_K, "ghost")["outcome"], "unknown")
    _eq(l.commit(_K, "a")["outcome"], "settled")
    _eq(l.commit(_K, "a")["outcome"], "replayed")
    r1 = l.release(_K, "a")
    _eq(r1["status"] if r1["outcome"] == "refused" else r1["outcome"], "committed")
    _eq(l.release(_K, "b")["outcome"], "settled")
    _eq(l.release(_K, "b")["outcome"], "replayed")
    c1 = l.commit(_K, "b")
    _eq(c1["status"] if c1["outcome"] == "refused" else c1["outcome"], "released")
    _eq([e["status"] for e in l.snapshot(_K)["events"]], ["committed", "released"])


def _bud_release_frees(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 100))
    l.reserve(_K, _req("b", 100))
    _eq(l.reserve(_K, _req("c", 1))["outcome"], "over_cap")
    l.release(_K, "a")
    l.commit(_K, "b")
    _eq(l.reserve(_K, _req("d", 100))["outcome"], "reserved")
    _eq(l.reserve(_K, _req("e", 1))["outcome"], "over_cap")


def _bud_release_unreserved(h: StoreHandle) -> None:
    l = h.store
    _eq(l.release(_K, "ghost")["outcome"], "unknown")
    _eq(l.reserve(_K, _req("a", 201))["outcome"], "over_cap")
    _eq(l.reserve(_K, _req("ghost", 200))["outcome"], "reserved")
    _eq(l.reserve(_K, _req("b", 1))["outcome"], "over_cap")


def _bud_late_commit(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 200))
    l.release(_K, "a")
    l.reserve(_K, _req("b", 200))
    _eq(l.commit(_K, "a")["outcome"], "refused")
    l.commit(_K, "b")
    _eq(len([e for e in l.snapshot(_K)["events"] if e["status"] == "committed"]), 1)


def _bud_expiry(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 40, expiresAt=500))
    l.reserve(_K, _req("b", 40, expiresAt=500))
    l.reserve(_K, _req("c", 40))
    l.reserve(_K, _req("d", 40, expiresAt=500))
    l.commit(_K, "b")
    l.start(_K, "d")
    _eq(l.expire(_K, 499)["released"], [])
    _eq(l.expire(_K, 500)["released"], ["a"])
    _eq(l.expire(_K, 10_000)["released"], [])
    _eq(_reserved_total(l), 120)
    _eq(l.commit(_K, "a")["outcome"], "refused")
    _eq(l.start(_K, "a")["outcome"], "refused")


def _bud_start(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 10, expiresAt=5))
    l.reserve(_K, _req("b", 10))
    l.reserve(_K, _req("c", 10))
    v = l.snapshot(_K)["version"]
    _eq(l.start(_K, "ghost")["outcome"], "unknown")
    _eq(l.snapshot(_K)["version"], v)
    _eq(l.start(_K, "a")["outcome"], "settled")
    _eq(l.start(_K, "a")["outcome"], "replayed")
    _eq(l.expire(_K, 100)["released"], [])
    _eq(l.commit(_K, "a")["outcome"], "settled")
    _eq(l.start(_K, "a")["outcome"], "replayed")
    l.start(_K, "b")
    _eq(l.release(_K, "b")["outcome"], "settled")
    s = l.start(_K, "b")
    _eq(s["status"] if s["outcome"] == "refused" else s["outcome"], "released")
    _eq(next(e for e in l.snapshot(_K)["events"] if e["id"] == "c").get("started"), None)


def _bud_keys(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 200))
    _eq(l.reserve(_K2, _req("a", 200))["outcome"], "reserved")
    _eq(l.reserve(_K, _req("b", 1))["outcome"], "over_cap")
    _eq([e["id"] for e in l.snapshot(_K2)["events"]], ["a"])
    _eq(l.snapshot(_K2)["version"], 1)


def _bud_windows(h: StoreHandle) -> None:
    l = h.store
    w = [_spend(win={"kind": "period", "ms": 1000, "t0": 0})]
    _eq(l.reserve(_K, {"event": _ev("a", 200, 100), "accumulators": w})["outcome"], "reserved")
    _eq(l.reserve(_K, {"event": _ev("b", 1, 900), "accumulators": w})["outcome"], "over_cap")
    _eq(l.reserve(_K, {"event": _ev("c", 200, 1100), "accumulators": w})["outcome"], "reserved")


def _bud_evidence(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 10))

    def mk(i: str) -> dict:
        return {"v": 1, "key": _K, "id": i, "reason": "effect_failed", "at": 5, "signer": "s", "sig": "x"}

    _rejects(lambda: l.release(_K, "a", mk("other")), ValueError)
    _eq(l.snapshot(_K)["events"][0]["status"], "reserved")
    _eq(l.release(_K, "a", mk("a"))["outcome"], "settled")
    _eq(l.snapshot(_K)["events"][0]["rel"], mk("a"))


def _bud_invalid(h: StoreHandle) -> None:
    l = h.store
    for bad in (_ev("", 1), {**_ev("x", 1), "t": 0.5}, {**_ev("x", 1), "verb": 7}):
        _rejects(lambda bad=bad: l.reserve(_K, {"event": bad, "accumulators": [_spend()]}), ValueError)
    _rejects(lambda: l.reserve(_K, _req("x", 1, expectedVersion=-1)), ValueError)
    no_max = _spend()
    del no_max["domain_max"]
    _rejects(lambda: l.reserve(_K, {"event": _ev("x", 1), "accumulators": [no_max]}), ValueError)
    _eq(l.snapshot(_K), {"version": 0, "events": []})


def _bud_copies(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 10))
    s = l.snapshot(_K)
    s["events"][0]["status"] = "released"
    _eq(l.snapshot(_K)["events"][0]["status"], "reserved")


def _bud_durable_claim(h: StoreHandle) -> None:
    want = h.adapter_durable is not False
    _eq(h.store.durable, want, "ledger.durable=%r but the adapter declares durable=%r" % (h.store.durable, want))


def _bud_reopen(h: StoreHandle) -> None:
    l = h.store
    l.reserve(_K, _req("a", 150))
    l.reserve(_K, _req("b", 50))
    l.commit(_K, "a")
    l.release(_K, "b")
    back = h.reopen()
    _eq([[e["id"], e["status"]] for e in back.snapshot(_K)["events"]], [["a", "committed"], ["b", "released"]])
    _eq(back.reserve(_K, _req("c", 51))["outcome"], "over_cap")
    _eq(back.reserve(_K, _req("c", 50))["outcome"], "reserved")


def _bud_crash(h: StoreHandle) -> None:
    h.store.reserve(_K, _req("a", 200))
    _background(lambda: h.store.reserve(_K, _req("b", 0)))
    back = h.crash()
    _eq(back.reserve(_K, _req("c", 1))["outcome"], "over_cap")
    _eq(back.snapshot(_K)["events"][0]["id"], "a")


BUDGET_CHECKS: List[Check] = [
    Check("empty-key-is-empty", "a key nobody reserved on has version 0 and no events", _bud_empty),
    Check("reservation-counts-at-once-and-cap-is-inclusive", "a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted", _bud_cap),
    Check("a-refusal-writes-nothing", "an over-cap reservation leaves no event and does not move the version", _bud_refusal),
    Check("reserve-retry-is-a-replay", "the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts", _bud_replay),
    Check("expected-version-is-compare-and-swap", "a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version", _bud_cas),
    Check("racing-reserves-never-pass-the-cap", "forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice", _bud_race_cap),
    Check("racing-reserves-at-one-version-have-one-winner", "clients reserving with the same expected version: exactly one lands, the others conflict", _bud_race_version),
    Check("racing-writers-with-retry-fill-the-cap-exactly", "twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused", _bud_race_retry),
    Check("settle-rules", "commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing", _bud_settle),
    Check("release-frees-budget-and-commit-keeps-it", "a released reservation no longer counts; a committed one still does; an open one keeps counting until settled", _bud_release_frees),
    Check("release-without-reserve-credits-nothing", "releasing an id that was never reserved does not create headroom, now or after the id is reserved later", _bud_release_unreserved),
    Check("a-late-commit-cannot-overspend", "after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap", _bud_late_commit),
    Check("expiry-releases-only-open-reservations-past-their-deadline", "expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused", _bud_expiry),
    Check("start-rules", "start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start", _bud_start),
    Check("keys-are-independent", "two keys have their own caps, versions and events", _bud_keys),
    Check("windows-reset-the-count", "a period window counts only the events of the period of the new event", _bud_windows),
    Check("release-evidence-is-stored-and-bound", "evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open", _bud_evidence),
    Check("invalid-input-is-refused", "a malformed event or request throws and writes nothing", _bud_invalid),
    Check("snapshots-are-copies", "mutating what a snapshot returned cannot change the ledger", _bud_copies),
    Check("durable-claim-matches-the-adapter", "a ledger says durable: true exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal", _bud_durable_claim),
    Check("state-survives-reopen", "every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds", _bud_reopen, "durable"),
    Check("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap", _bud_crash, "crash"),
]


# ---- bond-settlement stores ---------------------------------------------------------------------------------------------------------

def _rec(claim_id: str, action: str, amount: Any, frm: str, to: str, evidence_digest: str = "", split: Optional[dict] = None) -> dict:
    r = {"claimId": claim_id, "action": action, "amount": amount, "from": frm, "to": to, "at": 1, "evidenceDigest": evidence_digest}
    if split:
        r["split"] = split
    r["sig"] = "sig"
    return r


def _open_plan(i: str, dep: str, amount: Any, caps: Optional[dict] = None) -> dict:
    caps = caps or {"maxOpenClaims": 100, "maxOpenAmount": 1e9}
    return {"claimId": i, "expect": "none", "next": "open", "open": {"amount": amount, "depositor": dep, **caps},
            "moves": [{"account": dep, "op": "debit", "amount": amount}, {"account": "escrow", "op": "credit", "amount": amount}],
            "record": _rec(i, "open", amount, dep, "escrow")}


def _release_plan(i: str, dep: str, amount: Any) -> dict:
    return {"claimId": i, "expect": "open", "next": "released",
            "moves": [{"account": "escrow", "op": "debit", "amount": amount}, {"account": dep, "op": "credit", "amount": amount}],
            "record": _rec(i, "release", amount, "escrow", dep)}


def _slash_plan(i: str, amount: Any, evidence: str = "ev") -> dict:
    return {"claimId": i, "expect": "open", "next": "slashed",
            "moves": [{"account": "escrow", "op": "debit", "amount": amount}, {"account": "chal", "op": "credit", "amount": amount / 2},
                      {"account": "treasury", "op": "credit", "amount": amount / 2}],
            "record": _rec(i, "slash", amount, "escrow", "treasury", evidence,
                           {"amount": amount, "challengerReward": amount / 2, "victimCompensation": 0, "treasuryRemainder": amount / 2,
                            "challengerAccount": "chal", "victimAccount": "pool", "treasuryAccount": "treasury"})}


def _bal(s: Any, *accounts: str) -> List[Any]:
    out = []
    for a in accounts:
        b = s.read({"claimId": "", "depositor": a})["balances"]
        out.append(b[0][1] if len(b) > 0 and b[0][1] is not None else 0)
    return out


def _status(s: Any, i: str) -> str:
    b = s.read({"claimId": i}).get("bond")
    return b["status"] if b else "none"


_ACCOUNTS = ("alice", "bob", "escrow", "chal", "treasury")


def _total(s: Any) -> Any:
    return sum(_bal(s, *_ACCOUNTS))


def _outcomes(r: List[dict]) -> List[str]:
    return sorted(x["outcome"] for x in r)


def _bond_empty(h: StoreHandle) -> None:
    _eq(h.store.read({"claimId": "nope", "depositor": "alice"}), {"balances": [["alice", 0]], "openTotals": {"count": 0, "sum": 0}, "highWater": 0})


def _bond_deposit(h: StoreHandle) -> None:
    s = h.store
    _eq(s.deposit("alice", 2.5), 2.5)
    _eq(s.deposit("alice", 0.5), 3)
    for bad in (0, -1, math.nan, math.inf):
        _rejects(lambda bad=bad: s.deposit("alice", bad))
    _rejects(lambda: s.deposit("", 1))
    _eq(_bal(s, "alice"), [3])


def _bond_open(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    plan = _open_plan("b1", "alice", 60)
    _eq(s.commit(plan, 500), {"outcome": "committed", "record": plan["record"]})
    _eq(s.read({"claimId": "b1", "depositor": "alice"}),
        {"bond": {"claimId": "b1", "amount": 60, "depositor": "alice", "status": "open", "records": [plan["record"]]}, "balances": [["alice", 40]],
         "openTotals": {"count": 1, "sum": 60}, "highWater": 500})
    _eq(_bal(s, "escrow"), [60])


def _bond_overdraft(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 10)
    _eq(s.commit(_open_plan("b1", "alice", 60), 900)["outcome"], "conflict")
    _eq(s.read({"claimId": "b1", "depositor": "alice"}), {"balances": [["alice", 10]], "openTotals": {"count": 0, "sum": 0}, "highWater": 0})
    _eq(_bal(s, "escrow"), [0])


def _bond_open_retry(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    plan = _open_plan("b1", "alice", 60)
    s.commit(plan, 1)
    _eq(s.commit(plan, 2), {"outcome": "replayed", "record": plan["record"]})
    _eq(s.commit(_open_plan("b1", "alice", 61), 3)["outcome"], "conflict")
    _eq(s.commit(_open_plan("b1", "bob", 60), 3)["outcome"], "conflict")
    _eq(_bal(s, "alice", "escrow"), [40, 60])
    _eq(len(s.read({"claimId": "b1"})["bond"]["records"]), 1)


def _bond_caps(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    caps = {"maxOpenClaims": 2, "maxOpenAmount": 50}
    _eq(s.commit(_open_plan("c1", "alice", 30, caps), 1)["outcome"], "committed")
    _eq(s.commit(_open_plan("c2", "alice", 21, caps), 1)["outcome"], "conflict")  # 30 + 21 > 50
    _eq(s.commit(_open_plan("c3", "alice", 20, caps), 1)["outcome"], "committed")
    _eq(s.commit(_open_plan("c4", "alice", 1, caps), 1)["outcome"], "conflict")  # third open claim
    _eq(_bal(s, "alice", "escrow"), [50, 50])


def _bond_settle(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    s.commit(_open_plan("r", "alice", 20), 1)
    s.commit(_open_plan("s", "alice", 40), 1)
    rel = _release_plan("r", "alice", 20)
    sl = _slash_plan("s", 40)
    _eq(s.commit(rel, 2), {"outcome": "committed", "record": rel["record"]})
    _eq(s.commit(sl, 3), {"outcome": "committed", "record": sl["record"]})
    _eq(_bal(s, "alice", "escrow", "chal", "treasury"), [60, 0, 20, 20])
    _eq(_total(s), 100)
    _eq([_status(s, "r"), _status(s, "s")], ["released", "slashed"])
    _eq(s.read({"claimId": "s"})["bond"]["records"], [_open_plan("s", "alice", 40)["record"], sl["record"]])


def _bond_phase(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    _eq(s.commit(_release_plan("ghost", "alice", 5), 9)["outcome"], "conflict")
    s.commit(_open_plan("b", "alice", 20), 10)
    s.commit(_release_plan("b", "alice", 20), 11)
    before = [_bal(s, "alice", "escrow", "treasury", "chal"), s.read({"claimId": "b"})["highWater"]]
    late = s.commit(_slash_plan("b", 20), 99)
    _eq(late["outcome"], "conflict")
    _eq([_bal(s, "alice", "escrow", "treasury", "chal"), s.read({"claimId": "b"})["highWater"]], before)
    _eq(_status(s, "b"), "released")


def _bond_overdraw(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    s.commit(_open_plan("b", "alice", 20), 1)
    greedy = _slash_plan("b", 20)
    greedy["moves"] = [{"account": "escrow", "op": "debit", "amount": 21}, {"account": "treasury", "op": "credit", "amount": 21}]
    _eq(s.commit(greedy, 5)["outcome"], "conflict")
    _eq(_bal(s, "escrow", "treasury"), [20, 0])
    _eq(_status(s, "b"), "open")


def _bond_settle_retry(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    s.commit(_open_plan("b", "alice", 40), 1)
    sl = _slash_plan("b", 40, "ev-1")
    s.commit(sl, 2)
    _eq(s.commit({**_slash_plan("b", 40, "ev-1"), "record": {**sl["record"], "at": 77, "sig": "other"}}, 3), {"outcome": "replayed", "record": sl["record"]})
    _eq(s.commit(_slash_plan("b", 40, "ev-2"), 3)["outcome"], "conflict")
    _eq(s.commit(_release_plan("b", "alice", 40), 3)["outcome"], "conflict")
    _eq(_bal(s, "alice", "escrow", "chal", "treasury"), [60, 0, 20, 20])
    _eq(len(s.read({"claimId": "b"})["bond"]["records"]), 2)


def _bond_race_same(h: StoreHandle) -> None:
    h.store.deposit("alice", 100)
    h.store.commit(_open_plan("b", "alice", 40), 1)
    clients = [h.store] + [h.reopen() for _ in range(3)]
    r = _race([(lambda i=i: clients[i % len(clients)].commit(_release_plan("b", "alice", 40), 10 + i)) for i in range(8)])
    _eq(_outcomes(r), ["committed"] + ["replayed"] * 7)
    _eq(_bal(h.store, "alice", "escrow"), [100, 0])
    _eq(len(h.store.read({"claimId": "b"})["bond"]["records"]), 2)


def _bond_race_conflict(h: StoreHandle) -> None:
    h.store.deposit("alice", 100)
    h.store.commit(_open_plan("b", "alice", 40), 1)
    other = h.reopen()
    r = _race([lambda: h.store.commit(_release_plan("b", "alice", 40), 5), lambda: other.commit(_slash_plan("b", 40), 5),
               lambda: h.store.commit(_slash_plan("b", 40), 5), lambda: other.commit(_release_plan("b", "alice", 40), 5)])
    _eq(len([x for x in r if x["outcome"] == "committed"]), 1)
    _eq(len([x for x in r if x["outcome"] == "conflict"]) + len([x for x in r if x["outcome"] == "replayed"]), 3)
    st = _status(h.store, "b")
    _eq(_bal(h.store, "alice", "escrow", "chal", "treasury"), [100, 0, 0, 0] if st == "released" else [60, 0, 20, 20])
    _eq(_total(h.store), 100)


def _bond_race_opens(h: StoreHandle) -> None:
    h.store.deposit("alice", 100)
    other = h.reopen()
    r = _race([lambda: h.store.commit(_open_plan("b", "alice", 60), 1), lambda: other.commit(_open_plan("b", "alice", 60), 1),
               lambda: h.store.commit(_open_plan("b", "alice", 60), 1), lambda: other.commit(_open_plan("b", "alice", 50), 1)])
    _eq(len([x for x in r if x["outcome"] == "committed"]), 1)
    _eq(_bal(h.store, "alice", "escrow"), [50, 50] if r[3]["outcome"] == "committed" else [40, 60])
    _eq(_total(h.store), 100)


def _bond_race_overdraw(h: StoreHandle) -> None:
    h.store.deposit("alice", 100)
    other = h.reopen()
    r = _race([(lambda i=i: (h.store if i % 2 else other).commit(_open_plan("b%d" % i, "alice", 40), 1)) for i in range(6)])
    _eq(len([x for x in r if x["outcome"] == "committed"]), 2)
    _eq(_bal(h.store, "alice", "escrow"), [20, 80])


def _bond_race_deposits(h: StoreHandle) -> None:
    other = h.reopen()
    _race([(lambda i=i: (h.store if i % 2 else other).deposit("alice", 1)) for i in range(16)])
    _eq(_bal(h.store, "alice"), [16])


def _bond_highwater(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    s.commit(_open_plan("a", "alice", 10), 100)
    s.commit(_open_plan("b", "alice", 10), 40)
    _eq(s.read({"claimId": ""})["highWater"], 100)
    s.commit(_open_plan("c", "alice", 10), math.nan)
    _eq(s.read({"claimId": ""})["highWater"], 100)
    s.commit(_open_plan("d", "alice", 10), 101)
    _eq(s.read({"claimId": ""})["highWater"], 101)


def _bond_snapshots(h: StoreHandle) -> None:
    s = h.store
    s.deposit("alice", 100)
    s.commit(_open_plan("b", "alice", 10), 1)
    snap = s.read({"claimId": "b", "depositor": "alice"})
    snap["bond"]["amount"] = 999
    del snap["bond"]["records"][:]
    try:
        snap["balances"][0][1] = 12345
    except TypeError:  # an immutable pair cannot be changed through a snapshot, which is the point
        pass
    again = s.read({"claimId": "b", "depositor": "alice"})
    _eq(again["bond"]["amount"], 10)
    _eq(len(again["bond"]["records"]), 1)
    _eq(again["balances"], [["alice", 90]])


def _bond_hostile(h: StoreHandle) -> None:
    s = h.store
    for n in ("__proto__", "constructor", "toString", "hasOwnProperty"):
        s.deposit(n, 50)
        _eq(s.commit(_open_plan(n, n, 20), 1)["outcome"], "committed", n)
        _eq(_bal(s, n), [30], n)
        _eq(_status(s, n), "open", n)
    _eq(_status(s, "valueOf"), "none")
    _eq(_bal(s, "valueOf"), [0])


def _bond_reopen(h: StoreHandle) -> None:
    h.store.deposit("alice", 100)
    h.store.commit(_open_plan("a", "alice", 40), 7)
    h.store.commit(_open_plan("b", "alice", 20), 8)
    sl = _slash_plan("b", 20)
    h.store.commit(sl, 9)
    back = h.reopen()
    _eq(back.read({"claimId": "b", "depositor": "alice"}),
        {"bond": {"claimId": "b", "amount": 20, "depositor": "alice", "status": "slashed", "records": [_open_plan("b", "alice", 20)["record"], sl["record"]]},
         "balances": [["alice", 40]], "openTotals": {"count": 1, "sum": 40}, "highWater": 9})
    _eq(_bal(back, "escrow", "chal", "treasury"), [40, 10, 10])
    _eq(back.commit(sl, 10)["outcome"], "replayed")


def _bond_crash(h: StoreHandle) -> None:
    h.store.deposit("alice", 100)
    h.store.commit(_open_plan("a", "alice", 40), 1)
    h.store.commit(_open_plan("b", "alice", 30), 2)
    _background(lambda: h.store.commit(_slash_plan("b", 30), 3))
    back = h.crash()
    _eq(_status(back, "a"), "open")
    st = _status(back, "b")
    _ok(st in ("open", "slashed"), "bond b is %s" % st)
    _eq(_bal(back, "alice", "escrow", "chal", "treasury"), [30, 40, 15, 15] if st == "slashed" else [30, 70, 0, 0])
    _eq(_total(back), 100)
    _eq(back.commit(_slash_plan("b", 30), 4)["outcome"], "replayed" if st == "slashed" else "committed")
    _eq(_bal(back, "alice", "escrow", "chal", "treasury"), [30, 40, 15, 15])


BOND_CHECKS: List[Check] = [
    Check("empty-store-reads-empty", "an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0", _bond_empty),
    Check("deposit-validates-and-accumulates", "deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit", _bond_deposit),
    Check("open-is-atomic-and-recorded", "an open moves the collateral, stores the row with its record, and raises the high-water mark, all together", _bond_open),
    Check("open-overdraft-refused-without-trace", "an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched", _bond_overdraft),
    Check("open-retry-is-replayed-and-different-terms-conflict", "committing the same open again returns the stored record and moves nothing; other terms for that bond conflict", _bond_open_retry),
    Check("open-caps-are-rechecked-at-commit", "the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw", _bond_caps),
    Check("settle-applies-every-move-once", "a release and a slash apply all their balance moves, store the record, and conserve the total", _bond_settle),
    Check("settle-needs-the-expected-phase", "settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included", _bond_phase),
    Check("settle-overdraw-refused-without-trace", "a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change", _bond_overdraw),
    Check("settle-retry-returns-the-stored-record", "the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts", _bond_settle_retry),
    Check("racing-identical-settles-commit-once", "eight clients racing the same release: one commits, seven are replays, funds move once", _bond_race_same),
    Check("racing-conflicting-settles-have-one-winner", "a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved", _bond_race_conflict),
    Check("racing-opens-for-the-same-bond-commit-once", "concurrent identical opens collect the collateral once; a differing open loses", _bond_race_opens),
    Check("racing-opens-cannot-overdraw", "concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited", _bond_race_overdraw),
    Check("concurrent-deposits-lose-nothing", "sixteen racing deposits add up exactly", _bond_race_deposits),
    Check("time-high-water-only-moves-forward", "the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it", _bond_highwater),
    Check("reads-are-snapshots", "mutating a returned snapshot cannot change the store", _bond_snapshots),
    Check("hostile-names-are-plain-keys", "claim and account names such as __proto__, constructor and toString behave like any other name", _bond_hostile),
    Check("state-survives-reopen", "every acknowledged commit and deposit is visible to a new client after the backend restarts", _bond_reopen, "durable"),
    Check("acknowledged-commits-survive-a-crash", "after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all", _bond_crash, "crash"),
]


# ---- running a profile -----------------------------------------------------------------------------------------------------------------

def _run_profile(kind: str, checks: List[Check], adapter: ProfileAdapter, only: Optional[List[str]]) -> dict:
    results: List[dict] = []
    for c in checks:
        if only is not None and c.name not in only:
            continue
        if c.needs == "durable" and adapter.durable is False:
            results.append({"name": c.name, "status": "skip", "detail": "the adapter declares durable: false"})
            continue
        h = adapter.create()
        h.adapter_durable = adapter.durable
        try:
            if c.needs == "crash" and not h.crash:
                results.append({"name": c.name, "status": "skip", "detail": "the adapter has no crash()"})
                continue
            c.run(h)
            results.append({"name": c.name, "status": "pass"})
        except Exception as e:  # noqa: BLE001 - a failing check is a result, not a crash of the run
            results.append({"name": c.name, "status": "fail", "detail": str(e) or type(e).__name__})
        finally:
            if h.close:
                h.close()
    return {"adapter": adapter.name, "status": "fail" if any(x["status"] == "fail" for x in results) else "pass", "checks": results}


def _format_profile(label: str, r: dict) -> str:
    return "\n".join(["pca-store-conformance (%s): %s -> %s" % (label, r["adapter"], r["status"].upper())] +
                     ["  [%s] %s%s" % (c["status"].upper(), c["name"], (": " + c["detail"].split("\n")[0]) if c.get("detail") else "") for c in r["checks"]])


def run_guardian_lease_store_conformance(adapter: ProfileAdapter, only: Optional[List[str]] = None) -> dict:
    """Run :data:`GUARDIAN_LEASE_CHECKS` against a guardian lease store: ``{adapter, status, checks: [{name, status, detail?}]}``."""
    return _run_profile("lease store", GUARDIAN_LEASE_CHECKS, adapter, only)


def run_ledger_store_conformance(adapter: ProfileAdapter, only: Optional[List[str]] = None) -> dict:
    """Run :data:`LEDGER_CHECKS` against a transparency-log ledger store."""
    return _run_profile("ledger store", LEDGER_CHECKS, adapter, only)


def run_budget_ledger_conformance(adapter: ProfileAdapter, only: Optional[List[str]] = None) -> dict:
    """Run :data:`BUDGET_CHECKS` against an aggregate budget ledger."""
    return _run_profile("budget ledger", BUDGET_CHECKS, adapter, only)


def run_bond_store_conformance(adapter: ProfileAdapter, only: Optional[List[str]] = None) -> dict:
    """Run :data:`BOND_CHECKS` against a bond-settlement store."""
    return _run_profile("bond store", BOND_CHECKS, adapter, only)


def format_lease_report(r: dict) -> str:
    return _format_profile("lease store", r)


def format_ledger_report(r: dict) -> str:
    return _format_profile("ledger store", r)


def format_budget_report(r: dict) -> str:
    return _format_profile("budget ledger", r)


def format_bond_report(r: dict) -> str:
    return _format_profile("bond store", r)


# ---- mesh-witness state stores -------------------------------------------------------------------------------------------------------------

class MeshWitnessStoreAdapter:
    """``name``, ``make()`` (a fresh, empty store with ``load() -> state | None`` and ``save(state)``), optionally ``reopen(previous)`` (a new
    store object over the same backing storage: a restart) and ``damage(store)`` (damage the backing storage so that ``load`` must fail)."""

    def __init__(self, name: str, make: Callable[[], Any], reopen: Optional[Callable[[Any], Any]] = None, damage: Optional[Callable[[Any], None]] = None) -> None:
        self.name, self.make, self.reopen, self.damage = name, make, reopen, damage


def _mesh_seed(label: str) -> Any:
    from .agent import KeyPair
    lb = label.encode("utf-8")
    return KeyPair(bytes((lb[i % len(lb)] + i) & 0xFF for i in range(32)))


def _mesh_cap(label: str) -> dict:
    return {"id": label, "caveats": [{"type": "scope", "actions": [label]}]}


def _mesh_two_logs() -> Any:
    """Two logs of one domain key with different histories."""
    from .mesh_witness import MeshDomain
    honest, fork = MeshDomain("d", _mesh_seed("domain")), MeshDomain("d", _mesh_seed("domain"))
    honest.record(_mesh_cap("a"))
    fork.record(_mesh_cap("x"))
    return honest, fork


def _mesh_state(n: int) -> dict:
    return {"seen": [{"head": {"domain": "d%d" % n, "size": 0, "root": "", "rev_root": "r", "rev_size": 0, "timestamp": n}, "rev_ids": []}]}


def mesh_witness_store_cases(a: MeshWitnessStoreAdapter) -> List[Check]:
    """The mesh-witness profile: the store cases (round trip, replace, copy semantics, reopen, damage) and the cases that drive a real
    :class:`MeshWitness` over the store (every cosignature persisted, a failed save refuses, a restarted witness refuses a fork and a rollback)."""
    from .mesh_witness import MeshDomain, MeshWitness

    def fresh(_h: Any = None) -> None:
        _eq(a.make().load(), None)

    def round_trip(_h: Any = None) -> None:
        s = a.make()
        s.save(_mesh_state(1))
        _eq(s.load(), _mesh_state(1))

    def replaces(_h: Any = None) -> None:
        s = a.make()
        s.save(_mesh_state(1))
        s.save(_mesh_state(2))
        _eq(s.load(), _mesh_state(2))

    def load_copy(_h: Any = None) -> None:
        s = a.make()
        s.save(_mesh_state(1))
        got = s.load()
        got["seen"].pop()
        _eq(s.load(), _mesh_state(1))

    def save_copy(_h: Any = None) -> None:
        s = a.make()
        st = _mesh_state(1)
        s.save(st)
        del st["seen"][:]
        _eq(s.load(), _mesh_state(1))

    def persists(_h: Any = None) -> None:
        st = a.make()
        w = MeshWitness(_mesh_seed("w"), store=st)
        honest, _ = _mesh_two_logs()
        ch = honest.publish_head([w], 1_000)
        _eq(st.load(), w.export_state())
        _eq([x["head"] for x in st.load()["seen"]], [ch["head"]])

    def failed_save(_h: Any = None) -> None:
        inner = a.make()
        failing = [False]

        class Flaky:
            def load(self) -> Any:
                return inner.load()

            def save(self, state: Any) -> None:
                if failing[0]:
                    raise RuntimeError("disk full")
                inner.save(state)

        w = MeshWitness(_mesh_seed("w"), store=Flaky())
        honest, _ = _mesh_two_logs()
        honest.publish_head([w], 1_000)
        before = copy.deepcopy(w.export_state())
        honest.record(_mesh_cap("b"))
        failing[0] = True
        threw = ""
        try:
            honest.publish_head([w], 2_000)
        except Exception as e:  # noqa: BLE001
            threw = str(e)
        _eq(threw, "witness: could not persist state; refusing to cosign")
        _eq(w.export_state(), before)
        _eq(inner.load(), before)
        failing[0] = False
        _ok(len(honest.publish_head([w], 2_000)["cosigs"]) == 1, "the same head is cosigned once the disk recovers")

    cases = [
        Check("a fresh store loads nothing", "", fresh),
        Check("save then load returns the same state", "", round_trip),
        Check("a later save replaces the earlier one", "", replaces),
        Check("load returns a copy: changing it does not change the store", "", load_copy),
        Check("save keeps its own copy: changing the argument afterwards does not change the store", "", save_copy),
        Check("a witness persists every cosignature before returning it", "", persists),
        Check("a failed save refuses the cosignature and leaves the witness unchanged", "", failed_save),
    ]
    if a.reopen:
        reopen = a.reopen

        def survives(_h: Any = None) -> None:
            s = a.make()
            s.save(_mesh_state(3))
            _eq(reopen(s).load(), _mesh_state(3))

        def remembers(_h: Any = None) -> None:
            st = a.make()
            w1 = MeshWitness(_mesh_seed("w"), store=st)
            honest, fork = _mesh_two_logs()
            honest.publish_head([w1], 1_000)
            honest.record(_mesh_cap("b"))
            honest.publish_head([w1], 2_000)
            w2 = MeshWitness(_mesh_seed("w"), store=reopen(st))
            _eq(w2.last_seen(honest.id)["size"], 2)
            fork.record(_mesh_cap("y"))
            fork.record(_mesh_cap("z"))
            _rejects(lambda: fork.publish_head([w2], 3_000))  # a fork that grew past the remembered size
            rollback = MeshDomain("d", _mesh_seed("domain"))
            rollback.record(_mesh_cap("a"))
            _rejects(lambda: rollback.publish_head([w2], 3_000))  # a rollback to the first head
            _ok(len(honest.publish_head([w2], 3_000)["cosigs"]) == 1, "the honest log is still cosigned")

        cases.append(Check("state survives reopening the store", "", survives))
        cases.append(Check("a restarted witness remembers what it cosigned: it refuses a fork and a rollback", "", remembers))
    if a.damage:
        damage = a.damage

        def damaged(_h: Any = None) -> None:
            s = a.make()
            # a state a witness accepts, so that only the damage can make construction fail
            w0 = MeshWitness(_mesh_seed("w"))
            d0 = MeshDomain("d", _mesh_seed("domain"))
            d0.record(_mesh_cap("a"))
            d0.publish_head([w0], 1_000)
            s.save(w0.export_state())
            damage(s)
            _rejects(s.load)  # load must throw on damaged storage
            _rejects(lambda: MeshWitness(_mesh_seed("w"), store=s))  # a witness constructed over damaged storage must throw

        cases.append(Check("damaged storage makes load throw, so a witness never starts empty over it", "", damaged))
    return cases


def run_mesh_witness_store_conformance(a: MeshWitnessStoreAdapter) -> dict:
    """Run the store-only mesh-witness cases: ``{adapter, status, checks: [{name, status, detail?}]}``."""
    results = []
    for c in mesh_witness_store_cases(a):
        try:
            c.run(None)  # type: ignore[arg-type]
            results.append({"name": c.name, "status": "pass"})
        except Exception as e:  # noqa: BLE001
            results.append({"name": c.name, "status": "fail", "detail": str(e) or type(e).__name__})
    return {"adapter": a.name, "status": "fail" if any(x["status"] == "fail" for x in results) else "pass", "checks": results}
