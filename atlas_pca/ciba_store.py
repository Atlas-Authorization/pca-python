"""Durable approval broker over a compare-and-set store, plus the reference stores (one JSON file, a directory key-value store).
Mirrors the TypeScript reference (@atlasauth/pca-ciba): a restart or a second process cannot lose, double-apply or replay a human
decision.

An approval store is any object with ``get(key) -> Optional[{"version": int, "value": Any}]`` and
``cas(key, expected_version, value) -> bool`` (version 0 = the key must be absent; every write bumps the version). A durable
key-value store is any object with ``get(key) -> Optional[str]`` and ``put_if_equals(key, expected, next) -> bool`` (atomic across
every process sharing it; a write is durable before it returns; any failure raises). Stored records keep the reference's field
names (``createdAt``, ``expiresAt``, ``lastPollAt``, ``decidedBy``...), so Python and TypeScript processes can share a store."""
from __future__ import annotations

import copy
import hashlib
import json
import math
from ._fin import fin
import os
import secrets
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

from .ciba import to_ciba_auth_request
from .pca import utf8
from .private_fs import makedirs_private, open_private

MAX_CAS_TRIES = 8


def _now_ms() -> int:
    return int(time.time() * 1000)


def _dumps(v: Any) -> str:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def _no_const(c: str) -> Any:
    raise ValueError("ciba: " + c + " is not JSON")


# ---- reference stores -------------------------------------------------------------------------------------------------------

def create_file_approval_store(path: str) -> Any:
    """One JSON file, rewritten atomically (temp file + rename) on each write. Correct for ONE process at a time (a lock serialises
    threads); use a database store when several processes share the approvals. A corrupt file raises: fail closed."""
    lock = threading.RLock()

    def load() -> Dict[str, Any]:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8", newline="") as fh:
            parsed = json.loads(fh.read(), parse_constant=_no_const)
        if not isinstance(parsed, dict):
            raise ValueError("ciba: approval store file is corrupt")
        return parsed

    class _FileStore:
        def get(self, key: str) -> Optional[Dict[str, Any]]:
            with lock:
                return load().get(key)

        def cas(self, key: str, expected_version: int, value: Any) -> bool:
            with lock:
                allv = load()
                cur = allv.get(key)
                if ((cur or {}).get("version") or 0) != expected_version:
                    return False
                allv[key] = {"version": expected_version + 1, "value": value}
                tmp = "%s.%d.tmp" % (path, os.getpid())
                fd = open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
                try:
                    os.write(fd, _dumps(allv).encode("utf-8"))
                finally:
                    os.close(fd)
                os.replace(tmp, path)
                return True

    return _FileStore()


class ApprovalStoreError(Exception):
    """Raised by the key-value reference implementations; the broker treats any store failure as "no approval"."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code  # corrupt_record | lock_timeout | bad_key


def _decode(raw: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw, parse_constant=_no_const)
    except ValueError:
        raise ApprovalStoreError("corrupt_record", "ciba: stored approval record is not valid JSON")
    v = parsed.get("version") if isinstance(parsed, dict) else None
    is_int = (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, float) and v.is_integer())
    if not isinstance(parsed, dict) or not is_int or v < 1 or "value" not in parsed:
        raise ApprovalStoreError("corrupt_record", "ciba: stored approval record has no valid version")
    return {"version": int(v), "value": parsed["value"]}


def create_kv_approval_store(kv: Any) -> Any:
    """An approval store over a durable key-value store with compare-and-swap: each key holds ``{version, value}`` as JSON and a swap
    goes through only if the raw string is still the one that was read, so two racers on one version cannot both win."""
    if kv is None or not callable(getattr(kv, "get", None)) or not callable(getattr(kv, "put_if_equals", None)):
        raise TypeError("create_kv_approval_store: `kv` with get and put_if_equals is required")

    class _KvStore:
        def get(self, key: str) -> Optional[Dict[str, Any]]:
            raw = kv.get(key)
            return None if raw is None else _decode(raw)

        def cas(self, key: str, expected_version: int, value: Any) -> bool:
            raw = kv.get(key)
            current = 0 if raw is None else _decode(raw)["version"]
            if current != expected_version:
                return False
            return kv.put_if_equals(key, raw, _dumps({"version": expected_version + 1, "value": value})) is True

    return _KvStore()


def create_directory_kv(directory: str, lock_timeout_ms: float = 5000) -> Any:
    """A durable key-value store on a directory, safe for several processes on ONE host: one file per key (name = SHA-256 of the key),
    each swap takes a per-key lock file (exclusive create), compares, writes a fsynced temp file and renames it over the key. A lock
    left behind by a dead process makes every later swap on that key raise ``lock_timeout`` (fail closed) until it is removed."""
    if isinstance(lock_timeout_ms, bool) or not isinstance(lock_timeout_ms, (int, float)) or not fin(lock_timeout_ms) or lock_timeout_ms <= 0:
        raise TypeError("create_directory_kv: lock_timeout_ms must be a positive number")
    makedirs_private(directory)

    def file_of(key: Any) -> str:
        if not isinstance(key, str) or key == "":
            raise ApprovalStoreError("bad_key", "ciba: store key must be a non-empty string")
        return os.path.join(directory, hashlib.sha256(utf8(key)).hexdigest())

    def read(f: str) -> Optional[str]:
        for attempt in range(200):
            try:
                with open(f, "r", encoding="utf-8", newline="") as fh:
                    return fh.read()
            except FileNotFoundError:
                return None
            except PermissionError:
                # Windows refuses to open a file for the instant another handle is renaming over it: retry, never read a half state
                if os.name != "nt" or attempt == 199:
                    raise
                time.sleep(0.002)
        return None

    class _DirKv:
        def get(self, key: str) -> Optional[str]:
            return read(file_of(key))

        def put_if_equals(self, key: str, expected: Optional[str], nxt: str) -> bool:
            f = file_of(key)
            lock = f + ".lock"
            deadline = time.time() + lock_timeout_ms / 1000
            fd = None
            while fd is None:
                try:
                    fd = open_private(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                except (FileExistsError, PermissionError) as e:  # Windows reports a lock file pending deletion as PermissionError
                    if isinstance(e, PermissionError) and os.name != "nt":
                        raise
                    if time.time() >= deadline:
                        raise ApprovalStoreError("lock_timeout", "ciba: could not take the store lock in time")
                    time.sleep(0.002)
            try:
                if read(f) != expected:
                    return False
                tmp = "%s.%d.tmp" % (f, os.getpid())
                t = open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
                try:
                    os.write(t, nxt.encode("utf-8"))
                    os.fsync(t)  # durable before the rename publishes it
                finally:
                    os.close(t)
                for attempt in range(200):
                    try:
                        os.replace(tmp, f)
                        break
                    except PermissionError:  # Windows: a concurrent reader still has the target open
                        if os.name != "nt" or attempt == 199:
                            raise
                        time.sleep(0.002)
                return True
            finally:
                os.close(fd)
                os.unlink(lock)

    return _DirKv()


# ---- the durable broker -----------------------------------------------------------------------------------------------------

def _finite(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


def _as_rec(v: Any) -> Dict[str, Any]:
    req = v.get("request") if isinstance(v, dict) else None
    if not isinstance(req, dict) or not isinstance(req.get("auth_req_id"), str) or not _finite(v.get("createdAt")) or not _finite(v.get("expiresAt")) or not _finite(v.get("interval")):
        raise ValueError("ciba: stored approval record is malformed")
    return v


class DurableCibaBroker:
    """Asynchronous-contract broker of the reference, as a blocking one: ``start`` / ``poll`` / ``token`` / ``resolve`` / ``get``.
    Sessions and token outcomes are dicts with the reference's field names."""

    def __init__(self, store: Any, now: Optional[Callable[[], float]] = None, decision_ttl_sec: float = 300,
                 on_complete: Optional[Callable[[Dict[str, Any]], Any]] = None) -> None:
        if store is None or not callable(getattr(store, "get", None)) or not callable(getattr(store, "cas", None)):
            raise TypeError("create_durable_ciba_broker: `store` is required")
        self._store = store
        self._clock = now or _now_ms
        self._ttl_ms = decision_ttl_sec * 1000
        if isinstance(decision_ttl_sec, bool) or not _finite(self._ttl_ms) or self._ttl_ms <= 0:
            raise TypeError("create_durable_ciba_broker: decisionTtlSec must be a positive number")
        self._on_complete = on_complete

    def _status(self, r: Dict[str, Any], now: float) -> str:
        if r.get("decision") == "deny":
            return "denied"
        if r.get("decision") == "approve":
            return "approved" if _finite(now) and now < r["decidedAt"] + self._ttl_ms else "expired"
        return "pending" if _finite(now) and now < r["expiresAt"] else "expired"

    def _snap(self, r: Dict[str, Any], now: float) -> Dict[str, Any]:
        s = {"auth_req_id": r["request"]["auth_req_id"], "request": r["request"], "status": self._status(r, now), "createdAt": r["createdAt"], "expiresAt": r["expiresAt"]}
        if r.get("decidedBy") is not None:
            s["decidedBy"] = r["decidedBy"]
        if r.get("decidedAt") is not None:
            s["decidedAt"] = r["decidedAt"]
        return s

    def _load(self, id_: str) -> Optional[Tuple[Dict[str, Any], int]]:
        v = self._store.get("a:" + id_)
        return None if v is None else (_as_rec(v["value"]), v["version"])

    def _mutate(self, id_: str, fn: Callable[[Optional[Dict[str, Any]], float], Tuple[Optional[Dict[str, Any]], Any]]) -> Any:
        """Read-modify-write with CAS retry; ``fn`` returns (new record or None for "no write", result)."""
        for _ in range(MAX_CAS_TRIES):
            cur = self._load(id_)
            nxt, out = fn(copy.deepcopy(cur[0]) if cur else None, self._clock())
            if nxt is None:
                return out
            if self._store.cas("a:" + id_, cur[1] if cur else 0, nxt):
                return out
        raise RuntimeError("ciba: approval store contention, gave up")

    def start(self, step_up: Dict[str, Any], req_opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        live_key = "s:" + str(step_up.get("id"))
        for _ in range(MAX_CAS_TRIES):
            now = self._clock()
            idx = self._store.get(live_key)
            if idx is not None:
                ex = self._load(str(idx["value"]))
                # Never reset a flow that is still waiting or already approved: that would discard a decision.
                if ex and self._status(ex[0], now) in ("pending", "approved") and not ex[0].get("consumed"):
                    return ex[0]["request"]
            request = to_ciba_auth_request(step_up, dict(req_opts or {}, auth_req_id=secrets.token_urlsafe(20)))
            rec = {"request": request, "createdAt": now, "expiresAt": now + request["requested_expiry"] * 1000, "interval": request["interval"]}
            if not self._store.cas("a:" + request["auth_req_id"], 0, rec):
                continue
            if self._store.cas(live_key, idx["version"] if idx else 0, request["auth_req_id"]):
                return request
        raise RuntimeError("ciba: approval store contention, gave up")

    def poll(self, id_: str) -> Dict[str, str]:
        c = self._load(id_)
        if not c:
            raise KeyError("ciba: unknown auth_req_id %s" % id_)
        return {"status": self._status(c[0], self._clock())}

    def token(self, id_: str) -> Dict[str, Any]:
        def fn(r: Optional[Dict[str, Any]], now: float) -> Tuple[Optional[Dict[str, Any]], Any]:
            if not r:
                return None, {"ok": False, "error": "invalid_grant", "interval": 5}
            if r.get("consumed"):
                return None, {"ok": False, "error": "invalid_grant", "interval": r["interval"]}
            too_soon = r.get("lastPollAt") is not None and now - r["lastPollAt"] < r["interval"] * 1000
            r["lastPollAt"] = now
            if too_soon:
                r["interval"] += 5
                return r, {"ok": False, "error": "slow_down", "interval": r["interval"]}
            st = self._status(r, now)
            for state, err in (("pending", "authorization_pending"), ("denied", "access_denied"), ("expired", "expired_token")):
                if st == state:
                    return r, {"ok": False, "error": err, "interval": r["interval"]}
            r["consumed"] = True  # single use: a replayed approval gets invalid_grant
            return r, {"ok": True, "session": self._snap(r, now)}

        return self._mutate(id_, fn)

    def resolve(self, id_: str, decision: str, by: str) -> Dict[str, Any]:
        if decision not in ("approve", "deny"):
            raise ValueError('ciba: decision must be "approve" or "deny"')
        if not isinstance(by, str) or by == "":
            raise ValueError("ciba: `by` (the authenticated decider) is required")

        def fn(r: Optional[Dict[str, Any]], now: float) -> Tuple[Optional[Dict[str, Any]], Any]:
            if not r:
                raise KeyError("ciba: unknown auth_req_id %s" % id_)
            cur = self._status(r, now)
            if cur != "pending":
                raise RuntimeError("ciba: cannot resolve %s — already %s" % (id_, cur))
            r["decision"], r["decidedBy"], r["decidedAt"] = decision, by, now
            return r, self._snap(r, now)

        session = self._mutate(id_, fn)
        if self._on_complete is not None:
            try:
                self._on_complete(session)
            except Exception:
                pass  # the decision is already recorded; a failing notifier must not undo or hide it
        return session

    def get(self, id_: str) -> Optional[Dict[str, Any]]:
        c = self._load(id_)
        return self._snap(c[0], self._clock()) if c else None


def create_durable_ciba_broker(store: Any, now: Optional[Callable[[], float]] = None, decision_ttl_sec: float = 300,
                               on_complete: Optional[Callable[[Dict[str, Any]], Any]] = None) -> DurableCibaBroker:
    return DurableCibaBroker(store, now, decision_ttl_sec, on_complete)
