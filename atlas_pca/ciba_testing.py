"""Test doubles for the CIBA bridge: single-process, in-memory, everything is lost on restart. Use them in tests of code that
takes a broker, a store or a key-value store, never to guard a real approval; production code uses the durable broker over a
durable store. Mirrors the TypeScript reference (@atlasauth/pca-ciba)."""
from __future__ import annotations

import copy
import secrets
import threading
import time
from typing import Any, Callable, Dict, Optional

from ._fin import fin
from .ciba import DEFAULT_INTERVAL_SEC, to_ciba_auth_request


class MemoryCibaBroker:
    """An in-memory CIBA broker: ``start`` opens a session, ``poll`` reports pending / approved / denied / expired, ``token`` has the
    token-endpoint semantics (poll spacing with ``slow_down``, single-use approval) and ``resolve`` records the human's decision and
    fires ``on_complete`` (PING / PUSH). Sessions are dicts with the reference's field names; status is computed at read time."""

    def __init__(self, now: Optional[Callable[[], float]] = None, on_complete: Optional[Callable[[Dict[str, Any]], Any]] = None) -> None:
        self._clock = now or (lambda: int(time.time() * 1000))
        self._on_complete = on_complete
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._live: Dict[str, str] = {}  # step-up id -> auth_req_id of its live (pending or approved) flow
        self._lock = threading.RLock()

    @staticmethod
    def _status(s: Dict[str, Any], now: float) -> str:
        if s.get("decision") == "approve":
            return "approved"
        if s.get("decision") == "deny":
            return "denied"
        return "pending" if fin(now) and now < s["expiresAt"] else "expired"

    def _snapshot(self, s: Dict[str, Any], now: float) -> Dict[str, Any]:
        out = {"auth_req_id": s["request"]["auth_req_id"], "request": s["request"], "status": self._status(s, now), "createdAt": s["createdAt"], "expiresAt": s["expiresAt"]}
        if s.get("decidedBy") is not None:
            out["decidedBy"] = s["decidedBy"]
        if s.get("decidedAt") is not None:
            out["decidedAt"] = s["decidedAt"]
        return out

    def start(self, step_up: Dict[str, Any], req_opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            now = self._clock()
            existing_id = self._live.get(step_up.get("id"))
            existing = self._sessions.get(existing_id) if existing_id is not None else None
            if existing is not None and self._status(existing, now) in ("pending", "approved"):
                return existing["request"]  # never reset a flow that is waiting or approved
            request = to_ciba_auth_request(step_up, dict(req_opts or {}, auth_req_id=secrets.token_urlsafe(20)))
            self._sessions[request["auth_req_id"]] = {"request": request, "createdAt": now, "expiresAt": now + request["requested_expiry"] * 1000, "interval": request["interval"]}
            self._live[step_up.get("id")] = request["auth_req_id"]
            return request

    def poll(self, auth_req_id: str) -> Dict[str, str]:
        with self._lock:
            s = self._sessions.get(auth_req_id)
            if s is None:
                raise KeyError("ciba: unknown auth_req_id %s" % auth_req_id)
            return {"status": self._status(s, self._clock())}

    def token(self, auth_req_id: str) -> Dict[str, Any]:
        with self._lock:
            s = self._sessions.get(auth_req_id)
            if s is None:
                return {"ok": False, "error": "invalid_grant", "interval": DEFAULT_INTERVAL_SEC}
            now = self._clock()
            if s.get("consumed"):
                return {"ok": False, "error": "invalid_grant", "interval": s["interval"]}
            too_soon = s.get("lastPollAt") is not None and now - s["lastPollAt"] < s["interval"] * 1000
            s["lastPollAt"] = now
            if too_soon:
                s["interval"] += 5
                return {"ok": False, "error": "slow_down", "interval": s["interval"]}
            st = self._status(s, now)
            for state, err in (("pending", "authorization_pending"), ("denied", "access_denied"), ("expired", "expired_token")):
                if st == state:
                    return {"ok": False, "error": err, "interval": s["interval"]}
            s["consumed"] = True
            return {"ok": True, "session": self._snapshot(s, now)}

    def resolve(self, auth_req_id: str, decision: str, by: str) -> Dict[str, Any]:
        with self._lock:
            s = self._sessions.get(auth_req_id)
            if s is None:
                raise KeyError("ciba: unknown auth_req_id %s" % auth_req_id)
            now = self._clock()
            current = self._status(s, now)
            if current != "pending":
                raise RuntimeError("ciba: cannot resolve %s — already %s" % (auth_req_id, current))
            s["decision"], s["decidedBy"], s["decidedAt"] = decision, by, now
            snap = self._snapshot(s, now)
            if self._on_complete is not None:
                self._on_complete(snap)
            return snap

    def get(self, auth_req_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            s = self._sessions.get(auth_req_id)
            return self._snapshot(s, self._clock()) if s is not None else None


def create_ciba_broker(now: Optional[Callable[[], float]] = None, on_complete: Optional[Callable[[Dict[str, Any]], Any]] = None) -> MemoryCibaBroker:
    return MemoryCibaBroker(now, on_complete)


def create_memory_approval_store() -> Any:
    """Single-process approval store (compare-and-set, snapshots in and out). Not durable."""
    m: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()

    class _Store:
        def get(self, key: str) -> Optional[Dict[str, Any]]:
            with lock:
                v = m.get(key)
                return None if v is None else {"version": v["version"], "value": copy.deepcopy(v["value"])}

        def cas(self, key: str, expected_version: int, value: Any) -> bool:
            with lock:
                if (m[key]["version"] if key in m else 0) != expected_version:
                    return False
                m[key] = {"version": expected_version + 1, "value": copy.deepcopy(value)}
                return True

    return _Store()


def create_memory_kv() -> Any:
    """Single-process durable-KV double for tests of code that takes a KV. Not durable."""
    m: Dict[str, str] = {}
    lock = threading.Lock()

    class _Kv:
        def get(self, key: str) -> Optional[str]:
            with lock:
                return m.get(key)

        def put_if_equals(self, key: str, expected: Optional[str], nxt: str) -> bool:
            with lock:
                if m.get(key) != expected:
                    return False
                m[key] = nxt
                return True

    return _Kv()
