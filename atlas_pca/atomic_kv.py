"""A minimal atomic key/value store: the backend of :class:`atlas_pca.KvOperationStore` and the plan registry.

``get(key) -> value | None`` and ``update(key, fn) -> value``: ``fn(previous)`` returns the value to store, or ``None`` to
leave the key unchanged; the whole read-modify-write is ONE atomic step of the backend (across threads for
:class:`MemoryAtomicKv`, across threads AND processes sharing the file for :class:`SqliteAtomicKv`). Values are
JSON-serialisable."""
from __future__ import annotations

import copy
import json
import sqlite3
import threading
from typing import Any, Callable, Optional


class MemoryAtomicKv:
    """In-process store (one lock). Correct for ONE process only."""

    def __init__(self) -> None:
        self._m: dict = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any:
        with self._lock:
            return copy.deepcopy(self._m.get(key))

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._m[key] = copy.deepcopy(value)

    def update(self, key: str, fn: Callable[[Any], Any]) -> Any:
        with self._lock:
            nxt = fn(copy.deepcopy(self._m.get(key)))
            if nxt is not None:
                self._m[key] = copy.deepcopy(nxt)
            return copy.deepcopy(self._m.get(key))


class SqliteAtomicKv:
    """Durable store on SQLite (crash-safe; safe across threads and processes sharing the file). ``update`` runs inside
    ``BEGIN IMMEDIATE``, so two writers can never both read the same previous value."""

    TABLE = "pca_kv"

    def __init__(self, path: str, *, timeout: float = 30.0) -> None:
        self._path, self._timeout = path, timeout
        self._local = threading.local()
        self._conn().execute("CREATE TABLE IF NOT EXISTS %s (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)" % self.TABLE)

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self._path, timeout=self._timeout, isolation_level=None)
            self._local.conn = c
        return c

    def _read(self, c: sqlite3.Connection, key: str) -> Optional[Any]:
        row = c.execute("SELECT value FROM %s WHERE key = ?" % self.TABLE, (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def get(self, key: str) -> Any:
        return self._read(self._conn(), key)

    def set(self, key: str, value: Any) -> None:
        self.update(key, lambda _prev: value)

    def update(self, key: str, fn: Callable[[Any], Any]) -> Any:
        c = self._conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            prev = self._read(c, key)
            nxt = fn(copy.deepcopy(prev))
            if nxt is not None:
                c.execute("INSERT INTO %s (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
                          % self.TABLE, (key, json.dumps(nxt, separators=(",", ":"), allow_nan=False)))
            c.execute("COMMIT")
            return nxt if nxt is not None else prev
        except BaseException:
            c.execute("ROLLBACK")
            raise
