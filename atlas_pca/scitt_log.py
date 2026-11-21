"""Transparency Service logs for SCITT: the durable service over a pluggable store (an append is O(log n) store reads and
writes, state lives entirely in the store), a file-backed and an in-memory store, the in-memory reference service for tests,
and a conformance check for stores. Synchronous port of the TypeScript reference (@atlasauth/pca-scitt).

A store implements size(), get_entry(index), get_node(level, index) and append(expected_size, entry, nodes) where nodes are
dicts {"level", "index", "hash"}; append is an atomic compare-and-set on the size."""
from __future__ import annotations

import hashlib
import os
import struct
from typing import Any, Callable, Dict, List, Optional

from .pca import b64u
from .scitt import (_UNSET, _safe_int, _neg_zero, build_receipt, consistency_path, decode_cose_sign1, empty_root, encode, inclusion_path,
                    leaf_hash, node_hash, sibling_sides, sign_statement, tree_hash)

MAX_APPEND_ATTEMPTS = 16


class ScittLogError(Exception):
    """code: store_required | store_corrupt | append_contention | out_of_range | bad_statement."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require_key(key: Any) -> None:
    """A signing key that is None or empty is refused when the service is built, never carried until a later signature fails."""
    if key is None or (isinstance(key, (bytes, bytearray, str)) and len(key) == 0):
        raise ValueError("a signing key is required")


def _is_integer(v: Any) -> bool:
    """`Number.isInteger`."""
    if isinstance(v, bool):
        return False
    return isinstance(v, int) or (isinstance(v, float) and v == v and v not in (float("inf"), float("-inf")) and v == int(v))


def _largest_pow2_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _is_pow2(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


class _LogReader:
    """Read-side algorithms over a store (hashes of arbitrary ranges, root, proofs)."""

    def __init__(self, store: Any) -> None:
        self.store = store

    def _node(self, level: int, index: int) -> bytes:
        h = self.store.get_node(level, index)
        if h is None or len(h) != 32:
            raise ScittLogError("store_corrupt", "missing or malformed subtree hash (%d, %d)" % (level, index))
        return h

    def range(self, lo: int, n: int) -> bytes:
        if n == 1:
            return self._node(0, lo)
        if _is_pow2(n) and lo % n == 0:
            return self._node(n.bit_length() - 1, lo // n)
        k = _largest_pow2_below(n)
        return node_hash(self.range(lo, k), self.range(lo + k, n - k))

    def root(self, size: int) -> bytes:
        return empty_root() if size == 0 else self.range(0, size)

    def inclusion(self, index: int, size: int) -> List[bytes]:
        def walk(lo: int, n: int, idx: int) -> List[bytes]:
            if n == 1:
                return []
            k = _largest_pow2_below(n)
            if idx < k:
                return walk(lo, k, idx) + [self.range(lo + k, n - k)]
            return walk(lo + k, n - k, idx - k) + [self.range(lo, k)]

        return walk(0, size, index)

    def consistency(self, m: int, size: int) -> List[bytes]:
        def sub(lo: int, n: int, mm: int, complete: bool) -> List[bytes]:
            if not 0 < mm <= n:
                raise ValueError("consistency subproof: size out of range")  # outside 1..n the recursion never meets mm == n
            if mm == n:
                return [] if complete else [self.range(lo, n)]
            k = _largest_pow2_below(n)
            if mm <= k:
                return sub(lo, k, mm, complete) + [self.range(lo + k, n - k)]
            return sub(lo + k, n - k, mm - k, False) + [self.range(lo, k)]

        return sub(0, size, m, True)


class DurableTransparencyService:
    """A durable SCITT Transparency Service over a store you supply (there is no in-memory default)."""

    def __init__(self, store: Any, alg: str, key: Any, issuer: Any = _UNSET) -> None:
        if not all(callable(getattr(store, m, None)) for m in ("size", "get_entry", "get_node", "append")):
            raise ScittLogError("store_required", "a ScittLogStore (size, get_entry, get_node, append) is required; there is no in-memory default")
        _require_key(key)
        self.store = store
        self._reader = _LogReader(store)
        self._signer = (alg, key, issuer)

    def size(self) -> int:
        n = self.store.size()
        if _safe_int(n) is None or n < 0 or _neg_zero(n):
            raise ScittLogError("store_corrupt", "the store reported an invalid size")
        return int(n)

    def root(self) -> str:
        return b64u(self._reader.root(self.size()))

    def _receipt_for(self, index: int, size: int) -> Dict[str, Any]:
        root = self._reader.root(size)
        sides = sibling_sides(index, size)
        path = [{"side": sides[i], "hash": b64u(h)} for i, h in enumerate(self._reader.inclusion(index, size))]
        alg, key, issuer = self._signer
        return {"index": index, "receipt": build_receipt(b64u(root), {"index": index, "size": size, "path": path}, alg, key, issuer), "root": b64u(root)}

    def register(self, statement: bytes) -> Dict[str, Any]:
        """Append a Signed Statement (validated structurally first) and return its receipt against the new root."""
        try:
            cose = decode_cose_sign1(statement)
            if cose["payload"] is None:
                raise TypeError("detached payload")
        except Exception as e:  # noqa: BLE001
            raise ScittLogError("bad_statement", "cannot register: %s" % e) from None
        for _ in range(MAX_APPEND_ATTEMPTS):
            n = self.size()
            nodes = [{"level": 0, "index": n, "hash": leaf_hash(statement)}]
            h = nodes[0]["hash"]
            level = 1
            while (n + 1) % (2 ** level) == 0:  # the new leaf completes a subtree: its left sibling is already stored
                idx = (n + 1) // (2 ** level) - 1
                left = self.store.get_node(level - 1, 2 * idx)
                if left is None or len(left) != 32:
                    raise ScittLogError("store_corrupt", "missing subtree hash (%d, %d)" % (level - 1, 2 * idx))
                h = node_hash(left, h)
                nodes.append({"level": level, "index": idx, "hash": h})
                level += 1
            if self.store.append(n, statement, nodes):
                return self._receipt_for(n, n + 1)
        raise ScittLogError("append_contention", "could not append: the log kept changing")

    def append_and_receipt(self, payload: Any, alg: str, key: Any, issuer: str, subject: Any = _UNSET,
                           content_type: Optional[str] = None) -> Dict[str, Any]:
        statement = sign_statement(payload, alg, key, issuer, subject, content_type)
        return {"statement": statement, **self.register(statement)}

    def get_receipt(self, index: Any) -> Dict[str, Any]:
        """A receipt for an entry, against the CURRENT root."""
        size = self.size()
        if not _is_integer(index) or index < 0 or index >= size:
            raise ScittLogError("out_of_range", "getReceipt: index out of range")
        return self._receipt_for(int(index), size)

    def get_entry(self, index: Any) -> bytes:
        size = self.size()
        if not _is_integer(index) or index < 0 or index >= size:
            raise ScittLogError("out_of_range", "getEntry: index out of range")
        e = self.store.get_entry(int(index))
        if e is None:
            raise ScittLogError("store_corrupt", "entry %d is missing" % index)
        return e

    def consistency_proof(self, old_size: Any) -> Dict[str, Any]:
        """An RFC 9162 consistency proof that the first `old_size` entries are a prefix of the current log."""
        size = self.size()
        if not _is_integer(old_size) or old_size < 1 or old_size > size:
            raise ScittLogError("out_of_range", "consistencyProof: size out of range")
        old_size = int(old_size)
        path = self._reader.consistency(old_size, size)
        return {"oldSize": old_size, "newSize": size, "oldRoot": b64u(self._reader.root(old_size)), "newRoot": b64u(self._reader.root(size)),
                "proof": encode([old_size, size, path])}


def check_scitt_log_store(make_store: Callable[[], Any]) -> List[str]:
    """Check a store against the contract the service relies on (compare-and-set, atomic entry-plus-nodes, immutability).
    Returns the failures (empty = conforms)."""
    failures: List[str] = []
    try:
        s = make_store()
        if s.size() != 0:
            failures.append("a new store is not empty")
        h = lambda b: bytes([b]) * 32  # noqa: E731
        if not s.append(0, b"\x01", [{"level": 0, "index": 0, "hash": h(1)}]):
            failures.append("append at the right size was refused")
        if s.append(0, b"\x02", [{"level": 0, "index": 1, "hash": h(2)}]):
            failures.append("append at a stale size was accepted (no compare-and-set)")
        if s.size() != 1:
            failures.append("a refused append changed the size")
        if s.get_node(0, 1) is not None:
            failures.append("a refused append left a node behind (not atomic)")
        if s.get_entry(1) is not None:
            failures.append("a refused append left an entry behind")
        e0 = s.get_entry(0)
        if not e0 or len(e0) != 1 or e0[0] != 1:
            failures.append("the stored entry does not read back")
        if isinstance(e0, bytearray):
            e0[0] = 9
        again = s.get_entry(0)
        if not again or again[0] != 1:
            failures.append("a returned entry aliases the stored one (mutable)")
        wins = [s.append(1, bytes([10 + i]), [{"level": 0, "index": 1, "hash": h(10 + i)}]) for i in (1, 2, 3, 4)]
        if len([w for w in wins if w]) != 1:
            failures.append("concurrent appends at the same size did not produce exactly one winner")
        if s.size() != 2:
            failures.append("the size after a race is not 2")
    except Exception as e:  # noqa: BLE001
        failures.append("the store threw: %s" % e)
    return failures


class MemoryScittLogStore:
    """In-memory store: single process, forgets everything on restart. For tests only."""

    def __init__(self) -> None:
        self._entries: List[bytes] = []
        self._nodes: Dict[Any, bytes] = {}

    def size(self) -> int:
        return len(self._entries)

    def get_entry(self, index: Any) -> Optional[bytes]:
        return self._entries[index] if _is_integer(index) and 0 <= index < len(self._entries) else None

    def get_node(self, level: Any, index: Any) -> Optional[bytes]:
        return self._nodes.get((level, index))

    def append(self, expected_size: Any, entry: bytes, nodes: List[Dict[str, Any]]) -> bool:
        if len(self._entries) != expected_size:
            return False
        self._entries.append(bytes(entry))
        for n in nodes:
            self._nodes[(n["level"], n["index"])] = bytes(n["hash"])
        return True


def _pread(fd: int, n: int, at: int) -> bytes:
    if hasattr(os, "pread"):
        return os.pread(fd, n, at)
    os.lseek(fd, at, os.SEEK_SET)  # Windows has no pread: the store is single-writer, so the shared offset is not contended
    return os.read(fd, n)


def _pwrite(fd: int, data: bytes, at: int) -> int:
    if hasattr(os, "pwrite"):
        return os.pwrite(fd, data, at)
    os.lseek(fd, at, os.SEEK_SET)
    return os.write(fd, data)


class FileScittLogStore:
    """File-backed store: one append-only file of checksummed transactions (entry plus its new subtree hashes), fsynced before
    `append` returns, so a crash leaves the whole transaction or none of it. A torn final record is discarded on open;
    corruption elsewhere raises `store_corrupt`. SINGLE PROCESS: it does not lock the file."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._nodes: Dict[Any, bytes] = {}
        self._offsets: List[Any] = []
        self._end = 0

    @staticmethod
    def open(path: str) -> "FileScittLogStore":
        os.close(os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600))
        s = FileScittLogStore(os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0)))
        s._load()
        return s

    def close(self) -> None:
        os.close(self._fd)

    def _read(self, at: int, n: int) -> bytes:
        got = b""
        while len(got) < n:
            chunk = _pread(self._fd, n - len(got), at + len(got))
            if not chunk:
                break
            got += chunk
        return got

    def _load(self) -> None:
        total = os.fstat(self._fd).st_size
        pos = 0
        while pos < total:
            head = self._read(pos, 4)
            n = struct.unpack(">I", head)[0] if len(head) == 4 else -1
            rec_end = pos + 4 + n + 32
            if n < 6 or rec_end > total:
                self._discard_tail(pos, rec_end > total)
                return
            payload = self._read(pos + 4, n)
            if hashlib.sha256(payload).digest() != self._read(pos + 4 + n, 32):
                self._discard_tail(pos, rec_end == total)
                return
            entry_len = struct.unpack(">I", payload[:4])[0]
            p = 4 + entry_len
            count = struct.unpack(">H", payload[p:p + 2])[0]
            p += 2
            if p + count * 40 != n:
                raise ScittLogError("store_corrupt", "a log record has an inconsistent length")
            self._offsets.append((pos + 8, entry_len))
            for _ in range(count):
                self._nodes[(payload[p], struct.unpack(">I", payload[p + 1:p + 5])[0])] = payload[p + 8:p + 40]
                p += 40
            pos = rec_end
        self._end = pos

    def _discard_tail(self, pos: int, is_tail: bool) -> None:
        if not is_tail:
            raise ScittLogError("store_corrupt", "the log file is corrupt at offset %d" % pos)
        os.ftruncate(self._fd, pos)
        os.fsync(self._fd)
        self._end = pos

    def size(self) -> int:
        return len(self._offsets)

    def get_entry(self, index: Any) -> Optional[bytes]:
        if not _is_integer(index) or not 0 <= index < len(self._offsets):
            return None
        at, n = self._offsets[int(index)]
        return self._read(at, n)

    def get_node(self, level: Any, index: Any) -> Optional[bytes]:
        return self._nodes.get((level, index))

    def append(self, expected_size: Any, entry: bytes, nodes: List[Dict[str, Any]]) -> bool:
        if len(self._offsets) != expected_size:
            return False
        for n in nodes:
            if (not _is_integer(n["level"]) or n["level"] < 0 or n["level"] > 255 or not _is_integer(n["index"]) or n["index"] < 0
                    or n["index"] > 0xFFFFFFFF or len(n["hash"]) != 32):
                raise ScittLogError("store_corrupt", "a subtree node is malformed")
        entry = bytes(entry)
        payload = struct.pack(">I", len(entry)) + entry + struct.pack(">H", len(nodes))
        for n in nodes:
            payload += bytes([int(n["level"])]) + struct.pack(">I", int(n["index"])) + b"\x00\x00\x00" + bytes(n["hash"])
        record = struct.pack(">I", len(payload)) + payload + hashlib.sha256(payload).digest()
        w = 0
        while w < len(record):
            w += _pwrite(self._fd, record[w:], self._end + w)
        os.fsync(self._fd)
        self._offsets.append((self._end + 8, len(entry)))
        for n in nodes:
            self._nodes[(int(n["level"]), int(n["index"]))] = bytes(n["hash"])
        self._end += len(record)
        return True


class TransparencyService:
    """In-memory reference log: recomputes the Merkle tree on every registration and loses everything on restart. For tests
    and demos only; the production log is :class:`DurableTransparencyService`."""

    def __init__(self, alg: str, key: Any, issuer: Any = _UNSET) -> None:
        _require_key(key)
        self._statements: List[bytes] = []
        self._leaf_hashes: List[bytes] = []
        self._signer = (alg, key, issuer)

    @property
    def size(self) -> int:
        return len(self._statements)

    @property
    def root(self) -> str:
        return b64u(tree_hash(self._leaf_hashes))

    def snapshot(self) -> List[str]:
        return [b64u(st) for st in self._statements]

    def _receipt_for(self, index: int) -> Dict[str, Any]:
        root = tree_hash(self._leaf_hashes)
        size = len(self._leaf_hashes)
        sides = sibling_sides(index, size)
        path = [{"side": sides[i], "hash": b64u(h)} for i, h in enumerate(inclusion_path(self._leaf_hashes, index))]
        alg, key, issuer = self._signer
        return {"index": index, "receipt": build_receipt(b64u(root), {"index": index, "size": size, "path": path}, alg, key, issuer), "root": b64u(root)}

    def register(self, statement: bytes) -> Dict[str, Any]:
        cose = decode_cose_sign1(statement)
        if cose["payload"] is None:
            raise TypeError("scitt: cannot register a statement with a detached payload")
        index = len(self._statements)
        self._statements.append(bytes(statement))
        self._leaf_hashes.append(leaf_hash(statement))
        return self._receipt_for(index)

    def append_and_receipt(self, payload: Any, alg: str, key: Any, issuer: str, subject: Any = _UNSET,
                           content_type: Optional[str] = None) -> Dict[str, Any]:
        statement = sign_statement(payload, alg, key, issuer, subject, content_type)
        return {"statement": statement, **self.register(statement)}

    def get_receipt(self, index: Any) -> Dict[str, Any]:
        if not _is_integer(index) or index < 0 or index >= len(self._statements):
            raise ValueError("getReceipt: index out of range")
        return self._receipt_for(int(index))

    def consistency_proof(self, old_size: Any) -> Dict[str, Any]:
        """The log at `old_size` entries is a prefix of the current log: both roots and the RFC 9942 proof encoding."""
        if not _is_integer(old_size) or old_size < 1 or old_size > len(self._statements):
            raise ValueError("consistencyProof: size out of range")
        old_size = int(old_size)
        path = consistency_path(self._leaf_hashes, old_size)
        return {"oldSize": old_size, "newSize": len(self._statements), "oldRoot": b64u(tree_hash(self._leaf_hashes[:old_size])),
                "newRoot": self.root, "proof": encode([old_size, len(self._statements), path])}


def register_statement(statement: bytes, service: TransparencyService) -> Dict[str, Any]:
    """Register a Signed Statement into a Transparency Service (RFC 9943 register-signed-statement)."""
    return service.register(statement)
