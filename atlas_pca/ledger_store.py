"""Durable transparency ledger (the TypeScript ``ledger-store``): the ``LedgerStore`` contract, the reference :class:`KvLedgerStore` and
:class:`StoredLedger`.

CLAIMED: TAMPER EVIDENCE, given at least one honest independent witness. The ledger is an append-only Merkle log with guardian-signed
checkpoints. A party holding a checkpoint can later demand a consistency proof and catch a log that was rewritten, truncated or forked.

THE STORE: ``append`` and ``append_checkpoint`` are compare-and-swap on the current length (all entries of a batch or none, so two writers
never assign one index twice and a log never has holes); committing the same batch again at the same position is a replay.

``StoredLedger.open`` rebuilds the Merkle tree from the stored commits and checks it against EVERY stored checkpoint (guardian signature,
signed ``prev_root`` chain, the RFC 9162 consistency proof at each boundary, and that the commits reproduce each root): a store that lost
entries after a checkpoint (``rollback``), edited an entry (``tamper``) or holds a forged checkpoint FAILS CLOSED with a typed error.
``checkpoint`` refuses to sign a head that is not consistent with the previous one. Synchronous; every handle serializes its operations."""
from ._fin import fin
import copy
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from .agent import sign_artifact
from .ledger import STH_DOMAIN, verify_head_consistency, verify_tree_head
from .ledger_proofs import TransparencyLedger
from .pca import hash_canonical
from .store_errors import LedgerStoreError, RangeError

__all__ = ["LedgerStoreError", "append_to_ledger_doc", "checkpoint_to_ledger_doc", "KvLedgerStore", "StoredLedger"]

DOC_KEY = "pca-ledger-store/v1"


def _is_commit(c: Any) -> bool:
    return isinstance(c, str) and len(c) > 0


def _safe_int(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and x == x and abs(x) != float("inf") and int(x) == x and abs(x) <= 9007199254740991


def empty_ledger_doc() -> dict:
    return {"v": 1, "commits": [], "checkpoints": []}


def append_to_ledger_doc(doc: dict, expected_size: Any, commits: Any) -> dict:
    """Append `commits` to `doc` iff it has exactly `expected_size` entries (all or none); a batch already stored there is a replay."""
    if not _safe_int(expected_size) or expected_size < 0:
        raise RangeError("append: expectedSize must be a non-negative safe integer")
    if not isinstance(commits, list) or len(commits) == 0 or not all(_is_commit(c) for c in commits):
        raise RangeError("append: commits must be a non-empty array of non-empty strings")
    size = len(doc["commits"])
    if expected_size < size:
        same = all(i + expected_size < size and doc["commits"][expected_size + i] == c for i, c in enumerate(commits))
        return {"outcome": "replayed" if same else "conflict", "size": size}
    if expected_size > size:
        return {"outcome": "conflict", "size": size}
    doc["commits"].extend(commits)
    return {"outcome": "appended", "size": len(doc["commits"])}


def checkpoint_to_ledger_doc(doc: dict, expected_count: Any, cp: Any) -> dict:
    if not _safe_int(expected_count) or expected_count < 0:
        raise RangeError("appendCheckpoint: expectedCount must be a non-negative safe integer")
    count = len(doc["checkpoints"])
    if expected_count < count:
        if hash_canonical(doc["checkpoints"][expected_count]) == hash_canonical(cp):
            return {"outcome": "replayed", "count": count}
        return {"outcome": "conflict", "count": count, "reason": "another checkpoint holds that position"}
    if expected_count > count:
        return {"outcome": "conflict", "count": count, "reason": "the checkpoint position is ahead of the log"}
    sth = cp.get("sth") if isinstance(cp, dict) else None
    if not isinstance(sth, dict) or not _safe_int(sth.get("size")) or sth["size"] < 0 or str(sth["size"]) == "-0.0" or not isinstance(sth.get("root"), str):
        return {"outcome": "conflict", "count": count, "reason": "malformed checkpoint"}
    if sth["size"] > len(doc["commits"]):
        return {"outcome": "conflict", "count": count, "reason": "the checkpoint is beyond the end of the log"}
    last = doc["checkpoints"][count - 1]["sth"] if count > 0 else None
    if last and (sth["size"] < last["size"] or (sth["size"] == last["size"] and sth["root"] != last["root"])):
        return {"outcome": "conflict", "count": count, "reason": "the checkpoint does not extend the previous one"}
    doc["checkpoints"].append(copy.deepcopy(cp))
    return {"outcome": "appended", "count": len(doc["checkpoints"])}


def _decode_doc(raw: Any) -> dict:
    if raw is None:
        return empty_ledger_doc()
    if not isinstance(raw, dict) or raw.get("v") != 1 or not isinstance(raw.get("commits"), list) or not isinstance(raw.get("checkpoints"), list) \
            or not all(_is_commit(c) for c in raw["commits"]):
        raise LedgerStoreError("store_corrupt", "ledger document has the wrong shape")
    if not all(isinstance(c, dict) and isinstance(c.get("sth"), dict) for c in raw["checkpoints"]):
        raise LedgerStoreError("store_corrupt", "malformed checkpoint entry")
    return raw


class KvLedgerStore:
    """The reference ledger store: the whole log is one document in an atomic key-value store (``get`` / ``update``), so every write is
    one atomic read-modify-write. LIMIT: rewritten on every write; a production log lives in a database with a unique index on the position."""

    def __init__(self, kv: Any, key: str = DOC_KEY) -> None:
        if kv is None or not callable(getattr(kv, "get", None)) or not callable(getattr(kv, "update", None)):
            raise LedgerStoreError("store_missing", "KvLedgerStore needs an atomic kv")
        self._kv, self._key = kv, key

    def _doc(self) -> dict:
        return _decode_doc(self._kv.get(self._key))

    def size(self) -> int:
        return len(self._doc()["commits"])

    def read(self, from_: Any, to: Any) -> List[str]:
        d = self._doc()
        if not _safe_int(from_) or not _safe_int(to) or from_ < 0 or from_ > to or to > len(d["commits"]):
            raise RangeError("read: range is not inside the log")
        return d["commits"][int(from_):int(to)]

    def append(self, expected_size: Any, commits: Any) -> dict:
        out: List[dict] = []

        def fn(prev: Any) -> Any:
            d = _decode_doc(prev)
            out.append(append_to_ledger_doc(d, expected_size, commits))
            return d if out[0]["outcome"] == "appended" else None
        self._kv.update(self._key, fn)
        return out[0]

    def checkpoint_count(self) -> int:
        return len(self._doc()["checkpoints"])

    def checkpoints(self, from_: Any = 0) -> List[dict]:
        d = self._doc()
        if not _safe_int(from_) or from_ < 0 or from_ > len(d["checkpoints"]):
            raise RangeError("checkpoints: from is not inside the list")
        return copy.deepcopy(d["checkpoints"][int(from_):])

    def append_checkpoint(self, expected_count: Any, cp: Any) -> dict:
        out: List[dict] = []

        def fn(prev: Any) -> Any:
            d = _decode_doc(prev)
            out.append(checkpoint_to_ledger_doc(d, expected_count, cp))
            return d if out[0]["outcome"] == "appended" else None
        self._kv.update(self._key, fn)
        return out[0]


def _unavailable(e: BaseException) -> LedgerStoreError:
    return e if isinstance(e, LedgerStoreError) else LedgerStoreError("store_unavailable", str(e) or "store failed")


class StoredLedger:
    """A transparency log over a ledger store. Open it with :meth:`open`; the constructor is private so that no instance exists whose state
    was not verified against the stored checkpoints."""

    def __init__(self, opts: dict, guardian_public: str, log: TransparencyLedger, cps: List[dict], _token: object) -> None:
        if _token is not StoredLedger._TOKEN:
            raise TypeError("use StoredLedger.open")
        self._opts, self._guardian, self._log, self._cps = opts, guardian_public, log, cps
        self._lock = threading.RLock()

    _TOKEN = object()

    @classmethod
    def open(cls, store: Any, guardian: Any, instance_id: str, principal: str, clock: Optional[Callable[[], float]] = None,
             alg: Optional[str] = None, pq: Any = None, pin: Optional[dict] = None) -> "StoredLedger":
        """Load the log and verify it against every stored checkpoint. `guardian` is the guardian :class:`KeyPair`; `alg` / `pq` choose a
        post-quantum or hybrid checkpoint suite (which needs `pin`, the PQ pins ``{ed25519 b64u: pq_pk}``). Raises ``store_missing``,
        ``guardian_key_missing``, ``pin_missing``, ``rollback``, ``tamper``, ``forged_checkpoint``, ``inconsistent``, ``store_corrupt`` or
        ``store_unavailable``."""
        if store is None or not all(callable(getattr(store, m, None)) for m in ("append", "read", "append_checkpoint", "size", "checkpoints")):
            raise LedgerStoreError("store_missing", "a LedgerStore is required (there is no in-memory default)")
        if guardian is None or not isinstance(getattr(guardian, "public", None), str):
            raise LedgerStoreError("guardian_key_missing", "a guardian secret key is required")
        from .pca import _SIG_SUITES
        if alg is not None and (alg != "ed25519" and alg not in _SIG_SUITES or (alg != "ed25519" and not pin)):
            raise LedgerStoreError("pin_missing", "a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)")
        opts = {"store": store, "guardian": guardian, "instance_id": instance_id, "principal": principal, "clock": clock, "alg": alg, "pq": pq, "pin": pin}
        try:
            size = store.size()
            commits = store.read(0, size)
            cps = store.checkpoints(0)
            log = TransparencyLedger.from_entries([{"commit": c} for c in commits], principal)
            self = cls(opts, guardian.public, log, cps, cls._TOKEN)
            self._verify_against_checkpoints()
            return self
        except Exception as e:  # noqa: BLE001
            raise _unavailable(e) from None

    def _verify_chain(self, cps: List[dict]) -> dict:
        pin = self._opts["pin"]
        for i, cp in enumerate(cps):
            if not isinstance(cp, dict) or not verify_tree_head(cp.get("sth"), self._guardian, None, pin):
                return {"ok": False, "at": i, "reason": "head"}
            if i == 0:
                continue
            if not cp.get("proof"):
                return {"ok": False, "at": i, "reason": "proof_missing"}
            if not verify_head_consistency(cps[i - 1]["sth"], cp["sth"], cp["proof"], self._guardian, None, pin):
                return {"ok": False, "at": i, "reason": "inconsistent"}
        return {"ok": True}

    def _verify_against_checkpoints(self) -> None:
        attested = max([0] + [c["sth"]["size"] if _safe_int(c["sth"].get("size")) else 0 for c in self._cps])
        if self._log.size < attested:
            raise LedgerStoreError("rollback", "the log has %d entries but a checkpoint attests %d" % (self._log.size, attested))
        for i, cp in enumerate(self._cps):
            if cp["sth"].get("instance_id") != self._opts["instance_id"] or cp["sth"].get("principal") != self._opts["principal"]:
                raise LedgerStoreError("forged_checkpoint", "checkpoint %d belongs to another log" % i)
            if self._log.root_at(cp["sth"]["size"]) != cp["sth"]["root"]:
                raise LedgerStoreError("tamper", "the stored entries do not reproduce the root of checkpoint %d (size %s)" % (i, cp["sth"]["size"]))
        if not self._cps:
            return
        v = self._verify_chain(self._cps)
        if not v["ok"]:
            raise LedgerStoreError("inconsistent" if v["reason"] == "inconsistent" else "forged_checkpoint", "checkpoint %d: %s" % (v["at"], v["reason"]))

    @property
    def size(self) -> int:
        return self._log.size

    @property
    def guardian(self) -> str:
        """The guardian public key (b64u) every checkpoint verifies under."""
        return self._guardian

    def latest_checkpoint(self) -> Optional[dict]:
        return self._cps[-1]["sth"] if self._cps else None

    def checkpoint_chain(self) -> List[dict]:
        return copy.deepcopy(self._cps)

    def head(self) -> dict:
        return self._log.head()

    def inclusion_proof(self, index: Any) -> dict:
        return self._log.inclusion_proof(index)

    def consistency_proof_from(self, old_size: Any) -> dict:
        """RFC 9162 proof from a size the caller already pinned to the current log."""
        return self._log.consistency_proof(old_size, self._log.size)

    def commits(self) -> List[str]:
        return self._log.commits()

    def append(self, commit: Any) -> dict:
        """Append an opaque commitment leaf. Idempotent under retry at the position the caller read; if another writer took that position the
        ledger reloads and appends at the new tail. Returns ``{"index", "commit"}``."""
        if not _is_commit(commit):
            raise LedgerStoreError("invalid_commit", "a commit must be a non-empty string")
        with self._lock:
            for _ in range(16):
                index = self._log.size
                try:
                    out = self._opts["store"].append(index, [commit])
                except Exception as e:  # noqa: BLE001
                    raise _unavailable(e) from None
                if out["outcome"] in ("appended", "replayed"):
                    self._log.append_commitment(commit)
                    return {"index": index, "commit": commit}
                self._catch_up_locked()  # another writer advanced the log: pick up its entries, then try the new tail
            raise LedgerStoreError("conflict", "the log kept moving; could not append")

    def catch_up(self) -> None:
        """Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints)."""
        with self._lock:
            self._catch_up_locked()

    def _catch_up_locked(self) -> None:
        try:
            st = self._opts["store"]
            size = st.size()
            if size < self._log.size:
                raise LedgerStoreError("rollback", "the store shrank from %d to %d entries" % (self._log.size, size))
            for c in st.read(self._log.size, size):
                self._log.append_commitment(c)
            self._cps.extend(st.checkpoints(len(self._cps)))
            self._verify_against_checkpoints()
        except Exception as e:  # noqa: BLE001
            raise _unavailable(e) from None

    def _assert_store_matches_memory(self) -> None:
        try:
            stored = self._opts["store"].read(0, self._log.size)
        except Exception as e:  # noqa: BLE001
            raise _unavailable(e) from None
        if stored != self._log.commits():
            raise LedgerStoreError("tamper", "the stored entries no longer match this handle; refusing to sign a checkpoint over them")

    def checkpoint(self) -> dict:
        """Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent with the
        previous checkpoint, so a log that was rewritten under this handle is refused (``inconsistent``). An unchanged head returns the
        existing checkpoint."""
        with self._lock:
            self._catch_up_locked()
            self._assert_store_matches_memory()
            prev = self._cps[-1] if self._cps else None
            h = self._log.head()
            if prev and prev["sth"]["size"] == h["size"]:
                return prev["sth"]
            t = self._opts["clock"]() if self._opts["clock"] else time.time() * 1000
            if isinstance(t, bool) or not isinstance(t, (int, float)) or not fin(t):
                raise LedgerStoreError("clock_invalid", "the clock returned a non-finite time")
            t = int(t // 1)
            body = {"instance_id": self._opts["instance_id"], "principal": self._opts["principal"], "size": h["size"], "root": h["root"],
                    "prev_root": prev["sth"]["root"] if prev else "", "timestamp": t}
            signed = sign_artifact(STH_DOMAIN, body, self._opts["guardian"], self._opts["alg"], self._opts["pq"])
            sth = dict(body)
            sth["guardian"] = self._guardian
            sth.update({k: v for k, v in signed.items() if k not in body})
            cp: Dict[str, Any] = {"sth": sth, "proof": self._log.consistency_proof(prev["sth"]["size"], h["size"])} if prev else {"sth": sth}
            v = self._verify_chain(self._cps + [cp])
            if not v["ok"]:
                if v["reason"] == "head":
                    raise LedgerStoreError("forged_checkpoint", "the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)")
                raise LedgerStoreError("inconsistent", "the new head is not consistent with checkpoint %d" % (v["at"] - 1))
            try:
                out = self._opts["store"].append_checkpoint(len(self._cps), cp)
            except Exception as e:  # noqa: BLE001
                raise _unavailable(e) from None
            if out["outcome"] == "conflict":
                raise LedgerStoreError("conflict", out["reason"])
            self._cps.append(cp)
            return sth
