"""Crash-safe, tamper-evident, multi-process-safe persistent key/value state (a faithful port of the reference ``durable-state``;
the on-disk format is the same, a directory written by one language opens in the other).

WHY: rollback protection for signed manifests and key sets is only as good as the persistence of "the highest thing I ever
accepted".

LAYOUT (a directory you own, mode 0700): ``state.journal`` (hash-chained records, one JSON object per line), ``state.head`` (seq +
hash of the last record, written AFTER the journal), ``state.lock.<g>`` (the lock: immutable numbered generation files created
atomically with link(2)), ``state.fence*`` (operator-recovery fences).

GUARANTEES: every mutation is write-temp, fsync, rename, fsync(directory): a crash leaves the old or the new journal, never a torn
one, and the head trails by at most one record (repaired by the next writer). No lost updates across processes: every mutation
runs under the exclusive generation lock; a lock is taken over only from a PROVABLY dead holder on this host and PID namespace,
never by age; the generation is re-checked right before every rename. A holder that is only PAUSED across
:func:`recover_durable_state` is fenced: every record and head carries the writer's generation, and the fence recovery wrote makes
load refuse a late record from a released generation. Records are hash-chained (and HMAC-tagged with ``hmac_key``); a corrupt,
truncated or rolled-back state makes every operation raise :class:`DurableStateError`, never silently starting empty; the ONLY way
past is ``recover_from_corruption=True``, which quarantines the files (kept for forensics) and starts from genesis with
``recovered`` true.

NOT GUARANTEED: ONE HOST and ONE PID namespace per directory (a holder on another host or namespace is never judged dead: waiters
time out, fail closed); a LOCAL filesystem with working hard links (probed at open: ``link-unsupported``); a stalled live holder
blocks until it dies (``lock-timeout``); the journal is rewritten whole per mutation (small state) and compacted every
``compact_every`` records.

Values are JSON trees. ``None`` means "absent" for ``get`` and "leave unchanged" for the ``update`` callback (a JSON ``null`` value
is storable with ``set``)."""
from __future__ import annotations

from ._fin import fin
import hashlib
import hmac as _hmac
import json
import math
import os
import random
import re
import secrets
import signal
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .adapters import js_json
from .pca import utf8
from .private_fs import makedirs_private, open_private
from .atomic_kv import MemoryAtomicKv

__all__ = ["DurableState", "DurableStateError", "open_durable_state", "recover_durable_state", "create_memory_durable_kv"]

_DOMAIN = "pca-durable-state/v1\n"
_GENESIS = "0" * 64
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_KEY = 256
_FENCE_FILE = "state.fence"
_FENCE_ENTRY = re.compile(r"state\.fence\.(\d+)-([0-9a-f]+)")
_LOCK_ENTRY = re.compile(r"state\.lock\.(\d+)")
RECOVER_CRASH_ENV = "PCA_DURABLE_TEST_RECOVER_CRASH_AT"
_BOOT_ID = secrets.token_hex(12)


class DurableStateError(Exception):
    """``code``: invalid | corrupt | rollback | key-mismatch | too-large | lock-timeout | lock-lost | link-unsupported."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__("%s: %s" % (code, message))


def _reject_const(c: str) -> Any:
    raise ValueError(c)


def _loads(s: str) -> Any:
    return json.loads(s, parse_constant=_reject_const, parse_int=lambda t: -0.0 if t == "-0" else int(t))  # JSON -0 is negative zero, as in JS


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _safe_int(x: Any) -> bool:
    if isinstance(x, bool):
        return False
    if isinstance(x, float):
        return fin(x) and x == int(x) and abs(x) <= 9007199254740991 and not (x == 0 and math.copysign(1, x) < 0)
    return isinstance(x, int) and abs(x) <= 9007199254740991


def _gen(x: Any) -> bool:
    return _safe_int(x) and x >= 1


def _sha(s: str) -> str:
    return hashlib.sha256(utf8(s)).hexdigest()


def _u16len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _u16key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _read_text(path: str) -> str:
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace")


def _fsync_dir(d: str) -> None:
    if os.name == "nt":
        return  # a directory cannot be opened on Windows; the file's own fsync before the rename is the durability point there
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: str, data: str, before_rename: Optional[Callable[[], None]] = None) -> None:
    tmp = "%s.tmp-%d-%s" % (path, os.getpid(), secrets.token_hex(6))
    fd = open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        os.write(fd, data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if before_rename is not None:
        try:
            before_rename()
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass  # best effort: the orphan temp is harmless
            raise
    os.replace(tmp, path)  # replaces an existing file on Windows too
    _fsync_dir(os.path.dirname(path) or ".")


def _pid_alive(pid: Any) -> bool:
    if os.name == "nt":  # os.kill(pid, 0) is CTRL_C_EVENT on Windows (it interrupts the caller), never a liveness probe
        import ctypes
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenProcess.restype = ctypes.c_void_p
            h = k32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
            if not h:
                return ctypes.get_last_error() == 5  # access denied: it exists
            code = ctypes.c_ulong()
            ok = k32.GetExitCodeProcess(ctypes.c_void_p(h), ctypes.byref(code))
            k32.CloseHandle(ctypes.c_void_p(h))
            return bool(ok) and code.value == 259  # STILL_ACTIVE
        except Exception:  # noqa: BLE001
            return False
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        return True
    except Exception:  # noqa: BLE001
        return False


def _proc_start_of(pid: Any) -> Optional[str]:
    """Process start time (field 22 of /proc/<pid>/stat); None off Linux or when gone."""
    try:
        st = _read_text("/proc/%d/stat" % int(pid))
        return st[st.rindex(")") + 2:].split(" ")[19]
    except Exception:  # noqa: BLE001
        return None


def _my_ns() -> Optional[str]:
    try:
        return os.readlink("/proc/self/ns/pid")
    except OSError:
        return None


def _test_crash_point(point: str) -> None:
    """Test-only SIGKILL of this process at a named step of operator recovery (PCA_DURABLE_TEST=1 and the env var both set)."""
    if os.environ.get("PCA_DURABLE_TEST") == "1" and os.environ.get(RECOVER_CRASH_ENV) == point:
        os.kill(os.getpid(), getattr(signal, "SIGKILL", signal.SIGTERM))


def _lock_gens(d: str) -> List[int]:
    return [int(m.group(1)) for m in (_LOCK_ENTRY.fullmatch(f) for f in os.listdir(d)) if m]


def _fence_entry_files(d: str) -> List[Dict[str, Any]]:
    return [{"name": n, "gen": int(m.group(1))} for n, m in ((n, _FENCE_ENTRY.fullmatch(n)) for n in os.listdir(d)) if m]


def _parse_fence(f: Any, where: str) -> Dict[str, Any]:
    ok = (isinstance(f, dict) and _gen(f.get("gen")) and _safe_int(f.get("seq")) and f["seq"] >= 0
          and isinstance(f.get("h"), str) and _HEX64.fullmatch(f["h"]) is not None)
    if not ok:
        raise DurableStateError("corrupt", "%s has an invalid entry" % where)
    return {"gen": int(f["gen"]), "seq": int(f["seq"]), "h": f["h"]}


def _read_json(path: str, name: str) -> Any:
    try:
        return _loads(_read_text(path))
    except ValueError:
        raise DurableStateError("corrupt", "%s is not valid JSON" % name) from None


def _read_fences(d: str) -> List[Dict[str, Any]]:
    """Every fence: the list in ``state.fence`` (absent = none) then each ``state.fence.<gen>-<rand>`` by generation."""
    out: List[Dict[str, Any]] = []
    p = os.path.join(d, _FENCE_FILE)
    if os.path.exists(p):
        o = _read_json(p, "state.fence")
        if not (isinstance(o, dict) and o.get("v") == 1 and not isinstance(o.get("v"), bool) and isinstance(o.get("fences"), list)):
            raise DurableStateError("corrupt", "state.fence has an invalid shape")
        for f in o["fences"]:
            out.append(_parse_fence(f, "state.fence"))
    for e in sorted(_fence_entry_files(d), key=lambda e: (e["gen"], e["name"])):
        o = _read_json(os.path.join(d, e["name"]), e["name"])
        if not (isinstance(o, dict) and o.get("v") == 1 and not isinstance(o.get("v"), bool)):
            raise DurableStateError("corrupt", "%s has an invalid shape" % e["name"])
        f = _parse_fence(o.get("fence"), e["name"])
        if f["gen"] != e["gen"]:
            raise DurableStateError("corrupt", "%s names generation %d but holds %d" % (e["name"], e["gen"], f["gen"]))
        out.append(f)
    return out


def _journal_tail(d: str) -> Dict[str, Any]:
    """(seq, hash) of the last journal record as it is on disk right now; absent or unparsable gives (0, zeros)."""
    none = {"seq": 0, "h": _GENESIS}
    try:
        lines = [x for x in _read_text(os.path.join(d, "state.journal")).split("\n") if x]
        o = _loads(lines[-1] if lines else "null")
        if isinstance(o, dict) and _safe_int(o.get("seq")) and o["seq"] >= 1 and isinstance(o.get("h"), str) and _HEX64.fullmatch(o["h"]):
            return {"seq": int(o["seq"]), "h": o["h"]}
    except Exception:  # noqa: BLE001
        pass
    return none


def _write_fence(d: str, g: int, before_rename: Optional[Callable[[], None]] = None) -> None:
    """The operator's CUT: every journal record after the tail seen NOW must come from a generation above ``g``."""
    _read_fences(d)  # an unreadable fence set fails closed here too
    fence: Dict[str, Any] = {"gen": g + 1}
    fence.update(_journal_tail(d))
    fence["from"] = g
    fence["t"] = _now_ms()
    _atomic_write(os.path.join(d, "%s.%d-%s" % (_FENCE_FILE, g + 1, secrets.token_hex(6))), js_json({"v": 1, "fence": fence}) + "\n", before_rename)


def _classify_lock_file(path: str) -> Dict[str, Any]:
    try:
        o = _loads(_read_text(path))
    except Exception:  # noqa: BLE001
        return {"kind": "unreadable"}
    if not isinstance(o, (dict, list)):
        return {"kind": "unreadable"}
    if isinstance(o, list):
        return {"kind": "incomplete", "raw": o}  # readable JSON, no holder fields
    if o.get("st") == "free":
        return {"kind": "free"}
    if _is_num(o.get("pid")) and isinstance(o.get("host"), str) and isinstance(o.get("nonce"), str) and o["nonce"] != "":
        return {"kind": "complete", "body": o}
    return {"kind": "incomplete", "raw": o}


def _holder_alive_here(b: Dict[str, Any]) -> bool:
    """Is the recorded holder demonstrably ALIVE here? Judged by PID-namespace identity when the record names one, else by host."""
    if not isinstance(b, dict) or not _is_num(b.get("pid")):
        return False
    ns_now = _my_ns()
    judgeable = (ns_now is not None and b["ns"] == ns_now) if isinstance(b.get("ns"), str) else b.get("host") == socket.gethostname()
    if not judgeable or not _pid_alive(b["pid"]):
        return False
    if isinstance(b.get("start"), str):
        cur = _proc_start_of(b["pid"])
        if cur is not None and cur != b["start"]:
            return False  # the pid was reused by a different process
    return True


def _confirm_holder(c: Dict[str, Any], exp: Any, path: str) -> None:
    kind = c["kind"]
    if kind == "unreadable":
        if exp != "unreadable":
            raise DurableStateError("invalid", "%s is unreadable; pass expected_holder='unreadable' to release it" % path)
    elif kind == "incomplete":
        if exp != "unreadable":
            raise DurableStateError("invalid", "%s has an incomplete holder record (%s); after confirming its holder is gone, pass expected_holder='unreadable' to release it" % (path, js_json(c["raw"])[:160]))
        if _holder_alive_here(c["raw"]):
            raise DurableStateError("invalid", "the holder of %s (pid %s) is alive in this PID namespace; refusing to release a live holder" % (path, js_json(c["raw"]["pid"])))  # a non-dict raw never gets here: no numeric pid
    elif kind == "complete":
        b = c["body"]
        if exp == "unreadable":
            raise DurableStateError("invalid", "%s is readable (holder pid=%s host=%s); expected_holder 'unreadable' does not match" % (path, js_json(b["pid"]), b["host"]))
        if b["host"] != exp["host"] or b["pid"] != exp["pid"] or b["nonce"] != exp["nonce"]:
            raise DurableStateError("invalid", "expected_holder does not match the holder recorded in %s (recorded pid=%s host=%s nonce=%s); nothing was changed" % (path, js_json(b["pid"]), b["host"], b["nonce"]))
        if _holder_alive_here(b):
            raise DurableStateError("invalid", "the holder of %s (pid %s) is alive in this PID namespace; refusing to release a live holder" % (path, js_json(b["pid"])))


def recover_durable_state(*, dir: str, force: bool = False, expected_holder: Any = None, legacy_lock: bool = False) -> Dict[str, Any]:
    """Operator recovery for a lock whose holder cannot be judged dead automatically (another PID namespace, a changed hostname, an
    unreadable or incomplete top lock file, or a legacy single-file ``state.lock``). Out of band: it takes the lock itself
    (generation g+1), cuts and FENCES the released generation, then appends a "free" generation g+2. ``expected_holder`` is the
    recorded ``{'host','pid','nonce'}`` EXACTLY, or ``'unreadable'``. Returns ``{'released', 'reason', 'lock_file'?}``; raises
    :class:`DurableStateError` ('invalid')."""
    if force is not True:
        raise DurableStateError("invalid", "recover_durable_state requires force=True")
    exp = expected_holder
    if not (exp == "unreadable" or (isinstance(exp, dict) and isinstance(exp.get("host"), str) and _is_num(exp.get("pid")) and isinstance(exp.get("nonce"), str) and exp["nonce"] != "")):
        raise DurableStateError("invalid", "expected_holder must be { host, pid, nonce } as recorded in the lock file, or 'unreadable'")
    gens = _lock_gens(dir)
    g = max(gens) if gens else 0
    path = os.path.join(dir, "state.lock.%d" % g)
    top = None if g == 0 else _classify_lock_file(path)
    legacy_path = os.path.join(dir, "state.lock")
    if legacy_lock is True:
        if top is not None and top["kind"] != "free":
            raise DurableStateError("invalid", "legacy_lock=True, but the blocking lock is the generation lock %s; call recover_durable_state without legacy_lock" % path)
        if not os.path.exists(legacy_path):
            return {"released": False, "reason": "not-held"}
        legacy = _classify_lock_file(legacy_path)
        if legacy["kind"] == "free":
            return {"released": False, "reason": "not-held", "lock_file": legacy_path}
        _confirm_holder(legacy, exp, legacy_path)
        _write_fence(dir, g)
        os.rename(legacy_path, os.path.join(dir, "state.lock.legacy-recovered-%d-%s" % (_now_ms(), secrets.token_hex(3))))
        _fsync_dir(dir)
        return {"released": True, "reason": "released", "lock_file": legacy_path}
    if top is None or top["kind"] == "free":
        if os.path.exists(legacy_path):
            lb = _classify_lock_file(legacy_path)
            who = ("holder pid=%s host=%s nonce=%s" % (js_json(lb["body"]["pid"]), lb["body"]["host"], lb["body"]["nonce"])) if lb["kind"] == "complete" else "%s holder record" % lb["kind"]
            raise DurableStateError("invalid", "the blocking lock is the legacy single-file %s (%s); after confirming that holder is gone, pass legacy_lock=True with its expected_holder (or 'unreadable')" % (legacy_path, who))
        return {"released": False, "reason": "not-held"} if top is None else {"released": False, "reason": "not-held", "lock_file": path}
    _confirm_holder(top, exp, path)

    # in this order (formal/tla/DurableFence.tla): TAKE generation g+1 (marked `recovering`), CUT + FENCE under it, RELEASE as g+2 free
    def link_body(gen: int, body: Dict[str, Any], crash_point: str) -> None:
        tmp = os.path.join(dir, "state.lock.tmp-%d-%s" % (os.getpid(), secrets.token_hex(6)))
        fd = open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.write(fd, js_json(body).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        _test_crash_point(crash_point)
        try:
            os.link(tmp, os.path.join(dir, "state.lock.%d" % gen))
        except FileExistsError:
            raise DurableStateError("invalid", "%s was superseded while recovering; re-read the lock state and retry" % path) from None
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    ns = _my_ns()
    _test_crash_point("before-lock")
    start = _proc_start_of(os.getpid())
    body: Dict[str, Any] = {"st": "held", "pid": os.getpid(), "host": socket.gethostname(), "nonce": secrets.token_hex(12), "boot": _BOOT_ID}
    if ns is not None:
        body["ns"] = ns
    if start is not None:
        body["start"] = start
    body["recovering"] = g
    body["t"] = _now_ms()
    link_body(g + 1, body, "after-lock-temp")
    _test_crash_point("after-lock")
    _write_fence(dir, g, lambda: _test_crash_point("after-fence-temp"))
    _test_crash_point("after-fence")
    link_body(g + 2, {"st": "free", "t": _now_ms(), "recoveredFrom": g}, "after-release-temp")
    _test_crash_point("after-release")
    return {"released": True, "reason": "released", "lock_file": path}


class DurableState:
    """A durable state directory handle. Build with :func:`open_durable_state`."""

    def __init__(self, *, dir: str, hmac_key: Optional[bytes] = None, recover_from_corruption: bool = False, lock_timeout_ms: int = 10_000,
                 compact_every: int = 256, max_value_bytes: int = 1_048_576, now: Optional[Callable[[], int]] = None) -> None:
        if not isinstance(dir, str) or not dir:
            raise DurableStateError("invalid", "dir is required")
        if hmac_key is not None and len(hmac_key) < 32:
            raise DurableStateError("invalid", "hmac_key must be at least 32 bytes")
        self._dir = dir
        self._key = bytes(hmac_key) if hmac_key is not None else None
        self._recover_opt = recover_from_corruption is True
        self._lock_timeout = lock_timeout_ms
        self._compact_every = max(2, compact_every)
        self._max_value = max_value_bytes
        self._now = now or _now_ms
        self._journal_path = os.path.join(dir, "state.journal")
        self._head_path = os.path.join(dir, "state.head")
        self._seen = {"seq": 0, "hash": _GENESIS}
        self.recovered = False
        self._held_nonce: Optional[str] = None
        self._my_gen = -1
        self._my_ns = _my_ns()
        self._my_start = _proc_start_of(os.getpid())
        self._mutex = threading.Lock()
        makedirs_private(dir)
        try:
            if os.name != "nt":
                os.chmod(dir, 0o700)
        except OSError:
            pass  # not ours to chmod
        self._probe_links()

        def init() -> None:
            ld = self._load_or_recover()
            self._observe(ld)
            last = ld["recs"][-1] if ld["recs"] else None
            if last and (ld["head"] is None or ld["head"]["seq"] != last["seq"]):
                self._write_head(last)

        self._with_lock(init)

    # ---- public --------------------------------------------------------------------------------------------------------------
    def position(self) -> Dict[str, Any]:
        """Highest chain position this handle has observed: ``{'seq', 'hash'}``."""
        return dict(self._seen)

    def verify(self) -> Dict[str, Any]:
        """Verify the chain from disk now; raises DurableStateError on any problem."""
        def f() -> Dict[str, Any]:
            self._observe(self._load())
            return dict(self._seen)
        return self._with_lock(f)

    def get(self, k: str) -> Any:
        self._check_key(k)

        def f() -> Any:
            ld = self._load()
            self._observe(ld)
            v = ld["state"].get(k)
            return None if v is None else json.loads(v)
        return self._with_lock(f)

    def keys(self) -> List[str]:
        def f() -> List[str]:
            ld = self._load()
            self._observe(ld)
            return sorted(ld["state"], key=_u16key)
        return self._with_lock(f)

    def set(self, k: str, value: Any) -> None:
        """Unconditional write (still serialised and hash-chained). Prefer :meth:`update` for monotone state."""
        self._check_key(k)
        vj = self._encode(value)

        def f() -> None:
            ld = self._load()
            last = ld["recs"][-1] if ld["recs"] else None
            if last and (ld["head"] is None or ld["head"]["seq"] != last["seq"]):
                self._write_head(last)
            self._commit(ld, k, vj)
        self._with_lock(f)

    def update(self, k: str, fn: Callable[[Any], Any]) -> Any:
        """Atomic read-modify-write: ``fn`` gets the current value (None when absent) and returns the next value, or None to leave
        the key unchanged. Runs under the cross-process lock and must be quick. Returns the value now stored."""
        self._check_key(k)

        def f() -> Any:
            ld = self._load()
            last = ld["recs"][-1] if ld["recs"] else None
            if last and (ld["head"] is None or ld["head"]["seq"] != last["seq"]):
                self._write_head(last)
            cur = ld["state"].get(k)
            nxt = fn(None if cur is None else json.loads(cur))
            if nxt is None:
                return None if cur is None else json.loads(cur)
            vj = self._encode(nxt)
            if vj != cur:
                self._commit(ld, k, vj)
            return json.loads(vj)
        return self._with_lock(f)

    # ---- helpers -------------------------------------------------------------------------------------------------------------
    def _mac_of(self, msg: str) -> str:
        return _hmac.new(self._key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _mac_eq(a: str, b: str) -> bool:
        return _hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

    @staticmethod
    def _rec_hash(r: Dict[str, Any]) -> str:
        arr = [r["seq"], r["prev"], r["op"], r["payload"], r["ts"]]
        if r.get("gen") is not None:
            arr.append(r["gen"])
        return _sha(_DOMAIN + js_json(arr))

    @staticmethod
    def _head_msg(seq: int, h: str, gen: Optional[int] = None) -> str:
        return "head\n%d\n%s" % (seq, h) if gen is None else "head\n%d\n%s\n%d" % (seq, h, gen)

    def _encode(self, value: Any) -> str:
        try:
            s = js_json(value)
        except (TypeError, ValueError):
            raise DurableStateError("invalid", "value is not JSON-serialisable") from None
        if _u16len(s) > self._max_value:
            raise DurableStateError("too-large", "value exceeds maxValueBytes=%d" % self._max_value)
        return s

    @staticmethod
    def _check_key(k: Any) -> None:
        if not isinstance(k, str) or not k or _u16len(k) > _MAX_KEY or "\n" in k:
            raise DurableStateError("invalid", "key must be 1..256 chars without newlines")

    def _read_head(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self._head_path):
            return None
        try:
            o = _loads(_read_text(self._head_path))
        except ValueError:
            raise DurableStateError("corrupt", "state.head is not valid JSON") from None
        ok = (isinstance(o, dict) and _safe_int(o.get("seq")) and o["seq"] >= 0 and isinstance(o.get("h"), str) and _HEX64.fullmatch(o["h"])
              and ("gen" not in o or _gen(o["gen"])))
        if not ok:
            raise DurableStateError("corrupt", "state.head has an invalid shape")
        head: Dict[str, Any] = {"seq": int(o["seq"]), "h": o["h"]}
        if "gen" in o:
            head["gen"] = int(o["gen"])
        if isinstance(o.get("mac"), str):
            head["mac"] = o["mac"]
        if self._key is not None and (head.get("mac") is None or not self._mac_eq(head["mac"], self._mac_of(self._head_msg(head["seq"], head["h"], head.get("gen"))))):
            raise DurableStateError("key-mismatch", "state.head MAC does not verify (wrong key or forged head)")
        return head

    @staticmethod
    def _parse_line(line: str, i: int) -> Dict[str, Any]:
        try:
            o = _loads(line)
        except ValueError:
            raise DurableStateError("corrupt", "journal line %d is not valid JSON" % (i + 1)) from None
        ok = (isinstance(o, dict) and _safe_int(o.get("seq")) and isinstance(o.get("prev"), str) and _HEX64.fullmatch(o["prev"]) is not None
              and o.get("op") in ("set", "checkpoint") and isinstance(o.get("payload"), str) and _safe_int(o.get("ts"))
              and isinstance(o.get("h"), str) and _HEX64.fullmatch(o["h"]) is not None and ("gen" not in o or _gen(o["gen"])))
        if not ok:
            raise DurableStateError("corrupt", "journal line %d has an invalid shape" % (i + 1))
        rec: Dict[str, Any] = {"seq": int(o["seq"]), "prev": o["prev"], "op": o["op"], "payload": o["payload"], "ts": int(o["ts"])}
        if "gen" in o:
            rec["gen"] = int(o["gen"])
        rec["h"] = o["h"]
        if isinstance(o.get("mac"), str):
            rec["mac"] = o["mac"]
        return rec

    def _load(self) -> Dict[str, Any]:
        head = self._read_head()
        fences = _read_fences(self._dir)
        if not os.path.exists(self._journal_path):
            if head is not None and head["seq"] > 0:
                raise DurableStateError("rollback", "state.journal is missing but state.head records seq %d" % head["seq"])
            cut = next((f for f in fences if f["seq"] > 0), None)
            if cut is not None:
                raise DurableStateError("rollback", "state.journal is missing but operator recovery cut it at seq %d" % cut["seq"])
            if self._seen["seq"] > 0:
                raise DurableStateError("rollback", "state was deleted while open")
            return {"recs": [], "state": {}, "head": head}
        lines = _read_text(self._journal_path).split("\n")
        if lines[-1] != "":
            raise DurableStateError("corrupt", "journal does not end with a newline (torn or truncated)")
        lines.pop()
        recs: List[Dict[str, Any]] = []
        state: Dict[str, str] = {}
        prev_hash, prev_seq, prev_gen = _GENESIS, 0, 0
        for i, line in enumerate(lines):
            rec = self._parse_line(line, i)
            if i == 0:
                if rec["op"] == "set" and (rec["seq"] != 1 or rec["prev"] != _GENESIS):
                    raise DurableStateError("corrupt", "journal does not start at genesis")
                if rec["op"] == "checkpoint" and rec["seq"] < 1:
                    raise DurableStateError("corrupt", "bad checkpoint seq")
            else:
                if rec["seq"] != prev_seq + 1:
                    raise DurableStateError("corrupt", "journal line %d: sequence gap" % (i + 1))
                if rec["prev"] != prev_hash:
                    raise DurableStateError("corrupt", "journal line %d: hash chain broken" % (i + 1))
            if self._rec_hash(rec) != rec["h"]:
                raise DurableStateError("corrupt", "journal line %d: record hash mismatch (edited)" % (i + 1))
            if self._key is not None:
                if rec.get("mac") is None or not self._mac_eq(rec["mac"], self._mac_of(rec["h"])):
                    raise DurableStateError("key-mismatch", "journal line %d: MAC does not verify (wrong key or forged record)" % (i + 1))
            elif rec.get("mac") is not None:
                raise DurableStateError("key-mismatch", "journal is MAC-tagged but no hmac_key was supplied")
            rg = rec.get("gen") or 0
            if rg < prev_gen:
                raise DurableStateError("corrupt", "journal line %d (seq %d) was written by lock generation %d, older than generation %d of an earlier record: a stale writer's record (refused)" % (i + 1, rec["seq"], rg, prev_gen))
            for f in fences:
                if rec["seq"] > f["seq"] and rg < f["gen"]:
                    raise DurableStateError("corrupt", "journal line %d (seq %d) was written by lock generation %d, but operator recovery fenced generations below %d after seq %d: a holder paused across recover_durable_state resumed and replaced the journal late (refused; records committed after the recovery may be lost; recover_from_corruption quarantines the files)" % (i + 1, rec["seq"], rg, f["gen"], f["seq"]))
            prev_gen = rg
            if rec["op"] == "checkpoint":
                try:
                    entries = _loads(rec["payload"])
                except ValueError:
                    raise DurableStateError("corrupt", "checkpoint payload is not JSON") from None
                if not isinstance(entries, list):
                    raise DurableStateError("corrupt", "checkpoint payload is not an array")
                state.clear()
                for e in entries:
                    if not (isinstance(e, list) and len(e) == 2 and isinstance(e[0], str) and isinstance(e[1], str)):
                        raise DurableStateError("corrupt", "checkpoint entry is malformed")
                    state[e[0]] = e[1]
            else:
                nl = rec["payload"].find("\n")
                if nl < 1:
                    raise DurableStateError("corrupt", "journal line %d: malformed payload" % (i + 1))
                state[rec["payload"][:nl]] = rec["payload"][nl + 1:]
            recs.append(rec)
            prev_hash, prev_seq = rec["h"], rec["seq"]
        last = recs[-1] if recs else None
        last_seq = last["seq"] if last else 0
        for f in fences:
            if last_seq < f["seq"]:
                raise DurableStateError("rollback", "journal is at seq %d but operator recovery cut it at seq %d (truncation, or a stale writer replaced it)" % (last_seq, f["seq"]))
            at_cut = next((r for r in recs if r["seq"] == f["seq"]), None)
            if f["seq"] > 0 and at_cut is not None and at_cut["h"] != f["h"]:
                raise DurableStateError("corrupt", "journal record at seq %d is not the record operator recovery cut at: a stale writer replaced the journal (refused; recover_from_corruption quarantines the files)" % f["seq"])
        if head is not None:
            hg = head.get("gen") or 0
            if last_seq < head["seq"]:
                raise DurableStateError("rollback", "journal is at seq %d but state.head recorded seq %d (truncation or older copy)" % (last_seq, head["seq"]))
            if last is not None and (last.get("gen") or 0) < hg and (last_seq == head["seq"] + 1 or (last_seq == head["seq"] and last["h"] != head["h"])):
                raise DurableStateError("corrupt", "journal tail (seq %d) was written by lock generation %d, older than generation %d that wrote state.head: a stale writer replaced the journal (refused)" % (last_seq, last.get("gen") or 0, hg))
            stale_head = (last_seq > head["seq"] + 1 and any(hg < f["gen"] and head["seq"] <= f["seq"] and last_seq > f["seq"] for f in fences)
                          and any(r["seq"] == head["seq"] and r["h"] == head["h"] for r in recs))
            if last_seq > head["seq"] + 1 and not stale_head:
                raise DurableStateError("corrupt", "journal (seq %d) is more than one record ahead of state.head (seq %d)" % (last_seq, head["seq"]))
            if last is not None:
                if last_seq == head["seq"] and last["h"] != head["h"]:
                    raise DurableStateError("corrupt", "journal tail does not match state.head")
                if last_seq == head["seq"] + 1 and last["prev"] != head["h"]:
                    raise DurableStateError("corrupt", "journal tail is not chained from state.head")
        elif last_seq > 1:
            raise DurableStateError("rollback", "state.head is missing but the journal is at seq %d" % last_seq)
        if last is not None:
            if last["seq"] < self._seen["seq"]:
                raise DurableStateError("rollback", "state moved backwards from seq %d to %d while open" % (self._seen["seq"], last["seq"]))
            if last["seq"] == self._seen["seq"] and last["h"] != self._seen["hash"]:
                raise DurableStateError("rollback", "state forked at seq %d while open" % last["seq"])
        elif self._seen["seq"] > 0:
            raise DurableStateError("rollback", "state was emptied while open")
        return {"recs": recs, "state": state, "head": head}

    def _quarantine(self) -> None:
        tag = "%d-%s" % (self._now(), secrets.token_hex(3))
        self._assert_lock_held()  # a writer that lost the lock must not move a newer holder's files aside
        fence_path = os.path.join(self._dir, _FENCE_FILE)
        old_entries = _fence_entry_files(self._dir)
        if os.path.exists(fence_path) or old_entries:
            if os.path.exists(fence_path):
                os.link(fence_path, "%s.quarantine-%s" % (fence_path, tag))
            _atomic_write(fence_path, js_json({"v": 1, "fences": [{"gen": self._my_gen, "seq": 0, "h": _GENESIS, "from": self._my_gen - 1, "t": self._now()}]}) + "\n")
            for e in old_entries:
                os.rename(os.path.join(self._dir, e["name"]), os.path.join(self._dir, "%s.quarantine-%s" % (e["name"], tag)))
        for p in (self._journal_path, self._head_path):
            if os.path.exists(p):
                os.rename(p, "%s.quarantine-%s" % (p, tag))
        _fsync_dir(self._dir)
        self._seen = {"seq": 0, "hash": _GENESIS}
        self.recovered = True

    def _load_or_recover(self) -> Dict[str, Any]:
        try:
            return self._load()
        except DurableStateError:
            if not self._recover_opt:
                raise
            self._quarantine()
            return self._load()

    def _observe(self, ld: Dict[str, Any]) -> None:
        last = ld["recs"][-1] if ld["recs"] else None
        if last and last["seq"] >= self._seen["seq"]:
            self._seen = {"seq": last["seq"], "hash": last["h"]}

    # ---- the lock: immutable numbered generation files (formal/tla/DurableLockGen.tla) -----------------------------------------
    def _lock_file(self, g: int) -> str:
        return os.path.join(self._dir, "state.lock.%d" % g)

    def _legacy_lock(self) -> str:
        return os.path.join(self._dir, "state.lock")

    @staticmethod
    def _read_body(path: str) -> Optional[Dict[str, Any]]:
        try:
            o = _loads(_read_text(path))
            if isinstance(o, list):
                o = {}  # a JSON array is an object to the reference: every field reads as absent
            if not isinstance(o, dict):
                return None
            b: Dict[str, Any] = {"st": "free" if o.get("st") == "free" else "held"}
            if _is_num(o.get("pid")):
                b["pid"] = o["pid"]
            for k in ("host", "nonce", "start", "ns", "boot"):
                if isinstance(o.get(k), str):
                    b[k] = o[k]
            if _safe_int(o.get("recovering")):
                b["recovering"] = int(o["recovering"])
            return b
        except Exception:  # noqa: BLE001
            return None

    def _top_lock(self):
        gens = _lock_gens(self._dir)
        g = max(gens) if gens else -1
        return (g, self._read_body(self._lock_file(g))) if g >= 1 else (0, None)

    def _holder_dead(self, b: Optional[Dict[str, Any]], legacy_age_ms: float) -> bool:
        if b is None:
            return legacy_age_ms > 1000  # an unreadable legacy file (torn by an old version) older than 1 s
        if b.get("host") != socket.gethostname() or not _is_num(b.get("pid")):
            return False  # another host: cannot judge, never break
        if b.get("ns") is not None and b["ns"] != self._my_ns:
            return False  # another PID namespace: cannot judge, never break
        if not _pid_alive(b["pid"]):
            return True
        if b.get("start"):
            cur = _proc_start_of(b["pid"])
            if cur is not None and cur != b["start"]:
                return True  # the pid was reused by a different process
        return False

    def _create_gen(self, g: int, body: Dict[str, Any]) -> bool:
        """Create generation g atomically with its body. False = somebody else created it first."""
        tmp = os.path.join(self._dir, "state.lock.tmp-%d-%s" % (os.getpid(), secrets.token_hex(6)))
        fd = open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.write(fd, js_json(dict(body, t=_now_ms())).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, self._lock_file(g))
            return True
        except FileExistsError:
            return False
        except OSError as e:
            raise DurableStateError("invalid", "the state directory's filesystem cannot create the lock atomically (link: %s)" % (errno_name(e))) from None
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _gc_locks(self, keep_from: int) -> None:
        try:
            for f in os.listdir(self._dir):
                m = _LOCK_ENTRY.fullmatch(f)
                if m:
                    if int(m.group(1)) < keep_from:
                        os.unlink(os.path.join(self._dir, f))
                elif f.startswith("state.lock.tmp-"):
                    m2 = re.match(r"state\.lock\.tmp-(\d+)-", f)
                    pid = int(m2.group(1)) if m2 else 0
                    if pid > 0 and not _pid_alive(pid):
                        os.unlink(os.path.join(self._dir, f))
        except OSError:
            pass  # best effort

    def _probe_links(self) -> None:
        """Fail closed at open time when this filesystem cannot give the lock its atomic hard-link semantics."""
        a = os.path.join(self._dir, "state.probe-%d-%s" % (os.getpid(), secrets.token_hex(6)))
        b = a + ".lnk"
        try:
            try:
                fd = open_private(a, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                os.write(fd, b"probe")
                os.close(fd)
                os.link(a, b)
                try:
                    os.link(a, b)
                    second = False
                except FileExistsError:
                    second = True
                except OSError:
                    second = False
                if not second or os.stat(a).st_nlink != 2:
                    raise RuntimeError("link(2) is not atomic/exclusive here")
            except (OSError, RuntimeError) as e:
                what = errno_name(e) if isinstance(e, OSError) else str(e)
                raise DurableStateError("link-unsupported", "the state directory's filesystem does not provide working hard links with exclusive-create semantics (%s); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE" % what) from None
        finally:
            for f in (a, b):
                try:
                    os.unlink(f)
                except OSError:
                    pass

    def _with_lock(self, fn: Callable[[], Any]) -> Any:
        with self._mutex:
            return self._with_lock_locked(fn)

    def _with_lock_locked(self, fn: Callable[[], Any]) -> Any:
        nonce = secrets.token_hex(12)
        must_fence = False
        deadline = _now_ms() + self._lock_timeout
        legacy_lock = self._legacy_lock()
        while True:
            top_g, top_body = self._top_lock()
            legacy_blocks = False
            if os.path.exists(legacy_lock):
                try:
                    age = _now_ms() - int(os.stat(legacy_lock).st_mtime * 1000)
                except OSError:
                    age = 0
                legacy_blocks = not self._holder_dead(self._read_body(legacy_lock), age)
            free = top_g == 0 or (top_body is not None and top_body.get("st") == "free")
            if not legacy_blocks and (free or self._holder_dead(top_body, 0)):
                # taking over a DEAD holder whose lock is marked `recovering`: carry the mark and cut + fence before loading
                recovering = None if free else (top_body or {}).get("recovering")
                body: Dict[str, Any] = {"st": "held", "pid": os.getpid(), "host": socket.gethostname(), "nonce": nonce, "boot": _BOOT_ID}
                if self._my_ns is not None:
                    body["ns"] = self._my_ns
                if self._my_start is not None:
                    body["start"] = self._my_start
                if recovering is not None:
                    body["recovering"] = recovering
                if self._create_gen(top_g + 1, body):
                    if self._top_lock()[0] != top_g + 1:
                        continue  # a stale creator's re-created generation is buried below the real top: not a lock
                    self._my_gen = top_g + 1
                    must_fence = recovering is not None
                    break
                continue  # lost the race for that generation: look again immediately
            if not (_now_ms() <= deadline):
                def desc(b: Optional[Dict[str, Any]]) -> str:
                    if b is None:
                        return "an unreadable holder record"
                    if not _is_num(b.get("pid")) or b.get("host") is None or not b.get("nonce"):
                        return "an incomplete holder record (pid=%s host=%s nonce=%s); release it with expected_holder='unreadable'" % (
                            js_json(b["pid"]) if b.get("pid") is not None else "?", b.get("host") or "?", b.get("nonce") or "?")
                    return "holder pid=%s host=%s nonce=%s%s" % (js_json(b["pid"]), b["host"], b["nonce"], " (another PID namespace)" if b.get("ns") and b["ns"] != self._my_ns else "")
                if legacy_blocks and (free or self._holder_dead(top_body, 0)):
                    raise DurableStateError("lock-timeout", "could not acquire the state lock in %s within %d ms; blocked by %s (legacy single-file lock of an older version; %s). If that holder is provably gone, an operator can release it with recover_durable_state(dir=, force=True, legacy_lock=True, expected_holder=) after confirming the holder is dead; see the durable-state docs" % (self._dir, self._lock_timeout, legacy_lock, desc(self._read_body(legacy_lock))))
                raise DurableStateError("lock-timeout", "could not acquire the state lock in %s within %d ms; blocked by %s (%s). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recover_durable_state(dir=, force=True, expected_holder=) after confirming the holder is dead; see the durable-state docs" % (self._dir, self._lock_timeout, self._lock_file(top_g), desc(top_body)))
            time.sleep((5 + random.randrange(15)) / 1000.0)
        self._held_nonce = nonce
        self._gc_locks(self._my_gen - 16)
        try:
            if must_fence:
                # the recovery we took over may have died before (or after) writing its fence: cut and fence now, under OUR generation
                _test_crash_point("takeover-after-lock")
                _write_fence(self._dir, self._my_gen - 1, lambda: _test_crash_point("takeover-after-fence-temp"))
            return fn()
        finally:
            self._held_nonce = None
            try:
                self._create_gen(self._my_gen + 1, {"st": "free"})  # release; a live holder is never superseded
                self._gc_locks(self._my_gen - 15)
            except Exception:  # noqa: BLE001
                pass  # the lock stays "held" by a process about to be judged dead or alive by its pid: still safe

    def _assert_lock_held(self, outcome: str = "nothing was written") -> None:
        """Immediately before EVERY rename: this handle's generation must still be the highest and must still name us."""
        g, body = self._top_lock()
        if self._held_nonce is None or g != self._my_gen or body is None or body.get("st") != "held" or body.get("nonce") != self._held_nonce:
            raise DurableStateError("lock-lost", "the state lock is no longer held by this writer (generation %d, highest %d %s); %s" % (self._my_gen, g, body["st"] if body else "unreadable", outcome))

    def _commit(self, ld: Dict[str, Any], key_: str, value_json: str) -> None:
        last = ld["recs"][-1] if ld["recs"] else None
        seq = (last["seq"] if last else 0) + 1
        prev = last["h"] if last else _GENESIS
        base = {"seq": seq, "prev": prev, "op": "set", "payload": "%s\n%s" % (key_, value_json), "ts": self._now(), "gen": self._my_gen}
        rec = dict(base, h=self._rec_hash(base))
        if self._key is not None:
            rec["mac"] = self._mac_of(rec["h"])
        allr = ld["recs"] + [rec]
        if len(allr) > self._compact_every:
            # compact: ONE checkpoint at the same seq the new record would have, chained from the current tail, carrying the full state
            nxt = dict(ld["state"])
            nxt[key_] = value_json
            cb = {"seq": seq, "prev": prev, "op": "checkpoint", "payload": js_json([[k, v] for k, v in sorted(nxt.items(), key=lambda kv: _u16key(kv[0]))]), "ts": self._now(), "gen": self._my_gen}
            cp = dict(cb, h=self._rec_hash(cb))
            if self._key is not None:
                cp["mac"] = self._mac_of(cp["h"])
            allr = [cp]
        tail = allr[-1]
        # journal first (atomic), head second (atomic): a crash between leaves the head one record behind (repaired by the next writer)
        _atomic_write(self._journal_path, "".join(js_json(r) + "\n" for r in allr), lambda: self._assert_lock_held())
        self._write_head(tail, "the journal record (seq %d) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)" % tail["seq"])
        self._seen = {"seq": tail["seq"], "hash": tail["h"]}

    def _write_head(self, tail: Dict[str, Any], outcome: str = "nothing was written") -> None:
        """Head write, stamped with this writer's generation and guarded by the same lock re-check as the journal."""
        head: Dict[str, Any] = {"seq": tail["seq"], "h": tail["h"], "gen": self._my_gen}
        if self._key is not None:
            head["mac"] = self._mac_of(self._head_msg(head["seq"], head["h"], head["gen"]))
        _atomic_write(self._head_path, js_json(head) + "\n", lambda: self._assert_lock_held(outcome))


def errno_name(e: BaseException) -> str:
    import errno
    n = getattr(e, "errno", None)
    return errno.errorcode.get(n, type(e).__name__) if n else type(e).__name__


class _MemoryDurableKv(MemoryAtomicKv):
    """In-memory store with the DurableState interface (get/set/update/keys sorted) and no durability."""

    def keys(self) -> list:
        return sorted(super().keys(), key=_u16key)

    def snapshot(self) -> dict:
        return {k: self.get(k) for k in super().keys()}


def create_memory_durable_kv() -> _MemoryDurableKv:
    """In-memory key/value store with the same semantics and no durability (tests / one process)."""
    return _MemoryDurableKv()


def open_durable_state(**opts: Any) -> DurableState:
    """Open (creating if needed) a durable state directory. Raises DurableStateError on corrupt / rolled-back state unless
    ``recover_from_corruption=True``. Options: dir, hmac_key (>= 32 bytes), recover_from_corruption, lock_timeout_ms (10000),
    compact_every (256), max_value_bytes (1 MiB), now (-> ms)."""
    return DurableState(**opts)
