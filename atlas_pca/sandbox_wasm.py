"""WebAssembly hosts for the sandbox handle table (opt-in: ``pip install atlas-pca[wasm]``, wasmtime-py).

``run_core_module`` runs a hand-built or compiled core module in-process under wasmtime with an instruction budget (fuel), a
wall-clock deadline (epoch interruption), a hard linear-memory cap and no ambient authority (no WASI is ever configured or linked: the
only imports are ``pca:act.{invoke,handle_count,handle_verb}``). ``run_component`` runs a component in the pinned reference
wasmtime host binary as a subprocess. Both serve the guest only from a ``HandleTable``; the table decides every use."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import sys

from ._native_lib import bundled
from .private_fs import mkdtemp_private, open_private
import queue
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Union

from .sandbox import ALLOWED_IMPORTS, IMPORT_MODULE, USE_ERR, HandleTable, ReceiptLog, verified_runtime_class

RunResult = Dict[str, Any]  # {"ok": True, "value": int} | {"ok": False, "reason": str}
_SAFE = 2 ** 53 - 1


def _fail(reason: str) -> RunResult:
    return {"ok": False, "reason": reason}


def _bad_fuel(fuel: Any) -> bool:
    return isinstance(fuel, bool) or not isinstance(fuel, int) or fuel < 1 or fuel > _SAFE


def memory_limits(b: bytes) -> Any:
    """Parse only the memory section: ``{count, min, max, shared}`` of the first memory, None = no memory section, "bad" = unparseable.
    A flag above 3 (memory64 and anything newer) reads as shared, so it is refused."""
    if len(b) < 8 or b[0] != 0 or b[1:4] != b"asm":
        return "bad"
    o = 8

    def leb() -> int:
        nonlocal o
        r = 0
        for shift in range(0, 35, 7):
            x = b[o]  # IndexError = eof
            o += 1
            r += (x & 0x7F) * 2 ** shift
            if x & 0x80 == 0:
                return r
        raise ValueError("leb")

    try:
        while o < len(b):
            sid = b[o]
            o += 1
            size = leb()
            end = o + size
            if end > len(b):
                return "bad"
            if sid == 5:
                count = leb()
                if count == 0:
                    return None
                flag = b[o]
                o += 1
                if flag > 3:
                    return {"count": count, "min": math.inf, "max": None, "shared": True}
                mn = leb()
                mx = leb() if flag & 1 else None
                return {"count": count, "min": mn, "max": mx, "shared": (flag & 2) != 0}
            o = end
        return None
    except (IndexError, ValueError):
        return "bad"


def run_core_module(table: HandleTable, wasm: bytes, entry: str = "run", *, fuel: Any = None, timeout_ms: int = 5000,
                    max_module_bytes: int = 1 << 20, max_memory_pages: int = 256, max_result_bytes: int = 1 << 20) -> RunResult:
    """Run `wasm`'s `entry` export. `fuel` (a positive safe integer) is required: a budget is a decision. Refuses to run (fail closed)
    if the engine cannot enforce fuel, the wall-clock deadline or the memory cap.
    A runtime memory.grow past the cap makes the guest see -1 (wasmtime's store limiter), exactly like the reference (a JS
    WebAssembly.Memory returns -1); the declared-maximum check (step 2) refuses the static cases as memory_limits."""
    if _bad_fuel(fuel):
        return _fail("bad_fuel")
    if not isinstance(wasm, (bytes, bytearray)) or len(wasm) == 0 or len(wasm) > max_module_bytes:
        return _fail("module_size")
    wasm = bytes(wasm)
    mem = memory_limits(wasm)
    if mem == "bad":
        return _fail("malformed_module")
    if mem and (mem["count"] > 1 or mem["max"] is None or mem["shared"] or mem["min"] > max_memory_pages or mem["max"] > max_memory_pages):
        return _fail("memory_limits")
    try:
        import wasmtime as w
    except ImportError:
        return _fail("wasmtime_unavailable")

    try:
        cfg = w.Config()
        cfg.consume_fuel = True
        cfg.epoch_interruption = True
        engine = w.Engine(cfg)
    except Exception:  # noqa: BLE001
        return _fail("limit_unenforceable:fuel")
    try:
        module = w.Module(engine, wasm)
    except Exception:  # noqa: BLE001
        return _fail("malformed_module")
    for i in module.imports:
        if i.module != IMPORT_MODULE or not isinstance(i.type, w.FuncType) or i.name not in ALLOWED_IMPORTS:
            return _fail("ambient_import:%s.%s" % (i.module, i.name))

    store = w.Store(engine)
    try:
        store.set_limits(memory_size=max_memory_pages * 65536)
    except Exception:  # noqa: BLE001
        return _fail("limit_unenforceable:memory")
    try:
        store.set_fuel(fuel)
    except Exception:  # noqa: BLE001
        return _fail("limit_unenforceable:fuel")
    try:
        store.set_epoch_deadline(1)
    except Exception:  # noqa: BLE001
        return _fail("limit_unenforceable:timeout")

    def window(caller: Any, ptr: int, ln: int) -> Any:
        m = caller.get("memory")
        if not isinstance(m, w.Memory):
            return None
        p, n = ptr & 0xFFFFFFFF, ln & 0xFFFFFFFF
        return (m, p, n) if p + n <= m.data_len(caller) else None

    def put(caller: Any, win: Any, data: bytes) -> None:
        if data:
            win[0].write(caller, data, win[1])

    def handle_count() -> int:
        return table.size

    def handle_verb(caller: Any, h: int, ptr: int, cap: int) -> int:
        verb = table.verb_of(h)
        if verb is None:
            return USE_ERR["unknown_handle"]
        enc = verb.encode("utf-8", "replace")
        win = window(caller, ptr, cap)
        if win is None:
            return USE_ERR["bad_memory"]
        if len(enc) > win[2]:
            return USE_ERR["out_too_small"]
        put(caller, win, enc)
        return len(enc)

    def invoke(caller: Any, h: int, ptr: int, cap: int) -> int:
        if window(caller, ptr, cap) is None:  # validate the output window before a use is spent
            return USE_ERR["bad_memory"]
        r = table.use(h)
        if not r["ok"]:
            return USE_ERR[r["reason"]]
        res = r["result"]
        if len(res) > max_result_bytes or len(res) > (cap & 0xFFFFFFFF):
            return USE_ERR["out_too_small"]
        put(caller, window(caller, ptr, cap), res)
        return len(res)

    i32 = w.ValType.i32
    linker = w.Linker(engine)  # no define_wasi: the guest has no ambient authority
    linker.define_func(IMPORT_MODULE, "handle_count", w.FuncType([], [i32()]), handle_count)
    linker.define_func(IMPORT_MODULE, "handle_verb", w.FuncType([i32(), i32(), i32()], [i32()]), handle_verb, access_caller=True)
    linker.define_func(IMPORT_MODULE, "invoke", w.FuncType([i32(), i32(), i32()], [i32()]), invoke, access_caller=True)

    def classify(e: BaseException, instantiating: bool) -> RunResult:
        if isinstance(e, w.Trap):
            code = e.trap_code
            if code == w.TrapCode.OUT_OF_FUEL:
                return _fail("fuel_exhausted")
            if code == w.TrapCode.INTERRUPT:
                return _fail("timeout")
            return _fail("trap:RuntimeError")
        msg = str(e).lower()
        if "all fuel consumed" in msg or "out of fuel" in msg:
            return _fail("fuel_exhausted")
        if "interrupt" in msg:
            return _fail("timeout")
        if "memory" in msg and ("minimum" in msg or "limit" in msg or "exceed" in msg):
            return _fail("memory_limits")
        return _fail("trap:LinkError" if instantiating else "trap:RuntimeError")

    timer = threading.Timer(max(timeout_ms, 0) / 1000.0, engine.increment_epoch)
    timer.daemon = True
    timer.start()
    try:
        try:
            instance = linker.instantiate(store, module)
        except BaseException as e:  # noqa: BLE001
            return classify(e, True)
        fn = instance.exports(store).get(entry)
        if not isinstance(fn, w.Func):
            return _fail("no_entry")
        try:
            v = fn(store)
        except BaseException as e:  # noqa: BLE001
            return classify(e, False)
        return {"ok": True, "value": v} if isinstance(v, (int, float)) and not isinstance(v, bool) else {"ok": True, "value": 0}
    finally:
        timer.cancel()


# ----------------------------------------------------------------------------------------------------------- component host
def run_component(table: HandleTable, component: Union[bytes, str], *, fuel: Any = None, timeout_ms: int = 10000,
                  host: Optional[str] = None, expected_sha256: Optional[str] = None, max_result_bytes: int = 1 << 20) -> RunResult:
    """Run a component (binary or WAT text) in the reference wasmtime host binary, as a subprocess, with an instruction budget.

    The binary path comes from configuration only (`host`, else env PCA_WASMTIME_HOST) and is pinned by SHA-256 (`expected_sha256`,
    else env PCA_WASMTIME_HOST_SHA256), checked on every call; never a PATH search. The verified bytes are copied into a fresh
    0700 temp dir and THAT copy is executed, so the file cannot change between the hash and the exec (no TOCTOU window). The child gets
    an empty environment, no shell and no stderr."""
    if _bad_fuel(fuel):
        return _fail("bad_fuel")
    # the host binary and its SHA-256 shipped in the platform wheel are the default (an explicit argument or environment variable overrides both)
    packaged = bundled("pca-wasmtime-host", "pca-wasmtime-host.exe")
    host = host or os.environ.get("PCA_WASMTIME_HOST") or packaged
    if not host:
        return _fail("host_missing")
    try:
        with open(host, "rb") as f:
            binary = f.read()
    except OSError:
        return _fail("host_missing")
    pin = expected_sha256 or os.environ.get("PCA_WASMTIME_HOST_SHA256")
    if pin is None and host == packaged:
        try:
            with open(os.path.join(os.path.dirname(packaged), "pca-wasmtime-host.sha256")) as f:
                pin = f.read().strip()
        except OSError:
            pass
    if not isinstance(pin, str) or len(pin) != 64 or any(c not in "0123456789abcdefABCDEF" for c in pin):
        return _fail("host_unpinned")
    if not hmac.compare_digest(hashlib.sha256(binary).hexdigest(), pin.lower()):
        return _fail("host_hash_mismatch")

    d = mkdtemp_private("pca-comp-")  # owner-only from creation, on Windows too
    child: Optional[subprocess.Popen] = None  # type: ignore[type-arg]
    try:
        exe = os.path.join(d, "host.exe" if sys.platform == "win32" else "host")
        with os.fdopen(open_private(exe, os.O_WRONLY | os.O_CREAT | os.O_EXCL), "wb") as f:
            f.write(binary)
        os.chmod(exe, stat.S_IRWXU)
        comp = os.path.join(d, "tool.component")
        with os.fdopen(open_private(comp, os.O_WRONLY | os.O_CREAT | os.O_EXCL), "wb") as f:
            f.write(component.encode("utf-8") if isinstance(component, str) else bytes(component))
        try:
            child = subprocess.Popen([exe, comp, str(fuel)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     env={}, shell=False, close_fds=True)
        except OSError:
            return _fail("host_unavailable")
        lines: "queue.Queue[Optional[bytes]]" = queue.Queue()

        def pump() -> None:
            assert child is not None and child.stdout is not None
            for ln in child.stdout:
                lines.put(ln)
            lines.put(None)

        threading.Thread(target=pump, daemon=True).start()
        deadline = time.monotonic() + max(timeout_ms, 0) / 1000.0

        def reply(v: Any) -> None:
            assert child is not None and child.stdin is not None
            child.stdin.write((json.dumps(v) + "\n").encode("utf-8"))
            child.stdin.flush()

        while True:
            try:
                line = lines.get(timeout=max(deadline - time.monotonic(), 0))
            except queue.Empty:
                return _fail("timeout")
            if line is None:
                return _fail("host_exit")
            try:
                m = json.loads(line)
                if not isinstance(m, dict):
                    raise ValueError("not an object")
            except ValueError:
                return _fail("host_protocol")
            if isinstance(m.get("fail"), str):
                return _fail(m["fail"])
            done = m.get("done")
            if isinstance(done, (int, float)) and not isinstance(done, bool):
                out: RunResult = {"ok": True, "value": done}
                if isinstance(m.get("fuel_used"), (int, float)):
                    out["fuel_used"] = m["fuel_used"]
                return out
            h = m.get("h") if isinstance(m.get("h"), int) and not isinstance(m.get("h"), bool) else 0
            try:
                op = m.get("op")
                if op == "count":
                    reply({"n": table.size})
                elif op == "verb":
                    v = table.verb_of(h)
                    reply({"err": USE_ERR["unknown_handle"]} if v is None else {"ok": v})
                elif op == "invoke":
                    r = table.use(h)
                    if not r["ok"]:
                        reply({"err": USE_ERR[r["reason"]]})
                    else:
                        reply({"err": USE_ERR["out_too_small"]} if len(r["result"]) > max_result_bytes else {"ok": list(r["result"])})
                else:
                    return _fail("host_protocol")
            except (BrokenPipeError, OSError):
                return _fail("host_exit")
    finally:
        if child is not None:
            try:
                child.kill()
            except OSError:
                pass
            for s in (child.stdin, child.stdout):
                try:
                    if s:
                        s.close()
                except OSError:
                    pass
            child.wait()
        shutil.rmtree(d, ignore_errors=True)


class Sandbox:
    """A WebAssembly host whose only authority is the handles minted into ``table``: the composition ``create_sandbox`` returns
    (the receipt log, the handle table and the two guest hosts over that one table). ``run`` is the in-process core-module host
    (instruction budget, wall-clock deadline, memory cap); ``run_component`` the pinned-subprocess component host."""

    def __init__(self, table: HandleTable, log: ReceiptLog, limits: Dict[str, Any]) -> None:
        self.table = table
        self.log = log
        self._limits = limits

    def run(self, wasm: bytes, entry: str = "run", *, fuel: Any = None, timeout_ms: int = 5000) -> RunResult:
        return run_core_module(self.table, wasm, entry, fuel=fuel, timeout_ms=timeout_ms, **self._limits)

    def run_component(self, component: Union[bytes, str], *, fuel: Any = None, timeout_ms: int = 10000, host: Optional[str] = None,
                      expected_sha256: Optional[str] = None) -> RunResult:
        return run_component(self.table, component, fuel=fuel, timeout_ms=timeout_ms, host=host, expected_sha256=expected_sha256,
                             max_result_bytes=self._limits["max_result_bytes"])


def create_sandbox(executors: Dict[str, Any], *, log: Optional[ReceiptLog] = None, now: Any = None, max_module_bytes: int = 1 << 20,
                   max_memory_pages: int = 256, max_result_bytes: int = 1 << 20, runtime_claim: Optional[Dict[str, Any]] = None) -> Sandbox:
    """The single entry point: a receipt log, a handle table whose runtime class is what ``runtime_claim`` (``{'claim', 'trust'}``)
    verifies to (capped at what a WASM host can prove; without a claim that verifies the class is ``none``: an operator's say-so
    does not count) and the guest hosts. ``executors`` maps a verb to ``fn(op) -> bytes``. A memory without a declared maximum, an
    import outside ``pca:act`` or a module over ``max_module_bytes`` is refused before anything runs."""
    log = log or ReceiptLog(now=now)
    proven = verified_runtime_class(runtime_claim["claim"], runtime_claim["trust"]) if runtime_claim else "none"
    cls = proven if proven in ("wasi_no_ambient", "egress_default_deny", "os_confined") else "none"
    table = HandleTable(cls, log, executors, now)
    return Sandbox(table, log, {"max_module_bytes": max_module_bytes, "max_memory_pages": max_memory_pages, "max_result_bytes": max_result_bytes})
