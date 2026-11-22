"""Sandbox WebAssembly hosts: the in-process wasmtime core-module host (fuel, wall-clock deadline, memory cap, no ambient
authority) and the pinned-subprocess component host. Tests that need wasmtime-py skip, with the reason, when it is absent; CI
installs the `wasm` extra. The real component run is guarded by PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256."""
import hashlib
import os
import stat
import sys
import time

import pytest

from atlas_pca import sandbox as S
from atlas_pca import sandbox_wasm as W
from atlas_pca.pca import hash_canonical

try:
    import wasmtime  # noqa: F401
    HAVE_WASMTIME = True
except ImportError:
    HAVE_WASMTIME = False
IN_CI = bool(os.environ.get("CI"))  # in CI a missing engine or host is a failure, never a skip
needs_wasmtime = pytest.mark.skipif(not HAVE_WASMTIME and not IN_CI, reason="wasmtime-py not installed (pip install atlas-pca[wasm])")

REAL_HOST = os.environ.get("PCA_WASMTIME_HOST_BIN")
REAL_PIN = os.environ.get("PCA_WASMTIME_HOST_SHA256")
needs_real_host = pytest.mark.skipif(not (REAL_HOST and REAL_PIN) and not IN_CI, reason="set PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256 to run the real wasmtime host")


@pytest.mark.skipif(not IN_CI, reason="CI only")
def test_ci_has_engine_and_real_host():
    assert HAVE_WASMTIME, "CI must install wasmtime-py (pip install atlas-pca[wasm])"
    assert REAL_HOST and REAL_PIN, "CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256"


def _table(executors, verbs=("fetch",)):
    t = [0]
    log = S.ReceiptLog(now=lambda: t[0])
    table = S.HandleTable("wasi_no_ambient", log, executors, lambda: t[0])
    for v in verbs:
        op = {"verb": v, "resource": "r", "params": {"url": "https://example.com/a"}}
        res = {"allow": True, "operation": {"verb": v, "resource": "r", "params_digest": hash_canonical(op["params"]), "id": "op1"}}
        table.mint(res, op, {"uses": 5})
    return table, log


def _tool(**kw):
    return S.build_tool(dict({"calls": [{"handle": 1, "ptr": 0, "cap": 16}], "returns": "byte0"}, **kw))


FUEL = 1_000_000


def test_fuel_is_required():
    table, _ = _table({})
    for f in (None, 0, -1, True, 1.5, "9", 2 ** 53):
        assert W.run_core_module(table, _tool(), fuel=f) == {"ok": False, "reason": "bad_fuel"}
    assert W.run_component(table, "x", fuel=0, host="/nope") == {"ok": False, "reason": "bad_fuel"}


def test_module_size_and_malformed():
    table, _ = _table({})
    assert W.run_core_module(table, b"", fuel=FUEL)["reason"] == "module_size"
    assert W.run_core_module(table, _tool(), fuel=FUEL, max_module_bytes=10)["reason"] == "module_size"
    assert W.run_core_module(table, b"not wasm at all", fuel=FUEL)["reason"] == "malformed_module"
    assert W.run_core_module(table, b"\0asm\1\0\0\0\x01\x09\0", fuel=FUEL)["reason"] == "malformed_module"  # section overruns the module


def test_memory_limits_are_refused_before_anything_runs():
    table, _ = _table({})
    for mem in ({"min": 1, "max": None}, {"min": 1, "max": 257}, {"min": 300, "max": 300}):
        assert W.run_core_module(table, _tool(memory=mem), fuel=FUEL)["reason"] == "memory_limits", mem
    shared = bytearray(_tool())
    i = shared.index(bytes([1, 1, 1]), shared.index(b"\x05"))  # memory section: count 1, flag 1 (max), min 1, max 1
    shared[i + 1] = 3  # flag 3 = max + shared
    assert W.run_core_module(table, bytes(shared), fuel=FUEL)["reason"] == "memory_limits"
    shared[i + 1] = 5  # flag above 3 = memory64
    assert W.run_core_module(table, bytes(shared), fuel=FUEL)["reason"] == "memory_limits"
    assert W.memory_limits(_tool(memory={"min": 1, "max": 2})) == {"count": 1, "min": 1, "max": 2, "shared": False}
    assert W.memory_limits(b"\0asm\1\0\0\0") is None


@needs_wasmtime
def test_happy_path_writes_result_into_memory_and_logs_a_receipt():
    table, log = _table({"fetch": lambda op: bytes([42, 1, 2, 3])})
    assert W.run_core_module(table, _tool(), fuel=FUEL) == {"ok": True, "value": 42}
    assert [(e["outcome"], e["reason"]) for e in log.entries] == [("ok", "used")]
    assert S.verify_receipt_chain(log.entries)["ok"] is True


@needs_wasmtime
def test_probe_tool_reads_handle_count_and_verb():
    table, _ = _table({}, verbs=("fetch", "send"))
    assert W.run_core_module(table, S.build_probe_tool(), fuel=FUEL) == {"ok": True, "value": 2 * 256 + ord("f")}
    assert W.run_core_module(table, S.build_probe_tool(cap=3), fuel=FUEL) == {"ok": True, "value": 2 * 256 + 0}  # "fetch" > cap: -3 ignored, byte 0 of memory


@needs_wasmtime
def test_bad_window_spends_no_use_and_small_cap_is_refused():
    table, log = _table({"fetch": lambda op: b"abcd"})
    r = W.run_core_module(table, S.build_tool({"calls": [{"handle": 1, "ptr": 65530, "cap": 100}]}), fuel=FUEL)
    assert r == {"ok": True, "value": -4} and log.entries == []
    r = W.run_core_module(table, S.build_tool({"calls": [{"handle": 1, "ptr": 0, "cap": 2}]}), fuel=FUEL)
    assert r == {"ok": True, "value": -3}
    r = W.run_core_module(table, S.build_tool({"calls": [{"handle": 9, "ptr": 0, "cap": 8}]}), fuel=FUEL)
    assert r == {"ok": True, "value": -1}  # unknown handle
    # the unsigned 32-bit window check: ptr + len must not wrap
    r = W.run_core_module(table, S.build_tool({"calls": [{"handle": 1, "ptr": -8, "cap": 16}]}), fuel=FUEL)
    assert r == {"ok": True, "value": -4}


@needs_wasmtime
def test_result_over_max_result_bytes_is_out_too_small():
    table, _ = _table({"fetch": lambda op: b"x" * 10})
    assert W.run_core_module(table, _tool(returns="last"), fuel=FUEL, max_result_bytes=4) == {"ok": True, "value": -3}


@needs_wasmtime
def test_no_entry_and_non_i32_value():
    table, _ = _table({"fetch": lambda op: b"\x07"})
    assert W.run_core_module(table, _tool(), "missing", fuel=FUEL) == {"ok": False, "reason": "no_entry"}
    assert W.run_core_module(table, _tool(), "memory", fuel=FUEL) == {"ok": False, "reason": "no_entry"}  # exported, but a memory


@needs_wasmtime
def test_malformed_for_the_engine():
    table, _ = _table({})
    junk = b"\0asm\1\0\0\0" + bytes([1, 1, 0xFF])  # parses as a header + a type section the engine rejects
    assert W.run_core_module(table, junk, fuel=FUEL)["reason"] == "malformed_module"


@needs_wasmtime
@pytest.mark.parametrize("extra", [{"module": "wasi_snapshot_preview1", "name": "fd_write"}, {"module": "env", "name": "x"}, {"module": "pca:act", "name": "other"}])
def test_forbidden_imports_are_refused(extra):
    table, log = _table({"fetch": lambda op: b"\x01"})
    r = W.run_core_module(table, _tool(extraImports=[extra]), fuel=FUEL)
    assert r == {"ok": False, "reason": "ambient_import:%s.%s" % (extra["module"], extra["name"])} and log.entries == []


@needs_wasmtime
def test_infinite_loop_stops_on_fuel():
    table, _ = _table({"fetch": lambda op: b"\x01"})
    assert W.run_core_module(table, _tool(spin=True), fuel=50_000) == {"ok": False, "reason": "fuel_exhausted"}


@needs_wasmtime
def test_infinite_loop_stops_on_the_wall_clock_even_with_huge_fuel():
    table, _ = _table({"fetch": lambda op: b"\x01"})
    t0 = time.monotonic()
    assert W.run_core_module(table, _tool(spin=True), fuel=2 ** 52, timeout_ms=200) == {"ok": False, "reason": "timeout"}
    assert time.monotonic() - t0 < 10


def _grow_module(delta, mem_max):
    u, s = S._u, S._s
    body = [0] + S._i32c(delta) + [0x40, 0x00, 0x0B]  # memory.grow 0
    out = ([0, 0x61, 0x73, 0x6D, 1, 0, 0, 0] + S._section(1, S._vec([[0x60, 0, 1, 0x7F]])) + S._section(3, S._vec([[0]]))
           + S._section(5, S._vec([[1] + u(1) + u(mem_max)])) + S._section(7, S._vec([s("run") + [0, 0]])) + S._section(10, S._vec([u(len(body)) + body])))
    return bytes(out)


@needs_wasmtime
def test_runtime_growth_past_the_declared_maximum_is_stopped():
    table, _ = _table({})
    assert W.run_core_module(table, _grow_module(1, 2), fuel=FUEL) == {"ok": True, "value": 1}  # within the cap: the old size in pages
    assert W.run_core_module(table, _grow_module(5, 2), fuel=FUEL) == {"ok": True, "value": -1}  # past max: memory.grow fails
    # a cap lower than the declared module is a static refusal, so growth can never be asked for past the cap
    assert W.run_core_module(table, _grow_module(1, 2), fuel=FUEL, max_memory_pages=1)["reason"] == "memory_limits"


@needs_wasmtime
def test_egress_policy_admits_in_policy_and_refuses_out_of_policy():
    policy = S.EgressPolicy(lambda: 0)
    op_ok = {"verb": "fetch", "resource": "r", "params": {"url": "https://example.com/a"}}
    policy.admit({"allow": True, "operation": {"verb": "fetch", "resource": "r", "params_digest": hash_canonical(op_ok["params"]), "id": "o"}}, op_ok,
                 lambda op: {"method": "GET", "scheme": "https", "host": "example.com", "path": "/a"})

    def fetch(op):
        d = policy.claim({"method": "GET", "url": op["params"]["url"]})
        if not d["allow"]:
            raise PermissionError(d["reason"])
        return b"\x2a"

    t = [0]
    log = S.ReceiptLog(now=lambda: t[0])
    table = S.HandleTable("egress_default_deny", log, {"fetch": fetch}, lambda: t[0])
    for url in ("https://example.com/a", "https://evil.example/a"):
        op = {"verb": "fetch", "resource": "r", "params": {"url": url}}
        table.mint({"allow": True, "operation": {"verb": "fetch", "resource": "r", "params_digest": hash_canonical(op["params"]), "id": "o"}}, op)
    tool = lambda h: S.build_tool({"calls": [{"handle": h, "ptr": 0, "cap": 8}], "returns": "last"})  # noqa: E731
    assert W.run_core_module(table, tool(1), fuel=FUEL) == {"ok": True, "value": 1}  # one byte written
    assert W.run_core_module(table, tool(2), fuel=FUEL) == {"ok": True, "value": S.USE_ERR["executor_error"]}
    assert [e["outcome"] for e in log.entries] == ["ok", "error"]


# ------------------------------------------------------------------------------------------------------ component host: the pin
def _sha(b):
    return hashlib.sha256(b).hexdigest()


def test_pin_logic(tmp_path):
    table, _ = _table({})
    exe = tmp_path / "host"
    exe.write_bytes(b"#!/bin/sh\nexit 0\n")
    ok = lambda **k: W.run_component(table, "(component)", fuel=10, **k)["reason"]  # noqa: E731
    saved = {k: os.environ.pop(k, None) for k in ("PCA_WASMTIME_HOST", "PCA_WASMTIME_HOST_SHA256")}
    try:
        assert ok() == "host_missing"
        assert ok(host=str(tmp_path / "absent"), expected_sha256=_sha(b"x")) == "host_missing"
        assert ok(host=str(exe)) == "host_unpinned"
        assert ok(host=str(exe), expected_sha256="abc") == "host_unpinned"
        assert ok(host=str(exe), expected_sha256="0" * 64) == "host_hash_mismatch"
        assert ok(host=str(exe), expected_sha256=_sha(exe.read_bytes())) == "host_exit"  # matches: proceeds to spawn (and the no-op host exits)
        os.environ["PCA_WASMTIME_HOST"], os.environ["PCA_WASMTIME_HOST_SHA256"] = str(exe), _sha(exe.read_bytes())
        assert ok() == "host_exit"  # env config works the same
    finally:
        for k in ("PCA_WASMTIME_HOST", "PCA_WASMTIME_HOST_SHA256"):
            os.environ.pop(k, None)
            if saved[k] is not None:
                os.environ[k] = saved[k]


FAKE = """#!%s
import json, sys, time
mode = open(sys.argv[1]).read().strip()
def ask(m):
    print(json.dumps(m), flush=True)
    return json.loads(sys.stdin.readline())
if mode == "ok":
    n = ask({"op": "count"})["n"]
    v = ask({"op": "verb", "h": 1})
    bad = ask({"op": "verb", "h": 99})
    r = ask({"op": "invoke", "h": 1})
    e = ask({"op": "invoke", "h": 2})
    total = n * 1000 + len(v["ok"]) * 100 + sum(r["ok"]) + (0 if e.get("err") == -3 else 7) + (0 if bad.get("err") == -1 else 9)
    print(json.dumps({"done": total, "fuel_used": int(sys.argv[2]) // 2}), flush=True)
elif mode == "fail":
    print(json.dumps({"fail": "fuel_exhausted"}), flush=True)
elif mode == "garbage":
    print("not json", flush=True)
elif mode == "hang":
    time.sleep(60)
elif mode == "exit":
    pass
elif mode == "env":
    import os
    print(json.dumps({"done": len([k for k in os.environ if k in ("HOME", "PATH", "USER", "TMPDIR")])}), flush=True)
"""


def _fake(tmp_path):
    exe = tmp_path / "fakehost"
    exe.write_text(FAKE % sys.executable)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return str(exe), _sha(exe.read_bytes())


def test_protocol_against_a_fake_host(tmp_path):
    host, pin = _fake(tmp_path)
    table, log = _table({"fetch": lambda op: bytes([3, 4]), "send": lambda op: b"x" * 9}, verbs=("fetch", "send"))
    run = lambda mode, **k: W.run_component(table, mode, fuel=100, host=host, expected_sha256=pin, **k)  # noqa: E731
    assert run("ok", max_result_bytes=8) == {"ok": True, "value": 2000 + 500 + 7, "fuel_used": 50}
    assert [e["outcome"] for e in log.entries] == ["ok", "ok"]  # both uses spent; the oversized result is refused to the guest, not the table
    assert run("fail") == {"ok": False, "reason": "fuel_exhausted"}
    assert run("garbage") == {"ok": False, "reason": "host_protocol"}
    assert run("exit") == {"ok": False, "reason": "host_exit"}
    t0 = time.monotonic()
    assert run("hang", timeout_ms=300) == {"ok": False, "reason": "timeout"}
    assert time.monotonic() - t0 < 10
    assert run("env") == {"ok": True, "value": 0}  # an empty environment: no inherited secrets


def test_temp_dir_is_removed(tmp_path, monkeypatch):
    host, pin = _fake(tmp_path)
    import tempfile
    root = tmp_path / "tmproot"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    table, _ = _table({})
    W.run_component(table, "fail", fuel=5, host=host, expected_sha256=pin)
    assert list(root.iterdir()) == []


# ------------------------------------------------------------------------------------------- component host: the real binary
@needs_real_host
def test_real_host_reference_component():
    run = lambda table, wat, **k: W.run_component(table, wat, fuel=10_000_000, host=REAL_HOST, expected_sha256=REAL_PIN, **k)  # noqa: E731
    table, log = _table({"fetch": lambda op: bytes([42])})
    r = run(table, S.reference_component_wat())
    assert r["ok"] is True and r["value"] == 42 and [e["outcome"] for e in log.entries] == ["ok"]
    table, _ = _table({"fetch": lambda op: b"\x01"})
    r = W.run_component(table, S.reference_component_wat({"spin": True}), fuel=100_000, host=REAL_HOST, expected_sha256=REAL_PIN)
    assert r == {"ok": False, "reason": "fuel_exhausted"}
    r = run(table, S.reference_component_wat({"extraImport": "wasi:cli/environment@0.2.0"}))
    assert r["ok"] is False and r["reason"].startswith("ambient_import:")

    def refuse(op):
        raise PermissionError("egress denied")
    table, log = _table({"fetch": refuse})
    r = run(table, S.reference_component_wat())
    assert r["ok"] is True and r["value"] == S.USE_ERR["executor_error"] and [e["outcome"] for e in log.entries] == ["error"]
