"""Whole-output pins for mutation testing (the pca-java AuthorizePinnedTest scheme). Two kinds of group, each hashed and
compared with testdata/k05-pinned.tsv:

  fuzz:<mod>.<fn>  one function (or every method of one constructible class) defined in atlas_pca.<mod>, called with a
                   fixed matrix of junk arguments; the projected result or exception (type + message) of every call.
  oracle:<name>    every case of the shared TS-generated k05 oracles replayed through its Python twin, the WHOLE result pinned
                   (the diff tests compare the reference's projection only); authorize() results are captured in full.

The behaviour itself is held to the TypeScript reference by the diff / vector tests; these pins make any change to any
branch observable, so a mutant that changes an output dies. They run where the mutation job runs (Linux, CPython 3.12,
PYTHONHASHSEED=0 so set order is reproducible) and skip elsewhere. A new or changed group fails with
`PINNED <group> <hash>`: review the change, then copy the line into the file (tab separated)."""
import copy
import dataclasses
import hashlib
import importlib
import json
import math
import os
import pkgutil
import re
import signal
import sys
import threading
import time
import types

import pytest

import atlas_pca

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(HERE, "testdata", "k05-pinned.tsv")
ACTIVE = sys.platform.startswith("linux") and sys.version_info[:2] == (3, 12) and os.environ.get("PYTHONHASHSEED") == "0"
pytestmark = pytest.mark.skipif(not ACTIVE, reason="pins are recorded on Linux / CPython 3.12 / PYTHONHASHSEED=0 (the mutation job)")

# never fuzzed: web adapters and the HTTP server (they bind frameworks / sockets), the package root (re-exports)
# pq_backends: its outcomes depend on which backend an earlier test loaded (differed between the full and the solo run)
SKIP_MODULES = {"django", "fastapi", "server", "__init__", "pq_backends"}
SKIP_NAME = re.compile(r"mutmut|ǁ|^(serve|main|run_server)")


def _load_pins():
    if not os.path.exists(PINS):
        return {}
    out = {}
    with open(PINS, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line and not line.startswith("#"):
                g, h = line.split("\t")
                out[g] = h
    return out


_ADDR = re.compile(r"0x[0-9a-fA-F]+")
_MUT = re.compile(r"x_(\w+?)__mutmut_(?:orig|\d+)")
_ARITY = re.compile(r"[\w.<>]+\(\) (takes|missing|got)")


_TMP = re.compile(r"/tmp/pytest-of-[^/]+/pytest-\d+/[^/\s'\"]+")
_ROOTS = sorted({os.path.dirname(os.path.dirname(os.path.abspath(atlas_pca.__file__))), HERE}, key=len, reverse=True)


def _msg(s):
    """Text without what differs between a plain and a mutmut-trampolined run: addresses, function names in Python's own
    arity errors, the checkout / mutants / temporary directories."""
    for r in _ROOTS:
        s = s.replace(r, "<root>")
    return _ARITY.sub(r"f() \1", _MUT.sub(r"\1", _ADDR.sub("0x?", _TMP.sub("<tmp>", s))))


def P(v, depth=0):
    """A JSON-able, address-free projection of any value."""
    if depth > 8:
        return "<deep>"
    if v is None or isinstance(v, (bool, int, str)):
        return _msg(v) if isinstance(v, str) else v
    if isinstance(v, float):
        return repr(v) if (math.isnan(v) or math.isinf(v) or v == 0) else v
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"$b": bytes(v).hex()}
    if isinstance(v, dict):
        return {"$d": sorted(([json.dumps(P(k, depth + 1), sort_keys=True), P(x, depth + 1)] for k, x in v.items()), key=lambda kv: kv[0])}
    if isinstance(v, (list, tuple)):
        return [P(x, depth + 1) for x in v]
    if isinstance(v, (set, frozenset)):
        return {"$s": sorted(json.dumps(P(x, depth + 1), sort_keys=True) for x in v)}
    if isinstance(v, BaseException):
        return {"$e": type(v).__name__, "m": _msg(str(v)), "code": P(getattr(v, "code", None), depth + 1)}
    if isinstance(v, (types.FunctionType, types.MethodType, types.BuiltinFunctionType, type, types.ModuleType)) or callable(v) and not hasattr(v, "__dict__"):
        return "<callable>"
    if dataclasses.is_dataclass(v):
        return {"$t": type(v).__name__, "f": {f.name: P(getattr(v, f.name, None), depth + 1) for f in dataclasses.fields(v)}}
    if hasattr(v, "__dict__"):
        return {"$t": type(v).__name__, "f": {k: P(x, depth + 1) for k, x in sorted(vars(v).items()) if not callable(x) or hasattr(x, "__dict__")}}
    if hasattr(v, "__slots__"):
        return {"$t": type(v).__name__, "f": {k: P(getattr(v, k, None), depth + 1) for k in v.__slots__ if isinstance(k, str)}}
    return "<%s>" % type(v).__name__


class _Timeout(BaseException):  # not Exception: the SDK's fail-closed catches would turn it into a refusal row ("pack: timeout")
    pass


def _on_alarm(_sig, _frame):
    raise _Timeout("timeout")


_NONDET = []


def _call(fn, args, limit=0.5, runs=2):
    """Run fn(*args) `runs` times on fresh copies; the projected outcome, '<nondeterministic>' when the runs differ."""
    outs = []
    for _ in range(runs):
        r = _once(fn, args, limit)
        if r == ["timeout"]:
            r = _once(fn, args, limit * 10)  # a slow runner, not a hang: only a second timeout at 10x the limit counts
        outs.append(json.dumps(r, sort_keys=True))
    if len(set(outs)) == 1:
        return outs[0]
    _NONDET.append([o[:300] for o in outs])  # the two differing outcomes, shown by _check's failure text
    return '"<nondeterministic>"'


def _once(fn, args, limit):
    main = threading.current_thread() is threading.main_thread()
    a = copy.deepcopy(args)
    if main:
        signal.setitimer(signal.ITIMER_REAL, limit)
    try:
        r = ["ok", P(fn(*a))]
    except _Timeout:
        r = ["timeout"]
    except (KeyboardInterrupt, MemoryError, RecursionError):
        raise  # a crash is never a pinned outcome: under a mutant it must surface as a run error (conftest.py), not a kill
    except BaseException as e:  # noqa: BLE001 - the refusal (type and text) is what is pinned
        if main:
            signal.setitimer(signal.ITIMER_REAL, 0)  # disarm before serialising: P(e) runs in the except handler, where a fired ITIMER_REAL (wall-clock, so it trips under heavy parallel load) would escape uncaught
        r = ["raise", P(e)]
    finally:
        if main:
            signal.setitimer(signal.ITIMER_REAL, 0)
    return r


V = [None, True, False, 0, 1, -1, 2 ** 64, 1.5, -0.0, float("nan"), float("inf"), "", "x", "1", "a.b.c", "AAAA", "L1",
     "-----BEGIN CERTIFICATE-----\nAQI=\n-----END CERTIFICATE-----", b"", b"\x00\x01", bytes(64), [], [None], ["x", 1], {},
     {"v": 1}, {"v": 1, "kind": "x", "id": "x", "sig": "AAAA", "alg": "ed25519"}, [{}]]


def _arg_sets():
    n = len(V)
    out = [()] + [(v,) for v in V]
    for a, step in ((2, 1), (3, 2), (4, 4)):
        for i in range(0, n, step):
            out.append(tuple(V[(i + 7 * j) % n] for j in range(a)))
    return out


ARGS = _arg_sets()
METHOD_ARGS = [()] + [(v,) for v in V] + [(V[i], V[(i + 7) % len(V)]) for i in range(0, len(V), 2)]


class _Frozen:
    """Constant clocks, a scratch working directory and every atlas_pca module's globals restored afterwards (a fuzzed
    setter must not leak into later calls or tests)."""

    def __init__(self, tmp):
        self.tmp = tmp

    def __enter__(self):
        del _NONDET[:]
        self.saved_time = (time.time, time.time_ns, time.monotonic, time.monotonic_ns, time.perf_counter)
        time.time = lambda: 1_800_000_000.0
        time.time_ns = lambda: 1_800_000_000_000_000_000
        time.monotonic = lambda: 1000.0
        time.monotonic_ns = lambda: 1_000_000_000_000
        time.perf_counter = lambda: 1000.0
        self.cwd = os.getcwd()
        os.chdir(self.tmp)
        self.old = signal.signal(signal.SIGALRM, _on_alarm) if threading.current_thread() is threading.main_thread() else None
        self.globals = []
        for m in list(sys.modules.values()):
            if getattr(m, "__name__", "").startswith("atlas_pca"):
                d = vars(m)
                snap = {}
                for k, x in d.items():
                    if isinstance(x, dict):
                        snap[k] = (x, dict(x))
                    elif isinstance(x, list):
                        snap[k] = (x, list(x))
                    elif isinstance(x, set):
                        snap[k] = (x, set(x))
                self.globals.append((d, dict(d), snap))
        return self

    def __exit__(self, *_exc):
        (time.time, time.time_ns, time.monotonic, time.monotonic_ns, time.perf_counter) = self.saved_time
        os.chdir(self.cwd)
        if self.old is not None:
            signal.signal(signal.SIGALRM, self.old)
        for d, before, snap in self.globals:
            for k in [k for k in d if k not in before]:
                del d[k]
            d.update(before)
            for k, (obj, content) in snap.items():
                if isinstance(obj, dict):
                    obj.clear(); obj.update(content)
                elif isinstance(obj, list):
                    obj[:] = content
                else:
                    obj.clear(); obj.update(content)
        return False


def _modules():
    return sorted(m.name for m in pkgutil.iter_modules(atlas_pca.__path__) if m.name not in SKIP_MODULES)


def _own(mod):
    fns, classes = [], []
    for name, obj in sorted(vars(mod).items()):
        if SKIP_NAME.search(name) or getattr(obj, "__module__", None) != mod.__name__:
            continue
        if isinstance(obj, types.FunctionType):
            fns.append((name, obj))
        elif isinstance(obj, type) and not issubclass(obj, BaseException):
            classes.append((name, obj))
    return fns, classes


def _targets():
    out = []
    for m in _modules():
        fns, classes = _own(importlib.import_module("atlas_pca." + m))
        out += ["%s.%s" % (m, n) for n, _ in fns] + ["%s.%s" % (m, n) for n, _ in classes]
    return out


def _fuzz(target):
    """One function's (or one class's) outcomes over the junk matrix: a mutant re-runs only the groups that reach it."""
    modname, name = target.split(".", 1)
    obj = getattr(importlib.import_module("atlas_pca." + modname), name)
    rows = []
    if isinstance(obj, types.FunctionType):
        for args in ARGS:
            rows.append([len(args), _call(obj, args)])
            if '"timeout"' in rows[-1][1]:
                break  # a call that hangs on junk: the rest of its matrix would take minutes
        return rows
    cls, made = obj, None
    for args in METHOD_ARGS[:12]:
        try:
            cls(*copy.deepcopy(args))
        except BaseException as e:  # noqa: BLE001
            if isinstance(e, (KeyboardInterrupt, MemoryError, RecursionError)):
                raise
            rows.append(["init", json.dumps(P(e), sort_keys=True)])
            continue
        made = args
        break
    if made is None:
        return rows
    for mname in sorted(n for n in dir(cls) if not n.startswith("__") and not SKIP_NAME.search(n)):
        if not callable(getattr(cls, mname, None)):
            continue
        for margs in METHOD_ARGS:
            def call(*a, _m=mname):
                return getattr(cls(*copy.deepcopy(made)), _m)(*a)
            rows.append([mname, len(margs), _call(call, margs)])
            if '"timeout"' in rows[-1][2]:
                break
    return rows


def _digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def _check(group, rows):
    h = _digest(rows)
    want = _load_pins().get(group)
    if want != h:
        pytest.fail("PINNED\t%s\t%s  (%d rows; was %s)\nrows: %s\ndiffering runs: %s"
                    % (group, h, len(rows), want, json.dumps(rows, sort_keys=True), json.dumps(_NONDET)))


TARGETS = _targets() if ACTIVE else []  # importing every module needs the optional dependencies


@pytest.mark.parametrize("target", TARGETS)
def test_fuzz_pinned(target, tmp_path):
    with _Frozen(str(tmp_path)):
        rows = _fuzz(target)
    _check("fuzz:" + target, rows)


# mesh is not pinned: every mesh result (MeshVerdict ok/reason/hop, a reason string or None, a bool, the effective-authority
# map) is exactly what test_k05_mesh_diff already compares with the reference, and replaying its 16,431 cases cost ~11 min
# per mutant that reached it (shard 6 of 41916404655 ran out of time).
ORACLES = ["actionregistry", "actions", "approval", "argprov", "authorize", "caveatlang", "provgate", "sigstore", "undo"]
ORACLE_LIMIT = 300.0  # s per case: only for a hang. The slowest reference case takes ~2 s plain, far longer under mutmut's stats tracing


def _oracle_fns():
    out = []
    for name in ORACLES:
        out += [(name, fn) for fn in sorted(importlib.import_module("test_k05_%s_diff" % name).MAP)]
    return out


ORACLE_FNS = _oracle_fns() if ACTIVE else []


def _oracle_rows(name, fn):
    """One reference function's cases, each run ONCE (the reference is deterministic; the pin itself catches a flip). A group
    per function so a mutant re-runs only the groups that reach it; the first timeout fails at once (a hung mutant)."""
    import k05_oracle

    t = importlib.import_module("test_k05_%s_diff" % name)
    rows = []
    captured = []
    z = getattr(t, "Z", None)
    real = getattr(z, "authorize", None) if name == "authorize" else None
    if real is not None:
        def recording(*a, **k):
            r = real(*a, **k)
            captured.append(P(r))
            return r
        z.authorize = recording
    try:
        call = t.MAP[fn][0] if isinstance(t.MAP[fn], tuple) else t.MAP[fn]
        for c in t.CASES.get(fn, []):
            del captured[:]
            out = _call(call, tuple(k05_oracle.dec(c["args"])), limit=ORACLE_LIMIT, runs=1)
            if out == '["timeout"]':
                pytest.fail("oracle case %s %s ran over %s s (a hang)" % (fn, c["name"], ORACLE_LIMIT))
            rows.append([fn, c["name"], out, list(captured)])
    finally:
        if real is not None:
            z.authorize = real
    return rows


@pytest.mark.parametrize("name,fn", ORACLE_FNS)
def test_oracle_pinned(name, fn, tmp_path):
    with _Frozen(str(tmp_path)):
        rows = _oracle_rows(name, fn)
    if rows:
        _check("oracle:%s.%s" % (name, fn), rows)


def test_timeout_is_not_swallowed_by_a_fail_closed_catch():
    assert not issubclass(_Timeout, Exception)


def test_no_stale_pins():
    groups = {"fuzz:" + t for t in TARGETS} | {"oracle:%s.%s" % nf for nf in ORACLE_FNS}
    assert not (set(_load_pins()) - groups), sorted(set(_load_pins()) - groups)
