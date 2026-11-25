"""The ``pca-state`` profile (port of the reference, @atlasauth/pca-store-conformance, pca-state.ts): run the store behind the REAL
``require_pca`` guard with real signed PCActns and check the replay-state invariant: one action id (grant, leaf holder, counter) goes from
unconsumed to consumed at most once, however many copies arrive, on however many instances or processes, across crashes after the claim
and retries after a timeout.

A :class:`PcaStateAdapter` is ``name``, ``open()`` -> :class:`PcaStateHandle` (``store``: an :class:`atlas_pca.authorize.StateStore`, ``close()``),
optional ``restart()`` / ``crash()`` / ``teardown()`` and the capability flags ``durable`` / ``shared`` (both default true; declare false only for
a process-local store). Tests: claim-burst, claim-concurrent, claim-durability (the store's claim, through the claim contract), one-instance,
instances (K guards, each on its own handle, built with ``multi_instance=True``), processes (K child processes, needs the adapter module path),
crash-after-claim and retry-after-timeout. Reference adapters: ``builtin:in-memory``, ``builtin:durable-file`` (good) and ``builtin:bad-*``."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .agent import DEFAULT_RISK_POLICY, build_pcactn, delegate, generate_keypair, mint_grant, pca_headers
from .private_fs import mkdtemp_private, open_private
from .arg_provenance import create_provenance_recorder, principal_direct_provenance
from .authorize import AuthorizeOptions, ClaimResult, MemoryStateStore, SqliteStateStore, StateStore
from .pca import params_digest
from .server import require_pca
from .store_conformance import ConformanceReport, _race, run_state_store_conformance

AUDIENCE = "pca-store-conformance"
PCA_STATE_TESTS = ("claim-burst", "claim-concurrent", "claim-durability", "one-instance", "instances", "processes", "crash-after-claim", "retry-after-timeout")
_NODE = {"id": "n1", "verb": "read", "resource": "doc:1", "params_digest": params_digest({}), "reversibility_class": "reversible"}
_OP = {"verb": "read", "resource": "doc:1", "params": {}}
_CALM = {"semanticDistance": 0, "reversibility": 1, "blastRadius": 0, "taint": 0, "confidence": 1, "age": 0}
_PROV_SEED = hashlib.sha256(b"atlas-pca-conformance/pca-state/provenance").digest()


class PcaStateHandle:
    def __init__(self, store: Any, close: Optional[Callable[[], Any]] = None) -> None:
        self.store, self.close = store, close


class PcaStateAdapter:
    def __init__(self, name: str, open: Callable[[], PcaStateHandle], durable: bool = True, shared: bool = True,
                 restart: Optional[Callable[[], Any]] = None, crash: Optional[Callable[[], Any]] = None,
                 teardown: Optional[Callable[[], Any]] = None) -> None:
        self.name, self.open, self.durable, self.shared = name, open, durable, shared
        self.restart, self.crash, self.teardown = restart, crash, teardown


# ---- fixture and guard ------------------------------------------------------------------------------------------------------------

def make_fixture(n: int, now: Optional[int] = None) -> Dict[str, Any]:
    """A grant plus n pre-signed PCActns (counters 1..n) from one agent, with the provenance bundle: JSON, so child processes can share it.
    Throwaway keys, generated per call; nothing secret is in the result."""
    now = int(time.time() * 1000) if now is None else now
    principal, agent = generate_keypair(allow_insecure_signer=True), generate_keypair(allow_insecure_signer=True)
    env = {"predicates": [{"verb": "read", "resource": "doc:*"}],
           "caveats": [{"type": "expires", "at": now + 3_600_000}, {"type": "delegation_depth", "max": 2}],
           "agent_binding": {}, "risk_policy": DEFAULT_RISK_POLICY}
    grant = mint_grant(principal, principal.public, env, "store conformance")["grant"]
    task = delegate(grant, principal, agent.public, [{"type": "expires", "at": now + 3_600_000}])
    rec = create_provenance_recorder(mediator="pca-state-conformance", kid="k1", secret_key=_PROV_SEED)
    prov = principal_direct_provenance(rec, _OP)
    proofs = [pca_headers(build_pcactn(grant, [grant, task], [_NODE], "n1", i + 1, agent, AUDIENCE, params={}, now=now, ttl_ms=3_600_000),
                          provenance=prov) for i in range(n)]
    return {"grant": grant, "holder": agent.public, "headers": proofs, "provenance_pin": rec.pin}


def pca_state_guard(fx: Dict[str, Any], store: Any, multi_instance: bool = False) -> Callable[[int], Any]:
    """The guard under test: the real ``require_pca`` with the full default-deny profile, the store as the state store. Returns
    ``call(counter) -> PCAResult``. ``multi_instance=True`` refuses a store that only an in-process lock can serialise (raises)."""
    opts = AuthorizeOptions(state_store=store, is_revoked=lambda p, g: False,
                            context=lambda p: {"plan": [_NODE], "plan_authorized": True}, risk=lambda op, g, p: dict(_CALM),
                            provenance_mediators=[fx["provenance_pin"]], multi_instance=True if multi_instance else None)
    guard = require_pca(audience=AUDIENCE, resolve_grant=lambda ref: fx["grant"] if ref == fx["grant"]["id"] else None,
                        authorize=opts, operation=lambda h, b: dict(_OP))
    return lambda counter: guard(fx["headers"][counter - 1], None)


def outcome_of(r: Any) -> str:
    """admitted / denied as a replay (the counter check failed) / any other denial (fail closed, e.g. a store error)."""
    if r.ok:
        return "admitted"
    az = getattr(r, "authorization", None)
    # a store that raised is a guard error in the reference (no replay check); here it also marks the replay check, so tell it by its reason
    failed_store = az is not None and any("the replay store failed" in x for x in (getattr(az, "reasons", None) or ()))
    return "replay" if az is not None and (getattr(az, "checks", None) or {}).get("replay") == "fail" and not failed_store else "error"


def _safe(g: Callable[[int], Any], counter: int) -> str:
    try:
        return outcome_of(g(counter))
    except Exception:  # noqa: BLE001 - a guard that raises is a fail-closed error
        return "error"


# ---- tests ------------------------------------------------------------------------------------------------------------------------

def _with_handles(a: PcaStateAdapter, n: int, fn: Callable[[List[PcaStateHandle]], Any]) -> Any:
    hs = [a.open() for _ in range(n)]
    try:
        return fn(hs)
    finally:
        for h in hs:
            if h.close:
                h.close()


def _race_admitted(guards: List[Callable[[int], Any]], counter: int, copies: int) -> int:
    rs = _race(copies, lambda i: _safe(guards[i % len(guards)], counter))
    return sum(1 for r in rs if r == "admitted")


def _exactly_one(test: str, admitted: List[int], note: str = "") -> dict:
    return {"test": test, "status": "pass" if all(n == 1 for n in admitted) else "fail", "admitted": admitted, **({"note": note} if note else {})}


def _skip(test: str, note: str) -> dict:
    return {"test": test, "status": "skip", "note": note}


def _claim_tests(a: PcaStateAdapter, tests: List[str], threads: int, rounds: int) -> List[dict]:
    class _Claim:
        def __init__(self, h: PcaStateHandle) -> None:
            self.h = h

        def claim(self, key: str, counter: int) -> Any:
            r = self.h.store.claim(key, counter)
            return (bool(r.ok), r.last_counter)

        def close(self) -> None:
            if self.h.close:
                self.h.close()

    rep: ConformanceReport = run_state_store_conformance(lambda: _Claim(a.open()), durable=a.durable, shared=a.shared, crash=a.crash, restart=a.restart,
                                                         threads=threads, rounds=rounds, name=a.name)
    names = {"claim-burst": "claim-burst", "claim-concurrent": "claim-concurrent", "claim-durability": "claim-durability"}
    by = {r.test: r for r in rep.results}
    return [{"test": t, "status": by[t].status, **({"note": by[t].note} if by[t].note else {})} for t in tests if t in names and t in by]


def _one_instance(a: PcaStateAdapter, rounds: int, copies: int) -> dict:
    fx = make_fixture(rounds)

    def run(hs: List[PcaStateHandle]) -> dict:
        g = pca_state_guard(fx, hs[0].store)
        return _exactly_one("one-instance", [_race_admitted([g], r, copies) for r in range(1, rounds + 1)])

    return _with_handles(a, 1, run)


def _instances(a: PcaStateAdapter, rounds: int, copies: int, k: int) -> dict:
    if not a.shared:
        return _skip("instances", "the adapter declares shared=False (one instance only)")
    fx = make_fixture(rounds)

    def run(hs: List[PcaStateHandle]) -> dict:
        try:
            guards = [pca_state_guard(fx, h.store, multi_instance=True) for h in hs]
        except Exception as e:  # noqa: BLE001
            return {"test": "instances", "status": "fail", "note": "refused in multi-instance mode: %s" % e}
        return _exactly_one("instances", [_race_admitted(guards, r, copies) for r in range(1, rounds + 1)], "%d instances" % k)

    return _with_handles(a, k, run)


class _Hooked:
    """A store whose claim lands but the caller can be made to lose the answer or wait (delegates everything else)."""

    def __init__(self, st: Any, around: Callable[[Callable[[], Any]], Any]) -> None:
        self._st, self._around = st, around
        self.scope = getattr(st, "scope", None)

    def claim_budget(self, key: str, counter: int, before: Any, after: Any) -> Any:
        return self._around(lambda: self._st.claim_budget(key, counter, before, after))

    def claim(self, key: str, counter: int) -> Any:
        return self._around(lambda: self._st.claim(key, counter))

    def __getattr__(self, n: str) -> Any:
        return getattr(self._st, n)


def _retry_after_timeout(a: PcaStateAdapter) -> dict:
    fx = make_fixture(4)

    def run(hs: List[PcaStateHandle]) -> dict:
        other = hs[-1]
        lose = [True]

        def lossy(commit: Callable[[], Any]) -> Any:
            r = commit()
            if lose[0]:
                lose[0] = False
                raise RuntimeError("timeout (answer lost after commit)")
            return r

        first = _safe(pca_state_guard(fx, _Hooked(hs[0].store, lossy)), 1)
        retry = _safe(pca_state_guard(fx, other.store), 1)
        nxt = _safe(pca_state_guard(fx, other.store), 2)
        at_gate, release = threading.Event(), threading.Event()

        def slow(commit: Callable[[], Any]) -> Any:
            at_gate.set()
            release.wait(10)
            return commit()

        res: List[Any] = [None, None]
        t1 = threading.Thread(target=lambda: res.__setitem__(0, _safe(pca_state_guard(fx, _Hooked(hs[0].store, slow)), 3)))
        t1.start()
        at_gate.wait(10)
        t2 = threading.Thread(target=lambda: res.__setitem__(1, _safe(pca_state_guard(fx, other.store), 3)))
        t2.start()
        time.sleep(0.05)
        release.set()
        t1.join()
        t2.join()
        pair = sum(1 for r in res if r == "admitted")
        ok = first == "error" and retry == "replay" and nxt == "admitted" and pair == 1
        return {"test": "retry-after-timeout", "status": "pass" if ok else "fail",
                "admitted": [1 if first == "admitted" or retry == "admitted" else 0, pair],
                "note": "lost answer: first=%s, retry=%s, next counter=%s; in-flight retry: %d admitted of 2%s" % (
                    first, retry, nxt, pair, "" if a.shared else " (one instance: shared=False)")}

    return _with_handles(a, 2 if a.shared else 1, run)


def _run_worker(module: str, options: Dict[str, str], cfg: dict, timeout: float = 120) -> dict:
    full = dict(cfg, module=module, options=options)
    p = subprocess.Popen([sys.executable, "-m", "atlas_pca.store_conformance_pca_state", json.dumps(full)], stderr=subprocess.PIPE)
    try:
        _, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
    lines: List[dict] = []
    if os.path.exists(cfg["out"]):
        with open(cfg["out"], encoding="utf-8") as f:
            lines = [json.loads(x) for x in f.read().split("\n") if x]
    return {"admitted": sum(x["admitted"] for x in lines), "replays": sum(x["replays"] for x in lines), "returncode": p.returncode, "lines": lines}


def _crash_after_claim(a: PcaStateAdapter, module: Optional[str], options: Dict[str, str]) -> dict:
    if not a.durable:
        return _skip("crash-after-claim", "the adapter declares durable=False (state dies with the process)")
    fx = make_fixture(4)
    notes: List[str] = []
    h1 = a.open()
    first = _safe(pca_state_guard(fx, h1.store), 1)  # admitted on a handle that is then abandoned (no close)
    if a.crash:
        a.crash()
    if a.restart:
        a.restart()

    def after(hs: List[PcaStateHandle]) -> List[str]:
        g = pca_state_guard(fx, hs[0].store)
        return [_safe(g, 1), _safe(g, 2)]

    aft = _with_handles(a, 1, after)
    try:
        if h1.close:
            h1.close()
    except Exception:  # noqa: BLE001
        pass
    ok = first == "admitted" and aft[0] == "replay" and aft[1] == "admitted"
    notes.append("in process: admitted=%s, same proof after %s%s=%s, next counter=%s" % (
        first, "crash + " if a.crash else "", "restart" if a.restart else "re-open", aft[0], aft[1]))
    if module:
        d = mkdtemp_private("pcasc-pstate-crash-")
        fxf = os.path.join(d, "fixture.json")
        with os.fdopen(open_private(fxf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC), "w", encoding="utf-8") as f:
            json.dump(fx, f)
        base = {"fixture": fxf, "copies": 1, "instances": 1, "rounds": 1}
        killed = _run_worker(module, options, dict(base, mode="admit-then-die", out=os.path.join(d, "a.jsonl"), counter=3))
        if a.restart:
            a.restart()
        retried = _run_worker(module, options, dict(base, mode="race", out=os.path.join(d, "b.jsonl"), counter=3))
        fresh = _run_worker(module, options, dict(base, mode="race", out=os.path.join(d, "c.jsonl"), counter=4))
        p_ok = killed["returncode"] != 0 and killed["admitted"] == 1 and retried["admitted"] == 0 and retried["replays"] == 1 and fresh["admitted"] == 1
        ok = ok and p_ok
        notes.append("child process: killed after admission=%s, retry in a new process admitted %d, next counter admitted %d" % (
            killed["returncode"] != 0 and killed["admitted"] == 1, retried["admitted"], fresh["admitted"]))
    else:
        notes.append("process half skipped (needs the adapter module path)")
    return {"test": "crash-after-claim", "status": "pass" if ok else "fail", "note": "; ".join(notes)}


def _processes(a: PcaStateAdapter, module: Optional[str], options: Dict[str, str], rounds: int, copies: int, procs: int) -> dict:
    if not a.shared:
        return _skip("processes", "the adapter declares shared=False (one instance only)")
    if not module:
        return _skip("processes", "needs the adapter module path (the guards run in child processes)")
    fx = make_fixture(rounds)
    d = mkdtemp_private("pcasc-pstate-")
    fxf = os.path.join(d, "fixture.json")
    with os.fdopen(open_private(fxf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC), "w", encoding="utf-8") as f:
        json.dump(fx, f)
    round_ms, origin = 300, int(time.time() * 1000) + 3000  # time for every process to start and open its handles
    outs: List[Any] = [None] * procs

    def go(p: int) -> None:
        outs[p] = _run_worker(module, options, {"mode": "race", "fixture": fxf, "out": os.path.join(d, "p%d.jsonl" % p), "rounds": rounds,
                                                "origin": origin, "roundMs": round_ms, "copies": copies, "instances": 2})

    ts = [threading.Thread(target=go, args=(p,)) for p in range(procs)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    admitted = [sum(x["admitted"] for w in outs for x in w["lines"] if x["counter"] == r + 1) for r in range(rounds)]
    errors = sum(x["errors"] for w in outs for x in w["lines"])
    crashed = sum(1 for w in outs if w["returncode"] != 0 or len(w["lines"]) != rounds)
    r = _exactly_one("processes", admitted, "%d processes x 2 instances x %d copies per round; %d fail-closed errors%s" % (
        procs, copies, errors, "; %d worker(s) did not finish" % crashed if crashed else ""))
    return dict(r, status="fail") if crashed else r


def worker_main(cfg: dict) -> None:
    """One child process: open the adapter's handles, race the proofs at the shared round times, record the outcomes."""
    a = load_pca_state_adapter(cfg["module"], cfg["options"])
    with open(cfg["fixture"], encoding="utf-8") as f:
        fx = json.load(f)
    hs = [a.open() for _ in range(cfg["instances"])]
    guards = [pca_state_guard(fx, h.store, multi_instance=cfg["instances"] > 1 or cfg["mode"] == "race") for h in hs]

    def record(counter: int, rs: List[str]) -> None:
        with os.fdopen(open_private(cfg["out"], os.O_WRONLY | os.O_APPEND | os.O_CREAT), "a", encoding="utf-8") as f:
            f.write(json.dumps({"counter": counter, "admitted": rs.count("admitted"), "replays": rs.count("replay"), "errors": rs.count("error")}) + "\n")

    if cfg["mode"] == "admit-then-die":
        record(cfg["counter"], [_safe(guards[0], cfg["counter"])])
        os._exit(137)  # the instance dies after the claim committed and before any handler ran (no close, no flush of the backend)
    for r in range(cfg.get("rounds", 1)):
        counter = cfg.get("counter") or r + 1
        at = cfg.get("origin", int(time.time() * 1000)) + r * cfg.get("roundMs", 0)
        while int(time.time() * 1000) < at:
            time.sleep(0.005)
        rs = _race(cfg["copies"], lambda i: _safe(guards[i % len(guards)], counter))
        record(counter, rs)
    for h in hs:
        if h.close:
            h.close()
    if a.teardown:
        a.teardown()


# ---- runner -----------------------------------------------------------------------------------------------------------------------

def run_pca_state_conformance(a: PcaStateAdapter, tests: Optional[List[str]] = None, rounds: int = 10, copies: int = 16, instances: int = 4,
                              processes: int = 3, module: Optional[str] = None, module_options: Optional[Dict[str, str]] = None) -> dict:
    opts = module_options or {}
    probe = a.open()
    state_mode = type(probe.store).__name__
    if probe.close:
        probe.close()
    wanted = list(tests or PCA_STATE_TESTS)
    out: List[dict] = []
    claim = [t for t in wanted if t.startswith("claim-")]
    if claim:
        by = {r["test"]: r for r in _claim_tests(a, claim, copies, min(rounds, 5))}
        out += [by[t] for t in claim if t in by]
    for t in wanted:
        if t.startswith("claim-"):
            continue
        out.append(_one_instance(a, rounds, copies) if t == "one-instance" else _instances(a, rounds, copies, instances) if t == "instances"
                   else _processes(a, module, opts, rounds, copies, processes) if t == "processes"
                   else _crash_after_claim(a, module, opts) if t == "crash-after-claim" else _retry_after_timeout(a))
    statuses = [r["status"] for r in out]
    status = "fail" if "fail" in statuses else "pass"
    return {"adapter": a.name, "stateMode": state_mode, "status": status, "tests": out}


def format_pca_state_report(r: dict) -> str:
    lines = ["pca-store-conformance (pca-state): %s [%s] -> %s" % (r["adapter"], r["stateMode"], r["status"].upper())]
    for t in r["tests"]:
        adm = "admitted per round [%s]" % ",".join(str(n) for n in t["admitted"]) if t.get("admitted") else ""
        lines.append("  [%s] %s %s" % (t["status"].upper(), t["test"].ljust(20), "; ".join(x for x in (adm, t.get("note", "")) if x)))
    return "\n".join(lines)


# ---- reference adapters ------------------------------------------------------------------------------------------------------------

def in_memory_adapter() -> PcaStateAdapter:
    """GOOD for ONE process: MemoryStateStore (not durable, not shared: the multi-instance tests are skipped)."""
    st = MemoryStateStore()
    return PcaStateAdapter("in-memory (MemoryStateStore)", lambda: PcaStateHandle(st), durable=False, shared=False)


def durable_file_adapter(directory: Optional[str] = None) -> PcaStateAdapter:
    """GOOD: SqliteStateStore, one connection set per handle on the same file (crash-safe, multi-process)."""
    d = directory or mkdtemp_private("pcasc-pstate-durable-")
    path = os.path.join(d, "state.sqlite")
    return PcaStateAdapter("durable file (SqliteStateStore %s)" % d, lambda: PcaStateHandle(SqliteStateStore(path)), durable=True, shared=True)


class _RacyStore(StateStore):
    """BAD: claim_budget reads, yields, then writes: two handles both read "fresh" and both admit."""
    scope = "shared"

    def __init__(self, m: Dict[str, Any], lock: Optional[threading.Lock] = None) -> None:
        self.m, self.lock = m, lock

    def budget(self, key: str) -> Any:
        return (self.m.get(key) or {}).get("budget")

    def last(self, key: str) -> Optional[int]:
        return (self.m.get(key) or {}).get("last")

    def claim(self, key: str, counter: int) -> ClaimResult:
        return self.claim_budget(key, counter, None, None)

    def claim_budget(self, key: str, counter: int, before: Any, after: Any) -> ClaimResult:
        def step() -> ClaimResult:
            cur = self.m.get(key)
            time.sleep(0.001)
            if cur is not None and cur.get("last") is not None and not counter > cur["last"]:
                return ClaimResult(False, cur["last"], "replay")
            if (cur or {}).get("budget") != before:
                return ClaimResult(False, None, "conflict")
            self.m[key] = {"last": counter, "budget": after if after is not None else (cur or {}).get("budget")}
            return ClaimResult(True)
        if self.lock is None:
            return step()
        with self.lock:
            return step()

    def put_budget(self, key: str, budget: dict) -> None:
        self.m[key] = dict(self.m.get(key) or {}, budget=dict(budget))

    def pin(self, key: str) -> Optional[int]:
        return None

    def raise_pin(self, key: str, value: int) -> None:
        pass


def bad_read_then_write_adapter() -> PcaStateAdapter:
    m: Dict[str, Any] = {}
    return PcaStateAdapter("BAD claim as read, yield, write", lambda: PcaStateHandle(_RacyStore(m)), durable=False, shared=True)


def bad_local_lock_adapter() -> PcaStateAdapter:
    """BAD: a lock that only serialises ONE handle, passed off as shared."""
    m: Dict[str, Any] = {}
    return PcaStateAdapter("BAD per-handle lock passed off as shared", lambda: PcaStateHandle(_RacyStore(m, threading.Lock())), durable=False, shared=True)


def bad_volatile_adapter() -> PcaStateAdapter:
    """BAD: atomic and declared durable, but a restart forgets every claim (state in process memory)."""
    cur = [MemoryStateStore()]
    cur[0].scope = "shared"

    def restart() -> None:
        cur[0] = MemoryStateStore()
        cur[0].scope = "shared"

    return PcaStateAdapter("BAD volatile atomic store (claims lost on restart)", lambda: PcaStateHandle(cur[0]), durable=True, shared=True, restart=restart)


def bad_unshared_adapter() -> PcaStateAdapter:
    """BAD: every handle gets its own state while the adapter claims shared: instances do not see each other's claims."""
    def open_() -> PcaStateHandle:
        s = MemoryStateStore()
        s.scope = "shared"
        return PcaStateHandle(s)
    return PcaStateAdapter("BAD per-handle state passed off as shared", open_, durable=False, shared=True)


REFERENCE_ADAPTERS: Dict[str, Callable[[Dict[str, str]], PcaStateAdapter]] = {
    "in-memory": lambda o: in_memory_adapter(),
    "durable-file": lambda o: durable_file_adapter(o.get("dir")),
    "bad-read-then-write-claim": lambda o: bad_read_then_write_adapter(),
    "bad-local-lock": lambda o: bad_local_lock_adapter(),
    "bad-volatile": lambda o: bad_volatile_adapter(),
    "bad-unshared": lambda o: bad_unshared_adapter(),
}


def load_pca_state_adapter(spec: str, options: Optional[Dict[str, str]] = None) -> PcaStateAdapter:
    """``builtin:<name>`` or a module (path or importable name) exporting ``create_pca_state_adapter(options)`` / ``pca_state_adapter``."""
    options = options or {}
    if spec.startswith("builtin:"):
        name = spec[len("builtin:"):]
        if name not in REFERENCE_ADAPTERS:
            raise ValueError("unknown built-in pca-state adapter '%s' (known: %s)" % (name, ", ".join(REFERENCE_ADAPTERS)))
        return REFERENCE_ADAPTERS[name](options)
    from .store_conformance_load import _import
    mod = _import(spec)
    exported = next((getattr(mod, n) for n in ("create_pca_state_adapter", "pca_state_adapter") if callable(getattr(mod, n, None)) or hasattr(getattr(mod, n, None), "open")), None)
    a = exported(options) if callable(exported) and not hasattr(exported, "open") else exported
    if a is None or not callable(getattr(a, "open", None)) or not isinstance(getattr(a, "name", None), str):
        raise TypeError("%s: does not export a pca-state adapter" % spec)
    return a


__all__ = ["PcaStateAdapter", "PcaStateHandle", "PCA_STATE_TESTS", "REFERENCE_ADAPTERS", "format_pca_state_report", "load_pca_state_adapter",
           "make_fixture", "outcome_of", "pca_state_guard", "run_pca_state_conformance", "worker_main"]


if __name__ == "__main__":
    try:
        worker_main(json.loads(sys.argv[1]))
    except BaseException as e:  # noqa: BLE001
        sys.stderr.write("pca-state worker: %s\n" % e)
        sys.exit(1)
    sys.exit(0)
