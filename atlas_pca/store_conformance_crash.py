"""Multi-process crash harness (port of the TypeScript reference, @atlasauth/pca-store-conformance, crash.ts). Several client PROCESSES
(each with several clients) run the windowed workload against the same backend and append their histories to per-process files; the
parent SIGKILLs a random client process every ``killEveryMs`` and starts a replacement under a new identity, so killed processes leave
PENDING operations. When the adapter has ``crash()``, the backend is crashed and restarted once mid-run. The parent waits for EVERY
writer to exit before reading the histories (a partial history can make a FALSE look unexplained)."""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

from .store_conformance_load import load_adapter
from .store_conformance_model import parse_history, prng
from .store_conformance_runner import clock, random_namespace

_PKG_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_crash(kind: str, o: dict) -> dict:
    """``o``: the workload options (``clients`` per process, ``durationMs``, ``windowMs``, ``spread``, ``values``, ``retentionMs``,
    ``opTimeoutMs``, ``namespace``, ``seed``) plus ``module`` (required), ``options``, ``processes`` (3), ``killEveryMs`` (400),
    ``backendCrash`` (true), ``dir``, ``workerCommand`` (default: this interpreter running the worker module)."""
    def g(k: str, d: Any) -> Any:
        return o[k] if o.get(k) is not None else d

    d = o.get("dir") or tempfile.mkdtemp(prefix="pcasc-hist-")
    duration_ms = g("durationMs", 3000)
    kill_every = g("killEveryMs", 400)
    seed = g("seed", random.getrandbits(31))
    rand = prng(seed)
    origin = clock()
    deadline = origin + duration_ms
    base = {"module": o["module"], "options": g("options", {}), "kind": kind, "clients": g("clients", 4), "namespace": g("namespace", random_namespace()),
            "windowMs": g("windowMs", 5), "spread": g("spread", 3), "values": g("values", 20), "retentionMs": g("retentionMs", 600_000),
            "opTimeoutMs": g("opTimeoutMs", 5000), "origin": origin, "deadline": deadline}
    env = dict(os.environ)
    env["PYTHONPATH"] = _PKG_PARENT + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    cmd = o.get("workerCommand") or [sys.executable, "-m", "atlas_pca.store_conformance_worker"]
    live: List[subprocess.Popen] = []
    every: List[subprocess.Popen] = []
    n = [0]

    def spawn() -> None:
        proc = "p%d" % n[0]
        cfg = dict(base, proc=proc, file=os.path.join(d, "h-%s.jsonl" % proc), seed=seed + 7919 * n[0])
        n[0] += 1
        ch = subprocess.Popen(list(cmd) + [json.dumps(cfg)], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        live.append(ch)
        every.append(ch)

    for _ in range(g("processes", 3)):
        spawn()
    control = load_adapter(o["module"], g("options", {})) if o.get("backendCrash") is not False else None
    kills = backend_crashes = 0
    half = origin + duration_ms / 2
    try:
        while kill_every > 0 and clock() + kill_every < deadline:
            time.sleep(kill_every / 1000.0)
            live[:] = [p for p in live if p.poll() is None]
            if live:
                live[rand(len(live))].kill()
                kills += 1
                spawn()
            crash = getattr(control, "crash", None)
            if callable(crash) and backend_crashes == 0 and clock() >= half:
                crash()
                restart = getattr(control, "restart", None)
                if callable(restart):
                    restart()
                backend_crashes += 1
    finally:
        for p in every:
            p.wait()
        td = getattr(control, "teardown", None)
        if callable(td):
            td()
    text = "\n".join(open(os.path.join(d, f), encoding="utf-8").read() for f in sorted(os.listdir(d)) if f.startswith("h-") and f.endswith(".jsonl"))
    h = parse_history(text)
    return {"ops": h["ops"], "errors": len([x for x in h["ops"] if x["res"] == "unknown"]), "kills": kills, "backendCrashes": backend_crashes,
            "torn": h["torn"], "pending": h["pending"], "processes": n[0]}


__all__ = ["run_crash"]
