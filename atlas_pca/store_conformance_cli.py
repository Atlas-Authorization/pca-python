"""The command line of the store conformance kit (port of the TypeScript reference, @atlasauth/pca-store-conformance, cli.ts):
``python -m atlas_pca.store_conformance --adapter ./my_adapter.py [options]``.
Exit codes: 0 pass, 1 a contract violation was found, 3 unresolved (no violation, but not every key could be decided), 2 usage / adapter error.

``--profile pca-state`` runs the store behind the real ``require_pca`` guard (see :mod:`atlas_pca.store_conformance_pca_state`)."""
from __future__ import annotations

import json
import re
import sys
from typing import Any, Callable, Dict, List, Optional

from .store_conformance_load import load_adapter
from .store_conformance_model import format_report, report_json
from .store_conformance_runner import ALL_TESTS, run_conformance

PCA_STATE_TESTS = ("claim-burst", "claim-concurrent", "claim-durability", "one-instance", "instances", "processes", "crash-after-claim", "retry-after-timeout")

USAGE = """pca-store-conformance --adapter <module|builtin:name> [options]

  --adapter <path>        module exporting a store adapter (default export, 'adapter' or 'createAdapter(options)')
                          or builtin:in-memory | builtin:durable-file | builtin:bad-* (reference adapters)
  --option k=v            passed to the adapter factory (repeatable)
  --tests a,b             subset of: %s (default all)
  --clients N             concurrent clients (default 16)
  --duration MS           concurrent run length (default 2000)
  --rounds N              same-key burst rounds (default 20)
  --revisit-keys N        retention run size (default 500)
  --processes N           crash test: client processes alive at once (default 3)
  --kill-every MS         crash test: SIGKILL one client process this often (default 400)
  --budget N              search states per key before it is UNRESOLVED (default 200000)
  --values N              advance tests: counter values are drawn from [0, N) (default 20)
  --seed N                workload PRNG seed, to reproduce a run (default random)
  --json                  print the report as JSON
  --profile pca-state     test the store behind requirePCA instead (a module exporting createPcaStateAdapter(options),
                          or builtin:in-memory | builtin:durable-file | builtin:bad-*); --tests then takes a subset of:
                          %s
                          (--rounds = race rounds, default 10; --clients = copies per round, default 16; --processes)

Exit: 0 pass, 1 violation found, 3 unresolved, 2 usage or adapter error.""" % (", ".join(ALL_TESTS), ", ".join(PCA_STATE_TESTS))

_DEC = re.compile(r"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")
_RADIX = re.compile(r"^0([xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$")
_JS_WS = " \t\n\r\v\f                 　﻿"


def _js_number(v: str) -> float:
    """JavaScript ``Number(v)`` for a string: trimmed, empty is 0, decimal / hex / octal / binary, ``Infinity``; anything else NaN."""
    t = v.strip(_JS_WS)
    if t == "":
        return 0.0
    if _DEC.match(t):
        return float(t)
    if _RADIX.match(t):
        return float(int(t, {"x": 16, "o": 8, "b": 2}[t[1].lower()]))
    return {"Infinity": float("inf"), "+Infinity": float("inf"), "-Infinity": float("-inf")}.get(t, float("nan"))


def _num(flag: str, v: Optional[str]) -> Any:
    n = float("nan") if v is None else _js_number(v)
    if v is None or n != n or n in (float("inf"), float("-inf")) or n < 0:
        raise ValueError("%s needs a non-negative number" % flag)
    return int(n) if n == int(n) else n


def parse_cli(argv: List[str]) -> dict:
    a: dict = {"options": {}, "json": False, "help": False, "conf": {}}
    raw_tests: Optional[List[str]] = None
    i = 0

    def nxt() -> Optional[str]:
        nonlocal i
        i += 1
        return argv[i] if i < len(argv) else None

    while i < len(argv):
        f = argv[i]
        if f == "--adapter":
            v = nxt()
            if v is not None:
                a["adapter"] = v
        elif f == "--option":
            kv = nxt() or ""
            eq = kv.find("=")
            if eq < 1:
                raise ValueError("--option needs k=v")
            a["options"][kv[:eq]] = kv[eq + 1:]
        elif f == "--tests":
            raw_tests = [x for x in (nxt() or "").split(",") if x]
        elif f == "--profile":
            p = nxt()
            if p != "pca-state":
                raise ValueError("--profile: unknown profile %s (known: pca-state)" % ("undefined" if p is None else p))
            a["profile"] = p
        elif f == "--clients":
            a["conf"]["clients"] = _num(f, nxt())
        elif f == "--duration":
            a["conf"]["durationMs"] = _num(f, nxt())
        elif f == "--rounds":
            a["conf"]["rounds"] = _num(f, nxt())
        elif f == "--revisit-keys":
            a["conf"]["revisitKeys"] = _num(f, nxt())
        elif f == "--processes":
            a["processes"] = _num(f, nxt())
        elif f == "--kill-every":
            a["killEveryMs"] = _num(f, nxt())
        elif f == "--budget":
            a["conf"]["budget"] = _num(f, nxt())
        elif f == "--values":
            n = _num(f, nxt())
            if not isinstance(n, int) or n < 1:
                raise ValueError("--values needs a positive integer")
            a["conf"]["values"] = n
        elif f == "--seed":
            n = _num(f, nxt())
            if not isinstance(n, int):
                raise ValueError("--seed needs a non-negative integer")
            a["conf"]["seed"] = n
        elif f == "--json":
            a["json"] = True
        elif f in ("-h", "--help"):
            a["help"] = True
        else:
            raise ValueError("unknown argument %s" % f)
        i += 1
    if raw_tests is not None:
        known = PCA_STATE_TESTS if a.get("profile") == "pca-state" else ALL_TESTS
        bad = [x for x in raw_tests if x not in known]
        if bad or not raw_tests:
            raise ValueError("--tests: unknown test(s) %s" % (", ".join(bad) or "(none given)"))
        if a.get("profile") == "pca-state":
            a["pcaStateTests"] = raw_tests
        else:
            a["conf"]["tests"] = raw_tests
    return a


def main(argv: List[str], print_: Callable[[str], None] = print, print_err: Optional[Callable[[str], None]] = None) -> int:
    """Runs the CLI; returns the exit code. ``print_`` / ``print_err`` are injectable for tests."""
    print_err = print_err or (lambda s: print(s, file=sys.stderr))
    try:
        args = parse_cli(list(argv))
    except ValueError as e:
        print_err("%s\n\n%s" % (e, USAGE))
        return 2
    if args["help"]:
        print_(USAGE)
        return 0
    if not args.get("adapter"):
        print_err("--adapter is required\n\n%s" % USAGE)
        return 2
    if args.get("profile") == "pca-state":
        from .store_conformance_pca_state import format_pca_state_report, load_pca_state_adapter, run_pca_state_conformance
        try:
            pa = load_pca_state_adapter(args["adapter"], args["options"])
        except Exception as e:  # noqa: BLE001
            print_err("cannot load adapter: %s" % e)
            return 2
        try:
            kw: Dict[str, Any] = {"tests": args.get("pcaStateTests"), "module": None if args["adapter"].startswith("builtin:") else args["adapter"],
                                  "module_options": args["options"]}
            if args["conf"].get("rounds") is not None:
                kw["rounds"] = int(args["conf"]["rounds"])
            if args.get("processes") is not None:
                kw["processes"] = int(args["processes"])
            r = run_pca_state_conformance(pa, **kw)
            print_(json.dumps(r) if args["json"] else format_pca_state_report(r))
            return 0 if r["status"] == "pass" else 1
        except Exception as e:  # noqa: BLE001
            print_err("conformance run failed: %s" % e)
            return 2
        finally:
            if pa.teardown:
                pa.teardown()
    try:
        adapter = load_adapter(args["adapter"], args["options"])
    except Exception as e:  # noqa: BLE001
        print_err("cannot load adapter: %s" % e)
        return 2
    try:
        crash = {"module": args["adapter"], "options": args["options"]}
        if args.get("processes") is not None:
            crash["processes"] = args["processes"]
        if args.get("killEveryMs") is not None:
            crash["killEveryMs"] = args["killEveryMs"]
        r = run_conformance(adapter, {**args["conf"], "crash": crash})
        print_(report_json(r) if args["json"] else format_report(r))
        return 0 if r["status"] == "pass" else 1 if r["status"] == "fail" else 3
    except Exception as e:  # noqa: BLE001
        print_err("conformance run failed: %s" % e)
        return 2
    finally:
        td = getattr(adapter, "teardown", None)
        if callable(td):
            td()


__all__ = ["USAGE", "main", "parse_cli"]
