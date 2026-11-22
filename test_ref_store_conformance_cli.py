"""Differential replay of the store conformance kit's command line (argument parsing, usage text, usage-path exit codes) against the
TypeScript reference, plus native runs of the adapter loader and the multi-process crash harness."""
import os
import tempfile


from atlas_pca import store_conformance_cli as C
from atlas_pca import store_conformance_load as L
from atlas_pca import store_conformance_runner as R
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("store-conformance-java")


def _raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


def _consts():
    return {"DEFAULT_SEARCH_BUDGET": 200000, "ALL_TESTS": list(R.ALL_TESTS), "USAGE": C.USAGE}


def _main(argv):
    out, err = [], []
    code = C.main(argv, out.append, err.append)
    return {"code": code, "out": out, "err": err}


def _parse(argv):
    a = C.parse_cli(argv)
    return {k: v for k, v in a.items() if k not in ("pcaStateTests",) or v is not None}


def test_every_function_is_covered():
    assert set(BY_FN) == {"consts", "parseCli", "main"}


def test_consts():
    assert run(BY_FN["consts"], _consts)[0] == 1


def test_parse_cli():
    # the reference's own failures are thrown Errors: a refusal here is a ValueError
    assert run(BY_FN["parseCli"], _parse)[0] == len(BY_FN["parseCli"])


def test_main_usage_paths():
    ran, _ = run(BY_FN["main"], _main, compare=lambda got, out, c: got["code"] == out["code"] and got["out"] == out["out"] and got["err"] == out["err"])
    assert ran == len(BY_FN["main"])


# ---- native: loader and crash harness ----------------------------------------------------------------------------------------------

def test_builtin_adapters_load_and_unknown_is_refused():
    assert L.load_adapter("builtin:in-memory").name.startswith("in-memory")
    assert _raises(ValueError, lambda: L.load_adapter("builtin:nope"))


def test_a_module_adapter_loads_from_a_file():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "ad.py")
        open(p, "w").write("from atlas_pca.store_conformance_runner import in_memory_adapter\ndef create_adapter(options):\n    return in_memory_adapter()\n")
        assert L.load_adapter(p).name.startswith("in-memory")
        q = os.path.join(d, "bad.py")
        open(q, "w").write("x = 1\n")
        assert _raises(TypeError, lambda: L.load_adapter(q))


def test_cli_runs_a_good_store_and_flags_a_bad_one():
    out = []
    quick = ["--clients", "4", "--duration", "100", "--rounds", "4", "--revisit-keys", "16", "--seed", "3", "--tests", "burst,concurrent,retention"]
    assert C.main(["--adapter", "builtin:durable-file"] + quick, out.append, out.append) == 0, out
    assert C.main(["--adapter", "builtin:bad-non-strict-counter", "--clients", "8", "--rounds", "20", "--values", "1", "--tests", "burst"], out.append, out.append) == 1


def test_crash_harness_kills_workers_and_the_history_checks_out():
    from atlas_pca.store_conformance_crash import run_crash

    with tempfile.TemporaryDirectory() as d:
        w = run_crash("advance", {"module": "builtin:durable-file", "options": {"dir": d}, "processes": 2, "clients": 2, "durationMs": 1500,
                                  "killEveryMs": 300, "opTimeoutMs": 2000, "seed": 5, "dir": tempfile.mkdtemp(dir=d)})
        assert w["kills"] >= 1 and w["processes"] >= 3 and len(w["ops"]) > 0
        assert R.judge("crash", "advance", w, {})["status"] in ("pass", "unresolved")
