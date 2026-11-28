#!/usr/bin/env python3
"""`mutmut run` without the shard's clean-test run:  mutmut-run.py mutmut run --max-children 2 NAME...

mutmut 3.8.1 (__main__._run) runs, before any mutant, `runner.run_clean_tests(tests)`: the unmutated suite once more (22-28 min per shard
on this package, for ~40 min of fixed setup in all). The stats job has already run every test once under mutmut's own stats collection
(run_stats_collection fails on a non-zero exit), on the same commit and image, and the prepared mutants/ it ships the shards are the
ones that run was made against. With PCA_SKIP_CLEAN_TESTS=1 this wrapper makes run_clean_tests return 0 on both runner classes
(ForkServerRunner, ForkRunner); every mutant run (run_tests with a mutant name) and the forced-fail test are untouched.
Without the variable it is plain `mutmut run`. If mutmut's runner classes no longer have the method, it stops: the pin changed."""
import os, sys

sys.argv = sys.argv[1:]  # the command line keeps reading `mutmut run ...` (the memory sampler looks for it)
if os.environ.get("PCA_SKIP_CLEAN_TESTS") == "1":
    from mutmut.workers import isolation
    patched = []
    for name in ("ForkServerRunner", "ForkRunner"):
        cls = getattr(isolation, name, None)
        if cls is None or "run_clean_tests" not in vars(cls):
            sys.exit(f"mutmut-run.py: mutmut.workers.isolation.{name}.run_clean_tests not found (mutmut changed): update the wrapper")
        cls.run_clean_tests = lambda self, tests: (print("    clean tests skipped: the stats job ran the whole suite on this commit"), 0)[1]
        patched.append(name)
    print("mutmut-run.py: clean tests skipped on", ", ".join(patched), flush=True)
from mutmut.__main__ import cli
cli()
