#!/usr/bin/env bash
# mutmut-prepare.sh: the mutmut config + mutants every mutation job starts from (the stats job and each shard MUST end up with
# the same setup.cfg, or mutmut's config fingerprint differs and a shard re-collects the stats it downloaded).
#  - mutmut runs the tests from mutants/: the corpus they read sits next to them, and EVERY top-level test module (a test
#    file missing from also_copy never runs against the mutants: 57 were)
#  - the mutants are generated here, before any memory cap (libcst parsing the biggest modules hit MemoryError under it)
set -euo pipefail
python - <<'PY'
import glob, re
s = open("setup.cfg").read()
listed = set(re.findall(r"^\s+(\S+)$", s.split("also_copy=", 1)[1].split("do_not_mutate=", 1)[0], re.M))
extra = ["conformance"] + sorted(f for f in glob.glob("test_*.py") if f not in listed)
print("also_copy +", extra)
s = s.replace("also_copy=\n", "also_copy=\n" + "".join(f"    {f}\n" for f in extra), 1)
open("setup.cfg", "w").write(s)
PY
PCA_SCRIPTS="$(cd "$(dirname "$0")" && pwd)" python - <<'PY'
import os, sys
from multiprocessing import set_start_method
from mutmut.__main__ import create_mutants
sys.path.insert(0, os.environ["PCA_SCRIPTS"])
import mutmut_extra  # the statement / guard / decorated-function mutants mutmut itself never makes
mutmut_extra.install()
from mutmut.utils.file_utils import copy_also_copy_files, copy_src_dir, setup_source_paths
set_start_method("fork", force=True)  # importing mutmut already set a context
os.makedirs("mutants", exist_ok=True)
copy_src_dir(); copy_also_copy_files(); setup_source_paths()
print("pre-generated:", create_mutants(2))
PY
# every shipped source file, subdirectories included, must have mutants; atlas_pca/__init__.py alone is exempt while it only imports
python - <<'PY'
import ast, glob, os, sys
exempt = "atlas_pca/__init__.py"
if not all(isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.parse(open(exempt, encoding="utf-8").read()).body):
    sys.exit(exempt + " holds more than imports: it can no longer be exempt from mutation")
files = [f for f in glob.glob("atlas_pca/**/*.py", recursive=True) if f != exempt]
bad = [f for f in files if not os.path.exists("mutants/" + f) or "__mutmut_" not in open("mutants/" + f, encoding="utf-8").read()]
if bad or not files:
    sys.exit(f"source files with no mutants: {bad or 'no source files found'}")
print(f"mutation plan covers all {len(files)} source files")
PY
