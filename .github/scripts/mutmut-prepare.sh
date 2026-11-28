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
extra = ["conformance"] + sorted(f for f in glob.glob("*.py") if f not in listed and f != "setup.py")  # every top-level module: the tests and the helpers they import
print("also_copy +", extra)
s = s.replace("also_copy=\n", "also_copy=\n" + "".join(f"    {f}\n" for f in extra), 1)
open("setup.cfg", "w").write(s)
PY
# --config-only: just the setup.cfg edit above (a shard that unpacks the stats job's prepared mutants/ needs the same config, nothing else)
[ "${1:-}" = --config-only ] && exit 0
# -u: mutmut prints each file as its worker starts it, so a run that dies names the file it was on
PCA_SCRIPTS="$(cd "$(dirname "$0")" && pwd)" python -u - <<'PY'
import glob, os, re, sys
from multiprocessing import set_start_method
from mutmut.__main__ import create_mutants
from mutmut.mutation import file_mutation as fm
sys.path.insert(0, os.environ["PCA_SCRIPTS"])
import mutmut_extra  # the statement / guard / decorated-function mutants mutmut itself never makes
import mutmut.__main__ as mutmut_main
own = (fm.deep_replace, fm.render_and_collect_line_spans)
mutmut_extra.install()
mine = (fm.deep_replace, fm.render_and_collect_line_spans)
# the path-sharing deep_replace and the recording render must give exactly what mutmut's own give (code and line index), and
# the chunked syntax check must pass that code and, with one def line broken (same length), fail at that line: every source file under 8 KB,
# with every class split into members (CHUNK_LINES 0) so that path is exercised too
small = sorted(f for f in glob.glob("atlas_pca/**/*.py", recursive=True) if os.path.getsize(f) < 8192)
chunk, mutmut_extra.CHUNK_LINES = mutmut_extra.CHUNK_LINES, 0
for f in small:
    src = open(f, encoding="utf-8").read()
    fm.deep_replace, fm.render_and_collect_line_spans = own
    want = fm.mutate_file_contents(f, src)
    fm.deep_replace, fm.render_and_collect_line_spans = mine
    got = fm.mutate_file_contents(f, src)
    if (got.code, got.line_span_by_function_name) != (want.code, want.line_span_by_function_name):
        sys.exit(f"mutmut_extra renders {f} differently from mutmut 3.8.1")
    mutmut_main.ast.parse(got.code)
    lines = got.code.split("\n")
    bad = max((i for i, x in enumerate(lines) if re.match(r"\s*(async\s+)?def \w+__mutmut_\d+\(", x)), default=None)  # a mutant copy's def line
    if bad is None:
        continue
    body = lines[bad].lstrip()
    lines[bad] = lines[bad][:len(lines[bad]) - len(body)] + "'" + " " * (len(body) - 1)  # an unterminated string, same length (the recorded layout still applies)
    try:
        mutmut_main.ast.parse("\n".join(lines))
        sys.exit(f"the chunked syntax check passed {f} with line {bad + 1} broken")
    except SyntaxError as e:
        if e.lineno != bad + 1:
            sys.exit(f"the chunked syntax check put the error broken in at line {bad + 1} of {f} at line {e.lineno}")
mutmut_extra.CHUNK_LINES = chunk
print(f"mutmut_extra: same mutants and line index as mutmut's, chunked syntax check right, on {len(small)} files", flush=True)
from mutmut.utils.file_utils import copy_also_copy_files, copy_src_dir, setup_source_paths
set_start_method("fork", force=True)  # importing mutmut already set a context
os.makedirs("mutants", exist_ok=True)
copy_src_dir(); copy_also_copy_files(); setup_source_paths()
# one worker: two forked libcst workers over the biggest modules exhausted the 16 GB runner, which then lost its runner ("shutdown signal")
print("pre-generated:", create_mutants(1))
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
