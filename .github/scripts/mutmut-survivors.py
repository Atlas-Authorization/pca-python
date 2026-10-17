#!/usr/bin/env python3
"""mutmut 3 results of one shard -> counts.json + survivors.json for mutation-shard-report.mjs.
Survivors are `survived` and `no tests` mutants; each record is one mutation site in the native-check-equivalents.mjs format:
crate python-pca, file atlas_pca/<module>.py, fn = the mutated function (Class.method for methods), line = the trimmed
original line, mutant = '<fn>: <first replacement line>', lineno = the line in the file (a hint).
Also writes results.json ({name: status} for every mutant of the shard: the next targeted run's baseline, see mutmut-carry.py).
   python3 mutmut-survivors.py <shard-glob-regex> [--carry BASE_DIR]   (run in the package root after `mutmut run`)
--carry (targeted run): a mutant of the shard this run did not check takes its baseline status (mutmut-carry.py's rule);
one that has none (it should have been selected) fails the report, so a targeted shard never reports a partial set."""
import json, os, re, subprocess, sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sel = re.compile(sys.argv[1])
carry_base = sys.argv[sys.argv.index("--carry") + 1] if "--carry" in sys.argv else None
if carry_base:
    import importlib
    carry = importlib.import_module("mutmut-carry")
    carry_state = carry.load_base(carry_base)
    if carry_state is None:
        sys.exit(f"--carry {carry_base}: no usable baseline")
    changed = carry.changed_prefixes(carry_state[1], carry.fnhash())
results, uncarried = {}, []
res = subprocess.run(["mutmut", "results", "--all", "true"], capture_output=True, text=True)
if res.returncode != 0:
    res = subprocess.run(["mutmut", "results"], capture_output=True, text=True, check=True)
counts, survivors = Counter(), []
for raw in res.stdout.splitlines():
    m = re.match(r"^\s*([\w.ǁ]+__mutmut_\d+):\s*(.+?)\s*$", raw)
    if not m or not sel.search(m.group(1)):
        continue
    name, status = m.group(1), m.group(2)
    if status == "not checked":
        if not carry_base:
            continue
        st = carry.carried_status(carry_state, changed, name)
        if st is None:
            uncarried.append(name)
            continue
        status = st
    results[name] = status
    counts[status] += 1
    if status not in ("survived", "no tests"):
        continue
    mod, _, rest = name.rpartition(".x")  # atlas_pca.pca.x_verify__mutmut_5 | atlas_pca.server.xǁCǁm__mutmut_2
    rest = re.sub(r"__mutmut_\d+$", "", rest)
    fn = ".".join(p for p in rest.split("ǁ") if p) if rest.startswith("ǁ") else rest[1:]
    path = mod.replace(".", "/") + ".py"
    diff = subprocess.run(["mutmut", "show", name], capture_output=True, text=True, check=True).stdout.splitlines()
    minus = plus = None
    lineno, cur = None, None
    for d in diff:
        h = re.match(r"^@@ -(\d+)", d)
        if h:
            cur = int(h.group(1))
            continue
        if d.startswith("---") or d.startswith("+++"):
            continue
        if d.startswith("-") and minus is None:
            minus, lineno = d[1:].strip(), cur
        elif d.startswith("+") and plus is None:
            plus = d[1:].strip()
        if cur is not None and not d.startswith("+"):
            cur += 1
    if minus is None:
        sys.exit(f"cannot read the diff of {name}")
    src = open(path, encoding="utf-8").read().split("\n")
    # mutmut diffs one function: its hunk lines count from the `def` line. Place the site in the file: the def of the
    # mutated function (inside its class for a method), then that relative line, else the first copy of the text below it.
    parts = fn.split(".")
    start = 0
    for part, kw in [(c, "class") for c in parts[:-1]] + [(parts[-1], "def")]:
        pat = re.compile(rf"^\s*(?:async\s+)?{kw}\s+{re.escape(part)}\b")
        start = next((i for i in range(start, len(src)) if pat.match(src[i])), start)
    hint = None
    for cand in ([start + lineno] if lineno else []) + [lineno or 0]:
        if 1 <= cand <= len(src) and src[cand - 1].strip() == minus:
            hint = cand
            break
    if hint is None:
        hint = next((i + 1 for i in range(start, len(src)) if src[i].strip() == minus), None)
    if hint is not None:
        rec_occ = [i + 1 for i, l in enumerate(src) if l.strip() == minus].index(hint) + 1
    rec = {"crate": "python-pca", "file": path, "mutant": f"{fn}: {plus if plus is not None else '(line removed)'}", "line": minus, "fn": fn,
           "name": name}  # the mutmut name (targeted re-runs select by it)
    if hint:
        rec["occurrence"], rec["lineno"] = rec_occ, hint
    survivors.append(rec)
if uncarried:
    sys.exit(f"{len(uncarried)} mutant(s) of the shard were neither run nor carried, e.g. {uncarried[:3]}")
json.dump(dict(counts), open("counts.json", "w"))
json.dump(results, open("results.json", "w"), indent=0, sort_keys=True, ensure_ascii=False)
json.dump(survivors, open("survivors.json", "w"), indent=1, ensure_ascii=False)
print(dict(counts), len(survivors), "survivor(s)")
