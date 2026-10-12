#!/usr/bin/env python3
"""mutmut 3 results of one shard -> counts.json + survivors.json for mutation-shard-report.mjs.
Survivors are `survived` and `no tests` mutants; each record is one mutation site in the native-check-equivalents.mjs format:
crate python-pca, file atlas_pca/<module>.py, fn = the mutated function (Class.method for methods), line = the trimmed
original line, mutant = '<fn>: <first replacement line>', lineno = the line in the file (a hint).
   python3 mutmut-survivors.py <shard-glob-regex>   (run in the package root after `mutmut run`)"""
import json, re, subprocess, sys
from collections import Counter

sel = re.compile(sys.argv[1])
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
        continue
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
    # the diff may be relative to the function: keep the hint only when it really points at the text
    hint = lineno if lineno and lineno <= len(src) and src[lineno - 1].strip() == minus else None
    rec = {"crate": "python-pca", "file": path, "mutant": f"{fn}: {plus if plus is not None else '(line removed)'}", "line": minus, "fn": fn}
    if hint:
        rec["lineno"] = hint
    survivors.append(rec)
json.dump(dict(counts), open("counts.json", "w"))
json.dump(survivors, open("survivors.json", "w"), indent=1, ensure_ascii=False)
print(dict(counts), len(survivors), "survivor(s)")
