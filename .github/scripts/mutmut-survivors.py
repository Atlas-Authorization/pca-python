#!/usr/bin/env python3
"""mutmut 3 results of one shard -> counts.json + survivors.json for mutation-shard-report.mjs.
Survivors are `survived` and `no tests` mutants; each record is one mutation site in the native-check-equivalents.mjs format:
crate python-pca, file atlas_pca/<module>.py, fn = the mutated function (Class.method for methods), line = the trimmed
original line, mutant = '<fn>: <first replacement line>', lineno = the line in the file (a hint).
Also writes run-errors.json: the mutants mutmut counts as caught though no test decided them (see run_error_status), each a
site record + evidence; the merge fails on each one without a reason in mutation-run-errors.json.
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
counts, survivors, run_errors, timeouts = Counter(), [], [], 0
killed_names = []  # mutants a test killed in THIS run (not carried): candidates for killed-equivalents.json


def site(name):
    """One mutation site in the native-check-equivalents.mjs record format."""
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
    return rec


RUN_ERROR = "run error"
RUNERR_DIR = os.environ.get("PCA_RUNERR_DIR")


def run_error_status(name, status):
    """A mutant mutmut calls killed is a kill only if a test DECIDED it (conftest.py wrote <name>.decided: an ordinary
    failure). Killed with only a .crash record (MemoryError / RecursionError) or with none (pytest internal error, death
    outside a test), and every segfault / suspicious / timeout mutant (signal death, unknown exit, CPU limit), is a run error:
    not a kill."""
    if status == "timeout":  # a timeout is not a kill by itself: no test decided it (BRIEF "Timeouts are not kills")
        return RUN_ERROR
    if RUNERR_DIR is None or status not in ("killed", "segfault", "suspicious"):
        return status
    if status == "killed" and os.path.exists(os.path.join(RUNERR_DIR, name + ".decided")):
        return status
    return RUN_ERROR


def evidence(name, status):
    if status == "timeout":
        return "timeout: the CPU limit was exceeded before any test decided it"
    p = os.path.join(RUNERR_DIR, name + ".crash")
    if os.path.exists(p):
        return open(p, encoding="utf-8").read().strip().split("\n")[0]
    return "no test failed (signal death, pytest internal error or a crash outside a test)"


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
        results[name] = st  # a carried status is a kill (mutmut-carry KILLED): never a survivor or a run error
        counts[st] += 1
        continue
    raw_status, status = status, run_error_status(name, status)
    results[name] = status
    counts[status] += 1
    timeouts += raw_status == "timeout"
    if status == RUN_ERROR:
        run_errors.append(dict(site(name), evidence=evidence(name, raw_status)))
    elif status in ("survived", "no tests"):
        survivors.append(site(name))
    elif status == "killed":
        killed_names.append(name)


def ledger_entries():
    """The python-pca equivalents ledger (flagship file under $MONO + this repo's part file): the sites an equivalent entry names."""
    out = []
    for p in (os.path.join(os.environ.get("MONO", ""), "tools/pca-audit/native-mutation-equivalents.json"), "mutation-equivalents.part.json"):
        try:
            d = json.load(open(p, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out += [e for e in (d["equivalents"] if isinstance(d, dict) else d) if e.get("crate", "python-pca") == "python-pca"]
    return out


def killed_equivalents():
    """A ledgered equivalent that a test KILLED this run: the killer is nondeterministic (the equivalence proof says no test can
    tell the mutant from the original), so the merge reports it as a notice instead of a stale entry. Only mutants of a function
    that has a ledger entry are looked at (site() runs `mutmut show`)."""
    led = ledger_entries()
    fns = {(e["file"], e["fn"]) for e in led}
    out = []
    for name in killed_names:
        mod, _, rest = name.rpartition(".x")
        rest = re.sub(r"__mutmut_\d+$", "", rest)
        fn = ".".join(p for p in rest.split("ǁ") if p) if rest.startswith("ǁ") else rest[1:]
        if (mod.replace(".", "/") + ".py", fn) not in fns:
            continue
        rec = site(name)
        if any(e["file"] == rec["file"] and e["fn"] == rec["fn"] and e["mutant"] == rec["mutant"] and e["line"] == rec["line"]
               and e.get("occurrence") in (None, rec.get("occurrence")) for e in led):
            out.append(rec)
    return out
if uncarried:
    sys.exit(f"{len(uncarried)} mutant(s) of the shard were neither run nor carried, e.g. {uncarried[:3]}")
json.dump(dict(counts), open("counts.json", "w"))
json.dump(results, open("results.json", "w"), indent=0, sort_keys=True, ensure_ascii=False)
json.dump(survivors, open("survivors.json", "w"), indent=1, ensure_ascii=False)
json.dump(run_errors, open("run-errors.json", "w"), indent=1, ensure_ascii=False)
ke = killed_equivalents()
json.dump(ke, open("killed-equivalents.json", "w"), indent=1, ensure_ascii=False)
print(len(ke), "ledgered equivalent(s) killed this run")
print(dict(counts), len(survivors), "survivor(s),", len(run_errors), "run error(s), of them", timeouts, "timeout(s)")
