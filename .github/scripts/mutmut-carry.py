#!/usr/bin/env python3
"""Targeted mutmut runs with carry-forward (the pca-java/pca-kotlin PIT-history scheme, for mutmut 3).

Every shard uploads mut-results-<k>/: results.json ({mutant name: final status} for EVERY mutant of the shard), fnhash.json
(a hash per mutated function, see fnhash) and meta.json (the mutmut version). A later run seeded with that artifact re-runs
only what can have changed, and carries every other result forward, so each shard still reports its COMPLETE mutant set and
the merge checks the ledger over the full picture:
  - every mutant whose earlier status is not a kill (survived, no tests, not checked, skipped, suspicious, ...): new kill
    tests may kill it now;
  - every mutant of a function whose source changed or is new (mutmut numbers the mutants of one function, so an edited
    function is re-run whole), and of every function of a module whose module-level code (constants, imports, class
    attributes) changed.
A result is carried only when the function is unchanged and the mutmut version is the same (the same function then yields
the same mutant names). Changes in OTHER functions are not followed, as in PIT; `full: true` runs everything.

  mutmut-carry.py fnhash                                     -> JSON {mutmut prefix | "<module>:<module>": sha256}
  mutmut-carry.py names K/M                                  -> every mutant name of shard K of M (full run)
  mutmut-carry.py select BASE_DIR K/M                        -> "FULL", or one mutmut name / glob per line (none = nothing
                                                                to run: report the baseline with `carry-only`)
  mutmut-carry.py carry-only BASE_DIR                        -> counts.json, survivors.json ([]), results.json from BASE_DIR
Library use: mutmut-survivors.py --carry (load_base, fnhash, changed_prefixes, carried_status).
Run in the package root (atlas_pca/ is the mutated source, setup.cfg [mutmut] source_paths)."""
import ast, glob, hashlib, json, os, re, sys, zlib
from collections import Counter

SRC = "atlas_pca"
# statuses that are a kill: carried forward unless the function changed. Everything else is re-run, including a segfault
# and a "run error" (mutmut-survivors.py: caught though no test decided it), so each run lists them afresh.
KILLED = {"killed", "caught by type check"}  # a timeout is a run error, re-run like one (never carried as a kill)


def _h(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fnhash():
    """{mutmut name prefix: hash of the function's source (decorators included)} for every top-level function and method
    of atlas_pca/, plus "<module>:<module>" = the hash of the module with every such function cut out (module-level code)."""
    out = {}
    for path in sorted(glob.glob(os.path.join(SRC, "**", "*.py"), recursive=True)):
        mod = path[:-3].replace(os.sep, ".")
        text = open(path, encoding="utf-8").read()
        lines = text.split("\n")
        tree = ast.parse(text)
        spans = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                spans.append((f"{mod}.x_{node.name}", node))
            elif isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        spans.append((f"{mod}.xǁ{node.name}ǁ{sub.name}", sub))
        rest = list(lines)
        for prefix, node in spans:
            first = min([node.lineno] + [d.lineno for d in node.decorator_list])
            out[prefix] = _h("\n".join(lines[first - 1:node.end_lineno]))
            for i in range(first - 1, node.end_lineno):
                rest[i] = None
        # the module-level code alone: functions cut out (not blanked), blank lines dropped, so an edit inside a function
        # (or a deleted function) does not count as a module-level change
        out[f"{mod}:<module>"] = _h("\n".join(l for l in rest if l is not None and l.strip()))
    return out


# SHARD LAYOUT "hash-v1": mutant n of function f belongs to shard (crc32(f) + n) % M (0-based). The old layout (n % 50) put the
# first mutant of every function in one shard: shard 6 of 50 ran 150-180 min, the median 80. A baseline made under another layout
# (or M) is unusable (load_base): its shard k holds other mutants.
LAYOUT = "hash-v1"


def shard_of(name, m):
    return (zlib.crc32(prefix_of(name).encode("utf-8")) + int(name.rsplit("__mutmut_", 1)[1])) % m


class ShardSel:
    """`.search(name)` like a compiled regex: is this mutant in shard k (0-based) of m?"""
    def __init__(self, k, m):
        self.k, self.m = k, m

    def search(self, name):
        return "__mutmut_" in name and shard_of(name, self.m) == self.k


def all_names():
    """Every mutant name of the generated mutants/ tree (mutmut's .meta files list them)."""
    out = []
    for f in glob.glob(os.path.join("mutants", "**", "*.meta"), recursive=True):
        out.extend(json.load(open(f, encoding="utf-8")).get("exit_code_by_key", {}))
    return out


def layout_id():
    return f"{LAYOUT}/{os.environ.get('PCA_SHARDS', '')}"


def prefix_of(name):
    """atlas_pca.pca.x_verify__mutmut_12 -> atlas_pca.pca.x_verify"""
    return re.sub(r"__mutmut_\d+$", "", name)


def module_of(prefix):
    return prefix.split(".xǁ")[0] if ".xǁ" in prefix else prefix.rsplit(".x_", 1)[0]


def changed_prefixes(base_hash, cur_hash):
    """The prefixes whose results cannot be carried: new or edited functions, and every function of a module whose
    module-level code changed (or that is new)."""
    bad_mods = {k.split(":")[0] for k, v in cur_hash.items() if k.endswith(":<module>") and base_hash.get(k) != v}
    return {p for p, v in cur_hash.items() if not p.endswith(":<module>") and (base_hash.get(p) != v or module_of(p) in bad_mods)}


def load_base(base):
    """(results, fnhash) of a usable baseline, else None (missing files or another mutmut version)."""
    try:
        res = json.load(open(os.path.join(base, "results.json"), encoding="utf-8"))
        bh = json.load(open(os.path.join(base, "fnhash.json"), encoding="utf-8"))
        meta = json.load(open(os.path.join(base, "meta.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return None
    from importlib.metadata import version
    if meta.get("layout") != layout_id():
        print(f"baseline shard layout {meta.get('layout')} != {layout_id()}: full run", file=sys.stderr)
        return None
    if meta.get("mutmut") != version("mutmut"):
        print(f"baseline mutmut {meta.get('mutmut')} != {version('mutmut')}: full run", file=sys.stderr)
        return None
    return res, bh


def carried_status(base_state, changed, name):
    """The status a mutant not re-run in this run carries forward from the baseline, or None (it should have run).
    `changed` = changed_prefixes(baseline fnhash, current fnhash)."""
    if base_state is None:
        return None
    st = base_state[0].get(name)
    if st is None or st not in KILLED or prefix_of(name) in changed:
        return None
    return st


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "fnhash":
        json.dump(fnhash(), sys.stdout, indent=0, sort_keys=True, ensure_ascii=False)
        return
    if cmd == "names":  # names K/M: every mutant name of shard K of M (a full run)
        k, m = (int(x) for x in args[0].split("/"))
        print("\n".join(sorted(n for n in all_names() if ShardSel(k - 1, m).search(n))))
        return
    base = args[0]
    state = load_base(base)
    if cmd == "select":
        k, m = (int(x) for x in args[1].split("/"))
        shard_re = ShardSel(k - 1, m)
        if state is None:
            print("FULL")
            return
        res, bh = state
        cur = fnhash()
        changed = changed_prefixes(bh, cur)
        out = []
        # earlier non-kills of this shard whose function still exists unchanged (a changed one is re-run whole below)
        for name, st in sorted(res.items()):
            if shard_re.search(name) and st not in KILLED and prefix_of(name) in cur and prefix_of(name) not in changed:
                out.append(name)
        print(f"targeted: {len(out)} earlier non-kill(s), {len(changed)} changed function(s)", file=sys.stderr)
        # every mutant of a changed function that falls in this shard (the names mutmut generated, so none is guessed)
        out.extend(sorted(n for n in all_names() if prefix_of(n) in changed and shard_re.search(n)))
        print("\n".join(out))
    elif cmd == "carry-only":
        # nothing to re-run in this shard: no earlier non-kill, no changed function. The baseline IS the result.
        if state is None:
            sys.exit("carry-only without a usable baseline")
        # (select printed nothing: no function changed. A mutant of a function deleted since is gone, not carried.)
        cur = fnhash()
        res = {n: st for n, st in state[0].items() if prefix_of(n) in cur}
        bad = [n for n, st in res.items() if st not in KILLED]
        if bad:
            sys.exit(f"carry-only but the baseline has {len(bad)} non-kill(s), e.g. {bad[0]}")
        json.dump(dict(Counter(res.values())), open("counts.json", "w"))
        json.dump([], open("survivors.json", "w"))
        json.dump([], open("run-errors.json", "w"))  # a carried kill was decided by a test (run errors are re-run)
        json.dump(res, open("results.json", "w"), indent=0, sort_keys=True, ensure_ascii=False)
        print(f"carried {len(res)} result(s): {dict(Counter(res.values()))}")
    else:
        sys.exit(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
