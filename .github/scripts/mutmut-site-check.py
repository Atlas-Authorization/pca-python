#!/usr/bin/env python3
"""Every function and every guard of atlas_pca has a mutant (run in the package root after the mutants are generated).

Reads the source (ast) and the generated mutants/ (each function's __mutmut_orig copy and its __mutmut_<n> copies), and fails
when:
  - a function or method has no mutant at all (skipped code would otherwise hide: mutmut silently skipped decorated ones);
  - an `if`/`elif` test has no mutant touching it;
  - a `raise`, an expression-statement call, a `continue` or a `break` has no mutant that replaces it with `pass`.
Then a built-in negative control: it drops the mutants of one real guard and requires the check to report exactly that site.
  python3 mutmut-site-check.py [--json OUT]   -> counts on stdout; exit 1 with the list of gaps"""
import ast, glob, json, re, sys
from collections import defaultdict

SRC = "atlas_pca"
EXEMPT_FILES = {"atlas_pca/__init__.py"}  # imports only (mutmut-prepare.sh enforces that)
NEVER = {"__getattribute__", "__setattr__", "__new__"}  # mutmut never mutates these (file_mutation.NEVER_MUTATE_FUNCTION_NAMES)
PASS = re.compile(r"(^|:)\s*pass\s*(#.*)?$")  # a `pass` statement, alone or after `if x:` (not "passport", not a comment)
COPY = re.compile(r"^(x_\w+|xǁ\w+ǁ\w+)__mutmut_(orig|\d+)$")


def mangle(name, cls):
    return f"xǁ{cls}ǁ{name}" if cls else f"x_{name}"


def copies(path):
    """{mangled: {"orig": [lines], n: [lines]}} from the mutated file (lines from the def line to the end of the copy)."""
    text = open("mutants/" + path, encoding="utf-8").read()
    lines = text.split("\n")
    out = defaultdict(dict)

    def take(body):
        for n in body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                m = COPY.match(n.name)
                if m:
                    out[m.group(1)][m.group(2)] = lines[n.lineno - 1:n.end_lineno]
            elif isinstance(n, ast.ClassDef):
                take(n.body)

    take(ast.parse(text).body)
    return out


def changed(orig, mut):
    """The orig-relative line range a mutant changed, and its replacement lines (one site per mutant)."""
    p = 1  # line 0 is the def line: it differs by the copy's name only
    while p < min(len(orig), len(mut)) and orig[p] == mut[p]:
        p += 1
    s = 0
    while s < min(len(orig), len(mut)) - p and orig[-1 - s] == mut[-1 - s]:
        s += 1
    return p, len(orig) - s, mut[p:len(mut) - s]


def sites(fn):
    """(kind, first, last) source lines of each guard site in a function (nested functions included: they are in its copies)."""
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.If):
            out.append(("if", n.test.lineno, n.test.end_lineno))
        elif isinstance(n, (ast.Raise, ast.Continue, ast.Break)) or (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)):
            out.append((type(n).__name__.lower() if not isinstance(n, ast.Expr) else "call", n.lineno, n.end_lineno))
    return out


def check(drop=frozenset()):
    gaps, nfun, nsite, nmut = [], 0, 0, 0
    for path in sorted(glob.glob(SRC + "/**/*.py", recursive=True)):
        if path in EXEMPT_FILES:
            continue
        cps = copies(path)
        tree = ast.parse(open(path, encoding="utf-8").read())
        funcs = [(n, None) for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        funcs += [(m, c.name) for c in tree.body if isinstance(c, ast.ClassDef)
                  for m in c.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for fn, cls in funcs:
            if fn.name in NEVER:
                continue
            nfun += 1
            key = mangle(fn.name, cls)
            muts = {k: v for k, v in cps.get(key, {}).items() if k != "orig" and f"{key}__mutmut_{k}" not in drop}
            where = f"{path}:{fn.lineno} {(cls + '.') if cls else ''}{fn.name}"
            if not muts:
                gaps.append(f"{where}: no mutant at all")
                continue
            nmut += len(muts)
            orig = cps[key]["orig"]
            spans = [changed(orig, m) for m in muts.values()]
            for kind, a, b in sites(fn):
                nsite += 1
                lo, hi = a - fn.lineno, b - fn.lineno + 1  # orig-relative [lo, hi): the copies start at the def line
                if kind == "if":
                    ok = any(p < hi and e > lo for p, e, _ in spans)
                else:
                    # `pass` in place of the statement (also inside a one-line `if x: raise ...`)
                    ok = any(lo <= p < e <= hi and any(PASS.search(x) for x in new) and not any(PASS.search(x) for x in orig[p:e])
                             for p, e, new in spans)
                if not ok:
                    gaps.append(f"{path}:{a} in {fn.name}: {kind} has no {'mutant' if kind == 'if' else 'removal mutant'}")
    return gaps, nfun, nsite, nmut


def control():
    """Drop every mutant touching the first `if e: return e` guard found and require exactly that gap."""
    for path in sorted(glob.glob(SRC + "/**/*.py", recursive=True)):
        if path in EXEMPT_FILES:
            continue
        cps = copies(path)
        for cls in [None] + [c for c in ast.parse(open(path, encoding="utf-8").read()).body if isinstance(c, ast.ClassDef)]:
            body = ast.parse(open(path, encoding="utf-8").read()).body if cls is None else cls.body
            for fn in [n for n in body if isinstance(n, ast.FunctionDef)]:
                for n in ast.walk(fn):
                    if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and len(n.body) == 1 \
                            and isinstance(n.body[0], ast.Return) and not n.orelse:
                        key = mangle(fn.name, cls.name if cls else None)
                        lo = n.test.lineno - fn.lineno
                        orig = cps[key]["orig"]
                        drop = {f"{key}__mutmut_{k}" for k, m in cps[key].items()
                                if k != "orig" and changed(orig, m)[0] <= lo < changed(orig, m)[1]}
                        want = f"{path}:{n.test.lineno} in {fn.name}: if has no mutant"
                        return want, drop
    sys.exit("negative control: no `if <name>: return ...` guard found")


if __name__ == "__main__":
    gaps, nfun, nsite, nmut = check()
    print(f"{nfun} functions, {nsite} guard sites, {nmut} mutants checked; {len(gaps)} gap(s)")
    if "--json" in sys.argv:
        json.dump(gaps, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
    if gaps:
        print("\n".join(gaps[:200]))
        sys.exit(1)
    want, drop = control()
    got = check(frozenset(drop))[0]
    if want not in got:
        sys.exit(f"negative control FAILED: dropping {len(drop)} mutant(s) of {want.split(' in ')[0]} was not reported: {got[:5]}")
    print(f"negative control: dropping the {len(drop)} mutant(s) of {want.split(' in ')[0]} is reported")
