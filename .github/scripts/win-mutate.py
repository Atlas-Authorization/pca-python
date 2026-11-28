#!/usr/bin/env python3
"""Mutation of the Windows-only branches of atlas_pca on a Windows runner (mutmut forks, so it cannot run there; the Linux mutmut
job never executes these branches: `if os.name == "nt"`, `if _WIN`, `... if sys.platform == "win32" else ...`).

  win-mutate.py FILE TEST... [--slice K/N]

Region = every If / IfExp whose test mentions os.name, sys.platform or _WIN (test, body and orelse). Operators: comparison swap,
and<->or, `not` removal, constant change, `return v` -> `return None`, statement removal. Each mutant is written over FILE, the
tests run (python -m pytest -x -q TEST...), FILE is restored. A mutant that no test fails, or that hangs, is a survivor; any
survivor exits 1. No ledger: every mutant must be killed (a Windows-only equivalent is argued in the code, not skipped here)."""
import ast, copy, os, re, subprocess, sys

file_, rest = sys.argv[1], sys.argv[2:]
sl = (1, 1)
if "--slice" in rest:
    i = rest.index("--slice"); sl = tuple(int(x) for x in rest[i + 1].split("/")); del rest[i:i + 2]
tests = rest
src = open(file_, encoding="utf-8").read()
PLAT = re.compile(r"os\.name|sys\.platform|\b_WIN\b")


def region_roots(tree):
    return [n for n in ast.walk(tree) if isinstance(n, (ast.If, ast.IfExp)) and PLAT.search(ast.unparse(n.test))]


SWAP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt, ast.Gt: ast.LtE, ast.LtE: ast.Gt,
        ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.In: ast.NotIn, ast.NotIn: ast.In}


def mutants(tree):
    """[(label, mutate(tree_copy))]: each mutate edits the node at the same walk position of a fresh copy."""
    pos = {id(n): i for i, n in enumerate(ast.walk(tree))}
    in_region = set()
    for r in region_roots(tree):
        for n in ast.walk(r):
            in_region.add(id(n))
    out = []
    for n in ast.walk(tree):
        if id(n) not in in_region:
            continue
        i, line = pos[id(n)], getattr(n, "lineno", 0)
        if isinstance(n, ast.Compare):
            for k, op in enumerate(n.ops):
                if type(op) in SWAP:
                    out.append((f"{line}: compare {type(op).__name__}->{SWAP[type(op)].__name__}", i, ("cmp", k)))
        elif isinstance(n, ast.BoolOp):
            out.append((f"{line}: {type(n.op).__name__} swapped", i, ("bool",)))
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            out.append((f"{line}: `not` removed", i, ("not",)))
        elif isinstance(n, ast.Constant) and not isinstance(n.value, (type(None), type(...), bytes)):
            out.append((f"{line}: constant {n.value!r} changed", i, ("const",)))
        elif isinstance(n, ast.Return) and n.value is not None and not (isinstance(n.value, ast.Constant) and n.value.value is None):
            out.append((f"{line}: return value -> None", i, ("ret",)))
        elif isinstance(n, (ast.Expr, ast.Assign, ast.AugAssign, ast.Break, ast.Continue, ast.Raise)) and not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)):
            out.append((f"{line}: statement removed", i, ("stmt",)))
    return out


def apply(tree, i, how):
    t = copy.deepcopy(tree)
    nodes = list(ast.walk(t))
    n = nodes[i]
    if how[0] == "cmp":
        n.ops[how[1]] = SWAP[type(n.ops[how[1]])]()
    elif how[0] == "bool":
        n.op = ast.Or() if isinstance(n.op, ast.And) else ast.And()
    elif how[0] == "not":
        n.op = ast.UAdd(); n.operand = ast.UnaryOp(op=ast.Not(), operand=ast.UnaryOp(op=ast.Not(), operand=n.operand))  # `not x` -> `+(not not x)`: truthiness of x
    elif how[0] == "const":
        v = n.value
        n.value = (not v) if isinstance(v, bool) else v + 1 if isinstance(v, (int, float)) else "XX" + v + "XX"
    elif how[0] == "ret":
        n.value = ast.Constant(value=None)
    elif how[0] == "stmt":
        for p in nodes:
            for f in ("body", "orelse", "finalbody"):
                lst = getattr(p, f, None)
                if isinstance(lst, list) and any(x is n for x in lst):
                    lst[[id(x) for x in lst].index(id(n))] = ast.Pass()
    return ast.fix_missing_locations(t)


def run(cmd, timeout):
    # its own (hidden) console: a mutant that makes a test send Ctrl-C (os.kill(pid, 0) is CTRL_C_EVENT on Windows, delivered to every
    # process on the console) interrupts that test run, a kill, and never this script mid-restore
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}).returncode
    except subprocess.TimeoutExpired:
        return "timeout"


tree = ast.parse(src)
ms = mutants(tree)
print(f"{file_}: {len(region_roots(tree))} Windows branch(es), {len(ms)} mutant(s), slice {sl[0]}/{sl[1]}")
if not ms:
    sys.exit(f"{file_} has no platform-branch mutant: the file or the region rule is wrong")
pytest = [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *tests]
if run(pytest, 1800) != 0:
    sys.exit("the unmutated tests do not pass on this runner")
survivors = []
try:
    for j, (label, i, how) in enumerate(ms):
        if j % sl[1] != sl[0] - 1:
            continue
        open(file_, "w", encoding="utf-8").write(ast.unparse(apply(tree, i, how)) + "\n")
        rc = run(pytest, 600)
        print(("KILLED  " if rc not in (0, "timeout") else "SURVIVED " if rc == 0 else "TIMEOUT ") + label, flush=True)
        if rc in (0, "timeout"):
            survivors.append(label)
finally:
    open(file_, "w", encoding="utf-8").write(src)
print(f"{len(survivors)} survivor(s)")
sys.exit(1 if survivors else 0)
