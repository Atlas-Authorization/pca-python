"""Mutation kills (safe regex), differential: atlas_pca/safe_regex.py and predicates.is_safe_regex_source against the TS
reference (safe-regex.ts, predicates.ts, regex-budget.ts). testdata/killRegex.json.gz is the shared, language-neutral oracle
(tools/pca-audit/kotlin-mutate/killRegex-oracle-gen.mjs): full-match results (true / false / refused) of a pattern corpus
crossed with boundary subjects, compiled program sizes, the step boundary, the safe-source guard and per-document budget
sequences."""
import gzip
import json
import os

from atlas_pca.predicates import is_safe_regex_source
from atlas_pca.safe_regex import (
    MAX_MATCH_STEPS, MAX_NFA_INSTRUCTIONS, MAX_REPEAT, RegexBudget, compile_safe_regex, safe_regex_full_match,
)

with gzip.open(os.path.join(os.path.dirname(__file__), "testdata", "killRegex.json.gz"), "rt", encoding="utf-8") as fh:
    DATA = json.load(fh)


def _depth(p):
    d = m = 0
    for ch in p:
        d += ch == "("
        d -= ch == ")"
        m = max(m, d)
    return m


# Every protocol entry point caps a regex at 200 UTF-16 units (predicates `matches`, `re:` resources, prohibitions), so at
# most 100 nested groups reach the engine. Deeper engine-only probes refuse on stack exhaustion in every implementation,
# at a depth set by the language's stack (JS ~thousands, CPython's recursion limit ~250): not a protocol behaviour.
REACHABLE = 100


def _want(r):
    return None if r < 0 else r == 1


def test_full_match_agrees_with_the_reference():
    n = 0
    for p, subs, rs in DATA["fm"]:
        assert len(subs) == len(rs), p
        if _depth(p) > REACHABLE:
            continue
        for s, r in zip(subs, rs):
            want = None if r == "n" else r == "1"
            got = safe_regex_full_match(p, s)
            if got is not want:
                assert got == want, f"/{p}/ on {s!r}"
            n += 1
    assert n > 100_000


def test_compiled_sizes_agree():
    for p, want in DATA["size"]:
        if _depth(p) > REACHABLE:
            continue
        c = compile_safe_regex(p)
        if want < 0:
            assert c is None, f"/{p}/"
        else:
            assert c is not None and len(c.program) == want, f"/{p}/"


def test_step_boundary_agrees():
    assert (MAX_NFA_INSTRUCTIONS, MAX_REPEAT, MAX_MATCH_STEPS) == (4096, 64, 2_000_000)
    for p, n, r in DATA["steps"]:
        if _depth(p) > REACHABLE:
            continue
        assert safe_regex_full_match(p, "a" * n) is _want(r), f"/{p[:20]}/ n={n}"


def test_safe_source_guard_agrees():
    assert len(DATA["safe"]) > 500
    for p, want in DATA["safe"]:
        if _depth(p) > REACHABLE:
            continue
        got = is_safe_regex_source(p)
        if got is not want:
            assert got == want, f"/{p}/"


def test_budget_sequences_agree():
    for k, b in enumerate(DATA["budgets"]):
        budget = RegexBudget()
        for i, ((src, n), want) in enumerate(zip(b["ops"], b["res"])):
            assert budget.charge(src, n) is want, f"budget #{k} op {i}"
        ev, chars, steps, ref = b["fin"]
        assert (budget.evaluations, budget.chars, budget.steps, budget.refusals) == (ev, chars, steps, ref), f"budget #{k}"
