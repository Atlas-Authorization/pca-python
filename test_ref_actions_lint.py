"""Differential replay: the action lint rules, text and SARIF output, and the definition-level undo structure against the TypeScript reference."""
import pytest

from atlas_pca import actions_lint as L
from atlas_pca import actions_undo as U
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-lint")


def _lint(raw, opts=None):
    o = dict(opts or {})
    has = "att" in o
    att = o.pop("att", None)
    return L.lint_defs(raw, o, (lambda _d: att) if has else None)


MAP = {
    "lintDefs": _lint,
    "lintRulesDigest": L.lint_rules_digest,
    "LINT_RULES": lambda: [list(r) for r in L.LINT_RULES],
    "lintText": L.lint_text,
    "toSarif": L.to_sarif,
    "lintFails": L.lint_fails,
    "mayBeReversible": U.may_be_reversible,
    "reversibilityFor": U.reversibility_for,
    "compensationShape": U.compensation_shape,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
