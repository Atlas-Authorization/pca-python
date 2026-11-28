"""Differential replay: id patterns, effective profiles, structural param rules and semantic diffs against the TypeScript reference."""
import pytest

from atlas_pca import actions as A
from atlas_pca import actions_diff as D
from atlas_pca import actions_effective as E
from atlas_pca import actions_idpattern as ID
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-diff")
CORE = A.CORE_REGISTRY

MAP = {
    "idMatches": ID.id_matches,
    "idPatternContains": ID.id_pattern_contains,
    "join": A.join,
    "leq": A.leq,
    "profileEq": E.profile_eq,
    "effective": lambda d, c: E.effective_with(d, CORE, lambda _d: c),
    "hintTraits": A.hint_traits,
    "prulesViolations": E.prules_violations,
    "effWithTrait": lambda d, t: E.eff_with_trait(d, t, CORE),
    "requiredPrulesViolated": E.required_prules_violated,
    "diffDefs": lambda a, b, c=None: D.diff_defs(a, b, CORE, lambda _d: c),
    "diffDefsAuthoring": lambda a, b: D.diff_defs_authoring(a, b, CORE),
    "diffIsFree": D.diff_is_free,
    "diffPacks": lambda a, b: D.diff_packs(a, b, CORE),
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
