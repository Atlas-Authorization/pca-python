"""Differential replay: the example and property runner of the action packs against the TypeScript reference (the YAML form of the digest property
runs through the YAML writer and, with ruamel.yaml installed, the YAML loader; otherwise over the value form)."""
import pytest

pytest.importorskip("ruamel.yaml")  # the dependency-free job has no ruamel.yaml; every other job replays this corpus

from atlas_pca import actions as A
from atlas_pca import actions_test_runner as TR
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-test-runner")
CORE = A.CORE_REGISTRY

MAP = {
    "decideExample": lambda d, ex, defs: TR.decide_example(d, ex, CORE, defs),
    "runDefTests": lambda defs, limit=None: TR.run_def_tests(defs, CORE, limit),
    "testText": TR.test_text,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
