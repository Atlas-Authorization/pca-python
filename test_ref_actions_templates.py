"""Differential replay: the starter templates (custom traits and authoring YAML under several namespaces) against the TypeScript reference."""
import pytest

from atlas_pca import actions_templates as T
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-templates-py")


def _meta(t):
    return None if t is None else {"id": t.id, "title": t.title, "description": t.description, "ns": t.ns}


MAP = {
    "templateList": lambda: [_meta(t) for t in T.STARTER_TEMPLATES],
    "starterTemplate": lambda i: _meta(T.starter_template(i)),
    "templateTraits": lambda i, n: T.starter_template(i).traits(n),
    "templateYaml": lambda i, n: T.starter_template(i).yaml(n),
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
