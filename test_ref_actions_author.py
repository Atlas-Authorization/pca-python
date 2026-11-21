"""Differential replay: the authoring shorthands, entry expansion, document loader and action() constructor against the TypeScript reference."""
import pytest

from atlas_pca import actions_author as AU
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-author-py")

MAP = {
    "parseParamShorthand": AU.parse_param_shorthand,
    "parseResourceShorthand": AU.parse_resource_shorthand,
    "defaultTitle": AU.default_title,
    "expandAction": AU.expand_action,
    "loadActionsValue": AU.load_actions_value,
    "action": AU.action,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
