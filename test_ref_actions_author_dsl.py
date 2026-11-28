"""Differential replay: the typed param builder `P` (and action() over builder output) against the TypeScript reference. The other functions of the
same corpus are the shorthand / loader surface replayed by test_ref_actions_author."""
import pytest

from atlas_pca import actions_author as AU
from test_ref_actions_author import MAP
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-author")

_NAMES = {"bool": "bool_", "int": "int_", "id": "id_", "enum": "enum_", "set": "set_"}


def _builder(name, *args):
    return getattr(AU.P, _NAMES.get(name, name))(*args)


def test_builders_are_covered():
    assert {c["args"][0] for c in CASES["builder"]} >= {"email", "money", "int", "enum", "set", "array", "optional"}


@pytest.mark.parametrize("fn", ["builder"])
def test_matches_the_reference(fn):
    run(CASES[fn], _builder)


def test_the_shared_corpus_is_replayed_whole():
    """The whole of ref-actions-author: the builders above, the shorthand / expansion / loader surface through the handlers of test_ref_actions_author."""
    assert COUNT == 503 and set(CASES) == set(MAP) | {"builder"}
    assert {fn: len(cs) for fn, cs in CASES.items()} == {"parseParamShorthand": 86, "parseResourceShorthand": 24, "defaultTitle": 11, "expandAction": 74,
                                                         "loadActionsValue": 273, "builder": 30, "action": 5}


@pytest.mark.parametrize("fn", sorted(MAP))
def test_the_shared_corpus_matches_the_reference(fn):
    assert run(CASES[fn], MAP[fn])[0] == len(CASES[fn])
