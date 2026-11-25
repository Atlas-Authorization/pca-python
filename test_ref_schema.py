"""Differential replay of the PCA wire schemas and the structural validator against the TypeScript reference: every case,
the error list compared exactly and in order."""
import pytest

from atlas_pca import schema as S
from base_oracle import load_ref, run

COUNT, CASES = load_ref("schema")


def _validate(s, v):
    return S.validate(S.ALL_SCHEMAS[s] if isinstance(s, str) else s, v)


MAP = {"validate": _validate, "schemas": lambda: S.ALL_SCHEMAS}


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)
    assert COUNT == 3216 and sum(len(v) for v in CASES.values()) == 3216
    # the reference decides every case (none is a throw): 1198 valid, 2017 invalid with their error lists
    outs = [c["out"] for c in CASES["validate"]]
    assert sum(1 for o in outs if o == {"valid": True, "errors": []}) == 1198
    assert sum(1 for o in outs if o.get("valid") is False and o["errors"]) == 2017


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, skipped = run(CASES[fn], MAP[fn])
    assert (ran, skipped) == (len(CASES[fn]), 0)
