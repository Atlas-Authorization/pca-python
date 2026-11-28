"""Replays the TS-reference oracle that extends the policy-safety CI gate's (testdata/ref-policy-ci-java-extra.json.gz, 162 cases): the lint rules over a policy
checked against a schema, and the authoring ``test`` and ``coverage`` commands run to their results (exit code and output lines). The handlers are those
of the main policy-ci replay. Every fn has a handler and the totals are asserted; a reference refusal needs a native exception."""
import os

import pytest

from test_ref_policy_ci import MAP
from base_oracle import HERE, load, run

COUNT, CASES = load("policy-ci-java-extra", os.path.join(HERE, "testdata", "ref-policy-ci-java-extra.json.gz"))
TOTALS = {"lintPolicy": 81, "testCommand": 45, "coverageCommand": 36}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 162 and set(CASES) == set(TOTALS) and set(TOTALS) <= set(MAP)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(TOTALS))
def test_policy_ci_extra_replay(fn):
    assert run(CASES[fn], MAP[fn]) == (TOTALS[fn], 0)
