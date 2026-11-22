"""Differential replay of the TypeScript reference (@atlasauth/pca-goal examples): decision cells, boundary examples, goal tests and the policy pin."""
import pytest

from atlas_pca import goal_examples as E
from atlas_pca.ed25519 import allow_insecure_signer
from base_oracle import b64d, load_ref, run

COUNT, BY_FN = load_ref("goal-examples")


@pytest.fixture(autouse=True, scope="module")
def _signer():
    allow_insecure_signer(True)
    yield
    allow_insecure_signer(False)


def _boundary(g, ont, extra, verbs):
    opts = {"ont": ont}
    if extra:
        opts["extra"] = extra
    if verbs:
        opts["verbs"] = verbs
    return E.boundary_examples(g, opts)


def _check_tests(signed, pins, mode, g, ont):
    if mode == "ref":
        fn = lambda t: E.decide_case(g, ont, t)["decision"]  # noqa: E731
    else:
        fn = lambda t: {"allow": "allow", "deny": "deny"}.get(mode, "escalate")  # noqa: E731
    return E.check_goal_tests(signed, pins, fn)


FNS = {
    "buildSpace": E.build_space,
    "cellKey": lambda goals, extra, c: E.cell_key(E.build_space(goals, extra), c),
    "cells": lambda goals, extra, verbs: E.cells(E.build_space(goals, extra), {} if verbs is None else {"verbs": verbs}),
    "decideCase": E.decide_case, "replay": E.replay,
    "allowWitness": lambda g, i, ont: E.allow_witness(g, g["grants"][i], ont),
    "boundaryExamples": _boundary, "reviewSet": E.review_set, "testsDigest": E.tests_digest, "makeGoalTests": E.make_goal_tests,
    "signGoalTestsSeed": lambda s, seed: E.sign_goal_tests(s, b64d(seed)),
    "checkGoalTests": _check_tests,
    "signPinSeed": lambda p, seed: E.sign_pin(p, b64d(seed)),
    "checkPin": E.check_pin,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
