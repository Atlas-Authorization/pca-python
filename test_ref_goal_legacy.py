"""Differential replay of the TypeScript reference (@atlasauth/pca-goal legacy): the facade's {permissions, limits} lifted to a Goal and IR ontology."""
import pytest

from atlas_pca import goal_legacy as L
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("goal-legacy")


def _lift(permissions, limits, principal, not_after, not_before, nl):
    o = {"permissions": permissions, "principal": principal}
    if limits:
        o["limits"] = limits
    if not_after is not None:
        o["notAfter"] = not_after
    if not_before is not None:
        o["notBefore"] = not_before
    if nl is not None:
        o["nlDigest"] = nl
    return L.lift_legacy(o)


FNS = {"liftLegacy": _lift}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


def test_matches_reference():
    ran, _ = run(BY_FN["liftLegacy"], _lift)
    assert ran == len(BY_FN["liftLegacy"])
