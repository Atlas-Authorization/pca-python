"""Differential replay of the TypeScript reference (@atlasauth/pca-goal roundtrip): the card tape round trip, widening mutations and the
explainer + comparator detector (injected explainers and comparators are chosen by mode name)."""
import pytest

from atlas_pca import goal_roundtrip as R
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("goal-roundtrip")


class _Explainer:
    def __init__(self, mode):
        self.id, self.mode = mode, mode

    def explain(self, lines):
        if self.mode == "throw":
            raise RuntimeError("boom")
        return "\n".join(lines)


class _Comparator:
    id, family = "cmp", "f"

    def __init__(self, mode):
        self.mode = mode

    def equivalent(self, _text, explanation):
        if self.mode == "throw":
            raise RuntimeError("boom")
        if self.mode == "ok":
            return {"equivalent": True}
        if self.mode == "no":
            return {"equivalent": False, "reason": "x"}
        return {"equivalent": self.mode[9:] in explanation}


FNS = {
    "cardRoundTrips": R.card_round_trips,
    "mutateGoal": lambda g, k, ont: R.mutate_goal(g, k, ont),
    "roundTrip": lambda g, text, ex, cm: R.round_trip(g, text, _Explainer(ex), _Comparator(cm)),
    "measureDetection": lambda cases, ont, ex, cm: R.measure_detection(cases, ont, _Explainer(ex), _Comparator(cm)),
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
