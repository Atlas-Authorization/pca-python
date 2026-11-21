"""Differential replay of the TypeScript reference (@atlasauth/pca-goal nversion and disambiguate): the semantic meet of readings, the
panel check, N-version interpretation, witness questions and version-space halving."""
import pytest

from atlas_pca import goal_disambiguate as D
from atlas_pca import goal_nversion as N
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("goal-nversion")


def _disambiguate(readings, ont, mode, budget):
    def ask(q):
        if mode in ("allow", "deny"):
            return mode
        return "allow" if D.allows_witness(readings[int(mode[6:])]["goal"], ont, q) else "deny"
    opts = {"ont": ont}
    if budget is not None:
        opts["budget"] = budget
    return D.disambiguate(readings, ask, opts)


FNS = {
    "meet": N.meet, "meetGrants": N.meet_grants, "checkPanel": N.check_panel,
    "nVersion": lambda r, ont, th: N.n_version(r, dict({"ont": ont}, **({} if th is None else {"massThreshold": th}))),
    "questions": lambda r, ont: D.questions(r, {"ont": ont}),
    "disagreementMass": D.disagreement_mass, "allowsWitness": D.allows_witness, "disambiguate": _disambiguate,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
