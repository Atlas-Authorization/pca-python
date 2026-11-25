"""Differential replay of the deterministic parts of the invariant harness (atlas_pca.invariants: key pairs from seeds, the
legal-chain builder, the risk `worsen` helper, the registry constants) against vectors generated from the TypeScript reference
(@atlasauth/pca-invariants), plus a small run of the property-based checks themselves."""
import pytest

from atlas_pca import invariants as I
from base_oracle import load_ref, run

COUNT, CASES = load_ref("invariants")


def _key_pair(seed):
    p = I.key_pair_from_seed(seed)
    return {"secretKey": p["secret_key"], "publicKey": p["public_key"], "pub": p["pub"]}


def _build(m):
    chain = I.build_chain({
        "principal_seed": m["principalSeed"], "holder0_seed": m["holder0Seed"], "root_specs": m["rootSpecs"],
        "hops": [{"holder_seed": h["holderSeed"], "added_specs": h["addedSpecs"]} for h in m["hops"]],
        "predicates": m["predicates"],
    })
    return {"caps": chain["caps"], "predicates": chain["predicates"], "rootIssuer": chain["root_issuer"], "holders": chain["holders"]}


def _consts():
    return {"DEFAULT_SEED": I.DEFAULT_SEED, "DEFAULT_NUM_RUNS": I.DEFAULT_NUM_RUNS, "INVARIANT_NAMES": [i.name for i in I.INVARIANTS]}


MAP = {"keyPairFromSeed": _key_pair, "buildChain": _build, "worsen": I.worsen, "consts": _consts}


def test_corpus_is_the_full_oracle():
    assert COUNT == 312 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_every_invariant_holds_on_the_core():
    results = I.check_invariants(num_runs=8, seed=20260108)
    assert [r["name"] for r in results] == [i.name for i in I.INVARIANTS]
    assert [r for r in results if not r["ok"]] == []
    assert all(r["numRuns"] == 8 and r["seed"] == 20260108 for r in results)


def test_bail_stops_at_the_first_failure(monkeypatch):
    def boom(rng):
        return False
    monkeypatch.setattr(I, "INVARIANTS", [I.Invariant("a", lambda: lambda rng: True), I.Invariant("b", lambda: boom), I.Invariant("c", lambda: lambda rng: True)])
    assert [r["ok"] for r in I.check_invariants(num_runs=2, seed=1)] == [True, False, True]
    res = I.check_invariants(num_runs=2, seed=1, bail=True)
    assert [r["name"] for r in res] == ["a", "b"] and "seed 1" in res[1]["error"]


@pytest.mark.parametrize("kw", [{"num_runs": 0}, {"num_runs": -1}, {"num_runs": 1.5}, {"num_runs": "5"}, {"num_runs": True},
                                {"num_runs": 2, "seed": 1.5}, {"num_runs": 2, "seed": "1"}])
def test_refuses_a_vacuous_or_malformed_run(kw):
    with pytest.raises(ValueError):
        I.check_invariants(**kw)
