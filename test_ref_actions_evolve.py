"""Differential replay: pack evolution records, registry signing and the whole-change check against the TypeScript reference."""
import pytest

from atlas_pca import ed25519

from atlas_pca import actions as A
from atlas_pca import actions_evolve as EV
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("actions-evolve")
CORE = A.CORE_REGISTRY


def _opt(c):
    return lambda _d: c


MAP = {
    "evolutionRecords": lambda ns, p, n, c: EV.evolution_records(ns, p, n, CORE, _opt(c)),
    "signEvolution": EV.sign_evolution,
    "evolutionError": lambda ns, p, n, r, k, c: EV.evolution_error(ns, p, n, r, k, CORE, _opt(c)),
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
