"""Differential replay: the action vocabulary migration shims against the TypeScript reference."""
import pytest

from atlas_pca import actions_compat as C
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-compat")

MAP = {
    "normalizeReversibility": C.normalize_reversibility,
    "legacyOperationsClass": C.legacy_operations_class,
    "maxRevOf": C.max_rev_of,
    "unitTagOf": C.unit_tag_of,
    "blastOfFloat": C.blast_of_float,
    "blastExactOfFloat": C.blast_exact_of_float,
    "fromCatalogSpec": C.from_catalog_spec,
    "fromCatalog": C.from_catalog,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
