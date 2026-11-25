"""Replays the TS-reference oracle of the schema-derived outcome space (testdata/ref-intent-schema.json.gz, 267 cases): the outcome space derived from a
site action schema (dimensions only for parameters whose effective sensitivity, after the wallet floor, is material or critical, the canonical projections,
the default sets for silent parameters), the canonical text of a projected value, the wallet floor and the conservative reversibility. Every fn has a
handler and the totals are asserted; a reference refusal needs a native exception."""
import os

import pytest

from atlas_pca import intent_schema as S
from base_oracle import HERE, load, run

COUNT, CASES = load("intent-schema", os.path.join(HERE, "testdata", "ref-intent-schema.json.gz"))


def _derive(opts):
    out = S.derive_omega_from_schema(opts)
    return dict(out, omega=dict(out["omega"], v=1))  # the reference's Omega carries its version


HANDLERS = {
    "deriveSchemaOmega": _derive,
    "canonValue": S.canon_value,
    "effectiveSensitivity": lambda d, floor=None: S.effective_sensitivity(d, floor),
    "verbReversibility": S.verb_reversibility,
    "walletFloorOverrides": lambda verbs, floor=None: S.wallet_floor_overrides({"verbs": verbs}, floor),
}
TOTALS = {"deriveSchemaOmega": 22, "canonValue": 157, "effectiveSensitivity": 75, "verbReversibility": 10, "walletFloorOverrides": 3}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 267 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_intent_schema_replay(fn):
    assert run(CASES[fn], HANDLERS[fn]) == (TOTALS[fn], 0)
