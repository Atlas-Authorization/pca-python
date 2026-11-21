"""Differential replay of the intent outcome space (omega, policy plumbing, slots, regions) against the TypeScript
reference (@atlasauth/pca-intent) vectors."""
from atlas_pca import intent_omega as O, intent_policy as P, intent_region as R, intent_slots as S
from base_oracle import load_ref, run

COUNT, CASES = load_ref("intent-omega")


def _stats(s):
    return {"mass": s["mass"], "harm": s["harm"]}


def _rng_seq(seed, n):
    r = O.rng(seed)
    return [r() for _ in range(n)]


def _sample_outcomes(omega, seed, n):
    r = O.rng(seed)
    return [O.sample_outcome(omega, r)[1] for _ in range(n)]


MAP = {
    "deriveOmega": O.derive_omega,
    "harmMax": O.harm_max,
    "verbSpace": O.verb_space,
    "verbCellCount": O.verb_cell_count,
    "decodeCell": O.decode_cell,
    "encodeCell": O.encode_cell,
    "cellRep": O.cell_rep,
    "seeded": O.cell_rep,
    "cellStats": lambda vs, idx: _stats(O.cell_stats(vs, idx)),
    "cellOf": O.cell_of,
    "harmOf": O.harm_of,
    "cellCount": O.cell_count,
    "numCells": O.num_cells,
    "numRep": O.num_rep,
    "repValue": O.rep_value,
    "catRep": O.cat_rep,
    "catCellOf": O.cat_cell_of,
    "cellOfValue": O.cell_of_value,
    "dimCellStats": lambda d, i: _stats(O.dim_cell_stats(d, i)),
    "intervalWeight": O.interval_weight,
    "rngSeq": _rng_seq,
    "sampleOutcomes": _sample_outcomes,
    "normalizePolicy": P.normalize_policy,
    "slotsToPolicy": S.slots_to_policy,
    "outcomeToAction": P.outcome_to_action,
    "admits": lambda pol, vs, o: P.admitter(pol).admits(vs, o),
    "regionOfCell": R.region_of_cell,
    "regionCells": R.region_cells,
    "dimCellsIn": R.dim_cells_in,
    "restrictRegion": lambda d, part: R.restrict_region({"verb": "v", "dims": {}}, d, part),
    "valueInRegionDim": R.value_in_region_dim,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn])
