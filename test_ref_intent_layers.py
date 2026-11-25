"""Differential replay of the multi-principal rules, common refinement, wallet-side layer lattice, quorum approvals and
grant measurement against the TypeScript reference (@atlasauth/pca-intent) vectors."""
from atlas_pca import intent_layers_wallet as L, intent_metrics as M, intent_multi as U
from atlas_pca.pca import decode_b64u_strict
from base_oracle import load_ref, run

COUNT, CASES = load_ref("intent-layers")


def _assert_askable(view, c):
    L.assert_askable(view, c)
    return None


MAP = {
    "normalizeRule": U.normalize_rule,
    "effectiveVetoers": U.effective_vetoers,
    "ruleAdmits": U.rule_admits,
    "jointAcceptance": U.joint_acceptance,
    "commonRefinement": U.common_refinement,
    "ceilingOf": lambda layers, vs, o: L.ceiling_of(L.ceiling_admitters(layers), vs, o),
    "assertAskable": _assert_askable,
    "layerCells": lambda om, pol: L.layer_cells(om, L.admitter(pol)),
    "ownerRisk": lambda om, cells, pol: L.owner_risk(om, cells, M.acceptability_of(pol)),
    "cellKeyOf": L.cell_key_of,
    "signLayerApproval": lambda st, seed: L.sign_layer_approval(st, decode_b64u_strict(seed, 32)),
    "verifyQuorumApprovals": L.verify_quorum_approvals,
    "measureGrantExact": lambda om, g, t: M.measure_grant_exact(om, g, M.acceptability_of(t)),
    "measureGrant": lambda om, g, t, opts: M.measure_grant(om, g, M.acceptability_of(t), opts),
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn])
