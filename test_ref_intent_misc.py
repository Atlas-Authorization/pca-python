"""Differential replay of the intent statement, compiler pipeline, schema outcome space, provenance, classifier risk,
trajectory lift, frame constraints and just-in-time elicitation pure parts against the TypeScript reference
(@atlasauth/pca-intent) vectors."""
from atlas_pca import (intent_classifier as CL, intent_compilers as CO, intent_frames as FR, intent_jit as JI, intent_provenance as PV,
                       intent_schema as SC, intent_statement as ST, intent_trajectory as TR)
from atlas_pca.pca import decode_b64u_strict
from base_oracle import load_ref, run

COUNT, CASES = load_ref("intent-misc")


def _compiler(spec):
    if spec["kind"] == "captured":
        return CO.captured_slots_compiler(spec["id"])
    if spec["kind"] == "throws":
        def boom(_inp):
            raise RuntimeError("boom")
        return CO.IntentCompiler(spec["id"], spec["family"], boom)
    return CO.fixed_compiler(spec["id"], spec["family"], lambda _inp: spec["policy"])


def _regret(cases, scale=None):
    cs = [{**c, "admits": lambda x: x["values"]["ok"] == 1, "utility": lambda x: x["values"]["u"]} for c in cases]
    return PV.regret_report(cs) if scale is None else PV.regret_report(cs, scale)


def _step(om, psi, hist, cand, allow):
    def in_grant(_verb, cell):
        if allow == "all":
            return True
        if allow == "none":
            return False
        return any(",".join(map(str, x)) == ",".join(map(str, cell)) for x in allow)
    return TR.step_trajectory(om, psi, hist, {**cand, "id": "new"}, in_grant)


def _check_frame(spec, *rest):
    if not rest:  # the spec-only cases: the generator fixes the action and the empty snapshots
        rest = ({"verb": "v", "resource": "r"}, {}, {})
    return FR.check_frame(spec, *rest)


MAP = {
    "signIntent": lambda s, seed: ST.sign_intent(s, decode_b64u_strict(seed, 32)),
    "intentRef": ST.intent_ref,
    "verifyIntent": ST.verify_intent,
    "parseSlotsJSON": CO.parse_slots_json,
    "slotsPrompt": CO.slots_prompt,
    "runCompilers": lambda inp, specs: CO.run_compilers(inp, [_compiler(s) for s in specs]),
    "analyzeDisagreement": CO.analyze_disagreement,
    "panelFlags": CO.panel_flags,
    "committeeAnchors": CO.committee_anchors,
    "deriveOmegaFromSchema": SC.derive_omega_from_schema,
    "canonValue": SC.canon_value,
    "provenanceBanner": PV.provenance_banner,
    "provenanceFriction": PV.provenance_friction,
    "regretReport": _regret,
    "calibrateConfusion": CL.calibrate_confusion,
    "confusionDigest": CL.confusion_digest,
    "publishedErrorRate": CL.published_error_rate,
    "classifierCardNote": CL.classifier_card_note,
    "classifierRisk": CL.classifier_risk,
    "labelSound": CL.label_sound,
    "labelSoundBound": CL.label_sound_bound,
    "dimKindOf": TR.dim_kind_of,
    "describeAccCell": TR.describe_acc_cell,
    "trajectoryHarmRange": TR.trajectory_harm_range,
    "defaultAccumulators": TR.default_accumulators,
    "augmentOmega": TR.augment_omega,
    "liftAction": TR.lift_action,
    "stepTrajectory": _step,
    "stateDigest": FR.state_digest,
    "snapshotState": FR.snapshot_state,
    "writeSetOf": FR.write_set_of,
    "checkFrame": _check_frame,
    "cellCoords": JI.cell_coords,
    "cellFromCoords": JI.cell_from_coords,
    "intentRequiredBody": JI.intent_required_body,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn])
