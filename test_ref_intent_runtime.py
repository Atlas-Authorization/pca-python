"""Differential replay of the intent runtime digests, effect postconditions, trust-ramp drift detector and question cards
against the TypeScript reference (@atlasauth/pca-intent) vectors."""
from atlas_pca import intent_effects as E, intent_ramp as RA, intent_runtime as RT, intent_ux as UX
from base_oracle import load_ref, run

COUNT, CASES = load_ref("intent-runtime")


class _Stub:
    def __init__(self, omega, p):
        self.omega = omega
        self._p = p

    def acceptance(self, _o):
        return self._p


def _drift(opts, seq):
    d = RA.DriftDetector(opts)
    out = [d.update(x) for x in seq]
    out.append(d.state)
    d.reset()
    out.append(d.state)
    return out


MAP = {
    "pcactnActionOf": RT.pcactn_action_of,
    "judgeInputOf": lambda om, o, p, ctx: RT.judge_input_of(_Stub(om, p), o, ctx),
    "jitConsentRequest": lambda om, o, p, ctx: RT.jit_consent_request(_Stub(om, p), o, ctx),
    "jitConsentDigest": RT.jit_consent_digest,
    "calibrationDigest": RT.calibration_digest,
    "icAttDigest": RT.ic_att_digest,
    "foldSemanticRisk": RT.fold_semantic_risk,
    "defaultPostconditions": lambda: E.DEFAULT_POSTCONDITIONS,
    "checkPostconditions": E.check_postconditions,
    "effectContext": E.effect_context,
    "signalLabel": RA.signal_label,
    "narrowStart": RA.narrow_start,
    "driftRun": _drift,
    "questionCard": UX.question_card,
    "parseCardAnswer": UX.parse_card_answer,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn])
