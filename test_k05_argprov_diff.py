"""k05 differential oracle: provenance by default (atlas_pca.arg_provenance: receipt / pin / action-info / envelope wire
checks, token matching, leaves, the decision, the recorder and the request reader) against the shared TS-generated
testdata/k05-argprov.json.gz."""
import pytest

from atlas_pca import arg_provenance as P
from k05_oracle import b64d, canon, load, run

COUNT, CASES = load("argprov")
_SNAKE = {"principalPlan": "principal_plan", "principalControl": "principal_control"}


def _decide(i):
    return P.decide_arg_provenance({_SNAKE.get(k, k): v for k, v in i.items()} if isinstance(i, dict) else i)


def _recorder(spec):
    """The generator's recorder(): a fixed clock list (the last value repeats), each step's throw recorded in place."""
    clock, last = list(spec["clock"]), [0]

    def now():
        if clock:
            last[0] = clock.pop(0)
        return last[0]

    rec = P.create_provenance_recorder(mediator=spec["mediator"], kid=spec["kid"], secret_key=b64d(spec["sk"]),
                                       session=spec["session"], now=now)
    outs = []
    for s in spec["steps"]:
        try:
            if s[0] == "direct":
                outs.append(P.principal_direct_provenance(rec, s[1]))
            elif s[0] == "action":
                outs.append(rec.for_action(s[1]))
            else:
                outs.append(getattr(rec, s[0])(*s[1:]))
        except Exception:  # noqa: BLE001 - compared as "this step refused" (the message is language-specific)
            outs.append({"$throws": "*"})
    return {"pin": rec.pin, "outs": outs}


def _recorder_eq(got, out, _c):
    return canon(got) == canon(dict(out, outs=[{"$throws": "*"} if isinstance(o, dict) and "$throws" in o else o for o in out["outs"]]))


def _read_bundle(a):
    return P.read_provenance_bundle({"pca-provenance": a["header"]} if "header" in a else {}, a.get("body"))


MAP = {
    "provReceiptWireError": (P.prov_receipt_wire_error, {}),
    "isProvMediatorPin": (P.is_prov_mediator_pin, {}),
    "provActionInfoError": (P.prov_action_info_error, {}),
    "isReadOnlyAction": (P.is_read_only_action, {}),
    "provEnvelopeError": (P.prov_envelope_error, {}),
    "occursAsToken": (P.occurs_as_token, {}),
    "provLeaves": (P.prov_leaves, {}),
    "decideArgProvenance": (_decide, {}),
    "recorder": (_recorder, {"compare": _recorder_eq}),
    "provActionDigest": (P.prov_action_digest, {}),
    "provReceiptRef": (P.prov_receipt_ref, {}),
    "defaultProvenanceBundle": (_read_bundle, {}),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 9825 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    run(CASES[fn], call, **kw)
