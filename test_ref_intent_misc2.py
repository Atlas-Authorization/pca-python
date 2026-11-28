"""Replays the TS-reference oracle of the intent modules' leftovers (testdata/ref-intent-misc2.json.gz, 770 cases): the strict-artifact helpers, the signed
"ask the principal" question and its RFC 9457 problem, the classifier verdicts / policy / quorum decision / judge attestation gate, the signing and digest half
of accumulator receipts and sequencer key sets, and admission / settlement through a session store. Every fn has a handler and the totals are asserted; a
reference refusal needs a native exception. The one case that the reference accepts ONLY through the legacy ``allowUnboundPq`` option (a receipt signed under
a post-quantum suite with no pinned key) is asserted REFUSED (count asserted)."""
import copy
import math
import os

import pytest

from atlas_pca import intent_history as H
from atlas_pca import intent_jit as JIT
from atlas_pca import intent_required as R
from atlas_pca import intent_sign as G
from atlas_pca import intent_v2 as V
from atlas_pca import intent_wb as W
from atlas_pca import pca
from atlas_pca import signers_more as SM
from atlas_pca.agent import KeyPair, generate_pq_keypair
from base_oracle import HERE, canon, dec, load, run

COUNT, CASES = load("intent-misc2", os.path.join(HERE, "testdata", "ref-intent-misc2.json.gz"))
NUM = {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}


def _num(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return NUM[v["$num"]]
        return {k: _num(x) for k, x in v.items()}
    return [_num(x) for x in v] if isinstance(v, list) else v


def _n(f):
    return lambda *a: f(*[_num(x) for x in a])


def _re(p):
    return {"$regex": "^%s$" % getattr(p, "pattern", p)}


def _suite(su):
    if su is None:
        return None, None
    pq = generate_pq_keypair("ML-DSA-65", su["pqSeed"]) if su.get("pqSeed") is not None else None
    return su["alg"], pq


def _constants():
    return {
        "DATA_CLASS_RE": _re(W.DATA_CLASS_RE), "INTENT_NAME_RE": _re(W.INTENT_NAME_RE), "PARAM_SEGMENT_RE": _re(W.PARAM_SEGMENT_RE),
        "SUITE_MEMBERS": list(W.SUITE_MEMBERS), "FRICTIONS": list(R.FRICTIONS), "INTENT_ACTION_DOMAIN": JIT.INTENT_ACTION_DOMAIN,
        "INTENT_PROBLEM_KINDS": list(R.INTENT_PROBLEM_KINDS), "INTENT_REQUIRED_DOMAIN": SM.INTENT_REQUIRED_DOMAIN, "PROBLEM_BASE": R.PROBLEM_BASE,
        "INTENT_CLASSIFIER_DOMAIN": W.INTENT_CLASSIFIER_DOMAIN, "INTENT_CLASSIFIER_REF_DOMAIN": W.INTENT_CLASSIFIER_REF_DOMAIN,
        "MAX_CLASSIFIER_LABELS": W.MAX_CLASSIFIER_LABELS, "MAX_COMMITTED_CLASSES": W.MAX_COMMITTED_CLASSES, "ACC_AGGS": list(V.ACC_AGGS),
        "ACC_ID_RE": _re(pca.ACC_ID_RE), "ACC_RECEIPT_CORE_DOMAIN": V.ACC_RECEIPT_CORE_DOMAIN, "ACC_RECEIPT_DOMAIN": V.ACC_RECEIPT_DOMAIN,
        "ACC_RECEIPT_REF_DOMAIN": V.ACC_RECEIPT_REF_DOMAIN, "ACC_RESERVE_DOMAIN": V.ACC_RESERVE_DOMAIN, "ACC_SCOPES": list(V.ACC_SCOPES),
        "DEFAULT_MAX_KEYSET_AGE_MS": V.DEFAULT_MAX_KEYSET_AGE_MS, "DEFAULT_MAX_RECEIPT_AGE_MS": V.DEFAULT_MAX_RECEIPT_AGE_MS, "KID_RE": _re(V.KID_RE),
        "MAX_MONITOR_WITHIN": V.MAX_MONITOR_WITHIN, "MAX_RECEIPT_LIFETIME_MS": V.MAX_RECEIPT_LIFETIME_MS,
        "MAX_SESSION_ACCUMULATORS": V.MAX_SESSION_ACCUMULATORS, "MAX_SESSION_MONITORS": V.MAX_SESSION_MONITORS, "MONITOR_KINDS": list(V.MONITOR_KINDS),
        "RECEIPT_SKEW_MS": V.RECEIPT_SKEW_MS, "SEQUENCER_KEYS_DOMAIN": V.SEQUENCER_KEYS_DOMAIN, "SEQUENCER_KEYS_REF_DOMAIN": V.SEQUENCER_KEYS_REF_DOMAIN,
        "COUNTED_STATUSES": list(H.COUNTED_STATUSES), "EVENT_STATUSES": list(H.EVENT_STATUSES)}


def _set_nested(a):
    root = a["root"]
    return {"ok": W.set_nested(root, a["path"], a["value"]), "root": root}


def _sign_artifact(domain, body, secret, su):
    alg, pq = _suite(su)
    return G.sign_artifact(domain, body, secret, alg, pq)


def _sign_ir(body, kid, secret, su):
    alg, pq = _suite(su)
    return SM.sign_intent_required(body, kid, KeyPair(secret, allow_insecure_signer=True), alg, pq)


def _signer(f):
    def go(body, secret, su):
        alg, pq = _suite(su)
        return f(body, secret, alg, pq)
    return go


def _verify_receipt(r, signer, pin):
    pins = (pin or {}).get("pqPins") if isinstance(pin, dict) else None
    return V.verify_acc_receipt_signature(r, signer, pins)


class _Tx:
    def __init__(self, ev):
        self._ev = ev

    def events(self):
        return [dict(e) for e in self._ev]

    def append(self, e):
        self._ev.append(dict(e))

    def set_status(self, event_id, status):
        e = next((x for x in self._ev if x["id"] == event_id), None)
        if e is None:
            return False
        e["status"] = status
        return True


class _Store:
    def __init__(self, durable):
        self.ev = {}
        if durable is not None:
            self.durable = durable

    def with_session(self, session, fn):
        return fn(_Tx(self.ev.setdefault(session, [])))


def _admit(ops):
    st, out = _Store(True), []
    for op in ops:
        try:
            if op[0] == "store":
                st = _Store(None if op[1]["durable"] == "absent" else op[1]["durable"] is not False)
                out.append(None)
            elif op[0] == "admit":
                a = op[1]

                def verify(acc, a=a):
                    if a["verifyAs"] == "throws":
                        raise RuntimeError("verify boom")
                    out.append({"acc": acc})
                    return {"allow": a["verifyAs"]["allow"]}
                args = {"session": a["session"], "root": a["root"], "event": a["event"], "verify": verify}
                if a.get("schema"):
                    args["schema"] = a["schema"]
                if "requireDurable" in a:
                    args["requireDurable"] = a["requireDurable"]
                out.append({"allow": H.admit_intent_action(st, args)["allow"]})
            elif op[0] == "settle":
                out.append(H.settle_intent_event(st, op[1], op[2], op[3]))
            elif op[0] == "events":
                out.append(copy.deepcopy(st.ev.get(op[1], [])))
            else:
                out.append({"$err": "op"})
        except Exception:  # noqa: BLE001 - the oracle records the refusal, not its text
            out.append({"$err": True})
    return out


HANDLERS = {
    "constants": _constants,
    "isPathSegment": W.is_path_segment, "isPlainObject": W.is_plain_object, "isSafeInt": W.is_safe_int, "utf8Len": W.utf8_len,
    "isBoundedString": W.is_bounded_string, "isDigest": W.is_digest, "isScalar": W.is_scalar, "scalarEq": W.scalar_eq,
    "closedMembers": W.closed_members, "pinPqOk": W.pin_pq_ok, "artifactSuiteError": W.artifact_suite_error, "artifactMessage": W.artifact_message,
    "signArtifact": _sign_artifact, "verifyArtifactSig": W.verify_artifact_sig, "artifactRef": W.artifact_ref, "publicKeyB64u": G.public_key_b64u,
    "resolveParamPath": W.resolve_param_path, "isParamPath": W.is_param_path, "setNested": _set_nested, "isClock": W.is_clock, "ownGet": W.own_get,
    "nullRecord": W.null_record,
    "intentActionDigest": JIT.intent_action_digest, "cellCoordsError": SM._cell_coords_error,
    "intentRequiredShapeError": lambda b, opts: R.intent_required_shape_error(b, (opts or {}).get("signed") is not False),
    "signIntentRequired": _sign_ir, "verifyIntentRequired": R.verify_intent_required, "verifyIntentRequiredAt": R.verify_intent_required_at,
    "intentProblem": R.intent_problem,
    "validateClassifierVerdictWire": W.validate_classifier_verdict_wire, "classifierContentDigest": W.classifier_content_digest,
    "signClassifierVerdict": _signer(G.sign_classifier_verdict), "classifierVerdictRef": W.classifier_verdict_ref,
    "validateClassifierPolicy": W.validate_classifier_policy, "classifierCheckActive": W.classifier_check_active,
    "decideClassifierDimensions": W.decide_classifier_dimensions, "verifyClassifierAttestation": G.verify_classifier_attestation,
    "monitorStates": V.monitor_states, "monitorInitialState": V.monitor_initial_state, "distinctKey": V.distinct_key, "sortedDistinct": V.sorted_distinct,
    "signAccReceipt": _signer(G.sign_acc_receipt), "accReceiptDigest": V.acc_receipt_digest, "accReceiptCoreDigest": G.acc_receipt_core_digest,
    "verifyReceiptSignature": _verify_receipt, "signSequencerKeySet": _signer(G.sign_sequencer_key_set),
    "sequencerKeySetDigest": V.sequencer_key_set_digest, "verifyKeySet": V.verify_sequencer_key_set,
    "accContextFor": H.acc_context_for, "admit": _admit,
}
TOTALS = {"constants": 1, "isPathSegment": 16, "isPlainObject": 8, "isSafeInt": 12, "isScalar": 16, "isClock": 12, "scalarEq": 11, "utf8Len": 7,
          "isBoundedString": 12, "isDigest": 12, "closedMembers": 8, "pinPqOk": 6, "artifactSuiteError": 12, "artifactMessage": 10, "signArtifact": 8,
          "verifyArtifactSig": 18, "artifactRef": 8, "publicKeyB64u": 2, "resolveParamPath": 25, "isParamPath": 25, "setNested": 14, "ownGet": 11,
          "nullRecord": 1, "intentActionDigest": 6, "cellCoordsError": 26, "intentRequiredShapeError": 90, "signIntentRequired": 8,
          "verifyIntentRequired": 26, "verifyIntentRequiredAt": 26, "intentProblem": 42, "classifierContentDigest": 12, "signClassifierVerdict": 7,
          "validateClassifierVerdictWire": 26, "classifierVerdictRef": 5, "validateClassifierPolicy": 42, "classifierCheckActive": 11,
          "decideClassifierDimensions": 44, "verifyClassifierAttestation": 11, "monitorStates": 13, "monitorInitialState": 13, "distinctKey": 18,
          "sortedDistinct": 7, "signAccReceipt": 16, "accReceiptDigest": 4, "accReceiptCoreDigest": 4, "verifyReceiptSignature": 8, "signSequencerKeySet": 15,
          "sequencerKeySetDigest": 3, "verifyKeySet": 8, "accContextFor": 13, "admit": 11}


def _unbound(c):
    return c["fn"] == "verifyReceiptSignature" and isinstance((c["args"][2] or None), dict) and bool(c["args"][2].get("allowUnboundPq"))


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 770 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


def test_the_legacy_unbound_pq_acceptance_is_refused():
    cases = [c for c in CASES["verifyReceiptSignature"] if _unbound(c)]
    assert len(cases) == 1
    for c in cases:
        assert c["out"] is True
        assert _n(HANDLERS["verifyReceiptSignature"])(*dec(c["args"])) is False


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_intent_misc2_replay(fn):
    skipped = 1 if fn == "verifyReceiptSignature" else 0
    assert run(CASES[fn], _n(HANDLERS[fn]), skip=lambda c: "unbound-pq" if _unbound(c) else None) == (TOTALS[fn] - skipped, skipped)
