"""Replays the TS-reference oracle of the intent map attestation and the intent anchor receipt (testdata/ref-intent-attest.json.gz,
134 cases): the constants, signing a map attestation (Ed25519, ML-DSA-65, hybrid), verifying one (with and without the map, the expected
signer, the post-quantum pins), the anchor leaf and the verification of an anchoring receipt under a signed log head.
Every fn has a handler and the total is asserted. {"$bytes": {"$seed": label}} is sha256("atlas-pca-conformance/" + label) (the Ed25519
secret, or a suite's ML-DSA-65 key-generation seed); the text "$absent" is an argument not given; a reason that starts with
"malformed anchor receipt: " carries engine text after the colon and is cut, as the generator cuts the reference's.
ML-DSA needs OpenSSL >= 3.5 or dilithium-py: without one, the cases that use it are reported as a skip after every other case was checked."""
import json
import math
import os

import pytest

from atlas_pca import intent_attest as I
from atlas_pca import pq_backends
from atlas_pca.agent import KeyPair, generate_pq_keypair
from base_oracle import HERE, b64d, canon, load

COUNT, CASES = load("intent-attest", os.path.join(HERE, "testdata", "ref-intent-attest.json.gz"))
_CUT = "malformed anchor receipt"


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        if set(v) == {"$bytes"}:
            return b64d(v["$bytes"])  # the loader turned a seed label into base64url
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _sign(m, secret, signed_at, suite):
    suite = suite or {}
    pq = generate_pq_keypair("ML-DSA-65", suite["pqSeed"]) if "pqSeed" in suite else None
    return I.sign_intent_map_attestation(m, KeyPair(secret, allow_insecure_signer=True), signed_at, suite.get("alg"), pq)


def _verify(a, m, opts):
    return I.verify_intent_map_attestation(a, opts=opts) if m == "$absent" else I.verify_intent_map_attestation(a, m, opts)


def _anchor(r, guardian, instance, pin):
    out = I.verify_intent_anchor(r, guardian, instance, None if pin is None else pin.get("pqPins"))
    if isinstance(out.get("reason"), str) and out["reason"].startswith(_CUT + ": "):
        out = dict(out, reason=_CUT)
    return out


HANDLERS = {
    "constants": lambda: {"INTENT_MAP_SIG_DOMAIN": I.INTENT_MAP_SIG_DOMAIN, "INTENT_ANCHOR_DOMAIN": I.INTENT_ANCHOR_DOMAIN,
                          "INTENT_ANCHOR_LOG": I.INTENT_ANCHOR_LOG, "INTENT_ANCHOR_KINDS": list(I.INTENT_ANCHOR_KINDS)},
    "signIntentMapAttestation": _sign,
    "verifyIntentMapAttestation": _verify,
    "intentAnchorCommit": I.intent_anchor_commit,
    "verifyIntentAnchor": _anchor,
}


def _needs_ml_dsa(case):
    return "ml-dsa-65" in json.dumps(case["args"]) and not pq_backends.available("ML-DSA-65")


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 134 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == {"constants": 1, "signIntentMapAttestation": 36, "verifyIntentMapAttestation": 47,
                                                        "intentAnchorCommit": 13, "verifyIntentAnchor": 37}


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_intent_attest_replay(fn):
    bad, lacking = [], 0
    for c in CASES[fn]:
        if _needs_ml_dsa(c):
            lacking += 1
            continue
        out = c["out"]
        threw = isinstance(out, dict) and "$throws" in out
        try:
            got = HANDLERS[fn](*_dec(c["args"]))
        except Exception as e:  # noqa: BLE001 - a native refusal, compared against the reference
            if not threw:
                bad.append("%s\n    native raised %s: %s\n    ref:    %s" % (c["name"], type(e).__name__, e, canon(out)[:300]))
            continue
        if threw or canon(got) != canon(out):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:400], canon(out)[:400]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))
    if lacking:
        pytest.skip("without an ML-DSA-65 backend %d cases of %s were not replayed" % (lacking, fn))
