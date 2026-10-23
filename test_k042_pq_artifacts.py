"""Kill tests: rule-15 artifacts signed with a PURE post-quantum suite (ML-DSA-65 through dilithium-py, which the CI runners
have): the sequencer key set and the reservation receipt verify only under the verifier's pin of the signer's PQ key, the
signed body binds `alg` and `pq_pk`, and a pure suite carries no `pq_sig`. Skipped when no ML-DSA-65 backend exists."""
import copy
import json
import os

import pytest

from atlas_pca import intent_v2 as V
from atlas_pca import pq_backends
from atlas_pca.pca import b64u, canonical_bytes_strict

dil = pytest.importorskip("dilithium_py.ml_dsa")
pytestmark = pytest.mark.skipif(not pq_backends.available("ML-DSA-65"), reason="no ML-DSA-65 backend")

with open(os.path.join(os.path.dirname(__file__), "testdata", "k042-intentacc.json"), encoding="utf-8") as fh:
    _CASES = {c["name"]: c for c in json.load(fh)}

KEYGEN = dil.ML_DSA_65.keygen()
PK, SK = KEYGEN
PKB = b64u(PK)
ID = b64u(bytes(range(32)))


def _sign(domain, body):
    msg = domain.encode("utf-8") + canonical_bytes_strict(V._bind_suite_fields(body, "ml-dsa-65", PKB))
    return b64u(dil.ML_DSA_65.sign(SK, msg))


def key_set():
    ks = copy.deepcopy(_CASES["verifyKeySet/ok"]["args"][0])
    body = {k: v for k, v in ks.items() if k != "sig"}
    body["sequencer"] = ID
    sig = _sign(V.SEQUENCER_KEYS_DOMAIN, body)
    return dict(body, alg="ml-dsa-65", pq_pk=PKB, sig=sig)


def receipt():
    r = copy.deepcopy(_CASES["verifyReceiptSignature/ok"]["args"][0])
    body = {k: v for k, v in r.items() if k != "sig"}
    body["signer"] = ID
    sig = _sign(V.ACC_RECEIPT_DOMAIN, V._receipt_body(body))
    return dict(body, alg="ml-dsa-65", pq_pk=PKB, sig=sig)


def test_key_set_under_a_pq_pin():
    k = key_set()
    assert V.sequencer_key_set_shape_error(k) is None
    assert V.sequencer_key_set_error(k, ID, PKB) is None and V.verify_sequencer_key_set(k, ID, PKB) is True
    assert V.sequencer_key_set_error(k, ID) == "invalid"  # no pin: the artifact's own key proves nothing
    assert V.sequencer_key_set_error(k, ID, b64u(bytes(1952))) == "invalid"
    assert V.sequencer_key_set_error(k, ID, None) == "invalid"
    assert V.sequencer_key_set_error(dict(k, version=k["version"] + 1), ID, PKB) == "invalid"
    assert V.sequencer_key_set_error(dict(k, pq_pk=b64u(bytes(1952))), ID, PKB) == "invalid"
    # a pure suite ignores pq_sig (it is outside the signed body and nothing verifies it)
    assert V.sequencer_key_set_error(dict(k, pq_sig=k["sig"]), ID, PKB) is None
    assert V.sequencer_key_set_error({kk: v for kk, v in k.items() if kk != "pq_pk"}, ID, PKB) == "invalid"
    assert V.sequencer_key_set_error(k, b64u(bytes(32)), PKB) == "invalid"


def test_receipt_under_a_pq_pin():
    r = receipt()
    assert V.acc_receipt_shape_error(r) is None
    assert V.acc_receipt_signature_error(r, ID, {ID: PKB}) is None
    assert V.verify_acc_receipt_signature(r, ID, {ID: PKB}) is True
    assert V.acc_receipt_signature_error(r, ID, {}) == "invalid" and V.acc_receipt_signature_error(r, ID, None) == "invalid"
    assert V.acc_receipt_signature_error(r, ID, {ID: b64u(bytes(1952))}) == "invalid"
    assert V.acc_receipt_signature_error(r, ID, {b64u(bytes(32)): PKB}) == "invalid"
    assert V.acc_receipt_signature_error(dict(r, seq=r["seq"] + 1), ID, {ID: PKB}) == "invalid"
    assert V.acc_receipt_signature_error(dict(r, pq_sig=r["sig"]), ID, {ID: PKB}) is None
    assert V.acc_receipt_signature_error({k: v for k, v in r.items() if k != "pq_pk"}, ID, {ID: PKB}) == "invalid"
    assert V.acc_receipt_signature_error(r, b64u(bytes(32)), {ID: PKB}) == "invalid"


def test_pinned_suite_error_directly():
    msg = b"hello"
    sig = b64u(dil.ML_DSA_65.sign(SK, msg))
    U = V._UNDEF
    assert V._pinned_suite_error("ml-dsa-65", ID, PKB, msg, sig, U, {ID: PKB}) is None
    assert V._pinned_suite_error("ml-dsa-65", ID, PKB, b"other", sig, U, {ID: PKB}) == "invalid"
    assert V._pinned_suite_error("ml-dsa-65", ID, U, msg, sig, U, {ID: PKB}) == "invalid"  # no artifact key
    assert V._pinned_suite_error("ml-dsa-65", ID, PKB, msg, sig, U, None) == "invalid"
    assert V._pinned_suite_error("ml-dsa-65", ID, PKB, msg, 5, U, {ID: PKB}) == "invalid"
    assert V._pinned_suite_error("ml-dsa-65", 5, PKB, msg, sig, U, {5: PKB}) == "invalid"
    assert V._pinned_suite_error(5, ID, PKB, msg, sig, U, {ID: PKB}) == "invalid"
    assert V._pinned_suite_error(None, ID, PKB, msg, sig, U, {ID: PKB}) == "invalid"
    assert "unsupported_suite" in V._pinned_suite_error("fn-dsa-512", ID, PKB, msg, sig, U, {ID: PKB})
    assert "unsupported_suite" in V._pinned_suite_error("nope", ID, PKB, msg, sig, U, {ID: PKB})
    assert V._pinned_suite_error("ed25519", ID, U, msg, 5, U, None) == "invalid"
    assert V._pinned_suite_error("ed25519", ID, U, msg, "x" * 86, U, None) == "invalid"


def test_unsupported_suite_surfaces_in_the_error_twins():
    r = copy.deepcopy(_CASES["verifyReceiptSignature/ok"]["args"][0])
    res = V.acc_receipt_signature_error(dict(r, alg="fn-dsa-512"), r["signer"])
    assert isinstance(res, str) and "unsupported_suite" in res and "fn-dsa-512" in res
    ks = copy.deepcopy(_CASES["verifyKeySet/ok"]["args"][0])
    res = V.sequencer_key_set_error(dict(ks, alg="fn-dsa-512"), ks["sequencer"])
    assert isinstance(res, str) and "unsupported_suite" in res
    res = V.receipt_against_holder_error(dict(r, alg="fn-dsa-512"), {"kind": "sequenced", "uri": "https://s", "root": ks["sequencer"]},
                                         [ks], 1800000000000)
    assert isinstance(res, str) and "unsupported_suite" in res
