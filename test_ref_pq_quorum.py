"""Replays the TS-reference oracle of the in-core PQ quorum sets, quorum proofs and rotation chains (testdata/ref-pq-threshold-quorum.json.gz,
389 cases). Every fn has a handler and the total is asserted. A secret is {"$seed": label} = sha256("atlas-pca-conformance/" + label)
(an Ed25519 seed, or the key-generation seed of ML-DSA-65 / -87); bytes are {"$bytes"}; a reference throw is a native raise.

ML-DSA needs OpenSSL >= 3.5 or dilithium-py; SLH-DSA verification needs OpenSSL >= 3.5. Without a backend the cases that verify or sign with
it are not replayed and the test reports a skip after checking every other case; PCA_MPC_REQUIRE_MLKEM=1 (the OpenSSL 3.5 job) makes a
missing backend a failure."""
import json
import os

import pytest

from atlas_pca import pq_backends
from atlas_pca import pq_quorum as Q
from atlas_pca.agent import KeyPair, generate_pq_keypair
from base_oracle import HERE, b64d, canon, dec, load

COUNT, CASES = load("pq-threshold-quorum", os.path.join(HERE, "testdata", "ref-pq-threshold-quorum.json.gz"))
_FAMILY = {"ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87", "slh-dsa": "SLH-DSA-SHA2-128f", "slh-dsa-sha2-256s": "SLH-DSA-SHA2-256s"}
_CRYPTO = ("signQuorumShare", "signRotationShare", "verifyQuorum", "verifyQuorumApproval", "verifyRotationChain")
_PAIRS = {}


def _missing(case):
    """The PQ families a case names for which this runtime has no backend."""
    text = json.dumps(case["args"])
    return sorted({fam for tag, fam in _FAMILY.items() if tag in text and not pq_backends.available(fam)})


def _keys(alg, keys):
    """(ed, pq) key pairs for a signer of suite `alg` from the corpus key material (seeds as base64url after loading)."""
    ed = KeyPair(b64d(keys["edSecret"]), allow_insecure_signer=True) if "edSecret" in keys else None
    family, member = ("ML-DSA-87", "mlDsa87") if "ml-dsa-87" in str(alg) else ("ML-DSA-65", "mlDsa")
    pq = None
    if member in keys:
        if (family, keys[member]) not in _PAIRS:
            _PAIRS[(family, keys[member])] = generate_pq_keypair(family, b64d(keys[member]))
        pq = _PAIRS[(family, keys[member])]
    return ed, pq


def _sign(qset, index, epoch, digest, keys):
    signer = Q._at(qset["signers"], index)
    return Q.sign_quorum_share(qset, index, epoch, digest, *_keys(signer and signer.get("alg"), keys))


def _sign_rotation(from_set, index, from_epoch, to_set, keys):
    signer = Q._at(from_set["signers"], index)
    return Q.sign_rotation_share(from_set, index, from_epoch, to_set, *_keys(signer and signer.get("alg"), keys))


HANDLERS = {
    "constants": lambda: {"PQ_QUORUM_MAX_SIGNERS": Q.PQ_QUORUM_MAX_SIGNERS, "PQ_QUORUM_MAX_CHAIN": Q.PQ_QUORUM_MAX_CHAIN},
    "buildQuorumSet": Q.build_quorum_set,
    "loadQuorumSet": Q.load_quorum_set,
    "quorumMessage": Q.quorum_message,
    "quorumActionDigest": Q.quorum_action_digest,
    "signQuorumShare": _sign,
    "assembleQuorumProof": Q.assemble_quorum_proof,
    "verifyQuorum": Q.verify_quorum,
    "verifyQuorumApproval": Q.verify_quorum_approval,
    "rotationActionDigest": Q.rotation_action_digest,
    "signRotationShare": _sign_rotation,
    "buildRotationCert": Q.build_rotation_cert,
    "verifyRotationChain": Q.verify_rotation_chain,
    "isRotationFork": Q.is_rotation_fork,
    "quorumProofSize": Q.quorum_proof_size,
}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 389 and set(CASES) == set(HANDLERS)


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_pq_quorum_replay(fn):
    bad, unreplayed = [], set()
    for c in CASES[fn]:
        if fn in _CRYPTO and _missing(c):
            unreplayed.update(_missing(c))
            continue
        out = c["out"]
        threw = isinstance(out, dict) and "$throws" in out
        try:
            got = HANDLERS[fn](*dec(c["args"]))
        except Exception as e:  # noqa: BLE001 - a native refusal, compared against the reference
            if not threw:
                bad.append("%s\n    native raised %s: %s\n    ref:    %s" % (c["name"], type(e).__name__, e, canon(out)[:300]))
            continue
        if threw or canon(got) != canon(out):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:400], canon(out)[:400]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))
    if unreplayed:
        why = "no backend for %s: some cases of %s were not replayed" % (", ".join(sorted(unreplayed)), fn)
        if os.environ.get("PCA_MPC_REQUIRE_MLKEM") == "1":
            pytest.fail(why)
        pytest.skip(why)


def test_a_share_from_the_proof_cannot_stand_in_for_a_registered_signer():
    """Structure only (no backend needed): duplicate, unknown and excess shares are refused before any signature is checked."""
    case = next(c for c in CASES["verifyQuorum"] if c["name"] == "verifyQuorum/ok 2 of 3")
    inp = dec(case["args"])[0]
    n = len(inp["set"]["signers"])
    share = inp["proof"]["sigs"][0]
    assert Q.verify_quorum({**inp, "proof": {**inp["proof"], "sigs": [share] * (n + 1)}}) == {"ok": False, "reason": "too-many-signatures"}
    assert Q.verify_quorum({**inp, "proof": {**inp["proof"], "sigs": [{**share, "i": n}]}}) == {"ok": False, "reason": "unknown-signer"}
    assert Q.verify_quorum({**inp, "expectedSetId": None})["reason"] == "set-mismatch"
    assert Q.verify_quorum({**inp, "set": {**inp["set"], "t": 1}})["reason"] == "bad-set"
