"""Producer-side ports that mirror the reference: signed tree heads, witness cosignatures, the stored-ledger openings, the optimistic
challenge window and fraud proofs, intent map attestations / observations / anchors, passport extras, small caveat and revocation helpers,
the policy builder and the public authorize_execution entry. Each signer is checked against the existing verifier of the same artifact."""
import base64
import hashlib

import pytest

from atlas_pca.agent import generate_keypair
from atlas_pca.ledger import (cosign_tree_head, entry_commit, sign_tree_head, verify_opening, verify_tree_head, verify_witnessed_head,
                              verify_witness_cosignature)
from atlas_pca.ledger_proofs import TransparencyLedger
from atlas_pca.optimistic import DEFAULT_MIN_CHALLENGE_WINDOW_MS, DEFAULT_WINDOW_POLICY, resolve_window
from atlas_pca.intent_attest import (INTENT_ANCHOR_LOG, intent_anchor_commit, intent_map_shape_error, sign_intent_map_attestation,
                                     sign_intent_observation, verify_intent_anchor, verify_intent_map_attestation, verify_intent_observation)
from atlas_pca.mesh import effective_authority, revocation_latency_bound
from atlas_pca.objective_binding import read_objective_commitment
from atlas_pca.passport import matches_binding, passport_evidence_binding, trust_score
from atlas_pca.revocation_staleness import revocation_exposure_end
from atlas_pca.server_surface import PolicyBuilder, authorize_execution, policy
from atlas_pca.signers_more import BUDGET_ALLOC_CAVEAT, budget_alloc_caveat, revoke_message


def k():
    return generate_keypair(allow_insecure_signer=True)


def d32(tag):
    return base64.urlsafe_b64encode(hashlib.sha256(tag.encode()).digest()).decode().rstrip("=")


def test_tree_head_and_cosignature_verify():
    g, w = k(), k()
    head = {"instance_id": "i", "principal": "log", "size": 3, "root": d32("r"), "prev_root": "", "timestamp": 5}
    sth = sign_tree_head(g, head)
    assert verify_tree_head(sth, g.public)
    assert not verify_tree_head(dict(sth, size=4), g.public)
    c = cosign_tree_head(sth, w)
    assert verify_witness_cosignature(sth, c, w.public)
    assert not verify_witness_cosignature(dict(sth, root=d32("x")), c, w.public)
    sth["witnesses"] = [c]
    assert verify_tree_head(sth, g.public, {"threshold": 1, "witnessKeys": [w.public]})


def test_ledger_openings_shred_and_witness_head():
    t = TransparencyLedger("p")
    a = t.append({"x": 1}, salt="s")
    assert a["commit"] == entry_commit("s", {"x": 1})
    assert verify_opening(a["commit"], t.entry(0)["opening"])
    assert not verify_opening(a["commit"], {"salt": "s", "pcactn": {"x": 2}})
    root = t.head()["root"]
    assert t.audit_openings() == []
    assert t.shred(0) and not t.shred(0)
    assert t.head()["root"] == root and "opening" not in t.entry(0)
    w = k()
    assert verify_witnessed_head(t.witness_head(w), w.public)


def test_resolve_window_clamps():
    p = DEFAULT_WINDOW_POLICY
    assert resolve_window(p, 10, 1) == {"issued_at": 10, "challenge_window_ms": DEFAULT_MIN_CHALLENGE_WINDOW_MS}
    assert resolve_window(p, 10)["challenge_window_ms"] == p["defaultWindowMs"]
    assert resolve_window(p, 10, 10 ** 12)["challenge_window_ms"] == p["maxWindowMs"]
    with pytest.raises(ValueError):
        resolve_window(p, float("inf"))


def test_intent_map_attestation_observation_anchor():
    s = k()
    m = {"v": 1, "kind": "pca-intent-map", "intent_ref": None, "metrics": {"fidelity_est_ppm": 5, "residual_risk_ppm": 1}}
    assert intent_map_shape_error(m) is None and intent_map_shape_error({}) is not None
    att = sign_intent_map_attestation(m, s, 7)
    assert verify_intent_map_attestation(att, m) == {"ok": True}
    assert verify_intent_map_attestation(att, dict(m, metrics={"fidelity_est_ppm": 6, "residual_risk_ppm": 1}))["ok"] is False
    assert verify_intent_map_attestation(dict(att, signed_at=8))["ok"] is False
    ob = sign_intent_observation({"map_digest": att["map_digest"], "verb": "v", "values": {"a": 1}, "y": 1, "source": "runtime", "observed_at": 3}, s)
    assert verify_intent_observation(ob) == {"ok": True}
    assert verify_intent_observation(dict(ob, y=0))["ok"] is False
    with pytest.raises(ValueError):
        sign_intent_observation({"map_digest": "x", "verb": "v", "values": {}, "y": 1, "source": "runtime", "observed_at": 3}, s)

    g = k()
    digest = d32("a")
    t = TransparencyLedger(INTENT_ANCHOR_LOG)
    t.append_commitment(intent_anchor_commit("map", digest))
    h = t.head()
    sth = sign_tree_head(g, {"instance_id": "i", "principal": INTENT_ANCHOR_LOG, "size": h["size"], "root": h["root"], "prev_root": "", "timestamp": 1})
    r = {"kind": "map", "digest": digest, "index": 0, "proof": t.inclusion_proof(0), "signed_tree_head": sth}
    assert verify_intent_anchor(r, g.public, "i") == {"ok": True}
    assert verify_intent_anchor(dict(r, kind="statement"), g.public, "i")["ok"] is False


def test_passport_extras():
    p = {"id": "x", "model_id": "m", "operator": "o", "hardware_rooted": False, "runtime_measurement": "12"}
    assert matches_binding(p, {"model_allowlist": ["m"], "operator": "o"}) == {"ok": True, "reasons": []}
    assert not matches_binding(p, {"require_hardware": True})["ok"]
    assert not matches_binding(p, {"weights_allowlist": ["w"]})["ok"]
    assert matches_binding(p, {"min_measurement": {"svn": 12}})["ok"]
    assert not matches_binding(p, {"min_measurement": {"svn": 13}})["ok"]
    assert not matches_binding(p, {"min_measurement": {"svn": -1}})["ok"]
    assert not matches_binding(p, {"min_measurement": None})["ok"]
    assert trust_score(p) == 0 and trust_score(p, ["o"]) == pytest.approx(0.2)
    assert passport_evidence_binding("i", "s", "n") == {"holderPub": "s", "grantRef": "passport:i", "epoch": 0, "nonce": "n"}


def test_small_helpers_and_builder():
    assert budget_alloc_caveat(3) == {"type": BUDGET_ALLOC_CAVEAT, "limit": 3}
    assert revoke_message("g", "c").startswith(b"atlas-pca/revoke/v1\x00")
    assert revocation_exposure_end(10, 5) == 10 + 5 + 60_000
    assert read_objective_commitment({}) == {}
    assert effective_authority([{"type": "nope"}])["error"].startswith("unknown caveat type")
    assert effective_authority([{"type": "max_amount", "max": 5}, {"type": "max_amount", "max": 3}])["maxAmount"] == 3
    assert revocation_latency_bound({"maxHeadAgeMs": 10, "headIntervalMs": 5})["honest_provers_viable"] is True
    assert revocation_latency_bound({"maxHeadAgeMs": -1, "headIntervalMs": 5})["published_ms"] == float("inf")
    b = policy().allow("stripe", ["refund"]).allow("stripe", ["refund", "pay"]).limit("refund", "$5/day").build()
    assert b["permissions"] == {"stripe": ["refund", "pay"]} and b["limits"] == {"refund": "$5/day"}
    with pytest.raises(ValueError):
        PolicyBuilder().build()
    assert PolicyBuilder.from_template("finance-bot").build()["permissions"] == {"stripe": ["refund"]}


def test_authorize_execution_fails_closed():
    d = authorize_execution({}, {"verb": "v"}, object(), audience="a")
    assert d["allow"] is False and d["kind"] == "config"
