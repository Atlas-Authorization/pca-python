"""Exports the parity re-audit found missing by definition and then ported: parse_intent_goal, provenance_discharge_body,
CORE_TRAIT_IDS. Expectations follow the TypeScript reference."""
import pytest

import atlas_pca as A
from atlas_pca.actions import CORE_TRAIT_DEFS, CORE_TRAIT_IDS


def test_parse_intent_goal_round_trips_and_refuses_malformed():
    assert A.parse_intent_goal(A.intent_goal("r1")) == {"intentRef": "r1"}
    assert A.parse_intent_goal(A.intent_goal("r1", "m1")) == {"intentRef": "r1", "mapDigest": "m1"}
    assert A.parse_intent_goal("pca-intent:v1:r1:m1:extra") is None
    assert A.parse_intent_goal("pca-intent:v1:") is None
    assert A.parse_intent_goal("pca-intent:v1::m") is None
    assert A.parse_intent_goal("other:r1") is None
    assert A.parse_intent_goal(5) is None
    assert A.parse_intent_goal("pca-intent:v1:r1:") == {"intentRef": "r1"}  # an empty map digest is none


REQ = {"caveat_id": "c1", "issuer": "i", "cap_hash": "h", "bind": "action", "action_digest": "ad", "ttl_ms": 1000}


def test_discharge_body_binds_the_request_and_the_gate_claims():
    b = A.provenance_discharge_body(REQ, {"ok": True, "level": 3, "claims": {"slsa_level": 3}}, {"iat": 10, "ttl_ms": 500, "nonce": "n"})
    assert b == {"v": 1, "kind": "pca-discharge", "caveat_id": "c1", "issuer": "i", "cap_hash": "h", "bind": "action", "action_digest": "ad",
                 "claims": {"slsa_level": 3}, "iat": 10, "not_after": 510, "nonce": "n"}
    assert "action_digest" not in A.provenance_discharge_body(dict(REQ, action_digest=None), {"ok": True, "claims": {}}, {"iat": 1, "ttl_ms": 1, "nonce": "n"})


def test_discharge_body_refuses_a_failed_gate_and_an_over_long_ttl():
    with pytest.raises(ValueError, match="refused"):
        A.provenance_discharge_body(REQ, {"ok": False, "code": "no_slsa"}, {"iat": 1, "ttl_ms": 1, "nonce": "n"})
    with pytest.raises(ValueError, match="ttl_ms"):
        A.provenance_discharge_body(REQ, {"ok": True, "claims": {}}, {"iat": 1, "ttl_ms": 1001, "nonce": "n"})


def test_core_trait_ids_follow_the_table():
    assert list(CORE_TRAIT_IDS) == [d["id"] for d in CORE_TRAIT_DEFS] and CORE_TRAIT_IDS[0].startswith("pca.")
