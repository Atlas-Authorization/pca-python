"""The small public surface of atlas_pca.pca_surface and atlas_pca.pq_suites: cheap chain check, discharge requests, obligations, detector
policy fold, cheap claims, hash suites, composite signatures and the constants."""
import hashlib

import pytest

from atlas_pca.agent import DEFAULT_RISK_POLICY, Agent, delegate, keypair_from_seed, mint_grant
from atlas_pca.pca_surface import (EXECUTION_REQUIRED_CHECKS, REPLAY_MIN_RETENTION_MS, b64u_len, collect_obligations, detector_policy_error,
                                   detector_signal, discharge_requests, hash_with_suite, holder_pq_key, is_canonical_b64u, is_hash_suite,
                                   pcactn_cheap_claims, verify_chain_cheap, verify_goal_commit, verify_membership)
from atlas_pca.pq_suites import (COMPOSITE_SIGNATURE_BYTES, composite_representative, composite_verify, encode_ml_dsa_public_key,
                                 is_known_sig_alg, is_well_formed_pq_public_key, less_backend_status)

P = keypair_from_seed(b"\x01" * 32, allow_insecure_signer=True)
H = keypair_from_seed(b"\x02" * 32, allow_insecure_signer=True)
H2 = keypair_from_seed(b"\x03" * 32, allow_insecure_signer=True)
GRANT = mint_grant(P, H.public, {"predicates": [{"verb": "a", "resource": "b"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}, "g", salt="s")["grant"]


def test_cheap_chain_check_and_holder_pq_key():
    chain = [GRANT, delegate(GRANT, H, H2.public, [])]
    assert verify_chain_cheap(chain, P.public) == {"ok": True, "pqHops": 0}
    assert verify_chain_cheap([], None)["reason"] == "empty chain"
    assert verify_chain_cheap(chain, H.public)["reason"] == "hop 0: root issuer is not the expected principal"
    assert verify_chain_cheap([chain[1], chain[0]], None)["ok"] is False  # a reordered chain breaks its parent links
    assert holder_pq_key("ed25519", H.public, None, None) == {} and holder_pq_key("ml-dsa-65", H.public, "x", None) == {}


def test_cheap_claims_and_hash_helpers():
    p = Agent(H, GRANT, "rs", clock=lambda: 1_000).act("a", "b", {}).pcactn
    assert pcactn_cheap_claims(p, "rs", 1_000) is None and pcactn_cheap_claims(p, "other", 1_000)["check"] == "audience"
    assert pcactn_cheap_claims(p, "rs", p["exp"] + 1)["reason"] == "the PCActn has expired"
    assert REPLAY_MIN_RETENTION_MS == 3_600_000 + 120_000 and "policy" in EXECUTION_REQUIRED_CHECKS
    assert hash_with_suite(b"x") == hashlib.sha256(b"x").digest() and len(hash_with_suite(b"x", "sha384")) == 48
    assert is_hash_suite("sha384") and not is_hash_suite("md5") and b64u_len(32) == 43 and is_canonical_b64u("A" * 43, 32)
    assert verify_goal_commit("nope", "g", "s") is False
    assert verify_membership("r", {"size": 1, "index": 0, "path": []}, "id") is False


def test_discharge_requests_and_obligations():
    cav = {"type": "needs_discharge", "id": "d1", "issuer": H.public, "bind": "chain_hop", "require": [{"claim": "age", "op": "eq", "value": 1}], "ttl_ms": 1000}
    g = mint_grant(P, H.public, {"predicates": [{"verb": "a", "resource": "b"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}, "g", salt="s")["grant"]
    assert discharge_requests(g, None) == []  # a grant without a discharge caveat asks for nothing
    assert collect_obligations(None, {}) == {"ok": True, "obligations": []}
    assert collect_obligations("x", {})["ok"] is False and cav["id"] == "d1"


def test_detector_policy_and_fold_fail_closed():
    assert detector_policy_error({"detectors": []}) is None and detector_policy_error({}) == "policy must be {detectors}"
    bad = detector_signal({"nope": 1}, 1)
    assert bad["signal"] == "deny" and bad["rejected"][0]["index"] == -1
    ok = detector_signal({"detectors": [{"id": "d1", "keys": [{"pk": "k"}], "on_suspicious": "deny", "max_age_ms": 1000}]}, 1, receipts=[])
    assert ok["signal"] == "ok" and ok["env"]["detect"] == {"d1": False, "invalid": 0}
    junk = detector_signal({"detectors": [{"id": "d1", "keys": [{"pk": "k"}], "on_suspicious": "deny", "max_age_ms": 1000}]}, 1, receipts=[{"x": 1}])
    assert junk["signal"] == "escalate" and junk["rejected"][0]["reason"].startswith("malformed")


def test_composite_and_suite_guards():
    m = composite_representative(b"msg", "ctx")
    assert m.startswith(b"CompositeAlgorithmSignatures2025COMPSIG-MLDSA65-Ed25519-SHA512\x03ctx") and len(m) == 32 + 30 + 1 + 3 + 64
    with pytest.raises(ValueError):
        composite_representative(b"m", b"x" * 256)
    assert composite_verify(b"\x00" * 32, b"\x00" * 1952, b"m", b"short") is False and COMPOSITE_SIGNATURE_BYTES == 3373
    assert is_known_sig_alg("ml-dsa-65") and not is_known_sig_alg("rot13") and is_well_formed_pq_public_key(encode_ml_dsa_public_key(b"\x00" * 1952))
    assert set(less_backend_status()) <= {"available", "reason"}
