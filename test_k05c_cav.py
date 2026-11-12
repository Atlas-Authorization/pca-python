"""Kill tests (caveat_lang, k3, k4): the malformed-input markers of evaluate_k1, hop attribution, and the exact refusals the
shared vectors do not pin."""
import os

import pytest

from atlas_pca import caveat_lang as CL
from atlas_pca import k3 as K3
from atlas_pca import k4 as K4
from atlas_pca.agent import KeyPair
from atlas_pca.pca import b64u, cap_hash, canonical_bytes_strict, hash_canonical


def test_evaluate_k1_marks_a_malformed_chain():
    r = CL.evaluate_k1(5, None, {}, {"now": 1})
    assert r == {"ok": False, "failed": ["<malformed>"], "reasons": ["malformed capability chain"], "plain": [], "bound": []}


def test_evaluate_k1_marks_an_unsafe_clock():
    for now in ("x", 1.5, None):
        r = CL.evaluate_k1({"caveats": []}, None, {}, {"now": now})
        assert r == {"ok": False, "failed": ["<malformed>"], "reasons": ["the verifier clock is not a safe integer (fail closed)"],
                     "plain": [], "bound": []}, now


def test_evaluate_k1_is_total_and_marks_an_internal_fault():
    class Boom(dict):
        def __contains__(self, k):
            raise ValueError("boom")

    r = CL.evaluate_k1({"caveats": []}, None, Boom(), {"now": 1})
    assert r == {"ok": False, "failed": ["<malformed>"], "reasons": ["caveat language error (fail closed): boom"], "plain": [], "bound": []}


def test_bound_caveats_names_the_hop_that_introduced_each_caveat():
    a, b = {"type": "x", "n": 1}, {"type": "y", "n": 2}
    h0, h1 = {"caveats": [a]}, {"caveats": [a, b]}
    got = CL.bound_caveats(None, [h0, h1])
    assert got == [{"caveat": a, "hop": 0, "cap_hash": cap_hash(h0)}, {"caveat": b, "hop": 1, "cap_hash": cap_hash(h1)}]
    solo = {"caveats": [a, b]}
    assert CL.bound_caveats(solo) == [{"caveat": a, "hop": 0, "cap_hash": cap_hash(solo)}, {"caveat": b, "hop": 0, "cap_hash": cap_hash(solo)}]
    assert CL.bound_caveats(None, [h0, {"caveats": "x"}]) is None


# ---- k3

def test_verify_body_is_false_when_the_body_cannot_be_canonicalised():
    sig = b64u(bytes(64))
    assert K3.verify_body("d", {"a": float("nan")}, b64u(bytes(32)), sig) is False
    assert K3.verify_body("d", {"a": "\ud800"}, b64u(bytes(32)), sig) is False


def test_verify_record_inclusion_is_false_on_a_fault_after_the_head_check(monkeypatch):
    monkeypatch.setattr(K3, "verify_log_head", lambda *a: True)
    assert K3.verify_record_inclusion({}, {}, {}, "s") is False


def test_need_approval_grants_exactly_the_approved_verbs_and_resources(monkeypatch):
    p = KeyPair(os.urandom(32))
    nr = {"status": "pending", "id": "n1", "grant_id": "g1", "needs": [{"verb": "read", "resource": "/r"}, {"verb": "write", "resource": "/w"}]}
    g = {"rev": 1, "principal": p.public, "authority": {}}
    approved = [{"verb": "read", "resource": "/r"}, {"verb": "write", "resource": "/w"}]
    sig = b64u(p.sign(K3.NEED_APPROVE_DOMAIN.encode() + canonical_bytes_strict(K3.need_approve_message(nr, 1, approved))))
    monkeypatch.setattr(K3, "merge_authority", lambda auth, delta: delta)
    assert K3.verify_need_approval(nr, g, approved, sig, True) == {"ok": True, "authority": {"verbs": ["read", "write"], "resources": ["/r", "/w"]}}


# ---- k4

def test_binding_with_an_undecodable_holder_is_malformed():
    grant = {"g": 1}
    b = {"kind": K4.NETWORK_TOKEN_BINDING_KIND, "token_ref": "tok_abcdef12", "provider": "p", "grant_digest": hash_canonical(grant),
         "holder": "!!", "issuer_nonce": "n", "binding_proof": "!!"}
    assert K4.verify_network_token_binding(b, grant, "!!", "n") == "binding_malformed"
    assert K4.verify_network_token_binding(5, grant, "!!", "n") == "binding_malformed"


def test_pricing_config_that_is_not_an_object_is_malformed():
    assert K4.pricing_config_error(5) == "config_malformed"
    assert K4.pricing_config_error({"v": 1}) == "config_malformed"


def test_k4_faults_are_malformed(monkeypatch):
    grant = {"g": float("nan")}  # not strict-canonical: hash_canonical raises after every earlier check passed
    b = {"kind": K4.NETWORK_TOKEN_BINDING_KIND, "token_ref": "tok_abcdef12", "provider": "p", "grant_digest": "d",
         "holder": "h", "issuer_nonce": "n", "binding_proof": "x"}
    assert K4.verify_network_token_binding(b, grant, "h", "n") == "binding_malformed"

    def boom(*a):
        raise RuntimeError("boom")

    monkeypatch.setattr(K4, "_is_minor", boom)
    c = {"v": 1, "principal": "p", "currency": "USD", "sig": "s"}
    assert K4.pricing_config_error(c) == "config_malformed"
