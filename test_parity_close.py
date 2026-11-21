"""Native ports closing the parity audit: chain compaction, discovery, receipts, approvals, key aliases, assurance hooks."""
import pytest

from atlas_pca.agent import DEFAULT_RISK_POLICY, delegate, keypair_from_seed, mint_grant
from atlas_pca.approvals import (approve_class, apply_cosign, batch_review, class_approval_covers, describe_goal_lineage, pending_requests,
                                 record_decision, review_action)
from atlas_pca.caveat_lang import bound_caveats
from atlas_pca.chain_compact import CHAIN_MEMO_MAX_TTL_MS, ChainMemo, compact_chain, compact_chain_shape_error, hops_root
from atlas_pca.discovery import accepts_suite, build_discovery_document, fetch_discovery, parse_discovery_document
from atlas_pca.facade import create_agent
from atlas_pca.pca import decode_key, encode_key, verify_b64u
from atlas_pca.receipt import append_receipt, receipt_head, verify_receipt_chain

P = keypair_from_seed(b"\x01" * 32, allow_insecure_signer=True)
H = keypair_from_seed(b"\x02" * 32, allow_insecure_signer=True)
H2 = keypair_from_seed(b"\x03" * 32, allow_insecure_signer=True)
GRANT = mint_grant(P, H.public, {"predicates": [{"verb": "a", "resource": "b"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}, "g", salt="s")["grant"]
CHAIN = [GRANT, delegate(GRANT, H, H2.public, [])]


def test_chain_compaction_and_memo():
    assert len(hops_root(CHAIN)) == 43 and hops_root(CHAIN) != hops_root(CHAIN[:1])
    memo = ChainMemo()
    c = memo.remember_verified(CHAIN, P.public, 1000)
    assert c == compact_chain(CHAIN) and compact_chain_shape_error(c) is None
    r = memo.resolve(c, 1001)
    assert r["ok"] and r["view"].n == 2 and bound_caveats(GRANT, r["view"]) == bound_caveats(GRANT, CHAIN)
    assert memo.resolve(dict(c, depth=1), 1001)["ok"] is False
    assert memo.resolve(c, 1000 + CHAIN_MEMO_MAX_TTL_MS + 1)["ok"] is False and memo.size == 0
    with pytest.raises(ValueError):
        ChainMemo().remember_verified(CHAIN, H.public, 1000)  # wrong root issuer: never remembered
    assert memo.resolve(c, 1001)["ok"] is False


def test_discovery_round_trip():
    doc = build_discovery_document("https://rs", intent={"versions": [1, 2], "tiers": {"v": 3}})
    assert parse_discovery_document(doc) == doc and accepts_suite(doc, "ed25519")
    for bad in ({"versions": [3]}, {"versions": [1], "x": 1}, {"versions": [1], "tiers": {"v": 5}}):
        with pytest.raises(ValueError):
            build_discovery_document("https://rs", intent=bad)

    class R:
        ok, status = True, 200
        json = staticmethod(lambda: doc)
    seen = []
    assert fetch_discovery("https://rs/", lambda u, i: seen.append(u) or R) == doc and seen == ["https://rs/.well-known/pca-configuration"]


def test_receipt_chain_detects_tamper():
    p = {"iat": 5, "action": {"verb": "v", "resource": "r"}}
    log = append_receipt(append_receipt([], p, {"allow": True, "checks": {"a": "pass"}}), p, {"allow": False})
    assert verify_receipt_chain(log) == {"ok": True} and receipt_head(log) == log[-1]["hash"]
    log[0]["verb"] = "x"
    assert verify_receipt_chain(log)["brokenAt"] == 0


def test_key_aliases():
    assert decode_key(encode_key(b"\x01" * 32)) == b"\x01" * 32 and verify_b64u("!", b"m", "!") is False


def test_approvals():
    a = create_agent(P, "refund customers", {"stripe": ["refund"]}, {"stripe.refund": "$500/day"}, now=1000)
    assert review_action(a, "stripe.refund", "charges/1", {"amount": 450}, now=1001)["kind"] == "deny"  # no renderer
    r = review_action(a, "stripe.refund", "charges/1", {"amount": 450}, now=1001, goal="refund customers", insecure_unbound_approval=True)
    assert r["kind"] == "step_up" and r["request"]["lineage"]["goalVerified"] is True
    assert describe_goal_lineage(r["request"]["lineage"])[0].endswith("opens the signed grant commitment")
    assert pending_requests(batch_review(a, [{"verb": "stripe.refund", "resource": "c", "params": {"amount": 450}}], now=1001,
                                         insecure_unbound_approval=True))[0]["tier"] in (2, 3)
    ca = approve_class(["stripe.refund"], ttl_ms=1000, by="me", now=1001)
    assert class_approval_covers(ca, "stripe.refund", "x", 1500) and not class_approval_covers(ca, "stripe.refund", "x", 2001)
    assert review_action(a, "stripe.refund", "c", {"amount": 450}, now=1500, standing=[ca])["kind"] == "auto"
    assert record_decision(r["request"], "approve", "me", 9)["requestId"] == r["request"]["id"]
    assert apply_cosign({"B": 0, "tau": 0, "asOf": 0}, a.policy["riskPolicy"], 5)["B"] > 0


def test_assurance_report_reads_hook_labels():
    from atlas_pca.authorize import assurance_report, set_assurance_label
    zk = set_assurance_label(lambda *a: None, "groth16", ceremony="multi-party")
    rep = assurance_report({"zk_compliance": {}}, {"zk_compliance": "pass"}, hooks={"zk": zk})
    assert rep["zk_compliance"] == {"outcome": "pass", "level": "groth16", "ceremony": "multi-party"}


def test_threshold_verifier_and_baseline():
    from atlas_pca.agent import Agent
    from atlas_pca.pca import threshold_message
    from atlas_pca.threshold import assemble_threshold, create_threshold_verifier, sign_share, verify_threshold
    ss = [{"role": "agent", "publicKey": H.public}, {"role": "guardian", "publicKey": H2.public}]
    p = Agent(H, GRANT, "aud").act("a", "b", {}).pcactn
    m = threshold_message(p)
    assert create_threshold_verifier(ss, t=1)(p, GRANT, {"t": 1}) == {"enforced": True, "ok": True, "t": 1}  # the leaf signature is the baseline
    two = create_threshold_verifier(ss, t=2)
    assert two({"pcactn": p, "grant": GRANT})["ok"] is False
    shared = dict(p, threshold=assemble_threshold([sign_share("guardian", H2, m, ss, 2)]))
    assert two(shared, GRANT, {"t": 2})["ok"] is True
    # a share bound to another threshold never counts
    bad = dict(p, threshold=assemble_threshold([sign_share("guardian", H2, m, ss, 3)]))
    assert two(bad, GRANT, {"t": 2})["ok"] is False
    assert verify_threshold(assemble_threshold([]), m, ss, 7)["reason"].startswith("invalid threshold")
    with pytest.raises(TypeError):
        create_threshold_verifier(ss)


def test_less_signing_through_the_c_library_when_present():
    from atlas_pca.agent import generate_pq_keypair, sign_with_suite
    from atlas_pca.pca import verify_leaf_suite
    from atlas_pca.pq_backends import less_can_sign
    if not less_can_sign():
        return  # the pca-less-c library is not built here: LESS stays verify-only and signing refuses with unsupported_suite
    kp = generate_pq_keypair("LESS-cat1", b"\x07" * 32, sign_seed=b"\x08" * 32)
    parts = sign_with_suite("less-cat1", None, kp, b"msg")
    assert verify_leaf_suite({"alg": "less-cat1", "sig": parts["sig"], "pq_pk": kp.public}, None, b"msg")
    assert sign_with_suite("less-cat1", None, kp, b"msg") == parts  # a pinned signing seed repeats the signature


def test_status_aliases_and_small_ports():
    from atlas_pca.doctor import probe_decision
    from atlas_pca.lease import memory_lease_kv
    from atlas_pca.mldsa import ML_DSA_87_PUBLIC_KEY_BYTES
    from atlas_pca.pca import DecideInputGrantRequired, is_budget_alloc_caveat, plan_node_leaf
    from atlas_pca.testing import first_failed_check
    assert first_failed_check({"a": "pass", "b": "fail", "c": "fail"}) == "b" and first_failed_check({"a": "pass"}) is None
    assert probe_decision({"type": "max_spend", "usd": 100}, 150)["allowed"] is False
    assert memory_lease_kv() is not memory_lease_kv() and ML_DSA_87_PUBLIC_KEY_BYTES == 2592
    assert is_budget_alloc_caveat({"type": "budget_alloc", "limit": 0}) and not is_budget_alloc_caveat({"type": "budget_alloc", "limit": -1})
    assert plan_node_leaf({"id": "n", "verb": "v", "resource": "r"})["node_id"] == "n" and DecideInputGrantRequired.code == "grant_required"


def test_rag_filter_fails_closed():
    from atlas_pca.rag import acls_from_metadata, filter_documents, principal_from_pcactn, with_pca_filter
    policy = [{"verb": "viewer", "resource": "document:readme", "where": [{"field": "subject.id", "op": "eq", "value": "user:alice"}]}]
    docs = [{"id": "a", "acl": {"relation": "viewer", "object": "document:readme"}}, {"id": "b", "tags": ["viewer:document:secret"]}, {"id": "c"}]
    res = filter_documents("user:alice", docs, policy)
    assert [d["id"] for d in res["documents"]] == ["a"] and res["decision"]["droppedIds"] == ["b", "c"]
    assert filter_documents("user:bob", docs, policy)["documents"] == []
    assert filter_documents("user:alice", docs, "not a policy")["decision"]["policyIncomplete"] is True  # an unusable policy admits nothing
    assert acls_from_metadata(None, ["viewer:document:x:y", "bad", ":x"]) == [{"relation": "viewer", "object": "document:x:y"}]
    assert principal_from_pcactn({"cap_chain": [{"holder": "h"}]}) == {"id": "h"}

    class Retriever:
        def retrieve(self, q, k=None):
            return docs
    w = with_pca_filter(Retriever(), "user:alice", policy)
    assert [d["id"] for d in w.retrieve("q")] == ["a"] and w.last_decision()["allowedIds"] == ["a"]


def test_pack_build_chain_and_upgrade():
    from atlas_pca.actions_builtin import BUILTIN_DEFS
    from atlas_pca.actions_pack import build_pack, shard_defs, verify_upgrade
    from atlas_pca.actions_registry import verify_pack
    secret = b"\x05" * 32
    keys = [{"kid": "k1", "alg": "ed25519", "pk": keypair_from_seed(secret, allow_insecure_signer=True).public}]
    src = {"kind": "test", "uri": "x", "spec_digest": "d", "licence": "MIT", "licence_notes": ""}
    ns = BUILTIN_DEFS[0]["verb"].split(".")[0]
    v1 = build_pack(ns, "1.0.0", "beta", BUILTIN_DEFS[:5], src, "k1", secret)
    assert verify_pack(v1["pack"], keys)["ok"] is True
    v2 = build_pack(ns, "1.0.1", "beta", BUILTIN_DEFS[:6], src, "k1", secret, prev=v1)
    assert verify_upgrade(v1["pack"], v2["pack"], keys) == {"ok": True}
    assert verify_upgrade(v2["pack"], v1["pack"], keys)["ok"] is False  # a downgrade never verifies
    with pytest.raises(Exception):
        build_pack(ns, "1.0.0", "beta", BUILTIN_DEFS[:6], src, "k1", secret, prev=v1)  # the version must increase
    sharded = build_pack(ns, "1.1.0", "beta", BUILTIN_DEFS[:6], src, "k1", secret, shard={"max": 2})
    assert verify_pack(sharded["pack"], keys, sharded["shards"])["ok"] is True and len(sharded["shards"]) >= 2
    assert [s["name"] for s in shard_defs(BUILTIN_DEFS[:3], 1)][0].endswith("-1")


def test_policy_vm_decide_and_party_vector():
    from atlas_pca.agent import Agent
    from atlas_pca.mpc import evaluate_party
    from atlas_pca.policy_vm import decide, derive_decide_input
    grant = mint_grant(P, H.public, {"predicates": [{"verb": "pay", "resource": "invoice:*"}], "caveats": [{"type": "max_spend", "usd": 100}],
                                     "risk_policy": DEFAULT_RISK_POLICY}, "g", salt="s")["grant"]
    risk = {"reversibility": 1, "blastRadius": 0, "confidence": 1, "semanticDistance": 0, "taint": 0}
    budget = {"B": 1e9, "tau": 10, "asOf": 10}

    def run(amount):
        return decide({"grant": grant, "chain": [grant], "trustedRoot": grant, "risk": risk, "budget": budget, "now": 10,
                       "action": {"action": {"verb": "pay", "resource": "invoice:42", "params": {"amount": amount, "currency": "usd"},
                                             "reversibility_class": "reversible"}}})
    assert run(50)["releaseGuardianShare"] is True
    over = run(150)
    assert over["releaseGuardianShare"] is False and over["reasons"] == ["caveat(s) not satisfied: max_spend"]
    # an unverified chain is a denial: the chain below is not rooted at this grant's issuer
    other = mint_grant(H, H.public, {"predicates": [{"verb": "pay", "resource": "*"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}, "g", salt="s")["grant"]
    assert decide({"grant": grant, "chain": [other], "risk": risk, "budget": budget, "now": 10,
                   "action": {"action": {"verb": "pay", "resource": "invoice:1"}}})["releaseGuardianShare"] is False
    inp = derive_decide_input(Agent(H, grant, "aud").act("pay", "invoice:1", {"amount": 5}).pcactn, grant=grant, risk=risk, budget=budget, now=10, params={"amount": 5})
    assert decide(inp)["releaseGuardianShare"] is True and evaluate_party({"decideInput": inp}).allow == 1


def test_fhe_origin_authentication_without_the_native_library():
    from atlas_pca.fhe_risk import (attest_verdict, fhe_risk_policy, memory_nonce_guard, plaintext_verdict, quantize_risk_inputs, sign_risk_claim,
                                    signed_claim_digest, verify_signed_risk_claim, verify_verdict_attestation)
    pol = fhe_risk_policy(DEFAULT_RISK_POLICY, 0.6)
    assert pol["weightsScaled"] == [250, 200, 200, 200, 100, 50] and pol["budgetScaled"] == 600_000
    inputs = {"semanticDistance": 0.1, "reversibility": 0.9, "blastRadius": 0.1, "taint": 0.1, "confidence": 0.9, "age": 0.1}
    assert quantize_risk_inputs(inputs) == [100] * 6 and plaintext_verdict(inputs, DEFAULT_RISK_POLICY, 0.6)["admit"] is True
    claim = {"binding": {"aud": "a", "actionRef": "r", "counter": 1}, "encInputs": "QUJD", "policy": pol}
    signed = sign_risk_claim(claim, P, "grant-1")
    expect = {"trustedSigners": [P.public], "context": "grant-1", "binding": claim["binding"], "policy": pol, "nonces": memory_nonce_guard()}
    assert verify_signed_risk_claim(signed, expect)["ok"] is True
    assert "replay" in verify_signed_risk_claim(signed, expect)["reason"]  # a nonce is single use
    assert verify_signed_risk_claim(dict(signed, context="other"), dict(expect, nonces=memory_nonce_guard()))["ok"] is False
    assert verify_signed_risk_claim(signed, dict(expect, trustedSigners=[H.public], nonces=memory_nonce_guard()))["reason"] == "signer is not a trusted encryptor"
    gate = {"encRiskRaw": "AAAA", "encSlack": "BBBB"}
    att = attest_verdict(H, signed, gate, True)
    ok = {"trustedHolders": [H.public], "claimDigest": signed_claim_digest(signed), "gate": gate}
    assert verify_verdict_attestation(att, ok) == {"ok": True, "admit": True}
    assert verify_verdict_attestation(dict(att, admit=False), ok)["ok"] is False  # the signed decision cannot be flipped
