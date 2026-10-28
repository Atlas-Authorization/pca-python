"""The agent / issuer side (atlas_pca.agent): replays packages/pca/conformance/producer-vectors.json byte for byte (fixed keys,
nonces and timestamps; Ed25519 is deterministic), and round-trips everything it produces through this package's own verifiers
(and, when ML-DSA is available, the hybrid / pure PQ suites)."""
import json
import os
import unittest

from atlas_pca import supported_suites, verify_chain, verify_passport, verify_pcactn_core
from atlas_pca.agent import (Agent, KeyPair, PqKeyPair, build_escalation_request, commit_plan, delegate, escalation_action_digest,
                             escalation_history_head, escalation_policy_digest, generate_keypair, generate_pq_keypair,
                             goal_commit_of, issue_passport, keypair_from_seed, mint_grant, mint_root, pca_headers,
                             sign_aggregate_grant, sign_discharge, sign_escalation_answer, sign_fresh_at, sign_narrow,
                             sign_passport, sign_read_grant, sign_step_receipt, sign_workflow, discharge_digest,
                             DEFAULT_RISK_POLICY)
from atlas_pca.escalation import verify_escalation_answer
from atlas_pca.pca import b64u, canonicalize, decode_pca_header, hash_canonical, params_digest, strict_parse, unb64u

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "producer-vectors.json")
with open(FILE, encoding="utf-8") as f:
    DOC = json.load(f)
KEYS = {n: keypair_from_seed(k["seed"]) for n, k in DOC["keys"].items()}


def _caveat_args(a):
    return a["added_caveats"]


def run(c):
    a, op = c["args"], c["op"]
    if op == "ed25519_sign":
        k = keypair_from_seed(a["seed"])
        return {"public": k.public, "sig": b64u(k.sign(a["message_utf8"].encode("utf-8")))}
    if op == "goal_commit":
        return {"commit": goal_commit_of(a["goal"], a["salt"])}
    if op == "params_digest":
        return {"digest": params_digest(a["params"])}
    if op == "plan_commit":
        p = commit_plan(a["nodes"])
        return {"root": p["root"], "proofs": {n["id"]: p["proof_for"](n["id"]) for n in a["nodes"]}}
    if op == "mint_grant":
        r = mint_grant(KEYS[a["principal"]], KEYS[a["holder"]].public, a["envelope"], a["goal"], a["salt"])
        return r
    if op == "delegate":
        to = KEYS[a["to_holder"]].public if a["to_holder"] else None
        return delegate(a["parent"], KEYS[a["signer"]], to, a["added_caveats"])
    if op == "act":
        from atlas_pca.agent import build_pcactn
        p = build_pcactn(a["grant"], a["chain"], a["plan"], a["node_id"], a["counter"], KEYS[a["signer"]], a["aud"],
                         params=a.get("params"), iat=a["iat"], exp=a["exp"], nonce=a.get("nonce"), caution=a.get("caution"),
                         rationale_commitment=a.get("rationale_commitment"), tool_binding=a.get("tool_binding"),
                         fresh_at=a.get("fresh_at"))
        return {"pcactn": p, "header": pca_headers(p)["PCA-Action"]}
    if op == "fresh_at":
        return sign_fresh_at(KEYS[a["signer"]], a["scope"], a["state"], a["issued_at"])
    if op == "escalation_digests":
        return {"policy_digest": escalation_policy_digest(a["grant"]), "action_digest": escalation_action_digest(a["pcactn"]),
                "history_head": escalation_history_head(a["last_counter"])}
    if op == "sign_escalation_answer":
        b = a["body"]
        return sign_escalation_answer(KEYS[a["signer"]], b, b["decision"], b["iat"], b["expires_at"], b["nonce"], b.get("render_digest"))
    if op == "sign_discharge":
        b = a["body"]
        return sign_discharge(KEYS[a["signer"]], b["caveat_id"], b["issuer"], b["cap_hash"], b["claims"], b["iat"], b["not_after"],
                              b["bind"], b.get("action_digest"), b["nonce"])
    if op == "discharge_digest":
        return {"digest": discharge_digest(a["discharge"])}
    if op == "sign_narrow":
        b = a["body"]
        return sign_narrow(KEYS[a["signer"]], b["cap_hash"], b["caveats"], b["iat"], b["not_after"], b.get("action_digest"), b["nonce"])
    if op == "sign_passport":
        pp = issue_passport(a["identity"])
        return {"passport": pp, "signed": sign_passport(pp, KEYS[a["issuer"]], KEYS[a["subject"]].public, a["exp"])}
    if op == "sign_workflow":
        return sign_workflow(KEYS[a["signer"]], a["body"])
    if op == "sign_step_receipt":
        return sign_step_receipt(KEYS[a["signer"]], a["workflow"], a["step"], a["outcome"], a["params_digest"], a["outputs"],
                                 a["issued_at"], a.get("prev"))
    if op == "sign_read_grant":
        return sign_read_grant(KEYS[a["signer"]], a["body"])
    if op == "sign_aggregate_grant":
        return sign_aggregate_grant(KEYS[a["signer"]], a["body"])
    raise AssertionError("unknown op " + op)


class ProducerVectors(unittest.TestCase):
    def test_vectors(self):
        self.assertGreaterEqual(len(DOC["cases"]), 34)
        bad = []
        for c in DOC["cases"]:
            got, want = run(c), c["expect"]
            want = dict(want)
            want.pop("threshold_message", None)
            if json.loads(json.dumps(got)) != want:
                bad.append(c["name"])
        self.assertEqual(bad, [])


class RoundTrip(unittest.TestCase):
    def setUp(self):
        self.principal, self.agent_key = generate_keypair(), generate_keypair()
        env = {"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "agent_binding": {},
               "risk_policy": DEFAULT_RISK_POLICY}
        self.minted = mint_grant(self.principal, self.agent_key.public, env, "refund an order")
        self.grant = self.minted["grant"]

    def test_chain_verifies(self):
        sub = generate_keypair()
        att = delegate(self.grant, self.agent_key, None, [{"type": "budget_alloc", "limit": 5}])
        leaf = delegate(att, self.agent_key, sub.public, [{"type": "sealed"}])
        ok, reason = verify_chain([self.grant, att, leaf], self.principal.public)
        self.assertTrue(ok, reason)

    def test_agent_act_core_verifies(self):
        agent = Agent(self.agent_key, self.grant, "rs-test")
        a1 = agent.act("refund", "orders/1", {"amount_cents": 500})
        a2 = agent.act("refund", "orders/1", {"amount_cents": 500})
        self.assertEqual((a1.pcactn["counter"], a2.pcactn["counter"]), (1, 2))
        self.assertNotEqual(a1.pcactn["nonce"], a2.pcactn["nonce"])
        v = verify_pcactn_core(decode_pca_header(a1.headers["PCA-Action"]), self.grant, audience="rs-test")
        self.assertTrue(v.allow, v.reason)
        tampered = dict(a1.pcactn, counter=9)
        self.assertFalse(verify_pcactn_core(tampered, self.grant, audience="rs-test").allow)

    def test_agent_subdelegate_core_verifies(self):
        sub = generate_keypair()
        child = Agent(self.agent_key, self.grant, "rs-test").delegate(sub, [{"type": "sealed"}])
        a = child.act("refund", "orders/2", {"amount_cents": 1})
        v = verify_pcactn_core(a.pcactn, self.grant, audience="rs-test")
        self.assertTrue(v.allow, v.reason)

    def test_plan_node_proof(self):
        nodes = [{"id": "a", "verb": "read", "resource": "x"}, {"id": "b", "verb": "refund", "resource": "orders/1"}]
        agent = Agent(self.agent_key, self.grant, "rs-test").use_plan(nodes)
        v = verify_pcactn_core(agent.act("refund", "orders/1").pcactn, self.grant, audience="rs-test")
        self.assertTrue(v.allow, v.reason)

    def test_escalation_answer_verifies(self):
        agent = Agent(self.agent_key, self.grant, "rs-test")
        p = agent.act("refund", "orders/1").pcactn
        now = p["iat"]
        req = build_escalation_request("rs-test", self.grant, p, 0, ["escalate: big refund"], now)
        ans = sign_escalation_answer(self.principal, req, "allow", now, now + 60_000)
        bind = {k: req[k] for k in ("policy_digest", "action_digest", "history_head")}
        r = verify_escalation_answer(ans, [self.principal.public], bind, now)
        self.assertTrue(r["ok"], r)
        self.assertFalse(verify_escalation_answer(dict(ans, decision="deny"), [self.principal.public], bind, now)["ok"])

    def test_passport_verifies(self):
        issuer, subject = generate_keypair(), generate_keypair()
        pp = issue_passport({"model_id": "m", "operator": "acme", "hardware_rooted": False, "issued_at": 1_800_000_000_000})
        sp = sign_passport(pp, issuer, subject.public, 1_800_003_600_000)
        self.assertIsNone(verify_passport(sp, [issuer.public], 1_800_000_000_500, revoked=lambda *_: False))

    def test_hardware_rooted_passport_needs_evidence(self):
        pp = issue_passport({"model_id": "m", "operator": "acme", "hardware_rooted": True, "issued_at": 1})
        with self.assertRaises(ValueError):
            sign_passport(pp, generate_keypair(), generate_keypair().public, 99)

    def test_refuses_bad_input(self):
        with self.assertRaises(ValueError):
            mint_grant(self.principal, self.agent_key.public, {"predicates": [], "caveats": [], "risk_policy": {}}, "g")
        with self.assertRaises(ValueError):
            mint_grant(self.principal, self.agent_key.public, {"predicates": [], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}, "")
        with self.assertRaises(ValueError):
            Agent(self.agent_key, self.grant, "rs").use_plan([]).act("x", "y")


class Refusals(unittest.TestCase):
    """Exact-outcome kill tests for the producer's refusal paths, counters, nonces and header encoding (mutation-tested module)."""

    def setUp(self):
        self.principal, self.key = generate_keypair(), generate_keypair()
        self.env = {"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}
        self.grant = mint_grant(self.principal, self.key.public, self.env, "g", salt="s")["grant"]

    def test_seeds(self):
        for n in (0, 31, 33, 64):
            with self.assertRaisesRegex(ValueError, "^an Ed25519 seed is 32 bytes$"):
                keypair_from_seed(b"\x01" * n)
        k = keypair_from_seed(b"\x01" * 32)
        self.assertEqual(k.public, keypair_from_seed(b64u(b"\x01" * 32)).public)
        self.assertNotIn(b64u(b"\x01" * 32), repr(k))
        self.assertEqual(len(unb64u(k.public)), 32)
        self.assertEqual(len(k.sign(b"m")), 64)

    def test_unsupported_and_unknown_suite(self):
        from atlas_pca.agent import UnsupportedSuite, sign_artifact, sign_with_suite
        for alg in ("fn-dsa-512", "fn-dsa-1024", "less-cat1", "hybrid-ed25519-less-cat1"):
            with self.assertRaises(UnsupportedSuite) as c:
                sign_with_suite(alg, self.key, None, b"m")
            self.assertEqual(str(c.exception), "unsupported_suite: " + alg)
        with self.assertRaisesRegex(ValueError, "^unknown signature alg 'rot13'$"):
            sign_with_suite("rot13", self.key, None, b"m")
        with self.assertRaisesRegex(TypeError, "^'ed25519' needs an Ed25519 key$"):
            sign_with_suite(None, None, None, b"m")
        with self.assertRaisesRegex(TypeError, "^'ml-dsa-65' needs a ML-DSA-65 key pair$"):
            sign_with_suite("ml-dsa-65", self.key, None, b"m")
        with self.assertRaisesRegex(TypeError, "^'ml-dsa-65' needs a PQ key pair$"):
            sign_artifact("d", {"v": 1}, self.key, alg="ml-dsa-65")
        out = sign_artifact("d", {"v": 1}, self.key, alg="ed25519")
        self.assertEqual(sorted(out), ["sig", "v"])

    def test_mint_grant_refusals(self):
        def mg(env=None, goal="g", **kw):
            return mint_grant(self.principal, self.key.public, env if env is not None else self.env, goal, **kw)
        with self.assertRaisesRegex(ValueError, "^mint_grant: goal required$"):
            mg(goal="")
        with self.assertRaisesRegex(ValueError, "^mint_grant: risk_policy.weights missing$"):
            mg(dict(self.env, risk_policy={}))
        rp = dict(DEFAULT_RISK_POLICY, weights=dict(DEFAULT_RISK_POLICY["weights"], alpha=-1))
        with self.assertRaisesRegex(ValueError, "^mint_grant: risk_policy.weights.alpha must be finite and >= 0$"):
            mg(dict(self.env, risk_policy=rp))
        with self.assertRaisesRegex(ValueError, "^mint_grant: risk_policy.theta1 must be finite$"):
            mg(dict(self.env, risk_policy={k: v for k, v in DEFAULT_RISK_POLICY.items() if k != "theta1"}))
        with self.assertRaisesRegex(ValueError, "^mint_grant: risk_policy requires 0 <= theta1 <= theta2$"):
            mg(dict(self.env, risk_policy=dict(DEFAULT_RISK_POLICY, theta1=0.7)))
        with self.assertRaisesRegex(ValueError, "^mint_grant: risk_policy.kappa must be > 0$"):
            mg(dict(self.env, risk_policy=dict(DEFAULT_RISK_POLICY, kappa=0)))
        with self.assertRaisesRegex(ValueError, "^mint_grant: risk_policy lambda/rho/bMax must be >= 0$"):
            mg(dict(self.env, risk_policy=dict(DEFAULT_RISK_POLICY, rho=-1)))
        with self.assertRaisesRegex(ValueError, "^mint_grant: model_polarity must be 'legacy' when present$"):
            mg(dict(self.env, model_polarity="strict"))
        r = mg(salt="abc")
        self.assertEqual(r["goal_salt"], "abc")
        self.assertEqual(r["goal_commit"], goal_commit_of("g", "abc"))
        self.assertEqual(len(unb64u(mg()["goal_salt"])), 16)

    def test_delegate_appends_only_and_keeps_holder_pq(self):
        a = {"type": "budget_alloc", "limit": 5}
        child = delegate(self.grant, self.key, None, [a])
        self.assertEqual(child["caveats"], self.grant["caveats"] + [a])
        self.assertEqual(child["holder"], self.key.public)
        self.assertEqual(child["issuer"], self.key.public)
        self.assertEqual(child["parent"], hash_canonical(self.grant))
        g = mint_grant(self.principal, self.key.public, self.env, "g", holder_pq="PQKEY")["grant"]
        self.assertIn("holder_pq", delegate(g, self.key, None, []))
        self.assertNotIn("holder_pq", delegate(g, self.key, generate_keypair().public, []))

    def test_plan_and_params_refusals(self):
        from atlas_pca.agent import build_pcactn
        node = {"id": "a", "verb": "v", "resource": "r"}
        base = dict(grant=self.grant, chain=[self.grant], plan=[node], node_id="a", counter=1, signer=self.key, aud="x")
        with self.assertRaisesRegex(ValueError, "^build_pcactn: aud \\(audience\\) is required$"):
            build_pcactn(**dict(base, aud=""))
        with self.assertRaisesRegex(ValueError, "^build_pcactn: unknown plan node zz$"):
            build_pcactn(**dict(base, node_id="zz"))
        with self.assertRaisesRegex(ValueError, "^build_pcactn: params do not match plan node a's params_digest$"):
            build_pcactn(**dict(base, plan=[dict(node, params_digest=params_digest({"x": 1}))], params={"x": 2}))
        with self.assertRaisesRegex(ValueError, "^commit_plan: duplicate node id a$"):
            commit_plan([node, node])
        p = build_pcactn(**dict(base, iat=1000))
        self.assertEqual((p["iat"], p["exp"]), (1000, 1000 + 20 * 60_000))
        self.assertEqual(p["action"]["reversibility_class"], "reversible")
        self.assertEqual(build_pcactn(**dict(base, iat=1000, exp=5000))["exp"], 5000)
        self.assertEqual(build_pcactn(**dict(base, iat=1000, ttl_ms=7))["exp"], 1007)

    def test_counter_nonce_and_hook(self):
        seen = []
        agent = Agent(self.key, self.grant, "rs", counter=41, on_counter=seen.append, clock=lambda: 5000)
        a = [agent.act("v", "r") for _ in range(3)]
        self.assertEqual([x.pcactn["counter"] for x in a], [42, 43, 44])
        self.assertEqual(seen, [42, 43, 44])
        self.assertEqual(len({x.pcactn["nonce"] for x in a}), 3)
        for x in a:
            self.assertEqual(len(unb64u(x.pcactn["nonce"])), 16)
            self.assertEqual((x.pcactn["iat"], x.pcactn["exp"], x.pcactn["aud"]), (5000, 5000 + 20 * 60_000, "rs"))
        sub = agent.delegate(generate_keypair())
        self.assertEqual(sub.act("v", "r").pcactn["counter"], 1)
        self.assertEqual(len(sub.chain), 2)
        with self.assertRaisesRegex(ValueError, "^act: no node of the committed plan matches v nope$"):
            Agent(self.key, self.grant, "rs").use_plan([{"id": "a", "verb": "v", "resource": "r"}]).act("v", "nope")

    def test_header_encoding(self):
        agent = Agent(self.key, self.grant, "rs")
        act = agent.act("v", "r")
        self.assertEqual(list(act.headers), ["PCA-Action"])
        h = act.headers["PCA-Action"]
        self.assertNotIn("=", h)
        self.assertEqual(decode_pca_header(h), canonicalize(act.pcactn))
        disc, narrow, ans = {"d": 1}, {"n": 2}, {"a": 3}
        full = pca_headers(act.pcactn, discharges=[disc], narrow=narrow, escalation_answer=ans, fresh_at={"f": 4})
        self.assertEqual(sorted(full), ["PCA-Action", "PCA-Discharges", "PCA-Escalation-Answer", "PCA-Narrow", "pca-fresh-at"])
        self.assertEqual(decode_pca_header(full["PCA-Discharges"]), '[{"d":1}]')
        self.assertEqual(decode_pca_header(full["PCA-Narrow"]), '{"n":2}')
        self.assertEqual(decode_pca_header(full["PCA-Escalation-Answer"]), '{"a":3}')
        self.assertEqual(full["pca-fresh-at"], '{"f":4}')
        self.assertEqual(list(pca_headers(act.pcactn, discharges=[])), ["PCA-Action"])

    def test_signer_and_answer_refusals(self):
        other = generate_keypair()
        for fn, msg in ((sign_workflow, "sign_workflow"), (sign_read_grant, "sign_read_grant"), (sign_aggregate_grant, "sign_aggregate_grant")):
            with self.assertRaisesRegex(ValueError, "^%s: principal is not the signer$" % msg):
                fn(other, {"principal": self.key.public})
        with self.assertRaisesRegex(ValueError, "^decision must be 'allow' or 'deny'$"):
            sign_escalation_answer(self.principal, {"policy_digest": "a", "action_digest": "b", "history_head": "c"}, "maybe", 1, 2)
        pp = issue_passport({"model_id": "m", "operator": "o", "hardware_rooted": False, "issued_at": 10})
        with self.assertRaisesRegex(ValueError, "^sign_passport: exp must be after nbf$"):
            sign_passport(pp, self.principal, self.key.public, exp=10)
        with self.assertRaisesRegex(ValueError, "^sign_passport: passport.id is not the fingerprint of its identity \\(use issue_passport\\)$"):
            sign_passport(dict(pp, model_id="other"), self.principal, self.key.public, exp=99)
        hw = issue_passport({"model_id": "m", "operator": "o", "hardware_rooted": True, "issued_at": 10})
        with self.assertRaisesRegex(ValueError, "^sign_passport: hardware_rooted requires attestation evidence \\(fail closed\\)$"):
            sign_passport(hw, self.principal, self.key.public, exp=99)
        sp = sign_passport(pp, self.principal, self.key.public, exp=99)
        self.assertEqual((sp["iat"], sp["nbf"], sp["exp"]), (10, 10, 99))
        self.assertEqual(sign_passport(pp, self.principal, self.key.public, exp=99, iat=20, nbf=30)["nbf"], 30)


class PostQuantum(unittest.TestCase):
    """CI installs the `pq` extra and OpenSSL >= 3.5 and sets PCA_REQUIRE_PQ=1: a missing backend then FAILS instead of skipping."""

    def test_hybrid_and_pure_chain_and_leaf(self):
        required = os.environ.get("PCA_REQUIRE_PQ") == "1"
        principal, agent = generate_keypair(), generate_keypair()
        env = {"predicates": [{"verb": "read", "resource": "*"}], "caveats": [], "agent_binding": {},
               "risk_policy": DEFAULT_RISK_POLICY}
        cases = [("hybrid-ed25519-ml-dsa-65", "ML-DSA-65"), ("hybrid-nested-ed25519-ml-dsa-65", "ML-DSA-65"),
                 ("ml-dsa-87", "ML-DSA-87"), ("hybrid-ed25519-slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f")]
        for alg, family in cases:
            if alg not in supported_suites():
                self.assertFalse(required and family.startswith("ML-DSA"), alg + ": backend required in CI (SLH-DSA needs OpenSSL >= 3.5)")
                with self.assertRaises(Exception):
                    generate_pq_keypair(family)
                continue
            pq = generate_pq_keypair(family)
            grant = mint_grant(principal, agent.public, env, "g", holder_pq=pq.public)["grant"]
            a = Agent(agent, grant, "rs", alg=alg, pq=pq).act("read", "x")
            self.assertEqual(a.pcactn["alg"], alg)
            v = verify_pcactn_core(a.pcactn, grant, audience="rs")
            self.assertTrue(v.allow, v.reason)
            other = generate_pq_keypair(family)
            f = Agent(agent, grant, "rs", alg=alg, pq=other).act("read", "x")
            self.assertFalse(verify_pcactn_core(f.pcactn, grant, audience="rs").allow, alg + ": uncommitted PQ key verified")
        with self.assertRaises(Exception):
            sign_artifact_fn("fn-dsa-512")


def sign_artifact_fn(alg):
    from atlas_pca.agent import sign_artifact
    sign_artifact("d", {"v": 1}, generate_keypair(), alg=alg)


if __name__ == "__main__":
    unittest.main()
