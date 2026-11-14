"""The agent / issuer side (atlas_pca.agent): replays packages/pca/conformance/producer-vectors.json byte for byte (fixed keys,
nonces and timestamps; Ed25519 is deterministic), and round-trips everything it produces through this package's own verifiers
(and, when ML-DSA is available, the hybrid / pure PQ suites)."""
import json
import os
import unittest

import producer_ops

from atlas_pca import supported_suites, verify_chain, verify_passport, verify_pcactn_core
from atlas_pca.agent import (Agent, KeyPair, PqKeyPair, build_escalation_request, commit_plan, delegate, escalation_action_digest,
                             escalation_history_head, escalation_policy_digest, generate_keypair, generate_pq_keypair,
                             goal_commit_of, issue_passport, keypair_from_seed, mint_grant, mint_root, pca_headers,
                             sign_aggregate_grant, sign_discharge, sign_escalation_answer, sign_fresh_at, sign_narrow,
                             sign_passport, sign_read_grant, sign_step_receipt, sign_workflow, discharge_digest,
                             DEFAULT_RISK_POLICY)
from atlas_pca.escalation import verify_escalation_answer
from atlas_pca.pca import (b64u, canonicalize, decode_pca_header, hash_canonical, holder_pq_commitment, params_digest, strict_parse,
                           unb64u)

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "producer-vectors.json")
with open(FILE, encoding="utf-8") as f:
    DOC = json.load(f)
KEYS = producer_ops.keys_of(DOC["keys"])


def run(c):
    return producer_ops.run(c, KEYS)


def _error_suffix(text):
    """A refusal's text without the producer's name ("signPqBinding: x" and "sign_pq_binding: x" both give "x")."""
    return text.split(": ", 1)[1] if ": " in text else text


class ProducerVectors(unittest.TestCase):
    def test_vectors(self):
        self.assertGreaterEqual(len(DOC["cases"]), 89)
        bad = []
        for c in DOC["cases"]:
            want = {k: v for k, v in c["expect"].items() if k != "threshold_message"}
            exact = c["op"] in ("parse_limit", "compile_policy")  # the facade keeps the reference's function names
            try:
                got = run(c)
            except Exception as e:  # noqa: BLE001 - a refusal must match the reference's text
                if set(want) != {"error"} or (str(e) != want["error"] if exact else _error_suffix(str(e)) != _error_suffix(want["error"])):
                    bad.append("%s: %s" % (c["name"], e))
                continue
            if set(want) == {"error"} or json.loads(json.dumps(got)) != want:
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
        v = verify_pcactn_core(decode_pca_header(a1.headers["PCA-Action"]), self.grant, audience="rs-test", insecure_skip_plan_root_check=True)
        self.assertTrue(v.allow, v.reason)
        tampered = dict(a1.pcactn, counter=9)
        self.assertFalse(verify_pcactn_core(tampered, self.grant, audience="rs-test", insecure_skip_plan_root_check=True).allow)

    def test_agent_subdelegate_core_verifies(self):
        sub = generate_keypair()
        child = Agent(self.agent_key, self.grant, "rs-test").delegate(sub, [{"type": "sealed"}])
        a = child.act("refund", "orders/2", {"amount_cents": 1})
        v = verify_pcactn_core(a.pcactn, self.grant, audience="rs-test", insecure_skip_plan_root_check=True)
        self.assertTrue(v.allow, v.reason)

    def test_plan_node_proof(self):
        nodes = [{"id": "a", "verb": "read", "resource": "x"}, {"id": "b", "verb": "refund", "resource": "orders/1"}]
        agent = Agent(self.agent_key, self.grant, "rs-test").use_plan(nodes)
        v = verify_pcactn_core(agent.act("refund", "orders/1").pcactn, self.grant, audience="rs-test", insecure_skip_plan_root_check=True)
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
        bodies = {c["op"]: c["args"]["body"] for c in DOC["cases"] if c["op"] in ("sign_workflow", "sign_read_grant", "sign_aggregate_grant")}
        for fn, msg, what in ((sign_workflow, "sign_workflow", "workflow"), (sign_read_grant, "sign_read_grant", "grant"),
                              (sign_aggregate_grant, "sign_aggregate_grant", "grant")):
            with self.assertRaisesRegex(ValueError, "^%s: malformed %s$" % (msg, what)):
                fn(other, {"principal": other.public})
            with self.assertRaisesRegex(ValueError, "^%s: principal is not the signer$" % msg):
                fn(other, bodies[msg])
        cyclic = json.loads(json.dumps(bodies["sign_workflow"]))
        cyclic["steps"][0]["deps"] = [cyclic["steps"][-1]["id"]]
        with self.assertRaisesRegex(ValueError, "^sign_workflow: malformed workflow$"):
            sign_workflow(KEYS[[c for c in DOC["cases"] if c["op"] == "sign_workflow"][0]["args"]["signer"]], cyclic)
        with self.assertRaisesRegex(ValueError, r"^sign_escalation_answer: policy_digest must be canonical base64url \(32 bytes\)$"):
            sign_escalation_answer(self.principal, {"policy_digest": "a", "action_digest": "b", "history_head": "c"}, "maybe", 1, 2)
        # a signed artifact every verifier would refuse is never handed out: a short caller nonce fails the reference shape check
        dg = hash_canonical({"x": 1})
        bind = {"policy_digest": dg, "action_digest": dg, "history_head": dg}
        self.assertTrue(sign_escalation_answer(self.principal, bind, "allow", 1, 2)["nonce"])
        with self.assertRaisesRegex(ValueError, "^sign_escalation_answer: nonce must be canonical base64url of at least 16 bytes$"):
            sign_escalation_answer(self.principal, bind, "allow", 1, 2, nonce="n1")
        self.assertTrue(sign_discharge(self.principal, "d1", "idp", dg, {"tier": "gold"}, 1000, 2000)["nonce"])
        with self.assertRaisesRegex(ValueError, "^sign_discharge: nonce must be canonical base64url of at least 16 bytes$"):
            sign_discharge(self.principal, "d1", "idp", dg, {"tier": "gold"}, 1000, 2000, nonce="n1")
        cav = [{"type": "expires", "at": 2000}]
        self.assertTrue(sign_narrow(self.principal, dg, cav, 1000, 2000)["nonce"])
        with self.assertRaisesRegex(ValueError, "^sign_narrow: nonce must be canonical base64url of at least 16 bytes$"):
            sign_narrow(self.principal, dg, cav, 1000, 2000, nonce="n1")
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
            v = verify_pcactn_core(a.pcactn, grant, audience="rs", insecure_skip_plan_root_check=True)
            self.assertTrue(v.allow, v.reason)
            other = generate_pq_keypair(family)
            f = Agent(agent, grant, "rs", alg=alg, pq=other).act("read", "x")
            self.assertFalse(verify_pcactn_core(f.pcactn, grant, audience="rs", insecure_skip_plan_root_check=True).allow, alg + ": uncommitted PQ key verified")
        with self.assertRaises(Exception):
            sign_artifact_fn("fn-dsa-512")


PQ_FILE = os.path.join(os.path.dirname(FILE), "producer-pq-vectors.json")
with open(PQ_FILE, encoding="utf-8") as f:
    PQ_DOC = json.load(f)
PQ_ED = producer_ops.keys_of(PQ_DOC["ed_keys"])
PQ_KEYS = producer_ops.PqKeys(PQ_DOC["pq_keys"])


def _family(c):
    """The PQ family a case needs (None for Ed25519)."""
    from atlas_pca.pca import _SIG_SUITES
    if c["op"] == "pq_keygen":
        return producer_ops.FAMILIES[c["args"]["family"]]
    spec = _SIG_SUITES.get(c["alg"])
    return None if spec is None or not spec[1] else spec[3]


def _can_sign(family):
    from atlas_pca import agent as A, pq_backends
    return family is None or pq_backends.openssl_available(family) or family in A._ML_DSA


class PostQuantumVectors(unittest.TestCase):
    """producer-pq-vectors.json: every case that lists this SDK in `exact` is reproduced byte for byte (seeded keys,
    deterministic ML-DSA / SLH-DSA); a suite this SDK does not sign (FN-DSA) is refused, never signed differently.
    CI sets PCA_REQUIRE_PQ=1 where the `pq` extra is installed: a missing ML-DSA backend then FAILS instead of skipping."""

    def test_vectors(self):
        from atlas_pca.agent import UnsupportedSuite
        required = os.environ.get("PCA_REQUIRE_PQ") == "1"
        bad, refused, ran = [], [], 0
        for c in PQ_DOC["cases"]:
            fam = _family(c)
            if "python" not in c["exact"]:
                try:
                    producer_ops.run(c, PQ_ED, PQ_KEYS)
                    bad.append(c["name"] + ": signed a suite outside this SDK")
                except UnsupportedSuite as e:
                    refused.append(c["name"])
                    self.assertTrue(str(e).startswith("unsupported_suite: "), str(e))
                continue
            if not _can_sign(fam):
                self.assertFalse(required and fam.startswith("ML-DSA"), c["name"] + ": ML-DSA backend required in CI")
                continue
            got = json.loads(json.dumps(producer_ops.run(c, PQ_ED, PQ_KEYS)))
            ran += 1
            if got != c["expect"]:
                bad.append(c["name"])
            elif c["op"] == "suite_sign" and producer_ops.run(c, PQ_ED, PQ_KEYS) != got:
                bad.append(c["name"] + ": signing twice gave different bytes")
        self.assertEqual(bad, [])
        self.assertEqual(sorted(refused), sorted(c["name"] for c in PQ_DOC["cases"] if c["exact"] == ["rust"]))
        self.assertGreater(ran, 0)


# ---- natives -> reference: this SDK's signed artifacts for the reference verifier ------------------------------------------

V3_AUD, V3_NOW = "rs-python-producer", 1_800_000_000_000 + 1000


def _vector_args(name):
    return next(c for c in DOC["cases"] if c["name"] == name)["args"]


def _pins(key, pq=None, **extra):
    p = dict(extra, pk=key.public)
    if pq is not None:
        p["pq_pk"] = pq.public
    return p


def build_native_cases():
    """One PCActn per suite this runtime signs (and one from a delegated sub-agent under each), one facade act with
    params, and each artifact kind under Ed25519 and, when available, a hybrid ML-DSA suite. Every artifact is checked
    against this package's own verifiers before it is written."""
    from atlas_pca.agent import PQ_SEED_BYTES, generate_pq_keypair, sign_escalation_answer
    from atlas_pca.pca import _SIG_SUITES
    from atlas_pca import signers_more as S
    from atlas_pca.facade import create_agent
    t0 = V3_NOW - 1000
    principal, agent_key = KEYS["principal"], KEYS["agent"]
    env = {"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "agent_binding": {},
           "risk_policy": DEFAULT_RISK_POLICY}
    cases = []
    suites = [a for a, spec in _SIG_SUITES.items() if a == "ed25519" or (spec[3] in PQ_SEED_BYTES and _can_sign(spec[3]))]
    for i, alg in enumerate(sorted(suites)):
        fam = _SIG_SUITES[alg][3] if alg != "ed25519" else None
        pq = generate_pq_keypair(fam, bytes([i + 1]) * PQ_SEED_BYTES[fam]) if fam else None
        grant = mint_grant(principal, agent_key.public, env, "refund an order", salt="s",
                           holder_pq=pq.public if pq else None)["grant"]
        a = Agent(agent_key, grant, V3_AUD, clock=lambda: t0, alg=alg if fam else None, pq=pq)
        cases.append({"kind": "pcactn", "alg": alg, "grant": grant, "pcactn": a.act("refund", "orders/1", {"amount": 5}).pcactn})
        sub = a.delegate(KEYS["subagent"], [{"type": "budget_alloc", "limit": 5}])
        cases.append({"kind": "pcactn", "alg": alg, "grant": grant, "pcactn": sub.act("refund", "orders/2", {"amount": 1}).pcactn})
    h = create_agent(principal=principal, goal="refund order 1", permissions={"stripe": ["refund"]}, limits={"refund": "$500/day"},
                     holder=agent_key, aud=V3_AUD, now=t0)
    h.provenance.principal("refund order 1")
    cases.append({"kind": "pcactn", "alg": "ed25519", "grant": h.grant,
                  "pcactn": h.act("stripe.refund", "charge:ch_1", {"amount": 42, "currency": "usd"}, now=t0)["pcactn"]})

    hyb = "hybrid-ed25519-ml-dsa-65"
    variants = [("ed25519", None, None)]
    if _can_sign("ML-DSA-65"):
        variants.append((hyb, generate_pq_keypair("ML-DSA-65", bytes([42]) * 32), generate_pq_keypair("ML-DSA-65", bytes([43]) * 32)))
    for alg, pq, pq2 in variants:
        a_ = None if alg == "ed25519" else alg
        b = _vector_args("escalation-answer-allow")["body"]
        cases.append({"kind": "escalation_answer", "alg": alg, "pins": _pins(principal, pq), "artifact": sign_escalation_answer(
            principal, b, b["decision"], b["iat"], b["expires_at"], b["nonce"], alg=a_, pq=pq)})
        ep = _vector_args("revocation-epoch")["body"]
        cases.append({"kind": "revocation_epoch", "alg": alg, "pins": _pins(KEYS["guardian"], pq2),
                      "artifact": S.sign_revocation_epoch(KEYS["guardian"], ep, a_, pq2)})
        root = json.loads(json.dumps(_vector_args("session-root")["body"]))
        cases.append({"kind": "session_root", "alg": alg, "pins": _pins(principal, pq),
                      "artifact": S.sign_session_root(root, principal, a_, pq)})
        site = KEYS["site"]
        cases.append({"kind": "action_schema", "alg": alg, "pins": _pins(site, pq2, kid="site-k1", alg=alg),
                      "artifact": S.sign_action_schema(_vector_args("action-schema")["doc"], "site-k1", site, a_, pq2)})
        ir = _vector_args("intent-required")["body"]
        cases.append({"kind": "intent_required", "alg": alg, "pins": _pins(site, pq2, kid="site-k1", alg=alg),
                      "artifact": S.sign_intent_required(ir, "site-k1", site, a_, pq2)})
        lb = _vector_args("labels")["body"]
        cases.append({"kind": "labels", "alg": alg, "pins": _pins(site, pq2, kid=lb["kid"], site=lb["site"]),
                      "artifact": S.sign_labels(lb, site, a_, pq2)})
        cases.append({"kind": "fact", "alg": alg, "pins": _pins(KEYS["oracle"], pq),
                      "artifact": S.sign_fact(_vector_args("fact-integer")["body"], KEYS["oracle"], a_, pq)})
    cases.append({"kind": "caution", "alg": "ed25519", "pins": _pins(agent_key),
                  "artifact": S.sign_caution(_vector_args("caution-reason")["body"], agent_key)})
    cases.append({"kind": "pq_binding", "alg": "ed25519", "pins": _pins(agent_key),
                  "artifact": S.sign_pq_binding(agent_key, _vector_args("pq-binding")["pq_pk"], 1, V3_AUD)})
    return {"lang": "python", "aud": V3_AUD, "now": V3_NOW, "cases": cases}


def _self_check(c, doc):
    """This package's own verifier for each kind (the reference checks the same file)."""
    from atlas_pca.escalation import verify_escalation_answer
    from atlas_pca.intent_v2 import check_revocation_epoch, verify_action_schema, verify_session_root
    from atlas_pca.intent_wb import FACT_DOMAIN, validate_fact_wire, verify_artifact_sig, verify_labels
    from atlas_pca.ed25519 import verify as ed_verify
    from atlas_pca.pca import canonical_bytes, canonical_bytes_strict
    from atlas_pca import signers_more as S
    k, a, p = c["kind"], c.get("artifact"), c.get("pins") or {}
    pq_pins = {p["pk"]: p["pq_pk"]} if "pq_pk" in p else {}
    pin = {"pk": p.get("pk"), **({"pq_pk": p["pq_pk"]} if "pq_pk" in p else {})}
    if k == "pcactn":
        return verify_pcactn_core(c["pcactn"], c["grant"], audience=doc["aud"], now=doc["now"], insecure_skip_plan_root_check=True).allow
    if k == "escalation_answer":
        bind = {x: a[x] for x in ("policy_digest", "action_digest", "history_head")}
        return verify_escalation_answer(a, [pin], bind, doc["now"])["ok"]
    if k == "revocation_epoch":
        return check_revocation_epoch(a, p["pk"], doc["now"], pq_pins=pq_pins)["ok"]
    if k == "session_root":
        return verify_session_root(a, pq_pins)["ok"]
    if k == "action_schema":
        return verify_action_schema(a, [{"kid": p["kid"], "alg": p["alg"], "pk": p["pk"], **({"pq_pk": p["pq_pk"]} if "pq_pk" in p else {})}])["ok"]
    if k == "intent_required":  # no verifier in this package (host / wallet tooling); the classical half is checked here
        body = {x: v for x, v in a.items() if x != "sig"}
        msg = S.INTENT_REQUIRED_DOMAIN.encode("utf-8") + canonical_bytes_strict(body)
        return a["sig"]["kid"] == p["kid"] and a["sig"]["alg"] == p["alg"] and doc["now"] <= a["expires_at"] and \
            ed_verify(unb64u(p["pk"]), msg, unb64u(a["sig"]["value"])) and (("pq_value" in a["sig"]) == ("pq_pk" in p))
    if k == "labels":
        return verify_labels(a, [dict(pin, site=p["site"], kid=p["kid"])]) is None
    if k == "fact":
        return validate_fact_wire(a) is None and verify_artifact_sig(FACT_DOMAIN, a, pin)
    if k == "caution":
        body = {x: v for x, v in a.items() if x != "sig"}
        return a["holder"] == p["pk"] and ed_verify(unb64u(p["pk"]), canonical_bytes({"d": "atlas-pca/caution/v1", "b": body}), unb64u(a["sig"]))
    if k == "pq_binding":
        return S.pq_pin_for(a, doc["aud"]) is not None
    return False


class NativeProducerFile(unittest.TestCase):
    """Builds this SDK's artifacts for the reference verifier; with PCA_PRODUCER_OUT set (CI) writes them there."""

    def test_native_file(self):
        doc = build_native_cases()
        kinds = {c["kind"] for c in doc["cases"]}
        self.assertEqual(kinds, {"pcactn", "escalation_answer", "revocation_epoch", "session_root", "action_schema", "labels",
                                 "fact", "caution", "pq_binding", "intent_required"})
        bad = ["%s %s" % (c["kind"], c["alg"]) for c in doc["cases"] if not _self_check(c, doc)]
        self.assertEqual(bad, [])
        cs = doc["cases"]
        subs = [(cs[i - 1], c) for i, c in enumerate(cs) if c["kind"] == "pcactn" and len(c["pcactn"]["cap_chain"]) == 2]
        self.assertEqual(len(subs), len([c for c in cs if c["kind"] == "pcactn"]) // 2)
        for parent, c in subs:  # a PQ sub-agent signs with its own key, committed in its hop
            if c["alg"] != "ed25519":
                self.assertEqual(c["pcactn"]["cap_chain"][-1]["holder_pq"], holder_pq_commitment(c["pcactn"]["pq_pk"]))
                self.assertNotEqual(c["pcactn"]["pq_pk"], parent["pcactn"]["pq_pk"])
        out = os.environ.get("PCA_PRODUCER_OUT")
        if out:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(doc, f, sort_keys=True)


def sign_artifact_fn(alg):
    from atlas_pca.agent import sign_artifact
    sign_artifact("d", {"v": 1}, generate_keypair(), alg=alg)


if __name__ == "__main__":
    unittest.main()
