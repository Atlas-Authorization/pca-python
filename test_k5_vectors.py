"""K5 workflow admission and read-side authorization: replays packages/pca/conformance/workflow-vectors.json and
readside-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca.readside import check_sink, read_chain_labels, read_grant_digest, redact_read
from atlas_pca.workflow import admit_step, bind_promises, plan_root_authorized, value_digest, workflow_digest

_D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")
with open(os.path.join(_D, "workflow-vectors.json"), encoding="utf-8") as f:
    W = json.load(f)
with open(os.path.join(_D, "readside-vectors.json"), encoding="utf-8") as f:
    R = json.load(f)


def _inp(c):
    return {"workflow": W["workflows"][c["workflow"]], "principal": c["principal"], "rs_signer": c["rs_signer"],
            "receipts": c["receipts"], "now": c["now"], "request": c["request"]}


class WorkflowVectors(unittest.TestCase):
    def test_digests(self):
        self.assertEqual(workflow_digest(W["workflows"]["main"]["body"]), W["digests"]["workflow"])
        for v in W["digests"]["values"]:
            self.assertEqual(value_digest(v["value"]), v["digest"])

    def test_admit_bind_plan_root(self):
        self.assertGreaterEqual(len(W["admit"]), 50)
        for c in W["admit"]:
            with self.subTest("admit " + c["name"]):
                self.assertEqual(admit_step(_inp(c)), c["expect"])
        for c in W["bind"]:
            with self.subTest("bind " + c["name"]):
                self.assertEqual(bind_promises(_inp(c)), c["expect"])
        for c in W["plan_root"]:
            with self.subTest("plan_root " + c["name"]):
                self.assertIs(plan_root_authorized(W["workflows"][c["workflow"]], c["principal"], c["now"], c["root"]), c["expect"])

    def test_every_code_exercised(self):
        seen = {c["expect"]["code"] for c in W["admit"] + W["bind"] if c["expect"]["code"]}
        for code in ("bad_workflow", "bad_dag", "bad_signature", "not_yet", "expired", "goal_mismatch", "plan_root_mismatch", "bad_receipt",
                     "unplanned_step", "step_mismatch", "params_mismatch", "already_done", "budget_exceeded", "deps_unmet", "dep_failed",
                     "stale_dep", "edge_missing", "edge_unit", "edge_digest", "edge_value", "edge_relation", "taint_flow",
                     "pipeline_unconstrained", "taint_escalate"):
            self.assertIn(code, seen)

    def test_never_throws(self):
        k = W["keys"]
        for x in (None, 1, "x", [], {}, {"body": None}, {"body": {}, "sig": 1}):
            r = admit_step({"workflow": x, "principal": k["principal"], "rs_signer": k["rs"], "receipts": [], "now": 1, "request": x})
            self.assertEqual((r["decision"], r["code"], r["step"]), ("deny", "bad_workflow", None))
        self.assertEqual(admit_step({"workflow": W["workflows"]["main"], "principal": k["principal"], "rs_signer": k["rs"], "receipts": "x", "now": 1, "request": {}})["decision"], "deny")
        self.assertEqual(admit_step(None)["code"], "bad_workflow")
        self.assertEqual(bind_promises("x")["code"], "bad_workflow")


class ReadsideVectors(unittest.TestCase):
    def test_redact(self):
        self.assertGreaterEqual(len(R["redact"]), 20)
        for c in R["redact"]:
            with self.subTest("redact " + c["name"]):
                self.assertEqual(redact_read(dict(c["input"], grant=R["grants"][c["grant"]])), c["expect"])

    def test_sinks(self):
        for c in R["sinks"]:
            with self.subTest("sink " + c["name"]):
                self.assertEqual(check_sink({"grant": R["grants"][c["grant"]], "principal": c["principal"], "rs_signer": c["rs_signer"],
                                             "now": c["now"], "sink": c["sink"], "receipts": c["receipts"]}), c["expect"])

    def test_digests_and_chain(self):
        self.assertEqual(read_grant_digest(R["grants"]["main"]["body"]), R["digests"]["grant"])
        rs = next(s for s in R["sinks"] if s["name"] == "chain-of-two-public-reads")["receipts"]
        self.assertEqual(read_chain_labels(rs, R["keys"]["rs"], R["digests"]["grant"], 1_800_000_000_000), R["digests"]["chain_labels"])

    def test_masked_view_never_has_dropped_value(self):
        c = next(x for x in R["redact"] if x["name"] == "support-view")
        text = json.dumps(c["expect"]["view"])
        for secret in ("sk_live_x", "123-45-6789", "dev-1", "c_77", "not in the schema"):
            self.assertNotIn(secret, text)

    def test_never_throws(self):
        for x in (None, 1, "x", [], {}):
            self.assertEqual(redact_read(x)["decision"], "deny")
            self.assertEqual(check_sink(x), {"decision": "deny", "code": "bad_request", "labels": []})


if __name__ == "__main__":
    unittest.main()
