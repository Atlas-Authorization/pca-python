"""The A2A binding: replays packages/pca/conformance/a2a-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca.a2a import (check_chain_extension, check_push, check_receipt_chain, decode_need, may_trigger_next, need_digest,
                           push_token, receipt_digest, resume_gate, verify_receipt)

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "a2a-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class A2aVectors(unittest.TestCase):
    def test_need(self):
        self.assertGreaterEqual(len(DOC["need"]), 20)
        for c in DOC["need"]:
            with self.subTest(c["name"]):
                r = decode_need(c["input"])
                self.assertEqual(r["ok"], c["expect"]["ok"])
                if r["ok"]:
                    self.assertEqual(need_digest(r["need"]), c["expect"]["digest"])
                else:
                    self.assertEqual(r["code"], c["expect"]["code"])

    def test_push(self):
        for t in DOC["push"]["tokens"]:
            self.assertEqual(push_token(t["task_id"], t["chain_ids"], t["salt"]), t["token"])
        for s in DOC["push"]["weak_salts"]:
            self.assertIsNone(push_token("t", ["a"], s))
        for c in DOC["push"]["checks"]:
            with self.subTest(c["name"]):
                e = c["expected"]
                self.assertEqual(check_push(e["task_id"], e["chain_ids"], e["salt"], c["delivered"]["token"], c["delivered"]["payload"]), c["expect"])

    def test_chains(self):
        for c in DOC["chains"]:
            with self.subTest(c["name"]):
                self.assertEqual(check_chain_extension(c["chains"]), c["expect"])

    def test_resume(self):
        for c in DOC["resume"]:
            with self.subTest(c["name"]):
                self.assertEqual(resume_gate(c["state"], c["need_encoded"], c["answer_need_digest"], c["proof_action"]), c["expect"])

    def test_receipts(self):
        R = DOC["receipts"]
        for v in R["verify"]:
            self.assertEqual(verify_receipt(R["records"][v["record"]], R["signer"]), v["ok"], v)
        for d in R["digests"]:
            self.assertEqual(receipt_digest(R["records"][d["record"]]), d["digest"])
        for s in R["scenarios"]:
            with self.subTest(s["name"]):
                lst = [R["records"][i] for i in s["indices"]]
                self.assertEqual(check_receipt_chain(lst, R["signer"], s["task_id"], s["chain_ids"]), s["expect"])
                self.assertEqual(may_trigger_next(lst, R["signer"], s["task_id"], s["chain_ids"]), s["may_trigger_next"])


if __name__ == "__main__":
    unittest.main()
