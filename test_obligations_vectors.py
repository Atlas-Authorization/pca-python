"""Decision obligations: replays packages/pca/conformance/obligations-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca.obligations import merge_obligations, obligation_outcome, obligations_error, pep_obligation_gate

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "obligations-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class ObligationVectors(unittest.TestCase):
    def test_validate(self):
        self.assertGreater(len(DOC["validate"]), 10)
        for c in DOC["validate"]:
            with self.subTest(c["name"]):
                self.assertEqual(obligations_error(c.get("input")) is None, c["expect"]["ok"])

    def test_merge(self):
        self.assertGreater(len(DOC["merge"]), 0)
        for c in DOC["merge"]:
            with self.subTest(c["name"]):
                r = merge_obligations(*c["inputs"])
                self.assertEqual(r["ok"], c["expect"]["ok"])
                if r["ok"]:
                    self.assertEqual(r["obligations"], c["expect"]["obligations"])

    def test_gate(self):
        self.assertGreater(len(DOC["gate"]), 0)
        for c in DOC["gate"]:
            with self.subTest(c["name"]):
                r = pep_obligation_gate(c["decision"], c["answered"], c.get("obligations"), c["supported"])
                for k in ("decision", "perform", "unsupported"):
                    self.assertEqual(r[k], c["expect"][k])

    def test_outcome(self):
        self.assertGreater(len(DOC["outcome"]), 0)
        for c in DOC["outcome"]:
            with self.subTest(c["name"]):
                self.assertEqual(obligation_outcome(c.get("obligations"), c.get("fulfilled"), c.get("now")), c["expect"])


if __name__ == "__main__":
    unittest.main()
