"""Policy classes: replays packages/pca/conformance/policy-classes-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca.policy_classes import class_verdicts_error, decide_classes

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "policy-classes-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class PolicyClassesVectors(unittest.TestCase):
    def test_validate(self):
        self.assertGreater(len(DOC["validate"]), 8)
        for c in DOC["validate"]:
            with self.subTest(c["name"]):
                self.assertEqual(class_verdicts_error(c["input"]) is None, c["expect"]["ok"])

    def test_decide(self):
        self.assertGreater(len(DOC["decide"]), 6)
        for c in DOC["decide"]:
            with self.subTest(c["name"]):
                self.assertEqual(decide_classes(c["input"]), c["expect"])


if __name__ == "__main__":
    unittest.main()
