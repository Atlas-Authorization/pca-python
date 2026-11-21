"""Typed missing context and the stored-wins merge: replays packages/pca/conformance/missing-context-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca.missing_context import bind_context, decide_with_missing

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "missing-context-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class MissingContextVectors(unittest.TestCase):
    def test_decide(self):
        self.assertGreaterEqual(len(DOC["decide"]), 20)
        for c in DOC["decide"]:
            with self.subTest(c["name"]):
                got = decide_with_missing(c["where"], c["bound"], c.get("supplied"), c.get("suppliers"))
                exp = c["expect"]
                self.assertEqual(got["decision"], exp["decision"])
                self.assertEqual(got.get("reason"), exp.get("reason"))
                self.assertEqual(got["missing"], exp["missing"])

    def test_bind(self):
        self.assertGreaterEqual(len(DOC["bind"]), 8)
        for c in DOC["bind"]:
            with self.subTest(c["name"]):
                self.assertEqual(bind_context(c["bound"], c.get("supplied"), c.get("suppliers")), c["expect"])


if __name__ == "__main__":
    unittest.main()
