"""Break-glass grants: replays packages/pca/conformance/break-glass-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca.break_glass import BreakGlassRegistry

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "break-glass-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class BreakGlassVectors(unittest.TestCase):
    def test_scenarios(self):
        self.assertGreaterEqual(len(DOC["scenarios"]), 15)
        for s in DOC["scenarios"]:
            with self.subTest(s["name"]):
                reg = BreakGlassRegistry({"authorities": [DOC["authority"]], "reviewers": [DOC["reviewer"], *s.get("extra_reviewers", [])]})
                for st in s["steps"]:
                    exp = st["expect"]
                    if st["op"] == "accept":
                        got = reg.accept(DOC["grants"][st["grant"]], st["now"])
                    elif st["op"] == "use":
                        got = reg.use(st["id"], st["holder"], st["action_digest"], st["now"], st["notified"])
                    elif st["op"] == "review":
                        got = reg.review(DOC["reviews"][st["review"]], st["holder"], st["now"])
                    else:
                        got = reg.frozen(st["holder"], st["now"])
                    self.assertEqual(got, exp, (s["name"], st))


if __name__ == "__main__":
    unittest.main()
