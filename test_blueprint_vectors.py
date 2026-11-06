"""Agent blueprints: replays packages/pca/conformance/blueprint-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca import BlueprintRegistry, check_blueprints, verify_blueprint

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "blueprint-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class BlueprintVectors(unittest.TestCase):
    def test_records_verify_except_the_tampered_one(self):
        flags = [verify_blueprint(r) for r in DOC["records"]]
        self.assertEqual(flags, [True, True, True, True, True, True, True, True, False])

    def test_scenarios(self):
        self.assertGreaterEqual(len(DOC["scenarios"]), 16)
        for s in DOC["scenarios"]:
            with self.subTest(s["name"]):
                reg = BlueprintRegistry([DOC["operator"]])
                for st in s["steps"]:
                    if st["op"] == "accept":
                        got = reg.accept(DOC["records"][st["record"]])
                    else:
                        o = st["opts"]
                        got = check_blueprints(st["chain"], reg, o["now"], o["mode"], o.get("minEpoch"))
                    self.assertEqual(got, st["expect"])


if __name__ == "__main__":
    unittest.main()
