"""K4 vectors: replays packages/pca/conformance/k4-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca import (
    decide_escalation, pricing_config_error, update_calibration, verify_granted_permission, verify_network_token_binding,
)

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "k4-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class K4Vectors(unittest.TestCase):
    def test_pricing_config(self):
        self.assertGreaterEqual(len(DOC["escalation"]["config_cases"]), 6)
        for c in DOC["escalation"]["config_cases"]:
            with self.subTest(c["name"]):
                self.assertEqual(pricing_config_error(c["config"]), c["expect"])

    def test_decisions(self):
        self.assertGreaterEqual(len(DOC["escalation"]["decisions"]), 14)
        for c in DOC["escalation"]["decisions"]:
            with self.subTest(str(c["risk"])):
                self.assertEqual(decide_escalation(DOC["escalation"]["config"], c["calibration"], c["risk"]), c["expect"])

    def test_calibration(self):
        for c in DOC["escalation"]["calibration"]:
            with self.subTest(c["name"]):
                self.assertEqual(update_calibration(c["config"], c["start"], c["answers"], c["risks"]), c["expect"])

    def test_network_binding(self):
        self.assertGreaterEqual(len(DOC["network_binding"]["cases"]), 15)
        for c in DOC["network_binding"]["cases"]:
            with self.subTest(c["name"]):
                e = c["expect_in"]
                self.assertEqual(verify_network_token_binding(c["binding"], e["grant"], e["holder"], e["issuer_nonce"], e.get("provider")), c["expect"])

    def test_erc7715(self):
        self.assertGreaterEqual(len(DOC["erc7715"]["cases"]), 24)
        for c in DOC["erc7715"]["cases"]:
            with self.subTest(c["name"]):
                ctx = c["opts"].get("contexts", {})
                self.assertEqual(verify_granted_permission(c["envelope"], c["sent"], c["got"], c["opts"]["allowedManagers"], lambda x: ctx.get(x)), c["expect"])


if __name__ == "__main__":
    unittest.main()
