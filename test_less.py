"""LESS suites (`less-cat1`, `hybrid-ed25519-less-cat1`) through the suite dispatch: the known answers of
packages/pca/conformance/less-vectors.json (gen-less.mjs) when the LESS backend (sdks/pca-less-c built as a shared library,
`sdks/pca-less-c/build.sh`) is present, else the unsupported_suite refusal."""
import json
import os
import unittest

from atlas_pca import UNSUPPORTED_SUITE, decode_b64u_strict, supported_suites, verify_leaf_suite
from atlas_pca.pca import validate_signature_wire

HERE = os.path.dirname(os.path.abspath(__file__))
LESS = ("less-cat1", "hybrid-ed25519-less-cat1")


class LessSuiteTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(HERE, "conformance", "less-vectors.json"), encoding="utf-8") as f:
            self.doc = json.load(f)
        self.available = "less-cat1" in supported_suites()

    def test_manifest_lists_both_or_neither(self):
        self.assertEqual("hybrid-ed25519-less-cat1" in supported_suites(), self.available)

    def test_known_answers(self):
        if not self.available:
            self.skipTest("LESS backend not built (sdks/pca-less-c/build.sh)")
        vs = self.doc["vectors"]
        self.assertGreaterEqual(len(vs), 20)
        for v in vs:
            key = self.doc["keys"][v["key"]]
            art = {k: v[k] for k in ("alg", "sig", "pq_sig") if k in v}
            art["pq_pk"] = v.get("pq_pk_override", key["pq_pk"])
            wire_ok = validate_signature_wire(art) is None
            allow = wire_ok and verify_leaf_suite(art, key["ed_pub"], decode_b64u_strict(v["message"]))
            self.assertEqual((wire_ok, allow), (v["expect"]["wire_ok"], v["expect"]["allow"]), v["name"])

    def test_refused_without_backend(self):
        if self.available:
            self.skipTest("LESS backend present")
        for alg in LESS:
            self.assertEqual(validate_signature_wire({"alg": alg, "sig": "AA"}), "%s: %s" % (UNSUPPORTED_SUITE, alg))


if __name__ == "__main__":
    unittest.main()
