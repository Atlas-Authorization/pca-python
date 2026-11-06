"""Runtime-class claims: replays packages/pca/conformance/runtime-claim-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca import verified_runtime_class

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "runtime-claim-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class RuntimeClaimVectors(unittest.TestCase):
    def test_cases(self):
        self.assertGreaterEqual(len(DOC["cases"]), 8)
        t = DOC["trust"]
        for c in DOC["cases"]:
            with self.subTest(c["name"]):
                got = verified_runtime_class(c["claim"], t["pinnedAttestors"], t["passportDigest"], t["verifiedEvidenceDigests"], c["now"])
                self.assertEqual(got, c["expect"])

    def test_unpinned_or_unverified_evidence_is_none(self):
        t, c = DOC["trust"], DOC["cases"][0]
        self.assertEqual(verified_runtime_class(c["claim"], t["pinnedAttestors"], t["passportDigest"], t["verifiedEvidenceDigests"], c["now"]), "wasi_no_ambient")
        self.assertEqual(verified_runtime_class(c["claim"], [], t["passportDigest"], t["verifiedEvidenceDigests"], c["now"]), "none")
        self.assertEqual(verified_runtime_class(c["claim"], t["pinnedAttestors"], t["passportDigest"], [], c["now"]), "none")
        self.assertEqual(verified_runtime_class(c["claim"], t["pinnedAttestors"], "other", t["verifiedEvidenceDigests"], c["now"]), "none")
        self.assertEqual(verified_runtime_class(None, [], "", [], 0), "none")
        self.assertEqual(verified_runtime_class(c["claim"], t["pinnedAttestors"], t["passportDigest"], t["verifiedEvidenceDigests"], True), "none")


if __name__ == "__main__":
    unittest.main()
