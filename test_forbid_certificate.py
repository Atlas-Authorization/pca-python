"""Shared vectors for the forbid-wins certificate: packages/pca/conformance/forbid-certificate-vectors.json (`table`)."""
import json
import os
import unittest

from atlas_pca.forbid_certificate import certificate_consistent

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "forbid-certificate-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class ForbidCertificateVectors(unittest.TestCase):
    def test_table(self):
        self.assertGreaterEqual(len(DOC["table"]), 19)
        for e in DOC["table"]:
            with self.subTest(e["name"]):
                self.assertEqual(certificate_consistent(e["certificate"], (e.get("options") or {}).get("precedence")), e["expect"]["consistent"])

    def test_garbage_is_not_consistent(self):
        for bad in (None, 5, [], {}, {"v": 1, "kind": "forbid-wins", "clauses": "x"}, {"v": 1, "kind": "forbid-wins", "clauses": [None], "winner": {}, "shadowed": []}):
            with self.subTest(repr(bad)):
                self.assertFalse(certificate_consistent(bad))


if __name__ == "__main__":
    unittest.main()
