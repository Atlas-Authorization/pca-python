"""Offline Sigstore bundle verification (track K9): replays packages/pca/conformance/sigstore-vectors.json (a missing file fails).

Every case: `ok` and the refusal `code` must match the reference; on ok the whole `core` must match. Needs `cryptography` (the `sigstore` extra).
"""
import copy
import json
import os
import unittest

import pytest

pytest.importorskip("cryptography")  # optional `sigstore` extra

from atlas_pca.sigstore_bundle import parse_trusted_root, verify_sigstore_bundle, verify_sigstore_bundle_core

_HERE = os.path.dirname(os.path.abspath(__file__))
_P = next((p for p in (os.path.join(_HERE, "conformance", "sigstore-vectors.json"),
                       os.path.join(_HERE, "conformance", "sigstore-vectors.json")) if os.path.exists(p)), None)
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)
ROOTS = {k: parse_trusted_root(v) for k, v in DOC["roots"].items()}


class SigstoreVectors(unittest.TestCase):
    def test_counts(self):
        self.assertGreaterEqual(len(DOC["cases"]), 30)

    def test_cases(self):
        for c in DOC["cases"]:
            with self.subTest(c["name"]):
                r = verify_sigstore_bundle_core(c["bundle"], ROOTS[c["roots"]])
                self.assertEqual(r["ok"], c["expect"]["ok"], r.get("detail"))
                self.assertEqual(r.get("code"), c["expect"].get("code"), r.get("detail"))
                if r["ok"]:
                    self.assertEqual(r["core"], c["expect"]["core"])

    def test_slsa_facts(self):
        c = next(c for c in DOC["cases"] if c["name"] == "npm/sigstore-5.0.0")
        r = verify_sigstore_bundle(c["bundle"], ROOTS[c["roots"]])
        self.assertTrue(r["ok"], r)
        f = r["facts"]
        core = c["expect"]["core"]
        self.assertEqual((f["v"], f["identity"], f["integrated_time"], f["rekor_log_index"], f["subjects"]),
                         (1, core["identity"], core["signed_time"], core["rekor_log_index"], core["subjects"]))
        self.assertTrue(f["builder_id"] and f["build_type"])

    def test_hostile_input_never_raises(self):
        root = ROOTS["public-good-844a1c6d"]
        for bad in (None, 1, "x", [], {}, {"verificationMaterial": {}}, {"mediaType": SIGSTORE_V3, "verificationMaterial": []}):
            self.assertFalse(verify_sigstore_bundle_core(bad, root)["ok"])
        ok = next(c for c in DOC["cases"] if c["name"] == "npm/sigstore-5.0.0")["bundle"]
        cert = ok["verificationMaterial"]["certificate"]["rawBytes"]
        body = ok["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"]
        for path, value in ((("verificationMaterial", "certificate", "rawBytes"), cert[:40]),
                            (("verificationMaterial", "tlogEntries", 0, "canonicalizedBody"), body[:-8]),
                            (("verificationMaterial", "tlogEntries", 0, "logIndex"), 7),
                            (("verificationMaterial", "tlogEntries", 0, "inclusionProof", "hashes"), [None]),
                            (("dsseEnvelope", "payload"), "e30="),
                            (("dsseEnvelope", "signatures"), [{"sig": None}])):
            b = copy.deepcopy(ok)
            o = b
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = value
            r = verify_sigstore_bundle(b, root)
            self.assertFalse(r["ok"], path)
            self.assertIn("code", r)

    def test_bad_root(self):
        with self.assertRaises(ValueError):
            parse_trusted_root({"mediaType": "x"})


SIGSTORE_V3 = "application/vnd.dev.sigstore.bundle.v0.3+json"

if __name__ == "__main__":
    unittest.main()
