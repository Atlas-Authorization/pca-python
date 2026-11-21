"""The `pca_grant` authorization-details type: replays packages/pca/conformance/pca-grant-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca import pca_grant_chain_digest, pca_grant_check_presentation, pca_grant_parse_details, pca_grant_validate_detail

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "pca-grant-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class PcaGrantVectors(unittest.TestCase):
    def test_counts(self):
        self.assertGreaterEqual(len(DOC["detail"]), 40)

    def test_digests(self):
        for v in DOC["digest"]:
            self.assertEqual(pca_grant_chain_digest(v["ids"]), v["digest"])

    def test_detail(self):
        for v in DOC["detail"]:
            with self.subTest(v["name"]):
                r = pca_grant_validate_detail(v["input"])
                self.assertEqual(r["ok"], v["expect"]["ok"])
                if not r["ok"]:
                    self.assertEqual(r["code"], v["expect"]["code"])

    def test_array(self):
        for v in DOC["array"]:
            with self.subTest(v["name"]):
                r = pca_grant_parse_details(v["input"])
                self.assertEqual(r["ok"], v["expect"]["ok"])
                if r["ok"]:
                    self.assertEqual(len(r["details"]), v["expect"]["count"])
                else:
                    self.assertEqual(r["code"], v["expect"]["code"])

    def test_presentation(self):
        for v in DOC["presentation"]:
            with self.subTest(v["name"]):
                p = v["presented"]
                r = pca_grant_check_presentation(v["details"], p["resource"], p["chain_ids"], p["proof_verified"])
                self.assertEqual(r["allow"], v["expect"]["allow"])
                key = "index" if r["allow"] else "code"
                self.assertEqual(r[key], v["expect"][key])

    def test_truthy_non_bool_is_not_a_proof(self):
        v = DOC["presentation"][0]
        p = v["presented"]
        self.assertEqual(pca_grant_check_presentation(v["details"], p["resource"], p["chain_ids"], "yes")["code"], "proof_required")


if __name__ == "__main__":
    unittest.main()
