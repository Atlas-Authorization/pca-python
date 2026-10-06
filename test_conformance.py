import json
import os
import unittest

from atlas_pca import canonicalize, hash_canonical, merkle_root, params_digest, verify_inclusion, verify_pcactn_core

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")


def _load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


DOC = _load("vectors.json")


class Conformance(unittest.TestCase):
    def test_vectors(self):
        self.assertTrue(DOC["vectors"])
        for v in DOC["vectors"]:
            with self.subTest(v["name"]):
                got = verify_pcactn_core(v["pcactn"], v["grant"])
                self.assertEqual(got.allow, v["expect"]["allow"], got.reason)
                for k, w in v["expect"]["checks"].items():
                    self.assertEqual(got.checks[k], w, k)

    def test_primitives(self):
        prim = DOC["primitives"]
        for c in prim["canonical"]:
            self.assertEqual(canonicalize(c["value"]), c["expect"])
            self.assertEqual(hash_canonical(c["value"]), c["hash"])
        for m in prim["merkle"]:
            self.assertEqual(merkle_root(m["leaves"]), m["root"])
            for i, pr in enumerate(m["proofs"]):
                self.assertTrue(verify_inclusion(m["root"], pr, m["leaves"][i]))
        self.assertEqual(params_digest(), prim["params_digest_empty"])


if __name__ == "__main__":
    unittest.main()
