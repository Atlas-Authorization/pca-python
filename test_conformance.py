import json
import os
import unittest

from atlas_pca import (
    StrictJsonError, canonicalize_strict, decode_b64u_strict, hash_canonical, merkle_root, params_digest,
    strict_parse, verify_inclusion, verify_pcactn_core,
)
from atlas_pca.pca import b64u, sha256

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")


def _load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


DOC = _load("vectors.json")


class Conformance(unittest.TestCase):
    def test_format(self):
        self.assertEqual(DOC["format"], 2)

    # This verifier implements the ed25519 suite AND the B4 post-quantum suites (ml-dsa-65,
    # hybrid-ed25519-ml-dsa-65) via dilithium-py — for the LEAF signature (requires:"pq") AND for non-leaf
    # capability-chain hops (requires:"pq-nonleaf"). Vectors tagged with an unsupported `requires` suite are
    # skipped explicitly, not silently.
    SUPPORTED_SUITES = frozenset({"ed25519", "pq", "pq-nonleaf"})

    def test_vectors(self):
        self.assertTrue(DOC["vectors"])
        skipped = 0
        for v in DOC["vectors"]:
            req = v.get("requires")
            if req and req not in self.SUPPORTED_SUITES:
                skipped += 1
                continue
            with self.subTest(v["name"]):
                raw = v["pcactn_json"] if "pcactn_json" in v else v["pcactn"]
                ctx = v["context"]
                got = verify_pcactn_core(raw, v["grant"], now=ctx["now"], audience=ctx["aud"])
                self.assertEqual(got.allow, v["expect"]["allow"], got.reason)
                self.assertEqual(got.checks, v["expect"]["checks"], got.reason)
        if skipped:
            print(f"skipped {skipped} vectors requiring unsupported suite: pq")

    def test_smallorder_forgeries_reject(self):
        vs = [v for v in DOC["vectors"] if v["name"].startswith("forge-smallorder-")]
        self.assertEqual(len(vs), 3)
        for v in vs:
            got = verify_pcactn_core(v["pcactn"], v["grant"], now=v["context"]["now"], audience=v["context"]["aud"])
            self.assertFalse(got.allow, v["name"])

    def test_primitives(self):
        prim = DOC["primitives"]
        for c in prim["canonical"]:
            self.assertEqual(canonicalize_strict(c["value"]), c["expect"])
            self.assertEqual(b64u(sha256(c["expect"].encode("utf-8"))), c["hash"])
            self.assertEqual(hash_canonical(c["value"]), c["hash"])
        for m in prim["merkle"]:
            self.assertEqual(merkle_root(m["leaves"]), m["root"])
            for i, pr in enumerate(m["proofs"]):
                self.assertTrue(verify_inclusion(m["root"], pr, m["leaves"][i]))
        self.assertEqual(params_digest(), prim["params_digest_empty"])

    def test_json_parse(self):
        for c in DOC["primitives"]["json_parse"]:
            with self.subTest(c["input"][:40]):
                if c["accept"]:
                    self.assertEqual(canonicalize_strict(strict_parse(c["input"])), c["canonical"])
                else:
                    with self.assertRaises(StrictJsonError):
                        strict_parse(c["input"])

    def test_b64u(self):
        for c in DOC["primitives"]["b64u"]:
            with self.subTest(c["input"][:30]):
                self.assertEqual(decode_b64u_strict(c["input"], c.get("len")) is not None, c["valid"])


if __name__ == "__main__":
    unittest.main()
