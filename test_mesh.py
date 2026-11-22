"""Mesh trust verifier: every vector of packages/pca/conformance/mesh-vectors.json must reproduce `ok`, and `reason` / `hop`
on every vector whose reason does not start `chain:`. No skips; a missing file fails."""
import json
import os
import unittest

from atlas_pca import verify_mesh_proof
from atlas_pca.mesh import check_head_advance

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "mesh-vectors.json")


class TestMesh(unittest.TestCase):
    def test_empty_head_advances(self):
        """a head pinned at size 0 (root '') advances: '' is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused."""
        j = json.loads('{"e":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":0,"root":"","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"n":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":3,"root":"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"ok":{"oldSize":0,"newSize":3,"path":[]},"path":{"oldSize":0,"newSize":3,"path":["CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow"]},"old1":{"oldSize":1,"newSize":3,"path":[]}}')
        e, n = j["e"], j["n"]
        self.assertIsNone(check_head_advance(e, n, j["ok"]))
        self.assertEqual(check_head_advance(e, n), "consistency proof required for a larger head")
        self.assertEqual(check_head_advance(e, n, j["path"]), "head is not consistent with the previous head (fork or rewrite)")
        self.assertEqual(check_head_advance(e, n, j["old1"]), "consistency proof required for a larger head")

    def test_vectors(self):
        with open(FILE, encoding="utf-8") as f:
            vecs = json.load(f)["mesh"]
        self.assertGreaterEqual(len(vecs), 100)
        bad = []
        for v in vecs:
            exp = v["expect"]
            got = verify_mesh_proof(v["proof"], v["trust"])
            if got.ok != exp["ok"]:
                bad.append("%s: ok=%s (%r) want %s (%r)" % (v["name"], got.ok, got.reason, exp["ok"], exp.get("reason")))
                continue
            if exp["ok"]:
                continue
            want = exp.get("reason")
            if isinstance(want, str) and want.startswith("chain:"):
                if not got.reason.startswith("chain:"):
                    bad.append("%s: reason %r want a chain refusal" % (v["name"], got.reason))
                continue
            if got.reason != want:
                bad.append("%s: reason %r want %r" % (v["name"], got.reason, want))
            if got.hop != exp.get("hop", -1):
                bad.append("%s: hop %s want %s" % (v["name"], got.hop, exp.get("hop", -1)))
        self.assertEqual([], bad[:20])

    def test_total_on_garbage(self):
        for g in (None, 5, "x", [], {}):
            r = verify_mesh_proof(g, g)
            self.assertFalse(r.ok)
            self.assertEqual(-1, r.hop)


if __name__ == "__main__":
    unittest.main()
