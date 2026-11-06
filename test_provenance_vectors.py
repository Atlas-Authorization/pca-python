"""Build provenance (track K9): replays packages/pca/conformance/provenance-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca import provenance_caveat, provenance_gate, rfc9162_leaf_hash, verify_rfc9162_inclusion
from atlas_pca.decision import is_model_derived_path

_HERE = os.path.dirname(os.path.abspath(__file__))
_P = next((p for p in (os.path.join(_HERE, "conformance", "provenance-vectors.json"),
                       os.path.join(_HERE, "conformance", "provenance-vectors.json")) if os.path.exists(p)), None)
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)["primitives"]


class ProvenanceVectors(unittest.TestCase):
    def test_counts(self):
        self.assertGreaterEqual([len(DOC[k]) for k in ("merkle_inclusion", "gate", "model_path")], [44, 45, 7])

    def test_merkle_inclusion(self):
        for e in DOC["merkle_inclusion"]:
            with self.subTest(e["name"]):
                i = e["input"]
                ok = verify_rfc9162_inclusion(rfc9162_leaf_hash(bytes.fromhex(i["leaf_hex"])), i["index"], i["size"],
                                              [bytes.fromhex(h) for h in i["proof_hex"]], bytes.fromhex(i["root_hex"]))
                self.assertEqual({"ok": ok}, e["expect"])

    def test_gate(self):
        for e in DOC["gate"]:
            with self.subTest(e["name"]):
                self.assertEqual(provenance_gate(e["input"]), e["expect"])

    def test_model_path(self):
        for e in DOC["model_path"]:
            with self.subTest(e["name"]):
                self.assertEqual({"model": is_model_derived_path(e["input"]["path"])}, e["expect"])

    def test_caveat_defaults(self):
        c = provenance_caveat("ci", 3, source_repo="https://github.com/acme/tool")
        self.assertEqual(c, {"type": "needs_discharge", "id": "provenance", "issuer": "ci", "issuer_class": "artifact", "bind": "action", "ttl_ms": 300000,
                             "require": [{"claim": "slsa_level", "op": "gte", "value": 3}, {"claim": "source_repo", "op": "eq", "value": "https://github.com/acme/tool"},
                                         {"claim": "runtime_bound", "op": "eq", "value": True}]})

    def test_total(self):
        for bad in (None, 1, "x", [], {"facts": {}, "policy": {}}):
            self.assertFalse(provenance_gate(bad)["ok"])
        self.assertFalse(verify_rfc9162_inclusion(b"", 2**60, 1, None, b""))


if __name__ == "__main__":
    unittest.main()
