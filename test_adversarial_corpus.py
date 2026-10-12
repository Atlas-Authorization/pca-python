"""Full adversarial conformance corpus (packages/pca/conformance/vectors-adversarial.json.gz) against the native Python verifier.
test_conformance.py only runs the curated core; this runs every adversarial vector and primitive so a mutation of the verifier
that the shared corpus pins down cannot survive. Suites without a runnable backend are skipped exactly as in test_conformance."""
import gzip
import json
import os
import unittest

from atlas_pca import (
    StrictJsonError, canonicalize_strict, decode_b64u_strict, hash_canonical, merkle_root, strict_parse,
    verify_artifact_suite, verify_inclusion, verify_pcactn_core, verify_threshold_share,
)
from test_conformance import DIR, _terminal_wire_false, _unsupported_suite

with gzip.open(os.path.join(DIR, "vectors-adversarial.json.gz"), "rt", encoding="utf-8") as f:
    ADV = json.load(f)


class AdversarialCorpus(unittest.TestCase):
    def test_vectors(self):
        ran = 0
        for v in ADV["vectors"]:
            suite = _unsupported_suite(v)
            if suite is not None and not _terminal_wire_false(v):
                continue
            raw = v["pcactn_json"] if "pcactn_json" in v else v["pcactn"]
            ctx = v["context"]
            got = verify_pcactn_core(raw, v["grant"], now=ctx["now"], audience=ctx["aud"], allowed_suites=ctx.get("allowed_suites"))
            if got.allow != v["expect"]["allow"] or got.checks != v["expect"]["checks"]:
                self.fail(f"{v['name']}: got allow={got.allow} checks={got.checks} ({got.reason}); want {v['expect']}")
            ran += 1
        self.assertGreater(ran, 3000)

    def test_primitives(self):
        prim = ADV.get("primitives") or {}
        for c in prim.get("canonical", []):
            self.assertEqual(canonicalize_strict(c["value"]), c["expect"])
            self.assertEqual(hash_canonical(c["value"]), c["hash"])
        for m in prim.get("merkle", []):
            self.assertEqual(merkle_root(m["leaves"]), m["root"])
            for i, pr in enumerate(m["proofs"]):
                self.assertTrue(verify_inclusion(m["root"], pr, m["leaves"][i]))
        for c in prim.get("json_parse", []):
            if c["accept"]:
                self.assertEqual(canonicalize_strict(strict_parse(c["input"])), c["canonical"])
            else:
                with self.assertRaises(StrictJsonError):
                    strict_parse(c["input"])
        for c in prim.get("b64u", []):
            self.assertEqual(decode_b64u_strict(c["input"], c.get("len")) is not None, c["valid"], c["input"][:30])
        for s in prim.get("threshold_share", []):
            self.assertEqual(verify_threshold_share(s), s.get("valid", True), s.get("name") or s.get("role"))


if __name__ == "__main__":
    unittest.main()
