"""Shared vectors for linked policy templates: packages/pca/conformance/policy-link-vectors.json."""
import json
import os
import unittest

from atlas_pca.policy_link import template_def_error, instantiate_template, resolve_link, template_digest, template_ref_error, verify_template, verify_tighten

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "policy-link-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


def _out(r):
    return {"ok": True, "policy": r["policy"]} if r["ok"] else {"ok": False, "reason": r["reason"]}


class PolicyLinkVectors(unittest.TestCase):
    def test_digest(self):
        self.assertEqual(template_digest(DOC["template"]["def"]), DOC["template"]["digest"])

    def test_def_errors(self):
        self.assertGreaterEqual(len(DOC["def_errors"]), 9)
        for e in DOC["def_errors"]:
            with self.subTest(e["name"]):
                self.assertEqual(template_def_error(e["def"]), e["expect"])

    def test_instantiate(self):
        self.assertGreaterEqual(len(DOC["instantiate"]), 14)
        for e in DOC["instantiate"]:
            with self.subTest(e["name"]):
                self.assertEqual(_out(instantiate_template(DOC["template"]["def"], e["slots"])), e["expect"])

    def test_verify(self):
        for e in DOC["verify"]:
            with self.subTest(e["name"]):
                fn = verify_template if e["kind"] == "template" else verify_tighten
                self.assertEqual(fn(e["signed"], e["trusted"]), e["expect"])

    def test_ref_errors(self):
        for e in DOC["ref_errors"]:
            with self.subTest(e["name"]):
                self.assertEqual(template_ref_error(e["ref"]), e["expect"])

    def test_resolve(self):
        for e in DOC["resolve"]:
            with self.subTest(e["name"]):
                r = resolve_link(e["ref"], e["registry"])
                want = e["expect"]
                got = {"ok": True, "overlays": r["overlays"], "policy": r["policy"]} if r["ok"] else {"ok": False, "reason": r["reason"]}
                self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main()
