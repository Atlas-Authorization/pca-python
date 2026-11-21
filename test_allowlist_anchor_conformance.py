"""Replays packages/pca/conformance/allowlist-anchor-vectors.json (wire-level transparency-anchored allowlist evidence):
every vector must reproduce `expect.ok`, `expect.code` and `expect.highestAnchoredVersion`. No skips; a short corpus fails."""
import json
import os
import unittest

from atlas_pca.attest_allowlist_anchor import verify_allowlist_anchored

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")
with open(os.path.join(DIR, "allowlist-anchor-vectors.json"), encoding="utf-8") as f:
    DOC = json.load(f)
CODES = {"anchored-rollback", "bad-cache", "bad-head", "bad-proof", "feed-mismatch", "inconsistent-with-cache",
         "log-conflict", "log-rollback", "missing-proof", "split-view", "stale-head"}


def _run(v):
    r = verify_allowlist_anchored(
        v["manifest"], v.get("evidence"), DOC["trust"], v["now"],
        max_head_age_ms=v.get("maxHeadAgeMs"), clock_skew_ms=v.get("clockSkewMs"), cached_head=v.get("cachedHead"),
    )
    return {"ok": True, "highestAnchoredVersion": r["highestAnchoredVersion"]} if r["ok"] else {"ok": False, "code": r["code"]}


class AllowlistAnchorConformance(unittest.TestCase):
    def test_corpus_size_and_coverage(self):
        vs = DOC["allowlist_anchor"]
        self.assertGreaterEqual(len(vs), 74)
        self.assertEqual(len({v["name"] for v in vs}), len(vs))
        self.assertEqual({v["expect"]["code"] for v in vs if not v["expect"]["ok"]}, CODES)

    def test_every_vector(self):
        for v in DOC["allowlist_anchor"]:
            with self.subTest(v["name"]):
                self.assertEqual(_run(v), v["expect"])

    def test_total_on_garbage(self):
        # nothing raises and nothing passes: not a dict, wrong types, missing members
        for ev in (None, [], "x", {}, {"head": 1, "entries": [], "proof": {}}, {"head": {}, "entries": None, "proof": {}}):
            r = verify_allowlist_anchored({"issuer": "ops", "version": 1, "digest": "A" * 43}, ev, DOC["trust"], 1)
            self.assertFalse(r["ok"])
        self.assertFalse(verify_allowlist_anchored(None, None, None, None)["ok"])


if __name__ == "__main__":
    unittest.main()
