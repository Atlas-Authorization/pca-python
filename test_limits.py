"""Shared hard limits (all PCA verifiers): 512 KiB raw PCActn document, checked before parsing; 256 caveats per hop and
1024 per chain, checked on raw list sizes before any hashing or signature work."""
import time
import unittest

from atlas_pca.pca import (
    ARTIFACT_SIZE_REASON, CAVEAT_LIMIT_REASON, MAX_ARTIFACT_BYTES, artifact_too_large, caveat_limit_exceeded,
    verify_chain, verify_pcactn_core,
)


def hop(n):
    return {"caveats": [{"type": "note"} for _ in range(n)]}


class Limits(unittest.TestCase):
    def test_size_cap(self):
        self.assertEqual(ARTIFACT_SIZE_REASON, "artifact exceeds size limit (max 524288 bytes)")
        pad = lambda n: "{}" + " " * (n - 2)
        for n in (MAX_ARTIFACT_BYTES - 1, MAX_ARTIFACT_BYTES):
            v = verify_pcactn_core(pad(n), {}, now=0, audience="a")
            self.assertNotIn(ARTIFACT_SIZE_REASON, v.reason or "")
        t = time.perf_counter()
        v = verify_pcactn_core("x" + pad(MAX_ARTIFACT_BYTES), {}, now=0, audience="a")  # garbage: the SIZE reason proves it precedes parsing
        self.assertFalse(v.allow)
        self.assertEqual(v.checks, {"wire": False})
        self.assertIn(ARTIFACT_SIZE_REASON, v.reason)
        self.assertLess(time.perf_counter() - t, 0.1)
        # UTF-8 bytes, not characters
        self.assertTrue(artifact_too_large("€" * 174763))
        self.assertFalse(artifact_too_large("€" * 174762))
        self.assertTrue(artifact_too_large(b"x" * (MAX_ARTIFACT_BYTES + 1)))

    def test_caveat_caps(self):
        self.assertEqual(verify_chain([hop(257)]), (False, CAVEAT_LIMIT_REASON))
        self.assertEqual(verify_chain([hop(205)] * 5), (False, CAVEAT_LIMIT_REASON))
        self.assertFalse(caveat_limit_exceeded([hop(204), hop(205), hop(205), hop(205), hop(205)]))
        self.assertFalse(caveat_limit_exceeded([hop(256)]))


if __name__ == "__main__":
    unittest.main()
