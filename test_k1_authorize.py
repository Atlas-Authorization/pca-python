"""Caveat language v2 inside authorize() and the guard: no k1 refuses, max_uses is spent after the counter, request headers
(`PCA-Discharges` / `PCA-Narrow`) are merged under the verifier's own k1, and the `k1_headers` vectors."""
import copy
import json
import os
import sys
import unittest

from atlas_pca import AuthorizeOptions, MemoryStateStore, authorize, require_pca
from atlas_pca.pca import b64u, canonical_bytes_strict
from atlas_pca.server import presented_k1
from prov_harness import PIN, prov, prov_header

az = sys.modules["atlas_pca.authorize"]
HERE = os.path.dirname(os.path.abspath(__file__))
FIX = json.load(open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8"))
DOC = json.load(open(os.path.join(HERE, "conformance", "caveat-lang-vectors.json"), encoding="utf-8"))["primitives"]
NOW, AUD = FIX["now"], FIX["audience"]
CASE = next(c for c in FIX["cases"] if c["steps"][0]["expect"]["allow"] is True and len(c["steps"]) == 1)
STEP = CASE["steps"][0]
REAL = az.verify_pcactn_core
ORIG_VERDICT = REAL(STEP["pcactn"], CASE["grant"], now=NOW, audience=AUD)


def _with(root=(), delegated=()):
    """The allowing fixture with extra caveats on the root grant (and the leaf) / only on the leaf. The core verdict is the
    original's (the signatures are not re-minted); everything after it is the real pipeline."""
    g, p = copy.deepcopy(CASE["grant"]), copy.deepcopy(STEP["pcactn"])
    g["caveats"] = g["caveats"] + list(root)
    leaf = p["cap_chain"][-1]
    leaf["caveats"] = list(g["caveats"]) + list(delegated)
    return g, p


class K1Authorize(unittest.TestCase):
    def setUp(self):
        az.verify_pcactn_core = lambda *a, **k: ORIG_VERDICT

    def tearDown(self):
        az.verify_pcactn_core = REAL

    def run_az(self, g, p, **kw):
        return authorize(p, operation=STEP["operation"], audience=AUD, resolve_grant=lambda ref: g,
                         state_store=MemoryStateStore(), is_revoked=lambda p_, g_: False, now=NOW, plan="single-step",
                         **{**prov(STEP["operation"]), **kw})

    def test_no_k1_refuses_root_and_delegated(self):
        for g, p in (_with(root=[{"type": "sealed"}]), _with(delegated=[{"type": "sealed"}])):
            r = self.run_az(g, p)
            self.assertFalse(r.allow)
            self.assertEqual(r.checks["delegated_caveats"], "fail")
            self.assertIn("no k1 input", r.reason)
            for absent in ([], "x", 0):
                self.assertFalse(self.run_az(g, p, k1=absent).allow)

    def test_empty_k1_is_configured(self):
        for g, p in (_with(root=[{"type": "sealed"}]), _with(delegated=[{"type": "sealed"}])):
            self.assertTrue(self.run_az(g, p, k1={}).allow)

    def test_chain_without_k1_caveat_is_unchanged(self):
        g, p = _with()
        self.assertTrue(self.run_az(g, p).allow)

    def test_max_uses_needs_a_store_and_is_spent_once(self):
        g, p = _with(delegated=[{"type": "max_uses", "id": "u", "n": 1, "until": NOW + 60_000}])
        r = self.run_az(g, p, k1={})
        self.assertFalse(r.allow)
        self.assertIn("uses_store", r.reason)
        uses = MemoryStateStore()
        self.assertTrue(self.run_az(g, p, k1={}, uses_store=uses).allow)
        r = self.run_az(g, p, k1={}, uses_store=uses)
        self.assertFalse(r.allow)
        self.assertIn("exhausted", r.reason)

    def test_max_uses_not_spent_when_denied(self):
        g, p = _with(delegated=[{"type": "max_uses", "id": "u", "n": 1, "until": NOW + 60_000}, {"type": "spiffe_bound", "spiffe_id": "spiffe://a.test/x"}])
        uses = MemoryStateStore()
        self.assertFalse(self.run_az(g, p, k1={}, uses_store=uses).allow)
        g, p = _with(delegated=[{"type": "max_uses", "id": "u", "n": 1, "until": NOW + 60_000}])
        self.assertTrue(self.run_az(g, p, k1={}, uses_store=uses).allow)


def _hdr(v):
    return b64u(canonical_bytes_strict(v))


class K1Headers(unittest.TestCase):
    def test_k1_headers_vectors(self):
        self.assertGreaterEqual(len(DOC["k1_headers"]), 15)
        for e in DOC["k1_headers"]:
            with self.subTest(e["name"]):
                try:
                    got = {"ok": True, "value": presented_k1(e["input"]["headers"])}
                except ValueError:
                    got = {"ok": False}
                self.assertEqual(got["ok"], e["expect"]["ok"])
                if got["ok"]:
                    self.assertEqual(got["value"], e["expect"]["value"])

    def test_header_names_are_case_insensitive(self):
        self.assertEqual(presented_k1({"Pca-Narrow": _hdr({"a": 1})}), {"narrow": {"a": 1}})

    def test_guard_merges_presented_under_own_k1(self):
        seen = []
        real = az.evaluate_k1
        # record the k1 input; the verdict itself is stubbed (this test is about what the guard hands over)
        az.evaluate_k1 = lambda grant, chain, k1, ctx: (seen.append(k1), {"ok": k1 is not None, "failed": ["sealed"], "reasons": ["r"], "plain": [], "bound": []})[1]
        az.verify_pcactn_core = lambda *a, **k: ORIG_VERDICT
        try:
            g, p = _with(delegated=[{"type": "sealed"}])
            ds = [{"caveat_id": "x"}]

            def guard(k1):
                opts = AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda a, b: False, k1=k1,
                                        provenance_mediators=[PIN])
                return require_pca(audience=AUD, resolve_grant=lambda ref: g, now=NOW, authorize=opts)

            hdrs = {"PCA-Action": _hdr(p), "PCA-Discharges": _hdr(ds), "PCA-Narrow": _hdr({"n": 1}), **prov_header(STEP["operation"])}
            r = guard({"pins": ["p"], "narrow": "own"})(hdrs, None, operation=STEP["operation"])
            self.assertTrue(r.ok, r.error)
            self.assertEqual((seen[-1]["discharges"], seen[-1]["narrow"], seen[-1]["pins"]), (ds, "own", ["p"]))
            self.assertEqual(seen[-1]["action_digest"], az.discharge_action_digest(p))
            # unreadable headers are no discharges; the request is still judged
            bad = {"PCA-Action": _hdr(p), "PCA-Discharges": "!!!!", **prov_header(STEP["operation"])}
            self.assertTrue(guard({})(bad, None, operation=STEP["operation"]).ok)
            self.assertNotIn("discharges", seen[-1])
            # no k1 configured: presented headers do not configure the language, the K1 caveat is refused
            r = guard(None)(hdrs, None, operation=STEP["operation"])
            self.assertFalse(r.ok)
        finally:
            az.evaluate_k1 = real
            az.verify_pcactn_core = REAL


if __name__ == "__main__":
    unittest.main()
