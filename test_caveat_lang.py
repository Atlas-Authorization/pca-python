"""Caveat language v2 (track K1): replays every primitive of packages/pca/conformance/caveat-lang-vectors.json."""
import json
import os
import tempfile
import unittest

from atlas_pca import MemoryStateStore, SqliteStateStore
from atlas_pca.caveat_lang import (
    bound_caveats, derive_error, discharge_shape_error, evaluate_caveats_k1, evaluate_k1, max_uses_error, max_uses_slot_key,
    needs_discharge_error, reserve_max_uses, spiffe_bound_error, spiffe_id_error, verify_discharge, verify_narrow,
)
from atlas_pca.pca import supported_suites

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "caveat-lang-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)["primitives"]


def _shape(c):
    t = c.get("type") if isinstance(c, dict) else None
    fn = {"needs_discharge": needs_discharge_error, "max_uses": max_uses_error, "derive": derive_error, "spiffe_bound": spiffe_bound_error}.get(t)
    return fn(c) if fn else "unknown type"


class CaveatLangVectors(unittest.TestCase):
    def test_counts(self):
        # a runner that silently skipped vectors must fail
        self.assertGreaterEqual([len(DOC[k]) for k in ("discharge_verify", "k1_eval", "caveat_shape", "uses_key", "uses_reserve", "spiffe_id", "k1_unconfigured")],
                                [54, 102, 50, 5, 12, 24, 9])

    def test_discharge_verify(self):
        have = set(supported_suites())
        ran = 0
        for e in DOC["discharge_verify"]:
            with self.subTest(e["name"]):
                i = e["input"]
                r = verify_discharge(i["discharge"], i["caveat"], i["binding"])
                need = e.get("requires_suite")
                if need is not None and need not in have:
                    self.assertFalse(r["ok"])
                    self.assertIn("unsupported_suite", r["reason"])
                    continue
                ran += 1
                self.assertEqual(r["ok"], e["expect"]["ok"], r)
                if r["ok"]:
                    self.assertEqual((r["digest"], r["claims"]), (e["expect"]["digest"], e["expect"]["claims"]))
                else:
                    self.assertIn(e["expect"]["reason_contains"], r["reason"])
        self.assertGreaterEqual(ran, 51)

    def test_k1_eval(self):
        for e in DOC["k1_eval"]:
            with self.subTest(e["name"]):
                i = e["input"]
                allow, failed = evaluate_caveats_k1(i["grant"], i["chain"], i["k1"], i["context"])
                self.assertEqual(allow, e["expect"]["allow"])
                self.assertEqual(failed, sorted(e["expect"]["failed"]))

    def test_k1_unconfigured(self):
        for e in DOC["k1_unconfigured"]:
            with self.subTest(e["name"]):
                i = e["input"]
                allow, failed = evaluate_caveats_k1(i["grant"], i["chain"], None, i["context"])
                self.assertEqual(allow, e["expect"]["allow"])
                self.assertEqual(failed, sorted(e["expect"]["failed"]))

    def test_caveat_shape(self):
        for e in DOC["caveat_shape"]:
            with self.subTest(e["name"]):
                self.assertEqual(_shape(e["input"]["caveat"]) is None, e["expect"]["valid"])

    def test_uses_key(self):
        for e in DOC["uses_key"]:
            with self.subTest(e["name"]):
                i = e["input"]
                self.assertEqual(max_uses_slot_key(i["cap_hash"], i["id"], i["i"]), e["expect"]["key"])

    def test_uses_reserve(self):
        for e in DOC["uses_reserve"]:
            with self.subTest(e["name"]):
                store = MemoryStateStore()
                calls, want = e["input"]["calls"], e["expect"]["results"]
                self.assertEqual(len(calls), len(want))
                for call, w in zip(calls, want):
                    r = reserve_max_uses(store, e["input"]["bound"], call["now"])
                    self.assertEqual(r["ok"], w["ok"], r)
                    if w["ok"]:
                        self.assertEqual(r["spent"], w["spent"])
                    else:
                        self.assertIn(w["reason_contains"], r["reason"])

    def test_consume_once_ttl(self):
        self.assertGreaterEqual(len(DOC["consume_once_ttl"]), 9)
        d = tempfile.mkdtemp()
        makers = {"memory": MemoryStateStore, "sqlite": lambda: SqliteStateStore(os.path.join(tempfile.mkdtemp(dir=d), "s.db"))}
        for kind, make in makers.items():
            for e in DOC["consume_once_ttl"]:
                with self.subTest(kind + ":" + e["name"]):
                    store, got = make(), []
                    for st in e["input"]["steps"]:
                        try:
                            got.append("true" if store.consume_once(st["key"], st["retain_until"], st["now"]) else "false")
                        except ValueError:
                            got.append("error")
                    self.assertEqual(got, e["expect"]["results"])

    def test_spiffe_id(self):
        for e in DOC["spiffe_id"]:
            with self.subTest(e["name"]):
                self.assertEqual(spiffe_id_error(e["input"]["id"]) is None, e["expect"]["valid"])


class CaveatLangUnits(unittest.TestCase):
    HOSTILE = [None, 0, 1.5, "x", [], [1], {}, True, {"a": {"b": 1}}]

    def test_hostile_inputs_never_raise(self):
        for h in self.HOSTILE:
            self.assertFalse(verify_discharge(h, h, h)["ok"])
            self.assertFalse(verify_narrow(h, h, h, h)["ok"])
            self.assertFalse(reserve_max_uses(MemoryStateStore(), [{"caveat": h, "cap_hash": "x"}], "now")["ok"])
            self.assertFalse(evaluate_k1(h, h, h, h)["ok"])
            self.assertEqual(evaluate_caveats_k1(h, h, h, h)[0], False)
            self.assertIsNone(bound_caveats(h, h)) if not isinstance(h, dict) else None
            for fn in (needs_discharge_error, max_uses_error, derive_error, spiffe_bound_error, discharge_shape_error):
                self.assertIsInstance(fn(h), str)
            self.assertIsInstance(spiffe_id_error(h), str)

    def test_trailing_newline_and_bool_are_not_ids(self):
        c = {"type": "max_uses", "id": "u\n", "n": 1, "until": 5}
        self.assertEqual(max_uses_error(c), "id is malformed")
        self.assertIsNotNone(max_uses_error({"type": "max_uses", "id": "u", "n": True, "until": 5}))
        self.assertIsNotNone(spiffe_id_error("spiffe://acme.test\n"))

    def test_absent_k1_refuses_but_empty_k1_is_configured(self):
        g = {"issuer": "a", "holder": "b", "caveats": [{"type": "sealed"}], "parent": None}
        for absent in (None, [], "x", 0):
            r = evaluate_k1(g, [g], absent, {"now": 5})
            self.assertEqual((r["ok"], r["failed"], r["reasons"]), (False, ["sealed"], ["the caveat language is not configured (no k1 input)"]))
        self.assertTrue(evaluate_k1(g, [g], {}, {"now": 5})["ok"])

    def test_unknown_k1_free_chain_is_unchanged(self):
        g = {"issuer": "a", "holder": "b", "caveats": [{"type": "expires", "at": 10}], "parent": None}
        self.assertEqual(evaluate_caveats_k1(g, [g], {}, {"now": 5}), (True, []))
        self.assertEqual(evaluate_caveats_k1(g, [g], {}, {"now": 50}), (False, ["expires"]))


if __name__ == "__main__":
    unittest.main()
