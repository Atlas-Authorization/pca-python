"""Shared vectors for rules 20 (units), 21 (tighten-only) and the ternary decision: packages/pca/conformance/decision-vectors.json."""
import json
import os
import unittest

from atlas_pca.escalation import build_escalation_request, escalation_reasons_wire, verify_escalation_answer
from atlas_pca.decision import decide_tighten, decide_units, decision_of, fold_v2_reasons, meet, pep_decision, tighten
from atlas_pca.pca import supported_suites

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "decision-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)["primitives"]


def _input(e):
    # `input_text` is raw JSON text each runner parses itself: key order is part of the input
    return json.loads(e["input_text"]) if "input_text" in e else e["input"]


class DecisionVectors(unittest.TestCase):
    def test_escalation_truncate(self):
        for e in DOC["escalation_truncate"]:
            with self.subTest(e["name"]):
                req = build_escalation_request(aud="a", grant={"id": "g"}, pcactn={"action": {"verb": "v", "resource": "r"}},
                                               last_counter=None, reasons=e["input"]["reasons"], now=1)
                self.assertEqual(escalation_reasons_wire(req), e["expect"]["wire"])

    def test_units(self):
        for e in DOC["intent_units"]:
            with self.subTest(e["name"]):
                self.assertEqual(decide_units(_input(e)), e["expect"])

    def test_tighten(self):
        for e in DOC["intent_tighten"]:
            with self.subTest(e["name"]):
                r = decide_tighten(_input(e))
                self.assertEqual(r, e["expect"])

    def test_decision_of(self):
        for e in DOC["decision_of"]:
            with self.subTest(e["name"]):
                self.assertEqual(decision_of(e["input"]), e["expect"]["decision"])

    def test_lattice(self):
        for e in DOC["decision_lattice"]:
            i, n = e["input"], e["name"]
            with self.subTest(n):
                got = meet(i["a"], i["b"]) if n.startswith("meet-") else pep_decision(i["decision"], i.get("answered")) if n.startswith("pep-") else tighten(i["decision"], i["signal"])
                self.assertEqual(got, e["expect"]["decision"])
                if n.startswith("tighten-") or n.startswith("pep-") and i["decision"] != "escalate":
                    pass

    def test_escalation_answer(self):
        have = set(supported_suites())
        for e in DOC["escalation_answer"]:
            with self.subTest(e["name"]):
                i = _input(e)
                r = verify_escalation_answer(i["answer"], i["principals"], i["bind"], i["now"])
                need = e.get("requires_suite")
                if need is not None and need not in have:
                    # a suite this runtime cannot run is refused, never accepted and never mistaken for a bad signature
                    self.assertFalse(r["ok"])
                    self.assertIn("unsupported_suite", r["reason"])
                    continue
                self.assertEqual(r["ok"], e["expect"]["ok"])
                if r["ok"]:
                    self.assertEqual((r["principal"], r["decision"]), (e["expect"]["principal"], e["expect"]["decision"]))
                else:
                    self.assertIn(e["expect"]["reason_contains"], r["reason"])

    def test_every_suite_is_exercised_when_available(self):
        # at least the suites every build has must have run the positive vector (a skipped-everything runner fails here)
        names = {e["requires_suite"] for e in DOC["escalation_answer"] if e.get("requires_suite") and e["expect"]["ok"]}
        self.assertTrue({"ml-dsa-65", "slh-dsa-sha2-128f", "fn-dsa-512"} <= names)

    def test_escalation_fold(self):
        for e in DOC["escalation_fold"]:
            with self.subTest(e["name"]):
                i = e["input"]
                reasons = fold_v2_reasons(i["core_reasons"], i["v2"])
                allow = "fail" not in i["checks"].values()
                self.assertEqual({"reasons": reasons, "decision": decision_of({"allow": allow, "checks": i["checks"], "reasons": reasons})}, e["expect"])

    def test_never_widens(self):
        order = ["deny", "escalate", "allow"]
        for d in order:
            for s in ("ok", "escalate", "deny", None, "allow", 1):
                self.assertLessEqual(order.index(tighten(d, s)), order.index(d))
            self.assertNotEqual(pep_decision("deny", True), "allow")
            self.assertNotEqual(pep_decision("escalate", False), "allow")


if __name__ == "__main__":
    unittest.main()
