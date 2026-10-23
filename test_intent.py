"""Intent Layer M2 (`envelope.intent`) unit tests for the native Python verifier.

The shared `intent-*` conformance vectors (test_conformance.py) pin the full contract; these are small native
checks: wire refusals, the absent-policy back-compat verdict, policy misconfiguration, and a positive binding whose
goal commitment is built with this package's own canonical hash. Runs under pytest or `python3 test_intent.py`.
"""
import copy
import json
import os
import unittest

from atlas_pca import decide_intent_binding, hash_canonical, intent_goal, verify_pcactn_core
from atlas_pca.pca import b64u, sha256

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")

with open(os.path.join(DIR, "vectors.json"), encoding="utf-8") as f:
    VEC = next(x for x in json.load(f)["vectors"] if x["name"] == "valid-in-plan-action")
PCACTN, GRANT, NOW, AUD = VEC["pcactn"], VEC["grant"], VEC["context"]["now"], VEC["context"]["aud"]

REF = b64u(sha256(b"intent/ref"))
MAP = b64u(sha256(b"intent/map"))
SALT = "c2FsdC1pbnRlbnQ"
INTENT = {"ref": REF, "map_digest": MAP, "goal_salt": SALT, "fidelity_ppm": 950_000, "residual_risk_ppm": 4_310_000}


def _commit(ref=REF, map_digest=MAP, salt=SALT):
    return hash_canonical({"d": "atlas-pca/goal/v1\u0000", "goal": "pca-intent:v1:" + ref + ":" + map_digest, "salt": salt})


def _grant(*caveats):
    return {"caveats": list(caveats)}


def _with_intent(intent):
    p = copy.deepcopy(PCACTN)
    p["intent"] = intent
    return p


def _verify(p, policy=None):
    return verify_pcactn_core(p, GRANT, now=NOW, audience=AUD, intent_policy=policy)


class IntentWire(unittest.TestCase):
    def test_refusals_are_terminal_wire(self):
        bad = [
            "x", None, [INTENT], {**INTENT, "note": "x"},
            {k: v for k, v in INTENT.items() if k != "goal_salt"},
            {**INTENT, "ref": REF + "="}, {**INTENT, "map_digest": "+" + MAP[1:]}, {**INTENT, "ref": 1},
            {**INTENT, "goal_salt": ""}, {**INTENT, "goal_salt": "é" * 64 + "a"}, {**INTENT, "goal_salt": 5},
            {**INTENT, "fidelity_ppm": 1_000_001}, {**INTENT, "fidelity_ppm": -1}, {**INTENT, "fidelity_ppm": 1.5},
            {**INTENT, "fidelity_ppm": "950000"}, {**INTENT, "fidelity_ppm": True},
            {**INTENT, "residual_risk_ppm": -1}, {**INTENT, "residual_risk_ppm": 0.25},
            {**INTENT, "residual_risk_ppm": True}, {**INTENT, "residual_risk_ppm": -0.0},
        ]
        for i in bad:
            with self.subTest(i=repr(i)[:60]):
                got = _verify(_with_intent(i))
                self.assertFalse(got.allow)
                self.assertEqual(got.checks, {"wire": False}, got.reason)

    def test_well_formed_edges_pass_wire(self):
        for i in ({**INTENT, "goal_salt": "é" * 64}, {**INTENT, "fidelity_ppm": 1_000_000, "residual_risk_ppm": 0},
                  {**INTENT, "residual_risk_ppm": 9_007_199_254_740_991}):
            with self.subTest(i=repr(i)[:60]):
                self.assertTrue(_verify(_with_intent(i)).checks["wire"])


class IntentCheck(unittest.TestCase):
    def test_absent_without_policy_is_pre_m2_verdict(self):
        for policy in (None, {}, {"require": False}, {"require": 1}):
            with self.subTest(policy=policy):
                got = _verify(PCACTN, policy)
                self.assertTrue(got.allow, got.reason)
                self.assertEqual(got.checks, VEC["expect"]["checks"])
                self.assertNotIn("intent", got.checks)

    def test_active_policy_requires_intent(self):
        for policy in ({"require": True}, {"min_fidelity_ppm": 1}, {"max_residual_risk_ppm": 10}):
            with self.subTest(policy=policy):
                got = _verify(PCACTN, policy)
                self.assertFalse(got.allow)
                self.assertIs(got.checks["intent"], False)
                self.assertEqual(list(got.checks)[-1], "intent")
                self.assertTrue(got.reason.startswith("intent:"), got.reason)

    def test_policy_misconfigured_fails_closed(self):
        g = _grant({"type": "envelope", "goal_commit": _commit()})
        for policy in ({"min_fidelity_ppm": -1}, {"max_residual_risk_ppm": 0.5}, {"min_fidelity_ppm": None},
                       {"min_fidelity_ppm": True}, {"max_residual_risk_ppm": "5"}):
            with self.subTest(policy=policy):
                status, why = decide_intent_binding(INTENT, g, policy)
                self.assertEqual(status, "fail")
                self.assertIn("misconfigured", why)

    def test_positive_binding(self):
        self.assertEqual(intent_goal(REF, MAP), "pca-intent:v1:" + REF + ":" + MAP)
        g = _grant({"type": "max_spend", "usd": 1}, {"type": "envelope", "goal_commit": _commit()})
        self.assertEqual(decide_intent_binding(INTENT, g), ("pass", None))
        self.assertEqual(decide_intent_binding(INTENT, g, {"require": True}), ("pass", None))
        self.assertEqual(decide_intent_binding(INTENT, g, {"min_fidelity_ppm": 950_000, "max_residual_risk_ppm": 4_310_000}),
                         ("pass", None))
        self.assertEqual(decide_intent_binding(INTENT, g, {"min_fidelity_ppm": 950_001})[0], "fail")
        self.assertEqual(decide_intent_binding(INTENT, g, {"max_residual_risk_ppm": 4_309_999})[0], "fail")

    def test_binding_mismatches_fail(self):
        good = {"type": "envelope", "goal_commit": _commit()}
        cases = [
            (INTENT, _grant()),
            (INTENT, _grant({"type": "envelope", "goal_commit": 7})),
            (INTENT, _grant({"type": "envelope", "goal_commit": _commit(salt="other")}, good)),  # first envelope wins
            ({**INTENT, "goal_salt": "wrong"}, _grant(good)),
            ({**INTENT, "ref": MAP}, _grant(good)),
            (INTENT, "not-a-grant"),
        ]
        for intent, g in cases:
            with self.subTest(g=repr(g)[:60]):
                self.assertEqual(decide_intent_binding(intent, g)[0], "fail")

    def test_full_verify_reports_intent_last(self):
        # The fixture grant has no envelope caveat, and the added slot is signed, so both checks fail.
        got = _verify(_with_intent(INTENT))
        self.assertFalse(got.allow)
        self.assertTrue(got.checks["wire"])
        self.assertIs(got.checks["leaf_signature"], False)
        self.assertIs(got.checks["intent"], False)
        self.assertEqual(list(got.checks)[-1], "intent")


if __name__ == "__main__":
    unittest.main()
