"""Goal binding v3 (approved_goal): replays packages/pca/conformance/goal-commit-vectors.json (`commit`, `invalid`, `binding`)."""
import json
import os
import unittest

from atlas_pca import (decide_intent_binding, intent_goal_commit, intent_goal_commit_v3, intent_goal_v3,
                       intent_policy_active, is_approved_goal_ref)

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "goal-commit-vectors.json")
with open(FILE, encoding="utf-8") as fh:
    DOC = json.load(fh)

G = "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw"
P = "9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo"


def _grant(commit):
    return {"caveats": [{"type": "envelope", "goal_commit": commit}] if isinstance(commit, str) else []}


class TestGoalCommitV3(unittest.TestCase):
    def test_corpus_sizes(self):
        self.assertEqual((len(DOC["commit"]), len(DOC["invalid"]), len(DOC["binding"])), (7, 4, 16))

    def test_commit_vectors(self):
        for v in DOC["commit"]:
            ref = {"goal_digest": v["goal_digest"], "policy_digest": v["policy_digest"]}
            self.assertEqual(v["goal"], intent_goal_v3(ref), v["name"])
            self.assertEqual(v["commit"], intent_goal_commit_v3(ref, v["salt"]), v["name"])

    def test_invalid_digests_are_refused(self):
        for v in DOC["invalid"]:
            ref = {"goal_digest": v["goal_digest"], "policy_digest": v["policy_digest"]}
            self.assertFalse(is_approved_goal_ref(ref), v["name"])
            with self.assertRaises(ValueError, msg=v["name"]):
                intent_goal_v3(ref)
            with self.assertRaises(ValueError, msg=v["name"]):
                intent_goal_commit_v3(ref, "s")

    def test_binding_vectors(self):
        for v in DOC["binding"]:
            status, why = decide_intent_binding(v["intent"], _grant(v["grant_commit"]), v["policy"], v.get("session"), v.get("map_form"))
            self.assertEqual(v["expect"], "pass" if status == "pass" else "fail", "%s: %s %s" % (v["name"], status, why))

    def test_unit_exact_outcomes(self):
        ref = {"goal_digest": G, "policy_digest": P}
        intent = {"ref": G, "map_digest": P, "goal_salt": "s", "fidelity_ppm": 1, "residual_risk_ppm": 0}
        v3 = intent_goal_commit_v3(ref, "s")
        v1 = intent_goal_commit(G, P, "s")
        pol = {"approved_goal": ref}
        self.assertTrue(intent_policy_active(pol))  # approved_goal alone activates the check
        self.assertEqual(("pass", None), decide_intent_binding(intent, _grant(v3), pol))
        self.assertEqual("fail", decide_intent_binding(intent, _grant(v1), pol)[0])  # v1 grant under a v3 policy
        self.assertEqual("fail", decide_intent_binding(intent, _grant(v3), {"require": True})[0])  # v3 grant under v1
        self.assertEqual("fail", decide_intent_binding(None, _grant(v3), pol)[0])  # absent intent
        self.assertEqual("fail", decide_intent_binding(intent, _grant(None), pol)[0])  # no envelope commit
        for bad in ({"goal_digest": G}, {"goal_digest": G, "policy_digest": P, "x": 1}, {"goal_digest": G, "policy_digest": ""}, None):
            status, why = decide_intent_binding(intent, _grant(v3), {"approved_goal": bad})
            self.assertEqual("fail", status)
            self.assertIn("misconfigured", why)
        self.assertEqual("fail", decide_intent_binding(intent, _grant(v3), dict(pol, min_fidelity_ppm=2))[0])  # floors still apply


if __name__ == "__main__":
    unittest.main()
