"""The `fresh_at` PCActn member: replays packages/pca/conformance/fresh-at-vectors.json against verify_pcactn_core (allow, every core
check, the `fresh_at` status, the ternary decision and the exact reason). Also pins that a PCActn with neither the member nor a policy
verifies byte-identically to before (no `fresh_at` entry in `checks`)."""
import copy
import json
import os
import unittest

from atlas_pca import decision_of, verify_pcactn_core

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "fresh-at-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


def _policy(ctx):
    """context.fresh_at is already the snake_case policy dict (`side_carried` present even when null)."""
    return ctx.get("fresh_at")


def _verify(v, pcactn=None):
    ctx = v["context"]
    return verify_pcactn_core(v["pcactn"] if pcactn is None else pcactn, v["grant"], now=ctx["now"], audience=ctx["aud"], fresh_at=_policy(ctx))


class FreshAtVectors(unittest.TestCase):
    def test_check_order(self):
        self.assertEqual(DOC["check_order"][-1], "fresh_at")

    def test_vectors(self):
        self.assertEqual(len(DOC["vectors"]), 28)
        for v in DOC["vectors"]:
            with self.subTest(v["name"]):
                got = _verify(v)
                want = v["expect"]
                checks = dict(got.checks)
                status = {True: "pass", False: "fail"}.get(checks.pop("fresh_at", None), "absent")
                self.assertEqual(got.allow, want["allow"], got.reason)
                self.assertEqual(checks, want["checks"], got.reason)
                self.assertEqual(status, want["fresh_at"], got.reason)
                self.assertEqual(decision_of({"allow": got.allow, "checks": {k: "pass" if ok else "fail" for k, ok in got.checks.items()},
                                              "reasons": got.reasons}), want["decision"], got.reason)
                if "reason" in want:
                    # the reference spells the leaf-signature failure "... leaf holder key / suite"; every other reason is exact
                    if want["reason"].startswith("leaf_signature:"):
                        self.assertTrue(got.reason.startswith("leaf_signature: signature does not verify under the leaf holder key"), got.reason)
                    else:
                        self.assertEqual(got.reason, want["reason"])
                else:
                    self.assertIsNone(got.reason)

    def test_member_is_signed_by_the_leaf(self):
        v = next(x for x in DOC["vectors"] if x["name"] == "member-equal-state")
        p = copy.deepcopy(v["pcactn"])
        p["fresh_at"]["revocation_epoch"] += 1  # a different (still well-formed) member than the one the leaf signed
        got = _verify(v, p)
        self.assertFalse(got.allow)
        self.assertFalse(got.checks["leaf_signature"])

    def test_absent_member_and_policy_changes_nothing(self):
        v = next(x for x in DOC["vectors"] if x["name"] == "no-member-no-policy")
        got = verify_pcactn_core(v["pcactn"], v["grant"], now=v["context"]["now"], audience=v["context"]["aud"])
        self.assertTrue(got.allow)
        self.assertNotIn("fresh_at", got.checks)


if __name__ == "__main__":
    unittest.main()
