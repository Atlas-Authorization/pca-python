"""fresh_at through authorize() and the require_pca guard (what the FastAPI / Django adapters call): the signed vector PCActns
(packages/pca/conformance/fresh-at-vectors.json) admitted or escalated by the policy the host supplies."""
import copy
import json
import os
import unittest
from unittest import mock

import sys
import atlas_pca.authorize  # noqa: F401
az = sys.modules["atlas_pca.authorize"]
from atlas_pca import AuthorizeOptions, MemoryStateStore, authorize, require_pca

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "fresh-at-vectors.json")
with open(_P, encoding="utf-8") as f:
    V = {v["name"]: v for v in json.load(f)["vectors"]}

# The vector grants carry no policy envelope (the default-required `policy` check would fail them) and Python cannot sign one:
# give the grant an envelope permitting the write; the PCActn, its signatures and the fresh_at check stay real.
ENV = {"goal_commit": "g", "predicates": [{"verb": "write", "resource": "db/orders"}], "caveats": [], "agent_binding": {}}
patch_env = mock.patch.object(az, "read_envelope", lambda grant: dict(ENV))

OP = {"verb": "write", "resource": "db/orders", "params": {"qty": 3}}


def kwargs(v, policy):
    g = v["grant"]
    return dict(operation=OP, audience=v["context"]["aud"], resolve_grant=lambda ref: g if ref == g["id"] else None,
                state_store=MemoryStateStore(), is_revoked=lambda p, gr: False, now=v["context"]["now"],
                context=lambda p: {"plan": v["plan_nodes"], "plan_authorized": True}, fresh_at=policy)


def env(v):
    return json.dumps({"pcactn": v["pcactn"]})


def stale(policy):
    p = copy.deepcopy(policy)
    p["local"]["revocation_epoch"] -= 1  # the verifier is behind the token
    return p


class AuthorizeFreshAt(unittest.TestCase):
    def setUp(self):
        patch_env.start()
        self.addCleanup(patch_env.stop)

    def test_ok(self):
        v = V["member-equal-state"]
        r = authorize(v["pcactn"], **kwargs(v, v["context"]["fresh_at"]))
        self.assertTrue(r.allow, r.reasons)
        self.assertEqual(r.checks["fresh_at"], "pass")

    def test_callable_policy(self):
        v = V["member-equal-state"]
        r = authorize(v["pcactn"], **kwargs(v, lambda p: v["context"]["fresh_at"]))
        self.assertTrue(r.allow, r.reasons)

    def test_stale_escalates(self):
        v = V["member-equal-state"]
        r = authorize(v["pcactn"], **kwargs(v, stale(v["context"]["fresh_at"])))
        self.assertFalse(r.allow)
        self.assertEqual(r.decision, "escalate")
        self.assertEqual(r.checks["fresh_at"], "fail")

    def test_no_policy_refused(self):
        v = V["member-equal-state"]
        r = authorize(v["pcactn"], **kwargs(v, None))
        self.assertFalse(r.allow)
        self.assertEqual(r.checks["fresh_at"], "fail")

    def test_raising_callable_denies(self):
        v = V["member-equal-state"]

        def boom(p):
            raise RuntimeError("x")
        r = authorize(v["pcactn"], **kwargs(v, boom))
        self.assertFalse(r.allow)
        self.assertEqual(r.status, 403)


class GuardFreshAt(unittest.TestCase):
    def setUp(self):
        patch_env.start()
        self.addCleanup(patch_env.stop)

    def guard(self, v, policy):
        k = kwargs(v, policy)
        return require_pca(audience=k["audience"], resolve_grant=k["resolve_grant"], now=k["now"], fresh_at=policy,
                           authorize=AuthorizeOptions(state_store=k["state_store"], is_revoked=k["is_revoked"], context=k["context"]),
                           operation=lambda h, b: OP)

    def test_member_ok_and_stale(self):
        v = V["member-equal-state"]
        h = {}
        r = self.guard(v, v["context"]["fresh_at"])(h, env(v))
        self.assertTrue(r.ok, r.error)
        r = self.guard(v, stale(v["context"]["fresh_at"]))(h, env(v))
        self.assertFalse(r.ok)
        self.assertEqual(r.decision, "escalate")

    def test_side_carried_header(self):
        v = V["side-carried-ok"]
        pol = {k: x for k, x in v["context"]["fresh_at"].items() if k != "side_carried"}
        tok = json.dumps(v["context"]["fresh_at"]["side_carried"])
        r = self.guard(v, pol)({"Pca-Fresh-At": tok}, env(v))
        self.assertTrue(r.ok, r.error)
        r = self.guard(v, pol)({"pca-fresh-at": "{not json"}, env(v))  # garbage = bad token
        self.assertFalse(r.ok)
        self.assertNotEqual(r.decision, "escalate")
        r = self.guard(v, pol)({}, env(v))  # no header, no member, not required: unchanged
        self.assertTrue(r.ok, r.error)


if __name__ == "__main__":
    unittest.main()
