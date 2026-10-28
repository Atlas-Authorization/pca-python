"""Workflow admission through the guard (require_pca; FastAPI RequirePCA and Django PCAMiddleware wrap it unchanged and take the
same AuthorizeOptions): the step comes from the options' callback, else the JSON body member `workflow`."""
import json
import os
import unittest

from atlas_pca import AuthorizeOptions, MemoryStateStore
from atlas_pca.server import require_pca

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "authorize-workflow-fixtures.json")
with open(_P, encoding="utf-8") as f:
    F = json.load(f)
CASES = {c["name"]: c for c in F["cases"]}
KEYS = ("commitment", "receipts", "step", "units", "goal_digest")


def _guard(workflow, **kw):
    opts = AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False,
                            context=lambda p: {"plan": F["plan"], "plan_authorized": True}, workflow=workflow, **kw)
    return require_pca(audience=F["audience"], resolve_grant=lambda ref: F["grant"] if ref == F["grant"]["id"] else None,
                       now=F["now"], authorize=opts)


def _wf(required):
    return {"principal": F["principal"], "rs_signer": F["rs_signer"], "required": required}


def _call(g, s, member=True):
    body = {"pcactn": s["pcactn"]}
    w = s.get("workflow")
    if member and w is not None:
        body["workflow"] = {k: w.get(k) for k in KEYS}
    return g({}, json.dumps(body), operation=s["operation"])


class MiddlewareWorkflow(unittest.TestCase):
    def test_valid_steps_pass(self):
        c = CASES["pay-after-quote"]
        g = _guard(_wf(c["required"]))
        for s in c["steps"]:
            r = _call(g, s)
            self.assertTrue(r.ok, r.error)

    def test_edge_violation_is_403(self):
        c = CASES["amount-over-the-quote"]
        g = _guard(_wf(c["required"]))
        r = None
        for s in c["steps"]:
            r = _call(g, s)
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 403)
        self.assertIn("workflow: edge_relation (step pay)", r.error)
        self.assertEqual(r.authorization.checks, {"workflow": "fail"})

    def test_required_and_absent(self):
        for name in ("workflow-required-but-absent", "undecodable-pcactn-workflow-required-and-absent"):
            g = _guard(_wf(True))
            r = g({}, json.dumps({"pcactn": "not-a-pcactn"}), operation=CASES[name]["steps"][0]["operation"])
            self.assertEqual((r.ok, r.status), (False, 403), name)
            self.assertIn("workflow: this call carries no workflow step (fail closed)", r.error)
        s = CASES["workflow-required-but-absent"]["steps"][0]
        r = _call(_guard(_wf(True)), s)
        self.assertEqual((r.ok, r.status), (False, 403))
        self.assertIn("this call carries no workflow step", r.error)

    def test_optional_and_absent_passes(self):
        s = CASES["workflow-optional-and-absent"]["steps"][0]
        self.assertTrue(_call(_guard(_wf(False)), s).ok)

    def test_no_workflow_option_is_unchanged(self):
        c = CASES["amount-over-the-quote"]
        g = _guard(None)  # a `workflow` member in the body is ignored
        self.assertTrue(all(_call(g, s).ok for s in c["steps"][:1]))
        s = CASES["workflow-required-but-absent"]["steps"][0]
        self.assertTrue(_call(g, s).ok)

    def test_callback_source_wins_over_body(self):
        c = CASES["amount-over-the-quote"]
        ws = [dict(zip(KEYS, [s["workflow"].get(k) for k in KEYS])) for s in c["steps"]]
        it = iter(ws)
        g = _guard(_wf(True), workflow_step=lambda h, b: next(it))
        r = None
        for s in c["steps"]:
            r = _call(g, s, member=False)
        self.assertEqual(r.status, 403)
        self.assertIn("edge_relation (step pay)", r.error)

    def test_raising_callback_and_bad_option_fail_closed(self):
        s = CASES["pay-after-quote"]["steps"][0]
        def boom(h, b): raise RuntimeError("x")
        r = _call(_guard(_wf(False), workflow_step=boom), s)
        self.assertEqual((r.ok, r.status), (False, 403))
        r = _call(_guard("x"), s)
        self.assertEqual((r.ok, r.status), (False, 403))


if __name__ == "__main__":
    unittest.main()
