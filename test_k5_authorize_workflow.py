"""Workflow admission inside authorize() (C-308): replays packages/pca/conformance/authorize-workflow-fixtures.json (a missing file FAILS)."""
import json
import os
import unittest

from atlas_pca import MemoryStateStore, authorize
from prov_harness import prov

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "authorize-workflow-fixtures.json")
with open(_P, encoding="utf-8") as f:
    F = json.load(f)


class AuthorizeWorkflow(unittest.TestCase):
    def test_format(self):
        self.assertEqual(F["format"], "pca-authorize-workflow-fixtures/1")
        self.assertGreaterEqual(len(F["cases"]), 14)

    def test_cases(self):
        for c in F["cases"]:
            with self.subTest(c["name"]):
                store = MemoryStateStore()  # ONE replay store per case
                for s in c["steps"]:
                    w = s.get("workflow")
                    r = authorize(s["pcactn"], operation=s["operation"], audience=F["audience"],
                                  resolve_grant=lambda ref: F["grant"] if ref == F["grant"]["id"] else None, state_store=store,
                                  is_revoked=lambda p, g: False, now=F["now"],
                                  context=lambda p: {"plan": F["plan"], "plan_authorized": True},
                                  workflow={"principal": F["principal"], "rs_signer": F["rs_signer"], "required": c["required"]},
                                  workflow_step=None if w is None else {k: w.get(k) for k in ("commitment", "receipts", "step", "units", "goal_digest")},
                                  # provenance by default: every operation comes straight from the principal (harness pin)
                                  **prov(s["operation"]))
                    e = s["expect"]
                    self.assertEqual({"allow": r.allow, "decision": r.decision, "status": r.status,
                                      "failed": sorted(k for k, v in r.checks.items() if v == "fail")},
                                     {k: e[k] for k in ("allow", "decision", "status", "failed")})
                    if "reason" in e:
                        self.assertIn(e["reason"], r.reason or "")
                    if e["failed"] == ["workflow"]:
                        self.assertEqual(r.checks, {"workflow": "fail"})

    def test_bad_option_fails_closed(self):
        s = F["cases"][0]["steps"][0]
        r = authorize(s["pcactn"], operation=s["operation"], audience=F["audience"], resolve_grant=lambda ref: F["grant"],
                      state_store=MemoryStateStore(), is_revoked=lambda p, g: False, now=F["now"], workflow="x")
        self.assertFalse(r.allow)
        self.assertEqual(r.checks, {"workflow": "fail"})


if __name__ == "__main__":
    unittest.main()
