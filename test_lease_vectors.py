"""Leases: replays packages/pca/conformance/lease-vectors.json (a missing file fails)."""
import json
import os
import unittest

from atlas_pca.lease import LeaseRegistry, check_lease

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "lease-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)


class LeaseVectors(unittest.TestCase):
    def test_scenarios(self):
        self.assertGreaterEqual(len(DOC["scenarios"]), 20)
        for s in DOC["scenarios"]:
            with self.subTest(s["name"]):
                reg = LeaseRegistry({"authorities": [DOC["authority"]], **s.get("policy", {})})
                for st in s["steps"]:
                    exp = st["expect"]
                    if st["op"] == "accept":
                        got = reg.accept(DOC["records"][st["record"]], st.get("chain", []))
                        for k in ("ok", "code", "replaced", "seq"):
                            self.assertEqual(got.get(k), exp.get(k), (s["name"], st, got))
                    elif st["op"] == "revoke":
                        got = reg.revoke(DOC["revocations"][st["revocation"]])
                        for k in ("ok", "code", "revoked"):
                            self.assertEqual(got.get(k), exp.get(k), (s["name"], st, got))
                    else:
                        self.assertEqual(check_lease(DOC["records"][st["record"]], reg, st["now"]), exp, (s["name"], st))


if __name__ == "__main__":
    unittest.main()
