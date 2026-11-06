"""K3 operational-plane artifacts: replays packages/pca/conformance/k3-vectors.json (policy bundles, decision log, list receipts / cursors,
grant management, consistency tokens). Every vector must match its `expect` exactly."""
import json
import os
import unittest

from atlas_pca import (
    authority_digest, bundle_digest, check_fresh_at, compare_authority, fresh_at_digest, list_bind, objects_digest, record_commit,
    verify_amendment, verify_batch, verify_bundle, verify_fresh_at, verify_list_cursor, verify_list_receipt, verify_log_head,
    verify_need_approval, verify_record_inclusion, verify_revoke_signature,
)

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "k3-vectors.json")
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)["primitives"]


def _check_fresh_at(i):
    o = i["options"]
    return check_fresh_at(i["token"], i["local"], o["signer"], o["scope"], o["now"], o.get("maxTokenAgeMs"))


def _bundle_verify(i):
    o = i["options"]
    return verify_bundle(i["bundle"], o["signers"], o["threshold"], o["verifierVersion"], o.get("last"))


def _amend(i):
    r = verify_amendment(i["grant"], i["request"], i["step_up_ok"])
    return {"ok": True, "widens": r["widens"], "next_digest": authority_digest(r["next"])} if r["ok"] else r


def _need(i):
    r = verify_need_approval(i["need_request"], i["grant"], i["approved"], i.get("sig"), i["step_up_ok"])
    return {"ok": True, "authority_digest": authority_digest(r["authority"])} if r["ok"] else r


def _revoke(i):
    return verify_revoke_signature(i["root"], i["scope"], i.get("sig"))


def _cursor(i):
    return verify_list_cursor(i["cursor"], i["signer"], i.get("bind"))


def _receipt(i):
    return {"valid": verify_list_receipt(i["receipt"], i["signer"], i.get("objects"))}


RUNNERS = {
    "fresh_at_verify": lambda i: {"valid": verify_fresh_at(i["token"], i["signer"])},
    "fresh_at_digest": lambda i: {"digest": fresh_at_digest(i["token"])},
    "fresh_at_check": _check_fresh_at,
    "bundle_digest": lambda i: {"digest": bundle_digest(i["bundle"])},
    "bundle_verify": _bundle_verify,
    "log_commit": lambda i: {"commit": record_commit(i["record"])},
    "log_head_verify": lambda i: {"valid": verify_log_head(i["head"], i["signer"])},
    "log_inclusion": lambda i: {"valid": verify_record_inclusion(i["record"], i["proof"], i["head"], i["signer"])},
    "log_batch_verify": lambda i: verify_batch(i["batch"], i["state"], i["signer"]),
    "list_objects_digest": lambda i: {"digest": objects_digest(i["objects"])},
    "list_receipt_verify": _receipt,
    "list_bind": lambda i: {"digest": list_bind(i["bind"])},
    "list_cursor_verify": _cursor,
    "authority_digest": lambda i: {"digest": authority_digest(i["authority"])},
    "authority_compare": lambda i: {"order": compare_authority(i["old"], i["new"])},
    "amend_verify": _amend,
    "revoke_verify": _revoke,
    "need_approve_verify": _need,
}


class K3Vectors(unittest.TestCase):
    def test_every_kind_has_a_runner(self):
        self.assertEqual(set(DOC), set(RUNNERS))

    def test_vectors(self):
        n = 0
        for kind, entries in DOC.items():
            self.assertTrue(entries, kind)
            for e in entries:
                with self.subTest("%s: %s" % (kind, e["name"])):
                    self.assertEqual(RUNNERS[kind](e["input"]), e["expect"])
                n += 1
        self.assertGreaterEqual(n, 100)

    def test_total_on_garbage(self):
        junk = [None, 7, "x", [], {}, {"v": 1}, [None], {"sigs": 3}]
        for j in junk:
            self.assertFalse(verify_fresh_at(j, "s"))
            self.assertFalse(verify_log_head(j, "s"))
            self.assertFalse(verify_list_receipt(j, "s"))
            self.assertFalse(verify_record_inclusion(j, j, j, "s"))
            self.assertFalse(verify_bundle(j, [], 1, "1.0.0")["ok"])
            self.assertFalse(verify_batch(j, j, "s")["ok"])
            self.assertFalse(verify_list_cursor(j, "s")["ok"])
            self.assertFalse(verify_amendment(j, j, True)["ok"])
            self.assertFalse(verify_revoke_signature(j, "grant", j)["ok"])
            self.assertFalse(verify_need_approval(j, j, j, j, True)["ok"])
            self.assertNotEqual(check_fresh_at(j, j, "s", "sc", 0)["decision"], "ok")
            self.assertEqual(compare_authority(j, j), "incomparable")

    def test_cursor_rejects_extra_segment_and_empty_signature(self):
        v = next(e for e in DOC["list_cursor_verify"] if e["expect"].get("ok"))["input"]
        self.assertEqual(verify_list_cursor(v["cursor"] + ".x", v["signer"]), {"ok": False, "reason": "malformed"})
        self.assertEqual(verify_list_cursor(v["cursor"].split(".")[0] + ".", v["signer"]), {"ok": False, "reason": "malformed"})


if __name__ == "__main__":
    unittest.main()
