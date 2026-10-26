"""Extension-layer conformance (optimistic path and transparency ledger): every vector of
packages/pca/conformance/{optimistic,ledger}-vectors.json must reproduce its `expect` exactly. No skips."""
import json
import os
import unittest

from atlas_pca import (
    claim_check, challenge_window_end, claim_status, detect_equivocation, fraud_proof_wire_check, settlement_wire_check,
    verify_checkpoint_chain, verify_head_consistency, verify_ledger_consistency, verify_ledger_inclusion, verify_tree_head,
    verify_witnessed_head, within_challenge_window,
)
from atlas_pca.ledger import EMPTY_TREE_ROOT, STH_DOMAIN, STH_WITNESS_DOMAIN

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")


def _load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


OPT, LED = _load("optimistic-vectors.json"), _load("ledger-vectors.json")


def _opt(table, v):
    if table == "optimistic_claim":
        c = claim_check(v["claim"], v["pcactn_digest"], v["signer_public"], v["server_now"], OPT["window_policy"])
        return {"ok": c == "ok", "check": c}
    if table == "optimistic_window":
        c = {"issued_at": v["issued_at"], "challenge_window_ms": v["challenge_window_ms"]}
        return {"end": challenge_window_end(c), "within": within_challenge_window(c, v["now"]), "phase": claim_status(c, v["now"])}
    if table == "optimistic_fraud_proof":
        c = fraud_proof_wire_check(v["claim"], v["proof"])
    else:
        c = settlement_wire_check(v["record"], v["guardian_public"])
    return {"check": c, "ok": c == "ok"}


def _led(table, v):
    if table == "ledger_inclusion":
        return {"ok": verify_ledger_inclusion(v["root"], v["proof"], v["leaf"])}
    if table == "ledger_consistency":
        return {"ok": verify_ledger_consistency(v["old_root"], v["new_root"], v["proof"])}
    if table == "ledger_tree_head":
        return {"ok": verify_tree_head(v["sth"], v["guardian_public"])}
    if table == "ledger_cosign":
        return {"ok": verify_tree_head(v["sth"], v["guardian_public"], v["policy"])}
    if table == "ledger_head_consistency":
        return {"ok": verify_head_consistency(v["older"], v["newer"], v["proof"], v["guardian_public"])}
    if table == "ledger_checkpoint_chain":
        return verify_checkpoint_chain(v["chain"], v["guardian_public"], v["policy"])
    if table == "ledger_witnessed_head":
        return {"ok": verify_witnessed_head(v["head"], v["witness_public"])}
    return {"equivocation": detect_equivocation(v["a"], v["b"], v["witness_public"])}


class ExtVectors(unittest.TestCase):
    def _run(self, doc, table, fn):
        rows = doc[table]
        self.assertEqual(len(rows), doc["counts"][table])
        bad = [v["name"] for v in rows if fn(table, v) != v["expect"]]
        self.assertEqual(bad, [], table)

    def test_tables(self):
        for doc, fn in ((OPT, _opt), (LED, _led)):
            for table in doc["counts"]:
                with self.subTest(table=table):
                    self._run(doc, table, fn)

    def test_constants(self):
        self.assertEqual(LED["domains"]["sth"], STH_DOMAIN)
        self.assertEqual(LED["domains"]["sth_witness"], STH_WITNESS_DOMAIN)
        self.assertEqual(LED["empty_tree_root"], EMPTY_TREE_ROOT)


if __name__ == "__main__":
    unittest.main()
