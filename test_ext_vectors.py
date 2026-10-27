"""Extension-layer conformance (optimistic path and transparency ledger): every vector of
packages/pca/conformance/{optimistic,ledger}-vectors.json must reproduce its `expect` exactly. No skips."""
import json
import os
import unittest

from atlas_pca import (
    claim_check, challenge_window_end, claim_status, detect_equivocation, fraud_proof_wire_check, settlement_wire_check,
    verify_checkpoint_chain, verify_head_consistency, verify_ledger_consistency, verify_ledger_inclusion, verify_tree_head,
    supported_suites, verify_witnessed_head, within_challenge_window,
)
from atlas_pca.ledger import EMPTY_TREE_ROOT, STH_DOMAIN, STH_WITNESS_DOMAIN

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")


def _load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


OPT, LED = _load("optimistic-vectors.json"), _load("ledger-vectors.json")

# The row counts of the committed corpus, asserted against the REAL table sizes (not only the file's own `counts`).
EXPECTED_COUNTS = {
    "optimistic_claim": 52, "optimistic_window": 25, "optimistic_fraud_proof": 37, "optimistic_settlement": 102,
    "ledger_inclusion": 96, "ledger_consistency": 149, "ledger_tree_head": 64, "ledger_cosign": 56, "ledger_head_consistency": 26,
    "ledger_checkpoint_chain": 23, "ledger_witnessed_head": 30, "ledger_equivocation": 7,
}


def _lacks(v):
    """`requires_suite` names a registered suite this runtime lacks: it must refuse (false / `suite`), never accept."""
    return "requires_suite" in v and v["requires_suite"] not in supported_suites()


def _want(v):
    w = dict(v["expect"])
    if _lacks(v):
        if "check" in w:
            w.update(check="suite", ok=False)
        elif "ok" in w:
            w["ok"] = False
    return w


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
        c = settlement_wire_check(v["record"], v["guardian_public"], v.get("pins"))
    return {"check": c, "ok": c == "ok"}


def _led(table, v):
    if table == "ledger_inclusion":
        return {"ok": verify_ledger_inclusion(v["root"], v["proof"], v["leaf"])}
    if table == "ledger_consistency":
        return {"ok": verify_ledger_consistency(v["old_root"], v["new_root"], v["proof"])}
    if table == "ledger_tree_head":
        return {"ok": verify_tree_head(v["sth"], v["guardian_public"], None, v.get("pins"))}
    if table == "ledger_cosign":
        return {"ok": verify_tree_head(v["sth"], v["guardian_public"], v["policy"], v.get("pins"))}
    if table == "ledger_head_consistency":
        return {"ok": verify_head_consistency(v["older"], v["newer"], v["proof"], v["guardian_public"], None, v.get("pins"))}
    if table == "ledger_checkpoint_chain":
        return verify_checkpoint_chain(v["chain"], v["guardian_public"], v["policy"], v.get("pins"))
    if table == "ledger_witnessed_head":
        return {"ok": verify_witnessed_head(v["head"], v["witness_public"], v.get("pins"))}
    return {"equivocation": detect_equivocation(v["a"], v["b"], v["witness_public"], v.get("pins"))}


class ExtVectors(unittest.TestCase):
    def _run(self, doc, table, fn):
        rows = doc[table]
        self.assertEqual(len(rows), doc["counts"][table])
        self.assertEqual(len(rows), EXPECTED_COUNTS[table], "%s: this runner pins another size" % table)
        bad = [v["name"] for v in rows if fn(table, v) != _want(v)]
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
