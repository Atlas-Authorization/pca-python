"""Pins the verifier's observable output text (reasons, parse errors, number errors, chain verdicts) over the whole corpus; see
mutation_snapshots.py. Any behavioural change shows up here, which is what kills error-message and branch-order mutants."""
import gzip
import json
import os
import unittest

from mutation_snapshots import OUT, collect


class Snapshots(unittest.TestCase):
    def test_snapshot_matches(self):
        with gzip.open(OUT, "rt", encoding="utf-8") as f:
            want = json.load(f)
        got = json.loads(json.dumps(collect(), ensure_ascii=True))
        for section in want:
            self.assertEqual(set(got[section]), set(want[section]), section)
            bad = [k for k in want[section] if got[section][k] != want[section][k]]
            self.assertEqual(bad[:5], [], f"{section}: {len(bad)} differ; first {bad[:1] and (got[section][bad[0]], want[section][bad[0]])}")


if __name__ == "__main__":
    unittest.main()
