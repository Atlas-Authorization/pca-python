"""Pins the verifier's observable output text (reasons, parse errors, number errors, chain verdicts) over the whole corpus; see
mutation_snapshots.py. Any behavioural change shows up here, which is what kills error-message and branch-order mutants."""
import gzip
import json
import os
import unittest

from mutation_snapshots import OUT, collect, load_adv
from atlas_pca import REGISTERED_SUITES
from atlas_pca.pca import _SIG_SUITES
from test_conformance import DOC, SUPPORTED_SUITES


def _host_dependent():
    """"<src>:<name>" of every corpus vector that carries (anywhere: alg, requires, requires_suite) a suite this verifier
    implements but this runtime lacks the backend for (the cross-language gate's rule). The snapshot is written on a host with every backend (OpenSSL >= 3.5 +
    dilithium-py); on a host without some of them those vectors are refused with unsupported_suite (or not collected at
    all), so they are left out of the comparison on BOTH sides."""
    # only suites this verifier implements but whose backend is missing HERE: a never-implemented suite (fn-dsa) is refused
    # identically on every host and stays pinned
    lacking = ['"%s"' % a for a in REGISTERED_SUITES if a in _SIG_SUITES and a not in SUPPORTED_SUITES]
    out = set()
    if not lacking:
        return out
    for src, vs in (("core", DOC["vectors"]), ("adv", load_adv()["vectors"])):
        for v in vs:
            text = json.dumps(v, ensure_ascii=False) + (v.get("pcactn_json") or "")
            if any(a in text for a in lacking):
                out.add(src + ":" + v["name"])
    return out


def _keep(section, key, skip):
    if section == "vectors":
        return key not in skip
    if section == "chains":
        return key.rsplit(":", 1)[0] not in skip
    return True


class Snapshots(unittest.TestCase):
    def test_snapshot_matches(self):
        with gzip.open(OUT, "rt", encoding="utf-8") as f:
            want = json.load(f)
        got = json.loads(json.dumps(collect(), ensure_ascii=True))
        skip = _host_dependent()
        for section in want:
            want[section] = {k: x for k, x in want[section].items() if _keep(section, k, skip)}
            got[section] = {k: x for k, x in got[section].items() if _keep(section, k, skip)}
        for section in want:
            self.assertEqual(set(got[section]), set(want[section]), section)
            bad = [k for k in want[section] if got[section][k] != want[section][k]]
            self.assertEqual(bad[:5], [], f"{section}: {len(bad)} differ; first {bad[:1] and (got[section][bad[0]], want[section][bad[0]])}")


if __name__ == "__main__":
    unittest.main()
