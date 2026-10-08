"""PCA wire-format v2 conformance driver (native Python verifier).

Runs the shared golden + adversarial corpus at packages/pca/conformance/vectors.json (154 v2 vectors plus the
threshold-share and pq-artifact primitive tables) against the native `atlas_pca` verifier, requiring it to
reproduce `allow` and every listed check for EVERY vector it can evaluate.

Signature-suite coverage. The verifier implements the THREE cross-impl suites every conformant impl must agree
on: classical `ed25519`, the pure lattice `ml-dsa-65` (FIPS-204) and the hybrid `ed25519 + ml-dsa-65`. The
lattice/hybrid suites route through `dilithium-py`; when that library is absent they FAIL CLOSED, so a vector
that would need a genuine positive crypto verdict under them is skipped (never silently passed). The remaining
seven registered suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their hybrids and the SUF-CMA nested hybrid) are
not implemented in Python and are likewise skipped, per suite, with an explicit count.

A terminal `wire` failure (`{wire: false}`) is suite-AGNOSTIC: the verifier rejects an unknown / unimplemented
suite (unknown `alg`, or a `pq_sig` the suite requires but cannot size) at the wire stage, which IS the correct
contract verdict for those negatives, so those vectors are still RUN even when their suite is unimplemented.

Runs under pytest or directly (`python3 test_conformance.py`). No pytest dependency.
"""
import json
import os
import unittest

from atlas_pca import (
    StrictJsonError, canonicalize_strict, decode_b64u_strict, hash_canonical, merkle_root, params_digest,
    strict_parse, verify_artifact_suite, verify_inclusion, verify_pcactn_core, verify_threshold_share,
)
from atlas_pca.mldsa import ml_dsa65_available
from atlas_pca.pca import b64u, sha256

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")


def _load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


DOC = _load("vectors.json")

# The three cross-impl signature suites. `ml-dsa-65` / `hybrid-ed25519-ml-dsa-65` need dilithium-py at runtime;
# if it is absent they cannot produce a positive verdict, so they drop out of the RUNNABLE set (honest skip).
_ML_DSA = ml_dsa65_available()
SUPPORTED_SUITES = frozenset(
    {"ed25519"} | ({"ml-dsa-65", "hybrid-ed25519-ml-dsa-65"} if _ML_DSA else set())
)


def _alg(obj):
    return obj.get("alg", "ed25519") if isinstance(obj, dict) else "ed25519"


def _unsupported_suite(v):
    """The concrete signature suite a vector exercises that this verifier does NOT run, if any: the leaf `alg`
    for requires:"pq", or any capability-hop `alg` for requires:"pq-nonleaf". None otherwise (core vectors, and
    vectors that stay entirely within SUPPORTED_SUITES — e.g. a downgrade hop stripped back to ed25519)."""
    p = v.get("pcactn")
    if not isinstance(p, dict):
        return None
    req = v.get("requires")
    if req == "pq":
        a = _alg(p)
        return None if a in SUPPORTED_SUITES else a
    if req == "pq-nonleaf":
        for hop in p.get("cap_chain", []) or []:
            a = _alg(hop)
            if a not in SUPPORTED_SUITES:
                return a
    return None


def _terminal_wire_false(v):
    c = v["expect"]["checks"]
    return len(c) == 1 and c.get("wire") is False


class Conformance(unittest.TestCase):
    def test_format(self):
        self.assertEqual(DOC["format"], 2)
        self.assertEqual(len(DOC["vectors"]), 154)

    def test_vectors(self):
        self.assertTrue(DOC["vectors"])
        passed = 0
        skipped_by_suite = {}
        for v in DOC["vectors"]:
            suite = _unsupported_suite(v)
            # Skip ONLY a vector whose expected verdict needs a genuine signature outcome under an unrunnable
            # suite. A terminal {wire:false} negative is run regardless: unknown/unimplemented alg -> wire fail.
            if suite is not None and not _terminal_wire_false(v):
                skipped_by_suite[suite] = skipped_by_suite.get(suite, 0) + 1
                continue
            with self.subTest(v["name"]):
                raw = v["pcactn_json"] if "pcactn_json" in v else v["pcactn"]
                ctx = v["context"]
                got = verify_pcactn_core(raw, v["grant"], now=ctx["now"], audience=ctx["aud"])
                self.assertEqual(got.allow, v["expect"]["allow"], got.reason)
                self.assertEqual(got.checks, v["expect"]["checks"], got.reason)
            passed += 1
        total = len(DOC["vectors"])
        skipped = sum(skipped_by_suite.values())
        print(f"\n[vectors] {passed}/{total} passed; {skipped} skipped "
              f"(dilithium-py {'present' if _ML_DSA else 'ABSENT'})")
        for s in sorted(skipped_by_suite):
            print(f"  skip suite {s}: {skipped_by_suite[s]}")
        self.assertEqual(passed + skipped, total)
        # The three cross-impl suites MUST be exercised on BOTH the leaf (requires:"pq") and hops
        # (requires:"pq-nonleaf") whenever their crypto backend is available.
        if _ML_DSA:
            leaf_ran = [v["name"] for v in DOC["vectors"]
                        if v.get("requires") == "pq" and _unsupported_suite(v) is None
                        and _alg(v["pcactn"]) in ("ml-dsa-65", "hybrid-ed25519-ml-dsa-65")]
            hop_ran = [v["name"] for v in DOC["vectors"]
                       if v.get("requires") == "pq-nonleaf" and _unsupported_suite(v) is None
                       and any(_alg(h) in ("ml-dsa-65", "hybrid-ed25519-ml-dsa-65")
                               for h in v["pcactn"].get("cap_chain", []))]
            self.assertTrue(leaf_ran, "cross-impl PQ leaf vectors must run")
            self.assertTrue(hop_ran, "cross-impl PQ non-leaf hop vectors must run")

    def test_smallorder_forgeries_reject(self):
        vs = [v for v in DOC["vectors"] if v["name"].startswith("forge-smallorder-")]
        self.assertEqual(len(vs), 3)
        for v in vs:
            got = verify_pcactn_core(v["pcactn"], v["grant"], now=v["context"]["now"], audience=v["context"]["aud"])
            self.assertFalse(got.allow, v["name"])

    def test_threshold_shares(self):
        """v2.1 agent-leaf share binding: every primitives.threshold_share[] entry must verify over the
        signerSetHash|t-bound share message iff `valid`; in particular the PRE-v2.1 bare agent share and a
        cross-signer-set replay MUST be rejected. All corpus shares are ed25519, so no PQ backend is needed."""
        shares = DOC["primitives"]["threshold_share"]
        self.assertTrue(shares)
        accepted = rejected = 0
        bare_rejected = wrong_set_rejected = False
        for s in shares:
            name = s.get("name") or s["role"]
            want = s.get("valid", True)
            with self.subTest(name):
                got = verify_threshold_share(s)
                self.assertEqual(got, want, f"{name}: share verified={got}, want valid={want}")
            if want:
                accepted += 1
            else:
                rejected += 1
            if name == "agent-bare-rejected":
                bare_rejected = not verify_threshold_share(s)
            if name == "agent-bound-wrong-set":
                wrong_set_rejected = not verify_threshold_share(s)
        self.assertTrue(bare_rejected, "v2.1 binding: the pre-v2.1 bare agent share MUST be rejected")
        self.assertTrue(wrong_set_rejected, "v2.1 binding: a cross-signer-set agent share replay MUST be rejected")
        print(f"\n[threshold_share] {accepted} valid accepted, {rejected} invalid rejected "
              f"(incl. v2.1 bare-agent-share + cross-signer-set replay)")

    def test_pq_artifacts(self):
        """pq_artifact[]: each transparency/authority artifact signature must verify over `message` under its
        suite iff `valid`, for the IMPLEMENTED suites. Artifacts under an unrunnable suite are skipped per suite."""
        arts = DOC["primitives"]["pq_artifact"]
        self.assertTrue(arts)
        checked = 0
        skipped_by_suite = {}
        for a in arts:
            alg = a.get("alg", "ed25519")
            if alg not in SUPPORTED_SUITES:
                skipped_by_suite[alg] = skipped_by_suite.get(alg, 0) + 1
                continue
            with self.subTest(f"{a['artifact']}/{alg}/valid={a['valid']}"):
                self.assertEqual(verify_artifact_suite(a), a["valid"], a.get("description"))
            checked += 1
        skipped = sum(skipped_by_suite.values())
        print(f"\n[pq_artifact] {checked} checked, {skipped} skipped")
        for s in sorted(skipped_by_suite):
            print(f"  skip suite {s}: {skipped_by_suite[s]}")
        self.assertEqual(checked + skipped, len(arts))

    def test_primitives(self):
        prim = DOC["primitives"]
        for c in prim["canonical"]:
            self.assertEqual(canonicalize_strict(c["value"]), c["expect"])
            self.assertEqual(b64u(sha256(c["expect"].encode("utf-8"))), c["hash"])
            self.assertEqual(hash_canonical(c["value"]), c["hash"])
        for m in prim["merkle"]:
            self.assertEqual(merkle_root(m["leaves"]), m["root"])
            for i, pr in enumerate(m["proofs"]):
                self.assertTrue(verify_inclusion(m["root"], pr, m["leaves"][i]))
        self.assertEqual(params_digest(), prim["params_digest_empty"])

    def test_json_parse(self):
        for c in DOC["primitives"]["json_parse"]:
            with self.subTest(c["input"][:40]):
                if c["accept"]:
                    self.assertEqual(canonicalize_strict(strict_parse(c["input"])), c["canonical"])
                else:
                    with self.assertRaises(StrictJsonError):
                        strict_parse(c["input"])

    def test_b64u(self):
        for c in DOC["primitives"]["b64u"]:
            with self.subTest(c["input"][:30]):
                self.assertEqual(decode_b64u_strict(c["input"], c.get("len")) is not None, c["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
