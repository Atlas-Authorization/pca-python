"""Replays packages/pca/conformance/passport-vectors.json (signed agent passport) against the native verifier: every
signature suite available in this runtime (an unavailable one must answer `unsupported_suite`), and the hardware branch
through a stub vendor verifier that answers what the vector says. The `passport_hardware_vectors` table replays the same rows
through the REAL vendor verifiers (atlas_pca.attest) as the default verifier."""
import json
import os
import unittest

from atlas_pca import supported_suites, verify_passport

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "passport-vectors.json")


class PassportConformance(unittest.TestCase):
    def test_vectors(self):
        with open(FILE, encoding="utf-8") as f:
            vs = json.load(f)["passport_vectors"]
        self.assertGreaterEqual(len(vs), 74)
        supported = set(supported_suites())
        docs, bad, pq_seen = {}, [], 0
        for v in vs:
            signed = docs[v["signed_ref"]] if "signed_ref" in v else v["signed"]
            docs[v["name"]] = signed
            revoked = set(v["revoked"])
            seen = []
            attest = None
            if "hardware" in v:
                h = v["hardware"]

                def attest(doc, expected, h=h, seen=seen):
                    seen.append(expected)
                    if h.get("throws"):
                        raise RuntimeError("verifier down")
                    return {"ok": h["ok"], "bound": h["bound"], "measured": h.get("measured")}

            got = verify_passport(
                signed, v["trustedIssuers"], v["now"], v.get("clockSkewMs"), v.get("maxEvidenceAgeMs"), v.get("subject"),
                lambda i, _a, _b, r=revoked: i in r, v.get("pqPins"), attest,
            )
            want = None if v["expect"]["ok"] else v["expect"]["reason"]
            alg = signed.get("alg") if isinstance(signed, dict) else None
            if alg is not None:
                if alg in supported:
                    pq_seen += 1
                else:
                    want = "unsupported_suite"
            if got != want:
                bad.append("%s: got %r want %r" % (v["name"], got, want))
            if "expectBinding" in v:
                eb = v["expectBinding"]
                want_b = {"holder_pub": eb["holderPub"], "grant_ref": eb["grantRef"], "epoch": eb["epoch"], "nonce": eb["nonce"]}
                if seen != [want_b]:
                    bad.append("%s: verifier was handed %r want %r" % (v["name"], seen, want_b))
        self.assertGreaterEqual(pq_seen, 1)
        self.assertEqual(bad, [])

    def test_hardware_vendor_vectors(self):
        """Hardware-rooted passports verified by the real vendor verifier built from the vector's config (the default verifier)."""
        try:
            from atlas_pca.attest import verifier_from_config
            import cryptography  # noqa: F401
        except ImportError:
            if os.environ.get("PCA_REQUIRE_ATTEST") == "1":
                raise
            self.skipTest("needs the `cryptography` package (extra `attest`)")
        with open(FILE, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertIn("passport_hardware_vectors", doc, "passport-vectors.json lacks passport_hardware_vectors: regenerate and commit it")
        vs = doc["passport_hardware_vectors"]
        self.assertGreaterEqual(len(vs), 40)
        docs = {v["name"]: v["signed"] for v in doc["passport_vectors"] if "signed" in v}
        bad, hw_ok = [], 0
        for v in vs:
            signed = docs[v["signed_ref"]] if "signed_ref" in v else v["signed"]
            docs[v["name"]] = signed
            hv = v["hardware_verifier"]
            evidence = hv["evidence"]
            verifier = verifier_from_config(hv["vendor"], hv["config"], lambda _doc, e=evidence: e)
            revoked = set(v.get("revoked", []))
            got = verify_passport(
                signed, v["trustedIssuers"], v["now"], v.get("clockSkewMs"), v.get("maxEvidenceAgeMs"), v.get("subject"),
                lambda i, _a, _b, r=revoked: i in r, v.get("pqPins"), None, verifier,
            )
            want = None if v["expect"]["ok"] else v["expect"]["reason"]
            if got != want:
                bad.append("%s: got %r want %r" % (v["name"], got, want))
            hw_ok += 1 if want is None else 0
            # without the default verifier the same passport is refused, never passed
            if want is None:
                self.assertEqual(
                    verify_passport(signed, v["trustedIssuers"], v["now"], v.get("clockSkewMs"), v.get("maxEvidenceAgeMs"), v.get("subject"), lambda i, _a, _b, r=revoked: i in r, v.get("pqPins")),
                    "hardware_verifier_missing",
                    v["name"],
                )
        self.assertGreaterEqual(hw_ok, 5)
        self.assertEqual(bad, [])

    def test_fail_closed_without_revocation_source(self):
        with open(FILE, encoding="utf-8") as f:
            v = json.load(f)["passport_vectors"][0]
        self.assertEqual(verify_passport(v["signed"], v["trustedIssuers"], v["now"]), "revocation_unavailable")
        def boom(*_a):
            raise RuntimeError("down")
        self.assertEqual(verify_passport(v["signed"], v["trustedIssuers"], v["now"], revoked=boom), "revocation_unavailable")


if __name__ == "__main__":
    unittest.main()
