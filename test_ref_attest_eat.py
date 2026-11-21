"""Differential oracle for atlas_pca.attest_eat (EAT build / verify, freshness, channel binding, RATS appraisal, tolerant SEV-SNP
parse, AMD delegation, post-quantum co-signature, admission evidence, artifact discharge) against the TypeScript reference
(@atlasauth/pca-attest-eat) vectors in test-data/ref-attest-eat.json.gz.

Where the port is deliberately stricter than the reference the case is asserted as a refusal instead (see STRICTER); the cases
that read the real clock are skipped (their expected output depends on the day the vectors were made)."""
import hashlib

import pytest

pytest.importorskip("cryptography")

from atlas_pca import attest_eat as E, ed25519, pca  # noqa: E402
from atlas_pca.agent import generate_pq_keypair  # noqa: E402
from atlas_pca.pca import b64u  # noqa: E402
from atlas_pca.sigstore_bundle import parse_trusted_root  # noqa: E402
from base_oracle import b64d, canon, covered, load_gen, load_ref, merge_cases, require_gen, run  # noqa: E402

ed25519.allow_insecure_signer(True)
COUNT, _MAIN = load_ref("attest-eat")
_GEN = load_gen("attest-eat")
CASES = merge_cases(_MAIN, _GEN)

_DISCHARGE_NONCE = b64u(hashlib.sha256(b"eat-oracle-nonce/0").digest()[:16])  # the reference's counter-hash nonce, first draw
_DBGSTAT = ("enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently")
_PQ_SLOT = {"ml-dsa-65": ("mlDsa", "ML-DSA-65"), "ml-dsa-87": ("mlDsa87", "ML-DSA-87"),
            "slh-dsa-sha2-128f": ("slhDsa", "SLH-DSA-SHA2-128f"), "slh-dsa-sha2-256s": ("slhDsa256s", "SLH-DSA-SHA2-256s")}


def _verify_key(spec):
    if spec["alg"] == "EdDSA":
        return b64d(spec["pub"])
    return E.verify_key_from_jwk({"kty": "EC", "crv": "P-256", "x": spec["x"], "y": spec["y"]})


def _with_verify_key(opts):
    if isinstance(opts, dict) and isinstance(opts.get("verifyKey"), dict) and opts["verifyKey"].get("alg"):
        return dict(opts, verifyKey=_verify_key(opts["verifyKey"]))
    return opts


def _build(args):
    k = args.get("key")
    if isinstance(k, dict) and k.get("alg"):
        args = dict(args, key=b64d(k["seed"]))
    return E.build_eat(args)


def _verify_eat(eat, pub, opts=None):
    return E.verify_eat(eat, _verify_key(pub), {} if opts is None else opts)


def _tolerant(b):
    r = E.parse_report_tolerant(b)
    out = {"ok": r["ok"], "version": r["version"], "known": r["known"], "degraded": r["degraded"], "notes": r["notes"],
           "hasReport": "report" in r}
    if "evidence" in r:
        out["evidence"] = r["evidence"]
    if "report" in r:
        out["measured"] = E.measured_from_report(r["report"])
    return out


def _amd(b, opts):
    r = E.verify_amd_attestation(b, opts)
    return {k: r[k] for k in ("ok", "hardwareRoot", "reason", "evidence", "measured") if k in r}


def _pq_keys(spec):
    keys = {}
    if "ed" in spec:
        keys["edSecret"] = b64d(spec["ed"])
    if "pq" in spec:
        slot, family = _PQ_SLOT[spec["pq"]["prim"]]
        keys[slot] = generate_pq_keypair(family, b64d(spec["pq"]["seed"]))
    return keys


def _cosign(verdict, op):
    o = {"secretKey": _pq_keys(op["key"])}
    if "suite" in op:
        o["suite"] = op["suite"]
    if "now" in op:
        o["now"] = op["now"]
    return E.co_sign_attestation(verdict, o)


def _discharge(i):
    i = dict(i, roots=parse_trusted_root(i["roots"]), issuerSecret=b64d(i["issuerKey"]["seed"]), nonce=_DISCHARGE_NONCE)
    return E.issue_artifact_discharge(i)


def _constants():
    return {
        "EAT_TYP": E.EAT_TYP, "DEFAULT_EAT_ALG": E.DEFAULT_EAT_ALG, "DEFAULT_MAX_AGE_MS": E.DEFAULT_MAX_AGE_MS,
        "CHANNEL_BINDING_DOMAIN": E.CHANNEL_BINDING_DOMAIN, "AMD_SEV_SNP_SIGNED_REGION_END": E.AMD_SEV_SNP_SIGNED_REGION_END,
        "AMD_SEV_SNP_HARDWARE_ROOT_LABEL": E.AMD_SEV_SNP_HARDWARE_ROOT_LABEL, "KNOWN_REPORT_VERSIONS": list(E.KNOWN_REPORT_VERSIONS),
        "KNOWN_AMD_ARK_SPKI_SHA384": E.KNOWN_AMD_ARK_SPKI_SHA384, "AMD_MILAN_ARK_SPKI_SHA384": E.AMD_MILAN_ARK_SPKI_SHA384,
        "PQCOSIGN_DOMAIN": E.PQCOSIGN_DOMAIN, "DEFAULT_PQ_COSIGN_SUITE": E.DEFAULT_PQ_COSIGN_SUITE,
        "PQ_COSIGN_SUITES": list(E.PQ_COSIGN_SUITES),
    }


def _appraise_compare(got, out, c):
    if canon(got) == canon(out):
        return True
    # stricter than the reference: a dbgstat outside RFC 9711 is unknown, so a debug requirement fails closed
    a = c["args"]
    cl, rv = a[0], (a[1] if len(a) > 1 else None)
    return (isinstance(cl, dict) and "dbgstat" in cl and cl["dbgstat"] not in _DBGSTAT and isinstance(rv, dict)
            and rv.get("requireDebugDisabled") is True and got["tier"] == "rejected"
            and got["reasons"][-1] == "debug status unknown — failing closed")


# cases where the port is stricter than these vectors (a present clock skew that is not a finite number; a minimum tier other than
# affirming / affirming-hw-rooted): the current reference refuses them too, the vectors predate that fix
STRICTER = {"verifyFreshness/skew junk string", "verifyFreshness/skew junk stale", "verifyFreshness/skew string number",
            "verifyFreshness/skew null", "verifyFreshness/skew true", "verifyFreshAttestedEAT/amd skew junk",
            "eatAdmissionEvidence/min tier unknown", "eatAdmissionEvidence/min tier null"}
# cases whose reference output depends on the real clock of the day the vectors were generated
CLOCK = {"verifyFreshness/now missing uses clock", "verifyFreshness/now string uses clock", "verifyCoSignedAttestation/now string uses clock",
         "verifyCoSignedAttestation/valid no opts"}


def _compare_for(default=None):
    def cmp(got, out, c):
        if c["name"] in STRICTER:
            return got.get("ok") is False
        return default(got, out, c) if default else canon(got) == canon(out)
    return cmp


def _suite_skip(c):
    if c["name"] in CLOCK:
        return "reads the real clock"
    a, need = c["args"], set()
    if c["fn"] == "coSignAttestation":
        op = a[1]
        need.add(op.get("suite") or "ml-dsa-65")
        if isinstance(op.get("key"), dict) and "pq" in op["key"]:
            need.add(op["key"]["pq"]["prim"])
    elif c["fn"] == "verifyCoSignedAttestation" and isinstance(a[0], dict) and isinstance(a[0].get("suite"), str):
        need.add(a[0]["suite"])
    for s in need:
        if s in pca._SIG_SUITES and not pca.suite_available(s):
            return "no backend for %s in this runtime" % s
    return None


MAP = {
    "constants": (_constants, {}),
    "deriveChannelCnf": (E.derive_channel_cnf, {}),
    "bindChannel": (E.bind_channel, {}),
    "buildEAT": (_build, {}),
    "verifyEAT": (_verify_eat, {}),
    "verifyFreshness": (E.verify_freshness, {"compare": _compare_for(), "skip": lambda c: "reads the real clock" if c["name"] in CLOCK else None}),
    "verifyChannelBinding": (E.verify_channel_binding, {}),
    "appraise": (E.appraise, {"compare": _appraise_compare}),
    "parseReportTolerant": (_tolerant, {}),
    "verifyAmdAttestation": (_amd, {}),
    "verifyFreshAttestedEAT": (lambda eat, opts: E.verify_fresh_attested_eat(eat, _with_verify_key(opts)), {"compare": _compare_for()}),
    "canonicalVerdictBytes": (E.canonical_verdict_bytes, {}),
    "verdictFromAppraisal": (E.verdict_from_appraisal, {}),
    "isPqCoSignSuite": (E.is_pq_co_sign_suite, {}),
    "coSignAttestation": (_cosign, {"skip": _suite_skip}),
    "verifyCoSignedAttestation": (lambda c, op=None: E.verify_co_signed_attestation(c, op), {"skip": _suite_skip}),
    "ed25519Jkt": (E.ed25519_jkt, {}),
    "eatAdmissionEvidence": (lambda eat, op: E.eat_admission_evidence(eat, _with_verify_key(op)), {"compare": _compare_for()}),
    "runtimeDigestFromEat": (lambda v, op=None: E.runtime_digest_from_eat(v, op), {}),
    "issueArtifactDischarge": (_discharge, {}),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 1448 and covered(CASES, _GEN, MAP)  # 1448 committed; the private-key cases are in the generated -gen corpus


def test_secret_corpus_present():
    if _GEN is None:
        require_gen("attest-eat")


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    if fn not in CASES:
        require_gen("attest-eat")
    run(CASES[fn], call, **kw)


def test_stricter_cases_are_present_and_refused():
    names = {c["name"] for cs in CASES.values() for c in cs}
    assert STRICTER <= names


def test_issue_nonce_shape():
    n = E.issue_nonce({"now": 1_800_000_000_000, "bytes": 20})
    rand, _, ts = n["value"].partition(".")
    assert n["issuedAt"] == 1_800_000_000_000 and int(ts, 36) == 1_800_000_000_000 and len(b64d(rand)) == 20
    assert len(b64d(E.issue_nonce({"bytes": 3})["value"].split(".")[0])) == 16


def test_non_finite_clock_skew_and_unknown_min_tier_are_refused():
    base = {"expectedNonce": "n1", "now": 1_800_000_000_000, "maxAgeMs": 60_000}
    eat = {"eat_nonce": "n1", "iat": 1_000_000_000}  # decades stale: only an unbounded skew would admit it
    for skew in (float("inf"), float("-inf"), float("nan"), "5", None, True):
        r = E.verify_freshness(eat, dict(base, clockSkewMs=skew))
        assert r == {"ok": False, "reason": "invalid clockSkewMs (must be a finite number)"}, skew
    assert E.verify_freshness(eat, dict(base, clockSkewMs=5000))["ok"] is False
    for tier in ("warning", "rejected", "bogus", None, 2):
        assert E.eat_admission_evidence("x", {"instanceKey": "k", "minTier": tier}) == {"ok": False, "bound": False, "reason": "invalid minTier"}
