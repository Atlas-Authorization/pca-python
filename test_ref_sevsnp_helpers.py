"""Replays the TS-reference oracle of the pure SEV-SNP helpers (testdata/ref-sevsnp-helpers.json.gz, 248 cases): hex, PEM splitting, the report
parser (every field), the P-384 key and signature helpers, the report signature, the policy gate, the default identity, the AMD KDS VCEK fetch over an
injected transport and the certificate helpers (TBS extraction, VCEK key, VCEK <-> report binding). {"$bigint": s} is a 64-bit unsigned integer. Every
fn has a handler and the totals are asserted; a reference refusal needs a native exception. A binding reason after "VCEK extensions malformed:" is
library text: only the prefix is compared."""
import hashlib
import os

import pytest

pytest.importorskip("cryptography")  # the dependency-free job has no cryptography; every other job replays this corpus

from atlas_pca import attest_amd as A
from atlas_pca.attest_amd import BigU64
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("sevsnp-helpers", os.path.join(HERE, "testdata", "ref-sevsnp-helpers.json.gz"))
U64 = ("policy", "current_tcb", "platform_info", "reported_tcb", "committed_tcb", "launch_tcb", "launch_mit_vector", "current_mit_vector")
MARK = "VCEK extensions malformed:"


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$bigint"}:
            return BigU64(int(v["$bigint"]))
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _big(n):
    return {"$bigint": str(int(n))}


def _parse(b):
    r = A.parse_sev_snp_report(b)
    out = {k: v for k, v in r.items() if k not in ("sig_r", "sig_s", "signed", "raw")}
    for k in U64:
        out[k] = _big(out[k])
    out.update(signed_len=len(r["signed"]), signed_sha256=hashlib.sha256(r["signed"]).hexdigest(), raw_len=len(r["raw"]))
    return out


def _verify_sig(b, k):
    return A.verify_sev_snp_report_signature(A.parse_sev_snp_report(b), A.ec_key_from_point("P-384", k))


def _fetch_vcek(chip, tcb, op):
    seen = []
    o = {k: v for k, v in op.items() if k not in ("status", "body", "noFetch")}
    if not op.get("noFetch"):
        def fetch(url):
            seen.append(url)
            return {"ok": 200 <= op["status"] < 300, "status": op["status"], "body": op["body"]}
        o["fetch"] = fetch
    r = A.fetch_vcek_from_kds(chip, tcb, o)
    return {"url": seen[0], "bytes": r}


def _vcek_key(c):
    r = A.extract_vcek_public_key(c)
    return {"point": r["point"], "tbs": r["tbs"]}


HANDLERS = {
    "toHex": A.to_hex, "splitPemCertificates": A.split_pem_certificates, "parseReport": _parse, "ecdsaP384PublicKey": A.ecdsa_p384_public_key,
    "signatureToCompact": A.sev_snp_signature_to_compact, "verifyReportSignature": _verify_sig,
    "checkPolicy": lambda b, p: A.check_sev_snp_policy(A.parse_sev_snp_report(b), p),
    "deriveIdentity": lambda b, w: A.make_default_derive_identity(w)(A.parse_sev_snp_report(b)),
    "fetchVcek": _fetch_vcek, "extractTbsCertificate": A.extract_tbs_certificate, "extractVcekPublicKey": _vcek_key,
    "checkVcekReportBinding": lambda t, r: A.check_vcek_report_binding(t, A.parse_sev_snp_report(r)),
    "constants": lambda: {"SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384": A.SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384, "SEV_SNP_POLICY_DEBUG_BIT": _big(A.SEV_SNP_POLICY_DEBUG_BIT),
                          "AMD_MILAN_ARK_SPKI_SHA384": A.AMD_MILAN_ARK_SPKI_SHA384},
}
TOTALS = {"toHex": 4, "splitPemCertificates": 15, "parseReport": 17, "ecdsaP384PublicKey": 11, "signatureToCompact": 10, "verifyReportSignature": 13,
          "checkPolicy": 57, "deriveIdentity": 8, "fetchVcek": 14, "extractTbsCertificate": 16, "extractVcekPublicKey": 7, "checkVcekReportBinding": 75,
          "constants": 1}


def _same(got, out, _case):
    if isinstance(out, str) and out.startswith(MARK):
        return isinstance(got, str) and got.startswith(MARK)
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 248 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 39


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_sevsnp_helpers_replay(fn):
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same) == (TOTALS[fn], 0)
