"""Replays the TS-reference oracle of the safety certificate (testdata/ref-safety-certificate.json.gz, 262 cases): check-row validation,
the bound and its statement, the signed message, issuing (Ed25519, ML-DSA-65, hybrid), verification, the wire codec and the compliance row.
Every fn has a handler and the total is asserted. {"$bytes": {"$seed": label}} is sha256("atlas-pca-conformance/" + label) (the Ed25519
secret, or a suite's ML-DSA-65 key-generation seed); null in an optional position is "not given"; reason strings are compared exactly.

REFUSED_UNBOUND: the native verifiers are fail-closed and have no allowUnboundPq (the reference's legacy insecure opt-out is not ported
to any native); the two cases the reference accepts only through that option are asserted to be REFUSED here. Check rows with a URL need ada-url (a core dependency); ML-DSA needs OpenSSL >= 3.5 or
dilithium-py: without one, the cases that use it are reported as a skip after every other case was checked."""
import json
import math
import os

import pytest

from atlas_pca import pq_backends
from atlas_pca import safety_certificate as S
from atlas_pca.agent import KeyPair, generate_pq_keypair
from base_oracle import HERE, b64d, canon, load

COUNT, CASES = load("safety-certificate", os.path.join(HERE, "testdata", "ref-safety-certificate.json.gz"))
_REFUSED = {"ok": False, "reason": "guardian signature does not verify", "recomputedBound": 2}
REFUSED_UNBOUND = {c["name"]: _REFUSED for cs in CASES.values() for c in cs
                   if c["fn"] == "verifySafetyCertificate" and len(c["args"]) > 1 and (c["args"][1] or {}).get("allowUnboundPq") is True}
_VERIFY = {"guardian": "guardian", "requireChecks": "require_checks", "maxAgeMs": "max_age_ms", "now": "now", "pqPins": "pq_pins"}


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        if set(v) == {"$bytes"}:
            return b64d(v["$bytes"])  # the loader turned a seed label into base64url
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _options(opts):
    return {_VERIFY[k]: v for k, v in (opts or {}).items() if k != "allowUnboundPq"}  # not offered: see REFUSED_UNBOUND


def _issue(a):
    suite = a.get("suite") or {}
    pq = generate_pq_keypair("ML-DSA-65", suite["pqSeed"]) if "pqSeed" in suite else None
    kw = {py: a[js] for js, py in (("grantRef", "grant_ref"), ("instance", "instance"), ("checks", "checks"), ("issuedAt", "issued_at")) if a.get(js) is not None}
    return S.issue_safety_certificate(a.get("policy"), KeyPair(a["guardianSecret"], allow_insecure_signer=True), alg=suite.get("alg"), pq=pq, **kw)


HANDLERS = {
    "constants": lambda: {n: getattr(S, n) for n in ("MAX_SAFETY_CHECKS", "SAFETY_CERT_DOMAIN", "SAFETY_CERT_SCOPE", "SAFETY_CERT_VERSION")},
    "validateSafetyChecks": S.validate_safety_checks,
    "safetyCertificateBound": S.safety_certificate_bound,
    "safetyCertificateStatement": S.safety_certificate_statement,
    "safetyCertificateMessage": S.safety_certificate_message,
    "issueSafetyCertificate": _issue,
    "verifySafetyCertificate": lambda cert, opts=None: S.verify_safety_certificate(cert, **_options(opts)),
    "encodeSafetyCertificate": S.encode_safety_certificate,
    "decodeSafetyCertificate": S.decode_safety_certificate,
    "safetyCertificateForCompliance": lambda cert, opts=None: S.safety_certificate_for_compliance(cert, **_options(opts)),
}


def _needs(case):
    """What a case needs that this runtime may lack: "ada-url" for a URL evidence link, "ML-DSA-65" for a post-quantum suite."""
    text, out = json.dumps(case["args"]), set()
    if '"kind": "url"' in text:
        try:
            import ada_url  # noqa: F401
        except ImportError:
            out.add("ada-url")
    if "ml-dsa-65" in text and not pq_backends.available("ML-DSA-65"):
        out.add("ML-DSA-65")
    return out


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 262 and set(CASES) == set(HANDLERS) and len(REFUSED_UNBOUND) == 2


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_safety_certificate_replay(fn):
    bad, lacking = [], set()
    for c in CASES[fn]:
        if _needs(c):
            lacking |= _needs(c)
            continue
        out = REFUSED_UNBOUND.get(c["name"], c["out"])
        threw = isinstance(out, dict) and "$throws" in out
        try:
            got = HANDLERS[fn](*_dec(c["args"]))
        except Exception as e:  # noqa: BLE001 - a native refusal, compared against the reference
            if not threw:
                bad.append("%s\n    native raised %s: %s\n    ref:    %s" % (c["name"], type(e).__name__, e, canon(out)[:300]))
            continue
        if threw or canon(got) != canon(out):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:400], canon(out)[:400]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))
    if lacking:
        pytest.skip("without %s some cases of %s were not replayed" % (", ".join(sorted(lacking)), fn))
