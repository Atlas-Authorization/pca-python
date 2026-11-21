"""Replays the TS-reference oracle of the NVIDIA GPU confidential-computing attestation surface (testdata/ref-attest-nvidia.json.gz, 467 cases, and
ref-attest-nvidia-rim.json.gz, 163 cases): the SPDM transcript parse, the device chain and the report signature, the PCA challenge, RIM ids,
the golden comparison, CRL revocation, the guarded RIM / CRL / OCSP fetch helpers over a scripted transport (the requests are compared), the OCSP
request bytes, OCSP response and chain checks, the ASN.1 time check, the RIM XMLDSig verification and the collateral hook. Every fn has a handler and the
totals are asserted; a reference refusal needs a native exception. A reason that is a library's own text (``error:``, ``OCSP response rejected:``, an XML
parser message after ``(fail closed): ``) is compared by its fixed prefix. Two ocspRequest cases are pinned deviations, asserted refused: ``hash-md5``
(the reference writes a CertID with an empty hash OID for a hash it has no OID for) and ``nonce-len-0`` (the generator passed a non-bytes object there; a
real empty nonce is refused by the reference as well)."""
import base64
import datetime
import hashlib
import json
import os
import re

import pytest

pytest.importorskip("cryptography")  # the dependency-free job has no cryptography; every other job replays this corpus

from atlas_pca import attest_nvidia as N
from atlas_pca import attest_ocsp as O
from atlas_pca.attest_cert import Cert
from atlas_pca.attest_der import der_validity_ms
from atlas_pca.attest_xml import XmlError  # noqa: F401 - imported so a missing XML reader fails at collection
from base_oracle import HERE, canon, dec, load, run

COUNT, CASES = load("attest-nvidia", os.path.join(HERE, "testdata", "ref-attest-nvidia.json.gz"))
RIM_COUNT, RIM_CASES = load("attest-nvidia-rim", os.path.join(HERE, "testdata", "ref-attest-nvidia-rim.json.gz"))
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
PINNED_REFUSED = {"hash-md5", "nonce-len-0"}


def _openssl_time(ms):
    if ms is None:
        return "Bad time value"
    d = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=ms // 1000)  # fromtimestamp fails past 3000 on Windows
    return "%s %2d %02d:%02d:%02d %d GMT" % (MONTHS[d.month - 1], d.day, d.hour, d.minute, d.second, d.year)


def _serial(c):
    n = int.from_bytes(c.serial, "big", signed=True)
    h = "%X" % abs(n)
    return ("-" if n < 0 else "") + ("0" + h if len(h) % 2 else h)


def _cert(c):
    lo, hi = der_validity_ms(c.raw)
    return {"subject": c.subject, "issuer": c.issuer, "serial": _serial(c), "notBefore": _openssl_time(lo), "notAfter": _openssl_time(hi),
            "spkiSha256": N.spki_sha256_hex(c), "rawSha256": hashlib.sha256(c.raw).hexdigest(), "ca": c.ca}


def _report_summary(p):
    return {"request": p["request"], "response": p["response"], "signedBytesLength": len(p["signedBytes"]),
            "signedBytesSha256": hashlib.sha256(p["signedBytes"]).hexdigest()}


def _rim_summary(r):
    return {"tagId": r["tagId"], "product": r["product"], "version": r["version"], "golden": [r["golden"][k] for k in sorted(r["golden"])],
            "signerSubject": r["signerSubject"]}


def _rim_from(j):
    return dict(j, golden={g["index"]: g for g in j["golden"]})


def _response(r):
    if "$throws" in r:
        raise RuntimeError(r["$throws"])
    if "bodyBytes" in r:
        body = r["bodyBytes"]
    else:
        body = json.dumps(r.get("body"), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {"status": r.get("status", 200), "body": body}


def _fetch_helper(call):
    """Runs call(fetch) over a one-response scripted transport; the requests it made are appended to the result."""
    def go(response):
        log = []

        def fetch(url, init=None):
            init = init or {}
            entry = {"url": url, "method": init.get("method", "GET"), "contentType": (init.get("headers") or {}).get("content-type")}
            if init.get("body") is not None:
                entry["bodyBytes"] = len(init["body"])
            log.append(entry)
            return _response(response)
        try:
            out = dict(call(fetch), ok=True)
        except Exception as e:  # noqa: BLE001 - the refusal text is part of the corpus
            out = {"ok": False, "error": str(e)}
        out["requests"] = log
        return out
    return go


def _fetch_rim(a):
    opts = {"baseUrl": a["baseUrl"]} if "baseUrl" in a else {}
    return _fetch_helper(lambda f: {"value": N.fetch_nvidia_rim(a["id"], dict(opts, fetch=f))})(a["response"])


def _fetch_crl(a):
    return _fetch_helper(lambda f: {"value": N.fetch_nvidia_crl(a["url"], {"fetch": f})})(a["response"])


def _fetch_ocsp(a):
    cert, issuer = Cert.from_pem(a["certPem"]), Cert.from_pem(a["issuerPem"])
    return _fetch_helper(lambda f: dict(O.fetch_nvidia_ocsp(cert, issuer, dict(a.get("opts") or {}, fetch=f))))(a["response"])


def _ocsp_request(cert_pem, issuer_pem, opts):
    return O.build_nvidia_ocsp_request(Cert.from_pem(cert_pem), Cert.from_pem(issuer_pem), opts.get("nonce"), opts.get("hash", "sha384"))


def _ocsp_verify(der, a):
    chain = N.parse_pem_chain(a["chainPem"])
    return O.verify_ocsp_response(der, chain[a["certIndex"]], chain[a["issuerIndex"] if a.get("issuerIndex") is not None else a["certIndex"] + 1], chain, a["nowMs"], a.get("maxAgeMs"), a.get("clockSkewMs") or 0,
                                  a.get("expectedNonce"))


def _ocsp_chain(chain_pem, responses, now_ms, opts):
    return O.check_nvidia_chain_ocsp(N.parse_pem_chain(chain_pem), responses, now_ms, opts.get("maxAgeMs"), opts.get("requireGood"),
                                     opts.get("clockSkewMs"), opts.get("expectedNonces"))


def _verify_chain(pem, pins, now_ms):
    r = N.verify_nvidia_device_chain(pem, pins, now_ms)
    return dict(r, leaf=_cert(r["leaf"]), chain=[_cert(c) for c in r["chain"]]) if r["ok"] else r


def _verify_rim(xml, o):
    r = N.verify_nvidia_rim(xml, o["rimRootSpkiSha256"], o["nowMs"])
    return {"ok": True, "rim": _rim_summary(r["rim"])} if r["ok"] else r


def _hook(sc):
    b = sc["bundle"]
    hook = N.NvidiaCollateralHook(dict(sc["opts"], resolve=lambda *_: b))
    chain = N.parse_pem_chain(sc["chainPem"])
    return {"value": hook({"report": N.parse_nvidia_spdm_evidence(sc["evidence"]), "chain": chain, "leaf": chain[0], "nowMs": sc["nowMs"]})}


def _spdm_signature(ev, chain_pem):
    return N.verify_nvidia_spdm_signature(N.parse_nvidia_spdm_evidence(ev), N.parse_pem_chain(chain_pem)[0].public_key)


HANDLERS = {
    "constants": lambda: {"NVIDIA_SPDM_SUITE": N.NVIDIA_SPDM_SUITE, "NVIDIA_OPAQUE": N.NVIDIA_OPAQUE, "NVIDIA_RIM_BASE_URL": N.NVIDIA_RIM_BASE_URL,
                          "NVIDIA_GH100_CRL_URLS": list(N.NVIDIA_GH100_CRL_URLS), "NVIDIA_GB100_CRL_URLS": list(N.NVIDIA_GB100_CRL_URLS),
                          "NVIDIA_OCSP_URL": O.NVIDIA_OCSP_URL, "NVIDIA_OCSP_DEFAULT_MAX_AGE_MS": O.NVIDIA_OCSP_DEFAULT_MAX_AGE_MS},
    "parseReport": lambda b: _report_summary(N.parse_nvidia_spdm_evidence(b)),
    "formatVbiosVersion": N.format_vbios_version,
    "spkiSha256Hex": lambda pem: N.spki_sha256_hex(Cert.from_pem(pem)),
    "parsePemChain": lambda pem: [_cert(c) for c in N.parse_pem_chain(pem)],
    "verifyDeviceChain": _verify_chain,
    "verifySpdmSignature": _spdm_signature,
    "spdmChallenge": N.nvidia_spdm_challenge,
    "rimIds": lambda b: N.nvidia_rim_ids_for_report(N.parse_nvidia_spdm_evidence(b)),
    "compareReport": lambda b, d, v: N.compare_report_to_rims(N.parse_nvidia_spdm_evidence(b), _rim_from(d), _rim_from(v)),
    "checkRevocation": lambda pem, crls, now, issuers, req: N.check_nvidia_chain_revocation(N.parse_pem_chain(pem), crls, now, issuers, req),
    "fetchRim": _fetch_rim,
    "fetchCrl": _fetch_crl,
    "ocspRequest": _ocsp_request,
    "ocspUrls": lambda pem: O.cert_ocsp_urls(Cert.from_pem(pem)),
    "ocspVerify": _ocsp_verify,
    "ocspChain": _ocsp_chain,
    "fetchOcsp": _fetch_ocsp,
    "asn1TimesWellFormed": O.all_asn1_times_well_formed,
}
RIM_HANDLERS = {"verifyRim": _verify_rim, "collateralHook": _hook}
TOTALS = {"constants": 1, "parseReport": 66, "formatVbiosVersion": 9, "spkiSha256Hex": 3, "parsePemChain": 12, "verifyDeviceChain": 63,
          "verifySpdmSignature": 15, "spdmChallenge": 10, "rimIds": 26, "compareReport": 26, "checkRevocation": 39, "fetchRim": 12, "fetchCrl": 4,
          "ocspRequest": 20, "ocspUrls": 8, "ocspVerify": 81, "ocspChain": 30, "fetchOcsp": 5, "asn1TimesWellFormed": 37}
RIM_TOTALS = {"verifyRim": 108, "collateralHook": 55}


def _eq(g, o):
    if isinstance(o, str):
        if o.startswith("OCSP response rejected:"):
            return isinstance(g, str) and g.startswith("OCSP response rejected:")
        m = re.search(r"error:[0-9A-F]{8}:", o)
        if m:
            return isinstance(g, str) and g.startswith(o[:m.start()]) and len(g) > m.start()
    if isinstance(o, dict):
        return isinstance(g, dict) and set(g) == set(o) and all(_eq(g[k], o[k]) for k in o)
    if isinstance(o, list):
        return isinstance(g, list) and len(g) == len(o) and all(_eq(x, y) for x, y in zip(g, o))
    return canon(g) == canon(o)


def _same(got, out, _case):
    return _eq(json.loads(canon(got)), out)


def _replay(cases, fn, handlers):
    cs = cases[fn]
    if fn != "ocspRequest":
        return run(cs, handlers[fn], compare=_same)
    # the two pinned deviations are asserted refused, the rest replayed
    pinned = [c for c in cs if c["name"].split("/")[-1] in PINNED_REFUSED]
    assert len(pinned) == len(PINNED_REFUSED)
    for c in pinned:
        with pytest.raises(Exception):
            handlers[fn](*dec(c["args"]))
    ran, skipped = run(cs, handlers[fn], compare=_same, skip=lambda c: "pinned" if c["name"].split("/")[-1] in PINNED_REFUSED else None)
    return ran + len(pinned), skipped - len(pinned)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 467 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert RIM_COUNT == 163 and set(RIM_CASES) == set(RIM_HANDLERS)
    assert {fn: len(cs) for fn, cs in RIM_CASES.items()} == RIM_TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_nvidia_replay(fn):
    assert _replay(CASES, fn, HANDLERS) == (TOTALS[fn], 0)


@pytest.mark.parametrize("fn", sorted(RIM_HANDLERS))
def test_nvidia_rim_replay(fn):
    assert _replay(RIM_CASES, fn, RIM_HANDLERS) == (RIM_TOTALS[fn], 0)
