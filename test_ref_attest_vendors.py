"""Replays the TS-reference oracle of the vendor attestation facades (testdata/ref-attest-vendors.json.gz, 758 cases, 22 functions) through the reference-named
functions of :mod:`atlas_pca.attest_vendors`: constants, the DCAP quote / TD report parsers, the PCK extension reader and chain, the genuine-quote and collateral
verifiers, CRL / signed JSON, the Azure binding, the MAA / Confidential Space token parsers, the x5c chain checks, the hardware-model mapper and both JWKS
fetchers over a scripted transport (every requested URL is compared). Every function has a handler and the totals are asserted. A reason or throw text that
comes from a library (OpenSSL ``error:`` text, JSON.parse messages, the P-256 library's point errors, ``URI malformed``) is compared by presence; a case whose
certificate bytes are not DER at all only requires a refusal."""
import json
import os
import re

import pytest

pytest.importorskip("cryptography")  # the dependency-free job has no cryptography; every other job replays this corpus

from atlas_pca import attest_vendors as V
from base_oracle import HERE, canon, load, norm, run

COUNT, CASES = load("attest-vendors", os.path.join(HERE, "testdata", "ref-attest-vendors.json.gz"))
LIB = re.compile(r"error:[0-9A-Fa-f]{8}:|Unexpected token|Unexpected end of JSON input|bad point:|invalid Point, expected length|URI malformed|is not valid JSON|Expecting|Extra data")
NOT_DER = ("malformed-certificate", "pem-malformed-block", "garbage")


class _Resp:
    def __init__(self, r):
        self._r = r
        self.status = r.get("status", 200)
        self.ok = 200 <= self.status < 300

    def json(self):
        b = self._r.get("body")
        if isinstance(b, dict) and "$text" in b:
            return json.loads(b["$text"])
        return b


def _fetch(impl):
    def go(a):
        script, log, i = a["script"], [], [0]

        def transport(url):
            log.append(str(url))
            r = script[min(i[0], len(script) - 1)]
            i[0] += 1
            if "$throws" in r:
                raise RuntimeError(r["$throws"])
            return _Resp(r)
        try:
            out = {"ok": True, "jwks": impl(a["issuer"], transport, a.get("opts") or {})}
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "error": str(e)}
        out["requests"] = log
        return out
    return go


HANDLERS = {
    "constants": V.constants,
    "toHex": V.to_hex,
    "pemToDer": V.pem_to_der,
    "ecdsaP256PublicKey": V.ecdsa_p256_public_key,
    "parseDcapTdReport": V.parse_dcap_td_report,
    "parseDcapQuote": V.parse_dcap_quote,
    "extractPckFmspcAndTcb": V.extract_pck_fmspc_and_tcb,
    "verifyIntelPckChainX509": V.verify_intel_pck_chain_x509,
    "verifyGenuineTdxQuote": V.verify_genuine_tdx_quote,
    "verifyCrl": V.verify_crl,
    "serialIsRevoked": V.serial_is_revoked,
    "verifySignedJson": V.verify_signed_json,
    "decodeIssuerChainHeader": V.decode_issuer_chain_header,
    "verifyIntelTdxCollateral": V.verify_intel_tdx_collateral,
    "checkAzureRuntimeDataBinding": V.check_azure_runtime_data_binding,
    "parseMaaJwt": V.parse_maa_jwt,
    "parseGcpCsJwt": V.parse_gcp_cs_jwt,
    "verifyX5cChain": V.verify_x5c_chain,
    "verifyJwkX5cChain": V.verify_jwk_x5c_chain,
    "teeTypeOfHwModel": V.tee_type_of_hw_model,
    "fetchMaaJwks": _fetch(V.fetch_maa_jwks),
    "fetchGcpConfidentialSpaceJwks": _fetch(V.fetch_gcp_confidential_space_jwks),
}
TOTALS = {"constants": 1, "toHex": 8, "pemToDer": 10, "ecdsaP256PublicKey": 12, "parseDcapTdReport": 11, "parseDcapQuote": 45, "extractPckFmspcAndTcb": 25,
          "verifyIntelPckChainX509": 46, "verifyGenuineTdxQuote": 64, "verifyCrl": 34, "serialIsRevoked": 10, "verifySignedJson": 31, "decodeIssuerChainHeader": 13,
          "verifyIntelTdxCollateral": 159, "checkAzureRuntimeDataBinding": 24, "parseMaaJwt": 57, "parseGcpCsJwt": 57, "verifyX5cChain": 61,
          "verifyJwkX5cChain": 27, "teeTypeOfHwModel": 15, "fetchMaaJwks": 22, "fetchGcpConfidentialSpaceJwks": 26}


def _eq(g, o):
    if isinstance(o, dict):
        if not isinstance(g, dict):
            return False
        return set(g) == set(o) and all(_eq(g[k], o[k]) for k in o)
    if isinstance(o, list):
        return isinstance(g, (list, tuple)) and len(g) == len(o) and all(_eq(x, y) for x, y in zip(g, o))
    if isinstance(o, str) and LIB.search(o):
        return isinstance(g, str) and len(g) > 0
    return canon(g) == canon(o)


def _same(got, out, case):
    got = norm(got)
    if any(m in case["name"] for m in NOT_DER) and isinstance(out, dict) and out.get("ok") is False:
        return isinstance(got, dict) and got.get("ok") is False
    if isinstance(out, dict) and isinstance(got, dict) and isinstance(out.get("reason"), str) and LIB.search(out["reason"]):
        return _eq({k: v for k, v in got.items() if k != "reason"}, {k: v for k, v in out.items() if k != "reason"}) and isinstance(got.get("reason"), str)
    return _eq(got, out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 758 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_attest_vendors_replay(fn):
    assert run(CASES[fn], HANDLERS[fn], compare=_same) == (TOTALS[fn], 0)
