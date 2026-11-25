"""The public vendor-attestation facades under their reference names: the Intel TDX / DCAP quote and report parsers, the PCK chain, the genuine-quote and
collateral verifiers, CRL and signed-JSON checks, the Azure runtime-data binding, the MAA and Confidential Space token parsers, the x5c chain checks, the
hardware-model mapper, the JWKS fetchers over an injected transport, and the suite / pin constants. Each is a thin, total-where-the-reference-is-total layer over
the vendor modules (:mod:`attest_intel`, :mod:`attest_azure`, :mod:`attest_gcp`, :mod:`attest_amd`); results use the reference's member names."""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import unquote

from . import attest_azure as _az
from . import attest_gcp as _gcp
from . import attest_intel as _in
from .attest_amd import AMD_ARK_SPKI_SHA384, AMD_SNP_SUITE, check_azure_runtime_data_binding
from .attest_common import ec_key_from_point, ec_point, load_public_key, parse_jws, pem_to_der, to_hex

__all__ = ["constants", "to_hex", "pem_to_der", "ecdsa_p256_public_key", "parse_dcap_td_report", "parse_dcap_quote", "extract_pck_fmspc_and_tcb",
           "verify_intel_pck_chain_x509", "verify_genuine_tdx_quote", "verify_crl", "serial_is_revoked", "verify_signed_json", "decode_issuer_chain_header",
           "verify_intel_tdx_collateral", "check_azure_runtime_data_binding", "parse_maa_jwt", "parse_gcp_cs_jwt", "verify_x5c_chain", "verify_jwk_x5c_chain",
           "tee_type_of_hw_model", "fetch_maa_jwks", "fetch_gcp_confidential_space_jwks"]

parse_dcap_td_report = _in.parse_dcap_td_report
parse_dcap_quote = _in.parse_dcap_quote
extract_pck_fmspc_and_tcb = _in.extract_pck_fmspc_and_tcb
verify_jwk_x5c_chain_impl = _gcp.verify_jwk_x5c_chain


def constants() -> Dict[str, Any]:
    return {"INTEL_DCAP_SUITE": _in.INTEL_DCAP_SUITE, "AZURE_MAA_SUITE": _az.AZURE_MAA_SUITE, "AZURE_MAA_SUITES": ["ES256", "RS256"],
            "GCP_CS_SUITE": _gcp.GCP_CS_SUITE, "GCP_CS_SUITES": ["RS256", "ES256"], "GCP_CS_DEFAULT_ISSUER": _gcp.GCP_CS_DEFAULT_ISSUER,
            "INTEL_SGX_ROOT_CA_SPKI_SHA256": _in.INTEL_SGX_ROOT_CA_SPKI_SHA256, "AMD_SNP_SUITE": AMD_SNP_SUITE, "AMD_ARK_SPKI_SHA384": dict(AMD_ARK_SPKI_SHA384),
            "DEFAULT_ACCEPTED_STATUSES": list(_in.DEFAULT_ACCEPTED_STATUSES)}


def ecdsa_p256_public_key(sec1: bytes) -> Dict[str, bytes]:
    """The uncompressed SEC1 point of a P-256 public key (a compressed point is expanded); raises off the curve."""
    return {"point": ec_point(ec_key_from_point("P-256", bytes(sec1)), "P-256")}


def verify_intel_pck_chain_x509(opts: Dict[str, Any]) -> Dict[str, Any]:
    """The embedded PCK chain to the pinned Intel SGX Root CA: ``{ok, reason?, leafKey?: {point}, leafDer?, depth?, failure?}``."""
    r = _in.verify_intel_pck_chain(opts.get("pckChainPem"), opts.get("trustAnchorRootCaSpkiSha256"), opts.get("nowMs"))
    out = {k: v for k, v in r.items() if k not in ("leafKey", "leafCert")}
    if "leafKey" in r:
        out["leafKey"] = {"point": ec_point(r["leafKey"], "P-256")}
    return out


def verify_genuine_tdx_quote(opts: Dict[str, Any]) -> Dict[str, Any]:
    return _in.verify_genuine_tdx_quote(opts.get("quote"), opts.get("trustAnchorRootCaSpkiSha256"), opts.get("expected"), opts.get("policy"), opts.get("nowMs"))


def verify_crl(crl_der: bytes, issuer: Dict[str, Any], now_ms: Any) -> Dict[str, Any]:
    return _in.verify_crl(crl_der, load_public_key(bytes(issuer["spkiDer"])), now_ms)


def serial_is_revoked(revoked: List[str], serial_hex: str) -> bool:
    return _in.serial_is_revoked(set(revoked), serial_hex)


def verify_signed_json(text: str, name: str, issuer: Dict[str, Any]) -> Dict[str, Any]:
    return _in._verify_signed_json(text, name, load_public_key(bytes(issuer["spkiDer"])))


def decode_issuer_chain_header(value: str) -> str:
    """``decodeURIComponent``: a malformed %-escape or a sequence that is not UTF-8 is ``URI malformed``."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("URI malformed")
    try:
        return unquote(value, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("URI malformed") from None


def verify_intel_tdx_collateral(opts: Dict[str, Any]) -> Dict[str, Any]:
    return _in.verify_intel_tdx_collateral(opts.get("quote"), opts.get("collateral"), opts.get("nowMs"), opts.get("policy"),
                                           opts.get("trustAnchorRootCaSpkiSha256"), opts.get("allowDebug") is True)


def parse_maa_jwt(token: Any) -> Dict[str, Any]:
    return parse_jws(token, "parseMaaJwt")


def parse_gcp_cs_jwt(token: Any) -> Dict[str, Any]:
    return parse_jws(token, "parseGcpCsJwt")


def verify_x5c_chain(x5c: Any, anchors: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """An MAA ``x5c`` chain to a configured anchor: ``{ok, reason?, leafDer?, leafSpkiSha256?}`` (the leaf certificate is reported as its DER)."""
    r = _az.verify_x5c_chain(x5c, anchors, opts.get("nowMs"), opts.get("clockSkewMs") if opts.get("clockSkewMs") is not None else 0)
    out = {k: v for k, v in r.items() if k != "leaf"}
    if "leaf" in r:
        out["leafDer"] = r["leaf"].raw
    return out


def verify_jwk_x5c_chain(x5c: Any, anchors: Any, opts: Dict[str, Any]) -> Optional[str]:
    return _gcp.verify_jwk_x5c_chain(x5c, anchors, opts.get("nowMs"), opts.get("skewMs"))


def tee_type_of_hw_model(hwmodel: str) -> Optional[str]:
    return _gcp.tee_type_of_hwmodel(hwmodel)


def _s(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _sa(v: Any) -> Optional[List[str]]:
    return list(v) if isinstance(v, list) and all(isinstance(x, str) for x in v) else None


def _keys(body: Any, members: tuple, what: str) -> Dict[str, List[dict]]:
    keys = body.get("keys") if isinstance(body, dict) else None
    if not isinstance(keys, list):
        raise ValueError("%s: response has no keys array" % what)
    out = []
    for k in keys:
        if not isinstance(k, dict):
            continue
        e: Dict[str, Any] = {}
        for m in members:
            v = _sa(k.get(m)) if m == "x5c" else _s(k.get(m))
            if v is not None:
                e[m] = v
        out.append(e)
    return {"keys": out}


def fetch_maa_jwks(issuer: str, fetch: Callable[[str], Any], opts: Optional[Dict[str, Any]] = None) -> Dict[str, List[dict]]:
    """The MAA signing keys from ``<issuer><certsPath>`` over ``fetch(url)`` (an object with ``ok``, ``status`` and ``json()``); kid, kty, alg and x5c only."""
    opts = opts or {}
    url = re.sub(r"/+$", "", issuer) + (opts.get("certsPath") or "/certs")
    res = fetch(url)
    if not res.ok:
        raise ValueError("MAA JWKS fetch failed: HTTP %s for %s" % (res.status, url))
    return _keys(res.json(), ("kid", "kty", "alg", "x5c"), "MAA JWKS fetch")


def fetch_gcp_confidential_space_jwks(issuer: str, fetch: Callable[[str], Any], opts: Optional[Dict[str, Any]] = None) -> Dict[str, List[dict]]:
    """The Confidential Space signing keys: from ``opts["jwksUri"]``, else the ``jwks_uri`` of the issuer's OpenID configuration."""
    opts = opts or {}
    uri = opts.get("jwksUri")
    if not uri:
        conf_url = re.sub(r"/+$", "", issuer) + "/.well-known/openid-configuration"
        cres = fetch(conf_url)
        if not cres.ok:
            raise ValueError("Confidential Space OpenID config fetch failed: HTTP %s for %s" % (cres.status, conf_url))
        conf = cres.json()
        uri = _s(conf.get("jwks_uri")) if isinstance(conf, dict) else None
        if not uri:
            raise ValueError("Confidential Space OpenID config carries no jwks_uri")
    res = fetch(uri)
    if not res.ok:
        raise ValueError("Confidential Space JWKS fetch failed: HTTP %s for %s" % (res.status, uri))
    return _keys(res.json(), ("kid", "kty", "alg", "use", "n", "e", "crv", "x", "y", "x5c"), "Confidential Space JWKS fetch")
