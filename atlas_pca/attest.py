"""Vendor hardware-attestation verifiers for agent passports and PCActns, native counterpart of the vendor verifiers of
@atlasauth/pca (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, GCP Confidential Space, NVIDIA GPU SPDM).

    from atlas_pca.attest import verifier_from_config
    v = verifier_from_config("amd-sev-snp", {"family": "genoa", "binding": "report-data", "policy": {"measurements": [...]}})
    verify_passport(signed, issuers, now_ms, revoked=..., default_verifier=v)

`verifier_from_config(vendor, config)` builds a verifier from a JSON-serialisable configuration (the same schema the
language-neutral conformance vectors use). The verifier's `verify(document, expected, now_ms)` answers
`{"ok", "bound", "reason", "measured", "hostAsserted"}` and fails CLOSED: a missing pin, an empty measurement allowlist, an
unverifiable chain or an unbound quote is `ok: False` with a reason, never a pass. Evidence is resolved by
`resolve_evidence(document)` (default: `document["evidence"]`) and is the wire object of the vendor: bytes as standard base64
strings (raw `bytes` are accepted too), PEM and JSON documents as strings.

Needs the `cryptography` package (extra `attest`); everything else is the standard library.
"""
from typing import Any, Callable, Dict, Optional

from .attest_amd import AMD_ARK_SPKI_SHA384, AmdSnpVerifier, AttestConstructError
from .attest_azure import AzureMaaVerifier
from .attest_common import attestation_binding, js_str, node_b64decode
from .attest_der import (
    DerError,
    check_chain_roles,
    der_validity_ms,
    parse_cert_extensions,
    parse_der_time,
    parse_tbs_extensions,
    read_cert_role_info,
    tbs_of_certificate,
    unrecognised_critical_extension,
)
from .attest_gcp import GCP_CS_DEFAULT_ISSUER, GcpConfidentialSpaceVerifier
from .attest_intel import INTEL_SGX_ROOT_CA_SPKI_SHA256, IntelDcapVerifier
from .attest_nvidia import NvidiaCollateralHook, NvidiaSpdmVerifier

VENDORS = ("amd-sev-snp", "intel-tdx-dcap", "azure-maa", "gcp-confidential-space", "nvidia-gpu-spdm")

__all__ = [
    "VENDORS",
    "AttestConstructError",
    "AttestationVerifier",
    "attestation_binding",
    "verifier_from_config",
    "evidence_for",
    "run_attestation_vector",
    "run_x509_vector",
    "AMD_ARK_SPKI_SHA384",
    "INTEL_SGX_ROOT_CA_SPKI_SHA256",
    "GCP_CS_DEFAULT_ISSUER",
]


class AttestationVerifier:
    """What every vendor verifier answers to: `verify(document, expected, now_ms)` -> result dict."""

    def verify(self, document: Any, expected: Any, now_ms: Any) -> Dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError


_MISSING = object()


def _unb64(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        return node_b64decode(v)
    raise TypeError(
        "The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received %s"
        % ("null" if v is None else "undefined" if v is _MISSING else "type %s" % type(v).__name__)
    )


def _opt_bytes(v: Any) -> Optional[bytes]:
    if isinstance(v, str):
        return node_b64decode(v)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return None


def evidence_for(vendor: str, ev: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The wire evidence of `vendor` as the verifier consumes it (base64 strings decoded to bytes); None when there is none."""
    if ev is None:
        return None
    out: Dict[str, Any] = {}
    if vendor == "amd-sev-snp":
        if "report" in ev:
            out["report"] = _unb64(ev["report"])
        if "vcekDer" in ev:
            out["vcekDer"] = _unb64(ev["vcekDer"])
        if "askArkPem" in ev:
            out["askArkPem"] = ev["askArkPem"]
        rd = _opt_bytes(ev.get("runtimeData"))
        if rd is not None:
            out["runtimeData"] = rd
    elif vendor == "intel-tdx-dcap":
        if "quote" in ev:
            out["quote"] = _unb64(ev["quote"])
        rd = _opt_bytes(ev.get("runtimeData"))
        if rd is not None:
            out["runtimeData"] = rd
        c = ev.get("collateral")
        if isinstance(c, dict):
            out["collateral"] = {
                "tcbInfoJson": c.get("tcbInfoJson"),
                "tcbInfoIssuerChainPem": c.get("tcbInfoIssuerChainPem"),
                "qeIdentityJson": c.get("qeIdentityJson"),
                "qeIdentityIssuerChainPem": c.get("qeIdentityIssuerChainPem"),
                "pckCrlDer": _unb64(c.get("pckCrlDer", _MISSING)),
                "rootCrlDer": _unb64(c.get("rootCrlDer", _MISSING)),
            }
    elif vendor in ("azure-maa", "gcp-confidential-space"):
        if "token" in ev:
            out["token"] = ev["token"]
        if "jwks" in ev:
            out["jwks"] = ev["jwks"]
    elif vendor == "nvidia-gpu-spdm":
        if "evidence" in ev:
            out["evidence"] = _unb64(ev["evidence"])
        if "certChainPem" in ev:
            out["certChainPem"] = ev["certChainPem"]
        c = ev.get("collateral")
        if isinstance(c, dict):
            bundle: Dict[str, Any] = {"driverRimXml": c.get("driverRimXml"), "vbiosRimXml": c.get("vbiosRimXml")}
            if c.get("crls"):
                bundle["crls"] = [_unb64(x) for x in c["crls"]]
            if c.get("ocsp"):
                bundle["ocsp"] = [_unb64(x) for x in c["ocsp"]]
            out["collateral"] = bundle
    else:
        raise AttestConstructError("unknown attestation vendor %s" % js_str(vendor))
    return out


class _WithIdentity(AttestationVerifier):
    """`identity_overrides`: after a successful verification the keys of the override replace the same keys of `measured`."""

    def __init__(self, inner: AttestationVerifier, overrides: Dict[str, Any]) -> None:
        self._inner = inner
        self._ov = overrides

    def verify(self, document: Any, expected: Any, now_ms: Any) -> Dict[str, Any]:
        r = self._inner.verify(document, expected, now_ms)
        if r.get("ok") and r.get("measured"):
            merged = dict(r["measured"])
            merged.update(self._ov)
            out = dict(r)
            out["measured"] = merged
            return out
        return r


def _present(config: Dict[str, Any], *keys: str) -> Dict[str, Any]:
    return {k: config[k] for k in keys if k in config}


def verifier_from_config(vendor: str, config: Dict[str, Any], resolve_evidence: Optional[Callable[[Any], Optional[Dict[str, Any]]]] = None) -> AttestationVerifier:
    """Build the verifier of `vendor` from a JSON-serialisable `config`. Raises AttestConstructError (a TypeError) when the
    configuration is refused (accept-all, a missing pin or allowlist, an unknown mode)."""
    if vendor not in VENDORS:
        raise AttestConstructError("unknown attestation vendor %s" % js_str(vendor))
    if not isinstance(config, dict):
        raise AttestConstructError("verifier_from_config: config must be an object")
    resolve = resolve_evidence if resolve_evidence is not None else (lambda doc: doc.get("evidence") if isinstance(doc, dict) else None)
    resolved: Callable[[Any], Optional[Dict[str, Any]]] = lambda doc: evidence_for(vendor, resolve(doc))

    v: AttestationVerifier
    if vendor == "amd-sev-snp":
        opts = _present(config, "family", "binding", "policy", "clockSkewMs", "trustAnchorArkSpkiSha384")
        opts["resolve_evidence"] = resolved
        v = AmdSnpVerifier(opts)
    elif vendor == "intel-tdx-dcap":
        opts = _present(config, "binding", "policy", "trustAnchorRootCaSpkiSha256", "allowMissingCollateral")
        opts["resolve_evidence"] = resolved
        v = IntelDcapVerifier(opts)
    elif vendor == "azure-maa":
        opts = _present(config, "trustedIssuers", "trustAnchors", "policy", "clockSkewMs")
        opts["resolve_evidence"] = resolved
        v = AzureMaaVerifier(opts)
    elif vendor == "gcp-confidential-space":
        opts = _present(config, "trustedIssuers", "trustAnchors", "policy", "clockSkewMs")
        opts["resolve_evidence"] = resolved
        v = GcpConfidentialSpaceVerifier(opts)
    else:
        col = config.get("collateral")
        pol = config.get("policy") if isinstance(config.get("policy"), dict) else {}
        nv: Dict[str, Any] = {
            "rootSpkiSha256": config.get("rootSpkiSha256"),
            "policy": {"measurements": pol.get("measurements") if pol.get("measurements") is not None else {}},
            "resolve_evidence": resolved,
        }
        if pol.get("leafSubjectIncludes") is not None:
            nv["policy"]["leafSubjectIncludes"] = pol["leafSubjectIncludes"]
        if col is not None and col is not False:
            hook_opts = _present(col, "revocation", "requireCrls", "requireCrlIssuers", "firmware") if isinstance(col, dict) else {}
            hook_opts["rimRootSpkiSha256"] = col.get("rimRootSpkiSha256") if isinstance(col, dict) else None
            hook_opts["resolve"] = lambda ids, evidence: (evidence or {}).get("collateral")
            nv["postVerify"] = NvidiaCollateralHook(hook_opts)
        v = NvidiaSpdmVerifier(nv)
    ov = config.get("identity_overrides")
    if ov:
        return _WithIdentity(v, ov)
    return v


def run_attestation_vector(row: Dict[str, Any]) -> Dict[str, Any]:
    """Run one (hydrated) vector row `{vendor, config, evidence, now, expected_binding}` through the native verifier."""
    ev = row.get("evidence")
    try:
        verifier = verifier_from_config(row["vendor"], row["config"], lambda _doc: ev)
    except Exception as e:  # the factory refused the configuration
        return {"construct_error": str(e)}
    return verifier.verify({}, row.get("expected_binding"), row["now"])


def run_x509_vector(fn: str, inp: Dict[str, Any]) -> Dict[str, Any]:
    """Run one x509 unit row of the vectors: `{ok: True, value}` or `{ok: False, error}` (the exact reader message)."""
    import base64

    def b(x: Any) -> bytes:
        return node_b64decode(x)

    try:
        if fn == "read_cert_role_info":
            return {"ok": True, "value": read_cert_role_info(b(inp["cert"]))}
        if fn in ("parse_cert_extensions", "parse_tbs_extensions"):
            m = parse_cert_extensions(b(inp["cert"])) if fn == "parse_cert_extensions" else parse_tbs_extensions(b(inp["tbs"]))
            return {"ok": True, "value": [{"oid": oid, "critical": e.critical, "value": e.value.hex()} for oid, e in m.items()]}
        if fn == "tbs_of_certificate":
            return {"ok": True, "value": base64.b64encode(tbs_of_certificate(b(inp["cert"]))).decode("ascii")}
        if fn == "unrecognised_critical_extension":
            rec = inp.get("recognised")
            return {"ok": True, "value": unrecognised_critical_extension(b(inp["cert"]), rec if rec is not None else None)}
        if fn == "check_chain_roles":
            return {"ok": True, "value": check_chain_roles([b(x) for x in inp["chain"]])}
        if fn == "der_validity_ms":
            lo, hi = der_validity_ms(b(inp["cert"]))
            return {"ok": True, "value": {"from": lo, "to": hi}}
        if fn == "parse_der_time":
            return {"ok": True, "value": parse_der_time(inp["tag"], inp["text"])}
        return {"ok": False, "error": "unknown x509 function %s" % fn}
    except (DerError, ValueError, TypeError) as e:
        return {"ok": False, "error": str(e)}
