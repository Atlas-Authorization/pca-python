"""Microsoft Azure Attestation (MAA) JWT verifier (native counterpart of `createAzureMaaVerifier`).

The token-signing `x5c` chain is verified link by link to a CONFIGURED trust anchor (an SPKI SHA-256 pin or an external root
certificate), the JWS (ES256 / RS256) under the leaf key, the `iss` / time window, the isolation-type claims (`sevsnpvm` /
`tdxvm`), the PCA binding and the NON-EMPTY measurement allowlist. Fails closed with the reference's reason strings.
"""
import math
from typing import Any, Dict, List, Optional, Set

from .attest_amd import AttestConstructError
from .attest_cert import Cert
from .attest_common import (
    as_str,
    attestation_binding,
    decode_claim_bytes,
    ecdsa_verify_raw,
    first_string,
    is_num,
    jwk_curve,
    js_num_str,
    key_type,
    node_b64decode,
    parse_jws,
    rsa_pkcs1_verify,
    spki_sha,
    transform_binding,
)
from .attest_der import x509_valid_at

AZURE_MAA_SUITE = "azure-maa-jwt"

_SEVSNP_MEASUREMENT_KEYS = ("x-ms-sevsnpvm-launchmeasurement",)
_SEVSNP_REPORTDATA_KEYS = ("x-ms-sevsnpvm-reportdata",)
_SEVSNP_HOSTDATA_KEYS = ("x-ms-sevsnpvm-hostdata",)
_SEVSNP_DEBUG_KEY = "x-ms-sevsnpvm-is-debuggable"
_SEVSNP_TCB_CLAIMS = (
    ("bootloader", "x-ms-sevsnpvm-bootloader-svn", "bootloader_svn"),
    ("snp", "x-ms-sevsnpvm-snpfw-svn", "snpfw_svn"),
    ("microcode", "x-ms-sevsnpvm-microcode-svn", "microcode_svn"),
    ("tee", "x-ms-sevsnpvm-tee-svn", "tee_svn"),
)
_TDX_MRTD_KEYS = ("tdx_mrtd", "x-ms-tdx-mrtd")
_TDX_REPORTDATA_KEYS = ("tdx_report_data", "x-ms-tdx-report-data", "x-ms-tdx-reportdata")
_TDX_RTMR0_KEYS = ("tdx_rtmr0", "x-ms-tdx-rtmr0")


def _kty_crv(key: Any) -> str:
    t = key_type(key)
    return "%s/%s" % ({"ec": "EC", "rsa": "RSA"}.get(t, t), jwk_curve(key) or "undefined")


def _kty(key: Any) -> str:
    t = key_type(key)
    return {"ec": "EC", "rsa": "RSA"}.get(t, t)


def verify_x5c_chain(x5c: Any, anchors: Dict[str, Any], now_ms: float, skew_ms: float = 0) -> Dict[str, Any]:
    """An `x5c` chain (base64 DER, leaf first) to a configured trust anchor; every certificate valid at `now` (+- skew)."""
    try:
        if not isinstance(x5c, list) or len(x5c) == 0:
            return {"ok": False, "reason": "empty x5c certificate chain"}
        skew = max(0, skew_ms) if is_num(skew_ms) else 0
        certs: List[Cert] = []
        for i, b64 in enumerate(x5c):
            if not isinstance(b64, str) or len(b64) == 0:
                return {"ok": False, "reason": "empty x5c entry at index %d" % i}
            try:
                cert = Cert(node_b64decode(b64))
            except Exception as e:
                return {"ok": False, "reason": "malformed x5c certificate at index %d: %s" % (i, e)}
            if not x509_valid_at(cert.raw, now_ms, skew):
                return {"ok": False, "reason": "x5c certificate at index %d is outside its validity window" % i}
            certs.append(cert)

        fingerprints: Set[str] = set()
        root_keys: List[Any] = []
        for fp in (anchors.get("rootSpkiSha256") or []) if isinstance(anchors, dict) else []:
            if isinstance(fp, str) and len(fp) > 0:
                fingerprints.add(fp.lower())
        for pem in (anchors.get("rootCertsPem") or []) if isinstance(anchors, dict) else []:
            rc = Cert.from_pem(pem)
            root_keys.append(rc.public_key)
            fingerprints.add(spki_sha(rc.public_key, "sha256"))
        if len(fingerprints) == 0 and len(root_keys) == 0:
            return {"ok": False, "reason": "no MAA trust anchor configured (fail closed)"}

        anchor_idx = -1
        for j, c in enumerate(certs):
            if spki_sha(c.public_key, "sha256") in fingerprints:
                anchor_idx = j
                break
        if anchor_idx >= 0:
            for i in range(anchor_idx):
                if not certs[i].verify(certs[i + 1].public_key):
                    return {"ok": False, "reason": "x5c link %d is not signed by the certificate above it" % i}
            return {"ok": True, "leaf": certs[0]}

        for i in range(len(certs) - 1):
            if not certs[i].verify(certs[i + 1].public_key):
                return {"ok": False, "reason": "x5c link %d is not signed by the certificate above it" % i}
        top = certs[-1]
        if not any(top.verify(k) for k in root_keys):
            return {"ok": False, "reason": "x5c chain does not anchor in a configured MAA trust root"}
        return {"ok": True, "leaf": certs[0]}
    except Exception as e:
        return {"ok": False, "reason": "x5c chain verification error (fail closed): %s" % e}


def _verify_jws_signature(parsed: Dict[str, Any], leaf: Cert) -> Optional[str]:
    alg = parsed["header"]["alg"]
    key = leaf.public_key
    if alg == "ES256":
        if key_type(key) != "ec" or jwk_curve(key) != "P-256":
            return "ES256 token but signing key is %s (not EC P-256)" % _kty_crv(key)
        if len(parsed["signature"]) != 64:
            return "ES256 signature is %d bytes (expected 64: r‖s)" % len(parsed["signature"])
        ok = ecdsa_verify_raw(key, parsed["signature"], parsed["signingInput"], "sha256")
        return None if ok else "JWS ES256 signature does not verify under the MAA signing key"
    if alg == "RS256":
        if key_type(key) != "rsa":
            return "RS256 token but signing key is %s (not RSA)" % _kty(key)
        ok = rsa_pkcs1_verify(key, parsed["signature"], parsed["signingInput"], "sha256")
        return None if ok else "JWS RS256 signature does not verify under the MAA signing key"
    return "unsupported JWS alg '%s' (MAA uses ES256 / RS256)" % alg


def _resolve_signing_x5c(header: Dict[str, Any], jwks: Any) -> Dict[str, Any]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if isinstance(keys, list) and len(keys) > 0:
        kid = header.get("kid")
        if not isinstance(kid, str) or len(kid) == 0:
            only = keys[0] if len(keys) == 1 else None
            if only is None:
                return {"reason": "token has no kid and the JWKS publishes multiple keys (ambiguous)"}
            x5c = only.get("x5c") if isinstance(only, dict) else None
            return {"x5c": x5c} if isinstance(x5c, list) and len(x5c) > 0 else {"reason": "JWKS key carries no x5c chain"}
        match = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
        if match is None:
            return {"reason": "no JWKS key matches the token kid '%s' (untrusted signer)" % kid}
        x5c = match.get("x5c")
        if not isinstance(x5c, list) or len(x5c) == 0:
            return {"reason": "JWKS key '%s' carries no x5c chain" % kid}
        return {"x5c": x5c}
    hx = header.get("x5c")
    if hx and len(hx) > 0:
        return {"x5c": hx}
    return {"reason": "no signing x5c available (no JWKS and no header x5c)"}


def _lower(lst: Any) -> List[str]:
    return [x.lower() for x in lst]


class AzureMaaVerifier:
    """`verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}."""

    def __init__(self, opts: Dict[str, Any]) -> None:
        ti = opts.get("trustedIssuers")
        if not isinstance(ti, list) or len(ti) == 0:
            raise AttestConstructError("createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs")
        for iss in ti:
            if not isinstance(iss, str) or len(iss) == 0:
                raise AttestConstructError("createAzureMaaVerifier: every trusted issuer must be a non-empty URL string")
        anchors = opts.get("trustAnchors")
        a = anchors if isinstance(anchors, dict) else {}
        count = (len(a.get("rootCertsPem") or []) if a.get("rootCertsPem") is not None else 0) + (len(a.get("rootSpkiSha256") or []) if a.get("rootSpkiSha256") is not None else 0)
        if count == 0:
            raise AttestConstructError("createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted")
        policy = opts.get("policy")
        has_sev = isinstance(policy, dict) and isinstance(policy.get("sevSnpMeasurements"), list) and len(policy["sevSnpMeasurements"]) > 0
        has_tdx = isinstance(policy, dict) and isinstance(policy.get("tdxMrtds"), list) and len(policy["tdxMrtds"]) > 0
        if not isinstance(policy, dict) or (not has_sev and not has_tdx):
            raise AttestConstructError("createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)")
        if "sevSnpMinTcb" in policy:
            m = policy["sevSnpMinTcb"]
            if not isinstance(m, dict):
                raise AttestConstructError("createAzureMaaVerifier: policy.sevSnpMinTcb must be an object")
            for k, v in m.items():
                if not any(name == k for name, _c, _h in _SEVSNP_TCB_CLAIMS):
                    raise AttestConstructError("createAzureMaaVerifier: policy.sevSnpMinTcb.%s is not a known field (bootloader | snp | microcode | tee)" % k)
                if not (is_num(v) and float(v).is_integer() and v >= 0):
                    raise AttestConstructError("createAzureMaaVerifier: policy.sevSnpMinTcb.%s must be a non-negative integer" % k)
        self._anchors = a
        self._policy = dict(policy)
        self._has_sev, self._has_tdx = has_sev, has_tdx
        self._issuers = set(ti)
        skew = opts.get("clockSkewMs")
        self._skew = max(0, skew) if is_num(skew) else 0
        self._resolve = opts.get("resolve_evidence")

    def verify(self, document: Any, expected: Any, now_ms: Any) -> Dict[str, Any]:
        def fail(reason: str) -> Dict[str, Any]:
            return {"ok": False, "reason": reason}

        policy = self._policy
        try:
            if self._resolve is None:
                return fail("no Azure MAA evidence resolver configured (fail closed)")
            evidence = self._resolve(document)
            if not isinstance(evidence, dict) or not isinstance(evidence.get("token"), str) or len(evidence["token"]) == 0:
                return fail("no Azure MAA token for this action")
            try:
                parsed = parse_jws(evidence["token"], "parseMaaJwt")
            except TypeError as e:
                return fail("MAA token parse failed: %s" % e)
            alg = parsed["header"]["alg"]
            if alg != "ES256" and alg != "RS256":
                return fail("unsupported JWS alg '%s' (MAA uses ES256 / RS256)" % alg)
            signing = _resolve_signing_x5c(parsed["header"], evidence.get("jwks"))
            if "x5c" not in signing:
                return fail(signing.get("reason") or "no signing x5c available")
            chain = verify_x5c_chain(signing["x5c"], self._anchors, now_ms, self._skew)
            if not chain["ok"] or "leaf" not in chain:
                return fail("MAA signing chain invalid: %s" % (chain.get("reason") or "untrusted"))
            sig_err = _verify_jws_signature(parsed, chain["leaf"])
            if sig_err:
                return fail(sig_err)

            payload = parsed["payload"]
            iss = as_str(payload.get("iss"))
            if not iss or iss not in self._issuers:
                return fail("token iss '%s' is not a configured trusted MAA instance" % ("undefined" if iss is None else iss))
            now_sec = math.floor(now_ms / 1000)
            skew_sec = math.ceil(self._skew / 1000)
            exp = payload.get("exp") if is_num(payload.get("exp")) else None
            iat = payload.get("iat") if is_num(payload.get("iat")) else None
            nbf = payload.get("nbf") if is_num(payload.get("nbf")) else None
            if exp is None:
                return fail("token has no exp (cannot bound validity — fail closed)")
            if now_sec - skew_sec > exp:
                return fail("MAA token expired")
            if nbf is not None and now_sec + skew_sec < nbf:
                return fail("MAA token not yet valid (nbf)")
            if iat is not None and now_sec + skew_sec < iat:
                return fail("MAA token issued in the future (iat)")

            isolation = payload.get("x-ms-isolation-tee")
            tee = isolation if isinstance(isolation, dict) else payload
            itype = as_str(tee.get("x-ms-attestation-type"))
            if itype is None:
                itype = as_str(payload.get("x-ms-attestation-type"))
            if itype != "sevsnpvm" and itype != "tdxvm":
                return fail("unexpected x-ms-attestation-type '%s' (expected sevsnpvm | tdxvm)" % ("undefined" if itype is None else itype))

            if expected is None:
                return fail("no expected attestation binding supplied")
            if policy.get("runtimeUserDataBinding") is True:
                try:
                    raw_binding = attestation_binding(expected)
                except TypeError as e:
                    return fail("binding not constructible: %s" % e)
                runtime = payload.get("x-ms-runtime")
                if not isinstance(runtime, dict):
                    return fail("token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)")
                user_data = as_str(runtime.get("user-data"))
                if not user_data:
                    return fail("x-ms-runtime carries no user-data to bind the PCA challenge")
                ud = decode_claim_bytes(user_data)
                if ud is None or ud != raw_binding:
                    return fail("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")
            else:
                try:
                    binding_bytes = transform_binding(attestation_binding(expected), policy.get("reportDataHash"))
                except TypeError as e:
                    return fail("binding not constructible: %s" % e)
                rd_claim = first_string(tee, _SEVSNP_REPORTDATA_KEYS if itype == "sevsnpvm" else _TDX_REPORTDATA_KEYS)
                if not rd_claim:
                    return fail("token carries no report-data claim to bind the PCA challenge")
                rd = decode_claim_bytes(rd_claim)
                if rd is None:
                    return fail("report-data claim is not decodable (hex/base64)")
                if rd != binding_bytes:
                    return fail("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")

            if itype == "sevsnpvm":
                if not self._has_sev:
                    return fail("sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)")
                measurement = first_string(tee, _SEVSNP_MEASUREMENT_KEYS)
                if not measurement:
                    return fail("sevsnpvm token carries no launch-measurement claim")
                m_hex = measurement.lower()
                if m_hex not in _lower(policy["sevSnpMeasurements"]):
                    return fail("SEV-SNP launch measurement not in policy allowlist")
                debuggable = tee.get(_SEVSNP_DEBUG_KEY)
                if policy.get("allowDebug") is not True and debuggable is True:
                    return fail("SEV-SNP guest is debuggable (no confidentiality)")
                host_data = first_string(tee, _SEVSNP_HOSTDATA_KEYS)
                hd_list = policy.get("sevSnpHostData")
                if isinstance(hd_list, list) and len(hd_list) > 0:
                    if not host_data or host_data.lower() not in _lower(hd_list):
                        return fail("SEV-SNP host-data not in policy allowlist")
                tcb_reported: Dict[str, str] = {}
                floors = policy.get("sevSnpMinTcb")
                for name, claim, host_key in _SEVSNP_TCB_CLAIMS:
                    raw = tee.get(claim)
                    is_svn = is_num(raw) and float(raw).is_integer() and raw >= 0
                    if is_svn:
                        tcb_reported[host_key] = js_num_str(raw)
                    floor = floors.get(name) if isinstance(floors, dict) else None
                    if floor is None:
                        continue
                    if not is_svn:
                        return fail("SEV-SNP %s SVN claim '%s' is missing or not a non-negative integer (policy requires a minimum)" % (name, claim))
                    if raw < floor:
                        return fail("SEV-SNP %s SVN %s is below the policy minimum %s" % (name, js_num_str(raw), js_num_str(floor)))
                measured = {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": m_hex, "operator": ""}
                host: Dict[str, str] = {"attestation_type": "sevsnpvm"}
                host.update(tcb_reported)
                if host_data:
                    host["host_data"] = host_data.lower()
                return {"ok": True, "bound": True, "measured": measured, "hostAsserted": host}

            if not self._has_tdx:
                return fail("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)")
            mrtd = first_string(tee, _TDX_MRTD_KEYS)
            if not mrtd:
                return fail("tdxvm token carries no MRTD claim")
            mrtd_hex = mrtd.lower()
            if mrtd_hex not in _lower(policy["tdxMrtds"]):
                return fail("TDX MRTD not in policy allowlist")
            td_debug = tee.get("tdx_td_attributes_debug")
            dbgstat = as_str(tee.get("dbgstat"))
            if policy.get("allowDebug") is not True and (td_debug is True or (dbgstat is not None and dbgstat != "disabled")):
                return fail("TDX guest is debuggable (no confidentiality)")
            tcb_status = as_str(tee.get("attester_tcb_status"))
            if tcb_status is not None:
                ok_statuses = policy.get("tdxAllowedTcbStatuses")
                if ok_statuses is None:
                    ok_statuses = ["UpToDate", "SWHardeningNeeded"]
                if tcb_status not in ok_statuses:
                    return fail("TDX platform TCB status '%s' is not accepted by policy" % tcb_status)
            rtmr0 = first_string(tee, _TDX_RTMR0_KEYS)
            rt_list = policy.get("tdxRtmrs")
            if isinstance(rt_list, list) and len(rt_list) > 0:
                if not rtmr0 or rtmr0.lower() not in _lower(rt_list):
                    return fail("TDX RTMR0 not in policy allowlist")
            measured = {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": mrtd_hex, "operator": ""}
            host = {"attestation_type": "tdxvm"}
            if tcb_status:
                host["tcb_status"] = tcb_status
            if rtmr0:
                host["rtmr0"] = rtmr0.lower()
            return {"ok": True, "bound": True, "measured": measured, "hostAsserted": host}
        except Exception as e:
            return fail("azure-maa verification error (fail closed): %s" % e)
