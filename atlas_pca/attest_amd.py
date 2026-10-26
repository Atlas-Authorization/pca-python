"""AMD SEV-SNP attestation verifier (native counterpart of `createAmdSnpVerifier`).

Parses and verifies a genuine SEV-SNP ATTESTATION_REPORT: the VCEK -> ASK -> ARK chain to a PINNED per-family ARK, the
ECDSA-P384 / SHA-384 report signature under the VCEK, the VCEK <-> report binding (CHIP_ID + reported-TCB SPLs), the PCA
nonce binding (direct `report-data`, or Azure `azure-runtime-data`), and the acceptance policy. Fails closed; the reason
strings are those of the reference implementation.
"""
import hashlib
from typing import Any, Dict, List, Optional

from .attest_cert import Cert
from .attest_common import (
    JsError,
    attestation_binding,
    big_int,
    crypto,
    ec_point,
    ec_key_from_point,
    ecdsa_verify_der,
    is_num,
    key_type,
    node_curve,
    pem_blocks,
    spki_sha,
    to_hex,
)
from .attest_der import check_chain_roles, der_validity_ms, parse_cert_extensions, parse_tbs_extensions, tbs_of_certificate, RECOGNISED_CRITICAL_EXTENSIONS

AMD_SNP_SUITE = "amd-sev-snp-ecdsa-p384"
AMD_ARK_SPKI_SHA384: Dict[str, str] = {
    "milan": "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
    "genoa": "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
    "turin": "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
}

_P384_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
SEV_SNP_POLICY_DEBUG_BIT = 1 << 19

# ATTESTATION_REPORT layout (AMD SEV-SNP ABI specification), little-endian
_VERSION, _GUEST_SVN, _POLICY, _VMPL, _SIGNATURE_ALGO = 0x000, 0x004, 0x008, 0x030, 0x034
_CURRENT_TCB, _REPORT_DATA, _MEASUREMENT, _HOST_DATA, _REPORTED_TCB = 0x038, 0x050, 0x090, 0x0C0, 0x180
_CHIP_ID, _COMMITTED_TCB, _LAUNCH_TCB = 0x1A0, 0x1E0, 0x1F0
_SIGNED_END, _SIG_R, _SIG_S, _REPORT_LEN = 0x2A0, 0x2A0, 0x2E8, 0x4A0

_OID_HWID = "1.3.6.1.4.1.3704.1.4"
_OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
_OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
_OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
_OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
_HWID_LEN = 64


class BigU64(int):
    """A policy value that the reference holds as a BigInt (compared as a whole u64)."""


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


def _u64(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 8], "little")


def parse_sev_snp_report(b: bytes) -> Dict[str, Any]:
    """Parse the report layout. Raises ValueError when the buffer cannot hold the signed region and the r / s fields."""
    min_len = _SIG_S + 72
    if len(b) < min_len:
        raise ValueError("parseSevSnpReport: report too short (%d < %d)" % (len(b), min_len))
    b = bytes(b)
    return {
        "version": _u32(b, _VERSION),
        "guest_svn": _u32(b, _GUEST_SVN),
        "policy": _u64(b, _POLICY),
        "vmpl": _u32(b, _VMPL),
        "signature_algo": _u32(b, _SIGNATURE_ALGO),
        "current_tcb": _u64(b, _CURRENT_TCB),
        "report_data": b[_REPORT_DATA:_REPORT_DATA + 64],
        "measurement": b[_MEASUREMENT:_MEASUREMENT + 48],
        "host_data": b[_HOST_DATA:_HOST_DATA + 32],
        "reported_tcb": _u64(b, _REPORTED_TCB),
        "chip_id": b[_CHIP_ID:_CHIP_ID + 64],
        "committed_tcb": _u64(b, _COMMITTED_TCB),
        "launch_tcb": _u64(b, _LAUNCH_TCB),
        "sig_r": b[_SIG_R:_SIG_R + 72],
        "sig_s": b[_SIG_S:_SIG_S + 72],
        "signed": b[0:_SIGNED_END],
    }


def verify_sev_snp_report_signature(report: Dict[str, Any], vcek_key: Any) -> bool:
    """ECDSA-P384 / SHA-384 over the signed region, AMD's little-endian r || s. Never raises (fail closed)."""
    try:
        r = int.from_bytes(report["sig_r"], "little")
        s = int.from_bytes(report["sig_s"], "little")
        if r <= 0 or r >= _P384_N or s <= 0 or s >= _P384_N:
            return False
        return ecdsa_verify_der(vcek_key, crypto().utils.encode_dss_signature(r, s), report["signed"], "sha384")
    except Exception:
        return False


def _decode_spl(v: bytes) -> Any:
    """One DER INTEGER, minimally encoded, 0..255: the number, or a failure string."""
    if len(v) < 3 or v[0] != 0x02:
        return "is not a DER INTEGER"
    ln = v[1]
    if ln < 1 or ln > 2 or len(v) != 2 + ln:
        return "has a wrong-length INTEGER"
    c0 = v[2]
    if c0 & 0x80:
        return "is negative"
    if ln == 2:
        if c0 != 0x00:
            return "is out of range (> 255)"
        if (v[3] & 0x80) == 0:
            return "is a non-minimal INTEGER"
        return v[3]
    return c0


def check_vcek_report_binding(vcek_tbs: bytes, report: Dict[str, Any]) -> Optional[str]:
    """Bind the VCEK certificate body to the report: hwID == chip_id and the four SPL extensions == REPORTED_TCB bytes."""
    try:
        exts = parse_tbs_extensions(vcek_tbs)
    except ValueError as e:
        return "VCEK extensions malformed: %s" % e
    hw = exts.get(_OID_HWID)
    if hw is None:
        return "VCEK certificate has no CHIP_ID (hwID) extension"
    if hw.critical:
        return "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)"
    if len(hw.value) != _HWID_LEN:
        return "VCEK CHIP_ID (hwID) extension is %d bytes, expected %d" % (len(hw.value), _HWID_LEN)
    if hw.value != report["chip_id"]:
        return "VCEK CHIP_ID does not match report chip_id"
    t = report["reported_tcb"]

    def byte_at(i: int) -> int:
        return (t >> (8 * i)) & 0xFF

    for oid, name, want in (
        (_OID_BL_SPL, "bootloader", byte_at(0)),
        (_OID_TEE_SPL, "tee", byte_at(1)),
        (_OID_SNP_SPL, "snp", byte_at(6)),
        (_OID_UCODE_SPL, "microcode", byte_at(7)),
    ):
        ext = exts.get(oid)
        if ext is None:
            return "VCEK certificate has no %s SPL extension" % name
        if ext.critical:
            return "VCEK %s SPL extension is marked critical (the AMD profile is non-critical)" % name
        got = _decode_spl(ext.value)
        if isinstance(got, str):
            return "VCEK %s SPL extension %s" % (name, got)
        if got != want:
            return "VCEK %s SPL %d does not match report reported_tcb (%d) — TCB downgrade?" % (name, got, want)
    return None


def verify_amd_cert_chain(vcek_der: bytes, ask_ark_pem: str, trust_anchor: Optional[str], now_ms: Any, clock_skew_ms: Any = None) -> Dict[str, Any]:
    """VCEK -> ASK -> ARK, the ARK pinned by its SPKI SHA-384 (never taken from the supplied chain)."""
    try:
        if not is_num(now_ms):
            return {"ok": False, "reason": "nowMs (verifier clock) is required for the AMD chain validity check"}
        skew = 0 if clock_skew_ms is None else clock_skew_ms
        if not is_num(skew) or skew < 0:
            return {"ok": False, "reason": "clockSkewMs must be a non-negative number"}
        vcek = Cert(vcek_der)
        pems = pem_blocks(ask_ark_pem)
        if len(pems) != 2:
            return {"ok": False, "reason": "ASK+ARK chain must contain exactly two certificates (ASK then ARK)"}
        ask = Cert.from_pem(pems[0])
        ark = Cert.from_pem(pems[1])
        if ark.subject != ark.issuer or not ark.verify_self():
            return {"ok": False, "reason": "second certificate of the chain is not a self-signed ARK (chain out of order?)"}
        if ask.subject == ask.issuer:
            return {"ok": False, "reason": "first certificate of the chain is self-signed, not an ASK (chain out of order?)"}
        if ask.subject != vcek.issuer:
            return {"ok": False, "reason": "ASK subject does not match the VCEK issuer"}
        pin = (trust_anchor if trust_anchor is not None else AMD_ARK_SPKI_SHA384["milan"]).lower()
        if spki_sha(ark.public_key, "sha384") != pin:
            return {"ok": False, "reason": "ARK does not match the pinned AMD trust anchor"}
        if ask.issuer != ark.subject or not ask.verify(ark.public_key):
            return {"ok": False, "reason": "ASK is not signed by ARK"}
        if not vcek.verify(ask.public_key):
            return {"ok": False, "reason": "VCEK is not signed by ASK"}
        ders = [("VCEK", bytes(vcek_der), vcek), ("ASK", ask.raw, ask), ("ARK", ark.raw, ark)]
        role_err = check_chain_roles([d[1] for d in ders])
        if role_err:
            return {"ok": False, "reason": "AMD chain role check failed: %s" % role_err}
        for label, der, cert in ders:
            exts = parse_cert_extensions(der)
            for oid, ext in exts.items():
                if ext.critical and oid not in RECOGNISED_CRITICAL_EXTENSIONS:
                    return {"ok": False, "reason": "%s certificate has an unrecognised critical extension %s" % (label, oid)}
            bc = exts.get("2.5.29.19")
            if label != "VCEK" and not (bc is not None and bc.critical is True):
                return {"ok": False, "reason": "%s certificate BasicConstraints is not marked critical" % label}
            lo, hi = der_validity_ms(cert.raw)
            if lo is None or hi is None:
                return {"ok": False, "reason": "%s certificate validity is unparseable" % label}
            if now_ms + skew < lo:
                return {"ok": False, "reason": "%s certificate is not yet valid" % label}
            if now_ms - skew > hi:
                return {"ok": False, "reason": "%s certificate has expired" % label}
        pk = vcek.public_key
        if key_type(pk) != "ec" or node_curve(pk) != "secp384r1":
            raise TypeError("VCEK is not EC secp384r1 (got %s/%s)" % (key_type(pk), node_curve(pk) or "undefined"))
        key = ec_key_from_point("P-384", ec_point(pk, "P-384"))
        return {"ok": True, "vcek": key, "vcekTbs": tbs_of_certificate(vcek_der)}
    except Exception as e:
        return {"ok": False, "reason": "AMD chain verification error: %s" % e}


def _lower_list(v: Any) -> List[str]:
    return [x.lower() for x in v]


def check_sev_snp_policy(report: Dict[str, Any], policy: Dict[str, Any]) -> Optional[str]:
    if policy.get("requireEcdsaP384") is not False and report["signature_algo"] != 1:
        return "unexpected signature_algo %d" % report["signature_algo"]
    if policy.get("allowDebug") is not True and (report["policy"] & SEV_SNP_POLICY_DEBUG_BIT) != 0:
        return "guest policy has the DEBUG bit set (host can inspect the guest)"
    mg = policy.get("minGuestSvn")
    if is_num(mg) and report["guest_svn"] < mg:
        return "guest_svn %d below minimum %s" % (report["guest_svn"], _fmt_num(mg))
    v = policy.get("minReportedTcb")
    if isinstance(v, BigU64) and report["reported_tcb"] < v:
        return "reported_tcb below minimum (rollback?)"
    v = policy.get("minCommittedTcb")
    if isinstance(v, BigU64) and report["committed_tcb"] < v:
        return "committed_tcb below minimum (rollback?)"
    v = policy.get("minLaunchTcb")
    if isinstance(v, BigU64) and report["launch_tcb"] < v:
        return "launch_tcb below minimum"
    want_vmpl = policy.get("requireVmpl")
    if want_vmpl is None:
        want_vmpl = 0
    if want_vmpl != "any" and not (is_num(want_vmpl) and report["vmpl"] == want_vmpl):
        return "vmpl %d is not the required %s" % (report["vmpl"], _fmt_num(want_vmpl))
    meas = policy.get("measurements")
    if isinstance(meas, (list, tuple)) and len(meas) > 0:
        if to_hex(report["measurement"]) not in _lower_list(meas):
            return "measurement not in policy allowlist"
    hd = policy.get("hostData")
    if isinstance(hd, (list, tuple)) and len(hd) > 0:
        if to_hex(report["host_data"]) not in _lower_list(hd):
            return "host_data not in policy allowlist"
    ci = policy.get("chipIds")
    if isinstance(ci, (list, tuple)) and len(ci) > 0:
        if to_hex(report["chip_id"]) not in _lower_list(ci):
            return "chip_id not in policy allowlist"
    return None


def _fmt_num(v: Any) -> str:
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def default_identity(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "model_id": "",
        "weights_digest": "",
        "weights_measured": False,
        "runtime_measurement": to_hex(report["measurement"]),
        "operator": to_hex(report["chip_id"]),
    }


def verify_genuine_sev_snp_report(
    report: bytes,
    vcek_der: bytes,
    ask_ark_pem: str,
    trust_anchor: Optional[str],
    now_ms: Any,
    clock_skew_ms: Any = None,
    expected: Any = None,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Parse and verify a genuine report end to end, offline. Fails closed with a reason."""
    try:
        try:
            rep = parse_sev_snp_report(report)
        except ValueError as e:
            return {"ok": False, "reason": "report parse failed: %s" % e}
        # exactly 1184 bytes; the signature block beyond r and s is reserved-zero (anything else is a second encoding)
        if len(report) != _REPORT_LEN:
            return {"ok": False, "reason": "report length %d is not the canonical %d" % (len(report), _REPORT_LEN)}
        if (
            any(report[_SIG_S + 72:])
            or any(report[_SIG_R + 48:_SIG_R + 72])
            or any(report[_SIG_S + 48:_SIG_S + 72])
        ):
            return {"ok": False, "reason": "report signature block has non-zero reserved bytes"}
        chain = verify_amd_cert_chain(vcek_der, ask_ark_pem, trust_anchor, now_ms, clock_skew_ms)
        if not chain["ok"] or "vcek" not in chain or "vcekTbs" not in chain:
            return {"ok": False, "reason": "cert chain invalid: %s" % chain.get("reason")}
        if not verify_sev_snp_report_signature(rep, chain["vcek"]):
            return {"ok": False, "reason": "report signature does not verify under VCEK"}
        bind_err = check_vcek_report_binding(chain["vcekTbs"], rep)
        if bind_err:
            return {"ok": False, "reason": bind_err}
        if expected is not None:
            if attestation_binding(expected) != rep["report_data"]:
                return {"ok": False, "reason": "report_data does not bind holder/grant/epoch/nonce"}
        if policy is not None:
            pol_err = check_sev_snp_policy(rep, policy)
            if pol_err:
                return {"ok": False, "reason": pol_err}
        return {"ok": True, "report": rep, "measured": default_identity(rep)}
    except Exception as e:
        return {"ok": False, "reason": "genuine verification error (fail closed): %s" % e}


# ---------------------------------------------------------------------------------------------- Azure runtime-data binding


def check_azure_runtime_data_binding(report_data: bytes, runtime_data: bytes, expected: Any) -> Optional[str]:
    """The Azure binding: report_data[0:32] = sha256(runtime-data JSON), [32:64] = 0, and its 64-byte `user-data` = the PCA binding."""
    from .attest_common import is_hex, js_json_loads

    if len(report_data) != 64:
        return "report_data is not 64 bytes"
    if any(report_data[32:]):
        return "report_data[32:64] is not zero (not an Azure runtime-data hash)"
    if hashlib.sha256(runtime_data).digest() != bytes(report_data[:32]):
        return "sha256(runtime data) does not equal the quote report_data"
    try:
        parsed = js_json_loads(bytes(runtime_data).decode("utf-8", "replace"))
    except JsError:
        return "runtime data is not valid JSON"
    if not isinstance(parsed, dict):
        return "runtime data is not a JSON object"
    user_data = parsed.get("user-data")
    if not isinstance(user_data, str) or len(user_data) != 128 or not is_hex(user_data):
        return "runtime data carries no 64-byte hex user-data"
    try:
        want = attestation_binding(expected)
    except TypeError as e:
        return "binding not constructible: %s" % e
    if bytes.fromhex(user_data) != want:
        return "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)"
    return None


# ---------------------------------------------------------------------------------------------- the verifier


class AttestConstructError(TypeError):
    """The factory refused a configuration (accept-all, a missing pin, an unknown mode)."""


class AmdSnpVerifier:
    """`verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}."""

    def __init__(self, opts: Dict[str, Any]) -> None:
        pol = opts.get("policy")
        policy: Dict[str, Any] = dict(pol) if isinstance(pol, dict) else {}
        for k in ("minReportedTcb", "minCommittedTcb", "minLaunchTcb"):
            if k in policy:
                policy[k] = BigU64(big_int(policy[k]))
        family = opts.get("family")
        pin = AMD_ARK_SPKI_SHA384.get(family) if isinstance(family, str) else None
        override = opts.get("trustAnchorArkSpkiSha384")
        if override is not None and isinstance(family, str) and family in AMD_ARK_SPKI_SHA384:
            pin = override  # conformance harness only: the synthetic chains are rooted in a test ARK
        if not pin:
            raise AttestConstructError("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'")
        self._pin = pin
        self._family = family
        if opts.get("binding") not in ("report-data", "azure-runtime-data"):
            raise AttestConstructError("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'")
        self._binding = opts["binding"]
        meas = policy.get("measurements")
        if not isinstance(meas, list) or len(meas) == 0:
            raise AttestConstructError("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
        # a private copy: an allowlist emptied after construction must not become accept-all
        policy["measurements"] = list(meas)
        self._policy = policy
        self._skew = opts.get("clockSkewMs")
        self._resolve = opts.get("resolve_evidence")

    def verify(self, document: Any, expected: Any, now_ms: Any) -> Dict[str, Any]:
        def fail(reason: str) -> Dict[str, Any]:
            return {"ok": False, "reason": reason}

        try:
            if self._resolve is None:
                return fail("no AMD SEV-SNP evidence resolver configured (fail closed)")
            ev = self._resolve(document)
            if (
                not isinstance(ev, dict)
                or not isinstance(ev.get("report"), (bytes, bytearray))
                or not isinstance(ev.get("vcekDer"), (bytes, bytearray))
                or not isinstance(ev.get("askArkPem"), str)
            ):
                return fail("no AMD SEV-SNP evidence for this action")
            if expected is None:
                return fail("no expected attestation binding supplied")
            direct = self._binding == "report-data"
            r = verify_genuine_sev_snp_report(
                bytes(ev["report"]), bytes(ev["vcekDer"]), ev["askArkPem"], self._pin, now_ms, self._skew,
                expected if direct else None, self._policy,
            )
            if not r["ok"] or "report" not in r or "measured" not in r:
                return fail("SEV-SNP report invalid: %s" % (r.get("reason") or "unknown"))
            if not direct:
                rd = ev.get("runtimeData")
                if not isinstance(rd, (bytes, bytearray)):
                    return fail("azure-runtime-data binding needs the runtime-data JSON bytes")
                why = check_azure_runtime_data_binding(r["report"]["report_data"], bytes(rd), expected)
                if why:
                    return fail(why)
            return {
                "ok": True,
                "bound": True,
                "measured": r["measured"],
                "hostAsserted": {"attestation_type": "amd-sev-snp", "family": self._family, "measurement": to_hex(r["report"]["measurement"])},
            }
        except Exception as e:
            return fail("amd-snp verification error (fail closed): %s" % e)
