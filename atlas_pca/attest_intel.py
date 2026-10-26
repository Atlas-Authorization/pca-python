"""Intel TDX (DCAP v4, ECDSA-P256) attestation verifier and Intel PCS collateral evaluation.

Native counterpart of `createIntelDcapVerifier`, `verifyGenuineTdxQuote` and `verifyIntelTdxCollateral`: the PCK chain to the
pinned Intel SGX Root CA, the QE report under the PCK leaf, the attestation key endorsed by the QE, the TD quote signature, the
PCA nonce binding, the MRTD / FMSPC / RTMR0 allowlists and (by default REQUIRED) the signed TCB info / QE identity / CRL
collateral. Fails closed with the reference's reason strings.
"""
import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Set

from .attest_amd import AttestConstructError, check_azure_runtime_data_binding
from .attest_cert import Cert
from .attest_common import (
    attestation_binding,
    ec_key_from_point,
    ec_point,
    ecdsa_verify_der,
    ecdsa_verify_raw,
    is_num,
    js_json_loads,
    JsError,
    key_type,
    pem_blocks,
    rsa_pkcs1_verify,
    spki_sha,
    to_hex,
)
from .attest_der import check_chain_roles, days_from_civil, unrecognised_critical_extension, x509_valid_at

INTEL_DCAP_SUITE = "intel-tdx-dcap-ecdsa-p256"
INTEL_SGX_ROOT_CA_SPKI_SHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"

_HEADER_LEN, _TD_REPORT_LEN = 48, 584
_QE_ATTRIBUTES_OFF, _QE_REPORT_DATA_OFF, _SGX_REPORT_LEN = 48, 0x140, 384

_OID_SGX_FMSPC = bytes([0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04])
_OID_SGX_TCB = bytes([0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x02])

STATUS_ORDER = [
    "UpToDate",
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
    "OutOfDateConfigurationNeeded",
    "OutOfDate",
    "Revoked",
]
DEFAULT_ACCEPTED_STATUSES = ["UpToDate", "SWHardeningNeeded"]


def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 2], "little")


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


# ------------------------------------------------------------------------------------------------ quote parsing


def parse_dcap_quote(quote: bytes) -> Dict[str, Any]:
    """Parse a DCAP v4 / ECDSA-P256 / TDX quote. Raises ValueError (the reference's messages) on any structural violation."""
    quote = bytes(quote)
    if len(quote) < _HEADER_LEN + _TD_REPORT_LEN + 4:
        raise ValueError("parseDcapQuote: too short for header + TD report + sig length")
    version, att_key_type, tee_type = _u16(quote, 0), _u16(quote, 2), _u32(quote, 4)
    if version != 4:
        raise ValueError("parseDcapQuote: unsupported quote version %d (expected 4)" % version)
    if att_key_type != 2:
        raise ValueError("parseDcapQuote: unsupported attestation key type %d (expected ECDSA-P256 = 2)" % att_key_type)
    if tee_type != 0x81:
        raise ValueError("parseDcapQuote: unexpected TEE type 0x%x (expected TDX = 0x81)" % tee_type)
    header = quote[:_HEADER_LEN]
    td_body = quote[_HEADER_LEN:_HEADER_LEN + _TD_REPORT_LEN]
    o = _HEADER_LEN + _TD_REPORT_LEN
    sig_len = _u32(quote, o)
    o += 4
    sig_end = o + sig_len
    if sig_end > len(quote):
        raise ValueError("parseDcapQuote: signature data (%d) overruns the quote" % sig_len)

    def need(n: int, what: str) -> None:
        if o + n > sig_end:
            raise ValueError("parseDcapQuote: truncated reading %s" % what)

    need(64, "quote signature")
    quote_signature = quote[o:o + 64]
    o += 64
    need(64, "attestation public key")
    ak_pub_raw = quote[o:o + 64]
    o += 64
    need(6, "outer cert-data header")
    outer_type = _u16(quote, o)
    outer_size = _u32(quote, o + 2)
    o += 6
    if outer_type != 6:
        raise ValueError("parseDcapQuote: outer cert-data type %d (expected QE-report-cert-data = 6)" % outer_type)
    outer_end = o + outer_size
    if outer_end > sig_end:
        raise ValueError("parseDcapQuote: outer cert-data overruns signature data")
    need(_SGX_REPORT_LEN, "QE report")
    qe_report = quote[o:o + _SGX_REPORT_LEN]
    o += _SGX_REPORT_LEN
    need(64, "QE report signature")
    qe_sig = quote[o:o + 64]
    o += 64
    need(2, "QE auth-data size")
    auth_size = _u16(quote, o)
    o += 2
    need(auth_size, "QE auth-data")
    qe_auth = quote[o:o + auth_size]
    o += auth_size
    need(6, "inner cert-data header")
    inner_type = _u16(quote, o)
    inner_size = _u32(quote, o + 2)
    o += 6
    if inner_type != 5:
        raise ValueError("parseDcapQuote: inner cert-data type %d (expected PCK-cert-chain = 5)" % inner_type)
    if o + inner_size > outer_end:
        raise ValueError("parseDcapQuote: inner cert-data overruns outer cert-data")
    pck_chain_pem = quote[o:o + inner_size].decode("latin-1")
    # Azure pads the quote with zero bytes after the declared signature data; anything else is unverified data riding along
    if any(quote[sig_end:]):
        raise ValueError("parseDcapQuote: non-zero bytes after the signature data")
    return {
        "header": header,
        "tdReportBody": td_body,
        "quoteSignature": quote_signature,
        "akPubRaw": ak_pub_raw,
        "qeReportBody": qe_report,
        "qeReportSignature": qe_sig,
        "qeAuthData": qe_auth,
        "pckChainPem": pck_chain_pem,
    }


def parse_dcap_td_report(body: bytes) -> Dict[str, Any]:
    if len(body) < _TD_REPORT_LEN:
        raise ValueError("parseDcapTdReport: body too short (%d < %d)" % (len(body), _TD_REPORT_LEN))
    return {
        "teeTcbSvn": body[0:16],
        "mrSeam": body[16:64],
        "mrSignerSeam": body[64:112],
        "tdAttributes": body[120:128],
        "mrTd": body[136:184],
        "rtmr0": body[328:376],
        "reportData": body[520:584],
    }


# ------------------------------------------------------------------------------------------------ PCK certificate


def _read_der_tlv(buf: bytes, off: int) -> Optional[Dict[str, int]]:
    """A lenient DER TLV at `off`; None on any malformed or overrunning length."""
    if off + 2 > len(buf):
        return None
    tag = buf[off]
    ln = buf[off + 1]
    p = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or p + n > len(buf):
            return None
        ln = 0
        for _ in range(n):
            ln = ln * 256 + buf[p]
            p += 1
    end = p + ln
    if end > len(buf):
        return None
    return {"tag": tag, "start": p, "end": end}


def extract_pck_fmspc_and_tcb(leaf_der: bytes) -> Dict[str, Any]:
    """FMSPC + the PCK leaf's issued TCB, read from the Intel SGX extension (1.2.840.113741.1.13.1). Raises on anything off."""
    fi = leaf_der.find(_OID_SGX_FMSPC)
    if fi < 0:
        raise ValueError("extractPckFmspcAndTcb: FMSPC OID not found in certificate")
    fv = _read_der_tlv(leaf_der, fi + len(_OID_SGX_FMSPC))
    if fv is None or fv["tag"] != 0x04 or fv["end"] - fv["start"] != 6:
        raise ValueError("extractPckFmspcAndTcb: malformed FMSPC OCTET STRING")
    fmspc = leaf_der[fv["start"]:fv["end"]]
    ti = leaf_der.find(_OID_SGX_TCB)
    if ti < 0:
        raise ValueError("extractPckFmspcAndTcb: TCB OID not found in certificate")
    seq = _read_der_tlv(leaf_der, ti + len(_OID_SGX_TCB))
    if seq is None or seq["tag"] != 0x30:
        raise ValueError("extractPckFmspcAndTcb: malformed TCB SEQUENCE")
    sgx = bytearray(16)
    pcesvn = -1
    p = seq["start"]
    idx = 0
    while p < seq["end"]:
        pair = _read_der_tlv(leaf_der, p)
        if pair is None or pair["tag"] != 0x30:
            raise ValueError("extractPckFmspcAndTcb: malformed TCB component")
        oid = _read_der_tlv(leaf_der, pair["start"])
        if oid is None or oid["tag"] != 0x06:
            raise ValueError("extractPckFmspcAndTcb: TCB component missing OID")
        val = _read_der_tlv(leaf_der, oid["end"])
        if val is None:
            raise ValueError("extractPckFmspcAndTcb: TCB component missing value")
        last = leaf_der[oid["end"] - 1]
        if val["tag"] == 0x02:
            n = 0
            for b in range(val["start"], val["end"]):
                n = (n << 8) | leaf_der[b]
            if 1 <= last <= 16:
                sgx[last - 1] = n & 0xFF
            elif last == 17:
                pcesvn = n & 0xFFFF
        p = pair["end"]
        idx += 1
        if idx > 64:
            break
    if pcesvn < 0:
        raise ValueError("extractPckFmspcAndTcb: PCESVN not found in TCB extension")
    return {"fmspc": fmspc, "sgxTcbComponents": bytes(sgx), "pcesvn": pcesvn}


def verify_intel_pck_chain(pck_chain_pem: Any, trust_anchor: Optional[str] = None, now_ms: Any = None) -> Dict[str, Any]:
    """The embedded PCK chain to the PINNED Intel SGX Root CA: every certificate valid at `now`, every link signed, CA roles."""
    try:
        blocks = pem_blocks(pck_chain_pem) if isinstance(pck_chain_pem, str) else None
        if not blocks:
            return {"ok": False, "reason": "no PEM certificates in the PCK chain"}
        certs = [Cert.from_pem(b) for b in blocks]
        issuers = set(c.issuer for c in certs)
        by_subject = {c.subject: c for c in certs}
        leaf = next((c for c in certs if c.subject not in issuers), certs[0])
        ordered: List[Cert] = []
        seen: Set[str] = set()
        cur: Optional[Cert] = leaf
        while cur is not None and cur.subject not in seen:
            ordered.append(cur)
            seen.add(cur.subject)
            if cur.subject == cur.issuer:
                break
            cur = by_subject.get(cur.issuer)
        root = ordered[-1]
        if root.subject != root.issuer:
            return {"ok": False, "reason": "PCK chain does not terminate in a self-signed root"}
        if len(ordered) != len(certs):
            return {"ok": False, "reason": "PCK chain is not a single connected path (orphan/duplicate certificates)"}
        now = now_ms if now_ms is not None else time.time() * 1000
        if not is_num(now):
            return {"ok": False, "reason": "nowMs is not a finite number"}
        for c in ordered:
            if not x509_valid_at(c.raw, now):
                return {"ok": False, "reason": "PCK chain certificate outside its validity period", "failure": "validity"}
        for i in range(len(ordered) - 1):
            child, parent = ordered[i], ordered[i + 1]
            if child.issuer != parent.subject:
                return {"ok": False, "reason": "certificate at depth %d issuer does not match its parent subject" % i}
            if not child.verify(parent.public_key):
                return {"ok": False, "reason": "certificate at depth %d is not signed by its issuer" % i}
        if not root.verify(root.public_key):
            return {"ok": False, "reason": "root certificate is not self-signed"}
        pin = (trust_anchor if trust_anchor is not None else INTEL_SGX_ROOT_CA_SPKI_SHA256).lower()
        if spki_sha(root.public_key, "sha256") != pin:
            return {"ok": False, "reason": "Intel SGX Root CA does not match the pinned trust anchor"}
        role_fail = check_chain_roles([c.raw for c in ordered])
        if role_fail:
            return {"ok": False, "reason": role_fail}
        for i, c in enumerate(ordered):
            crit = unrecognised_critical_extension(c.raw)  # raises on a malformed table: fail closed below
            if crit:
                return {"ok": False, "reason": "PCK chain certificate at depth %d has an unrecognised critical extension %s" % (i, crit)}
        leaf_pk = leaf.public_key
        if key_type(leaf_pk) != "ec":
            return {"ok": False, "reason": "PCK leaf key is not EC (got %s)" % key_type(leaf_pk)}
        leaf_key = ec_key_from_point("P-256", ec_point(leaf_pk, "P-256"))
        return {"ok": True, "leafKey": leaf_key, "leafDer": leaf.raw, "leafCert": leaf, "depth": len(ordered)}
    except Exception as e:
        return {"ok": False, "reason": "PCK chain X.509 verification error (fail closed): %s" % e}


def _verify_p256(msg: bytes, sig_compact: bytes, key: Any) -> bool:
    try:
        return ecdsa_verify_raw(key, sig_compact, msg, "sha256")
    except Exception:
        return False


def verify_genuine_tdx_quote(
    quote: bytes,
    trust_anchor: Optional[str] = None,
    expected: Any = None,
    policy: Optional[Dict[str, Any]] = None,
    now_ms: Any = None,
) -> Dict[str, Any]:
    """A genuine DCAP v4 TDX quote end to end, offline (no PCS collateral). Fails closed with a reason."""
    try:
        try:
            q = parse_dcap_quote(quote)
        except ValueError as e:
            return {"ok": False, "reason": "quote parse failed: %s" % e}
        try:
            report = parse_dcap_td_report(q["tdReportBody"])
        except ValueError as e:
            return {"ok": False, "reason": "TD report parse failed: %s" % e}
        chain = verify_intel_pck_chain(q["pckChainPem"], trust_anchor, now_ms)
        if not chain["ok"] or "leafKey" not in chain or "leafDer" not in chain:
            return {"ok": False, "reason": "PCK chain invalid: %s" % (chain.get("reason") or "unknown")}
        try:
            pck_tcb = extract_pck_fmspc_and_tcb(chain["leafDer"])
        except ValueError as e:
            return {"ok": False, "reason": "PCK FMSPC/TCB extraction failed: %s" % e}
        if not _verify_p256(q["qeReportBody"], q["qeReportSignature"], chain["leafKey"]):
            return {"ok": False, "reason": "QE report signature does not verify under the PCK leaf"}
        # a debug QE can forge endorsements (SGX REPORT.ATTRIBUTES.FLAGS bit 1)
        if (q["qeReportBody"][_QE_ATTRIBUTES_OFF] & 0x02) != 0:
            return {"ok": False, "reason": "QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)"}
        qe_data = q["qeReportBody"][_QE_REPORT_DATA_OFF:_QE_REPORT_DATA_OFF + 64]
        ak_binding = hashlib.sha256(q["akPubRaw"] + q["qeAuthData"]).digest()
        if qe_data[:32] != ak_binding or any(qe_data[32:64]):
            return {"ok": False, "reason": "QE report_data does not bind the attestation key (AK not endorsed by this QE)"}
        try:
            ak_pub = ec_key_from_point("P-256", b"\x04" + q["akPubRaw"])
        except Exception:
            return {"ok": False, "reason": "attestation public key is not a valid P-256 point"}
        if not _verify_p256(q["header"] + q["tdReportBody"], q["quoteSignature"], ak_pub):
            return {"ok": False, "reason": "TD quote signature does not verify under the attestation key"}
        if expected is not None:
            try:
                expected_data = attestation_binding(expected)
            except TypeError as e:
                return {"ok": False, "reason": "binding not constructible: %s" % e}
            if expected_data != report["reportData"]:
                return {"ok": False, "reason": "report_data does not bind holder/grant/epoch/nonce"}
        pol = policy or {}
        if pol.get("allowDebug") is not True and (report["tdAttributes"][0] & 1) != 0:
            return {"ok": False, "reason": "TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)"}
        fmspc_hex = to_hex(pck_tcb["fmspc"])
        if policy is not None:
            def allowed(key: str, value: bytes, need_nonempty: bool) -> bool:
                lst = policy.get(key)
                if not isinstance(lst, list) or (need_nonempty and len(lst) == 0):
                    return True
                return to_hex(value) in [x.lower() for x in lst]

            if not allowed("mrtds", report["mrTd"], True):
                return {"ok": False, "reason": "MRTD not in policy allowlist"}
            if not allowed("fmspcs", pck_tcb["fmspc"], True):
                return {"ok": False, "reason": "FMSPC not in policy allowlist"}
            if not allowed("mrSeams", report["mrSeam"], False):
                return {"ok": False, "reason": "MRSEAM not in policy allowlist"}
            if not allowed("mrSignerSeams", report["mrSignerSeam"], False):
                return {"ok": False, "reason": "MRSIGNERSEAM not in policy allowlist"}
            if not allowed("rtmrs", report["rtmr0"], True):
                return {"ok": False, "reason": "RTMR0 not in policy allowlist"}
        measured = {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": to_hex(report["mrTd"]), "operator": ""}
        return {"ok": True, "report": report, "fmspc": fmspc_hex, "pckTcb": pck_tcb, "chainDepth": chain["depth"], "measured": measured}
    except Exception as e:
        return {"ok": False, "reason": "genuine TDX verification error (fail closed): %s" % e}


# ------------------------------------------------------------------------------------------------ collateral: CRL


class _Tlv:
    __slots__ = ("tag", "start", "end", "next")

    def __init__(self, tag: int, start: int, end: int) -> None:
        self.tag, self.start, self.end, self.next = tag, start, end, end


def _tlv(b: bytes, off: int, limit: Optional[int] = None) -> _Tlv:
    if limit is None:
        limit = len(b)
    if off + 2 > limit:
        raise ValueError("DER truncated")
    tag = b[off]
    ln = b[off + 1]
    p = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or p + n > limit:
            raise ValueError("DER bad length")
        ln = 0
        for i in range(n):
            ln = ln * 256 + b[p + i]
        p += n
    if p + ln > limit:
        raise ValueError("DER overrun")
    return _Tlv(tag, p, p + ln)


def _date_utc(y: int, mon0: int, d: int, h: int, mi: int, s: int) -> int:
    """Date.UTC: months and days roll over, years 0..99 mean 1900..1999."""
    if 0 <= y <= 99:
        y += 1900
    y += mon0 // 12
    mon0 = mon0 % 12
    days = days_from_civil(y, mon0 + 1, 1) + (d - 1)
    return (((days * 24 + h) * 60 + mi) * 60 + s) * 1000


def _der_time(b: bytes, t: _Tlv) -> int:
    s = bytes(b[t.start:t.end]).decode("ascii", "replace")
    if t.tag == 0x17:
        m = re.fullmatch(r"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z", s)
        if not m:
            raise ValueError("bad UTCTime")
        yy = int(m.group(1))
        return _date_utc(1900 + yy if yy >= 50 else 2000 + yy, int(m.group(2)) - 1, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))
    if t.tag == 0x18:
        m = re.fullmatch(r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z", s)
        if not m:
            raise ValueError("bad GeneralizedTime")
        return _date_utc(int(m.group(1)), int(m.group(2)) - 1, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))
    raise ValueError("not a DER time")


def norm_serial(hex_str: str) -> str:
    return hex_str.lower().lstrip("0")


def _parse_crl(der: bytes) -> Dict[str, Any]:
    outer = _tlv(der, 0)
    if outer.tag != 0x30 or outer.next != len(der):
        raise ValueError("CRL: bad outer SEQUENCE")
    tbs_t = _tlv(der, outer.start, outer.end)
    if tbs_t.tag != 0x30:
        raise ValueError("CRL: bad TBSCertList")
    tbs = bytes(der[outer.start:tbs_t.next])
    alg_t = _tlv(der, tbs_t.next, outer.end)
    sig_t = _tlv(der, alg_t.next, outer.end)
    if sig_t.tag != 0x03 or sig_t.next != outer.end:
        raise ValueError("CRL: bad signature")
    sig_der = bytes(der[sig_t.start + 1:sig_t.end])
    p = tbs_t.start
    t = _tlv(der, p, tbs_t.end)
    if t.tag == 0x02:
        p = t.next
        t = _tlv(der, p, tbs_t.end)
    p = t.next
    iss = _tlv(der, p, tbs_t.end)
    if iss.tag != 0x30:
        raise ValueError("CRL: bad issuer")
    tu = _tlv(der, iss.next, tbs_t.end)
    this_update = _der_time(der, tu)
    q = tu.next
    next_update: Optional[int] = None
    revoked: Set[str] = set()
    if q < tbs_t.end:
        n = _tlv(der, q, tbs_t.end)
        if n.tag in (0x17, 0x18):
            next_update = _der_time(der, n)
            q = n.next
        if q < tbs_t.end:
            n = _tlv(der, q, tbs_t.end)
            if n.tag == 0x30:
                e = n.start
                while e < n.end:
                    ent = _tlv(der, e, n.end)
                    ser = _tlv(der, ent.start, ent.end)
                    if ser.tag != 0x02:
                        raise ValueError("CRL: bad revoked entry")
                    revoked.add(norm_serial(bytes(der[ser.start:ser.end]).hex()))
                    e = ent.next
    if next_update is None:
        raise ValueError("CRL: missing nextUpdate")
    return {"tbs": tbs, "thisUpdate": this_update, "nextUpdate": next_update, "revoked": revoked, "sigDer": sig_der}


def verify_crl(crl_der: bytes, issuer_key: Any, now_ms: float) -> Dict[str, Any]:
    """A CRL (DER) under `issuer_key` at `now`: {ok, revoked} (lowercase hex serials, no leading zeros) or {ok: False, reason}."""
    try:
        crl = _parse_crl(bytes(crl_der))
    except ValueError as e:
        return {"ok": False, "reason": "CRL parse failed: %s" % e}
    kt = key_type(issuer_key)
    if kt == "ec":
        good = ecdsa_verify_der(issuer_key, crl["sigDer"], crl["tbs"], "sha256")
    elif kt == "rsa":
        good = rsa_pkcs1_verify(issuer_key, crl["sigDer"], crl["tbs"], "sha256")
    else:
        good = False
    if not good:
        return {"ok": False, "reason": "CRL signature does not verify under the issuer"}
    if now_ms < crl["thisUpdate"]:
        return {"ok": False, "reason": "CRL thisUpdate is in the future"}
    if now_ms > crl["nextUpdate"]:
        return {"ok": False, "reason": "CRL is stale (nextUpdate passed)"}
    return {"ok": True, "revoked": crl["revoked"]}


def serial_is_revoked(revoked: Set[str], serial_hex: str) -> bool:
    return norm_serial(serial_hex) in revoked


# ------------------------------------------------------------------------------------------------ collateral: signed JSON


def _signer_key_from_chain(chain_pem: str, pin: Optional[str], now_ms: float, root_revoked: Set[str]) -> Dict[str, Any]:
    chain = verify_intel_pck_chain(chain_pem, pin, now_ms)
    if chain.get("failure") == "validity":
        return {"error": "issuer chain certificate outside its validity period"}
    if not chain["ok"] or "leafDer" not in chain:
        return {"error": "issuer chain invalid: %s" % (chain.get("reason") or "unknown")}
    for b in pem_blocks(chain_pem):
        c = Cert.from_pem(b)
        if not x509_valid_at(c.raw, now_ms):
            return {"error": "issuer chain certificate outside its validity period"}
        if serial_is_revoked(root_revoked, c.serial_hex):
            return {"error": "issuer chain certificate is revoked by the Intel Root CA CRL"}
    return {"key": chain["leafCert"].public_key}


def _raw_json_object(text: str, name: str) -> Optional[str]:
    m = re.match(r'\s*\{\s*"%s"\s*:\s*' % re.escape(name), text)
    if not m:
        return None
    s = m.end()
    if s >= len(text) or text[s] != "{":
        return None
    depth = 0
    in_str = False
    i = s
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[s:i + 1]
        i += 1
    return None


def _verify_signed_json(text: str, name: str, key: Any) -> Dict[str, Any]:
    raw = _raw_json_object(text, name)
    if raw is None:
        return {"error": "%s not found / malformed" % name}
    try:
        doc = js_json_loads(text)
    except JsError:
        return {"error": "%s document is not valid JSON" % name}
    sig = doc.get("signature") if isinstance(doc, dict) else None
    if not isinstance(sig, str) or not re.fullmatch(r"[0-9a-fA-F]{128}", sig):
        return {"error": "%s signature missing or malformed" % name}
    if not ecdsa_verify_raw(key, bytes.fromhex(sig), raw.encode("utf-8"), "sha256"):
        return {"error": "%s signature does not verify under the TCB Signing certificate" % name}
    body = doc.get(name)
    if not isinstance(body, dict):
        return {"error": "%s is not an object" % name}
    return {"body": body}


_ISO = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?(Z|[+-][0-9]{2}:[0-9]{2})?)?"
)


def js_date_parse(s: str) -> Optional[int]:
    """Date.parse for the ISO 8601 forms Intel PCS emits (a zone-less date-time is read as UTC); None for anything else."""
    m = _ISO.fullmatch(s)
    if not m:
        return None
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    h = int(m.group(4) or 0)
    mi = int(m.group(5) or 0)
    sec = int(m.group(6) or 0)
    ms = int((m.group(7) or "0")[:3].ljust(3, "0"))
    if mo < 1 or mo > 12 or d < 1 or d > 31 or h > 24 or mi > 59 or sec > 59 or (h == 24 and (mi or sec or ms)):
        return None
    from .attest_der import days_in_month

    if d > days_in_month(y, mo):
        return None
    t = (((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60 + sec) * 1000 + ms
    tz = m.group(8)
    if tz and tz != "Z":
        off = (int(tz[1:3]) * 60 + int(tz[4:6])) * 60_000
        t -= off if tz[0] == "+" else -off
    return t


def _check_fresh(body: Dict[str, Any], what: str, now_ms: float) -> Optional[str]:
    issue = js_date_parse(body["issueDate"]) if isinstance(body.get("issueDate"), str) else None
    nxt = js_date_parse(body["nextUpdate"]) if isinstance(body.get("nextUpdate"), str) else None
    if issue is None or nxt is None:
        return "%s: issueDate/nextUpdate missing" % what
    if now_ms < issue:
        return "%s: issueDate is in the future" % what
    if now_ms > nxt:
        return "%s: stale (nextUpdate passed)" % what
    return None


# ------------------------------------------------------------------------------------------------ collateral: status evaluation


def _as_status(s: Any) -> Optional[str]:
    return s if isinstance(s, str) and s in STATUS_ORDER else None


def _worst(a: str, b: str) -> str:
    return a if STATUS_ORDER.index(a) >= STATUS_ORDER.index(b) else b


def _svns(comps: Any) -> Optional[List[float]]:
    if not isinstance(comps, list) or len(comps) != 16:
        return None
    out: List[float] = []
    for c in comps:
        if not isinstance(c, dict) or not is_num(c.get("svn")):
            return None
        out.append(c["svn"])
    return out


def _hex_bytes(s: Any, ln: int) -> Optional[bytes]:
    if not isinstance(s, str) or len(s) != ln * 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    return bytes.fromhex(s)


def _advisories(level: Dict[str, Any]) -> List[str]:
    a = level.get("advisoryIDs")
    return [x for x in a if isinstance(x, str)] if isinstance(a, list) else []


def _masked_eq(value: bytes, mask: bytes, expected: bytes) -> bool:
    for i in range(len(value)):
        if ((value[i] & mask[i]) ^ (expected[i] & mask[i])) != 0:
            return False
    return True


def _evaluate_tcb(info: Dict[str, Any], pck: Dict[str, Any], td: Dict[str, bytes]) -> Dict[str, Any]:
    levels = info.get("tcbLevels")
    if not isinstance(levels, list) or len(levels) == 0:
        return {"error": "TCB info has no tcbLevels"}
    minor = td["teeTcbSvn"][1]
    module_status = "UpToDate"
    adv: Set[str] = set()
    if minor > 0:
        ident_id = "TDX_%02X" % minor
        ids = info.get("tdxModuleIdentities")
        ident = None
        if isinstance(ids, list):
            ident = next((x for x in ids if isinstance(x, dict) and x.get("id") == ident_id), None)
        if ident is None:
            return {"error": "TDX module identity %s not present in TCB info" % ident_id}
        mod_mr_signer, mod_attr, mod_mask = ident.get("mrsigner"), ident.get("attributes"), ident.get("attributesMask")
        lv = ident.get("tcbLevels") if isinstance(ident.get("tcbLevels"), list) else []
        hit = next(
            (
                l
                for l in lv
                if isinstance(l, dict) and isinstance(l.get("tcb"), dict) and is_num(l["tcb"].get("isvsvn")) and l["tcb"]["isvsvn"] <= td["teeTcbSvn"][0]
            ),
            None,
        )
        if hit is None:
            return {"error": "TDX module %s SVN %d is below every known level" % (ident_id, td["teeTcbSvn"][0])}
        st = _as_status(hit.get("tcbStatus"))
        if st is None:
            return {"error": "TDX module level has an unknown tcbStatus"}
        module_status = st
        for a in _advisories(hit):
            adv.add(a)
    else:
        m = info.get("tdxModule")
        if not isinstance(m, dict):
            return {"error": "TCB info missing tdxModule"}
        mod_mr_signer, mod_attr, mod_mask = m.get("mrsigner"), m.get("attributes"), m.get("attributesMask")
    ex_mr, ex_attr, mask = _hex_bytes(mod_mr_signer, 48), _hex_bytes(mod_attr, 8), _hex_bytes(mod_mask, 8)
    if ex_mr is None or ex_attr is None or mask is None:
        return {"error": "TDX module identity fields malformed"}
    if ex_mr != td["mrSignerSeam"]:
        return {"error": "TD report MRSIGNERSEAM does not match the TDX module identity"}
    if not _masked_eq(td["seamAttributes"], mask, ex_attr):
        return {"error": "TD report SEAM attributes do not match the TDX module identity"}
    start = 2 if minor > 0 else 0
    for l in levels:
        if not isinstance(l, dict) or not isinstance(l.get("tcb"), dict):
            return {"error": "malformed TCB level"}
        sgx = _svns(l["tcb"].get("sgxtcbcomponents"))
        tdx = _svns(l["tcb"].get("tdxtcbcomponents"))
        if sgx is None or tdx is None or not is_num(l["tcb"].get("pcesvn")):
            return {"error": "malformed TCB level components"}
        st = _as_status(l.get("tcbStatus"))
        if st is None:
            return {"error": "TCB level has an unknown tcbStatus"}
        match = pck["pcesvn"] >= l["tcb"]["pcesvn"]
        i = 0
        while match and i < 16:
            if pck["sgx"][i] < sgx[i]:
                match = False
            i += 1
        i = start
        while match and i < 16:
            if td["teeTcbSvn"][i] < tdx[i]:
                match = False
            i += 1
        if not match:
            continue
        for a in _advisories(l):
            adv.add(a)
        return {"platform": st, "module": module_status, "advisories": sorted(adv)}
    return {"error": "platform TCB is below every level in the TCB info"}


def _evaluate_qe(ident: Dict[str, Any], qe: bytes) -> Dict[str, Any]:
    if ident.get("id") != "TD_QE":
        return {"error": "QE identity id is not TD_QE"}
    if not is_num(ident.get("version")) or ident.get("version") != 2:
        return {"error": "unsupported QE identity version"}
    miscsel = _hex_bytes(ident.get("miscselect"), 4)
    misc_mask = _hex_bytes(ident.get("miscselectMask"), 4)
    attr = _hex_bytes(ident.get("attributes"), 16)
    attr_mask = _hex_bytes(ident.get("attributesMask"), 16)
    mrsigner = _hex_bytes(ident.get("mrsigner"), 32)
    if miscsel is None or misc_mask is None or attr is None or attr_mask is None or mrsigner is None or not is_num(ident.get("isvprodid")):
        return {"error": "QE identity fields malformed"}
    if len(qe) != 384:
        return {"error": "QE report has wrong length"}
    if not _masked_eq(qe[16:20], misc_mask, miscsel):
        return {"error": "QE MISCSELECT does not match the QE identity"}
    if not _masked_eq(qe[48:64], attr_mask, attr):
        return {"error": "QE ATTRIBUTES do not match the QE identity"}
    if qe[128:160] != mrsigner:
        return {"error": "QE MRSIGNER does not match the QE identity"}
    prod = qe[256] | (qe[257] << 8)
    isvsvn = qe[258] | (qe[259] << 8)
    if prod != ident["isvprodid"]:
        return {"error": "QE ISVPRODID does not match the QE identity"}
    lv = ident.get("tcbLevels") if isinstance(ident.get("tcbLevels"), list) else []
    hit = next((l for l in lv if isinstance(l, dict) and isinstance(l.get("tcb"), dict) and is_num(l["tcb"].get("isvsvn")) and l["tcb"]["isvsvn"] <= isvsvn), None)
    if hit is None:
        return {"error": "QE ISVSVN is below every known level"}
    st = _as_status(hit.get("tcbStatus"))
    if st is None:
        return {"error": "QE level has an unknown tcbStatus"}
    return {"status": st, "advisories": _advisories(hit)}


def verify_intel_tdx_collateral(
    quote: bytes,
    collateral: Dict[str, Any],
    now_ms: float,
    policy: Optional[Dict[str, Any]] = None,
    trust_anchor: Optional[str] = None,
    allow_debug: bool = False,
) -> Dict[str, Any]:
    """The quote, then its Intel PCS collateral (TCB info, QE identity, CRLs) at `now`: the evaluated TCB status and the policy decision."""

    def fail(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}

    try:
        c = collateral
        if (
            not c
            or not c.get("tcbInfoJson")
            or not c.get("qeIdentityJson")
            or not c.get("pckCrlDer")
            or not c.get("rootCrlDer")
            or not c.get("tcbInfoIssuerChainPem")
            or not c.get("qeIdentityIssuerChainPem")
        ):
            return fail("collateral incomplete (fail closed)")
        pin = trust_anchor
        base = verify_genuine_tdx_quote(quote, pin, None, {"allowDebug": True} if allow_debug is True else None, now_ms)
        if not base["ok"] or "pckTcb" not in base or not base.get("fmspc"):
            return fail("quote invalid: %s" % (base.get("reason") or "unknown"))
        q = parse_dcap_quote(quote)
        quote_certs = [Cert.from_pem(b) for b in pem_blocks(q["pckChainPem"])]
        for x in quote_certs:
            if not x509_valid_at(x.raw, now_ms):
                return fail("PCK chain certificate outside its validity period")
        leaf = next((x for x in quote_certs if not any(y.issuer == x.subject for y in quote_certs)), None)
        if leaf is None:
            return fail("PCK leaf not found")
        ca = next((x for x in quote_certs if x.subject == leaf.issuer), None)
        if ca is None:
            return fail("PCK CA not found in the quote chain")
        root = next((x for x in quote_certs if x.subject == x.issuer), None)
        if root is None:
            return fail("Intel root not found in the quote chain")
        root_crl = verify_crl(c["rootCrlDer"], root.public_key, now_ms)
        if not root_crl["ok"]:
            return fail("Intel Root CA CRL: %s" % root_crl["reason"])
        pck_crl = verify_crl(c["pckCrlDer"], ca.public_key, now_ms)
        if not pck_crl["ok"]:
            return fail("PCK CRL: %s" % pck_crl["reason"])
        if serial_is_revoked(root_crl["revoked"], ca.serial_hex):
            return fail("PCK CA certificate is revoked by the Intel Root CA CRL")
        if serial_is_revoked(pck_crl["revoked"], leaf.serial_hex):
            return fail("PCK leaf certificate is revoked by the PCK CRL")

        tcb_key = _signer_key_from_chain(c["tcbInfoIssuerChainPem"], pin, now_ms, root_crl["revoked"])
        if "error" in tcb_key:
            return fail("TCB info: %s" % tcb_key["error"])
        tcb_doc = _verify_signed_json(_text(c["tcbInfoJson"]), "tcbInfo", tcb_key["key"])
        if "error" in tcb_doc:
            return fail("TCB info: %s" % tcb_doc["error"])
        info = tcb_doc["body"]
        stale = _check_fresh(info, "TCB info", now_ms)
        if stale:
            return fail(stale)
        if info.get("id") != "TDX" or not is_num(info.get("version")) or info.get("version") != 3:
            return fail("TCB info is not a TDX v3 document")
        if not isinstance(info.get("fmspc"), str) or info["fmspc"].lower() != base["fmspc"]:
            return fail("TCB info FMSPC does not match the quote PCK")

        qe_key = _signer_key_from_chain(c["qeIdentityIssuerChainPem"], pin, now_ms, root_crl["revoked"])
        if "error" in qe_key:
            return fail("QE identity: %s" % qe_key["error"])
        qe_doc = _verify_signed_json(_text(c["qeIdentityJson"]), "enclaveIdentity", qe_key["key"])
        if "error" in qe_doc:
            return fail("QE identity: %s" % qe_doc["error"])
        stale_qe = _check_fresh(qe_doc["body"], "QE identity", now_ms)
        if stale_qe:
            return fail(stale_qe)

        min_eval = (policy or {}).get("minTcbEvaluationDataNumber")
        info_num = info["tcbEvaluationDataNumber"] if is_num(info.get("tcbEvaluationDataNumber")) else -1
        qe_num = qe_doc["body"]["tcbEvaluationDataNumber"] if is_num(qe_doc["body"].get("tcbEvaluationDataNumber")) else -1
        if info_num < 0 or qe_num < 0:
            return fail("tcbEvaluationDataNumber missing")
        if min_eval is not None and (info_num < min_eval or qe_num < min_eval):
            return fail("tcbEvaluationDataNumber below policy minimum")

        body = q["tdReportBody"]
        td = {"teeTcbSvn": body[0:16], "mrSignerSeam": body[64:112], "seamAttributes": body[112:120]}
        pck = extract_pck_fmspc_and_tcb(leaf.raw)
        tcb = _evaluate_tcb(info, {"sgx": pck["sgxTcbComponents"], "pcesvn": pck["pcesvn"]}, td)
        if "error" in tcb:
            return fail("TCB evaluation: %s" % tcb["error"])
        qe = _evaluate_qe(qe_doc["body"], q["qeReportBody"])
        if "error" in qe:
            return fail("QE identity: %s" % qe["error"])

        status = _worst(_worst(tcb["platform"], tcb["module"]), qe["status"])
        advisory_ids = sorted(set(tcb["advisories"]) | set(qe["advisories"]))
        result = {"ok": False, "status": status, "advisoryIds": advisory_ids}
        accepted = (policy or {}).get("acceptStatuses")
        if accepted is None:
            accepted = DEFAULT_ACCEPTED_STATUSES
        if status not in accepted:
            result["reason"] = "TCB status %s is not accepted by policy" % status
            return result
        result["ok"] = True
        return result
    except Exception as e:
        return fail("collateral verification error (fail closed): %s" % e)


def _text(x: Any) -> str:
    return bytes(x).decode("utf-8", "replace") if isinstance(x, (bytes, bytearray)) else x


# ------------------------------------------------------------------------------------------------ the verifier


class IntelDcapVerifier:
    """`verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}."""

    def __init__(self, opts: Dict[str, Any]) -> None:
        if opts.get("binding") not in ("report-data", "azure-runtime-data"):
            raise AttestConstructError("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'")
        self._binding = opts["binding"]
        pol = opts.get("policy")
        pol = pol if isinstance(pol, dict) else {}
        mrtds_in = pol.get("mrtds")
        if not isinstance(mrtds_in, list) or len(mrtds_in) == 0:
            raise AttestConstructError("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)")
        mrtds = [m.lower() for m in mrtds_in]
        if any(not re.fullmatch(r"[0-9a-f]+", m) or len(m) != 96 for m in mrtds):
            raise AttestConstructError("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)")
        for name in ("mrSeams", "mrSignerSeams"):
            if name not in pol:
                continue
            lst = pol[name]
            if not isinstance(lst, list) or len(lst) == 0:
                raise AttestConstructError("createIntelDcapVerifier: policy.%s, if given, must be a NON-EMPTY list" % name)
            if any(not isinstance(m, str) or not re.fullmatch(r"[0-9a-fA-F]+", m) or len(m) != 96 for m in lst):
                raise AttestConstructError("createIntelDcapVerifier: every %s entry must be 96 hex chars (48 bytes)" % name)
        anchor = opts.get("trustAnchorRootCaSpkiSha256")
        self._pin = (anchor if anchor is not None else INTEL_SGX_ROOT_CA_SPKI_SHA256).lower()
        self._policy = pol
        self._mrtds = mrtds
        self._allow_missing = opts.get("allowMissingCollateral") is True
        self._resolve = opts.get("resolve_evidence")

    def verify(self, document: Any, expected: Any, now_ms: Any) -> Dict[str, Any]:
        def fail(reason: str) -> Dict[str, Any]:
            return {"ok": False, "reason": reason}

        try:
            if self._resolve is None:
                return fail("no Intel DCAP evidence resolver configured (fail closed)")
            ev = self._resolve(document)
            if not isinstance(ev, dict) or not isinstance(ev.get("quote"), (bytes, bytearray)):
                return fail("no Intel DCAP quote for this action")
            if expected is None:
                return fail("no expected attestation binding supplied")
            pol = self._policy
            gp: Dict[str, Any] = {"mrtds": self._mrtds}
            for k in ("mrSeams", "mrSignerSeams", "fmspcs", "rtmrs"):
                if pol.get(k):
                    gp[k] = pol[k]
            if pol.get("allowDebug") is True:
                gp["allowDebug"] = True
            quote = bytes(ev["quote"])
            q = verify_genuine_tdx_quote(quote, self._pin, None, gp, now_ms)
            if not q["ok"] or "report" not in q or "measured" not in q or not q.get("fmspc"):
                return fail("DCAP quote invalid: %s" % (q.get("reason") or "unknown"))
            if self._binding == "report-data":
                try:
                    want = attestation_binding(expected)
                except TypeError as e:
                    return fail("binding not constructible: %s" % e)
                if q["report"]["reportData"] != want:
                    return fail("report_data does not bind holder/grant/epoch/nonce")
            else:
                rd = ev.get("runtimeData")
                if not isinstance(rd, (bytes, bytearray)):
                    return fail("azure-runtime-data binding needs the runtime-data JSON bytes")
                why = check_azure_runtime_data_binding(q["report"]["reportData"], bytes(rd), expected)
                if why:
                    return fail(why)
            host: Dict[str, str] = {"attestation_type": "tdx-dcap", "fmspc": q["fmspc"]}
            col = ev.get("collateral")
            if col:
                c = verify_intel_tdx_collateral(quote, col, now_ms, pol.get("collateral") or None, self._pin, pol.get("allowDebug") is True)
                if c.get("status"):
                    host["tcb_status"] = c["status"]
                if c.get("advisoryIds"):
                    host["advisory_ids"] = ",".join(c["advisoryIds"])
                if not c["ok"]:
                    return fail("Intel collateral: %s" % (c.get("reason") or "rejected"))
            elif self._allow_missing:
                host["tcb_status"] = "unevaluated"
            else:
                return fail("Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)")
            return {"ok": True, "bound": True, "measured": q["measured"], "hostAsserted": host}
        except Exception as e:
            return fail("intel-dcap verification error (fail closed): %s" % e)
