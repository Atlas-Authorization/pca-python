"""NVIDIA device-chain revocation through OCSP (RFC 6960), native counterpart of `checkNvidiaChainOcsp`.

Verifies, offline, the DER OCSPResponses a caller obtained: responseStatus SUCCESSFUL with id-pkix-ocsp-basic, the CertID
(serial + issuer name / key hashes), the BasicOCSPResponse signature under the issuing CA or a delegated responder certificate
(signed by the supplied chain, inside its validity window, with the id-kp-OCSPSigning EKU), freshness, and the certStatus.
Fails closed; the reason strings are those of the reference implementation.
"""
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from .attest_cert import Cert
from .attest_common import ecdsa_verify_der, key_type, rsa_pkcs1_verify
from .attest_der import DerError, Tlv, _oid_to_dotted, _tlv_at, days_from_civil, der_validity_ms, read_tlv

OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"
OID_AIA = "1.3.6.1.5.5.7.1.1"
OID_AD_OCSP = "1.3.6.1.5.5.7.48.1"
OID_EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
OID_EKU = "2.5.29.37"

_HASHES = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
_SIG_ALGS = {
    "1.2.840.10045.4.3.2": ("sha256", "ec"),
    "1.2.840.10045.4.3.3": ("sha384", "ec"),
    "1.2.840.10045.4.3.4": ("sha512", "ec"),
    "1.2.840.113549.1.1.11": ("sha256", "rsa"),
    "1.2.840.113549.1.1.12": ("sha384", "rsa"),
    "1.2.840.113549.1.1.13": ("sha512", "rsa"),
}
NVIDIA_OCSP_DEFAULT_MAX_AGE_MS = 7 * 24 * 3600 * 1000

_GEN_TIME = re.compile(r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]*[1-9]))?Z")
_UTC_TIME = re.compile(r"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")


class OcspError(ValueError):
    pass


def _time_in_range(text: str, utc: bool) -> bool:
    m = (_UTC_TIME if utc else _GEN_TIME).fullmatch(text)
    if not m:
        return False
    y = int(m.group(1))
    if utc:
        y += 2000 if y < 50 else 1900
    mo, d, h, mi, se = int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6))
    if mo < 1 or mo > 12 or d < 1 or h > 23 or mi > 59 or se > 59:
        return False
    from .attest_der import days_in_month

    return d <= days_in_month(y, mo)


def _all_times_well_formed(der: bytes, start: int, end: int) -> bool:
    """Every UTCTime / GeneralizedTime anywhere in the (constructed) structure is a well-formed, in-range DER time."""
    p = start
    while p < end:
        t = _tlv_at(der, p)
        if t.end > end:
            raise OcspError("element overruns its parent")
        if (t.tag & 0xC0) == 0 and (t.tag & 0x1F) in (23, 24) and (t.tag & 0x20) == 0:
            if not _time_in_range(bytes(der[t.start:t.end]).decode("latin-1"), (t.tag & 0x1F) == 23):
                return False
        elif t.tag & 0x20:
            if not _all_times_well_formed(der, t.start, t.end):
                return False
        p = t.end
    return True


def _gen_time_ms(text: str) -> int:
    m = _GEN_TIME.fullmatch(text)
    if m:
        y = int(m.group(1))
        ms = int((m.group(7) or "0")[:3].ljust(3, "0"))
    else:
        m = _UTC_TIME.fullmatch(text)
        if not m:
            raise OcspError("response times are not parseable")
        y = int(m.group(1))
        y += 2000 if y < 50 else 1900
        ms = 0
    mo, d, h, mi, se = int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6))
    return (((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60 + se) * 1000 + ms


def _children(der: bytes, t: Tlv) -> List[Tuple[Tlv, int]]:
    """The child TLVs of a constructed element, each with the offset of its header."""
    out: List[Tuple[Tlv, int]] = []
    p = t.start
    while p < t.end:
        c = _tlv_at(der, p)
        if c.end > t.end:
            raise OcspError("element overruns its parent")
        out.append((c, p))
        p = c.end
    return out


def _strip_zeros(b: bytes) -> bytes:
    i = 0
    while i < len(b) - 1 and b[i] == 0:
        i += 1
    return b[i:]


def _spki_key_bits(spki_der: bytes) -> bytes:
    seq = _tlv_at(spki_der, 0)
    kids = _children(spki_der, seq)
    if len(kids) < 2 or kids[1][0].tag != 0x03:
        raise OcspError("malformed SubjectPublicKeyInfo")
    t = kids[1][0]
    return bytes(spki_der[t.start + 1:t.end])


def _verify_sig(alg_oid: str, tbs: bytes, sig: bytes, key: Any) -> bool:
    a = _SIG_ALGS.get(alg_oid)
    if a is None:
        return False
    hname, kind = a
    t = key_type(key)
    if (kind == "ec") != (t == "ec"):
        return False
    if kind == "rsa" and t != "rsa":
        return False
    try:
        return ecdsa_verify_der(key, sig, tbs, hname) if kind == "ec" else rsa_pkcs1_verify(key, sig, tbs, hname)
    except Exception:
        return False


def _cert_id_hashes(issuer: Cert, hname: str) -> Tuple[bytes, bytes]:
    return hashlib.new(hname, issuer.subject_der).digest(), hashlib.new(hname, _spki_key_bits(issuer.spki_der)).digest()


def _eku_of(cert: Cert) -> Optional[List[str]]:
    ext = cert.extensions().get(OID_EKU)
    if ext is None:
        return None
    try:
        seq = read_tlv(ext.value, 0)
        if seq.tag != 0x30:
            return None
        out: List[str] = []
        p = seq.start
        while p < seq.end:
            o = read_tlv(ext.value, p, seq.end)
            out.append(_oid_to_dotted(ext.value, o))
            p = o.end
        return out
    except DerError:
        return None


def _fail(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason}


def verify_ocsp_response(response_der: bytes, cert: Cert, issuer: Cert, chain: List[Cert], now_ms: float, max_age_ms: Optional[float] = None, clock_skew_ms: float = 0) -> Dict[str, Any]:
    """One DER OCSPResponse for `cert`. Never raises; any malformation is {ok: False}."""
    try:
        return _verify_inner(bytes(response_der), cert, issuer, chain, now_ms, max_age_ms, clock_skew_ms)
    except Exception as e:
        return _fail("OCSP response rejected: %s" % e)


def _verify_inner(der: bytes, cert: Cert, issuer: Cert, chain: List[Cert], now_ms: float, max_age_ms: Optional[float], skew: float) -> Dict[str, Any]:
    max_age = NVIDIA_OCSP_DEFAULT_MAX_AGE_MS if max_age_ms is None else max_age_ms
    try:
        top = _tlv_at(der, 0)
    except DerError:
        return _fail("response is not valid DER")
    if top.end != len(der):
        return _fail("trailing bytes after OCSPResponse")
    if top.tag != 0x30:
        raise OcspError("OCSPResponse is not a SEQUENCE")
    kids = _children(der, top)
    if len(kids) < 1 or kids[0][0].tag != 0x0A:
        raise OcspError("responseStatus is not an ENUMERATED")
    status = int.from_bytes(der[kids[0][0].start:kids[0][0].end], "big")
    if status != 0:
        return _fail("OCSP responseStatus is %d (not successful)" % status)
    if len(kids) < 2 or kids[1][0].tag != 0xA0:
        return _fail("successful response carries no responseBytes")
    rb = _children(der, kids[1][0])
    if len(rb) < 1 or rb[0][0].tag != 0x30:
        raise OcspError("responseBytes is not a SEQUENCE")
    rbk = _children(der, rb[0][0])
    if len(rbk) < 2 or rbk[0][0].tag != 0x06 or rbk[1][0].tag != 0x04:
        raise OcspError("responseBytes is malformed")
    if _oid_to_dotted(der, rbk[0][0]) != OID_OCSP_BASIC:
        return _fail("responseType is not id-pkix-ocsp-basic")
    basic = bytes(der[rbk[1][0].start:rbk[1][0].end])
    try:
        btop = _tlv_at(basic, 0)
    except DerError:
        return _fail("BasicOCSPResponse is not valid DER")
    if btop.tag != 0x30:
        raise OcspError("BasicOCSPResponse is not a SEQUENCE")
    bk = _children(basic, btop)
    if len(bk) < 3 or bk[0][0].tag != 0x30 or bk[1][0].tag != 0x30 or bk[2][0].tag != 0x03:
        raise OcspError("BasicOCSPResponse is malformed")
    if not _all_times_well_formed(basic, btop.start, btop.end):
        return _fail("response carries a malformed (out-of-range) ASN.1 time")
    tbs_t, tbs_off = bk[0]
    tbs_bytes = bytes(basic[tbs_off:tbs_t.end])
    if len(tbs_bytes) == 0:
        return _fail("missing tbsResponseData")
    sig_alg_t = bk[1][0]
    sig_alg_oid = _oid_to_dotted(basic, _tlv_at(basic, sig_alg_t.start))
    if sig_alg_oid not in _SIG_ALGS:
        return _fail("unsupported OCSP signature algorithm %s" % sig_alg_oid)
    sig = bytes(basic[bk[2][0].start + 1:bk[2][0].end])

    # ResponseData
    rd = _children(basic, tbs_t)
    idx = 0
    if idx < len(rd) and rd[idx][0].tag == 0xA0:
        idx += 1  # version
    if idx >= len(rd) or rd[idx][0].tag not in (0xA1, 0xA2):
        raise OcspError("responderID is malformed")
    rid_t = rd[idx][0]
    idx += 1
    if idx >= len(rd) or rd[idx][0].tag != 0x18:
        raise OcspError("producedAt is malformed")
    produced_at = _gen_time_ms(bytes(basic[rd[idx][0].start:rd[idx][0].end]).decode("latin-1"))
    idx += 1
    if idx >= len(rd) or rd[idx][0].tag != 0x30:
        raise OcspError("responses is malformed")
    responses_t = rd[idx][0]
    idx += 1

    # CertID match
    matches: List[Tuple[Tlv, int]] = []
    for single_t, single_off in _children(basic, responses_t):
        sk = _children(basic, single_t)
        if len(sk) < 3 or sk[0][0].tag != 0x30:
            raise OcspError("SingleResponse is malformed")
        cid = _children(basic, sk[0][0])
        if len(cid) < 4:
            raise OcspError("CertID is malformed")
        alg = _tlv_at(basic, cid[0][0].start)
        hname = _HASHES.get(_oid_to_dotted(basic, alg))
        if hname is None:
            continue
        want_name, want_key = _cert_id_hashes(issuer, hname)
        if (
            _strip_zeros(bytes(basic[cid[3][0].start:cid[3][0].end])) == _strip_zeros(cert.serial)
            and bytes(basic[cid[1][0].start:cid[1][0].end]) == want_name
            and bytes(basic[cid[2][0].start:cid[2][0].end]) == want_key
        ):
            matches.append((single_t, single_off))
    if len(matches) == 0:
        return _fail("no SingleResponse matches the certificate (serial / issuer hashes differ)")
    if len(matches) > 1:
        return _fail("ambiguous: multiple SingleResponses match the certificate")
    single_t, _single_off = matches[0]
    sk = _children(basic, single_t)

    def rid_matches(c: Cert) -> bool:
        if rid_t.tag == 0xA1:  # byName
            inner = _children(basic, rid_t)
            return len(inner) == 1 and bytes(basic[inner[0][1]:inner[0][0].end]) == c.subject_der
        oct_t = _tlv_at(basic, rid_t.start)  # byKey [2] EXPLICIT OCTET STRING
        return oct_t.tag == 0x04 and bytes(basic[oct_t.start:oct_t.end]) == hashlib.sha1(_spki_key_bits(c.spki_der)).digest()

    issuer_pub = issuer.public_key
    responder = "issuer"
    is_issuer_id = rid_matches(issuer)
    issuer_ok = is_issuer_id and _verify_sig(sig_alg_oid, tbs_bytes, sig, issuer_pub)
    if not issuer_ok:
        embedded: List[Cert] = []
        if len(bk) > 3 and bk[3][0].tag == 0xA0:
            for st, _soff in _children(basic, bk[3][0]):
                for ct, coff in _children(basic, st):
                    embedded.append(Cert(bytes(basic[coff:ct.end])))
        found = False
        why = "no embedded responder certificate verifies the response"
        for cand in embedded:
            if not rid_matches(cand):
                why = "embedded certificates do not match the responderID"
                continue
            eku = _eku_of(cand)
            if eku is None or OID_EKU_OCSP_SIGNING not in eku:
                why = "delegated responder certificate lacks the id-kp-OCSPSigning EKU"
                continue
            nb, na = der_validity_ms(cand.raw)
            if nb is None or na is None or not (nb - skew <= now_ms and now_ms <= na):
                why = "delegated responder certificate is outside its validity window"
                continue
            issuer_idx = next((i for i, c in enumerate(chain) if c.raw == issuer.raw), -1)
            signers = chain[issuer_idx:] if issuer_idx >= 0 else [issuer]
            if not any(cand.check_issued(s) and cand.verify(s.public_key) for s in signers):
                why = "delegated responder certificate is not signed by the supplied NVIDIA chain"
                continue
            if not _verify_sig(sig_alg_oid, tbs_bytes, sig, cand.public_key):
                why = "OCSP response signature does not verify under the delegated responder key"
                continue
            found = True
            break
        if not found:
            return _fail("OCSP response signature does not verify under the issuer key" if is_issuer_id else why)
        responder = "delegated"

    # freshness
    # certStatus is sk[1]; thisUpdate follows it
    status_t = sk[1][0]
    time_t = sk[2][0]
    if time_t.tag != 0x18:
        raise OcspError("thisUpdate is malformed")
    this_update = _gen_time_ms(bytes(basic[time_t.start:time_t.end]).decode("latin-1"))
    next_update: Optional[int] = None
    if len(sk) > 3 and sk[3][0].tag == 0xA0:
        inner = _children(basic, sk[3][0])
        if len(inner) < 1 or inner[0][0].tag != 0x18:
            raise OcspError("nextUpdate is malformed")
        next_update = _gen_time_ms(bytes(basic[inner[0][0].start:inner[0][0].end]).decode("latin-1"))
    if this_update > now_ms + skew:
        return _fail("response thisUpdate is in the future")
    if produced_at > now_ms + skew:
        return _fail("response producedAt is in the future")
    if next_update is not None:
        if next_update < this_update:
            return _fail("response nextUpdate is invalid")
        if now_ms > next_update:
            return _fail("response is stale (past nextUpdate)")
    if now_ms - this_update > max_age:
        return _fail("response is older than the maximum accepted age")

    if (status_t.tag & 0xC0) != 0x80:  # not a context-specific tag
        return _fail("malformed certStatus")
    num = status_t.tag & 0x1F
    if num == 0:
        return {"ok": True, "status": "good", "responder": responder}
    if num == 2:
        return {"ok": True, "status": "unknown", "responder": responder}
    if num == 1:
        kids2 = _children(basic, status_t)
        if len(kids2) < 1:
            return _fail("malformed revoked certStatus")
        txt = bytes(basic[kids2[0][0].start:kids2[0][0].end]).decode("latin-1")
        if not re.fullmatch(r"[0-9]{14}Z", txt):
            return _fail("malformed revoked certStatus")
        return {"ok": True, "status": "revoked", "responder": responder}
    return _fail("unrecognised certStatus")


def cert_ocsp_urls(cert: Cert) -> List[str]:
    """OCSP responder URLs advertised in the Authority Information Access extension."""
    ext = cert.extensions().get(OID_AIA)
    if ext is None:
        return []
    try:
        seq = read_tlv(ext.value, 0)
        if seq.tag != 0x30:
            return []
        out: List[str] = []
        p = seq.start
        while p < seq.end:
            ad = read_tlv(ext.value, p, seq.end)
            p = ad.end
            oid_t = read_tlv(ext.value, ad.start, ad.end)
            loc = read_tlv(ext.value, oid_t.end, ad.end)
            if _oid_to_dotted(ext.value, oid_t) == OID_AD_OCSP and loc.tag == 0x86:
                out.append(bytes(ext.value[loc.start:loc.end]).decode("latin-1"))
        return out
    except DerError:
        return []


def _subj(c: Cert) -> str:
    return c.subject.replace("\n", ", ")


def check_nvidia_chain_ocsp(chain: List[Cert], responses: List[bytes], now_ms: float, max_age_ms: Optional[float] = None) -> Dict[str, Any]:
    """The device chain against OCSP responses. Every response must verify for exactly one chain certificate; any REVOKED fails;
    each certificate that advertises an OCSP URL must have a GOOD response."""
    if len(chain) < 2:
        return {"ok": False, "reason": "chain too short for OCSP"}
    if len(responses) == 0:
        return {"ok": False, "reason": "no OCSP responses supplied"}
    last = len(chain) - 1
    required = set(i for i in range(last) if len(cert_ocsp_urls(chain[i])) > 0)
    statuses: Dict[int, str] = {i: "absent" for i in range(last)}
    verified = 0
    for ri, der in enumerate(responses):
        matched = False
        last_reason = "matches no chain certificate"
        for i in range(last):
            r = verify_ocsp_response(der, chain[i], chain[i + 1], chain, now_ms, max_age_ms)
            if not r["ok"]:
                if not r["reason"].startswith("no SingleResponse matches"):
                    return {"ok": False, "reason": "OCSP response #%d for '%s' rejected: %s" % (ri, _subj(chain[i]), r["reason"]), "statuses": statuses}
                last_reason = r["reason"]
                continue
            if matched:
                return {"ok": False, "reason": "OCSP response #%d matches more than one chain certificate" % ri, "statuses": statuses}
            matched = True
            if statuses[i] != "absent":
                return {"ok": False, "reason": "duplicate OCSP responses for chain certificate #%d" % i, "statuses": statuses}
            statuses[i] = r["status"]
            verified += 1
            if r["status"] == "revoked":
                return {"ok": False, "reason": "chain certificate '%s' is revoked (OCSP)" % _subj(chain[i]), "statuses": statuses}
        if not matched:
            return {"ok": False, "reason": "OCSP response #%d rejected: %s" % (ri, last_reason), "statuses": statuses}
    for i in sorted(required):
        if statuses[i] != "good":
            return {"ok": False, "reason": "no GOOD OCSP response for required certificate '%s' (status: %s)" % (_subj(chain[i]), statuses[i]), "statuses": statuses}
    return {"ok": True, "verifiedCrls": 0, "verifiedOcsp": verified, "statuses": statuses}
