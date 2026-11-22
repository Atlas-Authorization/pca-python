"""NVIDIA device-chain revocation through OCSP (RFC 6960), native counterpart of `checkNvidiaChainOcsp`.

Verifies, offline, the DER OCSPResponses a caller obtained: responseStatus SUCCESSFUL with id-pkix-ocsp-basic, the CertID
(serial + issuer name / key hashes), the BasicOCSPResponse signature under the issuing CA or a delegated responder certificate
(signed by the supplied chain, inside its validity window, with the id-kp-OCSPSigning EKU), freshness, and the certStatus.
Fails closed; the reason strings are those of the reference implementation.
"""
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from ._fin import fin
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
NVIDIA_OCSP_URL = "http://ocsp.ndis.nvidia.com/"
OID_OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2"

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
        if y <= 99:  # asn1js and Date.UTC read years 0..99 as 1900..1999
            y += 1900
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


class _A1:
    """A node of the tree the reference's ASN.1 reader builds: the identifier octets, and either the child nodes or the content."""

    __slots__ = ("ident", "constructed", "kids", "content")

    def __init__(self, ident: bytes, constructed: bool, kids: Optional[List["_A1"]], content: bytes) -> None:
        self.ident, self.constructed, self.kids, self.content = ident, constructed, kids, content


def _a1_parse(buf: bytes, off: int, in_len: int) -> Optional[Tuple[_A1, int, int]]:
    """One element read the way asn1js's fromBER reads it: ``(node, end offset, block length)``, or None for an error. The length of a constructed element
    only bounds the loop over its children (each child is read from the real buffer and counted by what it actually occupies), so a child that runs past
    its parent's declared length is accepted and the next sibling starts where the child really ended."""
    n = len(buf)
    if in_len <= 0 or off < 0 or off + in_len > n:
        return None
    p, end = off, off + in_len
    tag = buf[p]
    p += 1
    if tag & 0x1F == 0x1F:  # high tag number form: continuation octets while the top bit is set
        while True:
            if p >= end:
                return None
            c = buf[p]
            p += 1
            if not c & 0x80:
                break
    ident = bytes(buf[off:p])
    if p >= end:
        return None
    l0 = buf[p]
    p += 1
    constructed = bool(tag & 0x20)
    if l0 == 0xFF:
        return None
    if l0 == 0x80:  # indefinite length: a constructed element read until its end-of-contents
        if not constructed:
            return None
        kids: List[_A1] = []
        cur, blk = p, p - off
        while True:
            c = _a1_parse(buf, cur, end - cur)
            if c is None:
                return None
            node, cur, cb = c
            blk += cb
            if node.ident == b"\x00" and not node.constructed and node.content == b"":
                break
            kids.append(node)
        return _A1(ident, True, kids, b""), cur, blk
    if l0 & 0x80:
        cnt = l0 & 0x7F
        if cnt > 8 or p + cnt > end:
            return None
        length = int.from_bytes(buf[p:p + cnt], "big")
        p += cnt
    else:
        length = l0
    hdr = p - off
    if p + length > n:
        return None
    if not constructed:
        return _A1(ident, False, None, bytes(buf[p:p + length])), p + length, hdr + length
    if length == 0:
        return _A1(ident, True, [], b""), p, hdr
    kids = []
    cur, remaining, blk = p, length, hdr
    while remaining > 0:
        c = _a1_parse(buf, cur, remaining)
        if c is None:
            return None
        node, cur, cb = c
        kids.append(node)
        remaining -= cb
        blk += cb
    return _A1(ident, True, kids, b""), cur, blk


def _a1_der(node: _A1) -> bytes:
    """The definite-length DER of a node read by :func:`_a1_parse`: lengths are recomputed from the contents."""
    body = b"".join(_a1_der(k) for k in node.kids) if node.constructed else node.content
    n = len(body)
    ln = bytes([n]) if n < 0x80 else (b"\x84" + n.to_bytes(4, "big") if n > 0xFFFFFF else (b"\x83" + n.to_bytes(3, "big") if n > 0xFFFF else (
        b"\x82" + n.to_bytes(2, "big") if n > 0xFF else b"\x81" + bytes([n]))))
    return node.ident + ln + body


def _a1_times_ok(node: _A1) -> bool:
    if node.constructed:
        return all(_a1_times_ok(k) for k in (node.kids or []))
    if len(node.ident) == 1 and (node.ident[0] & 0xC0) == 0 and (node.ident[0] & 0x1F) in (23, 24):
        return _time_in_range(node.content.decode("latin-1"), (node.ident[0] & 0x1F) == 23)
    return True


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


def verify_ocsp_response(response_der: bytes, cert: Cert, issuer: Cert, chain: List[Cert], now_ms: float, max_age_ms: Optional[float] = None, clock_skew_ms: float = 0,
                         expected_nonce: Optional[bytes] = None) -> Dict[str, Any]:
    """One DER OCSPResponse for `cert`; ``expected_nonce`` (when given) must be echoed exactly. Never raises; any malformation is {ok: False}."""
    try:
        return _verify_inner(bytes(response_der), cert, issuer, chain, now_ms, max_age_ms, clock_skew_ms, expected_nonce)
    except Exception as e:
        return _fail("OCSP response rejected: %s" % e)


def _echoed_nonce(basic: bytes, rd: List[Tuple[Tlv, int]], idx: int) -> Optional[bytes]:
    """The nonce of the response's [1] responseExtensions (the OCTET STRING inside the extension value when the value is exactly one), or None."""
    for t, _off in rd[idx + 1:]:
        if t.tag != 0xA1:
            continue
        for seq, _o in _children(basic, t):
            for ext, _eo in _children(basic, seq):
                parts = _children(basic, ext)
                if not parts or parts[0][0].tag != 0x06 or _oid_to_dotted(basic, parts[0][0]) != OID_OCSP_NONCE:
                    continue
                val = parts[-1][0]
                if val.tag != 0x04:
                    return None
                raw = bytes(basic[val.start:val.end])
                try:
                    inner = _tlv_at(raw, 0)
                    if inner.end == len(raw) and inner.tag == 0x04:
                        return bytes(raw[inner.start:inner.end])
                except DerError:
                    pass
                return raw
    return None


def _verify_inner(der: bytes, cert: Cert, issuer: Cert, chain: List[Cert], now_ms: float, max_age_ms: Optional[float], skew: float,
                  expected_nonce: Optional[bytes] = None) -> Dict[str, Any]:
    max_age = NVIDIA_OCSP_DEFAULT_MAX_AGE_MS if max_age_ms is None else max_age_ms
    try:
        top = _tlv_at(der, 0)
    except DerError:
        return _fail("response is not valid DER")
    if _a1_parse(der, 0, len(der)) is None:
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
    a1 = _a1_parse(basic, 0, len(basic))
    if a1 is None:
        return _fail("BasicOCSPResponse is not valid DER")
    if btop.tag != 0x30:
        raise OcspError("BasicOCSPResponse is not a SEQUENCE")
    bk = _children(basic, btop)
    if len(bk) < 3 or bk[0][0].tag != 0x30 or bk[1][0].tag != 0x30 or bk[2][0].tag != 0x03:
        raise OcspError("BasicOCSPResponse is malformed")
    if not _a1_times_ok(a1[0]):
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

    # CertID match
    matches: List[Tuple[Tlv, int]] = []
    for single_t, single_off in _children(basic, responses_t):
        sk = _children(basic, single_t)
        # every SingleResponse, matching or not: after thisUpdate only [0] nextUpdate, then [1] extensions (the reference's schema)
        if len(sk) < 3 or sk[0][0].tag != 0x30 or [t.tag for t, _o in sk[3:]] not in ([], [0xA0], [0xA1], [0xA0, 0xA1]):
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
                    # the certificates are taken from the response's own bytes, never re-encoded: a re-encoding normalises a malformed certificate (a
                    # wrong inner length, a stray byte) into the genuine one, so a tampered copy verified
                    raw = bytes(basic[coff:ct.end])
                    try:
                        cand_cert = Cert(raw)
                    except Exception:  # noqa: BLE001 - a fixed text: a parser's own message is not reproducible across implementations
                        raise OcspError("embedded certificate is not valid DER") from None
                    if cand_cert.raw != raw:  # the parsed certificate must be exactly the bytes in the response (a recovered length is no length)
                        raise OcspError("embedded certificate is not canonical DER")
                    embedded.append(cand_cert)
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
            if nb is None or na is None or not (fin(now_ms, skew) and nb - skew <= now_ms and now_ms <= na):
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

    # nonce
    if expected_nonce is not None:
        echoed = _echoed_nonce(basic, rd, idx)
        if echoed is None:
            return _fail("response does not echo the nonce")
        if echoed != bytes(expected_nonce):
            return _fail("response nonce does not match the request nonce")

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
        if len(inner) != 1 or inner[0][0].tag != 0x18:
            raise OcspError("nextUpdate is malformed")
        next_update = _gen_time_ms(bytes(basic[inner[0][0].start:inner[0][0].end]).decode("latin-1"))
    if not (fin(now_ms, skew) and this_update <= now_ms + skew):
        return _fail("response thisUpdate is in the future")
    if not (fin(now_ms, skew) and produced_at <= now_ms + skew):
        return _fail("response producedAt is in the future")
    if next_update is not None:
        if next_update < this_update:
            return _fail("response nextUpdate is invalid")
        if not (now_ms <= next_update):
            return _fail("response is stale (past nextUpdate)")
    if not (now_ms - this_update <= max_age):
        return _fail("response is older than the maximum accepted age")

    # exact tags: a constructed [0] or [2], or a primitive [1], is not a status (masking the tag read 0xA0 as good)
    if (status_t.tag & 0xC0) != 0x80 or status_t.tag in (0x81, 0xA0, 0xA2):
        return _fail("malformed certStatus")
    accepted: Dict[str, Any] = {"ok": True, "thisUpdate": this_update, "producedAt": produced_at, "responder": responder}
    if next_update is not None:
        accepted["nextUpdate"] = next_update
    if status_t.tag == 0x80:
        return dict(accepted, status="good")
    if status_t.tag == 0x82:
        return dict(accepted, status="unknown")
    if status_t.tag == 0xA1:
        kids2 = _children(basic, status_t)
        if len(kids2) < 1:
            return _fail("malformed revoked certStatus")
        txt = bytes(basic[kids2[0][0].start:kids2[0][0].end]).decode("latin-1")
        if not re.fullmatch(r"[0-9]{14}Z", txt):
            return _fail("malformed revoked certStatus")
        accepted.update(status="revoked", revokedAt=_gen_time_ms(txt))
        if len(kids2) > 1 and kids2[1][0].tag == 0xA0:
            reason = _children(basic, kids2[1][0])
            if len(reason) > 0 and reason[0][0].tag == 0x0A:
                raw = bytes(basic[reason[0][0].start:reason[0][0].end])
                accepted["revocationReason"] = 0 if len(raw) >= 4 else int.from_bytes(raw, "big", signed=True)  # asn1js: valueDec is 0 from 4 bytes on
        return accepted
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


def check_nvidia_chain_ocsp(chain: List[Cert], responses: List[bytes], now_ms: float, max_age_ms: Optional[float] = None, require_good: Any = "aia",
                            clock_skew_ms: Optional[float] = None, expected_nonces: Optional[list] = None) -> Dict[str, Any]:
    """The device chain against OCSP responses. Every response must verify for exactly one chain certificate; any REVOKED fails; the certificates in
    ``require_good`` need a GOOD response: "aia" (default: each non-root certificate that advertises an OCSP URL), "all", or a list of chain indices
    (0 = leaf). ``expected_nonces[i]`` is the nonce the response for chain certificate i must echo."""
    if len(chain) < 2:
        return {"ok": False, "reason": "chain too short for OCSP"}
    if len(responses) == 0:
        return {"ok": False, "reason": "no OCSP responses supplied"}
    last = len(chain) - 1
    required = set()
    policy = "aia" if require_good is None else require_good
    if isinstance(policy, list):
        for i in policy:
            if isinstance(i, bool) or not isinstance(i, (int, float)) or i != int(i) or i < 0 or i >= last:
                return {"ok": False, "reason": "requireGood index %s is not a non-root chain certificate" % _js_index(i)}
            required.add(int(i))
    else:
        required = set(i for i in range(last) if policy == "all" or len(cert_ocsp_urls(chain[i])) > 0)
    statuses: Dict[int, str] = {i: "absent" for i in range(last)}
    verified = 0
    for ri, der in enumerate(responses):
        matched = False
        last_reason = "matches no chain certificate"
        for i in range(last):
            nonce = expected_nonces[i] if expected_nonces and i < len(expected_nonces) else None
            r = verify_ocsp_response(der, chain[i], chain[i + 1], chain, now_ms, max_age_ms, 0 if clock_skew_ms is None else clock_skew_ms, nonce)
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


def _js_index(i: Any) -> str:
    return str(int(i)) if isinstance(i, (int, float)) and not isinstance(i, bool) and i == int(i) else str(i)


def all_asn1_times_well_formed(der: bytes) -> bool:
    """True iff every GeneralizedTime / UTCTime inside the DER value is a well-formed DER time with in-range fields (no calendar roll-over). The
    contents of OCTET STRING / BIT STRING are opaque and never inspected; a value the reader itself refuses is False."""
    try:
        top = _tlv_at(bytes(der), 0)
        der = bytes(der)
        if (top.tag & 0xC0) == 0 and (top.tag & 0x1F) in (23, 24) and (top.tag & 0x20) == 0:
            return _time_in_range(der[top.start:top.end].decode("latin-1"), (top.tag & 0x1F) == 23)
        return _all_times_well_formed(der, top.start, top.end) if top.tag & 0x20 else True
    except Exception:  # noqa: BLE001 - an unreadable value is not well formed
        return False


# ---- the request (RFC 6960): five fixed-shape SEQUENCEs ----

_HASH_OIDS = {"sha1": bytes.fromhex("06052b0e03021a"), "sha256": bytes.fromhex("0609608648016503040201"),
              "sha384": bytes.fromhex("0609608648016503040202"), "sha512": bytes.fromhex("0609608648016503040203")}
_NONCE_OID_DER = bytes.fromhex("06092b0601050507300102")


def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(lb)]) + lb + content


def build_nvidia_ocsp_request(cert: Cert, issuer: Cert, nonce: Optional[bytes] = None, hash: str = "sha384") -> bytes:
    """A DER OCSPRequest for ``cert`` (issued by ``issuer``): a SHA-384 CertID (sha1 / sha256 / sha512 selectable, explicit NULL parameters) and an
    optional nonce extension (1..32 bytes, not critical); no requestorName, no signature."""
    if hash not in _HASH_OIDS:
        raise ValueError("unsupported hash %s" % hash)
    name_hash, key_hash = _cert_id_hashes(issuer, hash)
    cert_id = _tlv(0x30, _tlv(0x30, _HASH_OIDS[hash] + b"\x05\x00") + _tlv(0x04, name_hash) + _tlv(0x04, key_hash) + _tlv(0x02, bytes(cert.serial)))
    body = _tlv(0x30, _tlv(0x30, cert_id))  # requestList { Request { CertID } }
    if nonce is not None:  # an empty nonce is refused, as in the reference
        if len(nonce) < 1 or len(nonce) > 32:
            raise ValueError("nonce must be 1..32 bytes")
        ext = _tlv(0x30, _NONCE_OID_DER + _tlv(0x04, _tlv(0x04, bytes(nonce))))
        body += _tlv(0xA2, _tlv(0x30, ext))  # [2] requestExtensions
    tbs = _tlv(0x30, body)
    return _tlv(0x30, tbs)


def fetch_nvidia_ocsp(cert: Cert, issuer: Cert, opts: Optional[dict] = None) -> Dict[str, bytes]:
    """POST an OCSPRequest for ``cert`` over the injected transport ``opts["fetch"](url, init) -> {"status", "body": bytes}`` (``init``: method, headers,
    body) and return ``{"request", "response"}`` DER. ``opts["url"]`` defaults to NVIDIA's responder, ``opts["nonce"]`` adds a nonce. Explicit use only;
    raises on any problem."""
    opts = opts or {}
    fetch = opts.get("fetch")
    if not callable(fetch):
        raise RuntimeError("fetchNvidiaOcsp: no fetch implementation available")
    request = build_nvidia_ocsp_request(cert, issuer, opts.get("nonce"))
    res = fetch(opts.get("url") or NVIDIA_OCSP_URL, {"method": "POST", "headers": {"content-type": "application/ocsp-request"}, "body": request})
    status = res.get("status")
    if not (isinstance(status, int) and 200 <= status < 300):
        raise RuntimeError("OCSP fetch failed: HTTP %s" % status)
    return {"request": request, "response": bytes(res.get("body") or b"")}
