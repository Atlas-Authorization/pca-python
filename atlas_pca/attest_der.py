"""Strict DER / X.509 readers shared by the hardware-attestation chain verifiers.

Native counterpart of the strict X.509 helpers of @atlasauth/pca (x509-strict, x509-validity): every function raises or
returns exactly what the reference does, including the exact error text (it is part of the conformance vectors).
Pure stdlib; nothing here needs the `cryptography` package.
"""
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple


class DerError(ValueError):
    """The analogue of the reference's RangeError: a structural DER problem (the message is part of the contract)."""


class Tlv(NamedTuple):
    tag: int
    start: int  # content start
    end: int  # content end (exclusive)


def read_tlv(b: bytes, off: int, limit: Optional[int] = None) -> Tlv:
    """One strict DER TLV at `off` inside `[0, limit)`: no multi-byte tags, definite minimal lengths up to 3 length bytes."""
    if limit is None:
        limit = len(b)
    if off + 2 > limit:
        raise DerError("DER: truncated header")
    tag = b[off]
    if (tag & 0x1F) == 0x1F:
        raise DerError("DER: multi-byte tags are not supported")
    ln = b[off + 1]
    p = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 3:
            raise DerError("DER: unsupported length form")
        if p + n > limit:
            raise DerError("DER: truncated length")
        ln = 0
        if n > 1 and b[p] == 0:
            raise DerError("DER: non-minimal length (leading zero)")
        for i in range(n):
            ln = (ln << 8) | b[p + i]
        if ln < 0x80:
            raise DerError("DER: non-minimal length (long form below 128)")
        p += n
    if p + ln > limit:
        raise DerError("DER: element overruns its parent")
    return Tlv(tag, p, p + ln)


_OID_BASIC_CONSTRAINTS = bytes([0x55, 0x1D, 0x13])
_OID_KEY_USAGE = bytes([0x55, 0x1D, 0x0F])


def _oid_equals(b: bytes, t: Tlv, want: bytes) -> bool:
    return t.tag == 0x06 and bytes(b[t.start:t.end]) == want


def read_cert_role_info(cert_der: bytes) -> Dict[str, object]:
    """The CA-role-relevant extensions of a DER certificate (hasBasicConstraints, ca, pathLen?, hasKeyUsage, keyCertSign)."""
    outer = read_tlv(cert_der, 0)
    if outer.tag != 0x30:
        raise DerError("certificate is not a DER SEQUENCE")
    if outer.end != len(cert_der):
        raise DerError("trailing bytes after the certificate")
    tbs = read_tlv(cert_der, outer.start, outer.end)
    if tbs.tag != 0x30:
        raise DerError("certificate has no tbsCertificate")
    info: Dict[str, object] = {"hasBasicConstraints": False, "ca": False, "hasKeyUsage": False, "keyCertSign": False}
    p = tbs.start
    while p < tbs.end:
        el = read_tlv(cert_der, p, tbs.end)
        p = el.end
        if el.tag != 0xA3:
            continue  # [3] EXPLICIT extensions
        seq = read_tlv(cert_der, el.start, el.end)
        if seq.tag != 0x30:
            raise DerError("extensions is not a SEQUENCE")
        q = seq.start
        while q < seq.end:
            ext = read_tlv(cert_der, q, seq.end)
            q = ext.end
            if ext.tag != 0x30:
                raise DerError("extension is not a SEQUENCE")
            ident = read_tlv(cert_der, ext.start, ext.end)
            r = ident.end
            nxt = read_tlv(cert_der, r, ext.end)
            if nxt.tag == 0x01:
                r = nxt.end
                nxt = read_tlv(cert_der, r, ext.end)
            if nxt.tag != 0x04:
                raise DerError("extension value is not an OCTET STRING")
            if _oid_equals(cert_der, ident, _OID_BASIC_CONSTRAINTS):
                if info["hasBasicConstraints"]:
                    raise DerError("duplicate BasicConstraints extension")
                info["hasBasicConstraints"] = True
                bc = read_tlv(cert_der, nxt.start, nxt.end)
                if bc.tag != 0x30:
                    raise DerError("BasicConstraints is not a SEQUENCE")
                c = bc.start
                if c < bc.end:
                    first = read_tlv(cert_der, c, bc.end)
                    if first.tag == 0x01:
                        if first.end - first.start != 1:
                            raise DerError("BasicConstraints cA is not one byte")
                        info["ca"] = cert_der[first.start] != 0
                        c = first.end
                if c < bc.end:
                    pl = read_tlv(cert_der, c, bc.end)
                    if pl.tag != 0x02 or pl.end - pl.start < 1 or pl.end - pl.start > 2 or (cert_der[pl.start] & 0x80) != 0:
                        raise DerError("BasicConstraints pathLenConstraint malformed")
                    n = 0
                    for i in range(pl.start, pl.end):
                        n = (n << 8) | cert_der[i]
                    info["pathLen"] = n
                    c = pl.end
                if c != bc.end:
                    raise DerError("BasicConstraints has trailing data")
            elif _oid_equals(cert_der, ident, _OID_KEY_USAGE):
                if info["hasKeyUsage"]:
                    raise DerError("duplicate keyUsage extension")
                info["hasKeyUsage"] = True
                bs = read_tlv(cert_der, nxt.start, nxt.end)
                if bs.tag != 0x03 or bs.end - bs.start < 2:
                    raise DerError("keyUsage is not a BIT STRING")
                if cert_der[bs.start] > 7:
                    raise DerError("keyUsage BIT STRING has more than 7 unused bits")
                info["keyCertSign"] = (cert_der[bs.start + 1] & 0x04) != 0
    return info


class CertExtension(NamedTuple):
    critical: bool
    value: bytes  # the extnValue OCTET STRING content


def _oid_to_dotted(b: bytes, t: Tlv) -> str:
    if t.tag != 0x06 or t.end <= t.start:
        raise DerError("extension OID is malformed")
    arcs: List[int] = []
    v = 0
    is_open = False
    for i in range(t.start, t.end):
        byte = b[i]
        if not is_open and byte == 0x80:
            raise DerError("extension OID has a non-minimal arc")
        v = (v << 7) | (byte & 0x7F)
        is_open = (byte & 0x80) != 0
        if not is_open:
            arcs.append(v)
            v = 0
    if is_open:
        raise DerError("extension OID is truncated")
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(x) for x in head + arcs[1:])


def parse_tbs_extensions(tbs_der: bytes) -> Dict[str, CertExtension]:
    """STRICT extension table of a tbsCertificate (the SEQUENCE INCLUDING its header), keyed by dotted OID."""
    tbs = read_tlv(tbs_der, 0)
    if tbs.tag != 0x30:
        raise DerError("tbsCertificate is not a SEQUENCE")
    if tbs.end != len(tbs_der):
        raise DerError("trailing bytes after tbsCertificate")
    out: Dict[str, CertExtension] = {}
    seen = False
    block_end = -1
    p = tbs.start
    while p < tbs.end:
        el = read_tlv(tbs_der, p, tbs.end)
        p = el.end
        if el.tag != 0xA3:
            continue
        if seen:
            raise DerError("duplicate [3] extensions block")
        seen = True
        block_end = el.end
        seq = read_tlv(tbs_der, el.start, el.end)
        if seq.tag != 0x30:
            raise DerError("extensions is not a SEQUENCE")
        if seq.end != el.end:
            raise DerError("trailing bytes after the Extensions SEQUENCE")
        if seq.start == seq.end:
            raise DerError("empty Extensions SEQUENCE")
        q = seq.start
        while q < seq.end:
            ext = read_tlv(tbs_der, q, seq.end)
            q = ext.end
            if ext.tag != 0x30:
                raise DerError("extension is not a SEQUENCE")
            ident = read_tlv(tbs_der, ext.start, ext.end)
            dotted = _oid_to_dotted(tbs_der, ident)
            r = ident.end
            nxt = read_tlv(tbs_der, r, ext.end)
            critical = False
            if nxt.tag == 0x01:
                if nxt.end - nxt.start != 1 or tbs_der[nxt.start] != 0xFF:
                    raise DerError("extension %s has a non-DER critical flag" % dotted)
                critical = True
                r = nxt.end
                nxt = read_tlv(tbs_der, r, ext.end)
            if nxt.tag != 0x04:
                raise DerError("extension %s value is not an OCTET STRING" % dotted)
            if nxt.end != ext.end:
                raise DerError("extension %s has trailing bytes" % dotted)
            if dotted in out:
                raise DerError("duplicate extension %s" % dotted)
            out[dotted] = CertExtension(critical, bytes(tbs_der[nxt.start:nxt.end]))
    if seen and block_end != tbs.end:
        raise DerError("extensions block is not the last TBS element")
    return out


def tbs_of_certificate(cert_der: bytes) -> bytes:
    """The tbsCertificate bytes (header included) of a DER certificate; rejects trailing bytes after the certificate."""
    outer = read_tlv(cert_der, 0)
    if outer.tag != 0x30:
        raise DerError("certificate is not a DER SEQUENCE")
    if outer.end != len(cert_der):
        raise DerError("trailing bytes after the certificate")
    tbs = read_tlv(cert_der, outer.start, outer.end)
    if tbs.tag != 0x30:
        raise DerError("certificate has no tbsCertificate")
    return bytes(cert_der[outer.start:tbs.end])


def parse_cert_extensions(cert_der: bytes) -> Dict[str, CertExtension]:
    return parse_tbs_extensions(tbs_of_certificate(cert_der))


RECOGNISED_CRITICAL_EXTENSIONS = frozenset(["2.5.29.19", "2.5.29.15"])


def unrecognised_critical_extension(cert_der: bytes, recognised: Optional[Iterable[str]] = None) -> Optional[str]:
    """RFC 5280 4.2: the first critical extension this verifier does not understand, else None. Raises on a malformed table."""
    ok = RECOGNISED_CRITICAL_EXTENSIONS if recognised is None else frozenset(recognised)
    for oid, e in parse_cert_extensions(cert_der).items():
        if e.critical and oid not in ok:
            return oid
    return None


def check_chain_roles(ordered_der: Sequence[bytes]) -> Optional[str]:
    """CA roles over an ordered chain (index 0 = leaf ... last = self-signed root). A failure reason or None."""
    try:
        n = len(ordered_der)
        for i in range(n):
            info = read_cert_role_info(ordered_der[i])
            if i == 0 and n > 1:
                if info["ca"]:
                    return "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)"
                continue
            if i == 0:
                continue
            if not info["hasBasicConstraints"]:
                return "issuer certificate at depth %d has no BasicConstraints (not a CA)" % i
            if not info["ca"]:
                return "issuer certificate at depth %d is not a CA (BasicConstraints CA:FALSE)" % i
            if info["hasKeyUsage"] and not info["keyCertSign"]:
                return "issuer certificate at depth %d keyUsage lacks keyCertSign" % i
            pl = info.get("pathLen")
            if pl is not None and pl < i - 1:  # type: ignore[operator]
                return "issuer certificate at depth %d pathLenConstraint %d is exceeded (%d intermediate(s) below)" % (i, pl, i - 1)
        return None
    except DerError as e:
        return "certificate extension parse failed: %s" % e


# ---------------------------------------------------------------------------------------------- validity (x509-validity)


def _tlv_at(der: bytes, off: int) -> Tlv:
    if off + 2 > len(der):
        raise DerError("truncated")
    tag = der[off]
    ln = der[off + 1]
    start = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or start + n > len(der):
            raise DerError("bad length")
        ln = 0
        for i in range(n):
            ln = ln * 256 + der[start + i]
        start += n
    end = start + ln
    if end > len(der):
        raise DerError("truncated")
    return Tlv(tag, start, end)


def _is_digits(s: str) -> bool:
    return len(s) > 0 and all("0" <= c <= "9" for c in s)


def days_from_civil(y: int, m: int, d: int) -> int:
    """Days since 1970-01-01 of the proleptic Gregorian date (any year, including 0 and negatives)."""
    y -= 1 if m <= 2 else 0
    era = y // 400  # floor division: the era of negative years too
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def days_in_month(y: int, m: int) -> int:
    if m == 2:
        leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
        return 29 if leap else 28
    return 30 if m in (4, 6, 9, 11) else 31


def parse_der_time(tag: int, text: str) -> Optional[int]:
    """Strict RFC 5280 Time (UTCTime 0x17 / GeneralizedTime 0x18) to epoch ms; None for anything else (fail closed)."""
    if tag == 0x17 and len(text) == 13:
        yy = int(text[0:2]) if _is_digits(text[0:2]) else -1
        if yy < 0:
            return None
        y = 1900 + yy if yy >= 50 else 2000 + yy
        rest = text[2:]
    elif tag == 0x18 and len(text) == 15:
        if not _is_digits(text[0:4]):
            return None
        y = int(text[0:4])
        rest = text[4:]
    else:
        return None
    if rest[10] != "Z" or not _is_digits(text[: len(text) - 1]):
        return None
    mon, day, h, mi, sec = int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]), int(rest[8:10])
    if mon < 1 or mon > 12 or day < 1 or h > 23 or mi > 59 or sec > 59:
        return None
    if day > days_in_month(y, mon):  # Feb 30, Apr 31, ...
        return None
    return ((days_from_civil(y, mon, day) * 24 + h) * 60 + mi) * 60_000 + sec * 1000


def der_validity_ms(der: bytes) -> Tuple[Optional[int], Optional[int]]:
    """The validity instants (epoch ms) of a DER certificate; None members when malformed."""
    try:
        cert = _tlv_at(der, 0)
        if cert.tag != 0x30:
            raise DerError("not a SEQUENCE")
        tbs = _tlv_at(der, cert.start)
        if tbs.tag != 0x30:
            raise DerError("not a SEQUENCE")
        off = tbs.start
        el = _tlv_at(der, off)
        if el.tag == 0xA0:
            off = el.end
            el = _tlv_at(der, off)
        if el.tag != 0x02:
            raise DerError("serial")
        off = el.end
        el = _tlv_at(der, off)
        if el.tag != 0x30:
            raise DerError("signature")
        off = el.end
        el = _tlv_at(der, off)
        if el.tag != 0x30:
            raise DerError("issuer")
        validity = _tlv_at(der, el.end)
        if validity.tag != 0x30 or validity.end > tbs.end:
            raise DerError("validity")
        nb = _tlv_at(der, validity.start)
        na = _tlv_at(der, nb.end)
        if na.end != validity.end:
            raise DerError("validity has extra fields")

        def text(t: Tlv) -> str:
            return bytes(der[t.start:t.end]).decode("latin-1")

        return parse_der_time(nb.tag, text(nb)), parse_der_time(na.tag, text(na))
    except DerError:
        return None, None


def x509_valid_at(der: bytes, now_ms: float, skew_ms: float = 0) -> bool:
    """True iff both bounds parse and `from - skew <= now <= to + skew`; False (fail closed) for any unparseable bound."""
    lo, hi = der_validity_ms(der)
    if lo is None or hi is None:
        return False
    return now_ms + skew_ms >= lo and now_ms - skew_ms <= hi
