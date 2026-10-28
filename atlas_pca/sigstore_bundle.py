"""Offline Sigstore bundle verification for build provenance (track K9): a port of packages/pca-attest-eat/src/sigstore.ts.

Verifies a Sigstore bundle (v0.2 / v0.3) carrying a DSSE in-toto Statement against a pinned ``trusted_root.json``, with no
network access, and returns the facts ``provenance_gate`` checks. Same order and refusal codes as the reference: RFC 3161
timestamps and the Rekor v1 SET first, then the Rekor entry (v1 ``dsse`` 0.0.1 / ``intoto`` 0.0.2, v2 ``hashedrekord``
0.0.2), RFC 9162 inclusion and the signed-note checkpoint, the Fulcio path at every verified time, the embedded SCT, the
entry body, the DSSE signature, identity and the Statement. Never raises: every refusal is ``{"ok": False, "code", "detail"}``.

A port rather than sigstore-python: sigstore-python 4.5 refuses Rekor v1 ``intoto`` 0.0.2 entries (and the SET time on
them) and two timestamps from one TSA, and does not report which time sources it verified (the ``core`` the shared
vectors pin). Needs the ``cryptography`` package (``pip install 'atlas-pca[sigstore]'``).
"""
import base64
import hashlib
import json
import re
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, NamedTuple, Optional, Tuple
from urllib.parse import urlsplit

from .attest_cert import Cert
from .attest_common import crypto, ecdsa_verify_der, js_json_loads, key_type, load_public_key, rsa_pkcs1_verify
from .attest_der import der_validity_ms
from .provenance_gate import INTOTO_STATEMENT_V1, SLSA_PROVENANCE_V1, rfc9162_leaf_hash, verify_rfc9162_inclusion

__all__ = [
    "SIGSTORE_BUNDLE_MEDIA_TYPES", "INTOTO_PAYLOAD_TYPE", "PinnedLog", "PinnedCa", "PinnedRoots", "parse_trusted_root",
    "verify_rfc3161", "dsse_pae", "verify_sigstore_bundle_core", "verify_sigstore_bundle",
]

SIGSTORE_BUNDLE_MEDIA_TYPES = (
    "application/vnd.dev.sigstore.bundle+json;version=0.2",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
    "application/vnd.dev.sigstore.bundle.v0.3+json",
)
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_OID_FULCIO = "1.3.6.1.4.1.57264.1."
_OID_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2"
_OID_SAN = "2.5.29.17"
_OID_EKU = "2.5.29.37"
_EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_DIGEST_OIDS = {"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}
_INF = float("inf")


class _Fail(Exception):
    pass


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _get(v: Any, k: str) -> Any:
    return v.get(k) if isinstance(v, dict) else None


_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def _b64(s: Any) -> bytes:
    if not isinstance(s, str) or not _B64.fullmatch(s) or len(s) % 4 != 0:
        raise _Fail("not base64")
    return base64.b64decode(s)


_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})")


def _date_ms(s: str) -> Optional[int]:
    m = _RFC3339.fullmatch(s)
    if not m:
        return None
    try:
        tz = timezone.utc if m.group(8) == "Z" else datetime.strptime(m.group(8).replace(":", ""), "%z").tzinfo
        d = datetime(*(int(m.group(i)) for i in range(1, 7)), tzinfo=tz)
    except ValueError:
        return None
    frac = int((m.group(7) or "0")[:3].ljust(3, "0"))
    return int(d.timestamp()) * 1000 + frac


class _Validity(NamedTuple):
    start: float
    end: float


def _validity(v: Any) -> _Validity:
    s = _date_ms(v["start"]) if _is_obj(v) and isinstance(v.get("start"), str) else None
    if s is None:
        raise _Fail("validFor.start missing")
    e: Optional[float] = _INF
    if _is_obj(v) and isinstance(v.get("end"), str):
        e = _date_ms(v["end"])
        if e is None:
            raise _Fail("validFor.end malformed")
    return _Validity(s, e)


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


class PinnedLog(NamedTuple):
    key_id: bytes
    key: Any
    valid: _Validity
    v2_name: Optional[str] = None  # Rekor v2 (Ed25519, signed-note checkpoints): the host of the log's base URL


class PinnedCa(NamedTuple):
    chain: List[Cert]
    valid: _Validity


class PinnedRoots(NamedTuple):
    tlogs: List[PinnedLog]
    ctlogs: List[PinnedLog]
    cas: List[PinnedCa]
    tsas: List[PinnedCa]


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    elif n < 0x10000:
        ln = bytes([0x82, n >> 8, n & 0xFF])
    else:
        ln = bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([tag]) + ln + content


_RSA_ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def _pinned_log(t: Any, transparency: bool) -> Optional[PinnedLog]:
    """A log key: ECDSA P-256 (id = SHA-256(SPKI)), PKCS#1 RSA (CT only), Ed25519 (Rekor v2, id = signed-note key hash)."""
    if not _is_obj(t) or not _is_obj(t.get("publicKey")) or not _is_obj(t.get("logId")):
        raise _Fail("log entry malformed")
    pk = t["publicKey"]
    der = _b64(pk.get("rawBytes"))
    key_id = _b64(t["logId"].get("keyId"))
    valid = _validity(pk.get("validFor"))
    kd = pk.get("keyDetails")
    if kd == "PKIX_ECDSA_P256_SHA_256":
        if _sha256(der) != key_id:
            raise _Fail("log id is not the SHA-256 of its key")
        return PinnedLog(key_id, load_public_key(der), valid)
    if kd == "PKCS1_RSA_PKCS1V5":
        if transparency:
            return None
        spki = _der(0x30, _RSA_ALG_ID + _der(0x03, b"\x00" + der))
        key = load_public_key(spki)
        if _sha256(spki) != key_id:
            raise _Fail("log id is not the SHA-256 of its key")
        return PinnedLog(key_id, key, valid)
    if kd == "PKIX_ED25519":
        if not transparency:
            return None
        key = load_public_key(der)
        name = urlsplit(t["baseUrl"]).hostname or "" if isinstance(t.get("baseUrl"), str) else ""
        if not name or _sha256(name.encode() + b"\n", b"\x01", der[-32:]) != key_id:
            raise _Fail("log id is not the signed-note key hash of its key")
        return PinnedLog(key_id, key, valid, name)
    return None


def _pinned_chain(c: Any) -> PinnedCa:
    certs = _get(_get(c, "certChain"), "certificates")
    if not isinstance(certs, list) or len(certs) == 0:
        raise _Fail("certificate authority entry malformed")
    return PinnedCa([Cert(_b64(_get(x, "rawBytes"))) for x in certs], _validity(c.get("validFor")))


def parse_trusted_root(doc: Any) -> PinnedRoots:
    """Parse a Sigstore ``trusted_root.json`` (v0.1). Raises ValueError on anything malformed."""
    try:
        if not _is_obj(doc) or doc.get("mediaType") != "application/vnd.dev.sigstore.trustedroot+json;version=0.1":
            raise _Fail("not a trusted root v0.1")

        def arr(k: str) -> List[Any]:
            v = doc.get(k)
            return v if isinstance(v, list) else []

        tlogs = [x for x in (_pinned_log(t, True) for t in arr("tlogs")) if x is not None]
        ctlogs = [x for x in (_pinned_log(t, False) for t in arr("ctlogs")) if x is not None]
        cas = [_pinned_chain(c) for c in arr("certificateAuthorities")]
        tsas = [_pinned_chain(c) for c in arr("timestampAuthorities")]
        if not tlogs or not cas:
            raise _Fail("a trusted root needs a transparency log and a CA")
        return PinnedRoots(tlogs, ctlogs, cas, tsas)
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(str(e)) from e


# ------------------------------------------------------------------------------------------------ DER (as the reference)


class _Tlv(NamedTuple):
    tag: int
    start: int
    body: int
    end: int


def _tlv(b: bytes, off: int, limit: Optional[int] = None) -> _Tlv:
    if limit is None:
        limit = len(b)
    if off + 2 > limit:
        raise _Fail("DER truncated")
    tag = b[off]
    if tag & 0x1F == 0x1F:
        raise _Fail("DER multi-byte tag")
    ln = b[off + 1]
    body = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or body + n > limit:
            raise _Fail("DER length")
        ln = int.from_bytes(b[body:body + n], "big")
        body += n
    if body + ln > limit:
        raise _Fail("DER overrun")
    return _Tlv(tag, off, body, body + ln)


def _kids(b: bytes, t: _Tlv) -> List[_Tlv]:
    out, o = [], t.body
    while o < t.end:
        c = _tlv(b, o, t.end)
        out.append(c)
        o = c.end
    return out


def _oid(b: bytes, t: _Tlv) -> str:
    if t.tag != 0x06 or t.end <= t.body:
        raise _Fail("not an OID")
    parts, v = [], 0
    for i in range(t.body, t.end):
        v = v * 128 + (b[i] & 0x7F)
        if not b[i] & 0x80:
            parts.append(v)
            v = 0
    if not parts:
        raise _Fail("not an OID")
    first = parts.pop(0)
    a = min(2, first // 40)
    return ".".join(str(x) for x in [a, first - a * 40] + parts)


def _body(b: bytes, t: _Tlv) -> bytes:
    return bytes(b[t.body:t.end])


class _Ext(NamedTuple):
    oid: str
    value: bytes
    tlv: _Tlv


class _ParsedCert(NamedTuple):
    der: bytes
    tbs_kids: List[_Tlv]
    exts_wrapper: _Tlv
    exts: List[_Ext]


def _parse_cert(der: bytes) -> _ParsedCert:
    cert = _tlv(der, 0)
    if cert.tag != 0x30 or cert.end != len(der):
        raise _Fail("certificate is not one SEQUENCE")
    tbs = _kids(der, cert)[0]
    if tbs.tag != 0x30:
        raise _Fail("no TBSCertificate")
    tbs_kids = _kids(der, tbs)
    wrapper = next((k for k in tbs_kids if k.tag == 0xA3), None)
    if wrapper is None:
        raise _Fail("no extensions")
    seq = _kids(der, wrapper)[0]
    if seq.tag != 0x30:
        raise _Fail("extensions malformed")
    exts: List[_Ext] = []
    seen = set()
    for e in _kids(der, seq):
        parts = _kids(der, e)
        oct_ = parts[-1]
        if oct_.tag != 0x04:
            raise _Fail("extension value is not an OCTET STRING")
        oid = _oid(der, parts[0])
        if oid in seen:
            raise _Fail("duplicate extension " + oid)
        seen.add(oid)
        exts.append(_Ext(oid, _body(der, oct_), e))
    return _ParsedCert(der, tbs_kids, wrapper, exts)


def _ext(c: _ParsedCert, oid: str) -> Optional[_Ext]:
    return next((x for x in c.exts if x.oid == oid), None)


def _fulcio_ext(c: _ParsedCert, n: int) -> Optional[str]:
    """Fulcio extension ``.1.n``: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8."""
    e = _ext(c, _OID_FULCIO + str(n))
    if e is None:
        return None
    if n <= 6:
        return e.value.decode("utf-8-sig")
    t = _tlv(e.value, 0)
    if t.tag != 0x0C or t.end != len(e.value):
        raise _Fail("extension .1.%d is not a DER UTF8String" % n)
    return _body(e.value, t).decode("utf-8-sig")


def _san_identity(c: _ParsedCert) -> str:
    e = _ext(c, _OID_SAN)
    if e is None:
        raise _Fail("no subjectAltName")
    seq = _tlv(e.value, 0)
    names = _kids(e.value, seq)
    if seq.tag != 0x30 or len(names) != 1:
        raise _Fail("subjectAltName must hold exactly one name")
    if names[0].tag not in (0x86, 0x81):
        raise _Fail("subjectAltName must be a URI or an email")
    return _body(e.value, names[0]).decode("utf-8-sig")


def _eku(c: Cert) -> List[str]:
    """node's X509Certificate.keyUsage: the extended key usage OIDs."""
    e = c.extensions().get(_OID_EKU)
    if e is None:
        return []
    seq = _tlv(e.value, 0)
    return [_oid(e.value, k) for k in _kids(e.value, seq)]


def _inside(c: Cert, at: float) -> bool:
    lo, hi = der_validity_ms(c.raw)
    return lo is not None and hi is not None and lo <= at <= hi


def _chain_ok(chain: List[Cert], at: float) -> bool:
    """Leaf first, self-signed root last: issuer links, signatures, CA flags; every certificate valid at ``at``."""
    for i, c in enumerate(chain):
        up = chain[i + 1] if i + 1 < len(chain) else c
        if not c.check_issued(up) or not c.verify(up.public_key) or not _inside(c, at):
            return False
        if i > 0 and not c.ca:
            return False
    return True


def _verify(hash_name: Optional[str], data: bytes, key: Any, sig: bytes) -> bool:
    """node's crypto.verify: ECDSA (DER), RSA PKCS#1 v1.5, or Ed25519 when ``hash_name`` is None."""
    kt = key_type(key)
    if hash_name is None:
        if kt != "ed25519":
            return False
        try:
            key.verify(bytes(sig), bytes(data))
            return True
        except Exception:
            return False
    if kt == "ec":
        return ecdsa_verify_der(key, sig, data, hash_name)
    if kt == "rsa":
        return rsa_pkcs1_verify(key, sig, data, hash_name)
    return False


# ------------------------------------------------------------------------------------------------ SCT (RFC 6962 3.2)


def _verify_sct(leaf: _ParsedCert, issuer: Cert, roots: PinnedRoots) -> Optional[str]:
    e = _ext(leaf, _OID_SCT_LIST)
    if e is None:
        return "no embedded SCT"
    outer = _tlv(e.value, 0)
    if outer.tag != 0x04:
        return "SCT list is not an OCTET STRING"
    lst = _body(e.value, outer)
    if len(lst) < 2 or struct.unpack_from(">H", lst, 0)[0] != len(lst) - 2:
        return "SCT list length"
    der = leaf.der
    ext_seq = _kids(der, leaf.exts_wrapper)[0]
    kept = b"".join(der[k.start:k.end] for k in _kids(der, ext_seq) if k.start != e.tlv.start)
    tbs = _der(0x30, b"".join(_der(0xA3, _der(0x30, kept)) if k == leaf.exts_wrapper else der[k.start:k.end] for k in leaf.tbs_kids))
    issuer_key_hash = _sha256(issuer.spki_der)
    why = "no SCT from a pinned CT log"
    o = 2
    while o < len(lst):
        if o + 2 > len(lst):
            return "SCT truncated"
        n = struct.unpack_from(">H", lst, o)[0]
        s = lst[o + 2:o + 2 + n]
        o += 2 + n
        if len(s) != n or n < 47:
            return "SCT truncated"
        if s[0] != 0:
            continue
        log_id = s[1:33]
        ts = struct.unpack_from(">Q", s, 33)[0]
        ext_len = struct.unpack_from(">H", s, 41)[0]
        ext = s[43:43 + ext_len]
        p = 43 + ext_len
        if p + 4 > len(s):
            return "SCT truncated"
        hash_alg, sig_alg, sig_len = s[p], s[p + 1], struct.unpack_from(">H", s, p + 2)[0]
        sig = s[p + 4:p + 4 + sig_len]
        p += 4 + sig_len
        if p != len(s) or len(sig) != sig_len:
            return "SCT malformed"
        log = next((l for l in roots.ctlogs if l.key_id == log_id), None)
        if log is None:
            continue
        if hash_alg != 4 or sig_alg not in (3, 1):
            why = "SCT is not SHA-256 with ECDSA or RSA"
            continue
        if ts < log.valid.start or ts > log.valid.end:
            why = "SCT log key not valid at its timestamp"
            continue
        signed = (bytes([0, 0]) + struct.pack(">QH", ts, 1) + issuer_key_hash + len(tbs).to_bytes(3, "big") + tbs
                  + struct.pack(">H", len(ext)) + ext)
        if _verify("sha256", signed, log.key, sig):
            return None
        why = "SCT signature invalid"
    return why


# ------------------------------------------------------------------------------------------------ RFC 3161 timestamps


def _digest_of(b: bytes, t: _Tlv) -> str:
    alg = _DIGEST_OIDS.get(_oid(b, _kids(b, t)[0]))
    if alg is None:
        raise _Fail("unsupported digest algorithm")
    return alg


_GEN_TIME = re.compile(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z")


def _generalized_time(b: bytes, t: _Tlv) -> int:
    if t.tag != 0x18:
        raise _Fail("genTime is not a GeneralizedTime")
    m = _GEN_TIME.fullmatch(_body(b, t).decode("latin-1"))
    if not m:
        raise _Fail("genTime malformed")
    g = [int(m.group(i)) for i in range(1, 7)]
    try:
        d = datetime(g[0], g[1], g[2], g[3], g[4], g[5], tzinfo=timezone.utc)
    except ValueError:
        raise _Fail("genTime malformed")
    return int(d.timestamp()) * 1000 + (int(m.group(7).ljust(9, "0")[:3]) if m.group(7) else 0)


def _at(lst: List[_Tlv], i: int) -> Optional[_Tlv]:
    return lst[i] if 0 <= i < len(lst) else None


def verify_rfc3161(token: bytes, data: bytes, tsas: List[PinnedCa]) -> int:
    """Verify an RFC 3161 TimeStampResp (or bare token) over ``data`` (the raw signature bytes) against a pinned TSA;
    returns genTime (epoch ms). Raises on any failure."""
    ci = _tlv(token, 0)
    if ci.end != len(token) or ci.tag != 0x30:
        raise _Fail("timestamp is not one SEQUENCE")
    parts = _kids(token, ci)
    p0 = _at(parts, 0)
    if p0 is not None and p0.tag == 0x30 and p0.end - p0.body >= 3 and token[_kids(token, p0)[0].start] == 0x02:
        st = _kids(token, p0)[0]
        status = _body(token, st)
        if not (len(status) == 1 and status[0] in (0, 1)):
            raise _Fail("timestamp status is not granted")
        if _at(parts, 1) is None:
            raise _Fail("no timeStampToken")
        ci = parts[1]
        parts = _kids(token, ci)
    p1 = _at(parts, 1)
    if _oid(token, parts[0]) != _OID_SIGNED_DATA or p1 is None or p1.tag != 0xA0:
        raise _Fail("not CMS SignedData")
    sd = _kids(token, p1)[0]
    sdk = _kids(token, sd)
    encap = next(k for i, k in enumerate(sdk) if i > 1 and k.tag == 0x30)
    ek = _kids(token, encap)
    ek1 = _at(ek, 1)
    if _oid(token, ek[0]) != _OID_TST_INFO or ek1 is None or ek1.tag != 0xA0:
        raise _Fail("content is not TSTInfo")
    octet = _kids(token, ek1)[0]
    if octet.tag != 0x04:
        raise _Fail("TSTInfo is not an OCTET STRING")
    tst_bytes = _body(token, octet)
    tk = _kids(tst_bytes, _tlv(tst_bytes, 0))
    mi = _kids(tst_bytes, tk[2])
    mi_alg = _digest_of(tst_bytes, mi[0])
    if hashlib.new(mi_alg, bytes(data)).digest() != _body(tst_bytes, mi[1]):
        raise _Fail("messageImprint is not the hash of the signature")
    gen_time = _generalized_time(tst_bytes, tk[4])
    signer_infos = sdk[-1]
    if signer_infos.tag != 0x31:
        raise _Fail("no signerInfos")
    sis = _kids(token, signer_infos)
    if len(sis) != 1:
        raise _Fail("exactly one SignerInfo is required")
    si = _kids(token, sis[0])
    d_alg = _digest_of(token, si[2])
    attrs = si[3]
    if attrs.tag != 0xA0:
        raise _Fail("signed attributes are required")
    ct_ok = md_ok = False
    for a in _kids(token, attrs):
        ak = _kids(token, a)
        vals = _kids(token, ak[1])
        o = _oid(token, ak[0])
        if len(vals) != 1:
            raise _Fail("an attribute must have one value")
        if o == _OID_CONTENT_TYPE:
            ct_ok = _oid(token, vals[0]) == _OID_TST_INFO
        if o == _OID_MESSAGE_DIGEST:
            md_ok = hashlib.new(d_alg, tst_bytes).digest() == _body(token, vals[0])
    if not ct_ok or not md_ok:
        raise _Fail("signed attributes do not commit to the TSTInfo")
    signed_attrs = b"\x31" + bytes(token[attrs.start + 1:attrs.end])
    sig_t = si[5]
    if sig_t.tag != 0x04:
        raise _Fail("signature is not an OCTET STRING")
    sig = _body(token, sig_t)
    for tsa in tsas:
        if gen_time < tsa.valid.start or gen_time > tsa.valid.end:
            continue
        leaf = tsa.chain[0]
        if _EKU_TIME_STAMPING not in _eku(leaf):
            continue
        if not _verify(d_alg, signed_attrs, leaf.public_key, sig):
            continue
        if not _chain_ok(tsa.chain, gen_time):
            continue
        return gen_time
    raise _Fail("no pinned timestamp authority signed it (valid at its time)")


# ------------------------------------------------------------------------------------------------ Rekor

_SIG_LINE = re.compile(r"— (\S+) ([A-Za-z0-9+/=]+)")
_SIZE = re.compile(r"[1-9][0-9]*")


def _verify_checkpoint(text: str, log: PinnedLog, size: int, root: bytes) -> Optional[str]:
    """Signed-note checkpoint: origin, size, root; then ``— <name> <b64(hint4 || sig)>`` lines (v1 ECDSA, v2 Ed25519)."""
    cut = text.find("\n\n")
    if cut < 0:
        return "checkpoint has no signature block"
    body = text[:cut + 1]
    lines = body.split("\n")
    if len(lines) < 4 or len(lines[0]) == 0:
        return "checkpoint body too short or without an origin"
    if not _SIZE.fullmatch(lines[1]) or int(lines[1]) != size:
        return "checkpoint size differs from the proof"
    if _b64(lines[2]) != root:
        return "checkpoint root differs from the proof"
    for line in text[cut + 2:].split("\n"):
        m = _SIG_LINE.fullmatch(line)
        if not m:
            continue
        raw = _b64(m.group(2))
        if len(raw) < 5 or raw[:4] != log.key_id[:4]:
            continue
        if log.v2_name is not None and m.group(1) != log.v2_name:
            continue
        if _verify(None if log.v2_name is not None else "sha256", body.encode("utf-8"), log.key, raw[4:]):
            return None
    return "no checkpoint signature by the pinned log key"


_DEC_INT = re.compile(r"0|[1-9][0-9]{0,15}")


def _dec_int(v: Any) -> int:
    if not isinstance(v, str) or not _DEC_INT.fullmatch(v):
        raise _Fail("not a decimal integer string")
    n = int(v)
    if n > 2 ** 53 - 1:
        raise _Fail("integer out of range")
    return n


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE PAE (secure-systems-lab/dsse protocol.md)."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d " % len(t) + t + b" %d " % len(payload) + bytes(payload)


def _leaf_hash_alg(key: Any) -> Optional[str]:
    if key_type(key) != "ec":
        return None
    return {"secp256r1": "sha256", "secp384r1": "sha384"}.get(key.curve.name)


_PEM = re.compile(r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?")


def _pem_der(pem: str) -> bytes:
    m = _PEM.fullmatch(pem)
    return _b64(m.group(1).replace("\n", "")) if m else b""


def _kind_of(kv: Any) -> str:
    k, v = _get(kv, "kind"), _get(kv, "version")
    return "%s/%s" % (k, v) if isinstance(k, str) and isinstance(v, str) else ""


# ------------------------------------------------------------------------------------------------ the verifier


def verify_sigstore_bundle_core(bundle: Any, roots: PinnedRoots) -> Dict[str, Any]:
    """Verify a Sigstore bundle carrying a DSSE in-toto statement. Never raises. ``{"ok": True, "core", "statement"}`` or
    ``{"ok": False, "code", "detail"}`` (codes as the reference)."""
    stage = ["malformed"]

    def no(code: str, detail: str) -> Dict[str, Any]:
        return {"ok": False, "code": code, "detail": detail}

    def go() -> Dict[str, Any]:
        if not _is_obj(bundle) or not _is_obj(bundle.get("verificationMaterial")):
            return no("malformed", "not a bundle")
        mt = bundle.get("mediaType")
        if not isinstance(mt, str) or mt not in SIGSTORE_BUNDLE_MEDIA_TYPES:
            return no("media_type", "unsupported media type %s" % mt)
        vm = bundle["verificationMaterial"]
        if mt != SIGSTORE_BUNDLE_MEDIA_TYPES[0]:
            cert_raw = _get(vm.get("certificate"), "rawBytes")
        else:
            certs = _get(vm.get("x509CertificateChain"), "certificates")
            cert_raw = _get(certs[0], "rawBytes") if isinstance(certs, list) and certs else None
        if cert_raw is None:
            return no("not_keyless", "no Fulcio certificate (public-key bundles are not supported)")
        env = bundle.get("dsseEnvelope")
        if not _is_obj(env) or "messageSignature" in bundle:
            return no("envelope", "not a DSSE bundle")
        if env.get("payloadType") != INTOTO_PAYLOAD_TYPE:
            return no("envelope", "payloadType is not application/vnd.in-toto+json")
        sigs0 = env.get("signatures")
        if not isinstance(sigs0, list) or len(sigs0) != 1 or not _is_obj(sigs0[0]):
            return no("envelope", "a DSSE envelope must carry exactly one signature")
        payload = _b64(env.get("payload"))
        dsse_sig = _b64(sigs0[0].get("sig"))
        pae = dsse_pae(INTOTO_PAYLOAD_TYPE, payload)
        stage[0] = "cert_parse"
        leaf_der = _b64(cert_raw)
        leaf = Cert(leaf_der)
        pc = _parse_cert(leaf_der)
        alg = _leaf_hash_alg(leaf.public_key)

        # ---- the log entry and its log
        stage[0] = "tlog_count"
        entries = vm.get("tlogEntries")
        if not isinstance(entries, list) or len(entries) != 1 or not _is_obj(entries[0]):
            return no("tlog_count", "exactly one transparency log entry is required")
        t = entries[0]
        stage[0] = "tlog_kind"
        kv = _kind_of(t.get("kindVersion"))
        if kv not in ("dsse/0.0.1", "intoto/0.0.2", "hashedrekord/0.0.2"):
            return no("tlog_kind", "unsupported entry %s" % kv)
        v2 = kv == "hashedrekord/0.0.2"
        stage[0] = "tlog_key"
        key_id = _b64(_get(t.get("logId"), "keyId"))
        log = next((l for l in roots.tlogs if l.key_id == key_id), None)
        if log is None:
            return no("tlog_key", "the entry names a log the verifier did not pin")
        if v2 != (log.v2_name is not None):
            return no("tlog_key", "the entry type does not match the log version")
        log_index = _dec_int(t.get("logIndex"))
        body = _b64(t.get("canonicalizedBody"))

        # ---- time first: every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
        stage[0] = "tsa"
        times: List[int] = []
        tvd = vm.get("timestampVerificationData")
        ts_list = _get(tvd, "rfc3161Timestamps")
        for ts in ts_list if isinstance(ts_list, list) else []:
            times.append(verify_rfc3161(_b64(_get(ts, "signedTimestamp")), dsse_sig, roots.tsas))
        tsa_count = len(times)
        set_ok = False
        if not v2 and _is_obj(t.get("inclusionPromise")):
            stage[0] = "tlog_set"
            integrated = _dec_int(t.get("integratedTime"))
            msg = '{"body":%s,"integratedTime":%d,"logID":"%s","logIndex":%d}' % (
                json.dumps(t["canonicalizedBody"]), integrated, key_id.hex(), log_index)
            if not _verify("sha256", msg.encode("utf-8"), log.key, _b64(t["inclusionPromise"].get("signedEntryTimestamp"))):
                return no("tlog_set", "signed entry timestamp invalid")
            times.append(integrated * 1000)
            set_ok = True
        if not times:
            return no("no_verified_time", "no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp")
        if any(at < log.valid.start or at > log.valid.end for at in times):
            return no("tlog_key", "the log key was not valid at a signing time")

        # ---- inclusion
        stage[0] = "tlog_inclusion"
        ip = t.get("inclusionProof")
        if not _is_obj(ip) or not isinstance(ip.get("hashes"), list) or not _is_obj(ip.get("checkpoint")):
            return no("tlog_inclusion", "no inclusion proof")
        root = _b64(ip.get("rootHash"))
        size = _dec_int(ip.get("treeSize"))
        if not verify_rfc9162_inclusion(rfc9162_leaf_hash(body), _dec_int(ip.get("logIndex")), size, [_b64(h) for h in ip["hashes"]], root):
            return no("tlog_inclusion", "the inclusion proof does not lead to the root")
        stage[0] = "tlog_checkpoint"
        envelope = ip["checkpoint"].get("envelope")
        cpe = _verify_checkpoint(envelope, log, size, root) if isinstance(envelope, str) else "checkpoint has no signature block"
        if cpe:
            return no("tlog_checkpoint", cpe)

        # ---- certificate path at every verified time (hybrid model), CT
        stage[0] = "cert_chain"
        issuer: Optional[Cert] = None
        for ca in roots.cas:
            if any(at < ca.valid.start or at > ca.valid.end for at in times):
                continue
            first = ca.chain[0]
            if not leaf.check_issued(first) or not leaf.verify(first.public_key):
                continue
            if all(_chain_ok(ca.chain, at) for at in times) and all(c.ca for c in ca.chain):
                issuer = first
                break
        if issuer is None:
            return no("cert_chain", "no pinned CA issued the certificate, valid at every signing time")
        if leaf.ca:
            return no("cert_chain", "the leaf is a CA certificate")
        if not all(_inside(leaf, at) for at in times):
            return no("cert_time", "the certificate was not valid at a signing time")
        if _EKU_CODE_SIGNING not in _eku(leaf):
            return no("cert_eku", "the certificate lacks the code-signing EKU")
        if roots.ctlogs:
            stage[0] = "sct"
            sct = _verify_sct(pc, issuer, roots)
            if sct:
                return no("sct", sct)

        # ---- the entry body names this envelope
        stage[0] = "tlog_body"
        eb = js_json_loads(body.decode("utf-8", "replace"))
        if eb is None:
            raise _Fail("entry body is null")
        eb = eb if _is_obj(eb) else {}
        spec = eb.get("spec") if _is_obj(eb.get("spec")) else {}
        if _kind_of({"kind": eb.get("kind"), "version": eb.get("apiVersion")}) != kv:
            return no("tlog_body", "the entry body is not the kind the bundle names")
        payload_sha = hashlib.sha256(payload).hexdigest()
        if kv == "dsse/0.0.1":
            ph = spec.get("payloadHash")
            if _get(ph, "algorithm") != "sha256" or _get(ph, "value") != payload_sha:
                return no("tlog_body", "the entry names another payload")
            sigs = spec.get("signatures") if isinstance(spec.get("signatures"), list) else []
            if len(sigs) != 1 or not _is_obj(sigs[0]):
                return no("tlog_body", "the entry must name exactly one signature")
            if _b64(sigs[0].get("signature")) != dsse_sig:
                return no("tlog_body", "the entry names another signature")
            if _pem_der(_b64(sigs[0].get("verifier")).decode("utf-8", "replace")) != leaf_der:
                return no("tlog_body", "the entry names another certificate")
        elif kv == "intoto/0.0.2":
            # Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
            c = spec.get("content") if _is_obj(spec.get("content")) else {}
            ph = c.get("payloadHash")
            if _get(ph, "algorithm") != "sha256" or _get(ph, "value") != payload_sha:
                return no("tlog_body", "the entry names another payload")
            sigs = _get(c.get("envelope"), "signatures")
            sigs = sigs if isinstance(sigs, list) else []
            if len(sigs) != 1 or not _is_obj(sigs[0]):
                return no("tlog_body", "the entry must name exactly one signature")
            if _b64(_b64(sigs[0].get("sig")).decode("latin-1")) != dsse_sig:
                return no("tlog_body", "the entry names another signature")
            if _pem_der(_b64(sigs[0].get("publicKey")).decode("utf-8", "replace")) != leaf_der:
                return no("tlog_body", "the entry names another certificate")
        else:
            # Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
            h = spec.get("hashedRekordV002")
            data = _get(h, "data")
            hash_name = {"SHA2_256": "sha256", "SHA2_384": "sha384", "SHA2_512": "sha512"}.get(_get(data, "algorithm"))  # type: ignore[arg-type]
            if not hash_name or hash_name != alg:
                return no("tlog_body", "the entry digest algorithm is not the signing key's")
            if _b64(_get(data, "digest")) != hashlib.new(hash_name, pae).digest():
                return no("tlog_body", "the entry names another envelope")
            sg = _get(h, "signature")
            if _b64(_get(sg, "content")) != dsse_sig:
                return no("tlog_body", "the entry names another signature")
            if _b64(_get(_get(_get(sg, "verifier"), "x509Certificate"), "rawBytes")) != leaf_der:
                return no("tlog_body", "the entry names another certificate")

        # ---- DSSE signature
        stage[0] = "signature"
        if not alg:
            return no("signature", "unsupported leaf key type")
        if not _verify(alg, pae, leaf.public_key, dsse_sig):
            return no("signature", "DSSE signature invalid")

        # ---- identity
        stage[0] = "identity"
        identity = _san_identity(pc)
        iss_v2, iss_v1 = _fulcio_ext(pc, 8), _fulcio_ext(pc, 1)
        if iss_v2 is not None and iss_v1 is not None and iss_v2 != iss_v1:
            return no("identity", "the two issuer extensions disagree")
        oidc_issuer = iss_v2 if iss_v2 is not None else iss_v1
        if not oidc_issuer:
            return no("identity", "no OIDC issuer extension")
        source_repo, source_digest, source_ref = _fulcio_ext(pc, 12), _fulcio_ext(pc, 13), _fulcio_ext(pc, 14)

        # ---- statement
        stage[0] = "statement"
        st = js_json_loads(payload.decode("utf-8-sig"))
        if st is None:
            raise _Fail("statement is null")
        if not _is_obj(st) or st.get("_type") != INTOTO_STATEMENT_V1:
            return no("statement", "not an in-toto Statement v1")
        if not isinstance(st.get("subject"), list) or len(st["subject"]) == 0:
            return no("statement", "no subject")
        subjects: List[Dict[str, str]] = []
        for s in st["subject"]:
            d = _get(s, "digest")
            d = d if _is_obj(d) else {}
            for a in ("sha256", "sha512"):
                if isinstance(d.get(a), str):
                    subjects.append({"alg": a, "digest": d[a]})
        if len(subjects) == 0 or len(subjects) > 64:
            return no("statement", "no sha256/sha512 subject digest (or more than 64)")
        if not isinstance(st.get("predicateType"), str):
            return no("statement", "no predicateType")
        core: Dict[str, Any] = {"identity": identity, "oidc_issuer": oidc_issuer}
        for k, v in (("source_repo", source_repo), ("source_ref", source_ref), ("source_digest", source_digest)):
            if v is not None:
                core[k] = v
        core.update({
            "predicate_type": st["predicateType"],
            "subjects": subjects,
            "signed_time": min(times) // 1000,
            "rekor_log_index": log_index,
            "rekor": "v2" if v2 else "v1",
            "timestamps": {"tsa": tsa_count, "set": set_ok},
        })
        return {"ok": True, "core": core, "statement": st}

    try:
        return go()
    except Exception as e:  # fail closed on anything hostile input can raise
        return no(stage[0], "fail closed: %s" % e)


def verify_sigstore_bundle(bundle: Any, roots: PinnedRoots) -> Dict[str, Any]:
    """``verify_sigstore_bundle_core``, then the SLSA v1 predicate: the facts ``provenance_gate`` checks."""
    r = verify_sigstore_bundle_core(bundle, roots)
    if not r["ok"]:
        return r
    st, c = r["statement"], r["core"]
    if st.get("predicateType") != SLSA_PROVENANCE_V1:
        return {"ok": False, "code": "predicate", "detail": "predicate %s is not SLSA provenance v1" % st.get("predicateType")}
    pr = st.get("predicate") if _is_obj(st.get("predicate")) else {}
    bd = pr.get("buildDefinition") if _is_obj(pr.get("buildDefinition")) else {}
    rd = pr.get("runDetails") if _is_obj(pr.get("runDetails")) else {}
    builder_id = _get(rd.get("builder"), "id")
    if not isinstance(bd.get("buildType"), str) or not isinstance(builder_id, str) or not _is_obj(bd.get("externalParameters")):
        return {"ok": False, "code": "predicate", "detail": "buildType, externalParameters and builder.id are required (SLSA Build L1)"}
    deps = bd.get("resolvedDependencies")
    dep0 = deps[0] if isinstance(deps, list) and deps and _is_obj(deps[0]) else None
    facts: Dict[str, Any] = {
        "v": 1, "predicate_type": SLSA_PROVENANCE_V1, "build_type": bd["buildType"], "builder_id": builder_id,
        "subjects": c["subjects"], "identity": c["identity"], "oidc_issuer": c["oidc_issuer"],
    }
    for k in ("source_repo", "source_ref", "source_digest"):
        if k in c:
            facts[k] = c[k]
    if dep0 is not None and isinstance(dep0.get("uri"), str):
        ps: Dict[str, Any] = {"uri": dep0["uri"]}
        commit = _get(dep0.get("digest"), "gitCommit")
        if isinstance(commit, str):
            ps["git_commit"] = commit
        facts["provenance_source"] = ps
    facts["integrated_time"] = c["signed_time"]
    facts["rekor_log_index"] = c["rekor_log_index"]
    return {"ok": True, "facts": facts}
