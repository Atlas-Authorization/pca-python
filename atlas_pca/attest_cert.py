"""A minimal X.509 certificate model for the attestation chain verifiers.

Parsing is done here (the vendor chains use RSASSA-PSS with an explicit DEFAULT `trailerField` that strict ASN.1 parsers
reject and OpenSSL tolerates), so only the public-key and signature primitives come from `cryptography`. The behaviours the
reference gets from node's OpenSSL-backed X509Certificate are reproduced: DN comparison through the OpenSSL text form,
`X509_verify` (outer / inner algorithm must agree), `X509_check_ca == 1`, `X509_check_issued`.
"""
from typing import Any, Dict, List, Optional, Tuple

from .attest_common import (
    crypto,
    ecdsa_verify_der,
    hash_alg,
    key_type,
    load_public_key,
    pem_to_der,
    rsa_pkcs1_verify,
    spki_sha,
)
from .attest_der import CertExtension, DerError, Tlv, _oid_to_dotted, _tlv_at, parse_tbs_extensions, read_tlv


class CertError(ValueError):
    """An X.509 parse failure (the text mirrors the kind of message OpenSSL raises; its wording is not portable)."""


_SIG_ALGS: Dict[str, Tuple[str, str]] = {
    "1.2.840.10045.4.1": ("ec", "sha1"),
    "1.2.840.10045.4.3.1": ("ec", "sha224"),
    "1.2.840.10045.4.3.2": ("ec", "sha256"),
    "1.2.840.10045.4.3.3": ("ec", "sha384"),
    "1.2.840.10045.4.3.4": ("ec", "sha512"),
    "1.2.840.113549.1.1.5": ("rsa", "sha1"),
    "1.2.840.113549.1.1.14": ("rsa", "sha224"),
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
}
_OID_PSS = "1.2.840.113549.1.1.10"
_OID_MGF1 = "1.2.840.113549.1.1.8"
_HASH_OIDS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

_SHORT_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.13": "description",
    "2.5.4.15": "businessCategory",
    "2.5.4.17": "postalCode",
    "2.5.4.41": "name",
    "2.5.4.42": "GN",
    "2.5.4.43": "initials",
    "2.5.4.44": "generationQualifier",
    "2.5.4.46": "dnQualifier",
    "2.5.4.65": "pseudonym",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
    "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
    "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}


def _escape(s: str) -> str:
    out: List[str] = []
    for i, ch in enumerate(s):
        o = ord(ch)
        if o < 0x20 or o == 0x7F:
            out.append("\\%02X" % o)
        elif ch in ',+"\\<>;':
            out.append("\\" + ch)
        elif i == 0 and ch in "# ":
            out.append("\\" + ch)
        elif i == len(s) - 1 and ch == " ":
            out.append("\\ ")
        else:
            out.append(ch)
    return "".join(out)


def _name_value(der: bytes, off: int, t: Tlv) -> str:
    raw = bytes(der[t.start:t.end])
    if t.tag == 0x0C:
        return _escape(raw.decode("utf-8", "replace"))
    if t.tag in (0x13, 0x16, 0x1A, 0x12, 0x14):
        return _escape(raw.decode("latin-1"))
    if t.tag == 0x1E:
        return _escape(raw.decode("utf-16-be", "replace"))
    if t.tag == 0x1C:
        return _escape(raw.decode("utf-32-be", "replace"))
    return "#" + bytes(der[off:t.end]).hex().upper()


def render_name(der: bytes) -> str:
    """OpenSSL's multi-line text of a DN, as node prints `subject` / `issuer` (short names, one entry per line, ' + ' joins an RDN)."""
    seq = _tlv_at(der, 0)
    if seq.tag != 0x30:
        raise CertError("name is not a SEQUENCE")
    lines: List[str] = []
    p = seq.start
    while p < seq.end:
        rdn = _tlv_at(der, p)
        p = rdn.end
        if rdn.tag != 0x31:
            raise CertError("RDN is not a SET")
        parts: List[str] = []
        q = rdn.start
        while q < rdn.end:
            atv = _tlv_at(der, q)
            q = atv.end
            oid_t = _tlv_at(der, atv.start)
            val_off = oid_t.end
            val_t = _tlv_at(der, val_off)
            dotted = _oid_to_dotted(der, oid_t)
            parts.append(_SHORT_NAMES.get(dotted, dotted) + "=" + _name_value(der, val_off, val_t))
        lines.append(" + ".join(parts))
    return "\n".join(lines)


class Cert:
    """A parsed X.509 certificate (DER). Construction raises CertError / DerError on a structural problem."""

    def __init__(self, der: bytes) -> None:
        der = bytes(der)
        try:
            outer = _tlv_at(der, 0)
            if outer.tag != 0x30:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (not a SEQUENCE)")
            self.raw = der[: outer.end]
            tbs = _tlv_at(self.raw, outer.start)
            if tbs.tag != 0x30:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (no tbsCertificate)")
            alg = _tlv_at(self.raw, tbs.end)
            sigv = _tlv_at(self.raw, alg.end)
            if alg.tag != 0x30 or sigv.tag != 0x03 or sigv.end != outer.end or sigv.end - sigv.start < 1:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (bad signature wrapper)")
            self.tbs_der = bytes(self.raw[outer.start:tbs.end])
            self.sig_alg_der = bytes(self.raw[tbs.end:alg.end])
            self.sig_unused = self.raw[sigv.start]
            self.signature = bytes(self.raw[sigv.start + 1:sigv.end])
            off = tbs.start
            el = _tlv_at(self.raw, off)
            if el.tag == 0xA0:
                off = el.end
                el = _tlv_at(self.raw, off)
            if el.tag != 0x02:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (serial)")
            self.serial = bytes(self.raw[el.start:el.end])
            off = el.end
            inner = _tlv_at(self.raw, off)
            if inner.tag != 0x30:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (signature algorithm)")
            self.inner_sig_alg_der = bytes(self.raw[off:inner.end])
            off = inner.end
            iss = _tlv_at(self.raw, off)
            if iss.tag != 0x30:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (issuer)")
            self.issuer_der = bytes(self.raw[off:iss.end])
            off = iss.end
            val = _tlv_at(self.raw, off)
            if val.tag != 0x30:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (validity)")
            off = val.end
            sub = _tlv_at(self.raw, off)
            if sub.tag != 0x30:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (subject)")
            self.subject_der = bytes(self.raw[off:sub.end])
            off = sub.end
            spki = _tlv_at(self.raw, off)
            if spki.tag != 0x30:
                raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (subjectPublicKeyInfo)")
            self.spki_der = bytes(self.raw[off:spki.end])
        except DerError as e:
            raise CertError("error:0688010A:asn1 encoding routines::nested asn1 error (%s)" % e)
        self._key: Any = None
        self._subject: Optional[str] = None
        self._issuer: Optional[str] = None
        self._exts: Optional[Dict[str, CertExtension]] = None
        self._exts_failed = False

    # --- constructors
    @staticmethod
    def from_pem(pem: str) -> "Cert":
        try:
            return Cert(pem_to_der(pem))
        except ValueError as e:
            if isinstance(e, CertError):
                raise
            raise CertError("error:0480006C:PEM routines::no start line")

    # --- names
    @property
    def subject(self) -> str:
        if self._subject is None:
            self._subject = render_name(self.subject_der)
        return self._subject

    @property
    def issuer(self) -> str:
        if self._issuer is None:
            self._issuer = render_name(self.issuer_der)
        return self._issuer

    @property
    def serial_hex(self) -> str:
        """Lowercase hex of the serial number without leading zeros (the form the CRL logic compares)."""
        return self.serial.hex().lstrip("0")

    # --- key
    @property
    def public_key(self) -> Any:
        if self._key is None:
            try:
                self._key = load_public_key(self.spki_der)
            except Exception as e:  # cryptography raises ValueError / UnsupportedAlgorithm
                raise CertError("error:1E08010C:DECODER routines::unsupported (%s)" % e)
        return self._key

    def spki_sha256(self) -> str:
        return spki_sha(self.public_key, "sha256")

    # --- extensions
    def extensions(self) -> Dict[str, CertExtension]:
        if self._exts is None and not self._exts_failed:
            try:
                self._exts = parse_tbs_extensions(self.tbs_der)
            except DerError:
                self._exts_failed = True
        return self._exts or {}

    def _key_cert_sign(self) -> Optional[bool]:
        """None when keyUsage is absent, else whether keyCertSign is asserted."""
        e = self.extensions().get("2.5.29.15")
        if e is None:
            return None
        try:
            bs = read_tlv(e.value, 0)
        except DerError:
            return None
        if bs.tag != 0x03 or bs.end - bs.start < 2:
            return False
        return (e.value[bs.start + 1] & 0x04) != 0

    @property
    def ca(self) -> bool:
        """node's `ca` (X509_check_ca() == 1): BasicConstraints cA true, and keyUsage (when present) allows certificate signing."""
        if self._key_cert_sign() is False:
            return False
        e = self.extensions().get("2.5.29.19")
        if e is None:
            return False
        try:
            seq = read_tlv(e.value, 0)
            if seq.tag != 0x30 or seq.start == seq.end:
                return False
            first = read_tlv(e.value, seq.start, seq.end)
            return first.tag == 0x01 and first.end - first.start >= 1 and e.value[first.start] != 0
        except DerError:
            return False

    def check_issued(self, issuer: "Cert") -> bool:
        """X509_check_issued: the DN link, a matching authority key identifier, and keyCertSign on the issuer."""
        if self.issuer != issuer.subject:
            return False
        akid = self.extensions().get("2.5.29.35")
        skid = issuer.extensions().get("2.5.29.14")
        if akid is not None and skid is not None:
            try:
                seq = read_tlv(akid.value, 0)
                if seq.tag == 0x30 and seq.start < seq.end:
                    k = read_tlv(akid.value, seq.start, seq.end)
                    if k.tag == 0x80:
                        sk = read_tlv(skid.value, 0)
                        if sk.tag == 0x04 and bytes(akid.value[k.start:k.end]) != bytes(skid.value[sk.start:sk.end]):
                            return False
            except DerError:
                return False
        return issuer._key_cert_sign() is not False

    # --- signature
    def verify(self, key: Any) -> bool:
        """X509_verify: the outer and inner signature algorithms must agree, then the signature over the TBS."""
        try:
            if self.sig_alg_der != self.inner_sig_alg_der or self.sig_unused != 0:
                return False
            return _verify_signature(self.sig_alg_der, self.tbs_der, self.signature, key)
        except Exception:
            return False

    def verify_self(self) -> bool:
        return self.verify(self.public_key)


def _alg_parts(alg_der: bytes) -> Tuple[str, Optional[Tlv], bytes]:
    seq = _tlv_at(alg_der, 0)
    oid_t = _tlv_at(alg_der, seq.start)
    dotted = _oid_to_dotted(alg_der, oid_t)
    params = _tlv_at(alg_der, oid_t.end) if oid_t.end < seq.end else None
    return dotted, params, alg_der


def _hash_of_alg_id(der: bytes, t: Tlv) -> str:
    if t.tag != 0x30:
        raise CertError("hash algorithm is not a SEQUENCE")
    oid_t = _tlv_at(der, t.start)
    h = _HASH_OIDS.get(_oid_to_dotted(der, oid_t))
    if h is None:
        raise CertError("unsupported hash algorithm")
    return h


def _pss_params(alg_der: bytes, params: Optional[Tlv]) -> Tuple[str, str, int]:
    """RSASSA-PSS-params with its DEFAULTs (sha1, mgf1-sha1, 20, 1); an explicitly encoded default value is tolerated."""
    hash_name, mgf_hash, salt = "sha1", "sha1", 20
    if params is None or params.tag != 0x30:
        return hash_name, mgf_hash, salt
    p = params.start
    while p < params.end:
        el = _tlv_at(alg_der, p)
        p = el.end
        inner = _tlv_at(alg_der, el.start) if el.start < el.end else None
        if inner is None:
            raise CertError("empty PSS parameter")
        if el.tag == 0xA0:
            hash_name = _hash_of_alg_id(alg_der, inner)
        elif el.tag == 0xA1:
            if inner.tag != 0x30:
                raise CertError("mask generation function is not a SEQUENCE")
            oid_t = _tlv_at(alg_der, inner.start)
            if _oid_to_dotted(alg_der, oid_t) != _OID_MGF1:
                raise CertError("unsupported mask generation function")
            mgf_hash = _hash_of_alg_id(alg_der, _tlv_at(alg_der, oid_t.end))
        elif el.tag == 0xA2:
            if inner.tag != 0x02:
                raise CertError("salt length is not an INTEGER")
            salt = int.from_bytes(alg_der[inner.start:inner.end], "big")
        elif el.tag == 0xA3:
            if inner.tag != 0x02 or int.from_bytes(alg_der[inner.start:inner.end], "big") != 1:
                raise CertError("trailer field is not 1")
        else:
            raise CertError("unknown PSS parameter")
    return hash_name, mgf_hash, salt


def _verify_signature(alg_der: bytes, msg: bytes, sig: bytes, key: Any) -> bool:
    dotted, params, _ = _alg_parts(alg_der)
    if dotted in _SIG_ALGS:
        kind, hname = _SIG_ALGS[dotted]
        if kind == "ec":
            return ecdsa_verify_der(key, sig, msg, hname)
        return rsa_pkcs1_verify(key, sig, msg, hname)
    if dotted == _OID_PSS:
        c = crypto()
        if key_type(key) != "rsa":
            return False
        hname, mgf_h, salt = _pss_params(alg_der, params)
        try:
            key.verify(bytes(sig), bytes(msg), c.padding.PSS(mgf=c.padding.MGF1(hash_alg(mgf_h)), salt_length=salt), hash_alg(hname))
            return True
        except (c.InvalidSignature, ValueError, TypeError):
            return False
    return False


def verify_with_alg(alg_der: bytes, msg: bytes, sig: bytes, key: Any) -> bool:
    """Public entry used by the CRL / OCSP code for an AlgorithmIdentifier."""
    try:
        return _verify_signature(alg_der, msg, sig, key)
    except Exception:
        return False
