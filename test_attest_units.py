"""Unit tests of the native vendor attestation verifiers (atlas_pca.attest*): the strict DER / X.509 readers, the report / quote /
transcript parsers, the pure policy and binding checks, a fail-closed table per vendor (every row is "missing / invalid X =>
the exact result"), and end-to-end accept / reject paths for the token vendors (Azure MAA, GCP Confidential Space) over
certificates and keys minted with `cryptography`. The shared language-neutral vectors are replayed by
test_attestation_vectors.py."""
import base64
import datetime
import hashlib
import json
import os
import unittest

from atlas_pca import attest_der as D
from atlas_pca.attest import VENDORS, AttestConstructError, verifier_from_config
from atlas_pca.attest_amd import AmdSnpVerifier, BigU64, check_azure_runtime_data_binding, check_sev_snp_policy, check_vcek_report_binding, parse_sev_snp_report
from atlas_pca.attest_azure import AzureMaaVerifier
from atlas_pca.attest_common import (
    attestation_binding,
    decode_canonical_b64url,
    js_json_loads,
    node_b64decode,
    CanonicalJwsError,
    JsError,
)
from atlas_pca.attest_gcp import GcpConfidentialSpaceVerifier
from atlas_pca.attest_intel import IntelDcapVerifier, extract_pck_fmspc_and_tcb, parse_dcap_quote
from atlas_pca.attest_nvidia import NvidiaSpdmVerifier, format_vbios_version, parse_nvidia_spdm_evidence
from atlas_pca.attest_xml import XmlError, canonicalize, parse_xml

try:
    import cryptography  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
REQUIRE = os.environ.get("PCA_REQUIRE_ATTEST") == "1"
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO or REQUIRE, "needs the `cryptography` package (extra `attest`)")

EXP = {"holderPub": "holder-key", "grantRef": "grant-1", "epoch": 3, "nonce": "server-nonce-0123456789"}


# ---------------------------------------------------------------------------------------------- a tiny DER builder
def tlv(tag, content=b""):
    n = len(content)
    if n < 0x80:
        h = bytes([tag, n])
    elif n < 0x100:
        h = bytes([tag, 0x81, n])
    else:
        h = bytes([tag, 0x82, n >> 8, n & 255])
    return h + content


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def octets(b):
    return tlv(0x04, b)


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def integer(n):
    return tlv(0x02, bytes([n]))


def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    out = []
    for x in [40 * a[0] + a[1]] + a[2:]:
        chunk = [x & 0x7F]
        x >>= 7
        while x:
            chunk.append((x & 0x7F) | 0x80)
            x >>= 7
        out += reversed(chunk)
    return tlv(0x06, bytes(out))


def ext(dotted, critical, value):
    return seq(oid(dotted), boolean(True) if critical else b"", octets(value))


def bc(ca, path_len=None):
    return seq(*(([boolean(True)] if ca else []) + ([integer(path_len)] if path_len is not None else [])))


KU_CERT_SIGN = tlv(0x03, b"\x02\x04")  # keyCertSign (bit 5), 2 unused bits
KU_DIGITAL_SIGNATURE = tlv(0x03, b"\x07\x80")


def tbs_of(*exts):
    return seq(integer(1), tlv(0xA3, seq(*exts))) if exts else seq(integer(1))


def cert_of(*exts):
    return seq(tbs_of(*exts), seq(), tlv(0x03, b"\x00"))


def ms(y, mo, d, h=0, mi=0, s=0):
    return int(datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc).timestamp()) * 1000


def b64(b):
    return base64.b64encode(b).decode("ascii")


def b64u(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def raises(test, fn, message):
    with test.assertRaises(Exception) as cm:
        fn()
    test.assertEqual(str(cm.exception), message)


# ---------------------------------------------------------------------------------------------- strict DER / X.509
class StrictDer(unittest.TestCase):
    def test_read_tlv_rejections(self):
        raises(self, lambda: D.read_tlv(b"\x30", 0), "DER: truncated header")
        raises(self, lambda: D.read_tlv(b"\x1f\x01\x00", 0), "DER: multi-byte tags are not supported")
        raises(self, lambda: D.read_tlv(b"\x30\x84\x00\x00\x00\x01\x00", 0), "DER: unsupported length form")
        raises(self, lambda: D.read_tlv(b"\x30\x80", 0), "DER: unsupported length form")
        raises(self, lambda: D.read_tlv(b"\x30\x82\x01", 0), "DER: truncated length")
        raises(self, lambda: D.read_tlv(b"\x30\x82\x00\x80" + b"\x00" * 128, 0), "DER: non-minimal length (leading zero)")
        raises(self, lambda: D.read_tlv(b"\x30\x81\x05" + b"\x00" * 5, 0), "DER: non-minimal length (long form below 128)")
        raises(self, lambda: D.read_tlv(b"\x30\x05\x00", 0), "DER: element overruns its parent")

    def test_read_tlv_accepts_the_minimal_forms(self):
        self.assertEqual(tuple(D.read_tlv(b"\x04\x02ab", 0)), (4, 2, 4))
        self.assertEqual(tuple(D.read_tlv(b"\x04\x81\x80" + b"x" * 128, 0)), (4, 3, 131))
        self.assertEqual(tuple(D.read_tlv(b"\x04\x82\x01\x00" + b"x" * 256, 0)), (4, 4, 260))

    def test_role_info(self):
        self.assertEqual(
            D.read_cert_role_info(cert_of(ext("2.5.29.19", True, bc(True, 0)), ext("2.5.29.15", True, KU_CERT_SIGN))),
            {"hasBasicConstraints": True, "ca": True, "pathLen": 0, "hasKeyUsage": True, "keyCertSign": True},
        )
        self.assertEqual(
            D.read_cert_role_info(cert_of(ext("2.5.29.19", True, bc(False)))),
            {"hasBasicConstraints": True, "ca": False, "hasKeyUsage": False, "keyCertSign": False},
        )
        self.assertEqual(
            D.read_cert_role_info(cert_of(ext("2.5.29.15", False, KU_DIGITAL_SIGNATURE))),
            {"hasBasicConstraints": False, "ca": False, "hasKeyUsage": True, "keyCertSign": False},
        )
        self.assertEqual(D.read_cert_role_info(cert_of()), {"hasBasicConstraints": False, "ca": False, "hasKeyUsage": False, "keyCertSign": False})

    def test_role_info_rejections(self):
        raises(self, lambda: D.read_cert_role_info(cert_of(ext("2.5.29.19", True, bc(True)), ext("2.5.29.19", True, bc(True)))), "duplicate BasicConstraints extension")
        raises(self, lambda: D.read_cert_role_info(cert_of(ext("2.5.29.15", True, KU_CERT_SIGN), ext("2.5.29.15", True, KU_CERT_SIGN))), "duplicate keyUsage extension")
        raises(self, lambda: D.read_cert_role_info(cert_of(ext("2.5.29.15", True, tlv(0x03, b"\x08\x04")))), "keyUsage BIT STRING has more than 7 unused bits")
        raises(self, lambda: D.read_cert_role_info(cert_of(ext("2.5.29.15", True, tlv(0x03, b"\x00")))), "keyUsage is not a BIT STRING")
        raises(self, lambda: D.read_cert_role_info(cert_of(ext("2.5.29.19", True, seq(boolean(True), integer(0), integer(0))))), "BasicConstraints has trailing data")
        raises(self, lambda: D.read_cert_role_info(cert_of(ext("2.5.29.19", True, seq(boolean(True), tlv(0x02, b"\x80"))))), "BasicConstraints pathLenConstraint malformed")
        raises(self, lambda: D.read_cert_role_info(cert_of(ext("2.5.29.19", True, seq(tlv(0x01, b"\xff\xff"))))), "BasicConstraints cA is not one byte")
        raises(self, lambda: D.read_cert_role_info(cert_of(ext("2.5.29.19", True, tlv(0x31)))), "BasicConstraints is not a SEQUENCE")
        raises(self, lambda: D.read_cert_role_info(cert_of() + b"\x00"), "trailing bytes after the certificate")
        raises(self, lambda: D.read_cert_role_info(b"\x31" + cert_of()[1:]), "certificate is not a DER SEQUENCE")
        raises(self, lambda: D.read_cert_role_info(seq(integer(1))), "certificate has no tbsCertificate")

    def test_tbs_extensions(self):
        e1, e2, e3 = ext("2.5.29.19", True, bc(True, 0)), ext("2.5.29.15", True, KU_CERT_SIGN), ext("1.2.3.4", False, b"\x09")
        got = D.parse_tbs_extensions(tbs_of(e1, e2, e3))
        self.assertEqual(list(got.keys()), ["2.5.29.19", "2.5.29.15", "1.2.3.4"])
        self.assertEqual(got["2.5.29.19"], D.CertExtension(True, bc(True, 0)))
        self.assertEqual(got["2.5.29.15"], D.CertExtension(True, KU_CERT_SIGN))
        self.assertEqual(got["1.2.3.4"], D.CertExtension(False, b"\x09"))
        self.assertEqual(D.parse_tbs_extensions(tbs_of()), {})

    def test_tbs_extension_first_arc_forms(self):
        got = D.parse_tbs_extensions(tbs_of(ext("0.9.1", True, b"\x01"), ext("1.39.5", False, b"\x01"), ext("2.100.3", False, b"\x01")))
        self.assertEqual(list(got.keys()), ["0.9.1", "1.39.5", "2.100.3"])

    def test_tbs_extension_rejections(self):
        one = lambda inner: seq(integer(1), tlv(0xA3, seq(inner)))  # noqa: E731
        raises(self, lambda: D.parse_tbs_extensions(tbs_of(ext("1.2.3", False, b"\x01"), ext("1.2.3", False, b"\x02"))), "duplicate extension 1.2.3")
        raises(self, lambda: D.parse_tbs_extensions(seq(integer(1), tlv(0xA3, seq(ext("1.2.3", False, b"\x01"))), tlv(0xA3, seq(ext("1.2.4", False, b"\x01"))))), "duplicate [3] extensions block")
        raises(self, lambda: D.parse_tbs_extensions(seq(integer(1), tlv(0xA3, seq()))), "empty Extensions SEQUENCE")
        raises(self, lambda: D.parse_tbs_extensions(seq(integer(1), tlv(0xA3, seq(ext("1.2.3", False, b"\x01"))), tlv(0xA1, b"\x01"))), "extensions block is not the last TBS element")
        raises(self, lambda: D.parse_tbs_extensions(seq(integer(1), tlv(0xA3, seq(ext("1.2.3", False, b"\x01")) + b"\x00\x00"))), "trailing bytes after the Extensions SEQUENCE")
        raises(self, lambda: D.parse_tbs_extensions(seq(integer(1), tlv(0xA3, tlv(0x31)))), "extensions is not a SEQUENCE")
        raises(self, lambda: D.parse_tbs_extensions(one(seq(oid("1.2.3"), tlv(0x01, b"\x00"), octets(b"\x01")))), "extension 1.2.3 has a non-DER critical flag")
        raises(self, lambda: D.parse_tbs_extensions(one(seq(oid("1.2.3"), tlv(0x01, b"\x01"), octets(b"\x01")))), "extension 1.2.3 has a non-DER critical flag")
        raises(self, lambda: D.parse_tbs_extensions(one(seq(oid("1.2.3"), octets(b"\x01"), octets(b"\x02")))), "extension 1.2.3 has trailing bytes")
        raises(self, lambda: D.parse_tbs_extensions(one(seq(oid("1.2.3"), tlv(0x05, b"\x01")))), "extension 1.2.3 value is not an OCTET STRING")
        raises(self, lambda: D.parse_tbs_extensions(one(seq(tlv(0x04, b"\x2a"), octets(b"\x01")))), "extension OID is malformed")
        raises(self, lambda: D.parse_tbs_extensions(one(seq(tlv(0x06, b""), octets(b"\x01")))), "extension OID is malformed")
        raises(self, lambda: D.parse_tbs_extensions(one(seq(tlv(0x06, b"\x2a\x80\x01"), octets(b"\x01")))), "extension OID has a non-minimal arc")
        raises(self, lambda: D.parse_tbs_extensions(one(seq(tlv(0x06, b"\x2a\x83"), octets(b"\x01")))), "extension OID is truncated")
        raises(self, lambda: D.parse_tbs_extensions(tbs_of() + b"\x00"), "trailing bytes after tbsCertificate")
        raises(self, lambda: D.parse_tbs_extensions(tlv(0x31)), "tbsCertificate is not a SEQUENCE")

    def test_unrecognised_critical_extension(self):
        unknown = ext("1.2.3.4.5", True, b"\x01")
        base = [ext("2.5.29.19", True, bc(True, 0)), ext("2.5.29.15", True, KU_CERT_SIGN)]
        self.assertIsNone(D.unrecognised_critical_extension(cert_of(*base)))
        self.assertEqual(D.unrecognised_critical_extension(cert_of(*(base + [unknown]))), "1.2.3.4.5")
        self.assertIsNone(D.unrecognised_critical_extension(cert_of(*(base + [ext("1.2.3.4.5", False, b"\x01")]))))
        self.assertIsNone(D.unrecognised_critical_extension(cert_of(*(base + [unknown])), ["2.5.29.19", "2.5.29.15", "1.2.3.4.5"]))
        self.assertEqual(D.unrecognised_critical_extension(cert_of(*base), []), "2.5.29.19")

    def test_chain_roles(self):
        leaf = cert_of(ext("2.5.29.19", True, bc(False)))
        ca0 = cert_of(ext("2.5.29.19", True, bc(True, 0)), ext("2.5.29.15", True, KU_CERT_SIGN))
        root = cert_of(ext("2.5.29.19", True, bc(True, 5)), ext("2.5.29.15", True, KU_CERT_SIGN))
        self.assertIsNone(D.check_chain_roles([leaf, ca0, root]))
        self.assertIsNone(D.check_chain_roles([root]))
        self.assertEqual(D.check_chain_roles([leaf, ca0, ca0, root]), "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)")
        self.assertEqual(
            D.check_chain_roles([cert_of(ext("2.5.29.19", True, bc(True))), ca0, root]),
            "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)",
        )
        self.assertEqual(D.check_chain_roles([leaf, cert_of(ext("2.5.29.15", True, KU_CERT_SIGN)), root]), "issuer certificate at depth 1 has no BasicConstraints (not a CA)")
        self.assertEqual(D.check_chain_roles([leaf, cert_of(ext("2.5.29.19", True, bc(False))), root]), "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)")
        self.assertEqual(
            D.check_chain_roles([leaf, cert_of(ext("2.5.29.19", True, bc(True, 0)), ext("2.5.29.15", True, KU_DIGITAL_SIGNATURE)), root]),
            "issuer certificate at depth 1 keyUsage lacks keyCertSign",
        )
        self.assertIsNone(D.check_chain_roles([leaf, cert_of(ext("2.5.29.19", True, bc(True, 0))), root]))
        self.assertEqual(D.check_chain_roles([leaf, b"\x01\x02\x03", root]), "certificate extension parse failed: DER: element overruns its parent")
        self.assertEqual(D.check_chain_roles([leaf, ca0 + b"\x00", root]), "certificate extension parse failed: trailing bytes after the certificate")

    def test_der_time(self):
        utc = lambda s: D.parse_der_time(0x17, s)  # noqa: E731
        gen = lambda s: D.parse_der_time(0x18, s)  # noqa: E731
        self.assertEqual(utc("260102030405Z"), ms(2026, 1, 2, 3, 4, 5))
        self.assertEqual(utc("500101000000Z"), ms(1950, 1, 1))
        self.assertEqual(utc("491231235959Z"), ms(2049, 12, 31, 23, 59, 59))
        self.assertEqual(gen("20600101000000Z"), ms(2060, 1, 1))
        self.assertEqual(gen("20240229000000Z"), ms(2024, 2, 29))
        for bad in ("261301000000Z", "260431000000Z", "250229000000Z", "260101240000Z", "260101006000Z", "260101000060Z", "260100000000Z", "2601020304Z", "260102030405", "26010203040AZ"):
            self.assertIsNone(utc(bad), bad)
        self.assertIsNone(gen("260102030405Z"))
        self.assertIsNone(D.parse_der_time(0x16, "260102030405Z"))
        self.assertIsNone(D.parse_der_time(0x18, "2026010203040+Z"))

    def test_der_validity(self):
        def c(nb, na, version=True):
            validity = seq(tlv(0x17, nb), tlv(0x17, na))
            tbs = seq(*([tlv(0xA0, integer(2))] if version else []), integer(7), seq(), seq(), validity, seq())
            return seq(tbs, seq(), tlv(0x03, b"\x00"))

        self.assertEqual(D.der_validity_ms(c(b"260102030405Z", b"301231235959Z")), (ms(2026, 1, 2, 3, 4, 5), ms(2030, 12, 31, 23, 59, 59)))
        self.assertEqual(D.der_validity_ms(c(b"260102030405Z", b"301231235959Z", False)), (ms(2026, 1, 2, 3, 4, 5), ms(2030, 12, 31, 23, 59, 59)))
        self.assertEqual(D.der_validity_ms(c(b"261302030405Z", b"301231235959Z")), (None, ms(2030, 12, 31, 23, 59, 59)))
        self.assertEqual(D.der_validity_ms(b"\x01\x02\x03"), (None, None))
        self.assertTrue(D.x509_valid_at(c(b"260102030405Z", b"301231235959Z"), ms(2027, 1, 1)))
        self.assertFalse(D.x509_valid_at(c(b"260102030405Z", b"301231235959Z"), ms(2026, 1, 2, 3, 4, 4)))
        self.assertTrue(D.x509_valid_at(c(b"260102030405Z", b"301231235959Z"), ms(2026, 1, 2, 3, 4, 4), 1000))
        self.assertFalse(D.x509_valid_at(c(b"261302030405Z", b"301231235959Z"), ms(2027, 1, 1)))


# ---------------------------------------------------------------------------------------------- common helpers
class Common(unittest.TestCase):
    def test_binding_known_answer_and_refusals(self):
        def lp(s):
            b = s.encode("utf-8")
            return len(b).to_bytes(4, "big") + b

        want = hashlib.sha512(b"atlas-pca/attest-bind/v1\x00" + lp("holder-key") + lp("grant-1") + (3).to_bytes(8, "big") + lp("server-nonce-0123456789")).digest()
        self.assertEqual(attestation_binding(EXP), want)
        self.assertEqual(attestation_binding({"holder_pub": "holder-key", "grant_ref": "grant-1", "epoch": 3.0, "nonce": "server-nonce-0123456789"}), want)
        for field, msg in (("holderPub", "binding: holderPub required"), ("grantRef", "binding: grantRef required"), ("nonce", "binding: nonce required")):
            raises(self, lambda f=field: attestation_binding(dict(EXP, **{f: ""})), msg)
        for epoch in (-1, 1.5, True, "1", None, 2**53):
            raises(self, lambda e=epoch: attestation_binding(dict(EXP, epoch=e)), "binding: epoch must be a non-negative safe integer")
        raises(self, lambda: attestation_binding(None), "binding: holderPub required")
        self.assertEqual(attestation_binding(dict(EXP, epoch=2**53 - 1)), hashlib.sha512(b"atlas-pca/attest-bind/v1\x00" + lp("holder-key") + lp("grant-1") + (2**53 - 1).to_bytes(8, "big") + lp("server-nonce-0123456789")).digest())

    def test_node_base64_is_lenient_like_buffer_from(self):
        self.assertEqual(node_b64decode("AQID"), b"\x01\x02\x03")
        self.assertEqual(node_b64decode("AQI="), b"\x01\x02")
        self.assertEqual(node_b64decode("AQ\nID"), b"\x01\x02\x03")
        self.assertEqual(node_b64decode("-_8"), b"\xfb\xff")
        self.assertEqual(node_b64decode("+/8="), b"\xfb\xff")
        self.assertEqual(node_b64decode(""), b"")

    def test_canonical_base64url(self):
        self.assertEqual(decode_canonical_b64url("AQID"), b"\x01\x02\x03")
        self.assertEqual(decode_canonical_b64url(""), b"")
        for seg, why in (("AQI=", "bad-character"), ("AQ+D", "bad-character"), ("AQI ", "bad-character"), ("A", "non-canonical-base64url (impossible length)"), ("AQJ", "non-canonical-base64url")):
            with self.assertRaises(CanonicalJwsError) as cm:
                decode_canonical_b64url(seg)
            self.assertEqual(str(cm.exception), "non-canonical compact JWS: " + why)

    def test_json_parse_messages_follow_v8(self):
        self.assertEqual(js_json_loads('{"a":[1,2.5,"x",null]}'), {"a": [1, 2.5, "x", None]})
        for text, msg in (
            ("not json", "Unexpected token 'o', \"not json\" is not valid JSON"),
            ("nope", "Unexpected token 'o', \"nope\" is not valid JSON"),
            ("", "Unexpected end of JSON input"),
            ('{"a":', "Unexpected end of JSON input"),
            ("[1,]", "Unexpected token ']', \"[1,]\" is not valid JSON"),
            ("undefined", '"undefined" is not valid JSON'),
            ("NaN", '"NaN" is not valid JSON'),
        ):
            with self.assertRaises(JsError) as cm:
                js_json_loads(text)
            self.assertEqual(str(cm.exception), msg, text)


# ---------------------------------------------------------------------------------------------- pure checks per vendor
def sev_report(**f):
    b = bytearray(1184)
    b[0:4] = (f.get("version", 2)).to_bytes(4, "little")
    b[4:8] = (f.get("guest_svn", 5)).to_bytes(4, "little")
    b[8:16] = (f.get("policy", 0x30000)).to_bytes(8, "little")
    b[0x30:0x34] = (f.get("vmpl", 0)).to_bytes(4, "little")
    b[0x34:0x38] = (f.get("signature_algo", 1)).to_bytes(4, "little")
    b[0x50:0x90] = f.get("report_data", bytes(64))
    b[0x90:0xC0] = f.get("measurement", bytes([0xAB]) * 48)
    b[0xC0:0xE0] = f.get("host_data", bytes([0x11]) * 32)
    b[0x180:0x188] = (f.get("reported_tcb", 5)).to_bytes(8, "little")
    b[0x1A0:0x1E0] = f.get("chip_id", bytes([0x22]) * 64)
    b[0x1E0:0x1E8] = (f.get("committed_tcb", 5)).to_bytes(8, "little")
    b[0x1F0:0x1F8] = (f.get("launch_tcb", 5)).to_bytes(8, "little")
    return bytes(b)


class AmdPure(unittest.TestCase):
    def test_report_fields(self):
        r = parse_sev_snp_report(sev_report(guest_svn=9, vmpl=2, reported_tcb=0x0807000000000102))
        self.assertEqual((r["guest_svn"], r["vmpl"], r["reported_tcb"], r["signature_algo"], r["policy"]), (9, 2, 0x0807000000000102, 1, 0x30000))
        self.assertEqual(r["measurement"], bytes([0xAB]) * 48)
        self.assertEqual(len(r["signed"]), 0x2A0)
        raises(self, lambda: parse_sev_snp_report(bytes(10)), "parseSevSnpReport: report too short (10 < 816)")
        parse_sev_snp_report(bytes(816))

    def test_policy_gates_in_order(self):
        r = parse_sev_snp_report(sev_report(guest_svn=5, vmpl=1, policy=0x30000 | (1 << 19), signature_algo=2, reported_tcb=5))
        self.assertEqual(check_sev_snp_policy(r, {}), "unexpected signature_algo 2")
        self.assertEqual(check_sev_snp_policy(r, {"requireEcdsaP384": False}), "guest policy has the DEBUG bit set (host can inspect the guest)")
        self.assertEqual(check_sev_snp_policy(r, {"requireEcdsaP384": False, "allowDebug": True, "minGuestSvn": 6}), "guest_svn 5 below minimum 6")
        base = {"requireEcdsaP384": False, "allowDebug": True}
        self.assertEqual(check_sev_snp_policy(r, dict(base, minReportedTcb=BigU64(6))), "reported_tcb below minimum (rollback?)")
        self.assertEqual(check_sev_snp_policy(r, dict(base, minCommittedTcb=BigU64(6))), "committed_tcb below minimum (rollback?)")
        self.assertEqual(check_sev_snp_policy(r, dict(base, minLaunchTcb=BigU64(6))), "launch_tcb below minimum")
        self.assertEqual(check_sev_snp_policy(r, dict(base, minReportedTcb=BigU64(2**64 - 1))), "reported_tcb below minimum (rollback?)")
        self.assertEqual(check_sev_snp_policy(r, base), "vmpl 1 is not the required 0")
        self.assertEqual(check_sev_snp_policy(r, dict(base, requireVmpl=2)), "vmpl 1 is not the required 2")
        self.assertIsNone(check_sev_snp_policy(r, dict(base, requireVmpl=1, minReportedTcb=BigU64(5), minGuestSvn=5)))
        self.assertIsNone(check_sev_snp_policy(r, dict(base, requireVmpl="any")))

    def test_allowlists_compare_case_insensitively(self):
        r = parse_sev_snp_report(sev_report())
        base = {"requireVmpl": 0}
        self.assertEqual(check_sev_snp_policy(r, dict(base, measurements=["cd" * 48])), "measurement not in policy allowlist")
        self.assertIsNone(check_sev_snp_policy(r, dict(base, measurements=["00" * 48, "AB" * 48])))
        self.assertEqual(check_sev_snp_policy(r, dict(base, hostData=["00" * 32])), "host_data not in policy allowlist")
        self.assertIsNone(check_sev_snp_policy(r, dict(base, hostData=["11" * 32])))
        self.assertEqual(check_sev_snp_policy(r, dict(base, chipIds=["00" * 64])), "chip_id not in policy allowlist")
        self.assertIsNone(check_sev_snp_policy(r, dict(base, chipIds=["22" * 64])))
        self.assertIsNone(check_sev_snp_policy(r, dict(base, measurements=[], hostData=[], chipIds=[])))

    def test_vcek_binding(self):
        tcb = 4 | (2 << 8) | (3 << 48) | (200 << 56)
        report = parse_sev_snp_report(sev_report(reported_tcb=tcb))
        hw = bytes([0x22]) * 64

        def tbs(**o):
            exts = []
            if o.get("hw", hw) is not None:
                exts.append(ext("1.3.6.1.4.1.3704.1.4", o.get("hw_critical", False), o.get("hw", hw)))
            for oid_, key, val in (("1.3.6.1.4.1.3704.1.3.1", "bl", integer(4)), ("1.3.6.1.4.1.3704.1.3.2", "tee", integer(2)), ("1.3.6.1.4.1.3704.1.3.3", "snp", integer(3)), ("1.3.6.1.4.1.3704.1.3.8", "uc", tlv(0x02, b"\x00\xc8"))):
                if o.get(key, val) is not None:
                    exts.append(ext(oid_, False, o.get(key, val)))
            return tbs_of(*exts)

        self.assertIsNone(check_vcek_report_binding(tbs(), report))
        self.assertEqual(check_vcek_report_binding(tbs(hw=None), report), "VCEK certificate has no CHIP_ID (hwID) extension")
        self.assertEqual(check_vcek_report_binding(tbs(hw_critical=True), report), "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)")
        self.assertEqual(check_vcek_report_binding(tbs(hw=hw[:63]), report), "VCEK CHIP_ID (hwID) extension is 63 bytes, expected 64")
        self.assertEqual(check_vcek_report_binding(tbs(hw=bytes([0x23]) * 64), report), "VCEK CHIP_ID does not match report chip_id")
        self.assertEqual(check_vcek_report_binding(tbs(snp=integer(4)), report), "VCEK snp SPL 4 does not match report reported_tcb (3) — TCB downgrade?")
        self.assertEqual(check_vcek_report_binding(tbs(uc=integer(100)), report), "VCEK microcode SPL 100 does not match report reported_tcb (200) — TCB downgrade?")
        self.assertEqual(check_vcek_report_binding(tbs(bl=None), report), "VCEK certificate has no bootloader SPL extension")
        self.assertEqual(check_vcek_report_binding(tbs(tee=tlv(0x04, b"\x01")), report), "VCEK tee SPL extension is not a DER INTEGER")
        self.assertEqual(check_vcek_report_binding(tbs(tee=tlv(0x02, b"\x80")), report), "VCEK tee SPL extension is negative")
        self.assertEqual(check_vcek_report_binding(tbs(tee=tlv(0x02, b"\x00\x05")), report), "VCEK tee SPL extension is a non-minimal INTEGER")
        self.assertEqual(check_vcek_report_binding(tbs(tee=tlv(0x02, b"\x01\x05")), report), "VCEK tee SPL extension is out of range (> 255)")
        self.assertEqual(check_vcek_report_binding(tbs(tee=tlv(0x02, b"\x00\x00\x05")), report), "VCEK tee SPL extension has a wrong-length INTEGER")
        self.assertEqual(check_vcek_report_binding(tbs(tee=tlv(0x02, b"")), report), "VCEK tee SPL extension is not a DER INTEGER")
        self.assertEqual(check_vcek_report_binding(b"\x01", report), "VCEK extensions malformed: DER: truncated header")

    def test_azure_runtime_data_binding(self):
        def case(runtime, report_data=None):
            rd = json.dumps(runtime).encode() if not isinstance(runtime, bytes) else runtime
            data = report_data if report_data is not None else hashlib.sha256(rd).digest() + bytes(32)
            return check_azure_runtime_data_binding(data, rd, EXP)

        good = {"user-data": attestation_binding(EXP).hex(), "keys": []}
        self.assertIsNone(case(good))
        self.assertIsNone(case({"user-data": attestation_binding(EXP).hex().upper()}))
        self.assertEqual(check_azure_runtime_data_binding(bytes(63), b"{}", EXP), "report_data is not 64 bytes")
        self.assertEqual(case(good, hashlib.sha256(b"x").digest() + b"\x01" + bytes(31)), "report_data[32:64] is not zero (not an Azure runtime-data hash)")
        self.assertEqual(case(good, bytes(64)), "sha256(runtime data) does not equal the quote report_data")
        self.assertEqual(case(b"not json"), "runtime data is not valid JSON")
        self.assertEqual(case(b"[1]"), "runtime data is not a JSON object")
        self.assertEqual(case({"keys": []}), "runtime data carries no 64-byte hex user-data")
        self.assertEqual(case({"user-data": "ab" * 63}), "runtime data carries no 64-byte hex user-data")
        self.assertEqual(case({"user-data": "zz" * 64}), "runtime data carries no 64-byte hex user-data")
        other = attestation_binding(dict(EXP, nonce="other-nonce-0123456789")).hex()
        self.assertEqual(case({"user-data": other}), "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)")
        rd = json.dumps(good).encode()
        self.assertEqual(check_azure_runtime_data_binding(hashlib.sha256(rd).digest() + bytes(32), rd, dict(EXP, holderPub="")), "binding not constructible: binding: holderPub required")


def td_quote_header(version=4, key=2, tee=0x81, size=700, sig_len=None):
    b = bytearray(size)
    b[0:2] = version.to_bytes(2, "little")
    b[2:4] = key.to_bytes(2, "little")
    b[4:8] = tee.to_bytes(4, "little")
    if sig_len is not None:
        b[632:636] = sig_len.to_bytes(4, "little")
    return bytes(b)


class IntelPure(unittest.TestCase):
    def test_quote_parser_rejections(self):
        raises(self, lambda: parse_dcap_quote(bytes(10)), "parseDcapQuote: too short for header + TD report + sig length")
        raises(self, lambda: parse_dcap_quote(td_quote_header(version=3)), "parseDcapQuote: unsupported quote version 3 (expected 4)")
        raises(self, lambda: parse_dcap_quote(td_quote_header(key=3)), "parseDcapQuote: unsupported attestation key type 3 (expected ECDSA-P256 = 2)")
        raises(self, lambda: parse_dcap_quote(td_quote_header(tee=0x80)), "parseDcapQuote: unexpected TEE type 0x80 (expected TDX = 0x81)")
        raises(self, lambda: parse_dcap_quote(td_quote_header(sig_len=100000)), "parseDcapQuote: signature data (100000) overruns the quote")
        raises(self, lambda: parse_dcap_quote(td_quote_header(size=800, sig_len=100)), "parseDcapQuote: truncated reading attestation public key")
        raises(self, lambda: parse_dcap_quote(td_quote_header(size=800, sig_len=130)), "parseDcapQuote: truncated reading outer cert-data header")
        raises(self, lambda: parse_dcap_quote(td_quote_header(size=800, sig_len=140)), "parseDcapQuote: outer cert-data type 0 (expected QE-report-cert-data = 6)")

    def test_pck_extension_reader(self):
        fm_oid = bytes.fromhex("060a2a864886f84d010d0104")
        tcb_oid = bytes.fromhex("060a2a864886f84d010d0102")
        comp = lambda n, val: seq(tlv(0x06, bytes.fromhex("2a864886f84d010d0102") + bytes([n])), val)  # noqa: E731
        fmspc = bytes.fromhex("00606a000000")
        comps = [comp(i, integer(i)) for i in range(1, 17)] + [comp(17, integer(11)), comp(18, octets(bytes(16)))]
        leaf = b"junk" + fm_oid + octets(fmspc) + tcb_oid + seq(*comps) + b"tail"
        self.assertEqual(extract_pck_fmspc_and_tcb(leaf), {"fmspc": fmspc, "sgxTcbComponents": bytes(range(1, 17)), "pcesvn": 11})
        raises(self, lambda: extract_pck_fmspc_and_tcb(b"junk"), "extractPckFmspcAndTcb: FMSPC OID not found in certificate")
        raises(self, lambda: extract_pck_fmspc_and_tcb(fm_oid + octets(fmspc[:5])), "extractPckFmspcAndTcb: malformed FMSPC OCTET STRING")
        raises(self, lambda: extract_pck_fmspc_and_tcb(fm_oid + octets(fmspc)), "extractPckFmspcAndTcb: TCB OID not found in certificate")
        raises(self, lambda: extract_pck_fmspc_and_tcb(fm_oid + octets(fmspc) + tcb_oid + seq(*comps[:16])), "extractPckFmspcAndTcb: PCESVN not found in TCB extension")
        raises(self, lambda: extract_pck_fmspc_and_tcb(fm_oid + octets(fmspc) + tcb_oid + tlv(0x31)), "extractPckFmspcAndTcb: malformed TCB SEQUENCE")


def spdm(blocks=1, nonce=None, extra=b"", num_blocks=None, request_code=0xE0, response_code=0x60):
    nonce = nonce or bytes([7]) * 32
    request = bytes([0x11, request_code, 0, 0]) + nonce + bytes([0])
    records = b"".join(bytes([i + 1, 1]) + (51).to_bytes(2, "little") + bytes([0]) + (48).to_bytes(2, "little") + bytes([i]) * 48 for i in range(blocks))
    opaque = (3).to_bytes(2, "little") + (3).to_bytes(2, "little") + b"abc" + (6).to_bytes(2, "little") + (5).to_bytes(2, "little") + bytes(5)
    response = bytes([0x11, response_code, 0, 0, blocks if num_blocks is None else num_blocks]) + len(records).to_bytes(3, "little") + records + bytes([9]) * 32 + len(opaque).to_bytes(2, "little") + opaque + bytes([0xEE]) * 96
    return request + response + extra


class NvidiaPure(unittest.TestCase):
    def test_spdm_parser(self):
        t = spdm(blocks=2)
        p = parse_nvidia_spdm_evidence(t)
        self.assertEqual(p["request"]["nonce"], bytes([7]) * 32)
        self.assertEqual([(m["index"], m["valueType"], m["digest"]) for m in p["measurements"]], [(1, 0, bytes([0]) * 48), (2, 0, bytes([1]) * 48)])
        self.assertEqual(p["opaque"], {3: b"abc", 6: bytes(5)})
        self.assertEqual(p["signature"], bytes([0xEE]) * 96)
        self.assertEqual(p["signedBytes"], t[:-96])

    def test_spdm_parser_rejections(self):
        raises(self, lambda: parse_nvidia_spdm_evidence(bytes(10)), "parseNvidiaSpdmEvidence: transcript too short (10)")
        raises(self, lambda: parse_nvidia_spdm_evidence(spdm(request_code=0xE1)), "parseNvidiaSpdmEvidence: request code 0xe1 is not GET_MEASUREMENTS")
        raises(self, lambda: parse_nvidia_spdm_evidence(spdm(response_code=0x61)), "parseNvidiaSpdmEvidence: response code is not MEASUREMENTS")
        raises(self, lambda: parse_nvidia_spdm_evidence(spdm(num_blocks=2)), "parseNvidiaSpdmEvidence: header says 2 blocks, parsed 1")
        raises(self, lambda: parse_nvidia_spdm_evidence(spdm(extra=b"\x00")), "parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript")

    def test_vbios_version_rendering(self):
        self.assertEqual(format_vbios_version(bytes.fromhex("aabbcc0496009f00")[::-1]), "96.00.9f.00.04")
        self.assertEqual(format_vbios_version(b""), "")


# ---------------------------------------------------------------------------------------------- the XML subset + C14N
class XmlCanonical(unittest.TestCase):
    def test_canonical_form(self):
        d = parse_xml('<r b="2" a="1"><c></c><d/>x&amp;y&lt;</r>')
        self.assertEqual(canonicalize(d.root), '<r a="1" b="2"><c></c><d></d>x&amp;y&lt;</r>')
        self.assertEqual(d.violations, [])

    def test_namespaces_are_inclusive(self):
        d = parse_xml('<p:r xmlns:p="u" xmlns="d"><c xmlns="d"/><e xmlns="f"/><p:g q="1" p:a="2"/></p:r>')
        self.assertEqual(canonicalize(d.root), '<p:r xmlns="d" xmlns:p="u"><c></c><e xmlns="f"></e><p:g q="1" p:a="2"></p:g></p:r>')
        sub = d.root.element_children(local="c")[0]
        self.assertEqual(canonicalize(sub), '<c xmlns="d" xmlns:p="u"></c>')
        self.assertEqual(canonicalize(d.root, skip=d.root.element_children(local="e")[0]), '<p:r xmlns="d" xmlns:p="u"><c></c><p:g q="1" p:a="2"></p:g></p:r>')

    def test_profile_violations_are_recorded_in_order(self):
        self.assertEqual(parse_xml("<a><!-- c --></a>").violations, ["XML comments are not permitted"])
        self.assertEqual(parse_xml('<?xml version="1.0"?><a/>').violations, ["XML processing instructions are not permitted"])
        self.assertEqual(parse_xml("<!DOCTYPE a><a/>").violations, ["DTD / DOCTYPE is not permitted"])
        self.assertEqual(parse_xml('<a><b xml:lang="en"/><!-- c --></a>').violations, ["xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)", "XML comments are not permitted"])

    def test_ill_formed_documents_are_refused(self):
        for text in ("<a>", "<a></b>", "<a/><b/>", "text<a/>", "<a b=1/>", "<a b='1' b='2'/>", "<a>&nope;</a>", "<p:a/>", "<a", ""):
            with self.assertRaises(XmlError, msg=text):
                parse_xml(text)


# ---------------------------------------------------------------------------------------------- fail-closed tables
def evidence_resolver(ev):
    return lambda _doc: ev


class FailClosedTables(unittest.TestCase):
    def check(self, rows):
        for name, got, want in rows:
            self.assertEqual(got, want, name)

    def test_factory_refuses_unknown_vendor_and_bad_config(self):
        raises(self, lambda: verifier_from_config("tpm2", {}), "unknown attestation vendor tpm2")
        raises(self, lambda: verifier_from_config("amd-sev-snp", None), "verifier_from_config: config must be an object")
        self.assertEqual(len(VENDORS), 5)

    def test_amd(self):
        cfg = {"family": "genoa", "binding": "report-data", "policy": {"measurements": ["00" * 48]}}
        for name, over, msg in (
            ("unknown family", {"family": "zen9"}, "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'"),
            ("missing family", {"family": None}, "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'"),
            ("unknown binding", {"binding": "nope"}, "createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'"),
            ("empty allowlist", {"policy": {"measurements": []}}, "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            ("missing allowlist", {"policy": {}}, "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            ("missing policy", {"policy": None}, "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)"),
        ):
            raises(self, lambda o=over: verifier_from_config("amd-sev-snp", dict(cfg, **o)), msg)
        raises(self, lambda: verifier_from_config("amd-sev-snp", dict(cfg, policy={"measurements": ["00" * 48], "minReportedTcb": "abc"})), "Cannot convert abc to a BigInt")

        def run(ev, expected=EXP, resolver=True):
            v = AmdSnpVerifier(dict(cfg, resolve_evidence=evidence_resolver(ev) if resolver else None))
            return v.verify({}, expected, 1_800_000_000_000)

        report = lambda n: {"report": bytes(n), "vcekDer": b"abc", "askArkPem": ""}  # noqa: E731
        fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
        zero = bytearray(1184)
        zero[1183] = 1
        tail = bytearray(1184)
        tail[0x2A0 + 48] = 1
        got = run({"report": bytes(1184), "vcekDer": b"abc", "askArkPem": ""})
        self.assertFalse(got["ok"])
        self.assertTrue(got["reason"].startswith("SEV-SNP report invalid: cert chain invalid: AMD chain verification error: "), got["reason"])
        self.check(
            [
                ("no resolver", run(None, resolver=False), fail("no AMD SEV-SNP evidence resolver configured (fail closed)")),
                ("no evidence", run(None), fail("no AMD SEV-SNP evidence for this action")),
                ("no report", run({"vcekDer": b"a", "askArkPem": ""}), fail("no AMD SEV-SNP evidence for this action")),
                ("no pem", run({"report": b"a", "vcekDer": b"a"}), fail("no AMD SEV-SNP evidence for this action")),
                ("no expected binding", run(report(1184), None), fail("no expected attestation binding supplied")),
                ("short report", run(report(10)), fail("SEV-SNP report invalid: report parse failed: parseSevSnpReport: report too short (10 < 816)")),
                ("wrong length", run(report(1000)), fail("SEV-SNP report invalid: report length 1000 is not the canonical 1184")),
                ("reserved byte after s", run({"report": bytes(zero), "vcekDer": b"a", "askArkPem": ""}), fail("SEV-SNP report invalid: report signature block has non-zero reserved bytes")),
                ("reserved byte in r", run({"report": bytes(tail), "vcekDer": b"a", "askArkPem": ""}), fail("SEV-SNP report invalid: report signature block has non-zero reserved bytes")),
            ]
        )

    def test_intel(self):
        cfg = {"binding": "report-data", "policy": {"mrtds": ["00" * 48]}}
        for name, c, msg in (
            ("binding", dict(cfg, binding="x"), "createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'"),
            ("no mrtds", dict(cfg, policy={"mrtds": []}), "createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            ("no policy", dict(cfg, policy=None), "createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            ("short mrtd", dict(cfg, policy={"mrtds": ["abc"]}), "createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)"),
            ("empty mrSeams", dict(cfg, policy={"mrtds": ["00" * 48], "mrSeams": []}), "createIntelDcapVerifier: policy.mrSeams, if given, must be a NON-EMPTY list"),
            ("short mrSignerSeams", dict(cfg, policy={"mrtds": ["00" * 48], "mrSignerSeams": ["aa"]}), "createIntelDcapVerifier: every mrSignerSeams entry must be 96 hex chars (48 bytes)"),
        ):
            raises(self, lambda c=c: verifier_from_config("intel-tdx-dcap", c), msg)

        def run(ev, expected=EXP, resolver=True):
            return IntelDcapVerifier(dict(cfg, resolve_evidence=evidence_resolver(ev) if resolver else None)).verify({}, expected, 1_800_000_000_000)

        fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
        self.check(
            [
                ("no resolver", run(None, resolver=False), fail("no Intel DCAP evidence resolver configured (fail closed)")),
                ("no evidence", run(None), fail("no Intel DCAP quote for this action")),
                ("no expected", run({"quote": bytes(700)}, None), fail("no expected attestation binding supplied")),
                ("short quote", run({"quote": bytes(10)}), fail("DCAP quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length")),
                ("version", run({"quote": td_quote_header(version=3)}), fail("DCAP quote invalid: quote parse failed: parseDcapQuote: unsupported quote version 3 (expected 4)")),
                ("tee type", run({"quote": td_quote_header(tee=0x80)}), fail("DCAP quote invalid: quote parse failed: parseDcapQuote: unexpected TEE type 0x80 (expected TDX = 0x81)")),
            ]
        )

    def test_azure_maa(self):
        cfg = {"trustedIssuers": ["https://maa.example"], "trustAnchors": {"rootSpkiSha256": ["00" * 32]}, "policy": {"tdxMrtds": ["aa" * 48]}}
        for name, c, msg in (
            ("no issuers", dict(cfg, trustedIssuers=[]), "createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs"),
            ("empty issuer", dict(cfg, trustedIssuers=[""]), "createAzureMaaVerifier: every trusted issuer must be a non-empty URL string"),
            ("no anchors", dict(cfg, trustAnchors={}), "createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted"),
            ("no allowlist", dict(cfg, policy={}), "createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)"),
            ("min tcb not an object", dict(cfg, policy={"tdxMrtds": ["aa"], "sevSnpMinTcb": 1}), "createAzureMaaVerifier: policy.sevSnpMinTcb must be an object"),
            ("min tcb unknown field", dict(cfg, policy={"tdxMrtds": ["aa"], "sevSnpMinTcb": {"x": 1}}), "createAzureMaaVerifier: policy.sevSnpMinTcb.x is not a known field (bootloader | snp | microcode | tee)"),
            ("min tcb negative", dict(cfg, policy={"tdxMrtds": ["aa"], "sevSnpMinTcb": {"snp": -1}}), "createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer"),
        ):
            raises(self, lambda c=c: verifier_from_config("azure-maa", c), msg)

        def token(header, payload="{}", sig=b"sig"):
            h = header if isinstance(header, str) else b64u(json.dumps(header).encode())
            return "%s.%s.%s" % (h, b64u(payload.encode()) if not payload.startswith("b64:") else payload[4:], b64u(sig) if isinstance(sig, bytes) else sig)

        def run(ev, resolver=True):
            return AzureMaaVerifier(dict(cfg, resolve_evidence=evidence_resolver(ev) if resolver else None)).verify({}, EXP, 1_800_000_000_000)

        fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
        pre = "MAA token parse failed: parseMaaJwt: "
        self.check(
            [
                ("no resolver", run(None, resolver=False), fail("no Azure MAA evidence resolver configured (fail closed)")),
                ("no evidence", run(None), fail("no Azure MAA token for this action")),
                ("empty token", run({"token": ""}), fail("no Azure MAA token for this action")),
                ("two segments", run({"token": "a.b"}), fail(pre + "a compact JWS has exactly three dot-separated parts")),
                ("four segments", run({"token": "a.b.c.d"}), fail(pre + "a compact JWS has exactly three dot-separated parts")),
                ("empty header", run({"token": ".YQ.YQ"}), fail(pre + "empty JWS segment")),
                ("empty signature", run({"token": "YQ.YQ."}), fail(pre + "empty JWS segment")),
                ("not json", run({"token": token(b64u(b"not json"))}), fail(pre + "malformed JSON segment: Unexpected token 'o', \"not json\" is not valid JSON")),
                ("stray character", run({"token": token({"alg": "ES256"}, sig="YQ!")}), fail(pre + "malformed signature segment: non-canonical compact JWS: bad-character")),
                ("header array", run({"token": token(b64u(b"[1]"))}), fail(pre + "header is not a JSON object")),
                ("payload array", run({"token": token({"alg": "ES256"}, "[1]")}), fail(pre + "payload is not a JSON object")),
                ("no alg", run({"token": token({"kid": "k"})}), fail(pre + "header has no alg")),
                ("alg none", run({"token": token({"alg": "none"})}), fail("unsupported JWS alg 'none' (MAA uses ES256 / RS256)")),
                ("no x5c anywhere", run({"token": token({"alg": "ES256"})}), fail("no signing x5c available (no JWKS and no header x5c)")),
                ("kid matches nothing", run({"token": token({"alg": "ES256", "kid": "k1"}), "jwks": {"keys": [{"kid": "k2", "x5c": ["AA"]}]}}), fail("no JWKS key matches the token kid 'k1' (untrusted signer)")),
                ("jwks key without x5c", run({"token": token({"alg": "ES256", "kid": "k1"}), "jwks": {"keys": [{"kid": "k1"}]}}), fail("JWKS key 'k1' carries no x5c chain")),
                ("ambiguous keys", run({"token": token({"alg": "ES256"}), "jwks": {"keys": [{"x5c": ["AA"]}, {"x5c": ["AA"]}]}}), fail("token has no kid and the JWKS publishes multiple keys (ambiguous)")),
            ]
        )
        got = run({"token": token({"alg": "ES256", "x5c": ["!!!!"]})})
        self.assertFalse(got["ok"])
        self.assertTrue(got["reason"].startswith("MAA signing chain invalid: malformed x5c certificate at index 0: "), got["reason"])
        got = run({"token": token({"alg": "ES256", "x5c": [""]})})
        self.assertEqual(got, fail("MAA signing chain invalid: empty x5c entry at index 0"))

    def test_gcp(self):
        cfg = {"trustedIssuers": ["https://confidentialcomputing.googleapis.com"], "trustAnchors": {"trustedKeySpki": ["00" * 32]}, "policy": {"imageDigests": ["sha256:aa"]}}
        for name, c, msg in (
            ("no issuers", dict(cfg, trustedIssuers=[]), "createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs"),
            ("no anchors", dict(cfg, trustAnchors={}), "createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted"),
            ("no images", dict(cfg, policy={"imageDigests": []}), "createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            ("empty tee list", dict(cfg, policy={"imageDigests": ["a"], "allowedTeeTypes": []}), "createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty"),
        ):
            raises(self, lambda c=c: verifier_from_config("gcp-confidential-space", c), msg)

        def tok(header, payload="{}", sig="YQ"):
            return "%s.%s.%s" % (b64u(json.dumps(header).encode()) if not isinstance(header, str) else header, b64u(payload.encode()), sig)

        def run(ev, resolver=True):
            return GcpConfidentialSpaceVerifier(dict(cfg, resolve_evidence=evidence_resolver(ev) if resolver else None)).verify({}, EXP, 1_800_000_000_000)

        fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
        pre = "Confidential Space token parse failed: parseGcpCsJwt: "
        self.check(
            [
                ("no resolver", run(None, resolver=False), fail("no GCP Confidential Space evidence resolver configured (fail closed)")),
                ("no evidence", run(None), fail("no GCP Confidential Space token for this action")),
                ("two segments", run({"token": "a.b"}), fail(pre + "a compact JWS has exactly three dot-separated parts")),
                ("empty payload", run({"token": "YQ..YQ"}), fail(pre + "empty JWS segment")),
                ("not json", run({"token": tok(b64u(b"nope"))}), fail(pre + "malformed JSON segment: Unexpected token 'o', \"nope\" is not valid JSON")),
                ("header array", run({"token": tok(b64u(b"[1]"))}), fail(pre + "header is not a JSON object")),
                ("no alg", run({"token": tok({"kid": "k"})}), fail(pre + "header has no alg")),
                ("alg none", run({"token": tok({"alg": "none"})}), fail("unsupported JWS alg 'none' (Confidential Space uses RS256)")),
                ("no kid, no key", run({"token": tok({"alg": "RS256"})}), fail("Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available")),
                ("kid matches nothing", run({"token": tok({"alg": "RS256", "kid": "k"})}), fail("Confidential Space signing key invalid: no JWKS key matches the token kid 'k' (untrusted signer)")),
                ("jwk without material", run({"token": tok({"alg": "RS256", "kid": "k"}), "jwks": {"keys": [{"kid": "k"}]}}), fail("Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate")),
            ]
        )

    def test_nvidia(self):
        cfg = {"rootSpkiSha256": ["aa" * 32], "policy": {"measurements": {"1": "00" * 48}}}
        for name, c, msg in (
            ("no pins", dict(cfg, rootSpkiSha256=[]), "createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)"),
            ("no measurements", dict(cfg, policy={"measurements": {}}), "createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)"),
            ("index out of range", dict(cfg, policy={"measurements": {"256": "aa"}}), "createNvidiaSpdmVerifier: measurement index out of range"),
            ("index not a number", dict(cfg, policy={"measurements": {"x": "aa"}}), "createNvidiaSpdmVerifier: measurement index out of range"),
            ("hook without rim pin", dict(cfg, collateral={}), "nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root"),
            ("malformed firmware version", dict(cfg, collateral={"rimRootSpkiSha256": ["aa"], "firmware": {"minDriverVersion": "x"}}), "nvidiaCollateralHook: malformed minDriverVersion 'x'"),
        ):
            raises(self, lambda c=c: verifier_from_config("nvidia-gpu-spdm", c), msg)
        verifier_from_config("nvidia-gpu-spdm", dict(cfg, policy={"measurements": {}}, collateral={"rimRootSpkiSha256": ["aa"]}))  # a hook may supply the references

        def run(ev, resolver=True):
            return NvidiaSpdmVerifier(dict(cfg, resolve_evidence=evidence_resolver(ev) if resolver else None)).verify({}, EXP, 1_800_000_000_000)

        fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
        self.check(
            [
                ("no resolver", run(None, resolver=False), fail("no NVIDIA GPU evidence resolver configured (fail closed)")),
                ("no evidence", run(None), fail("no NVIDIA GPU evidence for this action")),
                ("no chain", run({"evidence": bytes(10)}), fail("no NVIDIA GPU evidence for this action")),
                ("empty chain", run({"evidence": bytes(10), "certChainPem": ""}), fail("device chain unparseable: parsePemChain: no certificates found")),
                ("chain too long", run({"evidence": bytes(10), "certChainPem": "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n" * 6}), fail("device chain unparseable: parsePemChain: chain longer than 5")),
            ]
        )


# ---------------------------------------------------------------------------------------------- real keys and certificates
def _crypto():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    from cryptography.x509.oid import NameOID

    class NS:
        pass

    ns = NS()
    ns.x509, ns.hashes, ns.serialization, ns.ec, ns.padding, ns.rsa, ns.utils, ns.NameOID = x509, hashes, serialization, ec, padding, rsa, utils, NameOID
    return ns


NB = datetime.datetime(2025, 1, 1)
NA = datetime.datetime(2035, 1, 1)
NOW = ms(2026, 10, 20)


def mint(c, cn, issuer_cn, pub, signer, serial, ca, hash_alg=None, nb=NB, na=NA, rsa_padding=None):
    name = lambda v: c.x509.Name([c.x509.NameAttribute(c.NameOID.COMMON_NAME, v)])  # noqa: E731
    b = (
        c.x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(name(issuer_cn))
        .public_key(pub)
        .serial_number(serial)
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(c.x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        b = b.add_extension(
            c.x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True,
        )
    kw = {"rsa_padding": rsa_padding} if rsa_padding is not None else {}
    return b.sign(signer, hash_alg or c.hashes.SHA384(), **kw).public_bytes(c.serialization.Encoding.DER)


@NEEDS_CRYPTO
class CertModel(unittest.TestCase):
    def setUp(self):
        from atlas_pca.attest_cert import Cert, render_name

        self.Cert, self.render_name = Cert, render_name
        self.c = _crypto()

    def test_ecdsa_chain(self):
        c = self.c
        root_key, leaf_key = c.ec.generate_private_key(c.ec.SECP384R1()), c.ec.generate_private_key(c.ec.SECP384R1())
        root = self.Cert(mint(c, "Test Root", "Test Root", root_key.public_key(), root_key, 1, True))
        leaf = self.Cert(mint(c, "Test Leaf", "Test Root", leaf_key.public_key(), root_key, 0x1234, False))
        self.assertEqual((root.subject, root.issuer, leaf.subject, leaf.issuer), ("CN=Test Root", "CN=Test Root", "CN=Test Leaf", "CN=Test Root"))
        self.assertTrue(root.verify_self())
        self.assertTrue(leaf.verify(root.public_key))
        self.assertFalse(leaf.verify(leaf.public_key))
        self.assertFalse(root.verify(leaf.public_key))
        self.assertTrue(root.ca)
        self.assertFalse(leaf.ca)
        self.assertTrue(leaf.check_issued(root))
        self.assertFalse(root.check_issued(leaf))
        self.assertEqual(leaf.serial_hex, "1234")
        self.assertEqual(root.serial_hex, "1")
        self.assertEqual(root.spki_sha256(), hashlib.sha256(root.spki_der).hexdigest())
        self.assertEqual(D.der_validity_ms(leaf.raw), (ms(2025, 1, 1), ms(2035, 1, 1)))
        self.assertEqual(D.check_chain_roles([leaf.raw, root.raw]), None)

    def test_trailing_bytes_are_tolerated_like_openssl_and_dropped(self):
        c = self.c
        k = c.ec.generate_private_key(c.ec.SECP256R1())
        der = mint(c, "R", "R", k.public_key(), k, 1, True, c.hashes.SHA256())
        self.assertEqual(self.Cert(der + b"\x00\x00").raw, der)

    def test_rsa_pkcs1_and_pss(self):
        c = self.c
        k = c.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = c.ec.generate_private_key(c.ec.SECP256R1())
        root = self.Cert(mint(c, "RSA Root", "RSA Root", k.public_key(), k, 1, True, c.hashes.SHA256()))
        leaf = self.Cert(mint(c, "Leaf", "RSA Root", leaf_key.public_key(), k, 2, False, c.hashes.SHA256()))
        self.assertTrue(root.verify_self())
        self.assertTrue(leaf.verify(root.public_key))
        self.assertFalse(leaf.verify(c.rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()))
        try:
            pss = c.padding.PSS(mgf=c.padding.MGF1(c.hashes.SHA384()), salt_length=48)
            der = mint(c, "RSA Root", "RSA Root", k.public_key(), k, 1, True, c.hashes.SHA384(), rsa_padding=pss)
        except TypeError:
            self.skipTest("this cryptography version cannot sign certificates with RSASSA-PSS")
        self.assertTrue(self.Cert(der).verify_self())

    def test_name_rendering(self):
        n = lambda *rdns: seq(*[tlv(0x31, b"".join(seq(oid(o), tlv(t, v.encode())) for o, t, v in rdn)) for rdn in rdns])  # noqa: E731
        self.assertEqual(self.render_name(n([("2.5.4.6", 0x13, "US")], [("2.5.4.10", 0x0C, "Acme Corp")], [("2.5.4.3", 0x0C, "Root CA")])), "C=US\nO=Acme Corp\nCN=Root CA")
        self.assertEqual(self.render_name(n([("2.5.4.3", 0x0C, "a,b")])), "CN=a\\,b")
        self.assertEqual(self.render_name(n([("2.5.4.3", 0x0C, "a"), ("2.5.4.10", 0x0C, "b")])), "CN=a + O=b")
        self.assertEqual(self.render_name(n([("1.2.3.4", 0x0C, "x")])), "1.2.3.4=x")
        self.assertEqual(self.render_name(n([("2.5.4.3", 0x0C, " lead")])), "CN=\\ lead")
        self.assertEqual(self.render_name(seq()), "")

    def test_crl(self):
        from atlas_pca.attest_intel import verify_crl

        c = self.c
        k = c.ec.generate_private_key(c.ec.SECP256R1())
        other = c.ec.generate_private_key(c.ec.SECP256R1())
        name = c.x509.Name([c.x509.NameAttribute(c.NameOID.COMMON_NAME, "CRL Issuer")])
        revoked = c.x509.RevokedCertificateBuilder().serial_number(0x0A0B).revocation_date(NB).build()
        crl = (
            c.x509.CertificateRevocationListBuilder().issuer_name(name).last_update(datetime.datetime(2026, 1, 1)).next_update(datetime.datetime(2027, 1, 1)).add_revoked_certificate(revoked).sign(k, c.hashes.SHA256())
        ).public_bytes(c.serialization.Encoding.DER)
        self.assertEqual(verify_crl(crl, k.public_key(), NOW), {"ok": True, "revoked": {"a0b"}})
        self.assertEqual(verify_crl(crl, other.public_key(), NOW), {"ok": False, "reason": "CRL signature does not verify under the issuer"})
        self.assertEqual(verify_crl(crl, k.public_key(), ms(2025, 12, 31)), {"ok": False, "reason": "CRL thisUpdate is in the future"})
        self.assertEqual(verify_crl(crl, k.public_key(), ms(2027, 1, 2)), {"ok": False, "reason": "CRL is stale (nextUpdate passed)"})
        self.assertEqual(verify_crl(crl[:-1], k.public_key(), NOW)["ok"], False)
        self.assertTrue(verify_crl(b"garbage", k.public_key(), NOW)["reason"].startswith("CRL parse failed: "))


# ---------------------------------------------------------------------------------------------- Azure MAA / GCP end to end
def spki_sha256(c, public_key):
    return hashlib.sha256(public_key.public_bytes(c.serialization.Encoding.DER, c.serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


@NEEDS_CRYPTO
class MaaEndToEnd(unittest.TestCase):
    MRTD = "AA" * 48

    def setUp(self):
        c = self.c = _crypto()
        self.root_key = c.ec.generate_private_key(c.ec.SECP256R1())
        self.leaf_key = c.ec.generate_private_key(c.ec.SECP256R1())
        self.root_der = mint(c, "MAA Root", "MAA Root", self.root_key.public_key(), self.root_key, 1, True, c.hashes.SHA256())
        self.leaf_der = mint(c, "MAA Signer", "MAA Root", self.leaf_key.public_key(), self.root_key, 2, False, c.hashes.SHA256())
        self.x5c = [b64(self.leaf_der), b64(self.root_der)]
        self.pin = spki_sha256(c, self.root_key.public_key())
        self.cfg = {"trustedIssuers": ["https://maa.example"], "trustAnchors": {"rootSpkiSha256": [self.pin]}, "policy": {"tdxMrtds": [self.MRTD]}}

    def token(self, payload=None, alg="ES256", tamper=False):
        c = self.c
        claims = {
            "iss": "https://maa.example",
            "exp": NOW // 1000 + 3600,
            "iat": NOW // 1000 - 60,
            "x-ms-isolation-tee": {"x-ms-attestation-type": "tdxvm", "tdx_mrtd": self.MRTD, "tdx_report_data": attestation_binding(EXP).hex()},
        }
        claims.update(payload or {})
        h = b64u(json.dumps({"alg": alg, "kid": "k", "typ": "JWT"}).encode())
        p = b64u(json.dumps(claims).encode())
        r, s = c.utils.decode_dss_signature(self.leaf_key.sign(("%s.%s" % (h, p)).encode(), c.ec.ECDSA(c.hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if tamper:
            p = b64u(json.dumps(dict(claims, iss="https://evil.example")).encode())
        return "%s.%s.%s" % (h, p, b64u(sig))

    def run_token(self, token, cfg=None, now=NOW, expected=EXP, jwks=True):
        ev = {"token": token}
        if jwks:
            ev["jwks"] = {"keys": [{"kid": "k", "kty": "RSA", "x5c": self.x5c}]}
        v = verifier_from_config("azure-maa", cfg or self.cfg, lambda _d: ev)
        return v.verify({}, expected, now)

    def test_a_bound_token_from_a_pinned_chain_passes(self):
        want = {
            "ok": True,
            "bound": True,
            "measured": {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": self.MRTD.lower(), "operator": ""},
            "hostAsserted": {"attestation_type": "tdxvm"},
        }
        self.assertEqual(self.run_token(self.token()), want)

    def test_identity_overrides_merge_over_the_measured_identity(self):
        got = self.run_token(self.token(), dict(self.cfg, identity_overrides={"model_id": "m1", "operator": "acme"}))
        self.assertEqual(got["measured"], {"model_id": "m1", "weights_digest": "", "weights_measured": False, "runtime_measurement": self.MRTD.lower(), "operator": "acme"})

    def test_denials(self):
        fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
        t = self.token()
        self.assertEqual(self.run_token(self.token(tamper=True)), fail("JWS ES256 signature does not verify under the MAA signing key"))
        self.assertEqual(self.run_token(t, expected=dict(EXP, nonce="other-nonce-0123456789")), fail("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)"))
        self.assertEqual(self.run_token(t, expected=dict(EXP, holderPub="")), fail("binding not constructible: binding: holderPub required"))
        self.assertEqual(self.run_token(t, expected=None), fail("no expected attestation binding supplied"))
        self.assertEqual(self.run_token(t, now=NOW + 3600_000 + 1000), fail("MAA token expired"))
        self.assertEqual(self.run_token(self.token({"nbf": NOW // 1000 + 100})), fail("MAA token not yet valid (nbf)"))
        self.assertEqual(self.run_token(self.token({"iat": NOW // 1000 + 100})), fail("MAA token issued in the future (iat)"))
        self.assertEqual(self.run_token(self.token({"exp": None})), fail("token has no exp (cannot bound validity — fail closed)"))
        self.assertEqual(self.run_token(self.token({"iss": "https://other.example"})), fail("token iss 'https://other.example' is not a configured trusted MAA instance"))
        self.assertEqual(self.run_token(self.token({"iss": None})), fail("token iss 'undefined' is not a configured trusted MAA instance"))
        self.assertEqual(self.run_token(t, dict(self.cfg, trustAnchors={"rootSpkiSha256": ["00" * 32]})), fail("MAA signing chain invalid: x5c chain does not anchor in a configured MAA trust root"))
        self.assertEqual(self.run_token(t, now=ms(2036, 1, 1)), fail("MAA signing chain invalid: x5c certificate at index 0 is outside its validity window"))
        self.assertEqual(self.run_token(t, now=ms(2024, 12, 31)), fail("MAA signing chain invalid: x5c certificate at index 0 is outside its validity window"))
        self.assertEqual(self.run_token(self.token(alg="RS256")), fail("RS256 token but signing key is EC (not RSA)"))
        self.assertEqual(self.run_token(t, dict(self.cfg, policy={"tdxMrtds": ["bb" * 48]})), fail("TDX MRTD not in policy allowlist"))
        self.assertEqual(self.run_token(t, dict(self.cfg, policy={"sevSnpMeasurements": ["bb" * 48]})), fail("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)"))
        self.assertEqual(self.run_token(self.token({"x-ms-isolation-tee": {"x-ms-attestation-type": "other"}})), fail("unexpected x-ms-attestation-type 'other' (expected sevsnpvm | tdxvm)"))
        dbg = {"x-ms-attestation-type": "tdxvm", "tdx_mrtd": self.MRTD, "tdx_report_data": attestation_binding(EXP).hex(), "tdx_td_attributes_debug": True}
        self.assertEqual(self.run_token(self.token({"x-ms-isolation-tee": dbg})), fail("TDX guest is debuggable (no confidentiality)"))
        self.assertEqual(self.run_token(self.token({"x-ms-isolation-tee": dict(dbg, tdx_td_attributes_debug=False, attester_tcb_status="OutOfDate")})), fail("TDX platform TCB status 'OutOfDate' is not accepted by policy"))

    def test_runtime_user_data_binding_and_report_data_hash(self):
        runtime_cfg = dict(self.cfg, policy={"tdxMrtds": [self.MRTD], "runtimeUserDataBinding": True})
        tee = {"x-ms-attestation-type": "tdxvm", "tdx_mrtd": self.MRTD}
        ok = self.run_token(self.token({"x-ms-isolation-tee": tee, "x-ms-runtime": {"user-data": attestation_binding(EXP).hex()}}), runtime_cfg)
        self.assertTrue(ok["ok"])
        self.assertEqual(self.run_token(self.token({"x-ms-isolation-tee": tee}), runtime_cfg), {"ok": False, "reason": "token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)"})
        self.assertEqual(self.run_token(self.token({"x-ms-isolation-tee": tee, "x-ms-runtime": {}}), runtime_cfg), {"ok": False, "reason": "x-ms-runtime carries no user-data to bind the PCA challenge"})
        hashed = dict(self.cfg, policy={"tdxMrtds": [self.MRTD], "reportDataHash": "sha256"})
        h_tee = dict(tee, tdx_report_data=hashlib.sha256(attestation_binding(EXP)).hexdigest())
        self.assertTrue(self.run_token(self.token({"x-ms-isolation-tee": h_tee}), hashed)["ok"])
        self.assertEqual(self.run_token(self.token(), hashed), {"ok": False, "reason": "report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)"})


@NEEDS_CRYPTO
class GcpEndToEnd(unittest.TestCase):
    ISSUER = "https://confidentialcomputing.googleapis.com"

    def setUp(self):
        c = self.c = _crypto()
        self.key = c.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = self.key.public_key().public_numbers()
        self.jwk = {"kid": "k", "kty": "RSA", "n": b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")), "e": b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}
        self.cfg = {"trustedIssuers": [self.ISSUER], "trustAnchors": {"trustedJwks": {"keys": [self.jwk]}}, "policy": {"imageDigests": ["sha256:AA"]}}

    def token(self, payload=None, key=None, kid="k"):
        c = self.c
        claims = {
            "iss": self.ISSUER,
            "exp": NOW // 1000 + 3600,
            "iat": NOW // 1000 - 60,
            "swname": "CONFIDENTIAL_SPACE",
            "swversion": ["240500"],
            "hwmodel": "GCP_AMD_SEV",
            "dbgstat": "disabled-since-boot",
            "eat_nonce": [attestation_binding(EXP).hex()],
            "submods": {"confidential_space": {"support_attributes": ["STABLE"]}, "container": {"image_digest": "sha256:aa", "image_reference": "gcr.io/x/y"}},
        }
        claims.update(payload or {})
        h = b64u(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
        p = b64u(json.dumps(claims).encode())
        sig = (key or self.key).sign(("%s.%s" % (h, p)).encode(), c.padding.PKCS1v15(), c.hashes.SHA256())
        return "%s.%s.%s" % (h, p, b64u(sig))

    def run_token(self, token, cfg=None, now=NOW, expected=EXP, jwks=None):
        ev = {"token": token}
        if jwks is not None:
            ev["jwks"] = jwks
        return verifier_from_config("gcp-confidential-space", cfg or self.cfg, lambda _d: ev).verify({}, expected, now)

    def test_a_bound_token_from_a_pinned_key_passes(self):
        self.assertEqual(
            self.run_token(self.token()),
            {
                "ok": True,
                "bound": True,
                "measured": {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": "sha256:aa", "operator": ""},
                "hostAsserted": {"attestation_type": "sev-snp", "hwmodel": "GCP_AMD_SEV", "image_digest": "sha256:aa", "image_reference": "gcr.io/x/y"},
            },
        )

    def test_an_evidence_jwks_key_must_corroborate_an_anchor(self):
        other = self.c.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = other.public_key().public_numbers()
        other_jwk = {"kid": "o", "kty": "RSA", "n": b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")), "e": b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}
        got = self.run_token(self.token(key=other, kid="o"), jwks={"keys": [other_jwk]})
        self.assertEqual(got, {"ok": False, "reason": "Confidential Space signing key invalid: signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)"})
        pinned = dict(self.cfg, trustAnchors={"trustedKeySpki": [spki_sha256(self.c, other.public_key()).upper()]})
        self.assertTrue(self.run_token(self.token(key=other, kid="o"), pinned, jwks={"keys": [other_jwk]})["ok"])

    def test_denials(self):
        fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
        t = self.token()
        h, p, s = t.split(".")
        tampered = "%s.%s.%s" % (h, b64u(json.dumps(dict(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))), dbgstat="enabled")).encode()), s)
        self.assertEqual(self.run_token(tampered), fail("JWS RS256 signature does not verify under the Confidential Space signing key"))
        self.assertEqual(self.run_token(self.token(key=self.c.rsa.generate_private_key(public_exponent=65537, key_size=2048))), fail("JWS RS256 signature does not verify under the Confidential Space signing key"))
        self.assertEqual(self.run_token(t, expected=dict(EXP, epoch=4)), fail("eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)"))
        self.assertEqual(self.run_token(t, expected=None), fail("no expected attestation binding supplied"))
        self.assertEqual(self.run_token(t, now=NOW + 3601_000), fail("Confidential Space token expired"))
        self.assertEqual(self.run_token(self.token({"nbf": NOW // 1000 + 60})), fail("Confidential Space token not yet valid (nbf)"))
        self.assertEqual(self.run_token(self.token({"iss": "https://other.example"})), fail("token iss 'https://other.example' is not a configured trusted Google attestation issuer"))
        self.assertEqual(self.run_token(self.token({"dbgstat": "enabled"})), fail("token dbgstat 'enabled' is not 'disabled-since-boot' (debug build — no confidentiality)"))
        self.assertTrue(self.run_token(self.token({"dbgstat": "enabled"}), dict(self.cfg, policy={"imageDigests": ["sha256:aa"], "allowDebug": True}))["ok"])
        self.assertEqual(self.run_token(self.token({"swname": "OTHER"})), fail("unexpected swname 'OTHER' (expected 'CONFIDENTIAL_SPACE')"))
        self.assertEqual(self.run_token(self.token({"hwmodel": "QEMU"})), fail("unrecognized hwmodel 'QEMU' (not a known AMD SEV-SNP / Intel TDX model)"))
        self.assertEqual(self.run_token(t, dict(self.cfg, policy={"imageDigests": ["sha256:aa"], "allowedTeeTypes": ["tdx"]})), fail("attestation type 'sev-snp' (hwmodel 'GCP_AMD_SEV') is not in the policy allowlist"))
        self.assertEqual(self.run_token(t, dict(self.cfg, policy={"imageDigests": ["sha256:aa"], "allowedSwVersions": ["1"]})), fail("swversion not in policy allowlist"))
        self.assertEqual(self.run_token(t, dict(self.cfg, policy={"imageDigests": ["sha256:bb"]})), fail("workload image_digest not in policy allowlist"))
        self.assertEqual(self.run_token(self.token({"submods": {"confidential_space": {}}})), fail("token carries no submods.container.image_digest to measure the workload"))
        self.assertEqual(self.run_token(self.token({"submods": {}})), fail("token carries no submods.confidential_space (not a Confidential Space token)"))
        self.assertEqual(self.run_token(self.token({"eat_nonce": []})), fail("token carries no eat_nonce claim to bind the PCA challenge"))

    def test_nonce_hash_and_nonce_lists(self):
        hashed = dict(self.cfg, policy={"imageDigests": ["sha256:aa"], "nonceHash": "sha256"})
        good = hashlib.sha256(attestation_binding(EXP)).hexdigest()
        self.assertTrue(self.run_token(self.token({"eat_nonce": ["zz-not-it", good]}), hashed)["ok"])
        self.assertEqual(self.run_token(self.token(), hashed), {"ok": False, "reason": "eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)"})
        self.assertTrue(self.run_token(self.token({"eat_nonce": attestation_binding(EXP).hex()}))["ok"])


# ---------------------------------------------------------------------------------------------- the passport seam
FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "passport-vectors.json")


class PassportDefaultVerifier(unittest.TestCase):
    """verify_passport(default_verifier=...) uses the default verifier for hardware evidence, an explicit `attest` wins, and without
    either the passport is refused (never a software pass)."""

    class Stub:
        def __init__(self, result):
            self.result, self.calls = result, []

        def verify(self, document, expected, now_ms):
            self.calls.append((document, expected, now_ms))
            return self.result

    def row(self):
        with open(FILE, encoding="utf-8") as f:
            vs = json.load(f)["passport_vectors"]
        for v in vs:
            if "hardware" in v and v["expect"]["ok"] and "signed" in v:
                return v
        self.fail("the passport corpus has no accepted hardware row")

    def call(self, v, **kw):
        from atlas_pca import verify_passport

        revoked = set(v["revoked"])
        return verify_passport(v["signed"], v["trustedIssuers"], v["now"], v.get("clockSkewMs"), v.get("maxEvidenceAgeMs"), v.get("subject"), lambda i, _a, _b: i in revoked, v.get("pqPins"), **kw)

    def test_default_verifier_is_used_and_handed_the_binding_and_the_clock(self):
        v = self.row()
        stub = self.Stub({"ok": True, "bound": True, "measured": v["hardware"]["measured"]})
        self.assertIsNone(self.call(v, default_verifier=stub))
        self.assertEqual(len(stub.calls), 1)
        doc, expected, now = stub.calls[0]
        self.assertEqual(now, v["now"])
        eb = v["expectBinding"]
        self.assertEqual(expected, {"holder_pub": eb["holderPub"], "grant_ref": eb["grantRef"], "epoch": eb["epoch"], "nonce": eb["nonce"]})
        self.assertEqual(doc["nonce"], eb["nonce"])

    def test_an_explicit_attest_wins_over_the_default_verifier(self):
        v = self.row()
        stub = self.Stub({"ok": True, "bound": True, "measured": v["hardware"]["measured"]})
        self.assertEqual(self.call(v, attest=lambda _d, _e: {"ok": False, "bound": False}, default_verifier=stub), "hardware_attestation_failed")
        self.assertEqual(stub.calls, [])

    def test_a_default_verifier_that_refuses_or_raises_fails_the_passport(self):
        v = self.row()
        self.assertEqual(self.call(v, default_verifier=self.Stub({"ok": False, "reason": "x"})), "hardware_attestation_failed")
        self.assertEqual(self.call(v, default_verifier=self.Stub({"ok": True, "bound": False, "measured": v["hardware"]["measured"]})), "hardware_attestation_failed")

        class Boom:
            def verify(self, *_a):
                raise RuntimeError("down")

        self.assertEqual(self.call(v, default_verifier=Boom()), "hardware_attestation_failed")

    def test_without_any_verifier_the_hardware_passport_is_refused(self):
        self.assertEqual(self.call(self.row()), "hardware_verifier_missing")


if __name__ == "__main__":
    unittest.main()
