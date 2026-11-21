"""OCSP kill tests of the 0.5 full mutation baseline: the DER time readers (UTCTime century window, leap days, minutes),
the element-overrun refusals, leading-zero stripping, AIA OCSP URL extraction from a real certificate, and
check_nvidia_chain_ocsp's exact refusal dicts (seam: verify_ocsp_response / cert_ocsp_urls stubbed per certificate)."""
import datetime
import types

import pytest

pytest.importorskip("cryptography")

from atlas_pca import attest_ocsp as O
from atlas_pca.attest_cert import Cert
from atlas_pca.attest_der import Tlv


def _ms(y, mo, d, h=0, mi=0, s=0):
    return int(datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc).timestamp()) * 1000


def test_time_in_range_uses_the_utc_century_window():
    assert O._time_in_range("240229000000Z", True) is True      # 2024 is a leap year
    assert O._time_in_range("250229000000Z", True) is False     # 2025 is not (y = 2000 would accept it)
    assert O._time_in_range("20250229000000Z", False) is False and O._time_in_range("20240229235959Z", False) is True
    assert O._time_in_range("251301000000Z", True) is False and O._time_in_range("250100000000Z", True) is False
    assert O._time_in_range("250101240000Z", True) is False and O._time_in_range("250101006000Z", True) is False
    assert O._time_in_range("250101000060Z", True) is False and O._time_in_range("2501010000Z", True) is False


def test_gen_time_ms():
    assert O._gen_time_ms("250102033005Z") == _ms(2025, 1, 2, 3, 30, 5)
    assert O._gen_time_ms("500102033005Z") == _ms(1950, 1, 2, 3, 30, 5)
    assert O._gen_time_ms("20250102033005Z") == _ms(2025, 1, 2, 3, 30, 5)
    assert O._gen_time_ms("20250102033005.25Z") == _ms(2025, 1, 2, 3, 30, 5) + 250
    with pytest.raises(O.OcspError) as e:
        O._gen_time_ms("2025")
    assert str(e.value) == "response times are not parseable"


def _utc(text):
    return bytes([0x17, len(text)]) + text.encode()


def test_all_times_well_formed_reaches_nested_times():
    good, bad = _utc("240229000000Z"), _utc("250229000000Z")
    assert O._all_times_well_formed(good, 0, len(good)) is True
    assert O._all_times_well_formed(bad, 0, len(bad)) is False
    nested = bytes([0x30, len(bad)]) + bad
    assert O._all_times_well_formed(nested, 0, len(nested)) is False
    gen = bytes([0x18, 15]) + b"20250229000000Z"
    assert O._all_times_well_formed(gen, 0, len(gen)) is False
    octet = bytes([0x04, len(bad) - 2]) + bad[2:]     # not a time tag: never read as one
    assert O._all_times_well_formed(octet, 0, len(octet)) is True


def test_overrun_refusals():
    der = bytes([0x04, 3, 1, 2, 3])
    with pytest.raises(O.OcspError) as e:
        O._all_times_well_formed(der, 0, 2)
    assert str(e.value) == "element overruns its parent"
    with pytest.raises(O.OcspError) as e:
        O._children(der, Tlv(0x30, 0, 2))
    assert str(e.value) == "element overruns its parent"
    assert O._children(der, Tlv(0x30, 0, 5)) == [(Tlv(0x04, 2, 5), 0)]


def test_strip_zeros():
    assert O._strip_zeros(b"\x00\x00\x00\x01") == b"\x01"
    assert O._strip_zeros(b"\x00\x01") == b"\x01"
    assert O._strip_zeros(b"\x00\x00") == b"\x00"
    assert O._strip_zeros(b"\x05\x00") == b"\x05\x00"


def _cert_with_aia(*urls):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key()).serial_number(7)
         .not_valid_before(datetime.datetime(2024, 1, 1)).not_valid_after(datetime.datetime(2030, 1, 1)))
    if urls:
        b = b.add_extension(x509.AuthorityInformationAccess(
            [x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("http://ca/x"))]
            + [x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(u)) for u in urls]), False)
    return Cert(b.sign(k, hashes.SHA256()).public_bytes(Encoding.DER))


def test_cert_ocsp_urls():
    assert O.cert_ocsp_urls(_cert_with_aia("http://ocsp/a", "http://ocsp/b")) == ["http://ocsp/a", "http://ocsp/b"]
    assert O.cert_ocsp_urls(_cert_with_aia()) == []


C3 = [types.SimpleNamespace(subject="CN=a\nO=x"), types.SimpleNamespace(subject="CN=b"), types.SimpleNamespace(subject="CN=root")]
NOMATCH = {"ok": False, "reason": "no SingleResponse matches the certificate"}


def _seam(monkeypatch, status_by_der, required=()):
    def verify(der, cert, *_a):
        i = C3.index(cert)
        st = status_by_der[der].get(i)
        return {"ok": True, "status": st, "responder": "issuer"} if st else NOMATCH
    monkeypatch.setattr(O, "verify_ocsp_response", verify)
    monkeypatch.setattr(O, "cert_ocsp_urls", lambda c: ["http://o"] if C3.index(c) in required else [])


def test_chain_ocsp_exact_results(monkeypatch):
    _seam(monkeypatch, {b"r0": {0: "good"}, b"r1": {0: "good"}})
    assert O.check_nvidia_chain_ocsp(C3, [b"r0", b"r1"], 1) == {
        "ok": False, "reason": "duplicate OCSP responses for chain certificate #0", "statuses": {0: "good", 1: "absent"}}
    _seam(monkeypatch, {b"r0": {1: "revoked"}})
    assert O.check_nvidia_chain_ocsp(C3, [b"r0"], 1) == {
        "ok": False, "reason": "chain certificate 'CN=b' is revoked (OCSP)", "statuses": {0: "absent", 1: "revoked"}}
    _seam(monkeypatch, {b"r0": {0: "revoked"}})
    assert O.check_nvidia_chain_ocsp(C3, [b"r0"], 1)["reason"] == "chain certificate 'CN=a, O=x' is revoked (OCSP)"
    _seam(monkeypatch, {b"r0": {0: "good"}}, required=(0, 1))
    assert O.check_nvidia_chain_ocsp(C3, [b"r0"], 1) == {
        "ok": False, "reason": "no GOOD OCSP response for required certificate 'CN=b' (status: absent)",
        "statuses": {0: "good", 1: "absent"}}
    _seam(monkeypatch, {b"r0": {0: "good"}, b"r1": {1: "good"}}, required=(0, 1))
    assert O.check_nvidia_chain_ocsp(C3, [b"r0", b"r1"], 1) == {
        "ok": True, "verifiedCrls": 0, "verifiedOcsp": 2, "statuses": {0: "good", 1: "good"}}
    _seam(monkeypatch, {b"r0": {0: "good", 1: "good"}})
    assert O.check_nvidia_chain_ocsp(C3, [b"r0"], 1) == {
        "ok": False, "reason": "OCSP response #0 matches more than one chain certificate", "statuses": {0: "good", 1: "absent"}}
    _seam(monkeypatch, {b"r0": {}})
    assert O.check_nvidia_chain_ocsp(C3, [b"r0"], 1) == {
        "ok": False, "reason": "OCSP response #0 rejected: no SingleResponse matches the certificate", "statuses": {0: "absent", 1: "absent"}}
