"""Kill tests for the remaining 0.5 mutation survivors of attest_intel.py, attest_der.py and attest_ocsp.py. Expectations follow the
TypeScript reference (x509-strict, x509-validity, attest-intel-tdx, attest-intel-collateral, attest-nvidia-ocsp): messages and
boundaries are the reference's; where an element is made to overrun its PARENT (not the buffer) the parent-bounded read must refuse."""
import calendar
import types

import pytest

pytest.importorskip("cryptography")

import test_k05_kill_intel as IT
import test_k05_kill_intel_ocsp_cert as OT
from atlas_pca import attest_der as D
from atlas_pca import attest_intel as A
from atlas_pca import attest_ocsp as O
from atlas_pca.attest_amd import AttestConstructError
from atlas_pca.attest_der import CertExtension, DerError, Tlv
from test_attest_units import cert_of, integer, octets, oid, seq, tlv

OVERRUN = "DER: element overruns its parent"
PAD = b"\x00" * 64
OID_BC = tlv(0x06, b"\x55\x1d\x13")
OID_KU = tlv(0x06, b"\x55\x1d\x0f")


def _day(y, m, d):
    return calendar.timegm((y, m, d, 0, 0, 0)) // 86400


def _derr(fn, *a):
    with pytest.raises(DerError) as e:
        fn(*a)
    return str(e.value)


def _wrap(tbs_content):
    """A certificate-shaped DER whose children may claim more than their parent holds (the zero padding sits after the TBS)."""
    return tlv(0x30, tlv(0x30, tbs_content) + PAD)


def _exts(*ext_bodies):
    return tlv(0xA3, seq(*[tlv(0x30, b) for b in ext_bodies]))


# ------------------------------------------------------------------------------------------ attest_der: read_tlv
def test_read_tlv_length_bytes_end_exactly_at_the_limit():
    assert _derr(D.read_tlv, b"\x04\x81\x80", 0) == OVERRUN   # the length bytes fit; the content does not
    assert _derr(D.read_tlv, b"\x04\x81\x00", 0) == "DER: non-minimal length (long form below 128)"
    assert _derr(D.read_tlv, b"\x04\x82\x00\x80", 0) == "DER: non-minimal length (leading zero)"


# ------------------------------------------------------------------------------------------ attest_der: read_cert_role_info
@pytest.mark.parametrize("tbs", [
    b"\x04\x20",                                                                  # a TBS element overruns the TBS
    b"\xa3\x02\x30\x20",                                                          # the extensions SEQUENCE overruns [3]
    tlv(0xA3, tlv(0x30, b"\x30\x20")),                                            # an extension overruns the SEQUENCE
    _exts(b"\x06\x20"),                                                           # the OID overruns its extension
    _exts(tlv(0x06, b"\x55") + b"\x04\x20"),                                      # the value overruns its extension
    _exts(tlv(0x06, b"\x55") + tlv(0x01, b"\xff") + b"\x04\x20"),                 # ... after a critical flag
    _exts(OID_BC + tlv(0x04, b"\x30\x20")),                                       # BasicConstraints overruns its OCTET STRING
    _exts(OID_BC + tlv(0x04, tlv(0x30, b"\x01\x20"))),                            # cA overruns BasicConstraints
    _exts(OID_BC + tlv(0x04, tlv(0x30, tlv(0x01, b"\xff") + b"\x02\x20"))),       # pathLenConstraint overruns BasicConstraints
    _exts(OID_KU + tlv(0x04, b"\x03\x20")),                                       # the BIT STRING overruns its OCTET STRING
])
def test_role_info_children_are_bounded_by_their_parent(tbs):
    assert _derr(D.read_cert_role_info, _wrap(tbs)) == OVERRUN


def _bc_cert(bc_content):
    return _wrap(_exts(OID_BC + tlv(0x04, tlv(0x30, bc_content))))


def _ku_cert(bits):
    return _wrap(_exts(OID_KU + tlv(0x04, tlv(0x03, bits))))


def test_role_info_ca_flag_is_any_non_zero_byte():
    assert D.read_cert_role_info(_bc_cert(tlv(0x01, b"\x00")))["ca"] is False
    assert D.read_cert_role_info(_bc_cert(tlv(0x01, b"\x01")))["ca"] is True
    assert D.read_cert_role_info(_bc_cert(tlv(0x01, b"\xff")))["ca"] is True


def test_role_info_path_length_forms():
    ca = tlv(0x01, b"\xff")
    assert D.read_cert_role_info(_bc_cert(ca + tlv(0x02, b"\x01\x02")))["pathLen"] == 258   # two bytes, big-endian
    assert D.read_cert_role_info(_bc_cert(ca + tlv(0x02, b"\x01\x00")))["pathLen"] == 256
    assert D.read_cert_role_info(_bc_cert(ca + tlv(0x02, b"\x05")))["pathLen"] == 5
    bad = "BasicConstraints pathLenConstraint malformed"
    assert _derr(D.read_cert_role_info, _bc_cert(ca + tlv(0x04, b"\x05"))) == bad     # not an INTEGER
    assert _derr(D.read_cert_role_info, _bc_cert(ca + tlv(0x02, b""))) == bad          # empty
    assert _derr(D.read_cert_role_info, _bc_cert(ca + tlv(0x02, b"\x00\x00\x01"))) == bad   # three bytes
    assert _derr(D.read_cert_role_info, _bc_cert(ca + tlv(0x02, b"\x80"))) == bad      # negative


def test_role_info_key_cert_sign_is_bit_5_only():
    assert D.read_cert_role_info(_ku_cert(b"\x00\x04"))["keyCertSign"] is True
    assert D.read_cert_role_info(_ku_cert(b"\x07\x01"))["keyCertSign"] is False
    assert D.read_cert_role_info(_ku_cert(b"\x00\x05"))["keyCertSign"] is True


def test_check_chain_roles_keeps_checking_after_a_non_ca_leaf():
    leaf, issuer = cert_of(), cert_of()
    assert D.check_chain_roles([leaf, issuer]) == "issuer certificate at depth 1 has no BasicConstraints (not a CA)"


# ------------------------------------------------------------------------------------------ attest_der: OIDs and extension table
@pytest.mark.parametrize("first,want", [(0x27, "0.39"), (0x28, "1.0"), (0x4F, "1.39"), (0x50, "2.0")])
def test_oid_first_byte_split(first, want):
    b = bytes([first])
    assert D._oid_to_dotted(b, Tlv(0x06, 0, 1)) == want


def test_oid_leading_0x80_arc_is_refused():
    assert _derr(D._oid_to_dotted, b"\x80\x01", Tlv(0x06, 0, 2)) == "extension OID has a non-minimal arc"


@pytest.mark.parametrize("content", [
    b"\xa3\x02\x30\x04" + b"\x04\x02\x01\x02",                                                       # SEQUENCE overruns [3]
    tlv(0xA3, tlv(0x30, b"\x30\x08")) + b"\x00" * 16,                                                  # extension overruns the SEQUENCE
    tlv(0xA3, seq(tlv(0x30, b"\x06\x08"))) + b"\x00" * 16,                                             # OID overruns its extension
    tlv(0xA3, seq(tlv(0x30, OID_BC + b"\x04\x08"))) + b"\x00" * 16,                                    # value overruns its extension
    tlv(0xA3, seq(tlv(0x30, OID_BC + tlv(0x01, b"\xff") + b"\x04\x08"))) + b"\x00" * 16,               # ... after a critical flag
])
def test_extension_table_children_are_bounded_by_their_parent(content):
    assert _derr(D.parse_tbs_extensions, tlv(0x30, content)) == OVERRUN


def test_extension_table_message_for_a_non_sequence_extension():
    assert _derr(D.parse_tbs_extensions, tlv(0x30, tlv(0xA3, seq(tlv(0x31, b""))))) == "extension is not a SEQUENCE"


def test_tbs_of_certificate_message():
    assert _derr(D.tbs_of_certificate, tlv(0x30, tlv(0x31, b""))) == "certificate has no tbsCertificate"


# ------------------------------------------------------------------------------------------ attest_der: _tlv_at, calendar, times
def test_tlv_at_length_forms():
    assert D._tlv_at(b"\x30\x84\x00\x00\x00\x01\x05", 0) == Tlv(0x30, 6, 7)   # four length bytes are fine
    assert _derr(D._tlv_at, b"\x30\x85\x00\x00\x00\x00\x01\x05", 0) == "bad length"
    assert _derr(D._tlv_at, b"\x30\x80\x00\x00", 0) == "bad length"
    assert _derr(D._tlv_at, b"\x30\x84\x00\x00", 0) == "bad length"
    assert _derr(D._tlv_at, b"\x30\x81\x05", 0) == "truncated"          # the length bytes end exactly at the buffer
    assert D._tlv_at(b"\x30\x81\x00", 0) == Tlv(0x30, 3, 3)


@pytest.mark.parametrize("ymd", [(1970, 1, 1), (1900, 3, 1), (2000, 2, 29), (2000, 3, 1), (2024, 2, 29), (2100, 2, 28), (2100, 3, 1),
                                 (2105, 6, 15), (2399, 12, 31), (2025, 3, 1)])
def test_days_from_civil(ymd):
    assert D.days_from_civil(*ymd) == _day(*ymd)


def test_days_in_month_and_leap_years():
    assert [D.days_in_month(2021, m) for m in range(1, 13)] == [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    for y, feb in ((1900, 28), (2000, 29), (2020, 29), (2021, 28), (2100, 28), (2400, 29), (2024, 29)):
        assert D.days_in_month(y, 2) == feb


def test_parse_der_time_year_and_digit_rules():
    assert D.parse_der_time(0x17, "000101000000Z") == _day(2000, 1, 1) * 86400000   # yy 00 is a year, not an error
    assert D.parse_der_time(0x17, "a50101000000Z") is None
    assert D.parse_der_time(0x18, "x0250101000000Z") is None


def test_der_validity_shapes():
    nb, na = tlv(0x17, b"250101000000Z"), tlv(0x17, b"350101000000Z")
    lo, hi = _day(2025, 1, 1) * 86400000, _day(2035, 1, 1) * 86400000
    head = integer(1) + seq() + seq()
    # validity is the LAST TBS element: it ends exactly at the TBS end
    assert D.der_validity_ms(seq(seq(head + seq(nb, na)))) == (lo, hi)
    # a SET is not a validity, even though it fits
    assert D.der_validity_ms(seq(seq(head + tlv(0x31, nb + na)))) == (None, None)
    assert D.der_validity_ms(seq(seq(head + seq(nb, na, nb)))) == (None, None)


# ------------------------------------------------------------------------------------------ attest_intel: quote parsing
def test_quote_length_and_exact_fit_boundaries():
    p = "parseDcapQuote: "
    assert IT._perr(IT._q(b"")) == p + "truncated reading quote signature"   # exactly header + report + sig length
    assert IT._perr(IT._q(b"")[:635]) == p + "too short for header + TD report + sig length"
    assert IT._perr(IT._q(IT.QS + IT.AK)) == p + "truncated reading outer cert-data header"
    assert IT._perr(IT._q(IT.QS + IT.AK + IT._u16(6) + IT._u32(0))) == p + "truncated reading QE report"
    assert IT._perr(IT._q(IT._outer(IT.QE + IT.QES))) == p + "truncated reading QE auth-data size"
    assert IT._perr(IT._q(IT._outer(IT.QE + IT.QES + IT._u16(0)))) == p + "truncated reading inner cert-data header"
    r = A.parse_dcap_quote(IT._q(IT._outer(IT._rest(auth=b"", pem=b""))))   # the inner header ends exactly at the signature data
    assert (r["qeAuthData"], r["pckChainPem"]) == (b"", "")


def test_lenient_der_reader_boundaries():
    t = A._read_der_tlv
    assert t(b"\x04\x00", 0) == {"tag": 4, "start": 2, "end": 2}
    assert t(b"\x04", 0) is None
    assert t(b"\x04\x85\x00\x00\x00\x00\x01\x05", 0) is None
    assert t(b"\x04\x80", 0) is None
    assert t(b"\x04\x84\x00\x00", 0) is None
    assert t(b"\x04\x81\x01\xaa", 0) == {"tag": 4, "start": 3, "end": 4}
    assert t(b"\x04\x84\x00\x00\x00\x01\xaa", 0) == {"tag": 4, "start": 6, "end": 7}
    assert t(b"\x04\x81\x00", 0) == {"tag": 4, "start": 3, "end": 3}


def test_extract_pck_reads_the_first_tcb_oid_and_one_at_offset_zero():
    two = IT.FM_OID + octets(IT.FM) + IT.TCB_OID + seq(IT._comp(17, integer(7))) + IT.TCB_OID + seq(IT._comp(17, integer(9)))
    assert A.extract_pck_fmspc_and_tcb(two)["pcesvn"] == 7
    first = IT.TCB_OID + seq(IT._comp(17, integer(7))) + IT.FM_OID + octets(IT.FM)
    assert A.extract_pck_fmspc_and_tcb(first)["pcesvn"] == 7


# ------------------------------------------------------------------------------------------ attest_intel: PCK chain
def test_pck_chain_of_a_lone_self_signed_root():
    root = IT._chain()[0]
    r = IT._vc([root])
    assert (r["ok"], r["depth"], r["leafDer"]) == (True, 1, root)


class _Cyc:
    def __init__(self, subject, issuer, box):
        self.subject, self._i, self._box, self.raw = subject, issuer, box, b""

    @property
    def issuer(self):
        self._box[0] += 1
        if self._box[0] > 200:
            raise RuntimeError("cycle walked without end")
        return self._i


def test_pck_chain_cycle_is_cut_by_the_seen_set(monkeypatch):
    box = [0]
    certs = iter([_Cyc("A", "B", box), _Cyc("B", "A", box)])
    monkeypatch.setattr(A, "Cert", types.SimpleNamespace(from_pem=lambda b: next(certs)))
    pem = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n" * 2
    assert A.verify_intel_pck_chain(pem, None, 1) == {"ok": False, "reason": "PCK chain does not terminate in a self-signed root"}


def test_pck_chain_wall_clock_is_exact(monkeypatch):
    root, inter, leaf = IT._chain()
    pem = IT._pem(leaf) + IT._pem(inter) + IT._pem(root)
    monkeypatch.setattr(A, "time", types.SimpleNamespace(time=lambda: IT._ms(2034, 12, 31) / 1000))   # one day before the certificates expire
    assert A.verify_intel_pck_chain(pem, IT._pin())["ok"] is True


def test_verify_p256_swallows_a_verifier_error(monkeypatch):
    def boom(*a):
        raise RuntimeError("x")

    monkeypatch.setattr(A, "ecdsa_verify_raw", boom)
    assert A._verify_p256(b"m", b"s", object()) is False


def test_genuine_qe_report_data_second_half_must_be_zero(monkeypatch):
    monkeypatch.setattr(A, "_verify_p256", lambda *a: True)
    q = IT._real()[0]
    assert IT._g(quote=IT._flip(q, IT.QE_OFF + 320 + 32, 1)) == {
        "ok": False, "reason": "QE report_data does not bind the attestation key (AK not endorsed by this QE)"}


# ------------------------------------------------------------------------------------------ attest_intel: DER time / CRL
def test_tlv_length_bytes_end_exactly_at_the_limit():
    t = A._tlv(b"\x30\x81\x00", 0)
    assert (t.tag, t.start, t.end) == (0x30, 3, 3)


def test_der_time_non_ascii_bytes_are_replaced_then_refused():
    der = tlv(0x17, b"25010203300\xff" + b"5Z")
    with pytest.raises(ValueError) as e:
        A._der_time(der, A._tlv(der, 0))
    assert str(e.value) == "bad UTCTime"


GARBAGE_SIG = tlv(0x03, b"\x00" * 61)


def _crl_raw(*tbs_parts):
    return seq(seq(*tbs_parts), IT.ECDSA_SHA256, GARBAGE_SIG)


@pytest.mark.parametrize("parts", [
    (b"\x02\x30",),
    (integer(1), b"\x30\x30"),
    (IT.ECDSA_SHA256, b"\x30\x30"),
    (IT.ECDSA_SHA256, IT.CRL_NAME, b"\x17\x30"),
    (IT.ECDSA_SHA256, IT.CRL_NAME, IT.THIS, b"\x17\x30"),
    (IT.ECDSA_SHA256, IT.CRL_NAME, IT.THIS, IT.NEXT, b"\x30\x30"),
    (IT.ECDSA_SHA256, IT.CRL_NAME, IT.THIS, IT.NEXT, tlv(0x30, b"\x30\x30")),
    (IT.ECDSA_SHA256, IT.CRL_NAME, IT.THIS, IT.NEXT, tlv(0x30, tlv(0x30, b"\x02\x30"))),
])
def test_crl_children_are_bounded_by_their_parent(parts):
    assert IT._crl_err(_crl_raw(*parts)) == "DER overrun"


# ------------------------------------------------------------------------------------------ attest_intel: signed JSON collateral
def test_signer_key_validity_and_now_are_forwarded():
    root, inter, leaf = IT._chain()
    pem = IT._pem(leaf) + IT._pem(inter) + IT._pem(root)
    assert A._signer_key_from_chain(pem, IT._pin(), IT._ms(2024, 6, 1), set()) == {"error": "issuer chain certificate outside its validity period"}
    assert "key" in A._signer_key_from_chain(pem, IT._pin(), IT.NOW, set())


@pytest.mark.parametrize("inner,want", [
    ({"ok": True}, "issuer chain invalid: unknown"),
    ({"ok": False, "leafDer": b"x"}, "issuer chain invalid: unknown"),
    ({"ok": False, "leafDer": b"x", "reason": "r"}, "issuer chain invalid: r"),
    ({"ok": False, "reason": ""}, "issuer chain invalid: "),
    ({"ok": False, "reason": None}, "issuer chain invalid: unknown"),
])
def test_signer_key_chain_result_seam(monkeypatch, inner, want):
    monkeypatch.setattr(A, "verify_intel_pck_chain", lambda *a: inner)
    assert A._signer_key_from_chain("x", None, 1, set()) == {"error": want}


def test_raw_json_object_scanner():
    assert A._raw_json_object('{"tcbInfo":', "tcbInfo") is None            # nothing after the name
    assert A._raw_json_object('{"tcbInfo": 5}', "tcbInfo") is None
    assert A._raw_json_object('{"tcbInfo":{"a":1', "tcbInfo") is None      # never closes
    assert A._raw_json_object('{"tcbInfo":{"a":"}"}}', "tcbInfo") == '{"a":"}"}'   # a brace inside a string
    assert A._raw_json_object('{"tcbInfo":{"a":"x\\"}y"}}', "tcbInfo") == '{"a":"x\\"}y"}'   # an escaped quote
    assert A._raw_json_object('{"tcbInfo":{"a":"x\\\\"}}', "tcbInfo") == '{"a":"x\\\\"}'      # an escaped backslash
    assert A._raw_json_object('{"tcbInfo":{"a":{"b":1}}}', "tcbInfo") == '{"a":{"b":1}}'


def _signed(raw, key, upper=False):
    c = IT._c()
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(key.sign(raw.encode("utf-8"), c.ec.ECDSA(c.hashes.SHA256())))
    sig = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()
    return '{"tcbInfo":%s,"signature":"%s"}' % (raw, sig.upper() if upper else sig)


def test_verify_signed_json_every_branch():
    k = IT._keys()[0]
    pub = k.public_key()
    raw = '{"a":"é"}'
    assert A._verify_signed_json(_signed(raw, k), "tcbInfo", pub) == {"body": {"a": "é"}}
    assert A._verify_signed_json(_signed(raw, k, upper=True), "tcbInfo", pub) == {"body": {"a": "é"}}   # hex digits of either case
    assert A._verify_signed_json('{"tcbInfo":{"a":1} x', "tcbInfo", pub) == {"error": "tcbInfo document is not valid JSON"}
    assert A._verify_signed_json('{"tcbInfo":{"a":1}}', "tcbInfo", pub) == {"error": "tcbInfo signature missing or malformed"}
    assert A._verify_signed_json('{"tcbInfo":{"a":1},"signature":"ab"}', "tcbInfo", pub) == {"error": "tcbInfo signature missing or malformed"}
    assert A._verify_signed_json('{"tcbInfo":{"a":1},"signature":5}', "tcbInfo", pub) == {"error": "tcbInfo signature missing or malformed"}
    assert A._verify_signed_json(_signed(raw, k), "tcbInfo", IT._keys()[1].public_key()) == {
        "error": "tcbInfo signature does not verify under the TCB Signing certificate"}


# ------------------------------------------------------------------------------------------ attest_intel: TCB evaluation
def test_svns_and_hex_bytes():
    assert A._svns([5] * 16) is None
    assert A._svns([{"svn": "x"}] * 16) is None
    assert A._svns([{"svn": 1}] * 15) is None
    assert A._svns([{"svn": 3}] * 16) == [3] * 16
    assert A._hex_bytes("ab" * 4, 4) == b"\xab" * 4
    assert A._hex_bytes("AB" * 4, 4) == b"\xab" * 4
    assert A._hex_bytes("ag" * 4, 4) is None


def _comps(**at):
    return [{"svn": at.get(str(i), 0)} for i in range(16)]


def _lvl(sgx=None, tdx=None, pcesvn=0, status="UpToDate", adv=()):
    return {"tcb": {"sgxtcbcomponents": sgx or _comps(), "tdxtcbcomponents": tdx or _comps(), "pcesvn": pcesvn}, "tcbStatus": status, "advisoryIDs": list(adv)}


MODULE = {"mrsigner": "00" * 48, "attributes": "00" * 8, "attributesMask": "FF" * 8}
PCK = {"sgx": bytes(16), "pcesvn": 0}


def _td(minor=0, svn0=0):
    return {"teeTcbSvn": bytes([svn0, minor]) + bytes(14), "mrSignerSeam": bytes(48), "seamAttributes": bytes(8)}


def _ident(id_="TDX_01", status="UpToDate", **kw):
    d = dict(MODULE, id=id_, tcbLevels=[{"tcb": {"isvsvn": 0}, "tcbStatus": status, "advisoryIDs": []}])
    d.update(kw)
    return d


def _ev(levels, minor=0, **info):
    return A._evaluate_tcb(dict({"tcbLevels": levels, "tdxModule": MODULE}, **info), PCK, _td(minor))


BELOW = {"error": "platform TCB is below every level in the TCB info"}


def test_tcb_levels_compare_tdx_components_from_the_right_index():
    assert _ev([_lvl(tdx=_comps(**{"0": 1}))]) == BELOW                                   # module 0: component 0 counts
    assert _ev([_lvl(tdx=_comps(**{"1": 1}))]) == BELOW                                   # ... and component 1
    ids = {"tdxModuleIdentities": [_ident()]}
    ok = {"platform": "UpToDate", "module": "UpToDate", "advisories": []}
    assert _ev([_lvl(tdx=_comps(**{"0": 5, "1": 5}))], minor=1, **ids) == ok               # minor > 0: components 0 and 1 are skipped
    assert _ev([_lvl(tdx=_comps(**{"2": 1}))], minor=1, **ids) == BELOW                    # ... but not component 2


def test_tcb_levels_compare_every_sgx_component_and_continue_past_a_miss():
    assert _ev([_lvl(sgx=_comps(**{"1": 5}))]) == BELOW   # an odd index
    r = _ev([_lvl(sgx=_comps(**{"0": 9}), status="OutOfDate"), _lvl(status="SWHardeningNeeded", adv=["A"])])
    assert r == {"platform": "SWHardeningNeeded", "module": "UpToDate", "advisories": ["A"]}


def test_tcb_level_component_shapes_are_refused():
    bad = {"error": "malformed TCB level components"}
    good = _comps()
    assert _ev([_lvl(sgx=good[:15])]) == bad
    assert _ev([_lvl(tdx=good[:15])]) == bad
    assert _ev([_lvl(pcesvn="x")]) == bad
    assert _ev([_lvl(sgx=good[:15], tdx=good[:15])]) == bad


def test_tdx_module_identity_selection_and_defaults():
    ok = {"platform": "UpToDate", "module": "UpToDate", "advisories": []}
    assert _ev([_lvl()], minor=1) == {"error": "TDX module identity TDX_01 not present in TCB info"}
    assert _ev([_lvl()], minor=1, tdxModuleIdentities="x") == {"error": "TDX module identity TDX_01 not present in TCB info"}
    assert _ev([_lvl()], minor=1, tdxModuleIdentities=[5, _ident()]) == ok
    other = _ev([_lvl()], minor=1, tdxModuleIdentities=[_ident("TDX_02", "OutOfDate"), _ident()])
    assert other["module"] == "UpToDate"
    no_levels = dict(_ident())
    del no_levels["tcbLevels"]
    assert _ev([_lvl()], minor=1, tdxModuleIdentities=[no_levels]) == {"error": "TDX module TDX_01 SVN 0 is below every known level"}


@pytest.mark.parametrize("field", ["mrsigner", "attributes", "attributesMask"])
def test_tdx_module_fields_must_each_be_well_formed(field):
    m = dict(MODULE)
    m[field] = None
    assert _ev([_lvl()], tdxModule=m) == {"error": "TDX module identity fields malformed"}


def test_evaluate_qe_isvsvn_is_sixteen_bit_and_levels_default_to_empty():
    lv = [{"tcb": {"isvsvn": 300}, "tcbStatus": "UpToDate"}]
    assert A._evaluate_qe(IT._ident(isvprodid=2, tcbLevels=lv), IT._qe(svn=0x0100)) == {"error": "QE ISVSVN is below every known level"}
    assert A._evaluate_qe(IT._ident(tcbLevels=None), IT._qe()) == {"error": "QE ISVSVN is below every known level"}


def test_collateral_checks_the_first_seam_attribute_byte(monkeypatch):
    def tweak(b):
        for x in b["tdxModuleIdentities"]:
            if x["id"] == "TDX_01":
                x["attributes"], x["attributesMask"] = "01" + "00" * 7, "FF" * 8

    IT._patch_docs(monkeypatch, tweak, None)
    assert IT._vcol() == {"ok": False, "reason": "TCB evaluation: TD report SEAM attributes do not match the TDX module identity"}


# ------------------------------------------------------------------------------------------ attest_intel: the verifier object
def _opts(**pol):
    return {"binding": "report-data", "policy": dict({"mrtds": [IT.MRTD]}, **pol)}


def test_verifier_mr_lists_must_be_hex_strings_of_48_bytes():
    for bad in ([5], ["zz" * 48]):
        with pytest.raises(AttestConstructError) as e:
            A.IntelDcapVerifier(_opts(mrSeams=bad))
        assert str(e.value) == "createIntelDcapVerifier: every mrSeams entry must be 96 hex chars (48 bytes)"
    A.IntelDcapVerifier(_opts(mrSeams=["aB" * 48]))


def test_verifier_pin_is_lowercased():
    o = _opts()
    o["trustAnchorRootCaSpkiSha256"] = "AB" * 32
    assert A.IntelDcapVerifier(o)._pin == "ab" * 32
    assert A.IntelDcapVerifier(_opts())._pin == A.INTEL_SGX_ROOT_CA_SPKI_SHA256


def _verifier(resolve, **pol):
    o = _opts(**pol)
    o["resolve_evidence"] = resolve
    return A.IntelDcapVerifier(o)


def test_verifier_hands_the_document_to_the_resolver():
    seen = []
    v = _verifier(lambda d: seen.append(d) or {})
    assert v.verify("DOC", {}, 1) == {"ok": False, "reason": "no Intel DCAP quote for this action"}
    assert seen == ["DOC"]


@pytest.mark.parametrize("q,want", [
    ({"ok": True}, "DCAP quote invalid: unknown"),
    ({"ok": True, "report": {}, "measured": {}, "fmspc": ""}, "DCAP quote invalid: unknown"),
    ({"ok": True, "measured": {}, "fmspc": "x"}, "DCAP quote invalid: unknown"),
    ({"ok": False, "report": {}, "measured": {}, "fmspc": "x", "reason": "r"}, "DCAP quote invalid: r"),
])
def test_verifier_quote_result_gate(monkeypatch, q, want):
    monkeypatch.setattr(A, "verify_genuine_tdx_quote", lambda *a: q)
    assert _verifier(lambda d: {"quote": b"q"}).verify("d", {}, 1) == {"ok": False, "reason": want}


def test_verifier_collateral_refusal_without_a_reason(monkeypatch):
    monkeypatch.setattr(A, "verify_genuine_tdx_quote", lambda *a: {"ok": True, "report": {"reportData": b"R"}, "measured": {"m": 1}, "fmspc": "ff"})
    monkeypatch.setattr(A, "attestation_binding", lambda e: b"R")
    monkeypatch.setattr(A, "verify_intel_tdx_collateral", lambda *a: {"ok": False})
    v = _verifier(lambda d: {"quote": b"q", "collateral": {"x": 1}})
    assert v.verify("d", {}, 1) == {"ok": False, "reason": "Intel collateral: rejected"}


def test_verifier_unexpected_error_fails_closed():
    def boom(d):
        raise RuntimeError("boom")

    assert _verifier(boom).verify("d", {}, 1) == {"ok": False, "reason": "intel-dcap verification error (fail closed): boom"}


def test_text_replaces_undecodable_bytes():
    assert A._text(b"a\xffb") == "a�b"
    assert A._text(bytearray(b"ok")) == "ok"
    assert A._text("s") == "s"


# ------------------------------------------------------------------------------------------ attest_ocsp
def test_ocsp_time_range_year_pivot_and_month_12():
    f = O._time_in_range
    assert f("000229000000Z", True) is True    # yy 00 is 2000: a leap year
    assert f("520229000000Z", True) is True    # yy 52 is 1952: a leap year
    assert f("010229000000Z", True) is False
    assert f("251231000000Z", True) is True
    assert f("251301000000Z", True) is False


def test_ocsp_generalized_time_keeps_three_fraction_digits():
    assert O._gen_time_ms("20250101000000.1239Z") == O._gen_time_ms("20250101000000Z") + 123


def test_verify_sig_refuses_a_non_rsa_key_for_an_rsa_algorithm(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    monkeypatch.setattr(O, "rsa_pkcs1_verify", lambda *a: True)
    assert O._verify_sig("1.2.840.113549.1.1.11", b"m", b"s", ed25519.Ed25519PrivateKey.generate().public_key()) is False


def test_verify_sig_verifier_error_is_false(monkeypatch):
    def boom(*a):
        raise RuntimeError("x")

    monkeypatch.setattr(O, "ecdsa_verify_der", boom)
    assert O._verify_sig(OT.ECDSA_SHA256, b"m", b"s", OT._k()["ca"].public_key()) is False


def _fake_cert(oid_, value):
    return types.SimpleNamespace(extensions=lambda: {oid_: CertExtension(False, value)})


def test_eku_elements_are_bounded_by_their_sequence():
    assert O._eku_of(_fake_cert(O.OID_EKU, b"\x30\x02\x06\x05" + b"\x00" * 8)) is None
    assert O._eku_of(_fake_cert(O.OID_EKU, seq(oid(O.OID_EKU_OCSP_SIGNING)))) == [O.OID_EKU_OCSP_SIGNING]


class _StrictInt:
    """int with Python 3.9/3.10 semantics: int.from_bytes needs its byteorder."""

    def __new__(cls, *a, **k):
        return int(*a, **k)

    @staticmethod
    def from_bytes(b, byteorder, *, signed=False):
        return int.from_bytes(b, byteorder, signed=signed)


def test_integer_decoding_names_its_byte_order(monkeypatch):
    monkeypatch.setattr(O, "int", _StrictInt, raising=False)
    assert OT._view(OT._v()) == OT._ok()
    at = OT._gt(OT._ms(2025, 1, 1))
    r = OT._v(OT._fresh(status=tlv(0xA1, at + tlv(0xA0, tlv(0x0A, b"\x04")))))
    assert (r["status"], r["revocationReason"]) == ("revoked", 4)


def test_missing_tbs_response_data_is_refused_through_a_seam(monkeypatch):
    real = O._children

    def fake(der, t):
        out = real(der, t)
        if len(out) >= 3 and out[0][0].tag == 0x30 and out[1][0].tag == 0x30 and out[2][0].tag == 0x03:
            return [(Tlv(0x30, 0, 0), 0)] + out[1:]
        return out

    monkeypatch.setattr(O, "_children", fake)
    assert OT._v() == {"ok": False, "reason": "missing tbsResponseData"}


@pytest.mark.parametrize("window", [(0, None), (None, 10 ** 18)])
def test_delegated_responder_with_one_unparseable_validity_bound(monkeypatch, window):
    d = OT._responder()
    der = OT._resp(OT._basic(OT._tbs(rid=OT._rid_name(d)), key="resp", certs=[d]))
    monkeypatch.setattr(O, "der_validity_ms", lambda raw: window)
    assert OT._v(der) == {"ok": False, "reason": "delegated responder certificate is outside its validity window"}


def test_delegated_responder_may_be_signed_by_a_chain_starting_at_the_issuer():
    root, ca, leaf = OT._pki()
    above = OT._responder(signer="root", issuer_cn="Root")
    der = OT._resp(OT._basic(OT._tbs(rid=OT._rid_name(above)), key="resp", certs=[above]))
    assert OT._view(OT._v(der, chain=[ca, root, leaf])) == OT._ok(responder="delegated")


URL = b"http://x.io"
OCSP_AD = tlv(0x06, bytes.fromhex("2b06010505073001"))


def test_aia_elements_are_bounded_by_their_parent():
    ad = OCSP_AD + tlv(0x86, URL)
    assert O.cert_ocsp_urls(_fake_cert(O.OID_AIA, seq(tlv(0x30, ad)))) == ["http://x.io"]
    assert O.cert_ocsp_urls(_fake_cert(O.OID_AIA, b"\x30\x02\x30" + bytes([len(ad)]) + ad)) == []      # the AccessDescription overruns the SEQUENCE
    assert O.cert_ocsp_urls(_fake_cert(O.OID_AIA, seq(tlv(0x30, OCSP_AD + b"\x86" + bytes([len(URL)]))) + URL)) == []   # the location overruns its AccessDescription


def test_chain_ocsp_uses_the_chain_and_the_age_limit():
    root, ca, leaf = OT._pki()
    chain = [leaf, ca, root]
    d = OT._responder()
    delegated = OT._resp(OT._basic(OT._tbs(rid=OT._rid_name(d)), key="resp", certs=[d]))
    assert O.check_nvidia_chain_ocsp(chain, [delegated], OT.NOW) == {"ok": True, "verifiedCrls": 0, "verifiedOcsp": 1, "statuses": {0: "good", 1: "absent"}}
    aged = OT._fresh(this=OT.NOW - OT.HOUR, nxt=None)
    assert O.check_nvidia_chain_ocsp(chain, [aged], OT.NOW, OT.HOUR)["ok"] is True
    assert O.check_nvidia_chain_ocsp(chain, [aged], OT.NOW, OT.HOUR - 1) == {
        "ok": False,
        "reason": "OCSP response #0 for '%s' rejected: response is older than the maximum accepted age" % O._subj(leaf),
        "statuses": {0: "absent", 1: "absent"},
    }
