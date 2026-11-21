"""Intel TDX DCAP kill tests of the 0.5 mutation baseline (attest_intel.py). Every expectation is the TypeScript reference's
(packages/pca/src/attest-intel-tdx.ts, attest-intel-collateral.ts): parse_dcap_quote's every truncation message, the
PCK TCB extension reader's refusals and its 64-component bound, verify_intel_pck_chain's exact refusal dicts over minted
chains (plus the unreachable issuer/subject-link refusal through a Cert seam), verify_genuine_tdx_quote and
verify_intel_tdx_collateral over the REAL Azure TDX quote + Intel PCS collateral of the shared vectors (signature checks
seamed where a field must change), the CRL reader / verifier (EC and RSA), Date.UTC / Date.parse emulation (values taken
from V8), and _evaluate_qe."""
import calendar
import copy
import datetime
import functools
import hashlib
import types

import pytest

pytest.importorskip("cryptography")

from atlas_pca import attest_intel as A
from atlas_pca.attest import evidence_for
from atlas_pca.attest_cert import Cert
from atlas_pca.attest_der import check_chain_roles
from test_attest_units import integer, octets, oid, seq, tlv

MRTD = "a2e61f1316e9e367e9c1f7a0adc98c48eb13875c399c85d286cee5ea2b05e57f2df9f61d903b0ae7ac5607d843dfffc1"
FMSPC = "90c06f000000"


def _ms(y, mo, d, h=0, mi=0, s=0):
    return calendar.timegm((y, mo, d, h, mi, s)) * 1000


@functools.lru_cache(maxsize=None)
def _real():
    import test_attestation_vectors as TV

    doc = TV.load()
    row = next(r for r in doc["attestation_vectors"] if r["id"] == "tdx-real-positive")
    h = TV.hydrate(row, doc["blobs"])
    ev = evidence_for("intel-tdx-dcap", h["evidence"])
    return ev["quote"], ev["collateral"], h["now"], h["expected_binding"]


def _col():
    return dict(_real()[1])


def _flip(q, off, bits=1):
    b = bytearray(q)
    b[off] ^= bits
    return bytes(b)


# ---------------------------------------------------------------------------------------------- parse_dcap_quote
def _u16(n):
    return n.to_bytes(2, "little")


def _u32(n):
    return n.to_bytes(4, "little")


QS, AK, QE, QES = b"\x01" * 64, b"\x02" * 64, b"\x03" * 384, b"\x04" * 64


def _q(sig_body, pad=b""):
    h = bytearray(636)
    h[0:2], h[2:4], h[4:8] = _u16(4), _u16(2), _u32(0x81)
    h[48:632] = bytes(i % 251 for i in range(584))
    h[632:636] = _u32(len(sig_body))
    return bytes(h) + sig_body + pad


def _outer(rest, outer_type=6, outer_size=None):
    return QS + AK + _u16(outer_type) + _u32(len(rest) if outer_size is None else outer_size) + rest


def _rest(auth=b"\x05\x06", inner_type=5, pem=b"PEM", inner_size=None):
    return QE + QES + _u16(len(auth)) + auth + _u16(inner_type) + _u32(len(pem) if inner_size is None else inner_size) + pem


def _perr(quote):
    with pytest.raises(ValueError) as e:
        A.parse_dcap_quote(quote)
    return str(e.value)


def test_parse_dcap_quote_happy_path_and_every_truncation_message():
    r = A.parse_dcap_quote(_q(_outer(_rest()), pad=b"\x00\x00"))
    assert r == {"version": 4, "attKeyType": 2, "teeType": 0x81, "header": _q(b"")[:48], "tdReportBody": _q(b"")[48:632], "quoteSignature": QS,
                 "akPubRaw": AK, "qeReportBody": QE, "qeReportSignature": QES, "qeAuthData": b"\x05\x06", "pckChainPem": "PEM"}
    p = "parseDcapQuote: "
    assert _perr(_q(QS[:63])) == p + "truncated reading quote signature"
    assert _perr(_q(QS + AK[:63])) == p + "truncated reading attestation public key"
    assert _perr(_q(QS + AK + b"\x06\x00\x00\x00\x00")) == p + "truncated reading outer cert-data header"
    assert _perr(_q(_outer(_rest(), outer_type=7))) == p + "outer cert-data type 7 (expected QE-report-cert-data = 6)"
    assert _perr(_q(_outer(_rest(), outer_size=len(_rest()) + 1))) == p + "outer cert-data overruns signature data"
    assert _perr(_q(_outer(QE[:383]))) == p + "truncated reading QE report"
    assert _perr(_q(_outer(QE + QES[:63]))) == p + "truncated reading QE report signature"
    assert _perr(_q(_outer(QE + QES + b"\x02"))) == p + "truncated reading QE auth-data size"
    assert _perr(_q(_outer(QE + QES + _u16(5) + b"ab"))) == p + "truncated reading QE auth-data"
    assert _perr(_q(_outer(QE + QES + _u16(0) + b"\x05\x00\x00\x00\x00"))) == p + "truncated reading inner cert-data header"
    assert _perr(_q(_outer(_rest(inner_type=4)))) == p + "inner cert-data type 4 (expected PCK-cert-chain = 5)"
    assert _perr(_q(_outer(_rest(inner_size=4)))) == p + "inner cert-data overruns outer cert-data"
    assert _perr(_q(_outer(_rest()), pad=b"\x00\x01")) == p + "non-zero bytes after the signature data"


def test_parse_dcap_quote_exact_fits_and_slack():
    # an empty QE auth-data and an outer wrapper larger than its content (inside the signature data) both parse
    r = A.parse_dcap_quote(_q(_outer(_rest(auth=b"", pem=b"")) + b"\x00" * 3))
    assert (r["qeAuthData"], r["pckChainPem"]) == (b"", "")
    rest = _rest()
    r = A.parse_dcap_quote(_q(_outer(rest, outer_size=len(rest) + 2) + b"zz"))
    assert r["pckChainPem"] == "PEM"


def test_parse_dcap_td_report():
    body = bytes(i % 251 for i in range(584))
    want = {"teeTcbSvn": body[0:16], "mrSeam": body[16:64], "mrSignerSeam": body[64:112], "tdAttributes": body[120:128], "mrTd": body[136:184],
            "mrConfigId": body[184:232], "rtmr0": body[328:376], "rtmr1": body[376:424], "rtmr2": body[424:472], "rtmr3": body[472:520],
            "reportData": body[520:584], "raw": body}
    assert A.parse_dcap_td_report(body) == want
    assert A.parse_dcap_td_report(body + b"tail") == want  # raw is the 584-byte report only
    with pytest.raises(ValueError) as e:
        A.parse_dcap_td_report(body[:583])
    assert str(e.value) == "parseDcapTdReport: body too short (583 < 584)"


# ---------------------------------------------------------------------------------------------- extract_pck_fmspc_and_tcb
FM_OID = bytes.fromhex("060a2a864886f84d010d0104")
TCB_OID = bytes.fromhex("060a2a864886f84d010d0102")
FM = bytes.fromhex("00606a000000")


def _comp(n, val):
    return seq(tlv(0x06, bytes.fromhex("2a864886f84d010d0102") + bytes([n])), val)


def _leaf(*comps):
    return FM_OID + octets(FM) + TCB_OID + seq(*comps)


def _xerr(der):
    with pytest.raises(ValueError) as e:
        A.extract_pck_fmspc_and_tcb(der)
    return str(e.value)


def test_extract_pck_tcb_component_refusals():
    p = "extractPckFmspcAndTcb: "
    # the component's OID TLV overruns the buffer (None), or the first element is not an OID
    assert _xerr(_leaf(tlv(0x30, b"\x06\x7f"))) == p + "TCB component missing OID"
    assert _xerr(_leaf(seq(integer(5), integer(1)))) == p + "TCB component missing OID"
    assert _xerr(_leaf(tlv(0x30, b"\x06\x01\x11"))) == p + "TCB component missing value"
    assert _xerr(_leaf(integer(1))) == p + "malformed TCB component"
    assert _xerr(FM_OID + tlv(0x04, b"\x00" * 7)) == p + "malformed FMSPC OCTET STRING"
    assert _xerr(FM_OID + b"\x04") == p + "malformed FMSPC OCTET STRING"
    assert _xerr(FM_OID + octets(FM) + TCB_OID + b"\x30") == p + "malformed TCB SEQUENCE"


def test_extract_pck_tcb_values():
    comps = [_comp(i, tlv(0x02, bytes([1, i]))) for i in range(1, 17)]  # 2-byte INTEGER: only the low byte is the SVN
    got = A.extract_pck_fmspc_and_tcb(_leaf(*comps + [_comp(17, tlv(0x02, b"\x01\x02\x03")), _comp(0, integer(9)), _comp(19, integer(9)),
                                                    _comp(18, octets(b"\x07" * 16))]))
    assert got == {"fmspc": FM, "sgxTcbComponents": bytes(range(1, 17)), "pcesvn": 0x0203, "cpusvn": b"\x07" * 16}
    assert A.extract_pck_fmspc_and_tcb(_leaf(_comp(17, tlv(0x02, b"")), _comp(18, integer(1)))) == {
        "fmspc": FM, "sgxTcbComponents": bytes(16), "pcesvn": 0, "cpusvn": b""}  # an INTEGER on arc 18 is not the CPUSVN
    assert A.extract_pck_fmspc_and_tcb(_leaf(_comp(17, integer(1)), _comp(5, octets(b"\x07"))))["cpusvn"] == b""  # nor an OCTET STRING on another arc
    # a non-INTEGER value of an SVN arc is ignored
    assert A.extract_pck_fmspc_and_tcb(_leaf(_comp(3, octets(b"\x09")), _comp(17, integer(4))))["sgxTcbComponents"] == bytes(16)


def test_extract_pck_tcb_reads_at_most_65_components():
    filler = [_comp(18, octets(b"")) for _ in range(64)]
    assert A.extract_pck_fmspc_and_tcb(_leaf(*filler + [_comp(17, integer(7))]))["pcesvn"] == 7
    assert _xerr(_leaf(*filler + [_comp(18, octets(b"")), _comp(17, integer(7))])) == "extractPckFmspcAndTcb: PCESVN not found in TCB extension"


# ---------------------------------------------------------------------------------------------- verify_intel_pck_chain (minted)
def _c():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    return types.SimpleNamespace(x509=x509, hashes=hashes, serialization=serialization, ec=ec, rsa=rsa, NameOID=NameOID)


NB, NA = datetime.datetime(2025, 1, 1), datetime.datetime(2035, 1, 1)


def _mint(cn, issuer_cn, pub, signer, serial, ca, exts=(), nb=NB, na=NA):
    c = _c()
    name = lambda v: c.x509.Name([c.x509.NameAttribute(c.NameOID.COMMON_NAME, v)])  # noqa: E731
    b = (c.x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer_cn)).public_key(pub).serial_number(serial)
         .not_valid_before(nb).not_valid_after(na).add_extension(c.x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(c.x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    for e, crit in exts:
        b = b.add_extension(e, critical=crit)
    return b.sign(signer, c.hashes.SHA256()).public_bytes(c.serialization.Encoding.DER)


def _pem(der):
    c = _c()
    return c.x509.load_der_x509_certificate(der).public_bytes(c.serialization.Encoding.PEM).decode()


@functools.lru_cache(maxsize=None)
def _keys():
    c = _c()
    return [c.ec.generate_private_key(c.ec.SECP256R1()) for _ in range(4)]


def _chain(leaf_signer=None, inter_signer=None, root_signer=None, leaf_ca=False, leaf_exts=(), leaf_key=None, inter_ca=True):
    rk, ik, lk, _ = _keys()
    root = _mint("Root", "Root", rk.public_key(), root_signer or rk, 1, True)
    inter = _mint("Inter", "Root", ik.public_key(), inter_signer or rk, 2, inter_ca)
    leaf = _mint("Leaf", "Inter", (leaf_key or lk).public_key(), leaf_signer or ik, 3, leaf_ca, leaf_exts)
    return root, inter, leaf


def _pin():
    c = _c()
    spki = _keys()[0].public_key().public_bytes(c.serialization.Encoding.DER, c.serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


NOW = _ms(2026, 6, 1)


def _vc(certs, pin=None, now=NOW):
    return A.verify_intel_pck_chain("".join(_pem(d) for d in certs), pin if pin is not None else _pin(), now)


def test_pck_chain_accepts_in_any_order_and_returns_the_leaf():
    root, inter, leaf = _chain()
    r = _vc([root, leaf, inter])
    assert (r["ok"], r["leafDer"], r["depth"]) == (True, leaf, 3)
    assert r["leafKey"].public_numbers() == _keys()[2].public_key().public_numbers()
    assert set(r) <= {"ok", "leafKey", "leafDer", "leafCert", "depth"}
    assert _vc([leaf, inter, root], pin=_pin().upper())["ok"] is True


def test_pck_chain_exact_refusals():
    root, inter, leaf = _chain()
    other = _keys()[3]
    stray = _mint("Stray", "Stray", other.public_key(), other, 9, True)
    fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
    assert A.verify_intel_pck_chain(None, _pin(), NOW) == fail("no PEM certificates in the PCK chain")
    assert A.verify_intel_pck_chain("no pem here", _pin(), NOW) == fail("no PEM certificates in the PCK chain")
    assert _vc([leaf, inter]) == fail("PCK chain does not terminate in a self-signed root")
    assert _vc([leaf, inter, root, stray]) == fail("PCK chain is not a single connected path (orphan/duplicate certificates)")
    assert _vc([leaf, inter, root], now=float("nan")) == fail("nowMs is not a finite number")
    assert _vc([leaf, inter, root], now=_ms(2024, 12, 31)) == {"ok": False, "reason": "PCK chain certificate outside its validity period", "failure": "validity"}
    assert _vc([leaf, inter, root], now=_ms(2025, 1, 1))["ok"] is True
    assert _vc(_chain(leaf_signer=other)[::-1]) == fail("certificate at depth 0 is not signed by its issuer")
    assert _vc(_chain(inter_signer=other)[::-1]) == fail("certificate at depth 1 is not signed by its issuer")
    assert _vc(_chain(root_signer=other)[::-1]) == fail("root certificate is not self-signed")
    assert _vc([leaf, inter, root], pin="00" * 32) == fail("Intel SGX Root CA does not match the pinned trust anchor")
    assert A.verify_intel_pck_chain(_pem(leaf) + _pem(inter) + _pem(root), None, NOW) == fail("Intel SGX Root CA does not match the pinned trust anchor")
    bad_roles = _chain(inter_ca=False)
    assert _vc(bad_roles[::-1]) == fail(check_chain_roles([bad_roles[2], bad_roles[1], bad_roles[0]]))
    assert _vc(_chain(leaf_ca=True)[::-1]) == fail("leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)")
    c = _c()
    crit = (c.x509.UnrecognizedExtension(c.x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00"), True)
    assert _vc(_chain(leaf_exts=[crit])[::-1]) == fail("PCK chain certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    p384 = c.ec.generate_private_key(c.ec.SECP384R1())
    r = _vc(_chain(leaf_key=p384)[::-1])
    assert r["ok"] is False and r["reason"].startswith("PCK chain X.509 verification error (fail closed): ")
    r = A.verify_intel_pck_chain("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----", _pin(), NOW)
    assert set(r) == {"ok", "reason"} and r["ok"] is False and r["reason"].startswith("PCK chain X.509 verification error (fail closed): ")


def test_pck_chain_rsa_leaf_is_refused():
    c = _c()
    rk, ik, _, _ = _keys()
    rsa_leaf = c.rsa.generate_private_key(public_exponent=65537, key_size=1024)
    root = _mint("Root", "Root", rk.public_key(), rk, 1, True)
    inter = _mint("Inter", "Root", ik.public_key(), rk, 2, True)
    leaf = _mint("Leaf", "Inter", rsa_leaf.public_key(), ik, 3, False)
    assert _vc([leaf, inter, root]) == {"ok": False, "reason": "PCK leaf key is not EC (got rsa)"}


def test_pck_chain_defaults_now_to_the_wall_clock(monkeypatch):
    root, inter, leaf = _chain()
    pem = _pem(leaf) + _pem(inter) + _pem(root)
    monkeypatch.setattr(A, "time", types.SimpleNamespace(time=lambda: _ms(2024, 6, 1) / 1000))
    assert A.verify_intel_pck_chain(pem, _pin()) == {"ok": False, "reason": "PCK chain certificate outside its validity period", "failure": "validity"}
    monkeypatch.setattr(A, "time", types.SimpleNamespace(time=lambda: NOW / 1000))
    assert A.verify_intel_pck_chain(pem, _pin())["ok"] is True


class _Fake:
    def __init__(self, subject, issuers):
        self.subject, self._iss, self.raw = subject, list(issuers), b""

    @property
    def issuer(self):
        return self._iss.pop(0) if len(self._iss) > 1 else self._iss[0]


def test_pck_chain_issuer_subject_link_refusal_through_a_seam(monkeypatch):
    # the ordering walk links child.issuer to parent.subject, so the explicit re-check only fires if a name read changes;
    # the seam makes the leaf's 4th issuer read differ
    certs = iter([_Fake("L", ["P", "P", "P", "Z"]), _Fake("P", ["P"])])
    monkeypatch.setattr(A, "Cert", types.SimpleNamespace(from_pem=lambda b: next(certs)))
    monkeypatch.setattr(A, "x509_valid_at", lambda *a: True)
    pem = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n" * 2
    assert A.verify_intel_pck_chain(pem, None, 1) == {"ok": False, "reason": "certificate at depth 0 issuer does not match its parent subject"}


# ---------------------------------------------------------------------------------------------- verify_genuine_tdx_quote (real quote)
TD, QE_OFF, AUTH_OFF = 48, 770, 1220


def _g(quote=None, pin=None, expected=None, policy=None, now=None):
    q, _, n, _ = _real()
    return A.verify_genuine_tdx_quote(q if quote is None else quote, pin, expected, policy, n if now is None else now)


def test_genuine_real_quote_accepts_with_the_reference_fields():
    q = _real()[0]
    r = _g()
    assert r["ok"] is True
    assert (r["fmspc"], r["chainDepth"]) == (FMSPC, 3)
    assert r["measured"] == {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": MRTD, "operator": ""}
    assert r["report"] == A.parse_dcap_td_report(q[TD:TD + 584])
    assert r["pckTcb"]["fmspc"] == bytes.fromhex(FMSPC)
    assert r["akPub"] == {"point": b"\x04" + q[700:764]}
    assert set(r) == {"ok", "report", "fmspc", "pckTcb", "akPub", "chainDepth", "measured"}
    assert _g(pin=A.INTEL_SGX_ROOT_CA_SPKI_SHA256.upper())["ok"] is True
    assert _g(policy={})["ok"] is True


def test_genuine_real_quote_exact_refusals():
    q, _, now, exp = _real()
    fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
    assert _g(expected=exp) == fail("report_data does not bind holder/grant/epoch/nonce")  # Azure binds runtime data, not report_data
    assert _g(expected=dict(exp, holderPub="")) == fail("binding not constructible: binding: holderPub required")
    assert _g(pin="00" * 32) == fail("PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor")
    assert _g(now=0) == fail("PCK chain invalid: PCK chain certificate outside its validity period")
    assert _g(quote=q[:100]) == fail("quote parse failed: parseDcapQuote: too short for header + TD report + sig length")
    assert _g(quote=_flip(q, TD + 200)) == fail("TD quote signature does not verify under the attestation key")
    assert _g(quote=_flip(q, 636)) == fail("TD quote signature does not verify under the attestation key")
    assert _g(quote=_flip(q, QE_OFF + 100)) == fail("QE report signature does not verify under the PCK leaf")
    assert _g(quote=_flip(q, AUTH_OFF)) == fail("QE report_data does not bind the attestation key (AK not endorsed by this QE)")


def test_genuine_policy_allowlists():
    q = _real()[0]
    rep = A.parse_dcap_td_report(q[TD:TD + 584])
    hx = lambda b: b.hex()  # noqa: E731
    fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
    assert _g(policy={"mrtds": [MRTD.upper()]})["ok"] is True
    assert _g(policy={"mrtds": []})["ok"] is True
    assert _g(policy={"mrtds": "x"})["ok"] is True
    assert _g(policy={"mrtds": ["00" * 48]}) == fail("MRTD not in policy allowlist")
    assert _g(policy={"fmspcs": [FMSPC.upper()]})["ok"] is True
    assert _g(policy={"fmspcs": []})["ok"] is True
    assert _g(policy={"fmspcs": ["000000000000"]}) == fail("FMSPC not in policy allowlist")
    assert _g(policy={"mrSeams": [hx(rep["mrSeam"]).upper()]})["ok"] is True
    assert _g(policy={"mrSeams": []}) == fail("MRSEAM not in policy allowlist")
    assert _g(policy={"mrSeams": ["11" * 48]}) == fail("MRSEAM not in policy allowlist")
    assert _g(policy={"mrSignerSeams": [hx(rep["mrSignerSeam"])]})["ok"] is True
    assert _g(policy={"mrSignerSeams": []}) == fail("MRSIGNERSEAM not in policy allowlist")
    assert _g(policy={"rtmrs": [hx(rep["rtmr0"]).upper()]})["ok"] is True
    assert _g(policy={"rtmrs": []})["ok"] is True
    assert _g(policy={"rtmrs": ["ff" * 48]}) == fail("RTMR0 not in policy allowlist")


def test_genuine_debug_bits_and_ak_point_with_the_signatures_seamed(monkeypatch):
    q = _real()[0]
    monkeypatch.setattr(A, "_verify_p256", lambda *a: True)
    fail = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
    dbg = _flip(q, TD + 120, 1)
    assert _g(quote=dbg) == fail("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)")
    assert _g(quote=dbg, policy={}) == fail("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)")
    assert _g(quote=dbg, policy={"allowDebug": 1}) == fail("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)")
    assert _g(quote=dbg, policy={"allowDebug": True})["ok"] is True
    assert _g(quote=_flip(q, TD + 121, 1))["ok"] is True  # only bit 0 of byte 0 is DEBUG
    assert _g(quote=_flip(q, QE_OFF + 48, 0x02)) == fail("QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)")
    assert _g(quote=_flip(q, QE_OFF + 48, 0x08))["ok"] is True
    assert _g(quote=_flip(q, QE_OFF + 320 + 63, 1)) == fail("QE report_data does not bind the attestation key (AK not endorsed by this QE)")
    # an off-curve AK whose hash the QE report_data does carry
    b = bytearray(q)
    b[700:764] = bytes(64)
    auth_len = int.from_bytes(q[AUTH_OFF - 2:AUTH_OFF], "little")
    b[QE_OFF + 320:QE_OFF + 352] = hashlib.sha256(bytes(64) + q[AUTH_OFF:AUTH_OFF + auth_len]).digest()
    assert _g(quote=bytes(b)) == fail("attestation public key is not a valid P-256 point")


@pytest.mark.parametrize("inner,want", [
    ({"ok": True}, "PCK chain invalid: unknown"),
    ({"ok": True, "leafKey": 1}, "PCK chain invalid: unknown"),
    ({"ok": True, "leafDer": b"x"}, "PCK chain invalid: unknown"),
    ({"ok": False, "leafKey": 1, "leafDer": b"x"}, "PCK chain invalid: unknown"),
    ({"ok": False, "reason": "why"}, "PCK chain invalid: why"),
    ({"ok": False, "reason": ""}, "PCK chain invalid: "),     # `??`: an empty reason is kept
    ({"ok": False, "reason": None}, "PCK chain invalid: unknown"),
])
def test_genuine_chain_result_seam(monkeypatch, inner, want):
    monkeypatch.setattr(A, "verify_intel_pck_chain", lambda *a: inner)
    assert _g() == {"ok": False, "reason": want}


def test_genuine_inner_failures_through_seams(monkeypatch):
    def boom(*a):
        raise ValueError("boom")

    monkeypatch.setattr(A, "extract_pck_fmspc_and_tcb", boom)
    assert _g() == {"ok": False, "reason": "PCK FMSPC/TCB extraction failed: boom"}
    monkeypatch.undo()
    monkeypatch.setattr(A, "parse_dcap_td_report", boom)
    assert _g() == {"ok": False, "reason": "TD report parse failed: boom"}
    monkeypatch.undo()

    def rt(*a):
        raise RuntimeError("rt")

    monkeypatch.setattr(A, "verify_intel_pck_chain", rt)
    assert _g() == {"ok": False, "reason": "genuine TDX verification error (fail closed): rt"}


# ---------------------------------------------------------------------------------------------- DER tlv / time / CRL
def test_tlv_reader():
    t = A._tlv(b"\x30\x82\x00\x01\x05", 0)
    assert (t.tag, t.start, t.end, t.next) == (0x30, 4, 5, 5)
    t = A._tlv(b"\x04\x84\x00\x00\x00\x01\x07", 0)
    assert (t.start, t.end) == (6, 7)
    for der, msg in ((b"\x30", "DER truncated"), (b"\x30\x80", "DER bad length"), (b"\x30\x85\x00\x00\x00\x00\x01\x00", "DER bad length"),
                     (b"\x30\x82\x00", "DER bad length"), (b"\x30\x02\x00", "DER overrun")):
        with pytest.raises(ValueError) as e:
            A._tlv(der, 0)
        assert str(e.value) == msg
    with pytest.raises(ValueError) as e:
        A._tlv(b"\x30\x02\x00\x00", 0, 3)
    assert str(e.value) == "DER overrun"
    with pytest.raises(ValueError) as e:
        A._tlv(b"\x30\x00", 1)
    assert str(e.value) == "DER truncated"


def _dt(tag, text):
    der = tlv(tag, text.encode())
    return A._der_time(der, A._tlv(der, 0))


def test_der_time_matches_date_utc():
    # values: V8's Date.UTC for the same fields
    assert _dt(0x18, "20250102033005Z") == 1735788605000
    assert _dt(0x17, "250102033005Z") == 1735788605000
    assert _dt(0x17, "500102033005Z") == -631052995000
    assert _dt(0x17, "491231235959Z") == 2524607999000
    assert _dt(0x18, "20251301000000Z") == 1767225600000   # month 13 rolls into the next year
    assert _dt(0x18, "20250132000000Z") == 1738368000000   # day 32 rolls into February
    assert _dt(0x18, "20250101240000Z") == 1735776000000
    assert _dt(0x18, "20250100000000Z") == 1735603200000   # day 0 is the last of the previous month
    assert _dt(0x18, "20250001000000Z") == 1733011200000   # month 0 is December of the previous year
    assert _dt(0x18, "20250101000060Z") == 1735689660000
    assert _dt(0x18, "20250101006000Z") == 1735693200000
    assert _dt(0x18, "00500101000000Z") == -631152000000   # Date.UTC maps years 0..99 to 1900..1999
    assert _dt(0x18, "00990101000000Z") == 915148800000
    assert _dt(0x18, "01000101000000Z") == -59011459200000
    for tag, text, msg in ((0x17, "2501020330Z", "bad UTCTime"), (0x17, "20250102033005Z", "bad UTCTime"),
                           (0x18, "250102033005Z", "bad GeneralizedTime"), (0x18, "20250102033005", "bad GeneralizedTime"),
                           (0x02, "250102033005Z", "not a DER time")):
        with pytest.raises(ValueError) as e:
            _dt(tag, text)
        assert str(e.value) == msg


def test_date_utc_direct():
    assert A._date_utc(2025, 0, 2, 3, 30, 5) == 1735788605000
    assert A._date_utc(99, 0, 1, 0, 0, 0) == 915148800000
    assert A._date_utc(0, 0, 1, 0, 0, 0) == -2208988800000   # Date.UTC(0, 0, 1) is 1900-01-01
    assert A._date_utc(100, 0, 1, 0, 0, 0) == -59011459200000
    assert A._date_utc(2025, 12, 1, 0, 0, 0) == 1767225600000
    assert A._date_utc(2025, -1, 1, 0, 0, 0) == 1733011200000
    assert A._date_utc(2025, 0, 1, 0, 0, 1) - A._date_utc(2025, 0, 1, 0, 0, 0) == 1000
    assert A._date_utc(2025, 0, 1, 0, 1, 0) - A._date_utc(2025, 0, 1, 0, 0, 0) == 60000
    assert A._date_utc(2025, 0, 1, 1, 0, 0) - A._date_utc(2025, 0, 1, 0, 0, 0) == 3600000


ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))
CRL_NAME = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0C, b"CRL"))))
THIS, NEXT = tlv(0x17, b"260101000000Z"), tlv(0x17, b"270101000000Z")


def _crl_tbs(this=THIS, nxt=NEXT, revoked=None, version=True, issuer=CRL_NAME):
    parts = ([integer(1)] if version else []) + [ECDSA_SHA256, issuer, this] + ([nxt] if nxt is not None else [])
    if revoked is not None:
        parts.append(seq(*[seq(tlv(0x02, r), tlv(0x17, b"250101000000Z")) for r in revoked]))
    return seq(*parts)


def _crl(tbs, key=None):
    c = _c()
    k = key or _keys()[0]
    return seq(tbs, ECDSA_SHA256, tlv(0x03, b"\x00" + k.sign(tbs, c.ec.ECDSA(c.hashes.SHA256()))))


def _crl_err(der):
    with pytest.raises(ValueError) as e:
        A._parse_crl(der)
    return str(e.value)


def test_parse_crl_exact():
    tbs = _crl_tbs(revoked=[b"\x00\xab", b"\x01", b"\x00"])
    der = _crl(tbs)
    got = A._parse_crl(der)
    assert {k: got[k] for k in ("tbs", "thisUpdate", "nextUpdate", "revoked")} == {
        "tbs": tbs, "thisUpdate": _ms(2026, 1, 1), "nextUpdate": _ms(2027, 1, 1), "revoked": {"ab", "1", ""}}
    gen = A._parse_crl(_crl(_crl_tbs(this=tlv(0x18, b"20260101000000Z"), nxt=tlv(0x18, b"20270101000000Z"), version=False)))
    assert (gen["thisUpdate"], gen["nextUpdate"], gen["revoked"]) == (_ms(2026, 1, 1), _ms(2027, 1, 1), set())


def test_parse_crl_sig_der_is_the_bit_string_after_the_unused_bits_byte():
    tbs = _crl_tbs()
    der = seq(tbs, ECDSA_SHA256, tlv(0x03, b"\x00SIG"))
    assert A._parse_crl(der)["sigDer"] == b"SIG"


def test_parse_crl_refusals():
    tbs = _crl_tbs()
    bit = tlv(0x03, b"\x00\x01")
    assert _crl_err(tlv(0x31, tbs + ECDSA_SHA256 + bit)) == "CRL: bad outer SEQUENCE"
    assert _crl_err(seq(tbs, ECDSA_SHA256, bit) + b"\x00") == "CRL: bad outer SEQUENCE"
    assert _crl_err(seq(tlv(0x31, b""), ECDSA_SHA256, bit)) == "CRL: bad TBSCertList"
    assert _crl_err(seq(tbs, ECDSA_SHA256, octets(b"\x00\x01"))) == "CRL: bad signature"
    assert _crl_err(seq(tbs, ECDSA_SHA256, bit, tlv(0x05, b""))) == "CRL: bad signature"
    assert _crl_err(seq(_crl_tbs(issuer=tlv(0x31, b"")), ECDSA_SHA256, bit)) == "CRL: bad issuer"
    assert _crl_err(seq(_crl_tbs(nxt=None), ECDSA_SHA256, bit)) == "CRL: missing nextUpdate"
    assert _crl_err(seq(_crl_tbs(nxt=None, revoked=[b"\x01"]), ECDSA_SHA256, bit)) == "CRL: missing nextUpdate"
    bad_entry = seq(integer(1), ECDSA_SHA256, CRL_NAME, THIS, NEXT, seq(seq(octets(b"\x01"))))
    assert _crl_err(seq(bad_entry, ECDSA_SHA256, bit)) == "CRL: bad revoked entry"
    assert _crl_err(seq(_crl_tbs(this=tlv(0x17, b"2601010000Z")), ECDSA_SHA256, bit)) == "bad UTCTime"


def test_verify_crl_ec_boundaries():
    der = _crl(_crl_tbs(revoked=[b"\x0a\x0b"]))
    k = _keys()[0].public_key()
    t0, t1 = _ms(2026, 1, 1), _ms(2027, 1, 1)
    assert A.verify_crl(der, k, t0) == {"ok": True, "revoked": {"a0b"}}
    assert A.verify_crl(der, k, t1) == {"ok": True, "revoked": {"a0b"}}
    assert A.verify_crl(der, k, t0 - 1) == {"ok": False, "reason": "CRL thisUpdate is in the future"}
    assert A.verify_crl(der, k, t1 + 1) == {"ok": False, "reason": "CRL is stale (nextUpdate passed)"}
    assert A.verify_crl(der, _keys()[1].public_key(), t0) == {"ok": False, "reason": "CRL signature does not verify under the issuer"}
    assert A.verify_crl(b"\x31\x00", k, t0) == {"ok": False, "reason": "CRL parse failed: CRL: bad outer SEQUENCE"}
    assert A.verify_crl(bytearray(der), k, t0)["ok"] is True


@functools.lru_cache(maxsize=None)
def _rsa_keys():
    c = _c()
    return c.rsa.generate_private_key(public_exponent=65537, key_size=1024), c.rsa.generate_private_key(public_exponent=65537, key_size=1024)


def test_verify_crl_rsa():
    c = _c()
    k, other = _rsa_keys()
    name = c.x509.Name([c.x509.NameAttribute(c.NameOID.COMMON_NAME, "RSA CRL")])
    rev = c.x509.RevokedCertificateBuilder().serial_number(0x0123).revocation_date(datetime.datetime(2025, 6, 1)).build()
    der = (c.x509.CertificateRevocationListBuilder().issuer_name(name).last_update(datetime.datetime(2026, 1, 1))
           .next_update(datetime.datetime(2027, 1, 1)).add_revoked_certificate(rev).sign(k, c.hashes.SHA256())).public_bytes(c.serialization.Encoding.DER)
    assert A.verify_crl(der, k.public_key(), _ms(2026, 6, 1)) == {"ok": True, "revoked": {"123"}}
    assert A.verify_crl(der, other.public_key(), _ms(2026, 6, 1)) == {"ok": False, "reason": "CRL signature does not verify under the issuer"}
    assert A.verify_crl(_crl(_crl_tbs()), k.public_key(), _ms(2026, 6, 1)) == {"ok": False, "reason": "CRL signature does not verify under the issuer"}


def test_serial_helpers():
    assert A.norm_serial("00AbC0") == "abc0"
    assert A.norm_serial("000") == ""
    assert A.serial_is_revoked({"abc0"}, "0ABC0") is True
    assert A.serial_is_revoked({"abc0"}, "abc") is False


# ---------------------------------------------------------------------------------------------- Date.parse / freshness
@pytest.mark.parametrize("text,want", [
    # every value is V8's Date.parse of the same string
    ("2025-01-00", None),
    ("2025-01-32", None),
    ("2025-13-01", None),
    ("2025-00-10", None),
    ("2024-02-29", 1709164800000),
    ("2025-01-31", 1738281600000),
    ("2025-12-01", 1764547200000),
    ("2025-12-31", 1767139200000),
    ("0000-01-01", -62167219200000),
    ("2025-01-01T24:00:00Z", 1735776000000),
    ("2025-01-01T24:00Z", 1735776000000),
    ("2025-01-01T24:00:00.000Z", 1735776000000),
    ("2025-01-01T24:00:00.0Z", 1735776000000),
    ("2025-12-31T24:00:00Z", 1767225600000),
    ("2025-01-01T24:00:01Z", None),
    ("2025-01-01T24:01:00Z", None),
    ("2025-01-01T24:00:00.001Z", None),
    ("2025-01-01T25:00Z", None),
    ("2025-01-01T10:60Z", None),
    ("2025-01-01T23:59:60Z", None),
    ("2025-01-01T00:00:59Z", 1735689659000),
    ("2025-01-01T00:59Z", 1735693140000),
    ("2025-01-01T10:00:00.1239Z", 1735725600123),
    ("2025-01-01T10:00:00.5Z", 1735725600500),
    ("2025-01-01T10:00:00.Z", None),
    ("2025-01-01T10", None),
    ("2025-01-01T10:00:00+01:30", 1735720200000),
    ("2025-01-01T10:00:00-00:00", 1735725600000),
    ("2025-01-01T10:00:00+23:59", 1735639260000),
    ("2025-01-01T10:00:00-23:59", 1735811940000),
    ("2025-01-01T10:00:00+24:00", None),
    ("2025-01-01T10:00:00+00:60", None),
    ("not a date", None),
])
def test_js_date_parse_matches_v8(text, want):
    assert A.js_date_parse(text) == want


@pytest.mark.parametrize("text,want", [
    # deliberate departures from V8: no day rollover (V8 reads 02-30 as March 2), and zone-less means UTC (V8: host-local)
    ("2025-02-29", None),
    ("2025-02-30", None),
    ("2025-04-31", None),
    ("2025-01-01T10:00", 1735725600000),
    ("2025-01-01T10:00:00", 1735725600000),
])
def test_js_date_parse_stays_strict_and_utc(text, want):
    assert A.js_date_parse(text) == want


def test_check_fresh_boundaries():
    body = {"issueDate": "2026-01-01T00:00:00Z", "nextUpdate": "2026-02-01T00:00:00Z"}
    i, n = _ms(2026, 1, 1), _ms(2026, 2, 1)
    assert A._check_fresh(body, "TCB info", i) is None
    assert A._check_fresh(body, "TCB info", n) is None
    assert A._check_fresh(body, "TCB info", i - 1) == "TCB info: issueDate is in the future"
    assert A._check_fresh(body, "QE identity", n + 1) == "QE identity: stale (nextUpdate passed)"
    for b in ({}, {"issueDate": body["issueDate"]}, {"nextUpdate": body["nextUpdate"]}, dict(body, issueDate=5), dict(body, nextUpdate="x"),
              dict(body, issueDate="2026-01-00")):
        assert A._check_fresh(b, "X", i) == "X: issueDate/nextUpdate missing"


# ---------------------------------------------------------------------------------------------- _evaluate_qe
def _ident(**kw):
    d = {"id": "TD_QE", "version": 2, "miscselect": "00000000", "miscselectMask": "FFFFFFFF", "attributes": "11" + "00" * 15,
         "attributesMask": "FB" + "FF" * 7 + "00" * 8, "mrsigner": "AB" * 32, "isvprodid": 2,
         "tcbLevels": [{"tcb": {"isvsvn": 4}, "tcbStatus": "UpToDate", "advisoryIDs": ["A2", 7, "A1"]}, {"tcb": {"isvsvn": 0}, "tcbStatus": "OutOfDate"}]}
    d.update(kw)
    return d


def _qe(misc=0, attr0=0x11, last_attr=0, mrsigner=b"\xab" * 32, prod=2, svn=4, n=384):
    b = bytearray(n)
    b[16:20] = misc.to_bytes(4, "little")
    b[48], b[63] = attr0, last_attr
    b[128:160] = mrsigner
    b[256:258], b[258:260] = prod.to_bytes(2, "little"), svn.to_bytes(2, "little")
    return bytes(b)


def test_evaluate_qe_accepts():
    assert A._evaluate_qe(_ident(), _qe()) == {"status": "UpToDate", "advisories": ["A2", "A1"]}
    assert A._evaluate_qe(_ident(), _qe(svn=3)) == {"status": "OutOfDate", "advisories": []}
    assert A._evaluate_qe(_ident(version=2.0), _qe()) == {"status": "UpToDate", "advisories": ["A2", "A1"]}
    assert A._evaluate_qe(_ident(), _qe(attr0=0x15, last_attr=0xFF))["status"] == "UpToDate"  # masked-out bits
    assert A._evaluate_qe(_ident(miscselectMask="FEFFFFFF"), _qe(misc=1))["status"] == "UpToDate"
    # 16-bit little-endian ISVPRODID / ISVSVN
    assert A._evaluate_qe(_ident(isvprodid=0x0102, tcbLevels=[{"tcb": {"isvsvn": 5}, "tcbStatus": "Revoked"}]), _qe(prod=0x0102, svn=0x0100)) == {
        "status": "Revoked", "advisories": []}
    lv = [5, {"tcb": "x"}, {"tcb": {"isvsvn": "4"}}, {"tcb": {"isvsvn": 4}, "tcbStatus": "SWHardeningNeeded", "advisoryIDs": "A"}]
    assert A._evaluate_qe(_ident(tcbLevels=lv), _qe()) == {"status": "SWHardeningNeeded", "advisories": []}


@pytest.mark.parametrize("ident,qe,want", [
    (_ident(id="TD_QE2"), _qe(), "QE identity id is not TD_QE"),
    (_ident(version=3), _qe(), "unsupported QE identity version"),
    (_ident(version="2"), _qe(), "unsupported QE identity version"),
    (_ident(miscselect="000000"), _qe(), "QE identity fields malformed"),
    (_ident(miscselectMask="ZZZZZZZZ"), _qe(), "QE identity fields malformed"),
    (_ident(attributes="11"), _qe(), "QE identity fields malformed"),
    (_ident(attributesMask=None), _qe(), "QE identity fields malformed"),
    (_ident(mrsigner="AB" * 31), _qe(), "QE identity fields malformed"),
    (_ident(isvprodid="2"), _qe(), "QE identity fields malformed"),
    (_ident(), _qe(n=383), "QE report has wrong length"),
    (_ident(), _qe(n=385), "QE report has wrong length"),
    (_ident(), _qe(misc=1), "QE MISCSELECT does not match the QE identity"),
    (_ident(), _qe(attr0=0x13), "QE ATTRIBUTES do not match the QE identity"),
    (_ident(), _qe(mrsigner=b"\xab" * 31 + b"\xac"), "QE MRSIGNER does not match the QE identity"),
    (_ident(), _qe(prod=3), "QE ISVPRODID does not match the QE identity"),
    (_ident(isvprodid=0x0102), _qe(prod=0x0002), "QE ISVPRODID does not match the QE identity"),
    (_ident(tcbLevels=[{"tcb": {"isvsvn": 5}, "tcbStatus": "UpToDate"}]), _qe(svn=4), "QE ISVSVN is below every known level"),
    (_ident(tcbLevels="x"), _qe(), "QE ISVSVN is below every known level"),
    (_ident(tcbLevels=[{"tcb": {"isvsvn": 4}, "tcbStatus": "Fine"}]), _qe(), "QE level has an unknown tcbStatus"),
])
def test_evaluate_qe_refusals(ident, qe, want):
    assert A._evaluate_qe(ident, qe) == {"error": want}


# ---------------------------------------------------------------------------------------------- verify_intel_tdx_collateral (real)
def _vcol(col=None, policy=None, pin=None, now=None, quote=None):
    q, c, n, _ = _real()
    return A.verify_intel_tdx_collateral(q if quote is None else quote, dict(c) if col is None else col, n if now is None else now, policy, pin)


def _patch_docs(monkeypatch, tcb=None, qe=None):
    real = getattr(A._verify_signed_json, "original", A._verify_signed_json)  # patches replace each other, never accumulate

    def fake(text, name, key):
        r = real(text, name, key)
        f = tcb if name == "tcbInfo" else qe
        if "body" in r and f is not None:
            b = copy.deepcopy(r["body"])
            f(b)
            r = {"body": b}
        return r

    fake.original = real
    monkeypatch.setattr(A, "_verify_signed_json", fake)


OK_COL = {"ok": True, "status": "UpToDate", "platformStatus": "UpToDate", "tdxModuleStatus": "UpToDate", "qeStatus": "UpToDate", "advisoryIds": [],
          "tcbEvaluationDataNumber": 20, "fmspc": FMSPC}


def test_collateral_real_accepts():
    assert _vcol() == OK_COL
    c = _col()
    c["tcbInfoJson"] = c["tcbInfoJson"].encode()
    c["qeIdentityJson"] = c["qeIdentityJson"].encode()
    assert _vcol(c) == OK_COL
    assert _vcol(policy={"acceptStatuses": None}) == OK_COL
    assert _vcol(policy={"acceptStatuses": ["UpToDate"]}) == OK_COL


@pytest.mark.parametrize("key", ["tcbInfoJson", "qeIdentityJson", "pckCrlDer", "rootCrlDer", "tcbInfoIssuerChainPem", "qeIdentityIssuerChainPem"])
def test_collateral_each_missing_piece_is_incomplete(key):
    c = _col()
    del c[key]
    assert _vcol(c) == {"ok": False, "reason": "collateral incomplete (fail closed)"}
    c[key] = b"" if key.endswith("Der") else ""
    assert _vcol(c) == {"ok": False, "reason": "collateral incomplete (fail closed)"}


def test_collateral_none_and_policy_rejections():
    q, _, n, _ = _real()
    assert A.verify_intel_tdx_collateral(q, None, n) == {"ok": False, "reason": "collateral incomplete (fail closed)"}
    assert _vcol(policy={"acceptStatuses": []}) == dict(OK_COL, ok=False, reason="TCB status UpToDate is not accepted by policy")
    assert _vcol(policy={"acceptStatuses": ["OutOfDate"]})["reason"] == "TCB status UpToDate is not accepted by policy"
    assert _vcol(pin="00" * 32) == {"ok": False, "reason": "quote invalid: PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor"}
    assert _vcol(quote=q[:10]) == {"ok": False, "reason": "quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length"}


def test_collateral_evaluation_data_numbers(monkeypatch):
    def nums(info, qe):
        def setter(v):
            def f(b):
                if v is None:
                    b.pop("tcbEvaluationDataNumber", None)
                else:
                    b["tcbEvaluationDataNumber"] = v
            return f
        _patch_docs(monkeypatch, setter(info), setter(qe))

    zero = dict(OK_COL, tcbEvaluationDataNumber=0)
    nums(0, 0)
    assert _vcol() == zero
    nums(20, 0)
    assert _vcol() == zero
    nums(0, 20)
    assert _vcol() == zero
    nums(30, 25)
    assert _vcol() == dict(OK_COL, tcbEvaluationDataNumber=25)
    nums(25, 30)
    assert _vcol() == dict(OK_COL, tcbEvaluationDataNumber=25)
    missing = {"ok": False, "reason": "tcbEvaluationDataNumber missing"}
    for info, qe in ((None, 20), (20, None), (-1, 20), (20, -1), ("20", 20), (20, True)):
        nums(info, qe)
        assert _vcol() == missing
    below = {"ok": False, "reason": "tcbEvaluationDataNumber below policy minimum"}
    nums(20, 20)
    assert _vcol(policy={"minTcbEvaluationDataNumber": 20}) == OK_COL
    assert _vcol(policy={"minTcbEvaluationDataNumber": 0}) == OK_COL
    assert _vcol(policy={"minTcbEvaluationDataNumber": 21}) == below
    nums(20, 19)
    assert _vcol(policy={"minTcbEvaluationDataNumber": 20}) == below
    nums(19, 20)
    assert _vcol(policy={"minTcbEvaluationDataNumber": 20}) == below


def test_collateral_tcb_info_document_checks(monkeypatch):
    def with_info(**kw):
        _patch_docs(monkeypatch, lambda b: b.update(kw))
        return _vcol()

    assert with_info(fmspc=FMSPC.upper()) == OK_COL
    assert with_info(version=3.0) == OK_COL
    assert with_info(fmspc="000000000000") == {"ok": False, "reason": "TCB info FMSPC does not match the quote PCK"}
    assert with_info(fmspc=5) == {"ok": False, "reason": "TCB info FMSPC does not match the quote PCK"}
    not_tdx = {"ok": False, "reason": "TCB info is not a TDX v3 document"}
    assert with_info(id="SGX") == not_tdx
    assert with_info(version=2) == not_tdx
    assert with_info(version="3") == not_tdx
    assert with_info(issueDate="2099-01-01T00:00:00Z") == {"ok": False, "reason": "TCB info: issueDate is in the future"}
    assert with_info(nextUpdate=None) == {"ok": False, "reason": "TCB info: issueDate/nextUpdate missing"}
    assert with_info(tcbLevels=[]) == {"ok": False, "reason": "TCB evaluation: TCB info has no tcbLevels"}


def test_collateral_qe_document_and_status_combination(monkeypatch):
    def with_qe(**kw):
        _patch_docs(monkeypatch, None, lambda b: b.update(kw))
        return _vcol()

    assert with_qe(nextUpdate="2000-01-01T00:00:00Z") == {"ok": False, "reason": "QE identity: stale (nextUpdate passed)"}
    assert with_qe(isvprodid=3) == {"ok": False, "reason": "QE identity: QE ISVPRODID does not match the QE identity"}
    sw = [{"tcb": {"isvsvn": 0}, "tcbStatus": "SWHardeningNeeded", "advisoryIDs": ["INTEL-SA-2", "INTEL-SA-1", "INTEL-SA-2"]}]
    assert with_qe(tcbLevels=sw) == dict(OK_COL, status="SWHardeningNeeded", qeStatus="SWHardeningNeeded", advisoryIds=["INTEL-SA-1", "INTEL-SA-2"])
    rv = [{"tcb": {"isvsvn": 0}, "tcbStatus": "Revoked"}]
    assert with_qe(tcbLevels=rv) == dict(OK_COL, ok=False, status="Revoked", qeStatus="Revoked", reason="TCB status Revoked is not accepted by policy")


def test_collateral_reports_each_component_status(monkeypatch):
    monkeypatch.setattr(A, "_evaluate_tcb", lambda *a: {"platform": "OutOfDate", "module": "SWHardeningNeeded", "advisories": ["Z", "B"]})
    assert _vcol() == dict(OK_COL, ok=False, status="OutOfDate", platformStatus="OutOfDate", tdxModuleStatus="SWHardeningNeeded", advisoryIds=["B", "Z"],
                           reason="TCB status OutOfDate is not accepted by policy")
    monkeypatch.setattr(A, "_evaluate_tcb", lambda *a: {"platform": "SWHardeningNeeded", "module": "UpToDate", "advisories": []})
    assert _vcol() == dict(OK_COL, status="SWHardeningNeeded", platformStatus="SWHardeningNeeded")


def test_collateral_signed_documents_and_issuer_chains():
    c = _col()
    c["tcbInfoJson"] = c["tcbInfoJson"].replace('"tcbEvaluationDataNumber":20', '"tcbEvaluationDataNumber":21')
    assert _vcol(c) == {"ok": False, "reason": "TCB info: tcbInfo signature does not verify under the TCB Signing certificate"}
    c = _col()
    c["qeIdentityJson"] = c["qeIdentityJson"].replace('"isvprodid":2', '"isvprodid":3')
    assert _vcol(c) == {"ok": False, "reason": "QE identity: enclaveIdentity signature does not verify under the TCB Signing certificate"}
    c = _col()
    c["tcbInfoIssuerChainPem"] = "x"
    assert _vcol(c) == {"ok": False, "reason": "TCB info: issuer chain invalid: no PEM certificates in the PCK chain"}
    c = _col()
    c["qeIdentityIssuerChainPem"] = "x"
    assert _vcol(c) == {"ok": False, "reason": "QE identity: issuer chain invalid: no PEM certificates in the PCK chain"}


def test_collateral_crls():
    c = _col()
    c["rootCrlDer"] = b"\x31\x00"
    assert _vcol(c) == {"ok": False, "reason": "Intel Root CA CRL: CRL parse failed: CRL: bad outer SEQUENCE"}
    c = _col()
    c["pckCrlDer"] = b"\x31\x00"
    assert _vcol(c) == {"ok": False, "reason": "PCK CRL: CRL parse failed: CRL: bad outer SEQUENCE"}
    c = _col()
    c["rootCrlDer"] = c["pckCrlDer"]
    assert _vcol(c) == {"ok": False, "reason": "Intel Root CA CRL: CRL signature does not verify under the issuer"}


def _quote_chain():
    q = _real()[0]
    certs = [Cert.from_pem(b) for b in A.pem_blocks(A.parse_dcap_quote(q)["pckChainPem"])]
    leaf = next(x for x in certs if not any(y.issuer == x.subject for y in certs))
    ca = next(x for x in certs if x.subject == leaf.issuer)
    return leaf, ca


@pytest.mark.parametrize("which,want", [(0, "PCK CA certificate is revoked by the Intel Root CA CRL"), (1, "PCK leaf certificate is revoked by the PCK CRL")])
def test_collateral_revocations(monkeypatch, which, want):
    leaf, ca = _quote_chain()
    real = A.verify_crl
    calls = []

    def fake(der, key, now):
        r = real(der, key, now)
        calls.append(1)
        if len(calls) == which + 1:
            serial = (ca if which == 0 else leaf).serial_hex
            r = {"ok": True, "revoked": set(r["revoked"]) | {A.norm_serial(serial)}}
        return r

    monkeypatch.setattr(A, "verify_crl", fake)
    assert _vcol() == {"ok": False, "reason": want}


def test_collateral_unexpected_error_fails_closed(monkeypatch):
    def rt(*a):
        raise RuntimeError("rt")

    monkeypatch.setattr(A, "_evaluate_qe", rt)
    assert _vcol() == {"ok": False, "reason": "collateral verification error (fail closed): rt"}


@pytest.mark.parametrize("base", [{"ok": True}, {"ok": True, "pckTcb": {}}, {"ok": True, "fmspc": "x"}, {"ok": True, "pckTcb": {}, "fmspc": ""},
                                  {"ok": False, "pckTcb": {}, "fmspc": "x"}])
def test_collateral_base_result_seam(monkeypatch, base):
    monkeypatch.setattr(A, "verify_genuine_tdx_quote", lambda *a: base)
    assert _vcol() == {"ok": False, "reason": "quote invalid: unknown"}


def test_collateral_forwards_only_a_literal_true_allow_debug(monkeypatch):
    q, c, n, _ = _real()
    seen = []

    def spy(quote, pin, expected, policy, now):
        seen.append((quote, pin, expected, policy, now))
        return {"ok": False, "reason": "r"}

    monkeypatch.setattr(A, "verify_genuine_tdx_quote", spy)
    for allow in (True, 1, False):
        assert A.verify_intel_tdx_collateral(q, dict(c), n, None, "PIN", allow) == {"ok": False, "reason": "quote invalid: r"}
    assert A.verify_intel_tdx_collateral(q, dict(c), n)["reason"] == "quote invalid: r"
    assert seen == [(q, "PIN", None, {"allowDebug": True}, n), (q, "PIN", None, None, n), (q, "PIN", None, None, n), (q, None, None, None, n)]


@pytest.mark.parametrize("certs,want", [
    ([("A", "A")], "PCK leaf not found"),
    ([("A", "B")], "PCK CA not found in the quote chain"),
    ([("A", "B"), ("B", "C")], "Intel root not found in the quote chain"),
])
def test_collateral_quote_chain_shape_through_seams(monkeypatch, certs, want):
    monkeypatch.setattr(A, "verify_genuine_tdx_quote", lambda *a: {"ok": True, "pckTcb": {}, "fmspc": "x"})
    monkeypatch.setattr(A, "pem_blocks", lambda _pem: list(range(len(certs))))
    monkeypatch.setattr(A, "Cert", types.SimpleNamespace(from_pem=lambda i: types.SimpleNamespace(subject=certs[i][0], issuer=certs[i][1], raw=b"")))
    monkeypatch.setattr(A, "x509_valid_at", lambda *a: True)
    assert _vcol() == {"ok": False, "reason": want}


def test_collateral_rechecks_quote_chain_validity(monkeypatch):
    monkeypatch.setattr(A, "verify_genuine_tdx_quote", lambda *a: {"ok": True, "pckTcb": {}, "fmspc": "x"})
    monkeypatch.setattr(A, "x509_valid_at", lambda *a: False)
    assert _vcol() == {"ok": False, "reason": "PCK chain certificate outside its validity period"}
