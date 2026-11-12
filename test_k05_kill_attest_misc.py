"""0.5 mutation-kill tests of the attest "misc" group: attest_common (JS-faithful helpers, crypto glue), attest_cert (DN
text, the certificate model), attest_amd (chain, report signature, policy, verifier), attest_allowlist_anchor, attest
(factory, vector runners) and sigstore_bundle (SCT, RFC 3161, checkpoint, entry body, failure stages). Expected strings and
limits are those of the TypeScript reference (packages/pca/src, packages/pca-attest-eat/src/sigstore.ts); seams are used only
where a state is unreachable through real input. Needs `cryptography`."""
import base64
import binascii
import hashlib
import json
import os
import sys
import time

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from atlas_pca import attest as AT
from atlas_pca import attest_allowlist_anchor as AA
from atlas_pca import attest_amd as A
from atlas_pca import attest_common as C
from atlas_pca import sigstore_bundle as S
from atlas_pca.attest_cert import Cert, CertError, _escape, _verify_signature, render_name
from atlas_pca.attest_der import CertExtension, _tlv_at
from atlas_pca.ledger import EMPTY_TREE_ROOT
from atlas_pca.pca import merkle_root
from test_attest_units import EXP, NOW, evidence_resolver, ms, oid, sev_report, seq, tlv
from test_k05_kill_attest_crypto import CRIT, mk

INF = float("inf")
SHA256, SHA384 = hashes.SHA256(), hashes.SHA384()


def b64u(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# ================================================================================================ attest_common


def test_node_b64decode_pads_and_skips_non_alphabet():
    assert C.node_b64decode("YWJj") == b"abc" and C.node_b64decode("YWI") == b"ab" and C.node_b64decode("YQ") == b"a"
    assert C.node_b64decode("Y") == b"" and C.node_b64decode("YQ==YQ") == b"a"
    # characters just outside the alphabet ranges (between 'Z' and 'a', after '9', before 'A') are skipped, not read as data
    for junk in ("[", "\\", "]", "^", "`", ":", ";", "<", "?", "@"):
        assert C.node_b64decode("YW%sJj" % junk) == b"abc", junk
    assert C.node_b64decode("-_-_") == C.node_b64decode("+/+/") == b"\xfb\xff\xbf"


def test_node_b64decode_decoder_error_is_empty(monkeypatch):
    def boom(*a, **k):
        raise binascii.Error("x")
    monkeypatch.setattr(C.base64, "b64decode", boom)
    assert C.node_b64decode("YWJj") == b""


def test_js_number_radix_prefixes_are_case_insensitive():
    assert C.js_number("0X1F") == 31.0 and C.js_number("0O17") == 15.0 and C.js_number("0B11") == 3.0
    assert C.big_int("0X1F") == 31 and C.big_int("0O17") == 15 and C.big_int("0B11") == 3


def test_safe_nonneg_int_includes_the_max_safe_float():
    assert C._safe_nonneg_int(9007199254740991.0) == 9007199254740991
    assert C._safe_nonneg_int(9007199254740992.0) is None


def test_utf8_lone_surrogate_and_length_prefix():
    assert C._utf8("a\ud800") == b"a\xef\xbf\xbd" and C._utf8("\udfff") == b"\xef\xbf\xbd"
    assert C._lp("é") == b"\x00\x00\x00\x02\xc3\xa9"


def test_first_string_skips_only_empty_and_takes_one_char():
    assert C.first_string({"a": "", "b": "x"}, ["a", "b"]) == "x"
    assert C.first_string({"a": "x"}, ["a"]) == "x"
    assert C.first_string({"a": ""}, ["a"]) is None


def test_js_num_str_switches_at_1e21():
    assert C.js_num_str(1e21) == "1e+21" and C.js_num_str(1e20) == "100000000000000000000"


def test_json_position_text_and_number_start():
    assert C._json_at("a\nb\ncd", 6) == "at position 6 (line 3 column 3)"
    assert C._v8_json_message('{"a":-}', 5) == "Unexpected number in JSON at position 5 (line 1 column 6)"


@pytest.mark.parametrize("text,msg", [
    ("X", "Unexpected token 'X', \"X\" is not valid JSON"),
    ("", "Unexpected end of JSON input"), ("  \n\t\r ", "Unexpected end of JSON input"),
    ("[1,]", "Unexpected token ']', \"[1,]\" is not valid JSON"),
])
def test_js_json_loads_messages(text, msg):
    with pytest.raises(C.JsError) as e:
        C.js_json_loads(text)
    assert str(e.value) == msg


def test_js_json_loads_trailing_comma_position_seams(monkeypatch):
    def fake(text, pos):
        def loads(*a, **k):
            raise json.JSONDecodeError("Illegal trailing comma before end of array", text, pos)
        return loads
    monkeypatch.setattr(C.json, "loads", fake("[1,]", 2))
    with pytest.raises(C.JsError) as e:  # the position moves exactly one past the comma
        C.js_json_loads("[1,]")
    assert str(e.value) == "Unexpected token ']', \"[1,]\" is not valid JSON"
    monkeypatch.setattr(C.json, "loads", fake("[1,", 2))
    with pytest.raises(C.JsError) as e:  # the whitespace scan stops at the end of the text
        C.js_json_loads("[1,")
    assert str(e.value) == "Unexpected end of JSON input"


def test_decode_canonical_b64url_x_ending():
    assert C.decode_canonical_b64url("AAAX") == b"\x00\x00\x17"


def test_parse_jws_decodes_invalid_utf8_with_replacement():
    h = b64u(b'{"alg":"ES256","kid":"\xff"}')
    p = b64u(b'{"a":"\xff"}')
    r = C.parse_jws("%s.%s.%s" % (h, p, b64u(b"sig")), "f")
    assert r["header"]["kid"] == "�" and r["payload"]["a"] == "�"
    assert r["signingInput"] == ("%s.%s" % (h, p)).encode() and r["signature"] == b"sig"


def test_crypto_namespace_is_built_once_and_complete(monkeypatch):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import utils
    monkeypatch.setattr(C, "_crypto_ns", None)
    ns = C.crypto()
    assert ns is not None and C.crypto() is ns and C._crypto_ns is ns
    assert ns.InvalidSignature is InvalidSignature and ns.hashes is hashes and ns.serialization is serialization
    assert ns.ec is ec and ns.padding is padding and ns.rsa is rsa and ns.utils is utils


def test_crypto_missing_package_message(monkeypatch):
    monkeypatch.setattr(C, "_crypto_ns", None)
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    with pytest.raises(ImportError) as e:
        C.crypto()
    assert str(e.value) == "the native attestation verifiers need the 'cryptography' package: pip install 'atlas-pca[attest]'"
    assert isinstance(e.value.__cause__, ImportError)


@pytest.mark.parametrize("name", ["sha1", "sha224", "sha256", "sha384", "sha512"])
def test_hash_alg_names(name):
    assert C.hash_alg(name).name == name


def test_key_type_fallback_names():
    assert C.key_type(type("Foo_BarPublicKey", (), {})()) == "foobar"
    assert C.key_type(type("PublicKey", (), {})()) == "unknown"


def test_curve_names():
    k256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    k384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    k521 = ec.generate_private_key(ec.SECP521R1()).public_key()
    k1 = ec.generate_private_key(ec.SECP256K1()).public_key()
    assert (C.node_curve(k256), C.jwk_curve(k256)) == ("prime256v1", "P-256")
    assert (C.node_curve(k384), C.jwk_curve(k384)) == ("secp384r1", "P-384")
    assert (C.node_curve(k521), C.jwk_curve(k521)) == ("secp521r1", "P-521")
    assert (C.node_curve(k1), C.jwk_curve(k1)) == ("secp256k1", "secp256k1")


def test_ec_key_from_point_only_the_two_curves():
    k = ec.generate_private_key(ec.SECP384R1()).public_key()
    pt = C.ec_point(k, "P-384")
    assert C.ec_key_from_point("P-384", pt).public_numbers() == k.public_numbers()
    with pytest.raises(KeyError):
        C.ec_key_from_point("P-521", pt)


def test_pem_to_der_with_wrapped_lines_and_is_hex():
    assert C.pem_to_der("-----BEGIN CERTIFICATE-----\nAQ\nI=\n-----END CERTIFICATE-----") == b"\x01\x02"
    assert C.is_hex("00") and C.is_hex("aF") and not C.is_hex("") and not C.is_hex("0") and not C.is_hex("0g")


# ================================================================================================ attest_cert


def name_der(*rdns):
    return seq(*[tlv(0x31, b"".join(seq(oid(o), tlv(t, v)) for o, t, v in rdn)) for rdn in rdns])


def test_escape_rules():
    assert _escape("\x7f") == "\\7F" and _escape("\x01") == "\\01" and _escape("a\x80b") == "a\x80b"
    assert _escape('a,b+c"d\\e<f>g;h') == 'a\\,b\\+c\\"d\\\\e\\<f\\>g\\;h'
    assert _escape("aXb") == "aXb" and _escape("Xa") == "Xa"
    assert _escape("#a") == "\\#a" and _escape(" a") == "\\ a" and _escape("a#") == "a#"
    assert _escape("a ") == "a\\ " and _escape(" ") == "\\ " and _escape("a b") == "a b"


def _cn(tag, value):
    return render_name(name_der([("2.5.4.3", tag, value)]))


def test_name_value_string_types():
    assert _cn(0x0C, b"a\xffb") == "CN=a�b"
    for tag in (0x13, 0x16, 0x1A, 0x12, 0x14):
        assert _cn(tag, b"a\xe9") == "CN=a\xe9", tag
    assert _cn(0x1E, b"\x00a\x00b") == "CN=ab" and _cn(0x1E, b"\x00a\x00") == "CN=a�"
    assert _cn(0x1C, b"\x00\x00\x00a") == "CN=a" and _cn(0x1C, b"\x00\x00\x00a\x00") == "CN=a�"
    assert _cn(0x02, b"\xab") == "CN=#0201AB"  # hex of the whole value TLV, upper case
    assert _cn(0x17, b"x") == "CN=#170178"


def test_render_name_rdn_must_be_a_set():
    with pytest.raises(CertError) as e:
        render_name(seq(seq()))
    assert str(e.value) == "RDN is not a SET"


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _pair():
    rk, lk = _ec_key(), _ec_key()
    root = Cert(mk("Root", "Root", rk.public_key(), rk, 1, True, h=SHA256))
    leaf = Cert(mk("Leaf", "Root", lk.public_key(), rk, 2, False, h=SHA256))
    return root, leaf, rk, lk


WRAP = "error:0688010A:asn1 encoding routines::nested asn1 error (bad signature wrapper)"


def test_cert_signature_wrapper_rules():
    root, _leaf, rk, _lk = _pair()
    der = root.raw
    outer = _tlv_at(der, 0)
    tbs = _tlv_at(der, outer.start)
    alg = _tlv_at(der, tbs.end)
    sigv = _tlv_at(der, alg.end)
    assert Cert(der).raw == der
    bad = bytearray(der)
    bad[tbs.end] = 0x31  # the algorithm is not a SEQUENCE
    with pytest.raises(CertError) as e:
        Cert(bytes(bad))
    assert str(e.value) == WRAP
    bad = bytearray(der)
    bad[alg.end] = 0x04  # the signature is not a BIT STRING
    with pytest.raises(CertError) as e:
        Cert(bytes(bad))
    assert str(e.value) == WRAP
    with pytest.raises(CertError) as e:  # bytes after the signature inside the certificate
        Cert(tlv(0x30, der[outer.start:] + b"\x00"))
    assert str(e.value) == WRAP
    with pytest.raises(CertError) as e:  # an empty BIT STRING
        Cert(tlv(0x30, der[outer.start:alg.end] + b"\x03\x00"))
    assert str(e.value) == WRAP
    assert sigv.end == outer.end


def _with_ext(cert, oid_, ext):
    cert._exts = dict(cert.extensions(), **{oid_: ext})
    return cert


def test_key_cert_sign_shapes():
    _r, leaf, _rk, _lk = _pair()
    ku = lambda v: _with_ext(leaf, "2.5.29.15", CertExtension(True, v))._key_cert_sign()  # noqa: E731
    assert ku(tlv(0x03, b"\x00\x04")) is True
    assert ku(tlv(0x03, b"\x00\x01")) is False  # encipherOnly is not keyCertSign
    assert ku(tlv(0x03, b"\x00")) is False  # no data byte
    assert ku(tlv(0x04, b"\x00\x04")) is False  # not a BIT STRING
    assert ku(b"") is None


def test_verify_requires_matching_algorithms_and_zero_unused_bits():
    root, leaf, _rk, _lk = _pair()
    assert leaf.verify(root.public_key) is True
    leaf.inner_sig_alg_der = b"\x30\x00"
    assert leaf.verify(root.public_key) is False
    root2, leaf2, _a, _b = _pair()
    leaf2.sig_unused = 1
    assert leaf2.verify(root2.public_key) is False


def test_verify_signature_refusals():
    k = _ec_key().public_key()
    assert _verify_signature(seq(oid("1.2.3.4")), b"m", b"s", k) is False
    assert _verify_signature(seq(oid("1.2.840.113549.1.1.10")), b"m", b"s", k) is False  # RSASSA-PSS under an EC key


def test_check_issued_authority_key_identifier():
    root, leaf, _rk, _lk = _pair()
    assert leaf.check_issued(root) is True
    akid = lambda v: _with_ext(leaf, "2.5.29.35", CertExtension(False, v))  # noqa: E731
    akid(b"")  # undecodable
    assert leaf.check_issued(root) is False
    akid(tlv(0x04, tlv(0x82, b"\x05")))  # not a SEQUENCE: nothing inside is read
    assert leaf.check_issued(root) is True
    akid(b"\x30\x02\x80\x04\xaa\xbb\xcc\xdd")  # an element running past its parent
    assert leaf.check_issued(root) is False
    akid(seq(tlv(0x80, b"x")))  # a key id with no subject key id on the issuer: ignored
    assert leaf.check_issued(root) is True
    akid(seq(tlv(0x82, root.serial)))
    assert leaf.check_issued(root) is True
    akid(seq(tlv(0x82, b"\x09")))
    assert leaf.check_issued(root) is False
    _with_ext(root, "2.5.29.14", CertExtension(False, tlv(0x04, b"KEYID")))
    akid(seq(tlv(0x82, root.serial)))  # a serial element is not compared with the key id
    assert leaf.check_issued(root) is True
    akid(seq(tlv(0x80, b"KEYID")))
    assert leaf.check_issued(root) is True
    akid(seq(tlv(0x80, b"OTHER")))
    assert leaf.check_issued(root) is False


# ================================================================================================ attest_amd


def _pem(der):
    import base64
    b = base64.b64encode(der).decode()  # no x509 round-trip: some tests need certificates cryptography refuses to load
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def _k384():
    return ec.generate_private_key(ec.SECP384R1())


class Chain:
    def __init__(self):
        self.ark_k, self.ask_k, self.vcek_k, self.other_k = _k384(), _k384(), _k384(), _k384()
        self.ark = mk("ARK", "ARK", self.ark_k.public_key(), self.ark_k, 1, True, h=SHA384)
        self.ask = mk("ASK", "ARK", self.ask_k.public_key(), self.ark_k, 2, True, h=SHA384)
        self.vcek = mk("VCEK", "ASK", self.vcek_k.public_key(), self.ask_k, 3, False, h=SHA384)
        self.pem = _pem(self.ask) + _pem(self.ark)
        self.pin = Cert(self.ark).spki_hash("sha384")

    def run(self, vcek=None, pem=None, pin="default", now=NOW, skew=None):
        return A.verify_amd_cert_chain(vcek or self.vcek, pem or self.pem, self.pin if pin == "default" else pin, now, skew)


@pytest.fixture(scope="module")
def chain():
    return Chain()


def bad(reason):
    return {"ok": False, "reason": reason}


def test_amd_chain_valid(chain):
    r = chain.run()
    assert r["ok"] is True and C.key_type(r["vcek"]) == "ec" and C.node_curve(r["vcek"]) == "secp384r1"
    assert r["vcekTbs"] == Cert(chain.vcek).tbs_der


def test_amd_chain_clock_skew(chain):
    for skew in (-1, "x"):
        assert chain.run(skew=skew) == bad("clockSkewMs must be a non-negative number")
    assert chain.run(now=ms(2035, 1, 1), skew=1000)["ok"] is True  # exactly at notAfter with a skew
    assert chain.run(now=ms(2035, 1, 1) + 1001, skew=1000) == bad("VCEK certificate has expired")
    assert chain.run(now=ms(2024, 1, 1)) == bad("VCEK certificate is not yet valid")
    assert chain.run(now=ms(2036, 1, 1)) == bad("VCEK certificate has expired")


def test_amd_chain_structure_refusals(chain):
    assert chain.run(pem=_pem(chain.ark)) == bad("ASK+ARK chain must contain exactly two certificates (ASK then ARK)")
    swapped = _pem(chain.ark) + _pem(chain.ask)
    assert chain.run(pem=swapped) == bad("second certificate of the chain is not a self-signed ARK (chain out of order?)")
    twice = _pem(chain.ark) * 2
    assert chain.run(pem=twice) == bad("first certificate of the chain is self-signed, not an ASK (chain out of order?)")
    other = mk("VCEK", "Other", chain.vcek_k.public_key(), chain.ask_k, 3, False, h=SHA384)
    assert chain.run(vcek=other) == bad("ASK subject does not match the VCEK issuer")


def test_amd_chain_pin(chain):
    expected = bad("ARK does not match the pinned AMD trust anchor")
    assert chain.run(pin=None) == expected  # the default pin is the Milan ARK
    assert chain.run(pin="00" * 48) == expected
    assert chain.run(pin=chain.pin.upper())["ok"] is True


def test_amd_chain_signature_refusals(chain):
    ask = mk("ASK", "ARK", chain.ask_k.public_key(), chain.other_k, 2, True, h=SHA384)
    assert chain.run(pem=_pem(ask) + _pem(chain.ark)) == bad("ASK is not signed by ARK")
    vcek = mk("VCEK", "ASK", chain.vcek_k.public_key(), chain.other_k, 3, False, h=SHA384)
    assert chain.run(vcek=vcek) == bad("VCEK is not signed by ASK")


def test_amd_chain_role_and_extension_refusals(chain):
    ask = mk("ASK", "ARK", chain.ask_k.public_key(), chain.ark_k, 2, False, h=SHA384)
    assert chain.run(pem=_pem(ask) + _pem(chain.ark)) == bad("AMD chain role check failed: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)")
    vcek = mk("VCEK", "ASK", chain.vcek_k.public_key(), chain.ask_k, 3, False, extra=((CRIT, True),), h=SHA384)
    assert chain.run(vcek=vcek) == bad("VCEK certificate has an unrecognised critical extension 1.2.3.4")
    soft = x509.BasicConstraints(ca=True, path_length=None)
    ark = mk("ARK", "ARK", chain.ark_k.public_key(), chain.ark_k, 1, True, bc=False, extra=((soft, False),), h=SHA384)
    assert chain.run(pem=_pem(chain.ask) + _pem(ark)) == bad("ARK certificate BasicConstraints is not marked critical")


def _resign(der, key, old, new):
    c = Cert(der)
    assert old in c.tbs_der
    tbs = c.tbs_der.replace(old, new, 1)
    return seq(tbs, c.sig_alg_der, tlv(0x03, b"\x00" + key.sign(tbs, ec.ECDSA(SHA384))))


def test_amd_chain_unparseable_validity(chain):
    ark = _resign(chain.ark, chain.ark_k, b"250101000000Z", b"251301000000Z")  # month 13: notBefore alone is unparseable
    assert chain.run(pem=_pem(chain.ask) + _pem(ark)) == bad("ARK certificate validity is unparseable")


def test_amd_chain_vcek_key_type(chain):
    p256 = mk("VCEK", "ASK", _ec_key().public_key(), chain.ask_k, 3, False, h=SHA384)
    assert chain.run(vcek=p256) == bad("AMD chain verification error: VCEK is not EC secp384r1 (got ec/prime256v1)")
    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    rsa_vcek = mk("VCEK", "ASK", rsa_pub, chain.ask_k, 3, False, h=SHA384)
    assert chain.run(vcek=rsa_vcek) == bad("AMD chain verification error: VCEK is not EC secp384r1 (got rsa/undefined)")


def test_amd_report_parse_fields_and_slices():
    rep = bytearray(sev_report(version=7))
    rep[0x38:0x40] = (0x1122334455667788).to_bytes(8, "little")
    rep[0x2E8 + 72] = 9  # the byte after s must stay out of sig_s
    r = A.parse_sev_snp_report(bytes(rep))
    assert r["version"] == 7 and r["current_tcb"] == 0x1122334455667788
    assert r["sig_s"] == bytes(rep[0x2E8:0x2E8 + 72]) and len(r["sig_r"]) == 72 and len(r["sig_s"]) == 72


def test_amd_report_signature_range(monkeypatch):
    monkeypatch.setattr(A, "ecdsa_verify_der", lambda *a: True)
    n = A._P384_N

    def ok(r, s):
        return A.verify_sev_snp_report_signature({"sig_r": r.to_bytes(72, "little"), "sig_s": s.to_bytes(72, "little"), "signed": b""}, object())
    for r, s in ((1, 1), (n - 1, n - 1), (1, n - 1)):
        assert ok(r, s) is True, (r, s)
    for r, s in ((0, 5), (5, 0), (n, 5), (5, n), (n + 1, 5), (5, n + 1)):
        assert ok(r, s) is False, (r, s)


def test_amd_policy_committed_tcb_boundary():
    rep = A.parse_sev_snp_report(sev_report(committed_tcb=5))
    assert A.check_sev_snp_policy(rep, {"minCommittedTcb": A.BigU64(5)}) is None
    assert A.check_sev_snp_policy(rep, {"minCommittedTcb": A.BigU64(6)}) == "committed_tcb below minimum (rollback?)"


def test_genuine_parse_failure_is_exact():
    assert A.verify_genuine_sev_snp_report(bytes(10), b"", "", None, 1) == bad("report parse failed: parseSevSnpReport: report too short (10 < 816)")


def test_genuine_chain_shape_checks(monkeypatch):
    rep = sev_report()
    run = lambda: A.verify_genuine_sev_snp_report(rep, b"", "", None, 1)  # noqa: E731
    monkeypatch.setattr(A, "verify_amd_cert_chain", lambda *a: {"ok": False, "reason": "boom"})
    assert run() == bad("cert chain invalid: boom")
    monkeypatch.setattr(A, "verify_amd_cert_chain", lambda *a: {"ok": True, "vcekTbs": b"x"})
    assert run() == bad("cert chain invalid: None")
    monkeypatch.setattr(A, "verify_amd_cert_chain", lambda *a: {"ok": True, "vcek": object()})
    assert run() == bad("cert chain invalid: None")
    monkeypatch.setattr(A, "verify_amd_cert_chain", lambda *a: {"ok": True, "vcek": object(), "vcekTbs": b"x"})
    assert run() == bad("report signature does not verify under VCEK")


def test_genuine_later_stages(monkeypatch):
    monkeypatch.setattr(A, "verify_amd_cert_chain", lambda *a: {"ok": True, "vcek": object(), "vcekTbs": b"x"})
    monkeypatch.setattr(A, "verify_sev_snp_report_signature", lambda *a: True)
    monkeypatch.setattr(A, "check_vcek_report_binding", lambda *a: "bind-err")
    assert A.verify_genuine_sev_snp_report(sev_report(), b"", "", None, 1) == bad("bind-err")
    monkeypatch.setattr(A, "check_vcek_report_binding", lambda *a: None)
    assert A.verify_genuine_sev_snp_report(sev_report(), b"", "", None, 1, expected=EXP) == bad("report_data does not bind holder/grant/epoch/nonce")
    r = A.verify_genuine_sev_snp_report(sev_report(signature_algo=2), b"", "", None, 1, policy={"requireEcdsaP384": True})
    assert r == bad("unexpected signature_algo 2")


def test_genuine_unexpected_exception_fails_closed(monkeypatch):
    def boom(*a):
        raise RuntimeError("x")
    monkeypatch.setattr(A, "verify_amd_cert_chain", boom)
    assert A.verify_genuine_sev_snp_report(sev_report(), b"", "", None, 1) == bad("genuine verification error (fail closed): x")


def test_azure_runtime_data_with_invalid_utf8_inside_a_string():
    want = C.attestation_binding(EXP)
    rd = b'{"x":"\xff","user-data":"' + want.hex().encode() + b'"}'
    assert A.check_azure_runtime_data_binding(hashlib.sha256(rd).digest() + bytes(32), rd, EXP) is None


CFG = {"family": "genoa", "binding": "report-data", "policy": {"measurements": ["00" * 48]}}


def test_amd_verifier_construction():
    with pytest.raises(A.AttestConstructError) as e:  # an unhashable family is refused, not a TypeError from the table lookup
        A.AmdSnpVerifier(dict(CFG, family=["genoa"]))
    assert str(e.value) == "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'"
    meas = ["aa" * 48]
    v = A.AmdSnpVerifier(dict(CFG, policy={"measurements": meas}))
    assert v._policy["measurements"] == meas and v._policy["measurements"] is not meas and "MEASUREMENTS" not in v._policy
    meas.append("bb")
    assert v._policy["measurements"] == ["aa" * 48]


def test_amd_verifier_resolver_gets_the_document_and_failures_are_exact():
    seen = []

    def resolve(doc):
        seen.append(doc)
        return None
    v = A.AmdSnpVerifier(dict(CFG, resolve_evidence=resolve))
    assert v.verify("DOC", EXP, 1) == bad("no AMD SEV-SNP evidence for this action") and seen == ["DOC"]

    def boom(doc):
        raise ValueError("kaput")
    v = A.AmdSnpVerifier(dict(CFG, resolve_evidence=boom))
    assert v.verify({}, EXP, 1) == bad("amd-snp verification error (fail closed): kaput")


# ================================================================================================ attest_allowlist_anchor

D43 = "A" * 43
TRUST = {"logKey": "K", "instanceId": "inst", "principal": "pr"}
T0 = 1_000_000


def entry(i="ops", v=1, d=D43):
    return {"issuer": i, "version": v, "digest": d}


def head_of(entries, **kw):
    root = merkle_root([AA.allowlist_anchor_commit(e) for e in entries]) if entries else EMPTY_TREE_ROOT
    return dict({"instance_id": "inst", "principal": "pr", "timestamp": T0, "size": len(entries), "root": root}, **kw)


@pytest.fixture
def seams(monkeypatch):
    out = {"th": [], "hc": [], "inc": True}

    def th(head, key, witnesses, pins):
        out["th"].append((head, key, witnesses, pins))
        return True

    def hc(older, newer, proof, key, witnesses, pins):
        out["hc"].append((older, newer, proof, key, witnesses, pins))
        return True
    monkeypatch.setattr(AA, "verify_tree_head", th)
    monkeypatch.setattr(AA, "verify_head_consistency", hc)
    monkeypatch.setattr(AA, "verify_ledger_inclusion", lambda root, proof, commit: out["inc"])
    return out


def run(mine, es, head=None, proof=None, trust=TRUST, now=T0, **kw):
    ev = {"head": head or head_of(es), "entries": es, "proof": proof if proof is not None else {"size": len(es)}}
    return AA.verify_allowlist_anchored(mine, ev, trust, now, **kw)


ES = [entry("ops", 1), entry("ops", 2, "B" * 43)]


def test_anchor_entry_issuer_length():
    assert AA._entry(entry("a")) and AA._entry(entry("a" * 200))
    assert not AA._entry(entry("")) and not AA._entry(entry("a" * 201))


def test_anchor_passes_witnesses_and_pins_through(seams):
    w, p, cons = object(), object(), object()
    cached = {"instance_id": "inst", "principal": "pr", "size": 1, "root": "x"}
    head = head_of(ES)
    ev = {"head": head, "entries": ES, "proof": {"size": 2}, "consistency": cons}
    r = AA.verify_allowlist_anchored(ES[1], ev, TRUST, T0, cached_head=cached, witnesses=w, pins=p)
    assert r == {"ok": True, "highestAnchoredVersion": 2}
    assert seams["th"] == [(head, "K", w, p), (cached, "K", w, p)]
    assert seams["hc"] == [(cached, head, cons, "K", w, p)]


def test_anchor_trust_and_clock_gates(seams):
    assert run(ES[1], ES, trust=None) == {"ok": False, "code": "bad-head"}
    assert run(ES[1], ES, now=1.5) == {"ok": False, "code": "bad-head"}
    assert run(None, ES) == {"ok": False, "code": "bad-head"}  # an exception is a refusal, never a raise


def test_anchor_feed_limits(seams, monkeypatch):
    assert run(ES[1], ES, head=head_of(ES, size=3), proof={"size": 3}) == {"ok": False, "code": "feed-mismatch"}  # right root, wrong size
    monkeypatch.setattr(AA, "MAX_FEED", 2)
    assert run(ES[1], ES)["ok"] is True  # exactly at the cap
    monkeypatch.setattr(AA, "MAX_FEED", 1)
    assert run(ES[1], ES) == {"ok": False, "code": "feed-mismatch"}  # one over, with a matching size and root


def test_anchor_proof_gates(seams):
    assert run(ES[1], ES, proof={"size": 3}) == {"ok": False, "code": "bad-proof"}
    assert run(ES[1], ES, proof={}) == {"ok": False, "code": "bad-proof"}
    assert run(entry("ops", 2, "short"), ES) == {"ok": False, "code": "bad-proof"}
    seams["inc"] = False
    assert run(ES[1], ES) == {"ok": False, "code": "bad-proof"}


def test_anchor_not_anchored(seams):
    assert run(entry("ops", 2, "C" * 43), ES) == {"ok": False, "code": "not-anchored"}


# ================================================================================================ attest (factory, vectors)


def test_unb64_messages():
    head = "The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received "
    for v, tail in ((None, "null"), (AT._MISSING, "undefined"), (5, "type int")):
        with pytest.raises(TypeError) as e:
            AT._unb64(v)
        assert str(e.value) == head + tail


def test_intel_collateral_missing_crls_are_undefined():
    head = "The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received "
    with pytest.raises(TypeError) as e:
        AT.evidence_for("intel-tdx-dcap", {"collateral": {}})
    assert str(e.value) == head + "undefined"
    with pytest.raises(TypeError) as e:
        AT.evidence_for("intel-tdx-dcap", {"collateral": {"pckCrlDer": "AQI="}})
    assert str(e.value) == head + "undefined"
    with pytest.raises(TypeError) as e:
        AT.evidence_for("intel-tdx-dcap", {"collateral": {"pckCrlDer": "AQI=", "rootCrlDer": None}})
    assert str(e.value) == head + "null"


def test_identity_wrapper():
    class Inner:
        def __init__(self, r):
            self.r, self.seen = r, []

        def verify(self, d, e, n):
            self.seen.append((d, e, n))
            return self.r
    inner = Inner({"ok": True, "measured": {"a": 1, "b": 2}})
    w = AT._WithIdentity(inner, {"b": 3})
    assert w.verify("doc", "exp", 5) == {"ok": True, "measured": {"a": 1, "b": 3}} and inner.seen == [("doc", "exp", 5)]
    for r in ({"ok": False, "measured": {"a": 1}}, {"ok": True, "measured": None}, {"ok": True}):
        assert AT._WithIdentity(Inner(r), {"b": 3}).verify(None, None, 0) is r


def test_factory_default_and_custom_resolvers():
    v = AT.verifier_from_config("amd-sev-snp", CFG)
    assert v._resolve({"evidence": {"report": "AQI="}}) == {"report": b"\x01\x02"}
    assert v._resolve(5) is None and v._resolve({}) is None
    seen = []
    v = AT.verifier_from_config("amd-sev-snp", CFG, resolve_evidence=lambda d: seen.append(d))
    assert v._resolve("DOC") is None and seen == ["DOC"]


def test_run_attestation_vector_passes_an_empty_document(monkeypatch):
    class V:
        def verify(self, d, e, n):
            self.args = (d, e, n)
            return {"ok": True}
    v = V()
    monkeypatch.setattr(AT, "verifier_from_config", lambda *a: v)
    assert AT.run_attestation_vector({"vendor": "x", "config": {}, "evidence": 1, "now": 5, "expected_binding": "e"}) == {"ok": True}
    assert v.args == ({}, "e", 5)


# ================================================================================================ sigstore_bundle

from test_k05_kill_stores_sigstore import (  # noqa: E402
    _CASES, _ROOT_DOC, HEAD, ISSUER, LOG, LOG_ID, OPEN, ROOT, ROOTS, V2, VF, _b, _cert, _cp, _ed_pub, _ext, _fails, _leaf, _line,
    _lst, _sct, _spki, der,
)


@pytest.fixture
def vcalls(monkeypatch):
    out = {"log": [], "result": False}

    def fake(hash_name, data, key, sig):
        out["log"].append((hash_name, data, key, sig))
        return out["result"]
    monkeypatch.setattr(S, "_verify", fake)
    return out


def test_der_three_byte_length_bytes():
    assert der(0x04, b"a" * 0x10203)[:5] == b"\x04\x83\x01\x02\x03"


def test_date_ms_offsets():
    assert S._date_ms("1970-01-01T00:00:00Z") == 0 and S._date_ms("1970-01-01T05:30:00+05:30") == 0
    assert S._date_ms("1970-01-01T00:00:00-00:30") == 1_800_000


def _pl(kd, raw, key_id, **kw):
    return dict({"publicKey": {"rawBytes": _b(raw), "keyDetails": kd, "validFor": VF}, "logId": {"keyId": _b(key_id)}}, **kw)


def test_pinned_log_loads_each_key_type():
    ecpub = _spki(ec.derive_private_key(5, ec.SECP256R1()).public_key())
    assert C.key_type(S._pinned_log(_pl("PKIX_ECDSA_P256_SHA_256", ecpub, hashlib.sha256(ecpub).digest()), True).key) == "ec"
    pk1 = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    spki = S._der(0x30, S._RSA_ALG_ID + S._der(0x03, b"\x00" + pk1))
    got = S._pinned_log(_pl("PKCS1_RSA_PKCS1V5", pk1, hashlib.sha256(spki).digest()), False)
    assert C.key_type(got.key) == "rsa" and got.key_id == hashlib.sha256(spki).digest()
    assert _fails(S._pinned_log, _pl("PKCS1_RSA_PKCS1V5", pk1, b"\x00" * 32), False) == "log id is not the SHA-256 of its key"
    ed = _spki(_ed_pub())
    kid = hashlib.sha256(b"log.example\n\x01" + ed[-32:]).digest()
    got = S._pinned_log(_pl("PKIX_ED25519", ed, kid, baseUrl="https://log.example"), True)
    assert C.key_type(got.key) == "ed25519" and got.v2_name == "log.example"


def test_pinned_log_base_url_is_cleaned_before_parsing(monkeypatch):
    seen = []
    real = S.urlsplit
    monkeypatch.setattr(S, "urlsplit", lambda u: (seen.append(u), real(u))[1])
    ed = _spki(_ed_pub())
    kid = hashlib.sha256(b"log.example\n\x01" + ed[-32:]).digest()
    got = S._pinned_log(_pl("PKIX_ED25519", ed, kid, baseUrl="\x01 \thttps://log.\texam\nple/x \x02\t"), True)
    assert got.v2_name == "log.example" and seen == ["https://log.example/x"]


def test_pinned_log_no_host_never_matches_a_placeholder_name():
    ed = _spki(_ed_pub())
    kid = hashlib.sha256(b"XXXX\n\x01" + ed[-32:]).digest()
    no = "log id is not the signed-note key hash of its key"
    assert _fails(S._pinned_log, _pl("PKIX_ED25519", ed, kid), True) == no
    assert _fails(S._pinned_log, _pl("PKIX_ED25519", ed, kid, baseUrl="file:///x"), True) == no
    assert _fails(S._pinned_log, _pl("PKIX_ED25519", ed, kid, baseUrl=5), True) == no


def test_oid_empty_content():
    assert _fails(lambda b: S._oid(b, S._tlv(b, 0)), b"\x06\x00") == "not an OID"


def test_fulcio_ext_seven_is_a_der_string():
    p = lambda *e: S._parse_cert(_cert(*e))  # noqa: E731
    assert S._fulcio_ext(p(_ext("1.3.6.1.4.1.57264.1.7", der(0x0C, b"s"))), 7) == "s"


def test_chain_ok_requires_ca_from_depth_one():
    rk, lk = _ec_key(), _ec_key()
    leaf = Cert(mk("L", "R", lk.public_key(), rk, 2, False, h=SHA256))
    bad_root = Cert(mk("R", "R", rk.public_key(), rk, 1, False, h=SHA256))
    good_root = Cert(mk("R", "R", rk.public_key(), rk, 1, True, h=SHA256))
    assert S._chain_ok([leaf, good_root], NOW) is True
    assert S._chain_ok([leaf, bad_root], NOW) is False


def test_verify_rsa_pkcs1():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = k.sign(b"m", padding.PKCS1v15(), SHA256)
    sig384 = k.sign(b"m", padding.PKCS1v15(), SHA384)
    assert S._verify("sha256", b"m", k.public_key(), sig) is True
    assert S._verify("sha384", b"m", k.public_key(), sig384) is True
    assert S._verify("sha256", b"x", k.public_key(), sig) is False
    assert S._verify("sha256", b"m", k.public_key(), sig384) is False


# ---- SCT

def test_sct_big_fields_are_unsigned(vcalls):
    vcalls["result"] = True
    assert S._verify_sct(_leaf(_lst(_sct(sig=b"S" * 40000))), ISSUER, OPEN) is None  # list, entry and signature lengths above 0x7fff
    assert vcalls["log"][-1][3] == b"S" * 40000
    assert S._verify_sct(_leaf(_lst(_sct(ext=b"E" * 40000))), ISSUER, OPEN) is None
    assert vcalls["log"][-1][1].endswith(b"\x9c\x40" + b"E" * 40000)


def test_sct_later_entry_can_succeed_after_a_skipped_one(vcalls):
    vcalls["result"] = True
    assert S._verify_sct(_leaf(_lst(_sct(version=1), _sct())), ISSUER, ROOTS) is None
    assert S._verify_sct(_leaf(_lst(_sct(ts=1), _sct())), ISSUER, ROOTS) is None


def test_sct_extension_runs_into_the_signature_header(vcalls):
    s = b"\x00" + LOG_ID + (150).to_bytes(8, "big") + b"\x00\x02" + b"ab" + b"\x04\x03"  # 47 bytes: no room for the signature length
    assert len(s) == 47
    assert S._verify_sct(_leaf(_lst(s)), ISSUER, ROOTS) == "SCT truncated"


# ---- RFC 3161

_RFC = next(c for c in _CASES["verifyRfc3161"] if c["name"] == "verifyRfc3161/valid resp")
TOK, DATA = base64.b64decode(_RFC["args"][0]), base64.b64decode(_RFC["args"][1])


def test_rfc3161_falls_through_to_the_next_authority(monkeypatch):
    good = S.parse_trusted_root(_ROOT_DOC).tsas[0]
    assert S.verify_rfc3161(TOK, DATA, [good]) == 1780315230000
    assert S.verify_rfc3161(TOK, DATA, [S.PinnedCa(good.chain, S._Validity(0, 1)), good]) == 1780315230000  # outside its validity
    real_eku, real_verify, real_chain = S._eku, S._verify, S._chain_ok

    def once(real, bad):
        n = [0]

        def f(*a):
            n[0] += 1
            return bad if n[0] == 1 else real(*a)
        return f
    monkeypatch.setattr(S, "_eku", once(real_eku, []))  # no time-stamping EKU
    assert S.verify_rfc3161(TOK, DATA, [good, good]) == 1780315230000
    monkeypatch.setattr(S, "_eku", real_eku)
    monkeypatch.setattr(S, "_verify", once(real_verify, False))  # signature does not verify
    assert S.verify_rfc3161(TOK, DATA, [good, good]) == 1780315230000
    monkeypatch.setattr(S, "_verify", real_verify)
    monkeypatch.setattr(S, "_chain_ok", once(real_chain, False))  # chain does not verify
    assert S.verify_rfc3161(TOK, DATA, [good, good]) == 1780315230000


@pytest.fixture
def tokyo():
    if not hasattr(time, "tzset"):
        pytest.skip("no tzset")
    old = os.environ.get("TZ")
    os.environ["TZ"] = "JST-9"
    time.tzset()
    yield
    if old is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = old
    time.tzset()


def test_generalized_time_is_utc_whatever_the_local_zone(tokyo):
    d = der(0x18, b"19700101000000Z")
    assert S._generalized_time(d, S._tlv(d, 0)) == 0


# ---- checkpoint

def test_checkpoint_edges(vcalls):
    assert S._verify_checkpoint("\n\nx", LOG, 7, ROOT) == "checkpoint body too short or without an origin"
    vcalls["result"] = True
    # a signature line by another name does not end the search for the log's own name
    assert S._verify_checkpoint(_cp(_line(b"ABCDsig", "other"), _line(b"ABCDsig", "log.example")), V2, 7, ROOT) is None


# ---- the verifier end to end (seams: the signatures and the inclusion proof; the corpus bundle is otherwise real)

@pytest.fixture
def open_log(monkeypatch):
    monkeypatch.setattr(S, "_verify", lambda *a: True)
    monkeypatch.setattr(S, "verify_rfc9162_inclusion", lambda *a: True)
    return S.parse_trusted_root(_ROOT_DOC)


def _bundle(name, edit=None, raw=None):
    c = next(c for c in _CASES["verifySigstoreBundleCore"] if c["name"] == name)
    b = json.loads(json.dumps(c["args"][0]))
    e = b["verificationMaterial"]["tlogEntries"][0]
    if raw is not None:
        e["canonicalizedBody"] = base64.b64encode(raw(base64.b64decode(e["canonicalizedBody"]))).decode()
    elif edit is not None:
        body = json.loads(base64.b64decode(e["canonicalizedBody"]))
        edit(body)
        e["canonicalizedBody"] = base64.b64encode(json.dumps(body).encode()).decode()
    return b


DSSE, INTOTO = "verifySigstoreBundleCore/dsse/valid", "verifySigstoreBundleCore/intoto/valid"


def test_bundle_failures_name_their_stage(open_log, monkeypatch):
    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(S, "_san_decodes", boom)
    assert S.verify_sigstore_bundle_core(_bundle(DSSE), open_log) == {"ok": False, "code": "cert_chain", "detail": "fail closed: boom"}
    monkeypatch.undo()
    monkeypatch.setattr(S, "_verify", lambda *a: True)
    monkeypatch.setattr(S, "verify_rfc9162_inclusion", lambda *a: True)
    monkeypatch.setattr(S, "_verify_sct", boom)
    assert S.verify_sigstore_bundle_core(_bundle(DSSE), open_log) == {"ok": False, "code": "sct", "detail": "fail closed: boom"}
    monkeypatch.undo()
    monkeypatch.setattr(S, "verify_rfc9162_inclusion", lambda *a: True)

    def v(hash_name, data, key, sig):
        if data.startswith(b"DSSEv1 "):
            raise RuntimeError("boom")
        return True
    monkeypatch.setattr(S, "_verify", v)
    assert S.verify_sigstore_bundle_core(_bundle(DSSE), open_log) == {"ok": False, "code": "signature", "detail": "fail closed: boom"}


def test_bundle_ca_valid_from_the_first_signing_time_is_accepted(open_log):
    base = S.verify_sigstore_bundle_core(_bundle(DSSE), open_log)
    assert base["ok"] is True
    start = base["core"]["signed_time"] * 1000  # the earliest verified time
    roots = open_log._replace(cas=[open_log.cas[0]._replace(valid=S._Validity(start, INF))])
    assert S.verify_sigstore_bundle_core(_bundle(DSSE), roots)["ok"] is True


def test_bundle_entry_body_is_decoded_leniently(open_log):
    r = S.verify_sigstore_bundle_core(_bundle(DSSE, raw=lambda b: b[:-1] + b',"zz":"\xff"}'), open_log)
    assert r["ok"] is True


def test_bundle_unreadable_certificate_pem_is_a_mismatch_not_a_crash(open_log):
    other = {"ok": False, "code": "tlog_body", "detail": "the entry names another certificate"}
    r = S.verify_sigstore_bundle_core(_bundle(DSSE, lambda b: b["spec"]["signatures"][0].__setitem__("verifier", _b(b"\xff"))), open_log)
    assert r == other
    r = S.verify_sigstore_bundle_core(_bundle(INTOTO, lambda b: b["spec"]["content"]["envelope"]["signatures"][0].__setitem__("publicKey", _b(b"\xff"))), open_log)
    assert r == other
