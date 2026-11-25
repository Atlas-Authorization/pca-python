"""k05 mutation-kill tests, group "stores": sigstore_bundle helpers on hand-built DER and scripted seams (the signature
primitive `_verify` is patched so the exact signed bytes can be asserted), plus the tlog-body rule the shared corpus cannot
reach without re-signing. Expectations follow packages/pca-attest-eat/src/sigstore.ts. Needs `cryptography`."""
import base64
import hashlib
import json
import types

import pytest

from k05_oracle import load

pytest.importorskip("cryptography")  # optional `sigstore` extra (the dependency-free CI job skips this file)
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402

from atlas_pca import sigstore_bundle as S  # noqa: E402

INF = float("inf")
der = S._der


def _b128(v):
    out = [v & 0x7F]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7F))
        v >>= 7
    return bytes(reversed(out))


def _oid_der(s):
    p = [int(x) for x in s.split(".")]
    return der(0x06, b"".join(_b128(x) for x in [p[0] * 40 + p[1]] + p[2:]))


def _ext(oid, value):
    return der(0x30, _oid_der(oid) + der(0x04, value))


BC = _ext("2.5.29.19", b"\x30\x00")
INT = der(0x02, b"\x01")


def _cert(*exts):
    return der(0x30, der(0x30, INT + der(0xA3, der(0x30, b"".join(exts)))) + der(0x30, b""))


def _fails(fn, *args):
    with pytest.raises(S._Fail) as e:
        fn(*args)
    return str(e.value)


# ---- DER


def test_der_lengths():
    assert der(0x04, b"") == b"\x04\x00"
    assert der(0x04, b"a" * 0x7F)[:2] == b"\x04\x7f"
    assert der(0x04, b"a" * 0x80)[:3] == b"\x04\x81\x80"
    assert der(0x04, b"a" * 0xFF)[:3] == b"\x04\x81\xff"
    assert der(0x04, b"a" * 0x100)[:4] == b"\x04\x82\x01\x00"
    assert der(0x04, b"a" * 0xFFFF)[:4] == b"\x04\x82\xff\xff"
    assert der(0x04, b"a" * 0x10000)[:5] == b"\x04\x83\x01\x00\x00"
    assert der(0x04, b"ab")[2:] == b"ab"


def test_tlv():
    t = S._tlv
    assert t(b"\x30\x00", 0) == S._Tlv(0x30, 0, 2, 2)
    assert t(b"\x00\x04\x01a", 1) == S._Tlv(0x04, 1, 3, 4)
    assert t(b"\x30\x81\x01a", 0) == S._Tlv(0x30, 0, 3, 4)
    assert t(b"\x30\x84\x00\x00\x00\x00", 0) == S._Tlv(0x30, 0, 6, 6)
    assert _fails(t, b"\x30", 0) == "DER truncated"
    assert _fails(t, b"\x30\x00", 1) == "DER truncated"
    assert _fails(t, b"\x1f\x00", 0) == "DER multi-byte tag"
    assert _fails(t, b"\x3f\x00", 0) == "DER multi-byte tag"
    assert _fails(t, b"\x30\x80", 0) == "DER length"
    assert _fails(t, b"\x30\x85\x00\x00\x00\x00\x00", 0) == "DER length"
    assert _fails(t, b"\x30\x82\x00", 0) == "DER length"
    assert _fails(t, b"\x30\x01", 0) == "DER overrun"
    assert _fails(t, b"\x30\x81\x02a", 0) == "DER overrun"
    assert _fails(t, b"\x30\x01a", 0, 2) == "DER overrun"
    assert _fails(t, b"\x30\x00", 0, 1) == "DER truncated"
    b = der(0x30, b"\x02\x01\x05\x04\x00")
    assert S._kids(b, t(b, 0)) == [S._Tlv(0x02, 2, 4, 5), S._Tlv(0x04, 5, 7, 7)]
    assert S._body(b, S._Tlv(0x02, 2, 4, 5)) == b"\x05"
    assert _fails(S._kids, b"\x30\x02\x04\x05", S._Tlv(0x30, 0, 2, 4)) == "DER overrun"  # a child is bounded by its parent
    assert S._at([1, 2], 0) == 1 and S._at([1, 2], 1) == 2 and S._at([1, 2], 2) is None and S._at([1, 2], -1) is None


def _oid(b):
    return S._oid(b, S._tlv(b, 0))


def test_oid_text():
    assert _oid(bytes.fromhex("06012a")) == "1.2"
    assert _oid(bytes.fromhex("06032a0304")) == "1.2.3.4"
    assert _oid(bytes.fromhex("060127")) == "0.39"
    assert _oid(bytes.fromhex("060128")) == "1.0"
    assert _oid(bytes.fromhex("06014f")) == "1.39"
    assert _oid(bytes.fromhex("060150")) == "2.0"
    assert _oid(bytes.fromhex("0603818001")) == "2.%d" % (16385 - 80)
    assert _oid(_oid_der("1.3.6.1.4.1.11129.2.4.2")) == "1.3.6.1.4.1.11129.2.4.2"
    assert _fails(_oid, b"\x05\x01\x00") == "not an OID"
    assert _fails(_oid, b"\x06\x00") == "not an OID"
    assert _fails(_oid, b"\x06\x01\x80") == "OID arc is not minimally encoded"
    assert _fails(_oid, b"\x06\x02\x01\x80") == "OID arc is not minimally encoded"
    # the first byte is checked even when the byte before it (here the length) has its high bit set
    assert _fails(_oid, b"\x06\x81\x80\x80" + b"\x01" * 127) == "OID arc is not minimally encoded"
    assert _fails(_oid, b"\x06\x02\x81\x80") == "OID ends inside an arc"
    assert _fails(_oid, b"\x06\x01\x81") == "OID ends inside an arc"


def test_parse_cert():
    d = _cert(BC, _ext("2.5.29.17", b"xy"))
    pc = S._parse_cert(d)
    assert pc.der == d and pc.exts_wrapper.tag == 0xA3 and [k.tag for k in pc.tbs_kids] == [0x02, 0xA3]
    assert [(e.oid, e.value) for e in pc.exts] == [("2.5.29.19", b"\x30\x00"), ("2.5.29.17", b"xy")]
    assert S._ext(pc, "2.5.29.17").value == b"xy" and S._ext(pc, "1.2") is None
    assert d[pc.exts[0].tlv.start:pc.exts[0].tlv.end] == BC
    # a critical flag sits between the OID and the value
    crit = der(0x30, _oid_der("1.2.3") + b"\x01\x01\xff" + der(0x04, b"v"))
    assert [(e.oid, e.value) for e in S._parse_cert(_cert(crit)).exts] == [("1.2.3", b"v")]
    p = S._parse_cert
    assert _fails(p, d + b"\x00") == "certificate is not one SEQUENCE"
    assert _fails(p, der(0x31, der(0x30, b""))) == "certificate is not one SEQUENCE"
    assert _fails(p, der(0x30, INT)) == "no TBSCertificate"
    assert _fails(p, der(0x30, der(0x30, INT))) == "no extensions"
    assert _fails(p, der(0x30, der(0x30, der(0xA3, der(0x04, b""))))) == "extensions malformed"
    assert _fails(p, _cert(der(0x30, _oid_der("1.2.3") + b"\x01\x01\xff"))) == "extension value is not an OCTET STRING"
    assert _fails(p, _cert(BC, BC)) == "duplicate extension 2.5.29.19"
    assert _fails(p, _cert(der(0x30, b"\x04\x00\x04\x00"))) == "not an OID"


def test_basic_constraints_ca():
    ca = lambda v: S._basic_constraints_ca(S._parse_cert(_cert(_ext("2.5.29.19", v))))  # noqa: E731
    assert S._basic_constraints_ca(S._parse_cert(_cert(_ext("1.2.3", b"")))) is False
    assert ca(der(0x30, b"\x01\x01\xff")) is True
    assert ca(der(0x30, b"\x01\x01\x01")) is True
    assert ca(der(0x30, b"\x01\x01\x00")) is False
    assert ca(der(0x30, b"")) is False
    assert ca(der(0x30, b"\x02\x01\xff")) is False
    assert ca(der(0x30, b"\x01\x02\xff\xff")) is False
    assert ca(der(0x31, b"\x01\x01\xff")) is False


def test_fulcio_ext_and_san():
    p = lambda *e: S._parse_cert(_cert(*e))  # noqa: E731
    pre = "1.3.6.1.4.1.57264.1."
    assert S._fulcio_ext(p(_ext(pre + "1", b"raw")), 1) == "raw"
    assert S._fulcio_ext(p(_ext(pre + "6", b"raw")), 6) == "raw"
    assert S._fulcio_ext(p(BC), 1) is None
    assert S._fulcio_ext(p(_ext(pre + "8", der(0x0C, b"str"))), 8) == "str"
    assert _fails(S._fulcio_ext, p(_ext(pre + "8", der(0x04, b"str"))), 8) == "extension .1.8 is not a DER UTF8String"
    assert _fails(S._fulcio_ext, p(_ext(pre + "8", der(0x0C, b"s") + b"x")), 8) == "extension .1.8 is not a DER UTF8String"
    san = lambda v: p(_ext("2.5.29.17", v))  # noqa: E731
    assert S._san_identity(san(der(0x30, der(0x86, b"https://x")))) == "https://x"
    assert S._san_identity(san(der(0x30, der(0x81, b"a@b")))) == "a@b"
    assert _fails(S._san_identity, p(BC)) == "no subjectAltName"
    assert _fails(S._san_identity, san(der(0x31, der(0x86, b"x")))) == "subjectAltName must hold exactly one name"
    assert _fails(S._san_identity, san(der(0x30, b""))) == "subjectAltName must hold exactly one name"
    assert _fails(S._san_identity, san(der(0x30, der(0x86, b"x") + der(0x86, b"y")))) == "subjectAltName must hold exactly one name"
    assert _fails(S._san_identity, san(der(0x30, der(0x82, b"x")))) == "subjectAltName must be a URI or an email"
    assert S._san_decodes(p(BC)) is True
    assert S._san_decodes(san(der(0x30, der(0x86, b"x") + der(0x82, b"y")))) is True
    assert S._san_decodes(san(der(0x30, der(0x05, b"")))) is False
    assert S._san_decodes(san(der(0x31, b""))) is False
    assert S._san_decodes(san(der(0x30, b"") + b"x")) is False
    assert S._san_decodes(san(b"\x30")) is False
    for tag in (0xA0, 0x81, 0x82, 0xA3, 0xA4, 0xA5, 0x86, 0x87, 0x88):
        assert S._san_decodes(san(der(0x30, der(tag, b"")))) is True


def test_digest_of_and_generalized_time():
    alg = lambda oid: der(0x30, _oid_der(oid))  # noqa: E731
    d = lambda b: S._digest_of(b, S._tlv(b, 0))  # noqa: E731
    assert d(alg("2.16.840.1.101.3.4.2.1")) == "sha256"
    assert d(alg("2.16.840.1.101.3.4.2.2")) == "sha384"
    assert d(alg("2.16.840.1.101.3.4.2.3")) == "sha512"
    assert _fails(d, alg("1.2.3")) == "unsupported digest algorithm"
    g = lambda s, tag=0x18: S._generalized_time(der(tag, s.encode()), S._tlv(der(tag, s.encode()), 0))  # noqa: E731
    assert g("19700101000000Z") == 0
    assert g("19700101000001Z") == 1000
    assert g("19700101000000.5Z") == 500
    assert g("19700101000000.1239Z") == 123
    assert g("20260601120000Z") == 1780315200000
    assert _fails(g, "19700101000000Z", 0x17) == "genTime is not a GeneralizedTime"
    for bad in ("197001010000Z", "19700101000000", "19700101000000.Z", "19700101000000.1234567891Z", "19700101000000z"):
        assert _fails(g, bad) == "genTime malformed", bad
    assert _fails(g, "19700230000000Z") == "genTime is not a real date"
    assert _fails(g, "19700101240000Z") == "genTime is not a real date"


# ---- values


def test_small_value_helpers():
    assert S._is_obj({}) is True and S._is_obj([]) is False and S._is_obj(None) is False
    assert S._get({"a": 1}, "a") == 1 and S._get({"a": 1}, "b") is None and S._get([], "a") is None
    assert S._b64("") == b"" and S._b64("QQ==") == b"A" and S._b64("QUJD") == b"ABC" and S._b64("+/+/") == b"\xfb\xff\xbf"
    for bad in ("QQ", "Q!==", "-_-_", "QQ===", 5, None, "QUJD\n"):
        assert _fails(S._b64, bad) == "not base64", bad
    assert S._sha256(b"a", b"b") == hashlib.sha256(b"ab").digest() and S._sha256() == hashlib.sha256().digest()
    assert S._dec_int("0") == 0 and S._dec_int("9007199254740991") == 2 ** 53 - 1
    assert _fails(S._dec_int, "9007199254740992") == "integer out of range"
    for bad in ("01", "", "-1", "1.5", "12345678901234567", 5, None, "1\n"):
        assert _fails(S._dec_int, bad) == "not a decimal integer string", bad
    assert S.dsse_pae("t/y", b"\x00ab") == b"DSSEv1 3 t/y 3 \x00ab"
    assert S.dsse_pae("é", b"") == b"DSSEv1 2 \xc3\xa9 0 "
    assert S._kind_of({"kind": "a", "version": "b"}) == "a/b"
    assert [S._kind_of(x) for x in ({"kind": "a"}, {"version": "b"}, {"kind": 1, "version": "b"}, {"kind": "a", "version": 1}, None)] == [""] * 5
    pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"
    assert S._pem_der(pem) == b"ABC" and S._pem_der(pem + "\n") == b"ABC"
    assert S._pem_der(pem + "\n\n") == b"" and S._pem_der("nope") == b"" and S._pem_der(" " + pem) == b""


def test_dates_and_validity():
    d = S._date_ms
    assert d("1970-01-01T00:00:00Z") == 0
    assert d("1970-01-01T00:00:01.5Z") == 1500
    assert d("1970-01-01T00:00:00.1239Z") == 123
    assert d("1970-01-01T01:00:00+01:00") == 0
    assert d("1970-01-01T00:00:00-01:00") == 3_600_000
    for bad in ("1970-01-01t00:00:00Z", "1970-01-01T00:00:00z", "1970-01-01T00:00:00", "1970-02-30T00:00:00Z", "1970-01-01T25:00:00Z",
                "1970-01-01T00:00:00.1234567891Z", "1970-13-01T00:00:00Z", "١970-01-01T00:00:00Z", "x"):
        assert d(bad) is None, bad
    v = S._validity
    assert v({"start": "1970-01-01T00:00:00Z"}) == (0, INF)
    assert v({"start": "1970-01-01T00:00:00Z", "end": 5}) == (0, INF)  # a non-string end means open-ended
    assert v({"start": "1970-01-01T00:00:00Z", "end": "1970-01-01T00:00:01Z"}) == (0, 1000)
    for bad in (None, {}, {"start": 5}, {"start": "x"}):
        assert _fails(v, bad) == "validFor.start missing", bad
    assert _fails(v, {"start": "1970-01-01T00:00:00Z", "end": "x"}) == "validFor.end malformed"


VF = {"start": "1970-01-01T00:00:00Z"}


def _b(x):
    return base64.b64encode(x).decode()


def _ed_pub():
    return ed25519.Ed25519PrivateKey.from_private_bytes(b"\x05" * 32).public_key()


def _spki(k):
    return k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_pinned_log():
    pl = S._pinned_log
    for bad in (None, {}, {"publicKey": {}}, {"logId": {}}, {"publicKey": 1, "logId": {}}, {"publicKey": {}, "logId": 1}):
        assert _fails(pl, bad, True) == "log entry malformed"
    log = lambda kd, raw=b"k", key_id=b"id", **kw: dict({"publicKey": {"rawBytes": _b(raw), "keyDetails": kd, "validFor": VF}, "logId": {"keyId": _b(key_id)}}, **kw)  # noqa: E731
    assert pl(log("OTHER"), True) is None and pl(log("OTHER"), False) is None
    assert pl(log("PKCS1_RSA_PKCS1V5"), True) is None
    assert pl(log("PKIX_ED25519"), False) is None
    assert _fails(pl, log("PKIX_ECDSA_P256_SHA_256"), True) == "log id is not the SHA-256 of its key"
    ecpub = _spki(ec.derive_private_key(5, ec.SECP256R1()).public_key())
    got = pl(log("PKIX_ECDSA_P256_SHA_256", ecpub, hashlib.sha256(ecpub).digest()), True)
    assert got.key_id == hashlib.sha256(ecpub).digest() and got.valid == (0, INF) and got.v2_name is None
    spki = _spki(_ed_pub())
    raw = spki[-32:]
    kid = hashlib.sha256(b"log.example\n\x01" + raw).digest()
    got = pl(log("PKIX_ED25519", spki, kid, baseUrl=" https://log.example/x "), True)
    assert (got.key_id, got.v2_name) == (kid, "log.example")
    no = "log id is not the signed-note key hash of its key"
    assert _fails(pl, log("PKIX_ED25519", spki, b"other", baseUrl="https://log.example"), True) == no
    assert _fails(pl, log("PKIX_ED25519", spki, kid), True) == no
    assert _fails(pl, log("PKIX_ED25519", spki, kid, baseUrl=5), True) == no


def test_parse_trusted_root_refusals():
    mt = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

    def msg(doc):
        with pytest.raises(ValueError) as e:
            S.parse_trusted_root(doc)
        return str(e.value)
    for bad in (None, [], {}, {"mediaType": "x"}):
        assert msg(bad) == "not a trusted root v0.1"
    needs = "a trusted root needs a transparency log and a CA"
    assert msg({"mediaType": mt}) == needs
    assert msg({"mediaType": mt, "tlogs": "x", "certificateAuthorities": 5}) == needs
    assert msg({"mediaType": mt, "tlogs": [None]}) == "log entry malformed"
    assert msg({"mediaType": mt, "ctlogs": [None]}) == "log entry malformed"
    for ca in ({}, {"certChain": {}}, {"certChain": {"certificates": []}}, {"certChain": {"certificates": "x"}}, 5):
        assert msg({"mediaType": mt, "certificateAuthorities": [ca]}) == "certificate authority entry malformed"
    assert msg({"mediaType": mt, "timestampAuthorities": [{}]}) == "certificate authority entry malformed"


# ---- _verify


def test_verify_dispatch():
    msg = b"m"
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
    sig = ed.sign(msg)
    assert S._verify(None, msg, ed.public_key(), sig) is True
    assert S._verify(None, b"x", ed.public_key(), sig) is False
    assert S._verify("sha256", msg, ed.public_key(), sig) is False
    k = ec.derive_private_key(5, ec.SECP256R1())
    dsig = k.sign(msg, ec.ECDSA(hashes.SHA256()))
    assert S._verify("sha256", msg, k.public_key(), dsig) is True
    assert S._verify("sha256", b"x", k.public_key(), dsig) is False
    assert S._verify(None, msg, k.public_key(), dsig) is False
    assert S._leaf_hash_alg(k.public_key()) == "sha256"
    assert S._leaf_hash_alg(ec.derive_private_key(5, ec.SECP384R1()).public_key()) == "sha384"
    assert S._leaf_hash_alg(ec.derive_private_key(5, ec.SECP521R1()).public_key()) is None
    assert S._leaf_hash_alg(ed.public_key()) is None


# ---- SCT

LOG_ID = b"L" * 32
SCT_OID = "1.3.6.1.4.1.11129.2.4.2"
ISSUER = types.SimpleNamespace(spki_der=b"SPKI")
ROOTS = S.PinnedRoots([], [S.PinnedLog(LOG_ID, "KEY", S._Validity(100, 200))], [], [])
OPEN = S.PinnedRoots([], [S.PinnedLog(LOG_ID, "KEY", S._Validity(0, INF))], [], [])


def _sct(log_id=LOG_ID, ts=150, ext=b"", hash_alg=4, sig_alg=3, sig=b"SIG", version=0):
    return (bytes([version]) + log_id + ts.to_bytes(8, "big") + len(ext).to_bytes(2, "big") + ext + bytes([hash_alg, sig_alg])
            + len(sig).to_bytes(2, "big") + sig)


def _lst(*scts):
    body = b"".join(len(s).to_bytes(2, "big") + s for s in scts)
    return len(body).to_bytes(2, "big") + body


def _leaf(lst):
    return S._parse_cert(_cert(BC, _ext(SCT_OID, der(0x04, lst))))


@pytest.fixture
def calls(monkeypatch):
    out = {"log": [], "result": False}

    def fake(hash_name, data, key, sig):
        out["log"].append((hash_name, data, key, sig))
        return out["result"]
    monkeypatch.setattr(S, "_verify", fake)
    return out


def test_sct_signed_bytes_are_the_rfc6962_structure(calls):
    calls["result"] = True
    assert S._verify_sct(_leaf(_lst(_sct(ext=b"\xab\xcd"))), ISSUER, ROOTS) is None
    tbs = der(0x30, INT + der(0xA3, der(0x30, BC)))  # the leaf TBS without the SCT list
    ext = b"\xab\xcd"
    signed = (b"\x00\x00" + (150).to_bytes(8, "big") + b"\x00\x01" + hashlib.sha256(b"SPKI").digest() + len(tbs).to_bytes(3, "big") + tbs
              + b"\x00\x02" + ext)
    assert calls["log"] == [("sha256", signed, "KEY", b"SIG")]


def test_sct_list_shape(calls):
    v = lambda lst: S._verify_sct(_leaf(lst), ISSUER, ROOTS)  # noqa: E731
    assert S._verify_sct(S._parse_cert(_cert(BC)), ISSUER, ROOTS) == "no embedded SCT"
    outer = S._parse_cert(_cert(_ext(SCT_OID, der(0x30, _lst(_sct())))))
    assert S._verify_sct(outer, ISSUER, ROOTS) == "SCT list is not an OCTET STRING"
    assert v(b"") == "SCT list length" and v(b"\x00") == "SCT list length"
    assert v(b"\x00\x05") == "SCT list length" and v(b"\x00\x00\x00") == "SCT list length"
    assert v(b"\x00\x00") == "no SCT from a pinned CT log"  # an empty list
    assert v(b"\x00\x01\x00") == "SCT truncated"
    s46 = _sct(sig=b"")[:-1]
    assert v(_lst(s46)) == "SCT truncated"
    s = _sct()
    claim = (len(s) + 1).to_bytes(2, "big") + s
    assert v(len(claim).to_bytes(2, "big") + claim) == "SCT truncated"
    calls["result"] = True
    assert v(_lst(_sct(sig=b""))) is None  # 47 bytes is the minimum
    assert calls["log"][-1][3] == b""


def test_sct_entry_rules(calls):
    v = lambda *s, roots=ROOTS: S._verify_sct(_leaf(_lst(*s)), ISSUER, roots)  # noqa: E731
    none = "no SCT from a pinned CT log"
    assert v(_sct(version=1)) == none and v(_sct(log_id=b"O" * 32)) == none
    assert calls["log"] == []
    big_ext = b"\x00" + LOG_ID + (150).to_bytes(8, "big") + b"\x00\x64" + b"\x00" * 4  # ext_len 100 runs off the end
    assert v(big_ext) == "SCT truncated"
    assert v(_sct() + b"\x00") == "SCT malformed"
    short = _sct()[:-1]
    assert v(short) == "SCT malformed"
    wrong = "SCT is not SHA-256 with ECDSA or RSA"
    assert v(_sct(hash_alg=5)) == wrong and v(_sct(sig_alg=2)) == wrong
    assert calls["log"] == []
    assert v(_sct(sig_alg=1)) == "SCT signature invalid" and v(_sct(sig_alg=3)) == "SCT signature invalid"
    calls["log"].clear()
    assert v(_sct(ts=2 ** 53), roots=OPEN) == "SCT timestamp out of range"
    assert calls["log"] == []
    assert v(_sct(ts=2 ** 53 - 1), roots=OPEN) == "SCT signature invalid"
    calls["log"].clear()
    late = "SCT log key not valid at its timestamp"
    assert v(_sct(ts=99)) == late and v(_sct(ts=201)) == late
    assert calls["log"] == []
    assert v(_sct(ts=100)) == "SCT signature invalid" and v(_sct(ts=200)) == "SCT signature invalid"
    # the last reason wins; an entry of an unknown log leaves it; a later valid one succeeds
    assert v(_sct(hash_alg=5), _sct(log_id=b"O" * 32)) == wrong
    assert v(_sct(), _sct(hash_alg=5)) == wrong
    assert v(_sct(hash_alg=5), _sct()) == "SCT signature invalid"
    calls["result"] = True
    assert v(_sct(hash_alg=5), _sct()) is None


# ---- checkpoint

ROOT = b"\x01" * 32
LOG = S.PinnedLog(b"ABCDEFGH", "K", S._Validity(0, INF))
V2 = S.PinnedLog(b"ABCDEFGH", "K", S._Validity(0, INF), "log.example")
HEAD = "origin\n7\n%s\n" % _b(ROOT)


def _line(raw, name="n"):
    return "— %s %s" % (name, _b(raw))


def _cp(*lines, head=HEAD):
    return head + "\n" + "\n".join(lines)


def test_checkpoint_body_rules(calls):
    v = lambda text, log=LOG, size=7: S._verify_checkpoint(text, log, size, ROOT)  # noqa: E731
    assert v("no block") == "checkpoint has no signature block"
    assert v("o\n7\n\n") == "checkpoint body too short or without an origin"
    assert v("\n7\n%s\n\n" % _b(ROOT)) == "checkpoint body too short or without an origin"
    for size_line in ("07", "8", " 7", "0"):
        assert v("o\n%s\nx\n\n" % size_line) == "checkpoint size differs from the proof", size_line
    assert v("o\n7\n%s\n\n" % _b(b"\x02" * 32)) == "checkpoint root differs from the proof"
    assert _fails(v, "o\n7\nnot-base64\n\n") == "not base64"
    assert v(_cp()) == "no checkpoint signature by the pinned log key"
    assert calls["log"] == []


def test_checkpoint_signature_lines(calls):
    v = lambda text, log=LOG: S._verify_checkpoint(text, log, 7, ROOT)  # noqa: E731
    no = "no checkpoint signature by the pinned log key"
    assert v(_cp(_line(b"XXXX" + b"sig"))) == no  # another key hint
    assert v(_cp(_line(b"ABCD"))) == no  # a hint and no signature
    assert v(_cp("- n " + _b(b"ABCDsig"))) == no  # not an em dash
    assert v(_cp(_line(b"ABCDsig") + " trailing")) == no
    assert calls["log"] == []
    calls["result"] = True
    assert v(_cp(_line(b"ABCDs"))) is None  # exactly one signature byte is long enough
    assert calls["log"] == [("sha256", HEAD.encode(), "K", b"s")]
    calls["log"].clear()
    assert v(_cp(_line(b"ABCDsig", "other")), V2) == no
    assert calls["log"] == []
    assert v(_cp(_line(b"ABCDsig", "log.example")), V2) is None
    assert calls["log"] == [(None, HEAD.encode(), "K", b"sig")]
    calls["log"].clear()
    # a line that does not verify does not end the search
    seq = [False, True]
    S._verify = lambda *a: (calls["log"].append(a), seq.pop(0))[1]
    assert v(_cp(_line(b"ABCDone"), _line(b"ABCDtwo"))) is None
    assert [c[3] for c in calls["log"]] == [b"one", b"two"]


def test_checkpoint_body_carries_extra_lines(calls):
    calls["result"] = True
    head = HEAD + "extra note\n"
    assert S._verify_checkpoint(_cp(_line(b"ABCDs"), head=head), LOG, 7, ROOT) is None
    assert calls["log"][0][1] == head.encode()


# ---- the entry body (the corpus cannot reach these without re-signing: the inclusion proof and the SET cover the body)

_, _CASES = load("sigstore")
_DSSE = next(c for c in _CASES["verifySigstoreBundleCore"] if c["name"] == "verifySigstoreBundleCore/dsse/valid")
_ROOT_DOC = next(c for c in _CASES["parseTrustedRoot"] if c["name"] == "parseTrustedRoot/synthetic")["args"][0]


def _with_body(edit):
    b = json.loads(json.dumps(_DSSE["args"][0]))
    e = b["verificationMaterial"]["tlogEntries"][0]
    body = json.loads(base64.b64decode(e["canonicalizedBody"]))
    edit(body)
    e["canonicalizedBody"] = base64.b64encode(json.dumps(body).encode()).decode()
    return b


@pytest.fixture
def open_log(monkeypatch):
    monkeypatch.setattr(S, "_verify", lambda *a: True)
    monkeypatch.setattr(S, "verify_rfc9162_inclusion", lambda *a: True)
    return S.parse_trusted_root(_ROOT_DOC)


def test_dsse_entry_signatures_must_be_a_list_of_one(open_log):
    assert S.verify_sigstore_bundle_core(_with_body(lambda b: None), open_log)["ok"] is True  # the seams alone change nothing
    one = {"ok": False, "code": "tlog_body", "detail": "the entry must name exactly one signature"}

    def sigs(v):
        return lambda b: b["spec"].__setitem__("signatures", v)
    assert S.verify_sigstore_bundle_core(_with_body(lambda b: b["spec"].pop("signatures")), open_log) == one
    for v in (None, 5, "x", {"a": 1}, {"signature": "x", "verifier": "y"}, [], [1], [{}, {}]):
        assert S.verify_sigstore_bundle_core(_with_body(sigs(v)), open_log) == one, v


def test_dsse_entry_body_kind_and_payload(open_log):
    r = S.verify_sigstore_bundle_core(_with_body(lambda b: b.update(kind="intoto")), open_log)
    assert r == {"ok": False, "code": "tlog_body", "detail": "the entry body is not the kind the bundle names"}
    r = S.verify_sigstore_bundle_core(_with_body(lambda b: b["spec"]["payloadHash"].update(value="00")), open_log)
    assert r == {"ok": False, "code": "tlog_body", "detail": "the entry names another payload"}
    r = S.verify_sigstore_bundle_core(_with_body(lambda b: b.pop("spec")), open_log)
    assert r == {"ok": False, "code": "tlog_body", "detail": "the entry names another payload"}


# ---- the SLSA facts


def _core(st, **core):
    c = {"subjects": [{"alg": "sha256", "digest": "d"}], "identity": "i", "oidc_issuer": "o", "signed_time": 5, "rekor_log_index": 6}
    c.update(core)
    return {"ok": True, "core": c, "statement": st}


def _stmt(**over):
    bd = {"buildType": "bt", "externalParameters": {}}
    st = {"predicateType": S.SLSA_PROVENANCE_V1, "predicate": {"buildDefinition": bd, "runDetails": {"builder": {"id": "bi"}}}}
    bd.update(over)
    return st


def _facts(monkeypatch, r):
    monkeypatch.setattr(S, "verify_sigstore_bundle_core", lambda b, roots: r)
    return S.verify_sigstore_bundle({}, None)


BASE_FACTS = {"v": 1, "predicate_type": S.SLSA_PROVENANCE_V1, "build_type": "bt", "builder_id": "bi", "subjects": [{"alg": "sha256", "digest": "d"}],
              "identity": "i", "oidc_issuer": "o", "integrated_time": 5, "rekor_log_index": 6}


def test_slsa_facts(monkeypatch):
    refused = {"ok": False, "code": "x", "detail": "y"}
    assert _facts(monkeypatch, refused) is refused
    assert _facts(monkeypatch, _core({"predicateType": "other"})) == {"ok": False, "code": "predicate", "detail": "predicate other is not SLSA provenance v1"}
    need = {"ok": False, "code": "predicate", "detail": "buildType, externalParameters and builder.id are required (SLSA Build L1)"}
    assert _facts(monkeypatch, _core({"predicateType": S.SLSA_PROVENANCE_V1})) == need
    for mutate in (lambda s: s["predicate"]["buildDefinition"].pop("buildType"), lambda s: s["predicate"]["buildDefinition"].update(externalParameters=1),
                   lambda s: s["predicate"]["runDetails"].update(builder={"id": 5}), lambda s: s["predicate"]["runDetails"].pop("builder"),
                   lambda s: s["predicate"].update(runDetails=5), lambda s: s["predicate"].update(buildDefinition=5), lambda s: s.update(predicate=5)):
        st = _stmt()
        mutate(st)
        assert _facts(monkeypatch, _core(st)) == need
    assert _facts(monkeypatch, _core(_stmt())) == {"ok": True, "facts": BASE_FACTS}
    src = _core(_stmt(), source_repo="r", source_ref="f", source_digest="g")
    assert _facts(monkeypatch, src) == {"ok": True, "facts": dict(BASE_FACTS, source_repo="r", source_ref="f", source_digest="g")}
    assert _facts(monkeypatch, _core(_stmt(), source_ref="f"))["facts"] == dict(BASE_FACTS, source_ref="f")


@pytest.mark.parametrize("deps,want", [
    ([{"uri": "u", "digest": {"gitCommit": "c"}}], {"uri": "u", "git_commit": "c"}),
    ([{"uri": "u"}, {"uri": "second"}], {"uri": "u"}),
    ([{"uri": "u", "digest": {"gitCommit": 5}}], {"uri": "u"}),
    ([{"uri": "u", "digest": 5}], {"uri": "u"}),
    ([{"uri": 5}], None), ([{}], None), ([5], None), ([], None), ("x", None), (None, None),
])
def test_slsa_provenance_source(monkeypatch, deps, want):
    facts = _facts(monkeypatch, _core(_stmt(resolvedDependencies=deps)))["facts"]
    assert facts == (dict(BASE_FACTS, provenance_source=want) if want else BASE_FACTS)


def test_public_constants():
    assert S.INTOTO_PAYLOAD_TYPE == "application/vnd.in-toto+json"
    assert S.SIGSTORE_BUNDLE_MEDIA_TYPES == ("application/vnd.dev.sigstore.bundle+json;version=0.2", "application/vnd.dev.sigstore.bundle+json;version=0.3",
                                             "application/vnd.dev.sigstore.bundle.v0.3+json")
