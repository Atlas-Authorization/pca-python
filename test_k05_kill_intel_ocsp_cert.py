"""OCSP + X.509 model kill tests of the 0.5 mutation baseline (attest_ocsp.py, attest_cert.py). verify_ocsp_response runs over
DER built byte by byte (so every optional element and malformation is reachable) and really signed; expected reasons are
those of packages/pca/src/attest-nvidia-ocsp.ts, except the structural refusals below (see NATIVE) and OpenSSL's parse errors,
where only the stable prefix is pinned."""
import datetime
import functools
import hashlib
import time

import pytest

pytest.importorskip("cryptography")

from atlas_pca import attest_cert as C
from atlas_pca import attest_ocsp as O
from atlas_pca.attest_cert import Cert, CertError
from atlas_pca.attest_der import DerError, _tlv_at
from test_attest_units import integer, octets, oid, seq, tlv
from test_k05_kill_intel import _c, _mint, _ms, _pem

NOW = _ms(2026, 6, 1)
HOUR, DAY = 3600 * 1000, 24 * 3600 * 1000
THIS, NEXT = NOW - HOUR, NOW + DAY
NOW_DT = datetime.datetime(2026, 6, 1)
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
HASH_OID = {"sha1": "1.3.14.3.2.26", "sha256": "2.16.840.1.101.3.4.2.1", "sha384": "2.16.840.1.101.3.4.2.2", "sha512": "2.16.840.1.101.3.4.2.3"}
GOOD, UNKNOWN = tlv(0x80), tlv(0x82)
NATIVE = "OCSP response rejected: "  # NATIVE-prefixed and PSS wording is this SDK's own diagnostics (TS's comes from pkijs), not a cross-language contract


def _gt(ms):
    return tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(ms // 1000)).encode())


@functools.lru_cache(maxsize=None)
def _k():
    c = _c()
    return {n: c.ec.generate_private_key(c.ec.SECP256R1()) for n in ("root", "ca", "leaf", "resp", "rogue")}


@functools.lru_cache(maxsize=None)
def _pki():
    k = _k()
    root = Cert(_mint("Root", "Root", k["root"].public_key(), k["root"], 1, True))
    ca = Cert(_mint("CA", "Root", k["ca"].public_key(), k["root"], 2, True))
    leaf = Cert(_mint("Leaf", "CA", k["leaf"].public_key(), k["ca"], 3, False))
    return root, ca, leaf


def _eku(*oids):
    c = _c()
    return (c.x509.ExtendedKeyUsage([c.x509.ObjectIdentifier(o) for o in oids]), False)


OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"


def _responder(signer="ca", issuer_cn="CA", key="resp", eku=(OCSP_SIGNING,), nb=datetime.datetime(2025, 1, 1), na=datetime.datetime(2035, 1, 1), cn="Responder"):
    k = _k()
    return Cert(_mint(cn, issuer_cn, k[key].public_key(), k[signer], 7, False, [_eku(*eku)] if eku else [], nb, na))


def _key_bits(cert):
    return O._spki_key_bits(cert.spki_der)


def _single(status=GOOD, this=THIS, nxt=NEXT, tail=b"", hash_="sha1", serial=None, name_hash=None, key_hash=None, hash_oid=None, this_t=None):
    _, ca, leaf = _pki()
    h = lambda b: hashlib.new(hash_, b).digest()  # noqa: E731
    cid = seq(seq(oid(hash_oid or HASH_OID[hash_]), tlv(0x05)),
              octets(name_hash if name_hash is not None else h(ca.subject_der)),
              octets(key_hash if key_hash is not None else h(_key_bits(ca))),
              tlv(0x02, serial if serial is not None else leaf.serial))
    nx = tlv(0xA0, _gt(nxt)) if nxt is not None else b""
    return seq(cid, status, this_t if this_t is not None else _gt(this), nx, tail)


def _rid_name(cert):
    return tlv(0xA1, cert.subject_der)


def _rid_key(cert):
    return tlv(0xA2, octets(hashlib.sha1(_key_bits(cert)).digest()))


def _tbs(rid=None, singles=None, produced=THIS, version=b""):
    return seq(version, rid if rid is not None else _rid_name(_pki()[1]), _gt(produced), seq(*(singles if singles is not None else [_single()])))


def _basic(tbs=None, key="ca", alg=None, sig_t=0x03, certs=(), certs_tag=0xA0):
    c = _c()
    t = tbs if tbs is not None else _tbs()
    sig = _k()[key].sign(t, c.ec.ECDSA(c.hashes.SHA256()))
    tail = tlv(certs_tag, seq(*[x.raw for x in certs])) if certs else b""
    return seq(t, alg if alg is not None else seq(oid(ECDSA_SHA256)), tlv(sig_t, b"\x00" + sig), tail)


def _resp(basic=None, status=0, rtype="1.3.6.1.5.5.7.48.1.1"):
    b = basic if basic is not None else _basic()
    return seq(tlv(0x0A, bytes([status])), tlv(0xA0, seq(oid(rtype), octets(b))))


def _v(der=None, now=NOW, max_age=None, skew=0, chain=None):
    root, ca, leaf = _pki()
    return O.verify_ocsp_response(_resp() if der is None else der, leaf, ca, [leaf, ca, root] if chain is None else chain, now, max_age, skew)


def _view(r):
    """The verdict of an accept (test_accept_result_times pins the times) or a whole refusal."""
    return {k: r[k] for k in ("ok", "status", "responder")} if r["ok"] else r


def _fail(reason):
    return {"ok": False, "reason": reason}


def _ok(status="good", responder="issuer"):
    return {"ok": True, "status": status, "responder": responder}


def _native(msg):
    return _fail(NATIVE + msg)


# ---------------------------------------------------------------------------------------------- envelope
def test_accepts_by_name_and_by_key():
    assert _view(_v()) == _ok()
    assert _view(_v(bytearray(_resp()))) == _ok()
    assert _view(_v(_resp(_basic(_tbs(rid=_rid_key(_pki()[1])))))) == _ok()
    assert _view(_v(_resp(_basic(_tbs(version=tlv(0xA0, integer(0))))))) == _ok()


def test_envelope_refusals():
    assert _v(b"\x30") == _fail("response is not valid DER")
    assert _v(b"\x30\x84\x7f\xff\xff\xff") == _fail("response is not valid DER")
    assert _v(_resp() + b"\x00") == _fail("trailing bytes after OCSPResponse")
    assert _v(seq(tlv(0x0A, b"\x01"))) == _fail("OCSP responseStatus is 1 (not successful)")
    assert _v(_resp(status=6)) == _fail("OCSP responseStatus is 6 (not successful)")
    assert _v(seq(tlv(0x0A, b"\x00"))) == _fail("successful response carries no responseBytes")
    assert _v(seq(tlv(0x0A, b"\x00"), tlv(0xA1, seq()))) == _fail("successful response carries no responseBytes")
    assert _v(_resp(rtype="1.2.3")) == _fail("responseType is not id-pkix-ocsp-basic")
    assert _v(_resp(b"\x30")) == _fail("BasicOCSPResponse is not valid DER")
    assert _v(_resp(b"\x30\x84\x7f\xff\xff\xff")) == _fail("BasicOCSPResponse is not valid DER")


@pytest.mark.parametrize("der,msg", [
    (tlv(0x31), "OCSPResponse is not a SEQUENCE"),
    (seq(), "responseStatus is not an ENUMERATED"),
    (seq(integer(0)), "responseStatus is not an ENUMERATED"),
    (seq(tlv(0x0A, b"\x00"), tlv(0xA0)), "responseBytes is not a SEQUENCE"),
    (seq(tlv(0x0A, b"\x00"), tlv(0xA0, octets(b""))), "responseBytes is not a SEQUENCE"),
    (seq(tlv(0x0A, b"\x00"), tlv(0xA0, seq(oid("1.3.6.1.5.5.7.48.1.1")))), "responseBytes is malformed"),
    (seq(tlv(0x0A, b"\x00"), tlv(0xA0, seq(octets(b""), octets(b"")))), "responseBytes is malformed"),
    (seq(tlv(0x0A, b"\x00"), tlv(0xA0, seq(oid("1.3.6.1.5.5.7.48.1.1"), integer(1)))), "responseBytes is malformed"),
])
def test_envelope_structure_fails_closed(der, msg):
    assert _v(der) == _native(msg)


def _alg():
    return seq(oid(ECDSA_SHA256))


def test_basic_response_every_field_is_checked_independently():
    # the signature over the TBS is genuine in all of these: only the wrapper is wrong, so a skipped check would accept
    bad = _native("BasicOCSPResponse is malformed")
    assert _v(_resp(_basic(alg=tlv(0x31, oid(ECDSA_SHA256))))) == bad
    assert _v(_resp(_basic(sig_t=0x04))) == bad
    t = _tbs()
    assert _v(_resp(seq(t, _alg()))) == bad
    assert _v(_resp(seq(tlv(0x31), _alg(), tlv(0x03, b"\x00")))) == bad
    assert _v(_resp(tlv(0x31, t))) == _native("BasicOCSPResponse is not a SEQUENCE")


def test_malformed_times_and_unsupported_algorithm():
    bad = _single(this_t=tlv(0x18, b"20250229000000Z"))
    assert _v(_resp(_basic(_tbs(singles=[bad])))) == _fail("response carries a malformed (out-of-range) ASN.1 time")
    assert _v(_resp(_basic(alg=seq(oid("1.2.840.113549.1.1.5"))))) == _fail("unsupported OCSP signature algorithm 1.2.840.113549.1.1.5")
    # an RSA algorithm over an EC issuer key never verifies
    assert _v(_resp(_basic(alg=seq(oid("1.2.840.113549.1.1.11"))))) == _fail("OCSP response signature does not verify under the issuer key")


@pytest.mark.parametrize("tbs", [
    seq(),
    seq(integer(1)),
    seq(tlv(0xA3)),
    seq(tlv(0xA0, integer(0))),
])
def test_response_data_without_a_responder_id_fails_closed(tbs):
    assert _v(_resp(_basic(tbs))) == _native("responderID is malformed")


def test_response_data_field_tags():
    _, ca, _ = _pki()
    rid = _rid_name(ca)
    assert _v(_resp(_basic(seq(rid)))) == _native("producedAt is malformed")
    assert _v(_resp(_basic(seq(rid, tlv(0x17, b"260601000000Z"), seq(_single()))))) == _native("producedAt is malformed")
    assert _v(_resp(_basic(seq(rid, _gt(THIS))))) == _native("responses is malformed")
    assert _v(_resp(_basic(seq(rid, _gt(THIS), tlv(0x31, _single()))))) == _native("responses is malformed")
    assert _v(_resp(_basic(seq(rid, _gt(THIS), seq(seq(integer(1), GOOD, _gt(THIS))))))) == _native("SingleResponse is malformed")   # CertID not a SEQUENCE
    assert _v(_resp(_basic(seq(rid, _gt(THIS), seq(seq(seq(), GOOD)))))) == _native("SingleResponse is malformed")                   # two fields only
    assert _v(_resp(_basic(seq(rid, _gt(THIS), seq(seq(seq(seq(oid(HASH_OID["sha1"]))), GOOD, _gt(THIS))))))) == _native("CertID is malformed")


# ---------------------------------------------------------------------------------------------- CertID
@pytest.mark.parametrize("hash_", ["sha1", "sha256", "sha384", "sha512"])
def test_certid_hash_algorithms(hash_):
    assert _view(_v(_resp(_basic(_tbs(singles=[_single(hash_=hash_)]))))) == _ok()


def test_certid_match_is_every_field():
    none = _fail("no SingleResponse matches the certificate (serial / issuer hashes differ)")
    one = lambda **kw: _v(_resp(_basic(_tbs(singles=[_single(**kw)]))))  # noqa: E731
    assert one(serial=b"\x63") == none
    assert one(name_hash=bytes(20)) == none
    assert one(key_hash=bytes(20)) == none
    assert one(hash_oid="1.2.3") == none
    assert _v(_resp(_basic(_tbs(singles=[])))) == none
    assert _view(one(serial=b"\x00\x00\x03")) == _ok()  # leading zeros of the serial do not count
    assert _v(_resp(_basic(_tbs(singles=[_single(), _single()])))) == _fail("ambiguous: multiple SingleResponses match the certificate")
    assert _view(_v(_resp(_basic(_tbs(singles=[_single(serial=b"\x63"), _single(hash_oid="1.2.3"), _single()]))))) == _ok()


# ---------------------------------------------------------------------------------------------- the responder
def test_responder_id_of_the_issuer():
    _, ca, _ = _pki()
    no_cert = _fail("no embedded responder certificate verifies the response")
    assert _v(_resp(_basic(key="rogue"))) == _fail("OCSP response signature does not verify under the issuer key")
    assert _v(_resp(_basic(_tbs(rid=_rid_key(ca)), key="rogue"))) == _fail("OCSP response signature does not verify under the issuer key")
    # the responder ID names someone else: only an embedded certificate could speak
    assert _v(_resp(_basic(_tbs(rid=tlv(0xA2, octets(bytes(20))))))) == no_cert
    assert _v(_resp(_basic(_tbs(rid=_rid_name(_pki()[2]))))) == no_cert
    assert _v(_resp(_basic(_tbs(rid=tlv(0xA1, ca.subject_der + ca.subject_der))))) == no_cert   # byName holds exactly one Name


def test_responder_by_key_must_be_an_octet_string():
    _, ca, _ = _pki()
    digest = hashlib.sha1(_key_bits(ca)).digest()
    assert _v(_resp(_basic(_tbs(rid=tlv(0xA2, tlv(0x05, digest)))))) == _fail("no embedded responder certificate verifies the response")


def test_delegated_responder_accepts():
    d = _responder()
    assert _view(_v(_resp(_basic(_tbs(rid=_rid_name(d)), key="resp", certs=[d])))) == _ok(responder="delegated")
    assert _view(_v(_resp(_basic(_tbs(rid=_rid_key(d)), key="resp", certs=[d])))) == _ok(responder="delegated")
    multi = _responder(eku=("1.3.6.1.5.5.7.3.1", OCSP_SIGNING))
    assert _view(_v(_resp(_basic(_tbs(rid=_rid_name(multi)), key="resp", certs=[multi])))) == _ok(responder="delegated")
    # any chain certificate at or above the issuer may have issued it
    above = _responder(signer="root", issuer_cn="Root")
    assert _view(_v(_resp(_basic(_tbs(rid=_rid_name(above)), key="resp", certs=[above])))) == _ok(responder="delegated")


def test_delegated_responder_refusals():
    root, ca, leaf = _pki()
    d = _responder()
    resp = lambda cert, key="resp", certs=None: _resp(_basic(_tbs(rid=_rid_name(cert)), key=key, certs=[cert] if certs is None else certs))  # noqa: E731
    assert _v(_resp(_basic(_tbs(rid=_rid_name(leaf)), key="resp", certs=[d]))) == _fail("embedded certificates do not match the responderID")
    assert _v(resp(_responder(eku=None))) == _fail("delegated responder certificate lacks the id-kp-OCSPSigning EKU")
    assert _v(resp(_responder(eku=("1.3.6.1.5.5.7.3.1",)))) == _fail("delegated responder certificate lacks the id-kp-OCSPSigning EKU")
    assert _v(resp(_responder(na=datetime.datetime(2026, 1, 1)))) == _fail("delegated responder certificate is outside its validity window")
    not_ours = _fail("delegated responder certificate is not signed by the supplied NVIDIA chain")
    assert _v(resp(_responder(signer="rogue"))) == not_ours
    above = _responder(signer="root", issuer_cn="Root")
    assert _v(resp(above), chain=[root, leaf, ca]) == not_ours    # the root sits below the issuer in this chain's order
    assert _v(resp(above), chain=[]) == not_ours                  # issuer outside the chain: the issuer alone may sign
    assert _view(_v(resp(d), chain=[])) == _ok(responder="delegated")
    assert _v(resp(d, key="ca")) == _fail("OCSP response signature does not verify under the delegated responder key")
    # the issuer is named but its signature fails: that reason wins over any delegated reason
    assert _v(_resp(_basic(key="rogue", certs=[d]))) == _fail("OCSP response signature does not verify under the issuer key")
    # certificates outside the [0] slot are not embedded certificates
    assert _v(_resp(_basic(_tbs(rid=_rid_name(d)), key="resp", certs=[d], certs_tag=0xA1))) == _fail("no embedded responder certificate verifies the response")


def test_delegated_responder_validity_window_boundaries():
    d = _responder(nb=NOW_DT, na=NOW_DT + datetime.timedelta(days=1))
    der = _resp(_basic(_tbs(rid=_rid_name(d), singles=[_single(nxt=NOW + 2 * DAY)]), key="resp", certs=[d]))
    out = _fail("delegated responder certificate is outside its validity window")
    good = _ok(responder="delegated")
    assert _view(_v(der, now=NOW)) == good
    assert _v(der, now=NOW - 1) == out
    assert _view(_v(der, now=NOW - 1, skew=1)) == good
    assert _view(_v(der, now=NOW + DAY)) == good
    assert _v(der, now=NOW + DAY + 1) == out
    assert _v(der, now=NOW + DAY + 1, skew=5) == out  # the skew widens the start only, as in the reference


@pytest.mark.parametrize("first", [
    lambda: _responder(eku=None),
    lambda: _responder(na=datetime.datetime(2026, 1, 1)),
    lambda: _responder(signer="rogue"),
    lambda: _responder(key="rogue"),
    lambda: _responder(cn="Someone Else"),
])
def test_a_refused_candidate_does_not_stop_the_search(first):
    d = _responder()
    der = _resp(_basic(_tbs(rid=_rid_name(d)), key="resp", certs=[first(), d]))
    assert _view(_v(der)) == _ok(responder="delegated")


# ---------------------------------------------------------------------------------------------- freshness
def _fresh(**kw):
    produced = kw.pop("produced", THIS)
    return _resp(_basic(_tbs(singles=[_single(**kw)], produced=produced)))


def test_future_times_and_their_skew():
    assert _v(_fresh(this=NOW + 1000)) == _fail("response thisUpdate is in the future")
    assert _view(_v(_fresh(this=NOW + 1000), skew=1000)) == _ok()
    assert _v(_fresh(this=NOW + 1000), skew=999) == _fail("response thisUpdate is in the future")
    assert _view(_v(_fresh(this=NOW))) == _ok()
    assert _v(_fresh(produced=NOW + 1000)) == _fail("response producedAt is in the future")
    assert _view(_v(_fresh(produced=NOW + 1000), skew=1000)) == _ok()
    assert _v(_fresh(produced=NOW + 1000), skew=999) == _fail("response producedAt is in the future")
    assert _view(_v(_fresh(produced=NOW))) == _ok()
    assert _v(_fresh(this=NOW + 1000, produced=NOW + 1000)) == _fail("response thisUpdate is in the future")


def test_next_update():
    assert _v(_fresh(nxt=THIS - 1000)) == _fail("response nextUpdate is invalid")
    assert _v(_fresh(this=NOW + 5000, nxt=NOW + 4000), skew=5000) == _fail("response nextUpdate is invalid")
    assert _view(_v(_fresh(this=NOW, nxt=NOW))) == _ok()
    assert _v(_fresh(this=NOW, nxt=NOW), now=NOW + 1) == _fail("response is stale (past nextUpdate)")
    assert _v(_fresh(nxt=NOW - 1000), max_age=0) == _fail("response is stale (past nextUpdate)")   # before the age check


def test_single_response_optional_fields():
    ext = tlv(0xA1, seq())
    assert _view(_v(_fresh(nxt=None))) == _ok()                 # three fields only: no [0] to read
    assert _view(_v(_fresh(nxt=None, tail=ext))) == _ok()       # a fourth field that is not [0]
    assert _view(_v(_fresh(tail=ext))) == _ok()
    # no nextUpdate means nothing can be stale or invalid, whatever the clock
    assert _view(_v(_fresh(nxt=None), now=NOW + 3 * DAY)) == _ok()
    single = lambda inner: _resp(_basic(_tbs(singles=[_single(nxt=None, tail=tlv(0xA0, inner))])))  # noqa: E731
    assert _v(single(b"")) == _native("nextUpdate is malformed")
    assert _v(single(tlv(0x17, b"260601000000Z"))) == _native("nextUpdate is malformed")
    assert _v(_fresh(this_t=tlv(0x17, b"260601000000Z"))) == _native("thisUpdate is malformed")


def test_max_age():
    aged = _fresh(this=NOW - HOUR, nxt=None)
    older = _fail("response is older than the maximum accepted age")
    assert _view(_v(aged, max_age=HOUR)) == _ok()
    assert _v(aged, max_age=HOUR - 1) == older
    assert _v(_fresh(this=NOW - 1000, produced=NOW - 1000, nxt=None), max_age=0) == older   # an explicit 0 is not the default
    assert _view(_v(_fresh(this=NOW, nxt=None), max_age=0)) == _ok()
    seven = _fresh(this=NOW - 7 * DAY, produced=NOW - 7 * DAY, nxt=None)
    assert _view(_v(seven)) == _ok()
    assert _v(seven, now=NOW + 1) == older
    assert O.NVIDIA_OCSP_DEFAULT_MAX_AGE_MS == 7 * DAY


def test_single_response_shape_is_exact():
    ext = tlv(0xA1, seq())
    nx = tlv(0xA0, _gt(NEXT))
    bad = _native("SingleResponse is malformed")
    # a past nextUpdate under another tag no longer skips the stale check
    assert _v(_fresh(nxt=None, tail=tlv(0xA2, _gt(NOW - 1000)))) == bad
    assert _v(_fresh(nxt=None, tail=_gt(NOW - 1000))) == bad
    for tail in (ext + nx, nx + nx, ext + ext, nx + ext + ext, nx + ext + nx):
        assert _v(_fresh(nxt=None, tail=tail)) == bad
    assert _view(_v(_fresh(nxt=None, tail=nx + ext))) == _ok()
    # every SingleResponse counts, matching or not: another serial, and a CertID hash this verifier cannot compare
    for other in (dict(serial=b"\x09"), dict(hash_oid="1.2.3")):
        der = _resp(_basic(_tbs(singles=[_single(nxt=None, tail=tlv(0xA2), **other), _single()])))
        assert _v(der) == bad
        assert _view(_v(_resp(_basic(_tbs(singles=[_single(nxt=None, tail=ext, **other), _single()]))))) == _ok()


def test_next_update_wrapper_holds_exactly_one_time():
    single = lambda inner: _resp(_basic(_tbs(singles=[_single(nxt=None, tail=tlv(0xA0, inner))])))  # noqa: E731
    assert _view(_v(single(_gt(NEXT)))) == _ok()
    assert _v(single(_gt(NEXT) + _gt(NEXT))) == _native("nextUpdate is malformed")
    assert _v(single(_gt(NEXT) + integer(1))) == _native("nextUpdate is malformed")


# ---------------------------------------------------------------------------------------------- certStatus
def test_cert_status_tags_are_exact():
    st = lambda s: _fresh(status=s)  # noqa: E731
    assert _view(_v(st(GOOD))) == _ok()
    for status in (tlv(0xA0), tlv(0xA2), tlv(0x81)):  # the correctly signed response stays refused
        assert _v(st(status)) == _fail("malformed certStatus")
    assert _v(st(tlv(0xA3))) == _fail("unrecognised certStatus")


def test_cert_status():
    st = lambda s: _fresh(status=s)  # noqa: E731
    revoked_at = _gt(_ms(2025, 1, 1))
    assert _view(_v(st(UNKNOWN))) == _ok("unknown")
    assert _view(_v(st(tlv(0xA1, revoked_at)))) == _ok("revoked")
    assert _v(st(tlv(0xA1, tlv(0x18, b"20261019123456.5Z")))) == _fail("malformed revoked certStatus")
    # the reference's ASN.1 schema refuses these before its own certStatus checks (mutation-kill-nvidia-ocsp.test.ts)
    assert _v(st(tlv(0xA1))) == _fail("malformed revoked certStatus")
    assert _v(st(tlv(0xA1, octets(b"2025")))) == _fail("malformed revoked certStatus")
    assert _v(st(tlv(0x83))) == _fail("unrecognised certStatus")
    for status in (tlv(0x05), tlv(0x40), tlv(0xC0)):
        assert _v(st(status)) == _fail("malformed certStatus")


def test_accept_result_times():
    produced, next_ = THIS - 1000, NOW + 2 * DAY
    der = lambda status=GOOD, nxt=next_: _fresh(status=status, nxt=nxt, produced=produced)  # noqa: E731
    base = {"ok": True, "thisUpdate": THIS, "nextUpdate": next_, "producedAt": produced, "responder": "issuer"}
    assert _v(der()) == dict(base, status="good")
    assert _v(der(UNKNOWN)) == dict(base, status="unknown")
    no_next = {k: v for k, v in base.items() if k != "nextUpdate"}
    assert _v(der(nxt=None)) == dict(no_next, status="good")
    assert _v(der(UNKNOWN, nxt=None)) == dict(no_next, status="unknown")
    at = _ms(2025, 1, 1)
    rv = dict(base, status="revoked", revokedAt=at)
    assert _v(der(tlv(0xA1, _gt(at)))) == rv
    assert _v(der(tlv(0xA1, _gt(at)), nxt=None)) == dict(no_next, status="revoked", revokedAt=at)
    d = _responder()
    assert _v(_resp(_basic(_tbs(rid=_rid_name(d), singles=[_single(nxt=next_)], produced=produced), key="resp", certs=[d]))) == dict(base, status="good", responder="delegated")
    # a fractional thisUpdate keeps its milliseconds
    assert _v(_fresh(this_t=tlv(0x18, time.strftime("%Y%m%d%H%M%S", time.gmtime(THIS // 1000)).encode() + b".5Z")))["thisUpdate"] == THIS + 500


@pytest.mark.parametrize("content,want", [
    # asn1js's valueDec for an ENUMERATED: signed, and 0 from 4 content bytes on
    (b"\x04", 4), (b"\x00", 0), (b"", 0), (b"\x80", -128), (b"\x00\x80", 128), (b"\x01\x00\x00", 65536), (b"\x01\x00\x00\x00", 0),
])
def test_revocation_reason(content, want):
    at = _gt(_ms(2025, 1, 1))
    assert _v(_fresh(status=tlv(0xA1, at + tlv(0xA0, tlv(0x0A, content)))))["revocationReason"] == want


def test_revocation_reason_absent():
    at = _gt(_ms(2025, 1, 1))
    for status in (tlv(0xA1, at), tlv(0xA1, at + tlv(0xA0)), tlv(0xA1, at + tlv(0xA0, integer(4))), tlv(0xA1, at + tlv(0xA1, tlv(0x0A, b"\x04")))):
        r = _v(_fresh(status=status))
        assert r["status"] == "revoked" and "revocationReason" not in r


def test_generalized_time_years_below_100_are_read_as_19xx():
    assert O._gen_time_ms("00500102030405Z") == -631054555000  # value: asn1js GeneralizedTime.toDate()
    assert O._gen_time_ms("00990101000000Z") == 915148800000
    assert O._gen_time_ms("01000101000000Z") == -59011459200000


def test_spki_without_a_key_is_refused():
    for spki in (seq(seq()), seq(seq(), octets(b""))):
        with pytest.raises(O.OcspError) as e:
            O._spki_key_bits(spki)
        assert str(e.value) == "malformed SubjectPublicKeyInfo"


def test_wrapper_reports_any_exception(monkeypatch):
    def boom(*a):
        raise RuntimeError("boom")

    monkeypatch.setattr(O, "_verify_inner", boom)
    assert _v(b"x") == _fail("OCSP response rejected: boom")


def test_inner_defaults_reach_the_checks(monkeypatch):
    seen = []
    monkeypatch.setattr(O, "_verify_inner", lambda *a: seen.append(a[4:]) or _ok())
    root, ca, leaf = _pki()
    O.verify_ocsp_response(b"", leaf, ca, [], 5)
    O.verify_ocsp_response(b"", leaf, ca, [], 5, 6, 7)
    assert seen == [(5, None, 0), (5, 6, 7)]


def test_verify_sig_kinds():
    c = _c()
    k = _k()["ca"]
    sig = k.sign(b"m", c.ec.ECDSA(c.hashes.SHA256()))
    assert O._verify_sig(ECDSA_SHA256, b"m", sig, k.public_key()) is True
    assert O._verify_sig(ECDSA_SHA256, b"n", sig, k.public_key()) is False
    assert O._verify_sig(ECDSA_SHA256, b"m", b"junk", k.public_key()) is False
    assert O._verify_sig("1.2.3", b"m", sig, k.public_key()) is False
    assert O._verify_sig("1.2.840.113549.1.1.11", b"m", sig, k.public_key()) is False


# ---------------------------------------------------------------------------------------------- Cert: construction
OPENSSL = "error:0688010A:asn1 encoding routines::nested asn1 error"
BIT = tlv(0x03, b"\x00")
SPKI = seq(seq(), BIT)


def _cert(*tbs_parts):
    return seq(seq(*tbs_parts), seq(), BIT)


HEAD = (integer(5), seq(integer(1)), seq(integer(2)), seq(), seq(integer(3)))


@pytest.mark.parametrize("der", [
    b"",                                              # truncated
    b"\x30\x05\x00",                                  # overrun
    tlv(0x31),                                        # not a SEQUENCE
    seq(tlv(0x31), seq(), BIT),                       # no tbsCertificate
    seq(seq()),                                       # nothing after the TBS
    seq(seq(), tlv(0x31), BIT),                       # outer algorithm
    seq(seq(), seq(), octets(b"\x00")),               # signature wrapper
    seq(seq(), seq(), BIT, tlv(0x05)),                # data after the signature
    seq(seq(), seq(), tlv(0x03)),                     # no unused-bits byte
    _cert(),                                          # empty TBS
    _cert(octets(b"")),                               # serial
    _cert(tlv(0xA0, integer(2)), octets(b"")),        # serial after a version
    _cert(integer(5), octets(b"")),                   # inner algorithm
    _cert(integer(5), seq(), octets(b"")),            # issuer
    _cert(integer(5), seq(), seq(), octets(b"")),     # validity
    _cert(integer(5), seq(), seq(), seq(), octets(b"")),         # subject
    _cert(*HEAD, octets(b"")),                        # subjectPublicKeyInfo
    _cert(*HEAD, seq(seq())),                         # key missing
    _cert(*HEAD, seq(seq(), BIT, BIT)),               # data after the key
    _cert(*HEAD, seq(octets(b""), BIT)),              # algorithm not a SEQUENCE
    _cert(*HEAD, seq(seq(), octets(b"\x00"))),        # key not a BIT STRING
    _cert(*HEAD, SPKI, octets(b"")),                  # data after the key in the TBS
    _cert(*HEAD, SPKI, tlv(0xA3, seq()), tlv(0x81)),  # a unique ID after the extensions
    _cert(*HEAD, SPKI, tlv(0x82), tlv(0x81)),         # unique IDs out of order
])
def test_cert_parse_failures_carry_the_openssl_error(der):
    with pytest.raises(CertError) as e:
        Cert(der)
    assert str(e.value).startswith(OPENSSL)


def test_cert_fields():
    tbs = seq(tlv(0xA0, integer(2)), *HEAD, SPKI, tlv(0x81), tlv(0x82), tlv(0xA3, seq()))
    der = seq(tbs, seq(oid(ECDSA_SHA256)), tlv(0x03, b"\x01SIG"))
    c = Cert(bytearray(der) + b"\x00\x00")   # trailing bytes after the certificate are dropped
    assert c.raw == der
    assert (c.tbs_der, c.sig_alg_der, c.sig_unused, c.signature, c.serial) == (tbs, seq(oid(ECDSA_SHA256)), 1, b"SIG", b"\x05")
    assert (c.inner_sig_alg_der, c.issuer_der, c.subject_der, c.spki_der) == (HEAD[1], HEAD[2], HEAD[4], SPKI)
    assert Cert(_cert(*HEAD, SPKI)).serial == b"\x05"  # no version, no extensions


def test_from_pem():
    der = _pki()[0].raw
    assert Cert.from_pem(_pem(der)).raw == der
    with pytest.raises(CertError) as e:
        Cert.from_pem("not pem")
    assert str(e.value) == "error:0480006C:PEM routines::no start line"
    import base64

    trailing = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % base64.b64encode(der + b"\x00").decode()
    with pytest.raises(CertError) as e:
        Cert.from_pem(trailing)
    assert str(e.value).startswith(OPENSSL)


def test_extension_table_failure_is_remembered(monkeypatch):
    calls = []

    def bad(_tbs):
        calls.append(1)
        raise DerError("x")

    monkeypatch.setattr(C, "parse_tbs_extensions", bad)
    c = Cert(_cert(*HEAD, SPKI))
    assert (c.extensions(), c.extensions()) == ({}, {})
    assert len(calls) == 1


# ---------------------------------------------------------------------------------------------- RSASSA-PSS parameters
SHA384 = seq(oid("2.16.840.1.101.3.4.2.2"), tlv(0x05))
MGF1 = "1.2.840.113549.1.1.8"


def _pss(*parts):
    der = seq(*parts)
    return C._pss_params(der, _tlv_at(der, 0))


def test_pss_params_values_and_defaults():
    assert C._pss_params(b"", None) == ("sha1", "sha1", 20)
    null = tlv(0x05)
    assert C._pss_params(null, _tlv_at(null, 0)) == ("sha1", "sha1", 20)
    assert _pss() == ("sha1", "sha1", 20)
    full = _pss(tlv(0xA0, SHA384), tlv(0xA1, seq(oid(MGF1), SHA384)), tlv(0xA2, tlv(0x02, b"\x01\x00")), tlv(0xA3, integer(1)))
    assert full == ("sha384", "sha384", 256)
    assert _pss(tlv(0xA0, SHA384)) == ("sha384", "sha1", 20)
    assert _pss(tlv(0xA1, seq(oid(MGF1), SHA384))) == ("sha1", "sha384", 20)
    assert _pss(tlv(0xA2, integer(32))) == ("sha1", "sha1", 32)


@pytest.mark.parametrize("part,msg", [
    # native-only diagnostics: never surfaced (Cert.verify and verify_with_alg turn them into False), the reference is OpenSSL's decoder
    (tlv(0xA4, integer(1)), "unknown PSS parameter"),
    (tlv(0xA0), "empty PSS parameter"),
    (tlv(0xA0, integer(1)), "hash algorithm is not a SEQUENCE"),
    (tlv(0xA0, seq(oid("1.2.3"))), "unsupported hash algorithm"),
    (tlv(0xA1, integer(1)), "mask generation function is not a SEQUENCE"),
    (tlv(0xA1, seq(oid("1.2.3"), SHA384)), "unsupported mask generation function"),
    (tlv(0xA2, octets(b"\x20")), "salt length is not an INTEGER"),
    (tlv(0xA3, octets(b"\x01")), "trailer field is not 1"),
    (tlv(0xA3, integer(2)), "trailer field is not 1"),
])
def test_pss_params_refusals(part, msg):
    with pytest.raises(CertError) as e:
        _pss(part)
    assert str(e.value) == msg


def test_a_bad_pss_parameter_never_verifies():
    alg = seq(oid("1.2.840.113549.1.1.10"), seq(tlv(0xA4, integer(1))))
    assert C.verify_with_alg(alg, b"m", b"s", _rsa_public()) is False


@functools.lru_cache(maxsize=None)
def _rsa_public():
    return _c().rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
