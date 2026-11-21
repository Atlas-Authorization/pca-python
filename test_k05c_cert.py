"""Kill tests (attest_cert, attest_der, attest_ocsp, attest_gcp, attest, a2a): exact parse-failure reasons, the CA test's operand
order, the validity-window tag checks and the early exits of two search loops."""
import hashlib

import pytest

pytest.importorskip("cryptography")

from atlas_pca import a2a as A2A
from atlas_pca import attest as AT
from atlas_pca import attest_cert as C
from atlas_pca import attest_der as D
from atlas_pca import attest_gcp as G
from atlas_pca import attest_ocsp as O
from atlas_pca.attest_cert import Cert, CertError
from test_attest_units import integer, octets, oid, seq, tlv
from test_k05_kill_intel_ocsp_cert import BIT, HEAD, OPENSSL, SPKI, _basic, _cert, _ok, _responder, _resp, _rid_name, _tbs, _v, _view

# ---------------------------------------------------------------------------------------------- Cert: each field's own reason


@pytest.mark.parametrize("der, field", [
    (seq(tlv(0x31), seq(), BIT), "no tbsCertificate"),
    (_cert(octets(b"")), "serial"),
    (_cert(integer(5), octets(b"")), "signature algorithm"),
    (_cert(integer(5), seq(), octets(b"")), "issuer"),
    (_cert(integer(5), seq(), seq(), octets(b"")), "validity"),
    (_cert(integer(5), seq(), seq(), seq(), octets(b"")), "subject"),
    (_cert(*HEAD, octets(b"")), "subjectPublicKeyInfo"),
])
def test_cert_parse_failures_name_the_field(der, field):
    with pytest.raises(CertError) as e:
        Cert(der)
    assert str(e.value) == "%s (%s)" % (OPENSSL, field)


def test_unsupported_public_key_reason():
    with pytest.raises(CertError) as e:
        Cert(_cert(*HEAD, SPKI)).public_key
    msg = str(e.value)
    assert msg.startswith("error:1E08010C:DECODER routines::unsupported (") and msg.endswith(")") and len(msg) > 45


def _with_basic_constraints(value):
    return Cert(_cert(*HEAD, SPKI, tlv(0xA3, seq(seq(oid("2.5.29.19"), octets(value))))))


def test_ca_reads_the_basic_constraints_flag_strictly():
    assert _with_basic_constraints(seq(tlv(0x01, b"\xff"))).ca is True
    assert _with_basic_constraints(seq(tlv(0x01, b"\x00"))).ca is False        # cA FALSE
    assert _with_basic_constraints(tlv(0x04, b"\x01\x01\xff")).ca is False     # not a SEQUENCE, though its content reads as TRUE
    assert _with_basic_constraints(b"\x30\x02\x01\x01\xff").ca is False        # the flag overruns the SEQUENCE (a byte follows it)
    assert _with_basic_constraints(seq(tlv(0x02, b"\xff"))).ca is False        # first member is not a BOOLEAN
    assert _with_basic_constraints(b"\x30\x02\x01\x00\xff").ca is False        # a zero-length BOOLEAN
    assert _with_basic_constraints(b"\x30\x01\x01").ca is False                # truncated member
    assert _with_basic_constraints(seq()).ca is False                          # empty SEQUENCE


def test_verify_is_false_when_the_signature_check_faults(monkeypatch):
    parts = (integer(5), seq(integer(1)), seq(integer(2)), seq(), seq(integer(3)), SPKI)
    c = Cert(seq(seq(*parts), seq(integer(1)), BIT))
    assert c.sig_alg_der == c.inner_sig_alg_der and c.sig_unused == 0

    def boom(*a):
        raise RuntimeError("boom")

    monkeypatch.setattr(C, "_verify_signature", boom)
    assert c.verify(object()) is False


# ---------------------------------------------------------------------------------------------- validity window

def _utc(text):
    return tlv(0x17, text)


def _cert_with(outer=0x30, tbs_tag=0x30, serial=None, alg=None, issuer=None):
    validity = seq(_utc(b"250101000000Z"), _utc(b"350101000000Z"))
    body = (serial if serial is not None else integer(1)) + (alg if alg is not None else seq()) + (issuer if issuer is not None else seq()) + validity
    return tlv(outer, tlv(tbs_tag, body) + seq() + BIT)


def test_validity_requires_every_wrapper_tag_in_order():
    want = (D.parse_der_time(0x17, "250101000000Z"), D.parse_der_time(0x17, "350101000000Z"))
    assert None not in want
    assert D.der_validity_ms(_cert_with()) == want
    for bad in (_cert_with(outer=0x31), _cert_with(tbs_tag=0x31), _cert_with(serial=octets(b"\x01")),
                _cert_with(alg=octets(b"")), _cert_with(issuer=octets(b""))):
        assert D.der_validity_ms(bad) == (None, None)


# ---------------------------------------------------------------------------------------------- small exact behaviours

def test_attestation_verifier_interface_is_abstract():
    with pytest.raises(NotImplementedError):
        AT.AttestationVerifier().verify({}, {}, 0)


def test_push_check_takes_the_first_task_id_it_finds():
    salt = "s" * 16
    tok = A2A.push_token("t1", ["c"], salt)
    both = {"task": {"id": "t1"}, "statusUpdate": {"taskId": "other"}}
    assert A2A.check_push("t1", ["c"], salt, tok, both) == {"ok": True}
    both = {"task": {"id": "other"}, "statusUpdate": {"taskId": "t1"}}
    assert A2A.check_push("t1", ["c"], salt, tok, both) == {"ok": False, "reason": "task_mismatch"}


def test_ocsp_delegated_search_stops_at_the_first_verified_responder(monkeypatch):
    d = _responder()
    seen = []
    real = O._verify_sig

    def counting(*a):
        seen.append(1)
        return real(*a)

    monkeypatch.setattr(O, "_verify_sig", counting)
    one = _resp(_basic(_tbs(rid=_rid_name(d)), key="resp", certs=[d]))
    two = _resp(_basic(_tbs(rid=_rid_name(d)), key="resp", certs=[d, d]))
    assert _view(_v(one)) == _ok(responder="delegated")
    n1 = len(seen)
    del seen[:]
    assert _view(_v(two)) == _ok(responder="delegated")
    assert len(seen) == n1 and n1 >= 1


def test_gcp_nonce_search_stops_at_the_first_binding(monkeypatch):
    from test_attest_units import GcpEndToEnd, attestation_binding, EXP
    t = GcpEndToEnd("test_a_bound_token_from_a_pinned_key_passes")
    t.setUp()
    seen = []
    real = G.decode_claim_bytes

    def spy(v):
        seen.append(v)
        return real(v)

    monkeypatch.setattr(G, "decode_claim_bytes", spy)
    good = attestation_binding(EXP).hex()
    assert t.run_token(t.token({"eat_nonce": [good, "late-candidate"]}))["ok"] is True
    assert "late-candidate" not in seen and good in seen
