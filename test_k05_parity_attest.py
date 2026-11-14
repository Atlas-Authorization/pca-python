"""Attestation parity items of the 0.5 audit: the Intel collateral body read from the signed bytes, the AMD root pin that no
configuration replaces, allowlists that one bad entry never drops, the evaluation-number floor, the OCSP responder key type
and X509_check_akid. Every expectation is the TypeScript reference, stricter only where its comment says so."""
import datetime
import json
import types

import pytest

pytest.importorskip("cryptography")

from atlas_pca import attest_amd as AMD, attest_nvidia as N, attest_ocsp as O
from atlas_pca.attest import verifier_from_config
from atlas_pca.attest_cert import Cert, verify_with_alg
from atlas_pca.attest_common import key_type, load_public_key, rsa_pkcs1_verify
from test_attest_units import integer, oid, seq, sev_report, tlv
from test_k05_attest_amd_kill import CFG
from test_k05_kill_intel import OK_COL, _col, _vcol
from test_k05_kill_intel_ocsp_cert import _basic, _c, _fail, _k, _ok, _resp, _responder, _rid_name, _tbs, _v, _view


# ---------------------------------------------------------------------------------------------- L: the signed body
def _dup(text, name):
    body = json.dumps(json.loads(text)[name], separators=(",", ":")).replace("UpToDate", "Revoked")
    t = text.replace(',"signature":', ',"%s":%s,"signature":' % (name, body))
    assert json.loads(t)[name] != json.loads(text)[name]
    return t


def test_collateral_reads_the_signed_body_never_a_later_duplicate():
    assert _vcol() == OK_COL
    assert _vcol(dict(_col(), tcbInfoJson=_dup(_col()["tcbInfoJson"], "tcbInfo"))) == OK_COL
    assert _vcol(dict(_col(), qeIdentityJson=_dup(_col()["qeIdentityJson"], "enclaveIdentity"))) == OK_COL


# ---------------------------------------------------------------------------------------------- M: the AMD root pin
def test_no_configuration_replaces_the_amd_root_pin():
    genoa = AMD.AMD_ARK_SPKI_SHA384["genoa"]
    forged = "ab" * 48
    assert AMD.AmdSnpVerifier(dict(CFG, trustAnchorArkSpkiSha384=forged))._pin == genoa
    assert verifier_from_config("amd-sev-snp", dict(CFG, trustAnchorArkSpkiSha384=forged))._pin == genoa


# ---------------------------------------------------------------------------------------------- N: mixed allowlists
@pytest.mark.parametrize("key", ["measurements", "hostData", "chipIds"])
def test_amd_policy_mixed_allowlist_raises_like_the_reference(key):
    with pytest.raises(AttributeError):
        AMD.check_sev_snp_policy(AMD.parse_sev_snp_report(sev_report()), {key: ["00" * 48, 1]})


def test_intel_accept_statuses_mixed_keeps_the_list():
    assert _vcol(policy={"acceptStatuses": ["SWHardeningNeeded", 1]}) == dict(OK_COL, ok=False, reason="TCB status UpToDate is not accepted by policy")


@pytest.mark.parametrize("key", ["denyDriverVersions", "denyVbiosVersions"])
@pytest.mark.parametrize("bad", [0, False])
def test_firmware_deny_list_falsy_non_list_is_refused(key, bad):
    with pytest.raises(TypeError):
        N._compile_firmware_policy({key: bad})


def test_firmware_deny_list_absent_is_empty():
    assert N._absent_empty(None) == []
    assert N._absent_empty("") == ""
    assert N._absent_empty(0) == 0
    assert N._absent_empty(["a"]) == ["a"]


# ---------------------------------------------------------------------------------------------- O: the evaluation floor
def test_min_evaluation_number_string_is_read_as_the_reference_reads_it():
    below = {"ok": False, "reason": "tcbEvaluationDataNumber below policy minimum"}
    assert _vcol(policy={"minTcbEvaluationDataNumber": "20"}) == OK_COL
    assert _vcol(policy={"minTcbEvaluationDataNumber": " 5 "}) == OK_COL
    assert _vcol(policy={"minTcbEvaluationDataNumber": "21"}) == below
    # stricter than the reference: `infoNum < "abc"` is false there, so the floor would be dropped
    assert _vcol(policy={"minTcbEvaluationDataNumber": "abc"}) == below


# ---------------------------------------------------------------------------------------------- P: the OCSP responder
def _rsa_and_pss_keys():
    """The same RSA key as a plain RSA SPKI and as an rsaPSS SPKI (no parameters)."""
    c = _c()
    priv = c.rsa.generate_private_key(65537, 2048)
    rsa = priv.public_key().public_bytes(c.serialization.Encoding.DER, c.serialization.PublicFormat.SubjectPublicKeyInfo)
    assert rsa[4:6] == bytes.fromhex("300d")
    body = bytes.fromhex("300b06092a864886f70d01010a") + rsa[19:]
    return priv, load_public_key(rsa), load_public_key(b"\x30\x82" + len(body).to_bytes(2, "big") + body)


def test_key_type_tells_rsa_pss_apart_and_the_key_stays_usable():
    _priv, rsa, pss = _rsa_and_pss_keys()
    assert key_type(rsa) == "rsa"
    assert key_type(pss) == "rsa-pss"
    assert pss.public_numbers() == rsa.public_numbers()


def test_pkcs1_under_an_rsa_pss_key_is_refused_pss_is_not():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    priv, rsa, pss = _rsa_and_pss_keys()
    sig = priv.sign(b"m", padding.PKCS1v15(), hashes.SHA256())
    assert O._verify_sig("1.2.840.113549.1.1.11", b"m", sig, rsa) is True
    assert O._verify_sig("1.2.840.113549.1.1.11", b"m", sig, pss) is False
    assert rsa_pkcs1_verify(rsa, sig, b"m", "sha256") is True
    assert rsa_pkcs1_verify(pss, sig, b"m", "sha256") is False
    alg = seq(oid("1.2.840.113549.1.1.11"))
    assert verify_with_alg(alg, b"m", sig, rsa) is True
    assert verify_with_alg(alg, b"m", sig, pss) is False
    # RSASSA-PSS with default-free parameters: SHA-256, MGF1-SHA-256, salt 32
    sha256 = seq(oid("2.16.840.1.101.3.4.2.1"))
    params = seq(tlv(0xA0, sha256), tlv(0xA1, seq(oid("1.2.840.113549.1.1.8"), sha256)), tlv(0xA2, integer(32)))
    pss_sig = priv.sign(b"m", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    pss_alg = seq(oid("1.2.840.113549.1.1.10"), params)
    assert verify_with_alg(pss_alg, b"m", pss_sig, rsa) is True
    assert verify_with_alg(pss_alg, b"m", pss_sig, pss) is True
    assert verify_with_alg(pss_alg, b"n", pss_sig, pss) is False


def test_rs256_and_crl_paths_refuse_an_rsa_pss_key(monkeypatch):
    """Node can't export an rsa-pss key as a JWK and both TS paths export first, so RS256 refuses such a key outright."""
    from types import SimpleNamespace

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    from atlas_pca import attest_azure, attest_gcp, attest_intel

    priv, rsa, pss = _rsa_and_pss_keys()
    jws = {"header": {"alg": "RS256"}, "signingInput": b"m", "signature": priv.sign(b"m", padding.PKCS1v15(), hashes.SHA256())}
    assert attest_azure._verify_jws_signature(jws, SimpleNamespace(public_key=rsa)) is None
    assert attest_gcp._verify_jws_signature(jws, rsa) is None
    assert "not RSA" in attest_azure._verify_jws_signature(jws, SimpleNamespace(public_key=pss))
    assert "not RSA" in attest_gcp._verify_jws_signature(jws, pss)
    monkeypatch.setattr(attest_intel, "_parse_crl", lambda _der: {"tbs": jws["signingInput"], "sigDer": jws["signature"], "thisUpdate": 0,
                                                                  "nextUpdate": 10, "revoked": []})
    assert attest_intel.verify_crl(b"", rsa, 5) == {"ok": True, "revoked": []}
    assert attest_intel.verify_crl(b"", pss, 5) == {"ok": False, "reason": "CRL signature does not verify under the issuer"}


def test_load_public_key_only_wraps_an_rsa_pss_spki():
    c = _c()
    ec = c.ec.generate_private_key(c.ec.SECP256R1()).public_key().public_bytes(c.serialization.Encoding.DER, c.serialization.PublicFormat.SubjectPublicKeyInfo)
    assert key_type(load_public_key(ec)) == "ec"
    assert key_type(load_public_key(bytearray(ec))) == "ec"


def test_ocsp_malformed_embedded_certificate_is_refused_not_skipped():
    r = _v(_resp(_basic(_tbs(rid=_rid_name(_responder())), key="resp", certs=[_responder(), types.SimpleNamespace(raw=b"\x30\x03\x02\x01\x01")])))
    assert r["ok"] is False
    assert r["reason"].startswith("OCSP response rejected")


# ---------------------------------------------------------------------------------------------- P: X509_check_akid
def _akid_pair(**akid):
    """A child carrying the AuthorityKeyIdentifier fields `akid` and its issuer (serial 5, itself issued by 'Top')."""
    c = _c()
    k = _k()
    now = datetime.datetime(2025, 1, 1)
    later = datetime.datetime(2035, 1, 1)

    def name(cn):
        return c.x509.Name([c.x509.NameAttribute(c.NameOID.COMMON_NAME, cn)])

    def build(subject, issuer, key, signer, serial, exts=()):
        b = c.x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer)).public_key(key.public_key()).serial_number(serial).not_valid_before(now).not_valid_after(later)
        for e in exts:
            b = b.add_extension(e, critical=False)
        return Cert(b.sign(signer, c.hashes.SHA256()).public_bytes(c.serialization.Encoding.DER))

    issuer = build("Mid", "Top", k["ca"], k["root"], 5)
    ext = c.x509.AuthorityKeyIdentifier(akid.get("key_id"), akid.get("names"), akid.get("serial"))
    return build("Kid", "Mid", k["leaf"], k["ca"], 9, [ext]), issuer


def _dn(cn):
    c = _c()
    return [c.x509.DirectoryName(c.x509.Name([c.x509.NameAttribute(c.NameOID.COMMON_NAME, cn)]))]


def test_check_issued_compares_the_akid_serial_and_issuer_name():
    kid, iss = _akid_pair(names=_dn("Top"), serial=5)
    assert kid.check_issued(iss) is True
    kid, iss = _akid_pair(names=_dn("Top"), serial=6)
    assert kid.check_issued(iss) is False
    kid, iss = _akid_pair(names=_dn("Else"), serial=5)
    assert kid.check_issued(iss) is False


def test_check_issued_only_the_first_directory_name_counts():
    c = _c()
    uri = c.x509.UniformResourceIdentifier("https://x.example")
    kid, iss = _akid_pair(names=[uri] + _dn("Top"), serial=5)
    assert kid.check_issued(iss) is True
    kid, iss = _akid_pair(names=_dn("Top") + _dn("Else"), serial=5)
    assert kid.check_issued(iss) is True
    kid, iss = _akid_pair(names=_dn("Else") + _dn("Top"), serial=5)
    assert kid.check_issued(iss) is False
    kid, iss = _akid_pair(names=[uri], serial=5)
    assert kid.check_issued(iss) is True
