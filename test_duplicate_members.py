"""A duplicate member in JSON read from outside is refused (JSON.parse keeps the last one, so the signer and a verifier could read different claims
from the same bytes): the WebAuthn clientDataJSON, the web bot auth key directory and the shared parse helper."""
import json

import pytest

from atlas_pca.sdjwt_jws import js_json_parse_no_duplicates as P


def test_the_helper_refuses_a_duplicate_at_any_depth_and_after_unescaping():
    assert P('{"a":1,"b":{"c":2}}') == {"a": 1, "b": {"c": 2}}
    assert P('{"a":[{"x":1},{"x":2}]}') == {"a": [{"x": 1}, {"x": 2}]}  # the same key in sibling objects is not a duplicate
    for text in ('{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"a":[{"x":1,"x":2}]}', '{"a":1,"\\u0061":2}'):
        with pytest.raises(ValueError, match="duplicate key"):
            P(text)
    with pytest.raises(ValueError):
        P('{"a":NaN}')


def test_a_directory_with_a_duplicate_member_is_refused():
    from atlas_pca import webbotauth as W
    key = {"kty": "OKP", "crv": "Ed25519", "x": "nyhMxDazvaOFgheJPwoXUUeByeYzQY0CCEXGg1KRPZg", "kid": "ka"}
    assert W.parse_key_directory(json.dumps({"keys": [key]}))["keys"][0]["kid"] == "ka"
    with pytest.raises(ValueError, match='duplicate key "keys"'):
        W.parse_key_directory(json.dumps({"keys": [key]}, separators=(",", ":"))[:-1] + ',"keys":[]}')


_HEADER = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwiamt1IjoiaHR0cHM6Ly9tYWEuZXhhbXBsZS5uZXQvY2VydHMiLCJ0eXAiOiJKV1QiLCJ4NWMiOlsiQUFBQSIsIkJCQkIiXX0"


def _b64u(text):
    import base64
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


@pytest.mark.parametrize("parse,name", [("parse_maa_jwt", "parseMaaJwt"), ("parse_gcp_cs_jwt", "parseGcpCsJwt")])
def test_vendor_jwt_parsers_refuse_a_duplicate_member_and_name_it_invalid_json(parse, name):
    from atlas_pca import attest_vendors as V
    f = getattr(V, parse)
    assert f("%s.%s.c2ln" % (_HEADER, _b64u('{"a":2}')))["payload"] == {"a": 2}
    for header, payload in ((_HEADER, '{"a":1,"a":2}'), (_b64u('{"alg":"ES256","alg":"none","kid":"k1"}'), '{"a":2}'),
                            (_b64u("not json"), '{"a":2}'), (_HEADER, '{"a":'), (_HEADER, "nope")):
        with pytest.raises(TypeError) as e:
            f("%s.%s.c2ln" % (header, _b64u(payload)))
        assert str(e.value) == "%s: malformed JSON segment: invalid JSON" % name


def test_signed_collateral_refuses_a_duplicate_member_in_the_body_or_beside_the_signature():
    from atlas_pca import attest_intel as I
    sig = "0" * 128
    for text in ('{"tcbInfo":{"a":1,"a":2},"signature":"%s"}' % sig, '{"tcbInfo":{"a":1},"signature":"%s","signature":"%s"}' % (sig, sig)):
        assert I._verify_signed_json(text, "tcbInfo", None) == {"error": "tcbInfo document is not valid JSON"}


def test_sigstore_entry_body_and_statement_are_read_through_the_duplicate_check(monkeypatch):
    """A real signed bundle (the committed vector) cannot be re-signed here, so the two reads are observed: each goes through the duplicate-only
    check, and a duplicate it reports fails the bundle with the reference's stage and detail."""
    pytest.importorskip("cryptography")
    from atlas_pca import sigstore_bundle as S
    import test_sigstore_vectors as V
    case = next(c for c in V.DOC["cases"] if c["name"] == "npm/sigstore-5.0.0")
    roots = V.ROOTS[case["roots"]]
    seen = []
    real = S.js_json_parse_no_duplicates

    def spy(text):
        seen.append(text)
        return real(text)

    monkeypatch.setattr(S, "js_json_parse_no_duplicates", spy)
    assert S.verify_sigstore_bundle_core(case["bundle"], roots)["ok"] is True
    assert len(seen) == 2 and '"kind"' in seen[0] and '"_type"' in seen[1]  # the entry body, then the in-toto statement

    def dup_on(member):
        def f(text):
            if member in text:
                raise ValueError("duplicate key %s" % member)
            return real(text)
        return f

    monkeypatch.setattr(S, "js_json_parse_no_duplicates", dup_on('"kind"'))
    r = S.verify_sigstore_bundle_core(case["bundle"], roots)
    assert (r["ok"], r["code"], r["detail"]) == (False, "tlog_body", 'fail closed: duplicate key "kind"')
    monkeypatch.setattr(S, "js_json_parse_no_duplicates", dup_on('"_type"'))
    r = S.verify_sigstore_bundle_core(case["bundle"], roots)
    assert (r["ok"], r["code"], r["detail"]) == (False, "statement", 'fail closed: duplicate key "_type"')


def _vc_with(disclosure_text):
    """A passport VC whose only disclosure is the given raw JSON text, signed with a throwaway key generated here."""
    import hashlib
    import os
    from atlas_pca import ed25519
    from atlas_pca.sdjwt_jws import sign_jwt
    from atlas_pca.vc import AGENT_PASSPORT_CONTEXT, AGENT_PASSPORT_VC_TYPE, VC_CONTEXT
    seed = os.urandom(32)
    disclosure = _b64u(disclosure_text)
    digest = base64_url(hashlib.sha256(disclosure.encode("ascii")).digest())
    payload = {"vc": {"@context": [VC_CONTEXT, AGENT_PASSPORT_CONTEXT], "type": ["VerifiableCredential", AGENT_PASSPORT_VC_TYPE],
                      "credentialSubject": {"id": "did:example:s", "passport_id": "p", "model_id": "m", "operator": "o", "hardware_rooted": True,
                                            "issued_at": 1, "_sd": [digest]}},
               "_sd_alg": "sha-256", "iss": "did:example:i", "sub": "did:example:s"}
    return sign_jwt(payload, {"alg": "EdDSA", "typ": "vc+sd-jwt"}, seed) + "~" + disclosure + "~", ed25519.public_key(seed)


def base64_url(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_a_vc_disclosure_with_a_duplicate_member_is_refused_but_number_spellings_stay_accepted():
    from atlas_pca import vc as V
    vc, pub = _vc_with('["s","weights_digest",{"a":1,"a":2}]')
    with pytest.raises(V.VcError, match="pca-vc: malformed disclosure"):
        V.verify_passport_vc(vc, pub)
    for spelling in ('[8.0,"weights_digest","dd"]', '[1e3,"weights_digest","dd"]'):
        vc, pub = _vc_with(spelling)
        assert V.verify_passport_vc(vc, pub)["passport"]["weights_digest"] == "dd"


def test_an_sdjwt_issuer_payload_with_a_duplicate_member_is_refused():
    from atlas_pca import sdjwt as S
    def sd(payload):
        return "%s.%s.%s~" % (_b64u('{"alg":"EdDSA"}'), _b64u(payload), base64_url(bytes([1]) * 64))
    assert S.present(sd('{"_sd":[],"a":1}'), []) == sd('{"_sd":[],"a":1}')
    # refused by the canonical-JWS gate (stricter than the reference, which also accepts 8.0 and 1e3 here)
    with pytest.raises(ValueError, match="duplicate key"):
        S.present(sd('{"_sd":[],"_sd":["x"]}'), [])


def test_a_stripe_webhook_body_with_a_duplicate_member_is_bad_json_even_when_signed():
    from atlas_pca import payments as PAY
    secret, now = "whsec_throwaway_for_this_test", 1_700_000_000
    handler = PAY.create_stripe_issuing_webhook({"secret": secret, "nowSec": lambda: now, "toleranceSec": 300,
                                                 "authorize": lambda a: {"approved": False}})
    def call(body):
        return handler({"rawBody": body, "signature": PAY.sign_stripe_payload(body, secret, now)})
    ok = call('{"type":"other","a":1}')
    assert ok["status"] == 200
    dup = call('{"type":"issuing_authorization.request","type":"other"}')
    assert dup["status"] == 400 and dup["body"] == '{"error":"bad_json"}'


def test_a_webauthn_client_data_with_a_duplicate_member_is_refused_though_correctly_signed():
    """clientDataJSON is built from raw text so a duplicate member survives, and signed with a P-256 key generated here: only the parse decides."""
    pytest.importorskip("cryptography")
    import hashlib
    import struct
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from atlas_pca import webauthn as W
    rp_id, origin = "login.example.com", "https://login.example.com"
    challenge = bytes(range(1, 33))
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": base64_url(nums.x.to_bytes(32, "big")), "y": base64_url(nums.y.to_bytes(32, "big"))}
    auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + struct.pack(">I", 1)
    expect = {"expected_challenge": challenge, "rp_id": rp_id, "origins": [origin], "require_uv": True, "stored_sign_count": 0}
    base = '"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false' % (base64_url(challenge), origin)

    def assertion(client_text):
        cd = client_text.encode()
        sig = key.sign(auth_data + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"authenticator_data": auth_data, "client_data_json": cd, "signature": sig, "public_key": jwk}

    assert W.verify_assertion(assertion("{%s}" % base), expect)["ok"] is True
    assert W.verify_assertion(assertion('{%s,"origin":"https://evil.example"}' % base), expect) == {"ok": False, "reason": "clientDataJSON is not valid JSON"}
    assert W.verify_assertion(assertion('{%s,"x":8.0,"y":1e3}' % base), expect)["ok"] is True  # number spellings stay accepted


def test_an_eat_with_a_duplicate_header_or_payload_member_is_refused_by_the_canonical_gate():
    pytest.importorskip("cryptography")
    from atlas_pca import attest_eat as E
    sig = base64_url(bytes([1]) * 64)

    def eat(header, payload):
        return "%s.%s.%s" % (_b64u(header), _b64u(payload), sig)

    with pytest.raises(ValueError, match=r"EAT invalid: non-canonical compact JWS: bad-json \(duplicate key"):
        E.verify_eat(eat('{"alg":"EdDSA","alg":"none","typ":"eat+jwt"}', '{"iss":"a","iat":1}'), b"\x00" * 32)
    with pytest.raises(ValueError, match=r"EAT invalid: non-canonical compact JWS: bad-json \(duplicate key"):
        E.verify_eat(eat('{"alg":"EdDSA","typ":"eat+jwt"}', '{"iss":"a","iss":"b","iat":1}'), b"\x00" * 32)


# ---- vendor attestation parsers: the duplicate check only, numbers as written, the 16 MiB bound ---------------------------------

@pytest.mark.parametrize("parse", ["parse_maa_jwt", "parse_gcp_cs_jwt"])
def test_vendor_jwt_segments_read_number_spellings_as_written_and_any_size_to_the_cap(parse):
    from atlas_pca import attest_vendors as V
    f = getattr(V, parse)
    got = f("%s.%s.c2ln" % (_HEADER, _b64u('{"a":8.0,"b":1e3,"c":-0,"d":1E+2}')))["payload"]
    assert got["a"] == 8 and got["b"] == 1000 and got["d"] == 100
    assert str(got["c"]) == "-0.0"  # an integer literal -0 is JS -0, so a claim check that refuses -0 still sees it
    big = '{"a":1,"pad":"%s"}' % ("x" * (2 << 20))  # over the old 1 MiB strict cap
    assert f("%s.%s.c2ln" % (_HEADER, _b64u(big)))["payload"]["a"] == 1


def test_signed_collateral_reads_number_spellings_and_a_large_body_but_not_a_duplicate():
    from atlas_pca import attest_intel as I
    from test_base_kill_attest_intel import _signed
    from test_base_kill_intel import _keys
    k = _keys()[0]
    for raw in ('{"a":8.0,"b":1e3,"c":-0}', '{"pad":"%s"}' % ("x" * (2 << 20))):
        assert "body" in I._verify_signed_json(_signed(raw, k), "tcbInfo", k.public_key())
    assert I._verify_signed_json(_signed('{"a":1,"a":2}', k), "tcbInfo", k.public_key()) == {"error": "tcbInfo document is not valid JSON"}


def test_azure_runtime_data_refuses_a_duplicate_and_reads_numbers_as_written():
    import hashlib
    from atlas_pca.attest_amd import check_azure_runtime_data_binding as chk
    for rd, want in ((b'{"user-data":"%s","user-data":"%s"}' % (b"ab" * 64, b"ab" * 64), "runtime data is not valid JSON"),
                     (b'{"n":8.0,"m":1e3}', "runtime data carries no 64-byte hex user-data"), (b"nope", "runtime data is not valid JSON")):
        assert chk(hashlib.sha256(rd).digest() + bytes(32), rd, {}) == want


def test_maa_key_set_refuses_a_duplicate_member_but_reads_number_spellings():
    from atlas_pca import attest_maa_keys as K
    issuer = "https://x.example"

    def go(body):
        return K.fetch_maa_certs(issuer, {"fetch": lambda url, o: {"status": 200, "url": url, "headers": {}, "body": body}})

    assert go(b'{"keys":[],"n":8.0,"m":1e3}') == {"keys": []}
    for body in (b'{"keys":[],"keys":[]}', b"nope"):
        with pytest.raises(RuntimeError, match="MAA certs response is not valid UTF-8 JSON"):
            go(body)
