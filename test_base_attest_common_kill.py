"""Exact pins of the attest_common helpers (JavaScript Number / BigInt / JSON.parse emulation, PEM, EC points, P1363
ECDSA, JWS parsing) that the vendor verifiers build their reasons from: each assertion kills a mutmut survivor of the
0.5 full baseline."""
import json
import math

import pytest

from atlas_pca import attest_common as C


def test_js_number_radix_and_infinity():
    assert C.js_number("0xaB") == 171.0 and C.js_number("0XAB") == 171.0
    assert C.js_number("0o17") == 15.0 and C.js_number("0O17") == 15.0
    assert C.js_number("0b101") == 5.0
    assert C.js_number("Infinity") == math.inf and C.js_number("+Infinity") == math.inf and C.js_number("-Infinity") == -math.inf
    assert math.isnan(C.js_number("0x")) and C.js_number(" 12 ") == 12.0 and C.js_number("") == 0.0


def test_js_str_integer_floats_below_1e21_only():
    assert C.js_str(1e20) == "100000000000000000000" and C.js_str(1e21) == "1e+21" and C.js_str(-3.0) == "-3"
    assert C.js_str(None) == "null" and C.js_str(True) == "true" and C.js_str(1.5) == "1.5"


def test_big_int_every_form():
    assert C.big_int(3.0) == 3 and type(C.big_int(3.0)) is int
    assert C.big_int(" 42 ") == 42 and C.big_int("-7") == -7 and C.big_int("") == 0
    assert C.big_int("0x1f") == 31 and C.big_int("0o17") == 15 and C.big_int("0b101") == 5 and C.big_int(True) == 1
    for v, msg in ((None, "Cannot convert null to a BigInt"), ("1.5", "Cannot convert 1.5 to a BigInt"), (1.5, "Cannot convert 1.5 to a BigInt")):
        with pytest.raises(C.JsError) as e:
            C.big_int(v)
        assert str(e.value) == msg


@pytest.mark.parametrize("text,msg", [
    ("1 2", "Unexpected non-whitespace character after JSON at position 2 (line 1 column 3)"),
    ("1\n 2", "Unexpected non-whitespace character after JSON at position 3 (line 2 column 2)"),
    ("[1]\r\n x", "Unexpected non-whitespace character after JSON at position 6 (line 2 column 2)"),
    ("1\r2", "Unexpected non-whitespace character after JSON at position 2 (line 2 column 1)"),
    ("null 1", "Unexpected non-whitespace character after JSON at position 5 (line 1 column 6)"),
    ("nul", "Unexpected end of JSON input"),
    ('{"a" "b"}', "Unexpected string in JSON at position 5 (line 1 column 6)"),
    ("[1 2]", "Unexpected number in JSON at position 3 (line 1 column 4)"),
    ("", "Unexpected end of JSON input"),
])
def test_js_json_loads_v8_messages(text, msg):
    with pytest.raises(C.JsError) as e:
        C.js_json_loads(text)
    assert str(e.value) == msg


def test_js_json_loads_trailing_comma_on_python_3_13(monkeypatch):
    # python >= 3.13 reports the comma itself; V8 names the token after it (seam: CI runs 3.12, which says "Expecting value")
    def loads(text, **_kw):
        raise json.JSONDecodeError("Illegal trailing comma before end of array", text, 2)
    monkeypatch.setattr(C.json, "loads", loads)
    for text in ("[1,]", "[1,  ]"):
        with pytest.raises(C.JsError) as e:
            C.js_json_loads(text)
        assert str(e.value) == "Unexpected token ']', \"%s\" is not valid JSON" % text


def test_pem_to_der():
    with pytest.raises(ValueError) as e:
        C.pem_to_der("no pem here")
    assert str(e.value) == "pemToDer: no certificate found"
    assert C.pem_to_der("-----BEGIN CERTIFICATE-----\nAQI=\n-----END CERTIFICATE-----") == b"\x01\x02"


def _ec(curve):
    c = C.crypto()
    return c.ec.generate_private_key(curve())


def test_ec_point_and_raw_ecdsa():
    pytest.importorskip("cryptography")
    c = C.crypto()
    k = _ec(c.ec.SECP256R1)
    pub = k.public_key()
    n = pub.public_numbers()
    assert C.ec_point(pub, "P-256") == b"\x04" + n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")
    rsa = c.rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    with pytest.raises(TypeError) as e:
        C.ec_point(rsa, "P-256")
    assert str(e.value) == "public key is not EC (got rsa)"
    with pytest.raises(TypeError) as e:
        C.ec_point(pub, "P-384")
    assert str(e.value) == "public key is not on P-384 (got P-256)"
    der = k.sign(b"data", c.ec.ECDSA(c.hashes.SHA256()))
    r, s = c.utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert C.ecdsa_verify_raw(pub, raw, b"data", "sha256") is True
    assert C.ecdsa_verify_raw(pub, raw[:-1], b"data", "sha256") is False
    assert C.ecdsa_verify_raw(pub, raw + b"\x00", b"data", "sha256") is False
    assert C.ecdsa_verify_raw(pub, raw[:32] + bytes(32), b"data", "sha256") is False
    assert C.ecdsa_verify_raw(pub, bytes(32) + raw[32:], b"data", "sha256") is False
    assert C.ecdsa_verify_raw(rsa, raw, b"data", "sha256") is False


def test_parse_jws_empty_signature_seam(monkeypatch):
    # a non-empty canonical base64url segment never decodes to zero bytes: the check is reached only through this seam
    real = C.decode_canonical_b64url
    monkeypatch.setattr(C, "decode_canonical_b64url", lambda x: b"" if x == "AA" else real(x))
    tok = "%s.%s.AA" % (C.base64.urlsafe_b64encode(b'{"alg":"ES256"}').decode().rstrip("="), C.base64.urlsafe_b64encode(b"{}").decode().rstrip("="))
    with pytest.raises(TypeError) as e:
        C.parse_jws(tok, "maa")
    assert str(e.value) == "maa: empty signature"
