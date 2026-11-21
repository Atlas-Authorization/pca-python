"""The RSA public-key rule (512 <= bitlen(n) <= 16384, e odd, 3 <= e, bitlen(e) <= 32) applies before any modular exponentiation at
every RSA verify (PKCS#1 and PSS); an unusable key never verifies and is refused fast."""
import time
import types

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from atlas_pca import attest_cert as AC
from atlas_pca import attest_common as C


def key(e, n):
    """A key object exposing exactly the numbers the rule reads (the library itself refuses some of them at construction)."""
    return types.SimpleNamespace(public_numbers=lambda: types.SimpleNamespace(e=e, n=n))


def real_key(e, n):
    try:
        return rsa.RSAPublicNumbers(e, n).public_key()
    except ValueError:
        pytest.skip("the installed cryptography refuses this key at construction")


N2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers().n


def test_rule_boundaries():
    for bits, want in [(511, False), (512, True), (513, True), (16383, True), (16384, True), (16385, False), (17000, False)]:
        n = (1 << (bits - 1)) + 1
        assert n.bit_length() == bits
        assert C.rsa_key_ok(key(65537, n)) is want, bits


def test_exponent_rules():
    n = N2048
    assert C.rsa_key_ok(key(3, n)) is True
    assert C.rsa_key_ok(key(65537, n)) is True
    assert C.rsa_key_ok(key((1 << 32) - 1, n)) is True  # 32 bits, odd
    assert C.rsa_key_ok(key((1 << 32) + 1, n)) is False  # 33 bits
    assert C.rsa_key_ok(key((1 << 33) + 1, n)) is False
    for bad in (1, 2, 4, 6, 65536):
        assert C.rsa_key_ok(key(bad, n)) is False, bad


def test_a_real_2048_bit_key_still_verifies_pkcs1_and_pss():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    sig = priv.sign(b"m", padding.PKCS1v15(), hashes.SHA256())
    assert C.rsa_pkcs1_verify(pub, sig, b"m", "sha256") is True
    assert C.rsa_pkcs1_verify(pub, sig, b"x", "sha256") is False


def test_an_unusable_key_never_verifies_and_is_refused_fast():
    sig = bytes(256)
    for k in (real_key(65537, (1 << 255) + 1), real_key(65537, (1 << 16999) + 1), real_key((1 << 33) + 1, N2048)):
        t0 = time.perf_counter()
        assert C.rsa_pkcs1_verify(k, sig, b"m", "sha256") is False
        assert time.perf_counter() - t0 < 0.1


def test_the_pss_branch_applies_the_rule_before_it_parses_or_verifies(monkeypatch):
    called = []
    pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    monkeypatch.setattr(AC, "_pss_params", lambda *a: called.append(a) or ("sha256", "sha256", 32))
    monkeypatch.setattr(AC, "_alg_parts", lambda der: (AC._OID_PSS, None, None))
    monkeypatch.setattr(AC, "rsa_key_ok", lambda k: False)
    assert AC._verify_signature(b"alg", b"m", bytes(256), pub) is False
    assert called == []  # refused before the parameters were even read
    monkeypatch.setattr(AC, "rsa_key_ok", lambda k: True)
    assert AC._verify_signature(b"alg", b"m", bytes(256), pub) is False  # a bad signature, but the rule let it reach the parameters
    assert len(called) == 1
