"""An RSASSA-PSS issuer key WITH parameters restricts what it may sign (OpenSSL: `digest not allowed`): the signature's hash and
MGF1 hash must equal the key's and its salt length must be at least the key's. A key without parameters is unrestricted."""
import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from atlas_pca import attest_cert as AC
from atlas_pca import attest_common as C

PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PKCS1 = PRIV.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)

HASHES = {"sha1": (hashes.SHA1, "1.3.14.3.2.26"), "sha256": (hashes.SHA256, "2.16.840.1.101.3.4.2.1"), "sha384": (hashes.SHA384, "2.16.840.1.101.3.4.2.2")}
OID_PSS, OID_MGF1 = "1.2.840.113549.1.1.10", "1.2.840.113549.1.1.8"


def tlv(tag, c=b""):
    n = len(c)
    h = bytes([tag, n]) if n < 0x80 else bytes([tag, 0x81, n]) if n < 0x100 else bytes([tag, 0x82, n >> 8, n & 255])
    return h + bytes(c)


def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    out = bytearray([a[0] * 40 + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(chunk))
    return tlv(6, out)


def hash_id(name):
    return tlv(0x30, oid(HASHES[name][1]) + tlv(5))


def pss_params(h=None, mgf=None, salt=None):
    body = b""
    if h:
        body += tlv(0xA0, hash_id(h))
    if mgf:
        body += tlv(0xA1, tlv(0x30, oid(OID_MGF1) + hash_id(mgf)))
    if salt is not None:
        body += tlv(0xA2, tlv(2, salt.to_bytes(2, "big").lstrip(b"\x00") or b"\x00"))
    return tlv(0x30, body)


def pss_alg(h=None, mgf=None, salt=None):
    return tlv(0x30, oid(OID_PSS) + pss_params(h, mgf, salt))


def key_with(alg_der):
    spki = tlv(0x30, alg_der + tlv(3, b"\x00" + PKCS1))
    return C.load_public_key(spki)


def sign(h, mgf, salt, msg=b"m"):
    return PRIV.sign(msg, padding.PSS(mgf=padding.MGF1(HASHES[mgf][0]()), salt_length=salt), HASHES[h][0]())


def check(key, h, mgf, salt):
    return AC._verify_signature(pss_alg(h, mgf, salt), b"m", sign(h, mgf, salt), key)


RESTRICTED = lambda: key_with(pss_alg("sha384", "sha384", 48))  # noqa: E731


def test_the_exact_restriction_verifies():
    assert check(RESTRICTED(), "sha384", "sha384", 48) is True


def test_a_longer_salt_is_allowed_and_a_shorter_one_is_not():
    assert check(RESTRICTED(), "sha384", "sha384", 64) is True
    assert check(RESTRICTED(), "sha384", "sha384", 47) is False
    assert check(RESTRICTED(), "sha384", "sha384", 20) is False


def test_another_hash_is_refused():
    assert check(RESTRICTED(), "sha256", "sha256", 48) is False
    assert check(RESTRICTED(), "sha256", "sha384", 48) is False


def test_another_mgf1_hash_is_refused():
    assert check(RESTRICTED(), "sha384", "sha256", 48) is False


def test_a_key_without_parameters_is_unrestricted():
    key = key_with(tlv(0x30, oid(OID_PSS)))
    assert check(key, "sha256", "sha256", 32) is True
    assert check(key, "sha384", "sha1", 0) is True


def test_a_plain_rsa_key_is_unrestricted():
    spki = tlv(0x30, tlv(0x30, oid("1.2.840.113549.1.1.1") + tlv(5)) + tlv(3, b"\x00" + PKCS1))
    assert check(C.load_public_key(spki), "sha256", "sha256", 32) is True


def test_empty_parameters_mean_the_defaults_sha1_mgf1_sha1_salt_20():
    key = key_with(pss_alg())
    assert check(key, "sha1", "sha1", 20) is True
    assert check(key, "sha1", "sha1", 30) is True
    assert check(key, "sha1", "sha1", 10) is False
    assert check(key, "sha256", "sha1", 20) is False
    assert check(key, "sha1", "sha256", 20) is False


def test_each_parameter_defaults_independently():
    key = key_with(pss_alg(h="sha256"))  # mgf1 sha1, salt 20 by default
    assert check(key, "sha256", "sha1", 20) is True
    assert check(key, "sha256", "sha256", 20) is False
