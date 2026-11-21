"""Per-run identity material for the TLS mesh: one P-256 key + self-signed certificate per node, built with the vetted
`cryptography` package (no hand-rolled crypto, no X.509 code of our own). The keys live only on the node that generated them; only
the PUBLIC certificates are exchanged and pinned (reference: packages/pca-mpc/src/net/certs.ts).

generate_identity(cn) draws a fresh random key (valid 2 days: per-run, throw-away). generate_identity(cn, seed=...) derives the key
and the serial from the seed label instead, with a fixed validity window, so tests get the same identity every run (a seed label
only, never key material in a committed file)."""
from __future__ import annotations

import datetime
import hashlib
from typing import NamedTuple, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_SEED_PREFIX = "atlas-pca-conformance/mpc-net/"
_FIXED_NOT_BEFORE = datetime.datetime(2026, 1, 1)
_FIXED_NOT_AFTER = datetime.datetime(2126, 1, 1)


class Identity(NamedTuple):
    key_pem: str
    cert_pem: str


def generate_identity(cn: str, seed: Optional[str] = None) -> Identity:
    if seed is None:
        key = ec.generate_private_key(ec.SECP256R1())
        serial = x509.random_serial_number()
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, tzinfo=None)
        nb, na = now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=2)
    else:
        d = hashlib.sha256((_SEED_PREFIX + seed).encode("utf-8")).digest()
        key = ec.derive_private_key(int.from_bytes(d, "big") % (_P256_ORDER - 1) + 1, ec.SECP256R1())
        serial = int.from_bytes(d[:16], "big") >> 1 | 1  # positive, nonzero
        nb, na = _FIXED_NOT_BEFORE, _FIXED_NOT_AFTER
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return Identity(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii"),
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


def fingerprint_of_der(der: bytes) -> str:
    """SHA-256 fingerprint of a DER certificate, colon-hex upper case (as Node reports it)."""
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, 64, 2))


def fingerprint_of(cert_pem: str) -> str:
    """SHA-256 fingerprint (colon-hex) of a PEM certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    return fingerprint_of_der(cert.public_bytes(serialization.Encoding.DER))


def read_pem(path: str) -> str:
    """The text of a PEM file."""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()
