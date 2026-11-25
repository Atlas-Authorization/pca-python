"""HKDF-SHA256 (RFC 5869) over the standard library's HMAC: the extract and expand steps are one HMAC call and one short loop."""
import hashlib
import hmac
from typing import Optional

MAX_OUTPUT = 255 * 32


def hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    """`length` bytes (1..8160) of HKDF-SHA256; a missing or empty salt is HashLen zero bytes (RFC 5869 2.2)."""
    if not isinstance(length, int) or isinstance(length, bool) or length < 1 or length > MAX_OUTPUT:
        raise ValueError("hkdf: length must be an integer in 1..%d" % MAX_OUTPUT)
    prk = hmac.new(bytes(salt) if salt else bytes(32), bytes(ikm), hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + bytes(info) + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]
