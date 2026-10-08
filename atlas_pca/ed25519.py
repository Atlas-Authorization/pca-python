"""Strict Ed25519 verification (RFC 8032 + PCA v2 hardening), pure Python.

Rejects: wrong lengths, non-canonical point encodings (y >= p, x=0 with sign bit), non-canonical S (S >= L),
small-order and mixed-order (torsion) public keys AND R values. Deliberately does NOT delegate to a general
library verifier, which may be permissive (accepting e.g. R=identity,S=0 under an identity key).
"""
import hashlib

_p = 2**255 - 19
_q = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)
_ID = (0, 1, 1, 0)


def _inv(x):
    return pow(x, _p - 2, _p)


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _I % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s, P):
    Q = _ID
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _eq(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _decode(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _is_small_order(P):
    return _eq(_mul(8, P), _ID)


def _is_torsion_free(P):
    return _eq(_mul(_q, P), _ID)


def _acceptable_point(P):
    return P is not None and not _is_small_order(P) and _is_torsion_free(P)


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        if len(pub) != 32 or len(sig) != 64:
            return False
        s = int.from_bytes(sig[32:], "little")
        if s >= _q:
            return False
        A = _decode(pub)
        R = _decode(sig[:32])
        if not (_acceptable_point(A) and _acceptable_point(R)):
            return False
        h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _q
        return _eq(_mul(s, _G), _add(R, _mul(h, A)))
    except Exception:
        return False


BACKEND = "pure-python-strict"
