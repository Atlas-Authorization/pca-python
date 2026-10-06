"""Ed25519 verification. Uses `cryptography` when installed, else a pure-Python RFC 8032 verifier."""
import hashlib

try:  # pragma: no cover - depends on environment
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False

    BACKEND = "cryptography"
except ImportError:  # pure-Python fallback (RFC 8032 section 6)
    BACKEND = "pure-python"
    _p = 2**255 - 19
    _q = 2**252 + 27742317777372353535851937790883648493
    _d = -121665 * pow(121666, _p - 2, _p) % _p
    _I = pow(2, (_p - 1) // 4, _p)

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
    _G = (_recover_x(_gy, 0), _gy, 1, _recover_x(_gy, 0) * _gy % _p)

    def _add(P, Q):
        A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
        B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
        C = 2 * P[3] * Q[3] * _d % _p
        D = 2 * P[2] * Q[2] % _p
        E, F, G, H = B - A, D - C, D + C, B + A
        return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)

    def _mul(s, P):
        Q = (0, 1, 1, 0)
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

    def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
        if len(pub) != 32 or len(sig) != 64:
            return False
        A = _decode(pub)
        R = _decode(sig[:32])
        if A is None or R is None:
            return False
        s = int.from_bytes(sig[32:], "little")
        if s >= _q:
            return False
        h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _q
        return _eq(_mul(s, _G), _add(R, _mul(h, A)))
