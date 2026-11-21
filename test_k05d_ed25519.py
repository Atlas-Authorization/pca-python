"""verify() refuses S == q (the group order): RFC 8032 section 5.1.7 requires S < q.

At S == q the scalar multiplication [S]B is the identity, so the group equation reduces to R + [h]A == identity, with h =
H(R || A || M). With a real hash that needs a hash fixed point, but the comparison `s >= q` can be tested directly: the digest is
pinned to a constant, R is chosen as -[h]A, and the equation then holds exactly. Only the S >= q guard rejects the signature."""
import pytest

from atlas_pca import ed25519 as E


class _FixedHash:
    """hashlib stand-in: every sha512 digest is the 64-byte little-endian encoding of 1, so h = 1 for any input."""

    class _D:
        def digest(self):
            return (1).to_bytes(64, "little")

    @classmethod
    def sha512(cls, *_a):
        return cls._D()


def _neg(P):
    return ((-P[0]) % E._p, P[1], 1, (-P[3]) % E._p)


@pytest.fixture
def forged(monkeypatch):
    pub = E.public_key(bytes(range(32)))
    A = E._decode(pub)
    R = _neg(A)  # R + [1]A is the identity, and [q]B is the identity too
    sig_r = E._encode(R)
    assert E._acceptable_point(A) and E._acceptable_point(E._decode(sig_r))
    assert E._eq(E._mul(E._q, E._G), E._ID) and E._eq(E._add(E._decode(sig_r), E._mul(1, A)), E._ID)  # the equation holds at S == q
    monkeypatch.setattr(E, "hashlib", _FixedHash)
    return pub, sig_r


def test_s_equal_to_the_group_order_is_refused(forged):
    pub, sig_r = forged
    assert E.verify(pub, b"m", sig_r + E._q.to_bytes(32, "little")) is False


def test_s_just_below_the_group_order_reaches_the_equation(forged):
    pub, sig_r = forged
    # S = q - 1 passes the range guard and fails the equation ([q-1]B = -B, and R + A is the identity), a different path than the refusal above
    assert E.verify(pub, b"m", sig_r + (E._q - 1).to_bytes(32, "little")) is False
