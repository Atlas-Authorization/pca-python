"""Ed25519 verify runs the cheap group equation first and the small-order / torsion checks only when it holds (a forged signature
never pays for them); every gate must still pass for an accept."""
import os

from atlas_pca import ed25519 as E


class _FixedHash:
    class _D:
        def digest(self):
            return (1).to_bytes(64, "little")

    @classmethod
    def sha512(cls, *_a):
        return cls._D()


def _counting(monkeypatch):
    calls = []
    real = E._acceptable_point
    monkeypatch.setattr(E, "_acceptable_point", lambda P: calls.append(P) or real(P))
    return calls


def test_a_forged_signature_never_reaches_the_torsion_checks(monkeypatch):
    calls = _counting(monkeypatch)
    pub = E.public_key(bytes(range(32)))
    for _ in range(5):
        forged = E._encode(E._mul(7, E._G)) + (12345).to_bytes(32, "little")
        assert E.verify(pub, b"m", forged) is False
        assert E.verify(pub, b"m", os.urandom(64)) is False
    assert calls == []


def test_a_valid_signature_passes_both_gates(monkeypatch):
    calls = _counting(monkeypatch)
    seed = bytes(range(32))
    sig = E.sign(seed, b"m")
    assert E.verify(E.public_key(seed), b"m", sig) is True
    assert len(calls) == 2  # A and R


def test_a_small_order_r_that_satisfies_the_equation_is_still_refused(monkeypatch):
    monkeypatch.setattr(E, "hashlib", _FixedHash)  # h = 1
    pub = E._encode(E._G)  # A = B
    r_ident = E._encode(E._ID)  # R = identity: small order
    sig = r_ident + (1).to_bytes(32, "little")  # [1]B == R + [1]A
    assert E._eq(E._mul(1, E._G), E._add(E._decode(r_ident), E._mul(1, E._decode(pub))))  # the equation holds
    assert E._is_small_order(E._decode(r_ident))
    assert E.verify(pub, b"m", sig) is False


def test_an_undecodable_point_is_refused():
    pub = E.public_key(bytes(range(32)))
    assert E.verify(pub, b"m", bytes([0xFF] * 32) + bytes(32)) is False  # R is not a curve point
    assert E.verify(bytes([0xFF] * 32), b"m", E.sign(bytes(range(32)), b"m")) is False  # A is not a curve point
