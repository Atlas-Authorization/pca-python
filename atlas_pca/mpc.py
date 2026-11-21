"""Secure multi-party composition of stakeholder decisions (the TypeScript reference, @atlasauth/pca-mpc), deterministic layer and the SPDZ
malicious-with-abort online phase (see mpc_spdz): additive sharing over F_p (p = 2^61 - 1), Beaver multiplication, thermometer encoding, the
cleartext and simulated-MPC compositions. Pure integer arithmetic (not constant time); every random draw comes from an explicit FieldRng seed
(tests) or the CSPRNG-backed SecureFieldRng (the default for protocol randomness). The OT-based offline phase is in mpc_mascot.

The namespaces mirror the reference: ``Field``, ``Sharing``, ``Gf128``, ``Enc``, ``Beaver``, ``Thermometer``, ``Party``, ``Compose``, ``Runner``.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass, field
from typing import Any, List, Optional

PRIME = (1 << 61) - 1
MASK64 = (1 << 64) - 1
LIMIT = (1 << 64) - 8  # the largest multiple of p that fits in 64 bits; anything at or above it is rejected so `% p` is uniform


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


class Field:
    """F_p, p = 2^61 - 1."""

    PRIME = PRIME
    MASK64 = MASK64
    LIMIT = LIMIT

    @staticmethod
    def mod(x: int) -> int:
        return x % PRIME

    @staticmethod
    def fadd(a: int, b: int) -> int:
        return (a + b) % PRIME

    @staticmethod
    def fsub(a: int, b: int) -> int:
        return (a - b) % PRIME

    @staticmethod
    def fmul(a: int, b: int) -> int:
        if not isinstance(a, int) or not isinstance(b, int):  # int * str / list repeats the operand (a huge allocation), never a field product
            raise TypeError("field elements must be integers")
        return (a * b) % PRIME

    @staticmethod
    def fneg(a: int) -> int:
        return (-a) % PRIME

    class FieldRng:
        """Deterministic SplitMix64 drawing unbiased field elements by rejection sampling."""

        def __init__(self, seed: int = 0x243F6A8885A308D3):
            self._s = seed & MASK64

        def next_u64(self) -> int:
            self._s = (self._s + 0x9E3779B97F4A7C15) & MASK64
            z = self._s
            z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
            z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
            return z ^ (z >> 31)

        def next(self) -> int:
            while True:
                u = self.next_u64()
                if u < LIMIT:
                    return u % PRIME

    class SecureFieldRng(FieldRng):
        """CSPRNG-backed field source: fresh random bytes, rejection sampled."""

        def __init__(self):
            super().__init__(0)

        def next_u64(self) -> int:
            return int.from_bytes(secrets.token_bytes(8), "big")

    @staticmethod
    def field_random(test_seed: Optional[int] = None):
        """CSPRNG by default, a reproducible seeded FieldRng only when test_seed is not None."""
        return Field.SecureFieldRng() if test_seed is None else Field.FieldRng(test_seed)


FieldRng = Field.FieldRng
SecureFieldRng = Field.SecureFieldRng


class Sharing:
    """Additive sharing over F_p."""

    MAX_PARTIES = 1024  # bounds allocation

    @staticmethod
    def check_n(n: Any, who: str) -> None:
        if not _is_int(n) or n < 1 or n > Sharing.MAX_PARTIES:
            raise ValueError("%s: n must be an integer in [1, %d]" % (who, Sharing.MAX_PARTIES))

    @staticmethod
    def share(secret: int, n: int, rng) -> List[int]:
        Sharing.check_n(n, "share")
        out = [rng.next() for _ in range(n - 1)]
        acc = 0
        for s in out:
            acc = Field.fadd(acc, s)
        out.append(Field.fadd(Field.mod(secret), Field.fneg(acc)))
        return out

    @staticmethod
    def reconstruct(shares) -> int:
        if len(shares) == 0:
            raise ValueError("reconstruct: no shares (fail closed)")
        acc = 0
        for s in shares:
            if s is None:
                raise ValueError("reconstruct: missing share (fail closed)")
            acc = Field.fadd(acc, s)
        return acc

    @staticmethod
    def share_constant(c: int, n: int) -> List[int]:
        Sharing.check_n(n, "shareConstant")
        out = [0] * n
        out[0] = Field.mod(c)
        return out

    @staticmethod
    def same(x, y) -> None:
        if len(x) != len(y):
            raise ValueError("shared values must have the same party count")

    @staticmethod
    def add_sv(x, y) -> List[int]:
        Sharing.same(x, y)
        return [Field.fadd(a, b) for a, b in zip(x, y)]

    @staticmethod
    def sub_sv(x, y) -> List[int]:
        Sharing.same(x, y)
        return [Field.fadd(a, Field.fneg(b)) for a, b in zip(x, y)]

    @staticmethod
    def neg_sv(x) -> List[int]:
        return [Field.fneg(a) for a in x]

    @staticmethod
    def scale_sv(x, c: int) -> List[int]:
        return [Field.fmul(a, c) for a in x]

    @staticmethod
    def add_public_sv(x, c: int) -> List[int]:
        o = list(x)
        o[0] = Field.fadd(o[0], Field.mod(c))
        return o

    @staticmethod
    def not_bit_sv(b) -> List[int]:
        return Sharing.add_public_sv(Sharing.neg_sv(b), 1)


class Gf128:
    """GF(2^128) with the reduction polynomial x^128 + x^7 + x^2 + x + 1: the field of the KOS correlation check. Elements are 128-bit
    non-negative integers (bit i = coefficient of x^i); addition is XOR. Not constant time."""

    MASK = (1 << 128) - 1
    RED = 0x87

    @staticmethod
    def add(a: int, b: int) -> int:
        return (a ^ b) & Gf128.MASK

    @staticmethod
    def mul_x(v: int) -> int:
        r = (v << 1) & Gf128.MASK
        return r ^ Gf128.RED if (v >> 127) & 1 == 1 else r

    @staticmethod
    def mul_by_xi(v: int, i: int) -> int:
        r = v & Gf128.MASK
        for _ in range(i):
            r = Gf128.mul_x(r)
        return r

    @staticmethod
    def mul(a: int, b: int) -> int:
        res = 0
        v = a & Gf128.MASK
        for i in range(128):
            if (b >> i) & 1 == 1:
                res ^= v
            v = Gf128.mul_x(v)
        return res & Gf128.MASK


@dataclass
class EncShare:
    value: int
    bits: List[int]


class Enc:
    """Privacy-amplified OT choice-bit encoding (the selective-failure remedy): the receiver chooses with m = 61 + 3s uniform bits b and takes
    x = sum g_k b_k (mod p) for a public gadget vector g. s = 0 is the legacy plain binary encoding."""

    FIELD_BITS = 61
    STAT_SEC = 64
    MIN_STAT_SEC = 40
    EncShare = EncShare

    @staticmethod
    def enc_bits(s: int) -> int:
        return Enc.FIELD_BITS + 3 * s

    @staticmethod
    def make_gadget(s: int, rng, unsafe: bool = False) -> List[int]:
        if not _is_int(s) or s < 0 or s > 64:
            raise ValueError("statSec must be an integer in [0, 64]")
        if s < Enc.MIN_STAT_SEC and not unsafe:
            raise ValueError("statSec %d is below %d: refused (tests may pass the explicit unsafe flag)" % (s, Enc.MIN_STAT_SEC))
        return [Field.mod(1 << k) if s == 0 else rng.next() for k in range(Enc.enc_bits(s))]

    @staticmethod
    def enc_value(g, bits) -> int:
        if len(g) != len(bits):
            raise ValueError("encValue: gadget / bits length mismatch")
        return Field.mod(sum(g[k] for k in range(len(g)) if bits[k] == 1))

    @staticmethod
    def plain_share(x: int) -> EncShare:
        v = Field.mod(x)
        return EncShare(v, [(v >> k) & 1 for k in range(Enc.FIELD_BITS)])

    @staticmethod
    def plain_gadget() -> List[int]:
        return [Field.mod(1 << k) for k in range(Enc.FIELD_BITS)]

    @staticmethod
    def random_bits(m: int, rng) -> List[int]:
        """m uniform bits from a field source (the 60 low bits of each draw are uniform)."""
        out: List[int] = []
        while len(out) < m:
            w = rng.next()
            for i in range(60):
                if len(out) < m:
                    out.append((w >> i) & 1)
        return out

    @staticmethod
    def sample_enc(g, rng) -> EncShare:
        bits = Enc.random_bits(len(g), rng)
        return EncShare(Enc.enc_value(g, bits), bits)


@dataclass
class Triple:
    a: List[int]
    b: List[int]
    c: List[int]


@dataclass
class OpenedMsg:
    label: str  # "d" or "e"
    value: int
    shares: List[int]


class Beaver:
    """Secure multiplication of two additively-shared values with Beaver triples (a trusted dealer supplies the triples)."""

    Triple = Triple
    OpenedMsg = OpenedMsg

    @staticmethod
    def gen_triples(count: int, n: int, rng) -> List[Triple]:
        return [Beaver.gen_triple(n, rng) for _ in range(count)]

    @staticmethod
    def gen_triple(n: int, rng) -> Triple:
        a = rng.next()
        b = rng.next()
        c = Field.fmul(a, b)
        return Triple(Sharing.share(a, n, rng), Sharing.share(b, n, rng), Sharing.share(c, n, rng))

    @staticmethod
    def beaver_mul(x, y, triple: Triple, transcript: Optional[list] = None) -> List[int]:
        """x*y consuming triple; every opened value is appended to transcript when not None."""
        if len(x) != len(y):
            raise ValueError("beaverMul: operand party counts differ")
        for part in (triple.a, triple.b, triple.c):
            if part is None or len(part) != len(x):
                raise ValueError("beaverMul: triple party count differs from the operands")
        d_shares = Sharing.sub_sv(x, triple.a)
        e_shares = Sharing.sub_sv(y, triple.b)
        d = Sharing.reconstruct(d_shares)
        e = Sharing.reconstruct(e_shares)
        if transcript is not None:
            transcript.append(OpenedMsg("d", d, d_shares))
            transcript.append(OpenedMsg("e", e, e_shares))
        de = Field.fmul(d, e)
        out = []
        for i in range(len(x)):
            zi = Field.fadd(triple.c[i], Field.fadd(Field.fmul(d, triple.b[i]), Field.fmul(e, triple.a[i])))
            out.append(Field.fadd(zi, de) if i == 0 else zi)
        return out


class Thermometer:
    """Thermometer (unary) encoding of a bounded integer: ge[k] = [v >= k] for k = 1..M, so MAX is a position-wise OR."""

    @staticmethod
    def thermometer_encode(v, m: int) -> List[int]:
        """Encodes v in {0..M}; v is clamped into range (fail safe). v is a JS number: NaN encodes all zero, infinities clamp."""
        if not _is_int(m) or m < 0:
            raise ValueError("thermometerEncode: M must be a non-negative integer")
        if isinstance(v, float) and v != v:
            return [0] * m
        tr = v if isinstance(v, float) and math.isinf(v) else math.trunc(v)
        clamped = max(0, min(m, tr))
        return [1 if clamped >= k + 1 else 0 for k in range(m)]

    @staticmethod
    def thermometer_decode(bits) -> int:
        """Number of 1s (robust to non-monotone input)."""
        return sum(1 for b in bits if b == 1)


@dataclass
class DecisionVector:
    """Per-stakeholder decision vector: allow in {0,1}, t in {1,2,3}, r_quant in {0..Q}."""

    allow: Any
    t: Any
    r_quant: Any


@dataclass
class ComposedDecision:
    allow: int
    t: int
    r_quant: int


class Party:
    DEFAULT_Q = 100

    @staticmethod
    def quantize_r(r: float, q: int = 100) -> int:
        """Quantizes r in [0,1] to {0..Q}; non-finite is the worst case (Q)."""
        if isinstance(r, float) and (r != r or math.isinf(r)):
            return q
        v = max(0, min(1, r)) * q
        return max(0, min(q, math.floor(v + 0.5)))  # JS Math.round: floor(x + 0.5)


class Compose:
    """Composition semantics (the "meet" of stakeholder authorities): allow = AND, t = MAX, r_quant = MAX. Composition can only tighten."""

    @staticmethod
    def assert_decision_vectors(vectors, q: int) -> None:
        """Rejects a malformed decision vector (allow in {0,1}, t in {1,2,3}, integer r_quant in [0,Q])."""
        if not isinstance(vectors, list):
            raise ValueError("decision vectors must be an array")
        for i, v in enumerate(vectors):
            if v is None:
                raise ValueError("party %d: decision vector must be an object" % i)
            if not (_is_int(v.allow) and v.allow in (0, 1)):
                raise ValueError("party %d: allow must be 0 or 1" % i)
            if not (_is_int(v.t) and v.t in (1, 2, 3)):
                raise ValueError("party %d: t must be 1, 2 or 3" % i)
            if not (_is_int(v.r_quant) and 0 <= v.r_quant <= q):
                raise ValueError("party %d: rQuant must be an integer in [0, %s]" % (i, q))

    @staticmethod
    def compose_clear(vectors, q: int = 100) -> ComposedDecision:
        if len(vectors) == 0:
            raise ValueError("composeClear: no parties (fail closed)")
        Compose.assert_decision_vectors(vectors, q)
        return ComposedDecision(0 if any(v.allow == 0 for v in vectors) else 1, max([1] + [v.t for v in vectors]),
                                max([0] + [v.r_quant for v in vectors]))


@dataclass
class SharingRecord:
    label: str
    party: int
    secret: int
    shares: List[int]  # the full additive sharing of one party's secret bit (test inspection)


@dataclass
class PartyView:
    party: int
    held_shares: List[int]
    opened: list
    output: ComposedDecision


@dataclass
class MpcResult:
    composed: ComposedDecision
    parties: int
    q: int
    opened: list
    sharings: List[SharingRecord]
    views: List[PartyView]
    multiplications: int


class Runner:
    """The simulated multi-party runner: all N parties in one process, exchanging shares and Beaver openings through inspectable structures.
    compose_secure computes exactly Compose.compose_clear under MPC."""

    T_M = 3
    SharingRecord = SharingRecord
    PartyView = PartyView
    MpcResult = MpcResult

    @staticmethod
    def compose_secure(vectors, q_opt: Optional[int] = None, seed: Optional[int] = None) -> MpcResult:
        """Composes under MPC. seed None means CSPRNG sharing randomness; a seed is for reproducible tests only."""
        n = len(vectors)
        if n == 0:
            raise ValueError("composeSecure: no parties (fail closed)")
        q = Party.DEFAULT_Q if q_opt is None else q_opt
        Compose.assert_decision_vectors(vectors, q)
        rng = Field.SecureFieldRng() if seed is None else Field.FieldRng(seed)
        opened: list = []
        sharings: List[SharingRecord] = []
        mults = [0]

        def share_bit(bit, label, party):
            s = Sharing.share(bit, n, rng)
            sharings.append(SharingRecord(label, party, bit, list(s)))
            return s

        def and_all(bits):
            if not bits:
                return Sharing.share_constant(1, n)
            acc = bits[0]
            for b in bits[1:]:
                mults[0] += 1
                acc = Beaver.beaver_mul(acc, b, Beaver.gen_triple(n, rng), opened)
            return acc

        def or_all(bits):
            if not bits:
                return Sharing.share_constant(0, n)
            prod = Sharing.not_bit_sv(bits[0])
            for b in bits[1:]:
                mults[0] += 1
                prod = Beaver.beaver_mul(prod, Sharing.not_bit_sv(b), Beaver.gen_triple(n, rng), opened)
            return Sharing.not_bit_sv(prod)

        allow = 1 if Sharing.reconstruct(and_all([share_bit(vectors[p].allow, "p%d.allow" % p, p) for p in range(n)])) == 1 else 0
        t_therm = [Thermometer.thermometer_encode(v.t, Runner.T_M) for v in vectors]
        t_ge = []
        for k in range(Runner.T_M):
            sv = or_all([share_bit(t_therm[p][k], "p%d.t.ge%d" % (p, k + 1), p) for p in range(n)])
            t_ge.append(1 if Sharing.reconstruct(sv) == 1 else 0)
        t = min(3, max(1, Thermometer.thermometer_decode(t_ge)))
        r_therm = [Thermometer.thermometer_encode(v.r_quant, q) for v in vectors]
        r_ge = []
        for k in range(q):
            sv = or_all([share_bit(r_therm[p][k], "p%d.r.ge%d" % (p, k + 1), p) for p in range(n)])
            r_ge.append(1 if Sharing.reconstruct(sv) == 1 else 0)
        composed = ComposedDecision(allow, t, Thermometer.thermometer_decode(r_ge))
        views = [PartyView(p, [s.shares[p] for s in sharings], opened, composed) for p in range(n)]
        return MpcResult(composed, n, q, opened, sharings, views, mults[0])


gf128_add = Gf128.add
gf128_mul_x = Gf128.mul_x
gf128_mul_by_xi = Gf128.mul_by_xi


def evaluate_party(policy: dict, q: int = Party.DEFAULT_Q) -> DecisionVector:
    """Evaluate a party's own policy to its decision vector through the policy VM (:func:`atlas_pca.policy_vm.decide`). `policy` is
    ``{"decideInput": <decide input>}``. Pure and total; the vector is the party's PRIVATE input to the composition."""
    from .policy_vm import decide
    d = decide(policy["decideInput"])
    return DecisionVector(1 if d["releaseGuardianShare"] else 0, d["requiredThreshold"]["t"], Party.quantize_r(d["r"], q))
