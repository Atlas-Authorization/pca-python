"""SPDZ-style authenticated secret sharing over F_p: the malicious-with-abort (dishonest-majority) layer of the MPC package. A global MAC key
alpha is additively shared; every authenticated value carries MAC shares summing to alpha*x under MAC_KEYS independent keys; the batched
commit-then-open MAC-check aborts on any deviation, so the result is correct or an abort. The authenticated triples come from a trusted dealer
(the explicit trust assumption) or the OT-based no-dealer offline phase (mpc_mascot); the online phase is the real thing.

Namespaces mirror the reference: ``Spdz`` (functions, ``SpdzEngine``, ``MacCheckAbort``) and ``SpdzRunner.compose_secure_malicious``.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, List, Optional

from .mpc import (ComposedDecision, Compose, Field, Party, Sharing, Thermometer, _is_int)

PRIME = Field.PRIME
MAC_KEYS = 2
MIN_MAC_SOUNDNESS_BITS = 100
SACRIFICE_PARTNERS = 2


class MacCheckAbort(Exception):
    """The MAC-check detected an inconsistent opening/MAC: the protocol ABORTS, no output."""


@dataclass
class MacKey:
    """One global MAC key, additively shared (alpha is for dealer preprocessing and tests only)."""

    alpha_shares: List[int]
    alpha: int


@dataclass
class MacContext:
    """Key 0 is alpha_shares/alpha; extra_keys are further independent keys."""

    n: int
    alpha_shares: List[int]
    alpha: int
    extra_keys: List[MacKey]


@dataclass
class AuthSV:
    """Value shares sum to x, mac shares to alpha*x (key 0), extra_mac[l-1] to extra_keys[l-1].alpha*x."""

    value: List[int]
    mac: List[int]
    extra_mac: List[List[int]]


@dataclass
class AuthTriple:
    a: AuthSV
    b: AuthSV
    c: AuthSV


@dataclass
class TripleWithPartners:
    """A triple to deliver plus its sacrifice partners (every partner shares keep.b)."""

    keep: AuthTriple
    partners: List[AuthTriple]


@dataclass
class DealerFault:
    """TEST-ONLY lying-dealer fault: the dealer authenticates a wrong product. None entries mean no delta."""

    keep_c_delta: Optional[int] = None
    partner_c_delta: Optional[List[Optional[int]]] = None


@dataclass
class Deviation:
    """A party's broadcast deviation in the online phase (models an active cheater); None deltas mean none; mac_key defaults to 0."""

    open_index: int
    party: int
    value_delta: Optional[int] = None
    mac_delta: Optional[int] = None
    mac_key: Optional[int] = None


@dataclass
class OpenedValue:
    """One partial opening as it reaches the MAC-check: the public value and mac_shares[key][party]."""

    value: int
    mac_shares: List[List[int]]
    label: str = ""


def _zip(x, y, op):
    return [op(a, b) for a, b in zip(x, y)]


class Spdz:
    MacKey = MacKey
    MacContext = MacContext
    AuthSV = AuthSV
    AuthTriple = AuthTriple
    TripleWithPartners = TripleWithPartners
    DealerFault = DealerFault
    Deviation = Deviation
    OpenedValue = OpenedValue
    MacCheckAbort = MacCheckAbort
    MAC_KEYS = MAC_KEYS
    MIN_MAC_SOUNDNESS_BITS = MIN_MAC_SOUNDNESS_BITS
    SACRIFICE_PARTNERS = SACRIFICE_PARTNERS
    PRIME = PRIME

    @staticmethod
    def mac_keys(ctx: MacContext) -> List[MacKey]:
        return [MacKey(ctx.alpha_shares, ctx.alpha)] + list(ctx.extra_keys)

    @staticmethod
    def mac_soundness_bits(keys: int, p: int = PRIME) -> float:
        """keys * (log2 p - 1): the soundness in bits of the batched MAC-check."""
        d = float(p)
        l = math.log(d) / math.log(2)
        r = round(l)
        if abs(l - r) < 1e-9 and 2.0 ** r == d:
            l = r
        return keys * (l - 1)

    @staticmethod
    def setup_mac(n: int, rng, keys: int = MAC_KEYS) -> MacContext:
        if not _is_int(n) or n < 1:
            raise ValueError("setupMac: n must be a positive integer")
        if not _is_int(keys) or keys < 1 or keys > 16:
            raise ValueError("setupMac: keys must be an integer in [1, 16]")
        first = Spdz.mk(n, rng)
        extra = [Spdz.mk(n, rng) for _ in range(keys - 1)]
        return MacContext(n, first.alpha_shares, first.alpha, extra)

    @staticmethod
    def mk(n: int, rng) -> MacKey:
        alpha = rng.next()
        return MacKey(Sharing.share(alpha, n, rng), alpha)

    @staticmethod
    def auth_share(secret: int, ctx: MacContext, rng) -> AuthSV:
        v = Field.mod(secret)
        value = Sharing.share(v, ctx.n, rng)
        mac = Sharing.share(Field.fmul(ctx.alpha, v), ctx.n, rng)
        extra = [Sharing.share(Field.fmul(k.alpha, v), ctx.n, rng) for k in ctx.extra_keys]
        return AuthSV(value, mac, extra)

    @staticmethod
    def auth_constant(c: int, ctx: MacContext) -> AuthSV:
        v = Field.mod(c)
        value = [0] * ctx.n
        value[0] = v
        return AuthSV(value, Sharing.scale_sv(ctx.alpha_shares, v), [Sharing.scale_sv(k.alpha_shares, v) for k in ctx.extra_keys])

    @staticmethod
    def add_auth(x: AuthSV, y: AuthSV) -> AuthSV:
        Spdz.require_same(x, y)
        return AuthSV(_zip(x.value, y.value, Field.fadd), _zip(x.mac, y.mac, Field.fadd),
                      [_zip(a, b, Field.fadd) for a, b in zip(x.extra_mac, y.extra_mac)])

    @staticmethod
    def sub_auth(x: AuthSV, y: AuthSV) -> AuthSV:
        Spdz.require_same(x, y)
        return AuthSV(_zip(x.value, y.value, Field.fsub), _zip(x.mac, y.mac, Field.fsub),
                      [_zip(a, b, Field.fsub) for a, b in zip(x.extra_mac, y.extra_mac)])

    @staticmethod
    def neg_auth(x: AuthSV) -> AuthSV:
        return AuthSV(Sharing.neg_sv(x.value), Sharing.neg_sv(x.mac), [Sharing.neg_sv(r) for r in x.extra_mac])

    @staticmethod
    def scale_auth(x: AuthSV, c: int) -> AuthSV:
        k = Field.mod(c)
        return AuthSV(Sharing.scale_sv(x.value, k), Sharing.scale_sv(x.mac, k), [Sharing.scale_sv(r, k) for r in x.extra_mac])

    @staticmethod
    def add_public_auth(x: AuthSV, c: int, ctx: MacContext) -> AuthSV:
        """x + c for a PUBLIC constant c: c to one party's value share, alpha_i*c to every party's MAC share under every key."""
        n = ctx.n
        if len(x.value) != n or len(x.mac) != n or len(ctx.alpha_shares) != n:
            raise ValueError("addPublicAuth: shared value and MAC context disagree on the party count")
        if len(x.extra_mac) != len(ctx.extra_keys):
            raise ValueError("addPublicAuth: shared value and MAC context disagree on the key count")
        k = Field.mod(c)
        value = list(x.value)
        value[0] = Field.fadd(value[0], k)
        mac = [Field.fadd(x.mac[i], Field.fmul(ctx.alpha_shares[i], k)) for i in range(n)]
        extra = []
        for l, row in enumerate(x.extra_mac):
            key = ctx.extra_keys[l]
            if len(row) != n or len(key.alpha_shares) != n:
                raise ValueError("addPublicAuth: extra MAC party count mismatch")
            extra.append([Field.fadd(row[i], Field.fmul(key.alpha_shares[i], k)) for i in range(n)])
        return AuthSV(value, mac, extra)

    @staticmethod
    def not_bit_auth(b: AuthSV, ctx: MacContext) -> AuthSV:
        return Spdz.add_public_auth(Spdz.neg_auth(b), 1, ctx)

    @staticmethod
    def gen_auth_triple(ctx: MacContext, rng) -> AuthTriple:
        a = rng.next()
        b = rng.next()
        as_ = Spdz.auth_share(a, ctx, rng)
        bs = Spdz.auth_share(b, ctx, rng)
        return AuthTriple(as_, bs, Spdz.auth_share(Field.fmul(a, b), ctx, rng))

    @staticmethod
    def gen_triple_with_partners(ctx: MacContext, rng, partners: int = SACRIFICE_PARTNERS, fault: Optional[DealerFault] = None) -> TripleWithPartners:
        if not _is_int(partners) or partners < 1 or partners > 8:
            raise ValueError("genTripleWithPartners: partners must be in [1, 8]")
        a = rng.next()
        b = rng.next()
        b_sv = Spdz.auth_share(b, ctx, rng)
        kd = (fault.keep_c_delta if fault is not None else None) or 0
        keep_a = Spdz.auth_share(a, ctx, rng)
        keep_c = Spdz.auth_share(Field.fadd(Field.fmul(a, b), kd), ctx, rng)
        keep = AuthTriple(keep_a, b_sv, keep_c)
        ps = []
        for r in range(partners):
            ah = rng.next()
            pd = 0
            if fault is not None and fault.partner_c_delta is not None and r < len(fault.partner_c_delta) and fault.partner_c_delta[r]:
                pd = fault.partner_c_delta[r]
            pa = Spdz.auth_share(ah, ctx, rng)
            pc = Spdz.auth_share(Field.fadd(Field.fmul(ah, b), pd), ctx, rng)
            ps.append(AuthTriple(pa, b_sv, pc))
        return TripleWithPartners(keep, ps)

    @staticmethod
    def sacrifice_verify(batch: List[TripleWithPartners], ctx: MacContext, rng, deviations=()) -> List[AuthTriple]:
        """Certifies the kept triples or raises MacCheckAbort, emitting nothing."""
        engine = SpdzEngine(ctx, deviations)
        taus = []
        for t in batch:
            keep = t.keep
            if len(t.partners) == 0:
                raise MacCheckAbort("sacrifice: a triple without partners cannot be certified")
            for sac in t.partners:
                if sac.b.value != keep.b.value:
                    raise MacCheckAbort("sacrifice: partner does not share b with the triple")
                e = rng.next()
                if e == 0:
                    e = 1
                rho = engine.open(Spdz.sub_auth(Spdz.scale_auth(keep.a, e), sac.a), "sacrifice:rho")
                tau = Spdz.sub_auth(Spdz.scale_auth(keep.c, e), sac.c)
                tau = Spdz.sub_auth(tau, Spdz.scale_auth(keep.b, rho))
                taus.append(engine.open(tau, "sacrifice:tau"))
        engine.mac_check(rng)
        for t in taus:
            if t == 0:
                continue
            raise MacCheckAbort("Beaver-triple sacrifice FAILED: residual tau=%d != 0 - a malformed triple (c != a*b) was delivered; aborting "
                                "with no triple emitted" % t)
        return [t.keep for t in batch]

    @staticmethod
    def mac_residuals(p: int, alpha_shares, opened: List[OpenedValue], challenges) -> List[List[int]]:
        """Arithmetic core of the batched MAC-check over an arbitrary modulus p; returns sigma[key][party]."""
        out = []
        for l, alphas in enumerate(alpha_shares):
            r = challenges[l]
            a = 0
            for j in range(len(opened)):
                a = (a + r[j] * opened[j].value) % p
            row = []
            for i, alpha in enumerate(alphas):
                gamma = 0
                for j in range(len(opened)):
                    gamma = (gamma + r[j] * opened[j].mac_shares[l][i]) % p
                row.append((gamma - alpha * a) % p)
            out.append(row)
        return out

    @staticmethod
    def commit(value: int, nonce: int) -> str:
        """SHA-256 binding commitment to a field element under a nonce."""
        return hashlib.sha256(("%x:%x" % (value, nonce)).encode("ascii")).hexdigest()

    @staticmethod
    def beaver_mul_auth(x: AuthSV, y: AuthSV, triple: AuthTriple, ctx: MacContext, engine: "SpdzEngine", label: str) -> AuthSV:
        """Authenticated Beaver multiplication consuming triple; the d and e openings are recorded for the MAC-check."""
        for o in (triple.a, triple.b, triple.c, y):
            Spdz.require_same(x, o)
        d = engine.open(Spdz.sub_auth(x, triple.a), "%s:d" % label)
        e = engine.open(Spdz.sub_auth(y, triple.b), "%s:e" % label)
        z = Spdz.add_auth(triple.c, Spdz.add_auth(Spdz.scale_auth(triple.b, d), Spdz.scale_auth(triple.a, e)))
        return Spdz.add_public_auth(z, Field.fmul(d, e), ctx)

    @staticmethod
    def auth_value(x: AuthSV) -> int:
        acc = 0
        for s in x.value:
            acc = Field.fadd(acc, s)
        return acc

    @staticmethod
    def require_same(x: AuthSV, y: AuthSV) -> None:
        if len(x.value) != len(y.value) or len(x.mac) != len(y.mac):
            raise ValueError("authenticated shared values must have the same party count")
        if len(x.extra_mac) != len(y.extra_mac):
            raise ValueError("authenticated shared values must carry the same number of MAC keys")
        for l in range(len(x.extra_mac)):
            if len(x.extra_mac[l]) != len(y.extra_mac[l]):
                raise ValueError("authenticated shared values must have the same party count")


class SpdzEngine:
    """The SPDZ online engine: partial openings and the batched MAC-check."""

    def __init__(self, ctx: MacContext, deviations=None):
        bits = Spdz.mac_soundness_bits(1 + len(ctx.extra_keys))
        if bits < MIN_MAC_SOUNDNESS_BITS:
            raise ValueError("SpdzEngine: MAC context gives only %d bits of statistical soundness (< %d); use setup_mac(n, rng) with the "
                             "default %d keys" % (round(bits), MIN_MAC_SOUNDNESS_BITS, MAC_KEYS))
        self._ctx = ctx
        self._deviations = list(deviations or [])
        self._opened: List[OpenedValue] = []
        self._counter = 0

    def open_count(self) -> int:
        return self._counter

    def open(self, x: AuthSV, label: str = "") -> int:
        idx = self._counter
        self._counter += 1
        if len(x.extra_mac) != len(self._ctx.extra_keys):
            raise ValueError("open: value and MAC context disagree on the key count")
        value_shares = list(x.value)
        mac_shares = [list(x.mac)] + [list(r) for r in x.extra_mac]
        for d in self._deviations:
            if d.open_index != idx:
                continue
            if d.party < 0 or d.party >= self._ctx.n:
                raise ValueError("Deviation.party out of range")
            if d.value_delta is not None:
                value_shares[d.party] = Field.fadd(value_shares[d.party], d.value_delta)
            if d.mac_delta is None:
                continue
            key = d.mac_key or 0
            if key < 0 or key >= len(mac_shares):
                raise ValueError("Deviation.macKey out of range")
            mac_shares[key][d.party] = Field.fadd(mac_shares[key][d.party], d.mac_delta)
        value = 0
        for s in value_shares:
            value = Field.fadd(value, s)
        self._opened.append(OpenedValue(value, mac_shares, label))
        return value

    def mac_check(self, rng) -> None:
        """Batched MAC-check over every partial open so far; raises MacCheckAbort on any inconsistency."""
        if not self._opened:
            return
        keys = Spdz.mac_keys(self._ctx)
        challenges = [[rng.next() for _ in range(len(self._opened))] for _ in keys]
        sigma = Spdz.mac_residuals(PRIME, [k.alpha_shares for k in keys], self._opened, challenges)
        for row in sigma:
            nonces = [rng.next() for _ in row]
            commitments = [Spdz.commit(row[i], nonces[i]) for i in range(len(row))]
            for i in range(len(commitments)):
                if Spdz.commit(row[i], nonces[i]) != commitments[i]:
                    raise MacCheckAbort("MAC-check: commitment from party %d did not open consistently" % i)
        for l, row in enumerate(sigma):
            residual = 0
            for s in row:
                residual = Field.fadd(residual, s)
            if residual == 0:
                continue
            raise MacCheckAbort("MAC-check FAILED (key %d): residual %d != 0 - an actively-malicious party was detected; aborting with no output"
                                % (l, residual))


Spdz.SpdzEngine = SpdzEngine


def make_no_dealer_offline(n: int, seed: Optional[int] = None, base_ot_fn=None):
    """The no-dealer (OT-based, MASCOT) offline provider of n parties (mpc_mascot); a non-None seed makes every draw reproducible (tests only).
    ``base_ot_fn(messages, choices, rng) -> received`` swaps the base OT of every channel (the Ed25519 one by default; e.g.
    ``mpc_lwe_ot.with_endemic_base_ot()`` for the post-quantum one). It never falls back to a trusted dealer."""
    from .mpc_mascot import NoDealerOptions, make_no_dealer_offline as _make

    return _make(n, seed, None if base_ot_fn is None else NoDealerOptions(base_ot_fn=base_ot_fn))


@dataclass
class DealerOptions:
    """Trusted-dealer options (honoured only with insecure_trusted_dealer); None verify_triples means True."""

    verify_triples: Optional[bool] = None
    partners: Optional[int] = None
    fault: Optional[DealerFault] = None


@dataclass
class MaliciousMpcResult:
    composed: ComposedDecision
    parties: int
    q: int
    opens: int
    multiplications: int
    offline_mode: str
    triples_verified: bool
    mac_checked: bool


class SpdzRunner:
    """The malicious-secure (SPDZ) runner: the same composition as Runner.compose_secure, but every shared value carries a MAC and nothing is
    accepted as output until the batched MAC-check passes (correct result or MacCheckAbort). Offline phase: a no-dealer provider (the default,
    OT-based), or an explicit trusted dealer with sacrifice-certified triples."""

    DealerOptions = DealerOptions
    MaliciousMpcResult = MaliciousMpcResult
    T_M = 3

    @staticmethod
    def compose_secure_malicious(vectors, q: Optional[int] = None, seed: Optional[int] = None, deviations=None, offline=None,
                                 insecure_trusted_dealer: bool = False, dealer: Optional[DealerOptions] = None,
                                 base_ot_fn=None) -> MaliciousMpcResult:
        """``offline``: an object with n, mac_context (a property), gen_auth_triple() and auth_input(value, owner); None selects the no-dealer OT
        phase (``base_ot_fn`` picks its base OT)."""
        n = len(vectors)
        if n == 0:
            raise ValueError("composeSecureMalicious: no parties (fail closed)")
        if q is None:
            q = Party.DEFAULT_Q
        Compose.assert_decision_vectors(vectors, q)
        rng = Field.SecureFieldRng() if seed is None else Field.FieldRng(seed)
        if offline is not None and insecure_trusted_dealer:
            raise ValueError("composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)")
        if dealer is not None and not insecure_trusted_dealer and offline is None:
            raise ValueError("composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)")
        if offline is None and not insecure_trusted_dealer:
            offline = make_no_dealer_offline(n, seed, base_ot_fn)
        if offline is not None and offline.n != n:
            raise ValueError("composeSecureMalicious: offline provider party count != number of vectors")
        ctx = offline.mac_context if offline is not None else Spdz.setup_mac(n, rng)
        engine = SpdzEngine(ctx, deviations or [])
        mults = [0]
        verify = dealer is None or dealer.verify_triples is None or dealer.verify_triples

        def next_triple() -> AuthTriple:
            if offline is not None:
                return offline.gen_auth_triple()
            if not verify:
                if dealer is not None and dealer.fault is not None:
                    return Spdz.gen_triple_with_partners(ctx, rng, 1, dealer.fault).keep
                return Spdz.gen_auth_triple(ctx, rng)
            partners = dealer.partners if dealer is not None and dealer.partners is not None else SACRIFICE_PARTNERS
            dealt = Spdz.gen_triple_with_partners(ctx, rng, partners, dealer.fault if dealer is not None else None)
            return Spdz.sacrifice_verify([dealt], ctx, rng, [])[0]

        def share_bit(bit, owner):
            return offline.auth_input(bit, owner) if offline is not None else Spdz.auth_share(bit, ctx, rng)

        def and_all(bits):
            if not bits:
                return Spdz.auth_constant(1, ctx)
            acc = bits[0]
            for i, b in enumerate(bits[1:], 1):
                mults[0] += 1
                acc = Spdz.beaver_mul_auth(acc, b, next_triple(), ctx, engine, "and%d" % i)
            return acc

        def or_all(bits):
            if not bits:
                return Spdz.auth_constant(0, ctx)
            prod = Spdz.not_bit_auth(bits[0], ctx)
            for i, b in enumerate(bits[1:], 1):
                mults[0] += 1
                prod = Spdz.beaver_mul_auth(prod, Spdz.not_bit_auth(b, ctx), next_triple(), ctx, engine, "or%d" % i)
            return Spdz.not_bit_auth(prod, ctx)

        allow_sv = and_all([share_bit(vectors[p].allow, p) for p in range(n)])
        t_therm = [Thermometer.thermometer_encode(v.t, SpdzRunner.T_M) for v in vectors]
        t_ge = [or_all([share_bit(t_therm[p][k], p) for p in range(n)]) for k in range(SpdzRunner.T_M)]
        r_therm = [Thermometer.thermometer_encode(v.r_quant, q) for v in vectors]
        r_ge = [or_all([share_bit(r_therm[p][k], p) for p in range(n)]) for k in range(q)]
        allow_open = engine.open(allow_sv, "out:allow")
        t_open = [1 if engine.open(sv, "out:t.ge%d" % (k + 1)) == 1 else 0 for k, sv in enumerate(t_ge)]
        r_open = [1 if engine.open(sv, "out:r.ge%d" % (k + 1)) == 1 else 0 for k, sv in enumerate(r_ge)]
        engine.mac_check(rng)
        composed = ComposedDecision(1 if allow_open == 1 else 0, min(3, max(1, Thermometer.thermometer_decode(t_open))),
                                    Thermometer.thermometer_decode(r_open))
        return MaliciousMpcResult(composed, n, q, engine.open_count(), mults[0], "no-dealer" if offline is not None else "trusted-dealer",
                                  offline is not None or verify, True)
