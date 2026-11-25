"""The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real oblivious transfers (Gilboa
multiplication over OT extension), the MAC key is distributed and never reconstructed, and every produced triple is certified by the sacrifice
check. When a check fails the OT transcripts are searched to blame the cheating party.

``make_no_dealer_offline(n, seed=None, opts=None)`` returns a ``NoDealerOffline`` (the offline provider ``SpdzRunner.compose_secure_malicious``
takes: ``n``, ``mac_context`` (a property), ``gen_auth_triple()``, ``auth_input(value, owner)``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from .mpc import Enc, EncShare, Field, Sharing
from .mpc_ot import Ot, OtChannel
from .mpc_spdz import (AuthSV, AuthTriple, MacCheckAbort, MacContext, MacKey, MAC_KEYS, SACRIFICE_PARTNERS, Spdz, SpdzEngine,
                       TripleWithPartners)


class OfflineCheatingAbort(MacCheckAbort):
    """A MAC-check abort raised by the offline phase, naming the party the OT transcripts convict (when one can be named)."""

    def __init__(self, message: str, blamed: List[int]):
        super().__init__(message if not blamed else "%s; offline OT transcript names party %s" % (message, ", ".join(str(b) for b in blamed)))
        self.blamed = blamed


@dataclass
class OtRecord:
    receiver: int
    sender: int
    msg0: list
    msg1: list
    received: list


@dataclass
class ProductClaim:
    claimed: list
    implied: list


@dataclass
class OfflineDeviation:
    """TEST-ONLY: the product_mul-th product's claimed share is shifted by delta (a cheating party lying about a product)."""

    product_mul: int
    delta: int


@dataclass
class NoDealerOptions:
    """Options (None fields mean the defaults). ``base_ot_fn`` (messages, choices, rng) -> received swaps the base OT of every channel."""

    sacrifice: Optional[bool] = None
    sacrifice_partners: Optional[int] = None
    mac_keys: Optional[int] = None
    deviation: Optional[OfflineDeviation] = None
    stat_sec: Optional[int] = None
    unsafe_stat_sec: Optional[bool] = None
    base_ot_fn: Optional[Callable] = None


@dataclass
class Req:
    """One operand of a multiplication request: x is a list of plain values or encoded (value, choice bits) shares."""

    x: list
    y: list


@dataclass
class Part:
    bits: list
    gad: list


@dataclass
class Piece:
    value: int
    parts: List[Part]


@dataclass
class Seg:
    q: int
    start: int
    len: int
    sender_sum: int


class NoDealerOffline:
    """The no-dealer offline provider of n parties; a non-None seed makes every draw reproducible (tests only)."""

    def __init__(self, n: int, seed: Optional[int] = None, opts: Optional[NoDealerOptions] = None):
        opts = opts or NoDealerOptions()
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            raise ValueError("NoDealerOffline: n must be a positive integer")
        self.n = n
        self._deterministic = seed is not None
        self._seed = 0xABCDEF12345 if seed is None else seed
        self._rng = Field.FieldRng(self._seed) if self._deterministic else Field.SecureFieldRng()
        self._sacrifice_on = opts.sacrifice is None or bool(opts.sacrifice)
        self._deviation = opts.deviation
        self._base_ot_fn = opts.base_ot_fn
        keys = MAC_KEYS if opts.mac_keys is None else opts.mac_keys
        if not isinstance(keys, int) or isinstance(keys, bool) or keys < 1 or keys > 16:
            raise ValueError("NoDealerOffline: macKeys must be an integer in [1, 16]")
        self.stat_sec = Enc.STAT_SEC if opts.stat_sec is None else opts.stat_sec
        self._gadget = Enc.make_gadget(self.stat_sec, self._rng, opts.unsafe_stat_sec is True)
        self._key_enc = [[Enc.sample_enc(self._gadget, self._rng) for _ in range(n)] for _ in range(keys)]
        self._key_shares = [[e.value for e in row] for row in self._key_enc]
        self.alpha_shares = self._key_shares[0]
        self._sacrifice_partners = SACRIFICE_PARTNERS if opts.sacrifice_partners is None else opts.sacrifice_partners
        sp = self._sacrifice_partners
        if not isinstance(sp, int) or isinstance(sp, bool) or sp < 1 or sp > 8:
            raise ValueError("NoDealerOffline: sacrificePartners must be an integer in [1, 8]")
        self._channels: dict = {}
        self._product_mul_count = 0
        self._log: Optional[list] = None
        self._claims: list = []

    @property
    def mac_context(self) -> MacContext:
        """The MAC context: the shares of each key and (for tests and the check only) their sums."""
        keys = []
        for shares in self._key_shares:
            tot = 0
            for s in shares:
                tot = Field.fadd(tot, s)
            keys.append(MacKey(list(shares), tot))
        return MacContext(self.n, keys[0].alpha_shares, keys[0].alpha, keys[1:])

    def ot_share_multiply(self, x, y) -> List[int]:
        """Additive shares of x*y where party i holds x_i and y_i (all cross terms via OT)."""
        return self._mul_batch([Req(x, y)])[0]

    def gen_auth_triple(self) -> AuthTriple:
        """One authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off)."""
        if not self._sacrifice_on:
            return self._raw_triple_with_partners(0).keep
        self._log = []
        self._claims = []
        try:
            t = self._raw_triple_with_partners(self._sacrifice_partners)
            return Spdz.sacrifice_verify([t], self.mac_context, self._rng, [])[0]
        except MacCheckAbort as e:
            raise self._attribute(e) from e
        finally:
            self._log = None
            self._claims = []

    def gen_auth_triples(self, count: int) -> List[AuthTriple]:
        return [self.gen_auth_triple() for _ in range(count)]

    def auth_input(self, value: int, owner: int) -> AuthSV:
        """An authenticated sharing of a value contributed by owner, MACed by OT under the distributed key."""
        if not isinstance(owner, int) or isinstance(owner, bool) or owner < 0 or owner >= self.n:
            raise ValueError("authInput: owner out of range")
        return self._authenticate(Sharing.share(Field.mod(value), self.n, self._rng))

    def check_input_consistency(self, inputs: List[AuthSV]) -> None:
        """Verifies that every supplied input's MAC matches its value via a random combination (aborts otherwise)."""
        if not inputs:
            return
        for inp in inputs:
            if len(inp.value) != self.n or len(inp.mac) != self.n:
                raise ValueError("checkInputConsistency: input party count mismatch")
        engine = SpdzEngine(self.mac_context, [])
        w = self._authenticate([self._rng.next() for _ in range(self.n)])
        for inp in inputs:
            e = self._rng.next()
            if e == 0:
                e = 1
            w = Spdz.add_auth(w, Spdz.scale_auth(inp, e))
        engine.open(w, "input-check:w")
        engine.mac_check(self._rng)

    # ---- private ----

    def _channel(self, i: int, j: int) -> OtChannel:
        key = "%d->%d" % (i, j)
        ch = self._channels.get(key)
        if ch is None:
            if self._deterministic:
                ot_rng = Ot.ot_random(Ot.split_mix64(self._seed ^ ((i + 1) * 0x100000001B3) ^ ((j + 1) * 0x1000000000)))
            else:
                ot_rng = Ot.secure_ot_random()
            ch = OtChannel(ot_rng, self._base_ot_fn)
            self._channels[key] = ch
        return ch

    def _sample_share(self) -> EncShare:
        return Enc.sample_enc(self._gadget, self._rng)

    def _mul_batch(self, reqs: List[Req]) -> List[List[int]]:
        """Batched Gilboa multiplication: one OT-extension call per ordered party pair for every request."""
        n = self.n
        for r in reqs:
            if len(r.x) != n or len(r.y) != n:
                raise ValueError("otShareMultiply: wrong length")
        pieces: List[List[Piece]] = []
        for r in reqs:
            row = []
            for xi in r.x:
                if isinstance(xi, EncShare):
                    row.append(Piece(xi.value, [Part(xi.bits, self._gadget)]))
                else:
                    v = Field.mod(xi)
                    e = Enc.sample_enc(self._gadget, self._rng)
                    d = Enc.plain_share(Field.fsub(v, e.value))
                    row.append(Piece(v, [Part(e.bits, self._gadget), Part(d.bits, Enc.plain_gadget())]))
            pieces.append(row)
        z = [[Field.fmul(pieces[q][i].value, reqs[q].y[i]) for i in range(n)] for q in range(len(reqs))]
        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                bits: list = []
                msg0: list = []
                msg1: list = []
                segs: List[Seg] = []
                for q, req in enumerate(reqs):
                    y = Field.mod(req.y[j])
                    for part in pieces[q][i].parts:
                        at = len(bits)
                        sender_sum = 0
                        for k, bit in enumerate(part.bits):
                            rho = self._rng.next()
                            sender_sum = Field.fadd(sender_sum, rho)
                            bits.append(bit)
                            msg0.append(rho)
                            msg1.append(Field.fadd(rho, Field.fmul(part.gad[k], y)))
                        segs.append(Seg(q, at, len(part.bits), sender_sum))
                received = self._channel(i, j).extend_ot(bits, msg0, msg1).received
                if self._log is not None:
                    self._log.append(OtRecord(i, j, msg0, msg1, received))
                for sg in segs:
                    receiver_sum = 0
                    for k in range(sg.len):
                        receiver_sum = Field.fadd(receiver_sum, Field.mod(received[sg.start + k]))
                    z[sg.q][i] = Field.fadd(z[sg.q][i], receiver_sum)
                    z[sg.q][j] = Field.fadd(z[sg.q][j], Field.fneg(sg.sender_sum))
        return z

    def _key_req(self, l: int) -> list:
        return list(self._key_enc[l])

    def _authenticate(self, value_shares: list) -> AuthSV:
        return self._to_auth(value_shares, self._mul_batch([Req(self._key_req(l), value_shares) for l in range(len(self._key_enc))]))

    @staticmethod
    def _to_auth(value: list, macs: list) -> AuthSV:
        return AuthSV(value, macs[0], macs[1:])

    def _claim_product(self, implied: list) -> list:
        z = list(implied)
        idx = self._product_mul_count
        self._product_mul_count += 1
        if self._deviation is not None and self._deviation.product_mul == idx:
            z[0] = Field.fadd(z[0], self._deviation.delta)
        self._claims.append(ProductClaim(z, implied))
        return z

    @staticmethod
    def _mac_of(z: list, start: int, per: int, off: int, k: int) -> list:
        return [z[start + (l * per) + off] for l in range(k)]

    def _raw_triple_with_partners(self, partners: int) -> TripleWithPartners:
        k = len(self._key_enc)
        a_enc = [self._sample_share() for _ in range(self.n)]
        b_shares = [self._rng.next() for _ in range(self.n)]
        ah_enc = [[self._sample_share() for _ in range(self.n)] for _ in range(partners)]
        a_val = [e.value for e in a_enc]
        ah_val = [[e.value for e in row] for row in ah_enc]
        reqs = [Req(list(a_enc), b_shares)]
        for r in range(partners):
            reqs.append(Req(list(ah_enc[r]), b_shares))
        mac_start = len(reqs)
        for l in range(k):
            reqs.append(Req(self._key_req(l), a_val))
            reqs.append(Req(self._key_req(l), b_shares))
            for r in range(partners):
                reqs.append(Req(self._key_req(l), ah_val[r]))
        z1 = self._mul_batch(reqs)
        c_shares = self._claim_product(z1[0])
        ch_shares = [self._claim_product(z1[1 + r]) for r in range(partners)]
        per = 2 + partners
        reqs2 = []
        for l in range(k):
            reqs2.append(Req(self._key_req(l), c_shares))
            for r in range(partners):
                reqs2.append(Req(self._key_req(l), ch_shares[r]))
        z2 = self._mul_batch(reqs2)
        per2 = 1 + partners
        b = self._to_auth(b_shares, self._mac_of(z1, mac_start, per, 1, k))
        keep = AuthTriple(self._to_auth(a_val, self._mac_of(z1, mac_start, per, 0, k)), b,
                          self._to_auth(c_shares, self._mac_of(z2, 0, per2, 0, k)))
        parts = [AuthTriple(self._to_auth(ah_val[r], self._mac_of(z1, mac_start, per, 2 + r, k)), b,
                            self._to_auth(ch_shares[r], self._mac_of(z2, 0, per2, 1 + r, k))) for r in range(partners)]
        return TripleWithPartners(keep, parts)

    def _attribute(self, abort: Exception) -> OfflineCheatingAbort:
        blamed: List[int] = []
        for r in (self._log or []):
            for k, v in enumerate(r.received):
                got = Field.mod(v)
                if got == r.msg0[k] or got == r.msg1[k]:
                    continue
                blamed.append(r.sender)
                break
        for c in self._claims:
            for i in range(len(c.claimed)):
                if c.claimed[i] != c.implied[i]:
                    blamed.append(i)
        return OfflineCheatingAbort(str(abort), sorted(set(blamed)))


def make_no_dealer_offline(n: int, seed: Optional[int] = None, opts: Optional[NoDealerOptions] = None) -> NoDealerOffline:
    """The no-dealer offline provider of n parties; a non-None seed makes every draw reproducible (tests only)."""
    return NoDealerOffline(n, seed, opts)


class Mascot:
    """Ruby-shaped namespace: ``Mascot.make_no_dealer_offline`` and the option/record types."""

    OfflineCheatingAbort = OfflineCheatingAbort
    OtRecord = OtRecord
    ProductClaim = ProductClaim
    OfflineDeviation = OfflineDeviation
    NoDealerOptions = NoDealerOptions
    NoDealerOffline = NoDealerOffline
    Req = Req
    Part = Part
    Piece = Piece
    Seg = Seg
    make_no_dealer_offline = staticmethod(make_no_dealer_offline)
