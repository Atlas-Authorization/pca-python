"""Oblivious transfer, the root of the no-dealer offline phase. (1) A maliciously secure Chou-Orlandi base OT over the Ed25519 subgroup: the sender
proves knowledge of its discrete log with a Schnorr NIZK, every received point is validated, and the core runs as a random OT so there is no
selective-failure surface. (2) IKNP OT extension with the KOS consistency check (a deviating receiver is caught and the protocol aborts). Both
roles run in one process; the functions take both parties' inputs and return the receiver's outputs plus an inspectable transcript.

The namespace ``Ot`` mirrors the reference (``Ot.base_ot``, ``Ot.OtChannel`` ...); the OtChannel accepts a pluggable base OT
(``base_ot_fn(messages, choices, rng) -> received``), e.g. ``KemOt.with_kem_base_ot_mal``, ``HybridOt.with_hybrid_base_ot`` or the endemic
post-quantum one in ``mpc_lwe_ot``."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from .mpc import Gf128
from .mpc_ec import Ec, Point, SchnorrProof
from .mpc_libcrypto import Libcrypto
from .mpc_otx import OtTweak, Otx

KAPPA = 128  # IKNP security parameter (number of base OTs / width of the selector s)
SSEC = 128  # KOS statistical parameter: extra random check rows that mask the revealed combination
SEED_BYTES = KAPPA // 8
MASK64 = (1 << 64) - 1

TAG_BINDING = b"atlas-pca-mpc/base-ot-binding"
TAG_TRANSCRIPT = b"atlas-pca-mpc/base-ot-transcript"
TAG_KDF = b"atlas-pca-mpc/ot-kdf"
TAG_KOS = b"atlas-pca-mpc/ot-kos"
TAG_COMMIT = b"atlas-pca-mpc/ot-msg-commit"


class MalOtAbort(Exception):
    """The KOS correlation check failed: a cheating OT-extension receiver is detected."""


class BaseOtAbort(Exception):
    """A base OT aborted: a cheating sender (bad proof / inconsistent ciphertext) is detected."""


class OtRandom:
    """A source of scalars (uniform in [1, L)) and byte strings for OT needs."""

    def __init__(self, scalar_fn: Callable[[], int], bytes_fn: Callable[[int], bytes]):
        self._scalar_fn = scalar_fn
        self._bytes_fn = bytes_fn

    def scalar(self) -> int:
        return self._scalar_fn()

    def bytes(self, n: int) -> bytes:
        return self._bytes_fn(n)


@dataclass
class BaseOtBinding:
    """Session binding of one base OT: who runs it, in which session and round (indices are uint32)."""

    session_id: bytes
    sender_index: int
    receiver_index: int
    round: Any


@dataclass
class BaseOtTamper:
    """TEST-ONLY injection points modelling a malicious sender or receiver in the base OT (None = honest); each is a callable."""

    tamper_s: Optional[Callable] = None
    tamper_proof: Optional[Callable] = None
    tamper_r: Optional[Callable] = None
    tamper_ciphertext: Optional[Callable] = None


@dataclass
class BaseOtTranscript:
    s: Point
    proof: SchnorrProof
    r: List[Point]
    ct: list  # [i][0/1] byte strings
    com: list


@dataclass
class BaseOtResult:
    received: List[bytes]
    transcript: BaseOtTranscript


@dataclass
class MalRandomOtResult:
    """Output of the malicious-secure random base OT: validated points and the two RO pads per index."""

    s: Point
    proof: SchnorrProof
    r: List[Point]
    sender_pads: list
    recv_pads: List[bytes]


@dataclass
class SenderSetup:
    y: int
    t: Point
    s: Point
    proof: SchnorrProof


@dataclass
class ReceiverResponse:
    r: List[Point]
    recv_pads: List[bytes]


@dataclass
class ExtRoundMsg:
    """The receiver's extension-round message: the u columns and the KOS values (x, t)."""

    u: list
    x: int
    t_comb: int


@dataclass
class ExtPending:
    """The receiver's per-round state between begin and finish."""

    m: int
    choice_bits: list
    t: list
    w: int
    row_offset: int


def _sha256(*chunks: bytes) -> bytes:
    return hashlib.sha256(b"".join(chunks)).digest()


def _u32(x: int) -> bytes:
    return (x & 0xFFFFFFFF).to_bytes(4, "big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))  # zip truncates to the shorter, as the reference's bytes.zip does for equal lengths


def _ct_eq(a: bytes, b: bytes) -> bool:
    return len(a) == len(b) and hmac.compare_digest(bytes(a), bytes(b))


def _uint32(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 0xFFFFFFFF


class OtExtReceiver:
    """The extension receiver (base-OT sender): makes the seed pairs, then per round the u matrix and KOS values."""

    @dataclass
    class Begin:
        msg: ExtRoundMsg
        pending: ExtPending

    def __init__(self, rng, kos_binding: bytes):
        self._rng = rng
        self._kos_binding = kos_binding
        self._seed0: List[bytes] = []
        self._seed1: List[bytes] = []
        self._blk0 = [0] * KAPPA
        self._blk1 = [0] * KAPPA
        self._round = 0
        self._rows_done = 0
        self._tweak_domain = Otx.ot_tweak_domain(kos_binding)
        self.ready = False
        self.tamper_u: Optional[Callable] = None

    def make_seeds(self) -> list:
        """The kappa seed pairs, to be transferred by the base OT with the sender's selector as choices."""
        messages = []
        for _ in range(KAPPA):
            k0 = self._rng.bytes(SEED_BYTES)
            k1 = self._rng.bytes(SEED_BYTES)
            self._seed0.append(k0)
            self._seed1.append(k1)
            messages.append([k0, k1])
        self.ready = True
        return messages

    def begin_round(self, choice_bits) -> "OtExtReceiver.Begin":
        if not self.ready:
            raise RuntimeError("OtExtReceiver: base OT not done")
        Ot.check_ext_inputs(choice_bits, None, None)
        m = len(choice_bits)
        round_idx = self._round
        self._round += 1
        row_offset = self._rows_done
        self._rows_done += m
        pad = KAPPA + SSEC
        m_ext = m + pad
        w = (m_ext + 31) >> 5
        col_bytes = (m_ext + 7) // 8
        bvec = [0] * w
        for j in range(m):
            if (choice_bits[j] & 1) != 0:
                bvec[j >> 5] |= 1 << (j & 31)
        pad_bytes = self._rng.bytes(pad)
        for p in range(pad):
            j = m + p
            if (pad_bytes[p] & 1) != 0:
                bvec[j >> 5] |= 1 << (j & 31)
        blocks = (w + 3) // 4
        t = [0] * (Otx.COLS * w)
        u: list = [None] * Otx.COLS
        ubytes: list = [None] * Otx.COLS
        for i in range(KAPPA):
            ti = Otx.prg_column(self._seed0[i], self._blk0[i], w)
            gi = Otx.prg_column(self._seed1[i], self._blk1[i], w)
            self._blk0[i] += blocks
            self._blk1[i] += blocks
            Otx.mask_tail(ti, m_ext)
            Otx.mask_tail(gi, m_ext)
            t[i * w:i * w + w] = ti
            uw = [gi[k] ^ ti[k] ^ bvec[k] for k in range(w)]
            ubytes[i] = Otx.le_bytes(uw, w)[:col_bytes]
            u[i] = Otx.bytes_to_big(ubytes[i])
        if self.tamper_u is not None:
            self.tamper_u(u, round_idx)
        pending = ExtPending(m, list(choice_bits), t, w, row_offset)
        limit = 1 << m_ext
        if any(c is None or c < 0 or c >= limit for c in u):
            return OtExtReceiver.Begin(ExtRoundMsg(u, 0, 0), pending)
        chi = Ot.kos_chi_words(self._kos_binding, round_idx, u, m_ext, None if self.tamper_u is not None else ubytes)
        x = [0, 0, 0, 0]
        Otx.accum_column(bvec, 0, w, chi, x)
        t_comb = Otx.kos_combine(t, w, chi)
        return OtExtReceiver.Begin(ExtRoundMsg(u, Otx.gf_to_big(x), Otx.gf_to_big(t_comb)), pending)

    def finish(self, pending: ExtPending, y0, y1) -> List[int]:
        """The receiver's outputs: m_{c_j} for every row j, from the sender's ciphertexts."""
        m = pending.m
        if len(y0) != m or len(y1) != m:
            raise MalOtAbort("OT extension: ciphertext count does not match the number of rows; aborting")
        rows = Otx.transpose_cols(pending.t, pending.w, m)
        h = Otx.tmmo_crh(rows, m, OtTweak(pending.row_offset, self._tweak_domain))
        return [(y1[j] if pending.choice_bits[j] == 1 else y0[j]) ^ Otx.word64(h, j) for j in range(m)]


@dataclass
class _Response:
    y0: list
    y1: list


class OtExtSender:
    """The extension sender (base-OT receiver): holds the secret selector s and answers each round after the KOS check."""

    Response = _Response

    def __init__(self, rng, kos_binding: bytes):
        self._rng = rng
        self._kos_binding = kos_binding
        self._s: List[int] = []
        self._s_bits = 0
        self._seeds: list = []
        self._blk: List[int] = []
        self._round = 0
        self._rows_done = 0
        self._tweak_domain = Otx.ot_tweak_domain(kos_binding)
        self.ready = False

    def make_selector(self) -> List[int]:
        self._s = [self._rng.bytes(1)[0] & 1 for _ in range(KAPPA)]
        return list(self._s)

    def set_seeds(self, seeds) -> None:
        if len(seeds) != KAPPA or len(self._s) != KAPPA:
            raise RuntimeError("OtExtSender: wrong base-OT output size")
        self._seeds = seeds
        self._blk = [0] * KAPPA
        acc = 0
        for i in range(KAPPA):
            if self._s[i] == 1:
                acc |= 1 << i
        self._s_bits = acc
        self.ready = True

    def selector(self) -> int:
        return self._s_bits

    def respond(self, msg: ExtRoundMsg, msg0, msg1) -> _Response:
        if not self.ready:
            raise RuntimeError("OtExtSender: base OT not done")
        m = len(msg0)
        if len(msg1) != m:
            raise ValueError("OtChannel.extend: length mismatch")
        Ot.check_ext_inputs([0] * m, msg0, msg1)
        round_idx = self._round
        self._round += 1
        row_offset = self._rows_done
        self._rows_done += m
        m_ext = m + KAPPA + SSEC
        u = msg.u
        if u is None or len(u) != KAPPA:
            raise MalOtAbort("KOS check (round %d): wrong number of u columns; a cheating OT-extension receiver was detected; aborting" % round_idx)
        col_limit = 1 << m_ext
        for i, ui in enumerate(u):
            if ui is None or ui < 0 or ui >= col_limit:
                raise MalOtAbort("KOS check (round %d): malformed u column %d; a cheating OT-extension receiver was detected; aborting"
                                 % (round_idx, i))
        lim128 = 1 << 128
        x = msg.x
        tc = msg.t_comb
        if x is None or tc is None or x < 0 or x >= lim128 or tc < 0 or tc >= lim128:
            raise MalOtAbort("KOS check (round %d): malformed (x, t); a cheating OT-extension receiver was detected; aborting" % round_idx)
        w = (m_ext + 31) >> 5
        col_bytes = (m_ext + 7) // 8
        blocks = (w + 3) // 4
        q = [0] * (Otx.COLS * w)
        ubytes: list = [None] * Otx.COLS
        for i in range(KAPPA):
            ubytes[i] = Otx.big_to_bytes(u[i], col_bytes)
            ks = Otx.prg_column(self._seeds[i], self._blk[i], w)
            self._blk[i] += blocks
            Otx.mask_tail(ks, m_ext)
            if self._s[i] == 1:
                uw = Otx.words_from_le_bytes(ubytes[i] + bytes((4 * w) - len(ubytes[i])), w)
                for k in range(w):
                    ks[k] ^= uw[k]
            q[i * w:i * w + w] = ks
        chi = Ot.kos_chi_words(self._kos_binding, round_idx, u, m_ext, ubytes)
        q_comb = Otx.gf_to_big(Otx.kos_combine(q, w, chi))
        expected = tc ^ Gf128.mul(x, self._s_bits)
        if q_comb != expected:
            raise MalOtAbort("KOS correlation check FAILED (round %d): a cheating OT-extension receiver was detected; aborting" % round_idx)
        rows = Otx.transpose_cols(q, w, m)
        tweak = OtTweak(row_offset, self._tweak_domain)
        h0 = Otx.tmmo_crh(rows, m, tweak)
        sw = Otx.gf_from_big(self._s_bits)
        for j in range(m):
            row = rows[4 * j:4 * j + 4]
            Otx.gf_xor_into(row, sw, 0)
            rows[4 * j:4 * j + 4] = row
        h1 = Otx.tmmo_crh(rows, m, tweak)
        return _Response([msg0[j] ^ Otx.word64(h0, j) for j in range(m)], [msg1[j] ^ Otx.word64(h1, j) for j in range(m)])


@dataclass
class Extended:
    received: list
    u_matrix: list


class OtChannel:
    """An in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later extend. The base OT is the EC base
    OT unless base_ot_fn (callable (messages, choices, rng) -> received) supplies another (a post-quantum one)."""

    Extended = Extended

    def __init__(self, rng=None, base_ot_fn: Optional[Callable] = None, binding: Optional[BaseOtBinding] = None):
        """binding: only session_id, sender_index and receiver_index are used (its round is ignored); may be None."""
        self._rng = rng or Ot.secure_ot_random()
        self._base_ot_fn = base_ot_fn
        self._binding_opt = binding
        self._ready = False
        self.base_transcript: Optional[BaseOtTranscript] = None
        self.tamper_u: Optional[Callable] = None
        self._recv: Optional[OtExtReceiver] = None
        self._send: Optional[OtExtSender] = None

    def selector(self) -> int:
        if not self._ready:
            self._setup()
        return self._send.selector()

    def extend_ot(self, choice_bits, msg0, msg1) -> Extended:
        if not self._ready:
            self._setup()
        m = len(choice_bits)
        if len(msg0) != m or len(msg1) != m:
            raise ValueError("OtChannel.extend: length mismatch")
        if m == 0:
            return Extended([], [])
        Ot.check_ext_inputs(choice_bits, msg0, msg1)
        self._recv.tamper_u = self.tamper_u
        b = self._recv.begin_round(choice_bits)
        r = self._send.respond(b.msg, msg0, msg1)
        return Extended(self._recv.finish(b.pending, r.y0, r.y1), b.msg.u)

    def _setup(self) -> None:
        base = self._binding_opt or Ot.random_binding(self._rng, "x")
        kos = Ot.binding_bytes(BaseOtBinding(base.session_id, base.sender_index, base.receiver_index, "iknp-kos"))
        r = OtExtReceiver(self._rng, kos)
        sd = OtExtSender(self._rng, kos)
        messages = r.make_seeds()
        sel = sd.make_selector()
        if self._base_ot_fn is not None:
            sd.set_seeds(self._base_ot_fn(messages, sel, self._rng))
        else:
            res = Ot.base_ot(messages, sel, self._rng, None, BaseOtBinding(base.session_id, base.sender_index, base.receiver_index,
                                                                         "iknp-kappa-setup"))
            sd.set_seeds(res.received)
            self.base_transcript = res.transcript
        self._recv = r
        self._send = sd
        self._ready = True


class Ot:
    KAPPA = KAPPA
    SSEC = SSEC
    SEED_BYTES = SEED_BYTES
    MASK64 = MASK64
    MalOtAbort = MalOtAbort
    BaseOtAbort = BaseOtAbort
    OtRandom = OtRandom
    BaseOtBinding = BaseOtBinding
    BaseOtTamper = BaseOtTamper
    BaseOtTranscript = BaseOtTranscript
    BaseOtResult = BaseOtResult
    MalRandomOtResult = MalRandomOtResult
    SenderSetup = SenderSetup
    ReceiverResponse = ReceiverResponse
    ExtRoundMsg = ExtRoundMsg
    ExtPending = ExtPending
    OtExtReceiver = OtExtReceiver
    OtExtSender = OtExtSender
    OtChannel = OtChannel

    @staticmethod
    def secure_ot_random() -> OtRandom:
        """The CSPRNG-backed default: scalars by rejection over 32 random bytes."""
        bound = (1 << 256) - ((1 << 256) % Ec.L)

        def scalar() -> int:
            while True:
                acc = int.from_bytes(secrets.token_bytes(32), "big")
                if acc >= bound:
                    continue
                s = acc % Ec.L
                if s != 0:
                    return s

        return OtRandom(scalar, secrets.token_bytes)

    @staticmethod
    def split_mix64(seed: int) -> Callable[[], int]:
        """A raw SplitMix64 stream (deterministic; reproducible tests only): a callable returning unsigned 64-bit ints."""
        state = [seed & MASK64]

        def nxt() -> int:
            state[0] = (state[0] + 0x9E3779B97F4A7C15) & MASK64
            z = state[0]
            z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
            z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
            return z ^ (z >> 31)

        return nxt

    @staticmethod
    def ot_random(next64: Callable[[], int]) -> OtRandom:
        """An OtRandom from a 64-bit stream."""

        def scalar() -> int:
            for _ in range(8):
                acc = 0
                for _ in range(4):
                    acc = (acc << 64) | next64()
                s = acc % Ec.L
                if s != 0:
                    return s
            raise RuntimeError("otRandom: entropy stream returned zero scalars repeatedly (RNG failure)")

        def byts(n: int) -> bytes:
            out = bytearray()
            while len(out) < n:
                out += struct.pack("<Q", next64())
            return bytes(out[:n])

        return OtRandom(scalar, byts)

    sha256 = staticmethod(_sha256)
    u32 = staticmethod(_u32)
    xor_bytes = staticmethod(_xor_bytes)
    ct_eq = staticmethod(_ct_eq)

    @staticmethod
    def binding_bytes(b: BaseOtBinding) -> bytes:
        """Canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input)."""
        sid = b.session_id
        if not isinstance(sid, (bytes, bytearray)) or len(sid) < 8 or len(sid) > 64:
            raise ValueError("base-OT binding: sessionId must be 8..64 bytes")
        if not _uint32(b.sender_index):
            raise ValueError("base-OT binding: senderIndex must be a uint32")
        if not _uint32(b.receiver_index):
            raise ValueError("base-OT binding: receiverIndex must be a uint32")
        if b.sender_index == b.receiver_index:
            raise ValueError("base-OT binding: sender and receiver must be different parties")
        rnd = b.round if isinstance(b.round, (bytes, bytearray)) else str(b.round).encode("utf-8")
        if len(rnd) == 0 or len(rnd) > 64:
            raise ValueError("base-OT binding: round label must be 1..64 bytes")
        return TAG_BINDING + _u32(len(sid)) + bytes(sid) + _u32(b.sender_index) + _u32(b.receiver_index) + _u32(len(rnd)) + bytes(rnd)

    @staticmethod
    def random_binding(rng, round: Any, sender_index: int = 0, receiver_index: int = 1) -> BaseOtBinding:
        """A fresh binding for an in-process OT: a random 16-byte session id from rng."""
        return BaseOtBinding(rng.bytes(16), sender_index, receiver_index, round)

    @staticmethod
    def base_ot_transcript_hash(binding: BaseOtBinding, s: Point, r: List[Point]) -> bytes:
        """Hash of the whole base-OT transcript: binding, S and every receiver point, in order."""
        return _sha256(TAG_TRANSCRIPT, Ot.binding_bytes(binding), Ec.encode_point(s), _u32(len(r)), *[Ec.encode_point(p) for p in r])

    @staticmethod
    def base_ot_kdf(transcript_hash: bytes, index: int, ri: Point, p: Point) -> bytes:
        """H("ot-kdf" || H(transcript) || index || R_i || P), SEED_BYTES bytes."""
        return _sha256(TAG_KDF, transcript_hash, _u32(index), Ec.encode_point(ri), Ec.encode_point(p))[:SEED_BYTES]

    @staticmethod
    def kos_chi_words(binding: bytes, round: int, u, m_ext: int, col_bytes_list=None) -> List[int]:
        """The KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column of u."""
        col_bytes = (m_ext + 7) // 8
        cols = col_bytes_list if col_bytes_list is not None else [Otx.big_to_bytes(c, col_bytes) for c in u]
        inp = TAG_KOS + _u32(len(binding)) + bytes(binding) + _u32(round) + _u32(m_ext) + _u32(len(u)) + b"".join(cols)
        return Otx.words_from_le_bytes(Libcrypto.shake256(inp, m_ext * 16), m_ext * 4)

    @staticmethod
    def kos_challenges(binding: bytes, round: int, u, m_ext: int) -> List[int]:
        w = Ot.kos_chi_words(binding, round, u, m_ext)
        return [Otx.gf_to_big(w, 4 * j) for j in range(m_ext)]

    # ---- base OT ----

    @staticmethod
    def ot_commit(i: int, b: int, msg: bytes, pad: bytes) -> bytes:
        return _sha256(TAG_COMMIT, _u32(i), bytes([b & 1]), msg, pad)

    @staticmethod
    def mal_base_random_ot(choices, rng=None, tamper: Optional[BaseOtTamper] = None, binding: Optional[BaseOtBinding] = None) -> MalRandomOtResult:
        rng = rng or Ot.secure_ot_random()
        binding = binding or Ot.random_binding(rng, "base-ot")
        setup = Ot.mal_base_ot_sender_setup(rng, binding)
        s = tamper.tamper_s(setup.s) if tamper is not None and tamper.tamper_s else setup.s
        proof = tamper.tamper_proof(setup.proof) if tamper is not None and tamper.tamper_proof else setup.proof
        rr = Ot.mal_base_ot_receiver_respond(s, proof, choices, rng, binding)
        if tamper is not None and tamper.tamper_r:
            tamper.tamper_r(rr.r)
        sender_pads = Ot.mal_base_ot_sender_derive(setup.y, setup.t, rr.r, s, binding)
        return MalRandomOtResult(s, proof, rr.r, sender_pads, rr.recv_pads)

    @staticmethod
    def mal_base_ot_sender_setup(rng, binding: BaseOtBinding) -> SenderSetup:
        ctx = Ot.binding_bytes(binding)
        y = rng.scalar()
        s = Ec.mul_base(y)
        t = Ec.mul(y, s)
        proof = Ec.schnorr_prove(y, s, lambda: rng.scalar(), ctx)
        return SenderSetup(y, t, s, proof)

    @staticmethod
    def mal_base_ot_receiver_respond(s: Point, proof: SchnorrProof, choices, rng, binding: BaseOtBinding) -> ReceiverResponse:
        ctx = Ot.binding_bytes(binding)
        Ec.assert_in_subgroup(s, "base-OT S (received by receiver)")
        if not Ec.schnorr_verify(s, proof, ctx):
            raise BaseOtAbort("base OT: sender Schnorr proof-of-knowledge of S=y*B failed; aborting")
        xs: List[int] = []
        r: List[Point] = []
        for c in choices:
            x = rng.scalar()
            xs.append(x)
            r.append(Ec.add_points(Ec.mul_base(x), s) if (c & 1) == 1 else Ec.mul_base(x))
        th = Ot.base_ot_transcript_hash(binding, s, r)
        return ReceiverResponse(r, [Ot.base_ot_kdf(th, i, r[i], Ec.mul(xs[i], s)) for i in range(len(choices))])

    @staticmethod
    def mal_base_ot_sender_derive(y: int, t: Point, r: List[Point], s: Point, binding: BaseOtBinding) -> list:
        for i, p in enumerate(r):
            Ec.assert_in_subgroup(p, "base-OT R_%d (received by sender)" % i)
        th = Ot.base_ot_transcript_hash(binding, s, r)
        out = []
        for i, ri in enumerate(r):
            yr = Ec.mul(y, ri)
            out.append([Ot.base_ot_kdf(th, i, ri, yr), Ot.base_ot_kdf(th, i, ri, Ec.sub(yr, t))])
        return out

    @staticmethod
    def base_ot_sender_encrypt(messages, sender_pads):
        """One-time-pads the messages under the sender pads and commits to each (message, pad). Returns (ct, com)."""
        if len(messages) != len(sender_pads):
            raise ValueError("baseOT: messages/pads length mismatch")
        for i, (m0, m1) in enumerate(messages):
            if len(m0) > SEED_BYTES or len(m1) > SEED_BYTES or len(m0) != len(m1):
                raise ValueError("baseOT: message pair %d must be equal length and at most %d bytes (pad width)" % (i, SEED_BYTES))
        ct = [[_xor_bytes(m[0], sender_pads[i][0]), _xor_bytes(m[1], sender_pads[i][1])] for i, m in enumerate(messages)]
        com = [[Ot.ot_commit(i, 0, m[0], sender_pads[i][0]), Ot.ot_commit(i, 1, m[1], sender_pads[i][1])] for i, m in enumerate(messages)]
        return ct, com

    @staticmethod
    def base_ot_receiver_decrypt(choices, recv_pads, ct, com) -> List[bytes]:
        if len(ct) != len(choices) or len(com) != len(choices) or len(recv_pads) != len(choices):
            raise BaseOtAbort("base OT: ciphertext/commitment count does not match the number of choices; aborting")
        out = []
        for i, c in enumerate(choices):
            ci = c & 1
            c0, c1 = ct[i]
            if len(c0) != len(c1) or len(c0) > SEED_BYTES:
                raise BaseOtAbort("base OT (index %d): malformed ciphertext shape; aborting" % i)
            m = _xor_bytes(ct[i][ci], recv_pads[i])
            if not _ct_eq(Ot.ot_commit(i, ci, m, recv_pads[i]), com[i][ci]):
                raise BaseOtAbort("base OT (index %d): sender ciphertext inconsistent with its commitment; aborting" % i)
            out.append(m)
        return out

    @staticmethod
    def base_ot(messages, choices, rng=None, tamper: Optional[BaseOtTamper] = None, binding: Optional[BaseOtBinding] = None) -> BaseOtResult:
        """Chosen-message 1-of-2 OT for len(choices) transfers, built over the random base OT."""
        rng = rng or Ot.secure_ot_random()
        binding = binding or Ot.random_binding(rng, "base-ot")
        if len(messages) != len(choices):
            raise ValueError("baseOT: messages/choices length mismatch")
        ro = Ot.mal_base_random_ot(choices, rng, tamper, binding)
        ct, com = Ot.base_ot_sender_encrypt(messages, ro.sender_pads)
        if tamper is not None and tamper.tamper_ciphertext:
            tamper.tamper_ciphertext(ct)
        received = Ot.base_ot_receiver_decrypt(choices, ro.recv_pads, ct, com)
        return BaseOtResult(received, BaseOtTranscript(ro.s, ro.proof, ro.r, ct, com))

    # ---- OT extension (IKNP + KOS) ----

    @staticmethod
    def check_ext_inputs(choice_bits, msg0, msg1) -> None:
        m = len(choice_bits)
        limit = 1 << 64
        for j, b in enumerate(choice_bits):
            if isinstance(b, bool) or b not in (0, 1):
                raise ValueError("OtChannel.extend: choice bit %d must be 0 or 1" % j)
        if msg0 is None or msg1 is None:
            return
        for j in range(m):
            a = msg0[j]
            b = msg1[j]
            if a is None or b is None or a < 0 or b < 0 or a >= limit or b >= limit:
                raise ValueError("OtChannel.extend: message %d must be a bigint in [0, 2^64) (the pad is 64 bits wide)" % j)
