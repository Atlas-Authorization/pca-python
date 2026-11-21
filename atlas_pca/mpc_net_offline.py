"""The NO-DEALER offline phase over the mutual-TLS mesh (research prototype), port of the reference's net/offline-net.ts.

Each party is its own process holding only its own shares. Every party samples its own MAC key shares and triple shares, and the products needed
for the triples and the MACs are computed by Gilboa OT multiplication between every ordered pair of parties:

  ob-S / ob-R / ob-C   all-to-all  the kappa = 128 base OTs of every ordered pair (malicious-secure, session-bound Chou-Orlandi)
  in-share             all-to-all  each owner splits every input bit into additive shares and sends one to each peer
  ox<layer>.<chunk>.u  all-to-all  OT-extension receiver messages (u matrix + KOS pair) -> KOS correlation check
  ox<layer>.<chunk>.y  all-to-all  OT-extension sender ciphertexts

Layer 1 = the triple products and the MACs of every value known before them; layer 2 = the MACs of the products; layer 3 = the pairwise tags
T_ij = K_ij + Delta_j * x_i (identifiable abort). Receivers choose with the privacy-amplified encoding of their share under a gadget all parties
contribute a signed seed to. The triple sacrifice and the input-consistency opening run in the online phase. No security proof."""
from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from .mpc import PRIME, Enc, EncShare, Field, SecureFieldRng, Thermometer
from .mpc_ec import PointValidationError, SchnorrProof
from .mpc_mesh import Mesh
from .mpc_net import AW, PA, NetAbort, NetWire, SlotDisclosure, js_utf8
from .mpc_net_gadget import GadgetIo, agree_gadget_seeds
from .mpc_net_ot import J, b64, hex_big, j_pt, pt_j, unb64
from .mpc_net_prep import T_M, Behavior, Forensics, Prep, sharings_per_triple
from .mpc_ot import KAPPA, SSEC, BaseOtAbort, BaseOtBinding, MalOtAbort, Ot, OtExtReceiver, OtExtSender

ROWS_PER_ROUND = 128 * Enc.FIELD_BITS  # most OT rows per extension round (bounds frame size and memory)
_MASK61 = (1 << 61) - 1
_LIMIT = Field.LIMIT
_hx = NetWire.hx


@dataclass
class OfflineNetArgs:
    mesh: Mesh
    id: int
    n: int
    C: int
    keys: int
    partners: int
    session_id: str
    input: Any  # mpc.DecisionVector: allow, t, r_quant
    Q: int
    behavior: Optional[Behavior]  # TEST ONLY (gated by the caller): an offline misbehaviour of this party
    exchange: Callable[..., Awaitable[Dict[int, Any]]]  # exchange(rd, mine, parse, timeout_ms=None)
    crash_if: Callable[[str], None]
    bad: Callable[[int, str], Any]
    arr: Callable[[int, Any, int], List[int]]


class _Item:
    """One OT multiplication item: my choice bits (weights `gad`, public) against my sender operand `y`."""

    __slots__ = ("bits", "gad", "y")

    def __init__(self, bits, gad, y):
        self.bits = bits
        self.gad = gad
        self.y = y


class _Kept:
    """Per-row transcript of selected items (for post-abort attribution)."""

    __slots__ = ("recv", "rho")

    def __init__(self):
        self.recv: Dict[int, Dict[int, List[int]]] = {}
        self.rho: Dict[int, Dict[int, List[int]]] = {}


def _fvec(k: int) -> List[int]:
    """k uniform field elements by rejection sampling over 64-bit CSPRNG words (same distribution as SecureFieldRng.next)."""
    out: List[int] = []
    while len(out) < k:
        need = k - len(out)
        for u in struct.unpack(">%dQ" % need, secrets.token_bytes(8 * need)):
            if u < _LIMIT:
                out.append(u % PRIME)
    return out


class _FnRng:
    """A field source over a callable (the gadget hash chain); make_gadget calls .next()."""

    def __init__(self, f):
        self.next = f


def _gadget_from_seeds(session_id: str, seeds: List[bytes]) -> List[int]:
    """The public gadget: H(all seeds in party order || session) expanded by a hash chain; every party contributed a committed seed."""
    h0 = hashlib.sha256(b"atlas-pca-mpc/enc-gadget" + js_utf8(session_id))
    for sd in seeds:
        h0.update(sd)
    seed = h0.digest()
    ctr = [0]

    def nxt() -> int:
        while True:
            h = hashlib.sha256(seed + ctr[0].to_bytes(8, "little")).digest()
            ctr[0] += 1
            v = int.from_bytes(h[:8], "little") & _MASK61
            if v < PRIME:
                return v

    return Enc.make_gadget(Enc.STAT_SEC, _FnRng(nxt))


def _hex128(s: Any) -> int:
    if not isinstance(s, str) or not _is_hex128(s):
        raise ValueError("bad 128-bit value")
    return int(s, 16)


def _is_hex128(s: str) -> bool:
    if s == "0":
        return True
    return 1 <= len(s) <= 32 and s[0] != "0" and all(c in "0123456789abcdef" for c in s)


def _encode_u(msg, m_ext: int) -> dict:
    if not isinstance(m_ext, int) or isinstance(m_ext, bool) or not 0 < m_ext <= 1 << 20:
        raise ValueError("u encoding: width out of range")
    cb = (m_ext + 7) // 8
    mask = (1 << (8 * cb)) - 1
    return {"u": b64(b"".join((c & mask).to_bytes(cb, "little") for c in msg.u)), "x": _hx(msg.x), "t": _hx(msg.t_comb)}


def _decode_u(raw: Any, m_ext: int):
    if not J(raw):
        raise ValueError("bad extension message")
    cb = (m_ext + 7) // 8
    data = unb64(raw.get("u"), KAPPA * cb)
    u = [int.from_bytes(data[i * cb:(i + 1) * cb], "little") for i in range(KAPPA)]
    return Ot.ExtRoundMsg(u, _hex128(raw.get("x")), _hex128(raw.get("t")))


def _words64(vs: List[int]) -> bytes:
    return struct.pack("<%dQ" % len(vs), *vs)


def _encode_y(y0: List[int], y1: List[int]) -> dict:
    return {"y0": b64(_words64(y0)), "y1": b64(_words64(y1))}


def _decode_y(raw: Any, m: int):
    if not J(raw):
        raise ValueError("bad ciphertext message")
    a = unb64(raw.get("y0"), m * 8)
    b = unb64(raw.get("y1"), m * 8)
    return list(struct.unpack("<%dQ" % m, a)), list(struct.unpack("<%dQ" % m, b))


def _pairs_b64(ps) -> list:
    return [[b64(a), b64(b)] for a, b in ps]


def _parse_pairs(raw: Any, count: int, length: int) -> list:
    if not isinstance(raw, list) or len(raw) != count:
        raise ValueError("bad pair array")
    out = []
    for p in raw:
        if not isinstance(p, list) or len(p) != 2:
            raise ValueError("bad pair")
        out.append((unb64(p[0], length), unb64(p[1], length)))
    return out


async def run_offline_net(a: OfflineNetArgs) -> Prep:
    mesh, ident, n, C, K, P, exchange = a.mesh, a.id, a.n, a.C, a.keys, a.partners, a.exchange
    others = [i for i in range(n) if i != ident]
    rng = Ot.secure_ot_random()
    frng = SecureFieldRng()
    kind = a.behavior.kind if a.behavior is not None else None
    fadd, fsub, fmul, mod = Field.fadd, Field.fsub, Field.fmul, Field.mod
    # my pairwise verification key Delta (non-zero, secret): the key that verifies every share the peers open to me
    delta = frng.next()
    while delta == 0:
        delta = frng.next()
    gadget: List[int] = []  # set by the commit-reveal below, before the first OT multiplication
    sid = hashlib.sha256(b"atlas-pca-mpc/net-session/v2" + js_utf8(mesh.session_id)).digest()

    def chan(recv: int, send: int, rnd: str) -> BaseOtBinding:
        """Binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is `recv` and extension sender is `send`."""
        return BaseOtBinding(sid, recv, send, rnd)

    def ot_guard(peer: int, what: str, f):
        """Run a check that may throw an OT error, turning it into an abort that names `peer`."""
        try:
            return f()
        except NetAbort:
            raise
        except Exception as e:  # noqa: BLE001
            k = "ot-check" if isinstance(e, (BaseOtAbort, MalOtAbort, PointValidationError)) else "malformed"
            ne = NetAbort(k, peer, ident, "%s: %s" % (what, e))
            mesh.fail(ne)
            raise ne from None

    # ------------------------------------------------------------------ base OTs (kappa per ordered pair, both roles)
    recv_ch: Dict[int, OtExtReceiver] = {}  # I am the extension receiver (base-OT sender) towards `peer`
    send_ch: Dict[int, OtExtSender] = {}  # I am the extension sender (base-OT receiver) towards `peer`
    seeds: Dict[int, list] = {}
    my_setup: Dict[int, Any] = {}
    selector: Dict[int, List[int]] = {}
    for p in others:
        r = OtExtReceiver(rng, Ot.binding_bytes(chan(ident, p, "iknp-kos")))
        seeds[p] = r.make_seeds()
        recv_ch[p] = r
        my_setup[p] = Ot.mal_base_ot_sender_setup(rng, chan(ident, p, "offline-kappa"))
        s = OtExtSender(rng, Ot.binding_bytes(chan(p, ident, "iknp-kos")))
        selector[p] = s.make_selector()
        send_ch[p] = s

    def mine_s(peer):
        st = my_setup[peer]
        z = st.proof.z + 1 if kind == "ot-proof-lie" else st.proof.z
        return {"S": pt_j(st.s), "U": pt_j(st.proof.u), "z": _hx(z)}

    def parse_s(p, raw):
        if not J(raw):
            return a.bad(p, "bad S message")
        proof = SchnorrProof(j_pt(raw.get("U")), hex_big(raw.get("z")))
        return j_pt(raw.get("S")), proof

    their_s = await exchange("ob-S", mine_s, parse_s)
    respond: Dict[int, Any] = {}
    for p in others:
        s_pt, proof = their_s[p]
        respond[p] = ot_guard(p, "base OT (receiver)", lambda s_pt=s_pt, proof=proof, p=p: Ot.mal_base_ot_receiver_respond(s_pt, proof, selector[p], rng, chan(p, ident, "offline-kappa")))

    def parse_r(p, raw):
        if not isinstance(raw, list) or len(raw) != KAPPA:
            return a.bad(p, "bad R array")
        return [j_pt(x) for x in raw]

    their_r = await exchange("ob-R", lambda peer: [pt_j(x) for x in respond[peer].r], parse_r)
    enc: Dict[int, Any] = {}
    for p in others:
        st = my_setup[p]

        def derive(st=st, p=p):
            pads = Ot.mal_base_ot_sender_derive(st.y, st.t, their_r[p], st.s, chan(ident, p, "offline-kappa"))
            return Ot.base_ot_sender_encrypt(seeds[p], pads)

        enc[p] = ot_guard(p, "base OT (sender)", derive)

    def parse_c(p, raw):
        if not J(raw):
            return a.bad(p, "bad ciphertext message")
        return _parse_pairs(raw.get("ct"), KAPPA, 16), _parse_pairs(raw.get("com"), KAPPA, 32)

    their_ct = await exchange("ob-C", lambda peer: {"ct": _pairs_b64(enc[peer][0]), "com": _pairs_b64(enc[peer][1])}, parse_c)
    for p in others:
        ct, com = their_ct[p]
        got = ot_guard(p, "base OT (receiver)", lambda ct=ct, com=com, p=p: Ot.base_ot_receiver_decrypt(selector[p], respond[p].recv_pads, ct, com))
        send_ch[p].set_seeds(got)

    # ------------------------------------------------------------------ the jointly contributed choice-bit gadget
    # signed commit / reveal / echo: one corrupt party cannot give different honest parties different gadgets
    seeds_agreed = await agree_gadget_seeds(mesh, n, GadgetIo(exchange, a.bad))
    gadget = _gadget_from_seeds(mesh.session_id, seeds_agreed)
    plain_gad = Enc.plain_gadget()

    # ------------------------------------------------------------------ the OT multiplication layer (Gilboa)
    async def ot_rows(layer: str, items: List[_Item], keep: Optional[Set[int]] = None):
        """The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my item and get
        recv[p][t] = x_t*y^p_t + sum(rho^p_t); as the OT SENDER I offer (rho_k, rho_k + gad_k*y) with fresh masks and keep send_sum[p][t] = sum(rho)."""
        T = len(items)
        recv = {p: [0] * T for p in others}
        send_sum = {p: [0] * T for p in others}
        kept = _Kept()
        for p in others:
            kept.recv[p] = {}
            kept.rho[p] = {}
        if T == 0 or not others:
            return recv, send_sum, kept
        rows = sum(len(it.bits) for it in items)
        row_item = [0] * rows
        choice = [0] * rows
        m0 = {p: [0] * rows for p in others}
        m1 = {p: [0] * rows for p in others}
        item_off = [0] * T
        off = 0
        for t in range(T):
            it = items[t]
            ln = len(it.bits)
            item_off[t] = off
            kt = keep is not None and t in keep
            if kt:
                for p in others:
                    kept.recv[p][t] = [0] * ln
            choice[off:off + ln] = it.bits
            row_item[off:off + ln] = [t] * ln
            y = it.y
            gad = it.gad
            for p in others:
                rhos = _fvec(ln)
                m0[p][off:off + ln] = rhos
                m1[p][off:off + ln] = [(r + g * y) % PRIME for r, g in zip(rhos, gad)]
                send_sum[p][t] = sum(rhos) % PRIME
                if kt:
                    kept.rho[p][t] = list(rhos)
            off += ln
        chunk = 0
        for start in range(0, rows, ROWS_PER_ROUND):
            end = min(rows, start + ROWS_PER_ROUND)
            m = end - start
            m_ext = m + KAPPA + SSEC
            tag = "ox%s.%d" % (layer, chunk)
            chunk += 1
            if kind == "ot-u-lie":
                # an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
                def lie(u, _r):
                    for i in range(64):
                        u[i] = u[i] ^ 1

                for p in others:
                    recv_ch[p].tamper_u = lie
            begun = {p: recv_ch[p].begin_round(choice[start:end]) for p in others}
            us = await exchange(tag + ".u", lambda peer: _encode_u(begun[peer].msg, m_ext), lambda p, raw: _decode_u(raw, m_ext))
            ys2 = {}
            for p in others:
                ys2[p] = ot_guard(p, "OT extension (%s)" % tag,
                                  lambda p=p: send_ch[p].respond(us[p], m0[p][start:end], m1[p][start:end]))
            cts = await exchange(tag + ".y", lambda peer: _encode_y(ys2[peer].y0, ys2[peer].y1), lambda p, raw: _decode_y(raw, m))
            for p in others:
                got = ot_guard(p, "OT extension (%s)" % tag,
                               lambda p=p: recv_ch[p].finish(begun[p].pending, cts[p][0], cts[p][1]))
                rv = recv[p]
                kr = kept.recv[p]
                for j in range(m):
                    t = row_item[start + j]
                    g = got[j] % PRIME
                    rv[t] = (rv[t] + g) % PRIME
                    if t in kr:
                        kr[t][start + j - item_off[t]] = g
        return recv, send_sum, kept

    async def mul_layer(layer: str, xs: List[EncShare], ys: List[int], lie_at: int = -1, keep: Optional[Set[int]] = None):
        """Given my shares xs[t] of X_t and ys[t] of Y_t, return my additive share of X_t*Y_t: the diagonal locally plus, for every ordered
        pair, the Gilboa OT product of one party's x with the other's y."""
        z = [fmul(x.value, ys[t]) for t, x in enumerate(xs)]
        items = [_Item(x.bits, gadget, fadd(ys[t], 1) if t == lie_at else ys[t]) for t, x in enumerate(xs)]
        recv, send_sum, kept = await ot_rows(layer, items, keep)
        for p in others:
            rv = recv[p]
            ss = send_sum[p]
            for t in range(len(z)):
                z[t] = fsub(fadd(z[t], rv[t]), ss[t])
        return z, kept

    async def tag_layer(layer: str, xs: List[int]):
        """Pairwise tags: for every peer j, a tag T_ij (mine) and a key K_ij with T_ij = K_ij + Delta_j * x_i, via one OT product of my x with
        j's Delta per item. Each x is split as x = e + d with a fresh encoded e and d = x - e; both halves are multiplied with Delta."""
        items: List[_Item] = []
        for x in xs:
            e = Enc.sample_enc(gadget, frng)
            d = Enc.plain_share(fsub(x, e.value))
            items.append(_Item(e.bits, gadget, delta))
            items.append(_Item(d.bits, plain_gad, delta))
        recv, send_sum, _ = await ot_rows(layer, items)
        tag: Dict[int, List[int]] = {}
        key: Dict[int, List[int]] = {}
        for p in others:
            r = recv[p]
            k = send_sum[p]
            tag[p] = [fadd(r[2 * u], r[2 * u + 1]) for u in range(len(xs))]
            key[p] = [fadd(k[2 * u], k[2 * u + 1]) for u in range(len(xs))]
        return tag, key

    # ------------------------------------------------------------------ my randomness and the input sharings
    alpha_enc = [Enc.sample_enc(gadget, frng) for _ in range(K)]
    alpha_share = [e.value for e in alpha_enc]
    my_bits = [a.input.allow] + Thermometer.thermometer_encode(a.input.t, T_M) + Thermometer.thermometer_encode(a.input.r_quant, a.Q)
    if len(my_bits) != C:
        raise NetAbort("local", None, ident, "input chain count mismatch")
    # split each of my bits into additive shares: a random share for every peer, the rest is mine
    out_shares = {p: [frng.next() for _ in range(C)] for p in others}
    my_own = []
    for c, b in enumerate(my_bits):
        s = int(b)
        for p in others:
            s = fsub(s, out_shares[p][c])
        my_own.append(s)
    got_shares = await exchange("in-share", lambda peer: [_hx(v) for v in out_shares[peer]], lambda p, raw: a.arr(p, raw, C))
    input_value: List[int] = []  # my value share of every (owner, chain)
    for o in range(n):
        for c in range(C):
            input_value.append(my_own[c] if o == ident else got_shares[o][c])
    mask_share = frng.next()  # my share of the input-check mask

    nT = (n - 1) * C
    a_e: List[EncShare] = []
    b_s: List[int] = []
    ah_e: List[List[EncShare]] = []
    for _ in range(nT):
        a_e.append(Enc.sample_enc(gadget, frng))
        b_s.append(frng.next())
        ah_e.append([Enc.sample_enc(gadget, frng) for _ in range(P)])
    a_s = [e.value for e in a_e]
    ah_s = [[e.value for e in row] for row in ah_e]

    # ------------------------------------------------------------------ layer 1: products and the MACs of known values
    xs1: List[EncShare] = []
    ys1: List[int] = []

    def push1(x: EncShare, y: int) -> int:
        xs1.append(x)
        ys1.append(y)
        return len(xs1) - 1

    i_c: List[int] = []
    i_ch: List[List[int]] = []
    i_ma: List[List[int]] = []
    i_mb: List[List[int]] = []
    i_mah: List[List[List[int]]] = []
    for t in range(nT):
        i_c.append(push1(a_e[t], b_s[t]))
        i_ch.append([push1(ah_e[t][r], b_s[t]) for r in range(P)])
        i_ma.append([push1(al, a_s[t]) for al in alpha_enc])
        i_mb.append([push1(al, b_s[t]) for al in alpha_enc])
        i_mah.append([[push1(al, ah_s[t][r]) for al in alpha_enc] for r in range(P)])
    i_in = [[push1(al, val) for al in alpha_enc] for val in input_value]
    i_mask = [push1(al, mask_share) for al in alpha_enc]
    keep_items = set(i_c) | {i for row in i_ch for i in row}
    z1, kept1 = await mul_layer("1", xs1, ys1, i_c[0] if kind == "offline-lie" and i_c else -1, keep_items)

    # ------------------------------------------------------------------ layer 2: the MACs of the products
    c_s = [z1[i] for i in i_c]
    ch_s = [[z1[i] for i in row] for row in i_ch]
    xs2: List[EncShare] = []
    ys2_: List[int] = []

    def push2(x: EncShare, y: int) -> int:
        xs2.append(x)
        ys2_.append(y)
        return len(xs2) - 1

    i_mc: List[List[int]] = []
    i_mch: List[List[List[int]]] = []
    for t in range(nT):
        i_mc.append([push2(al, c_s[t]) for al in alpha_enc])
        i_mch.append([[push2(al, chv) for al in alpha_enc] for chv in ch_s[t]])
    z2, _ = await mul_layer("2", xs2, ys2_)

    # ------------------------------------------------------------------ assemble, then pairwise-tag every share
    def pa(x: int) -> PA:
        return PA(x, [0] * n, [0] * n)

    def aw(value: int, mac_idx: List[int], z: List[int]) -> AW:
        return AW(pa(value), [pa(z[i]) for i in mac_idx])

    triples: List[List[AW]] = []
    for t in range(nT):
        sh = [aw(a_s[t], i_ma[t], z1), aw(b_s[t], i_mb[t], z1), aw(c_s[t], i_mc[t], z2)]
        for r in range(P):
            sh.append(aw(ah_s[t][r], i_mah[t][r], z1))
            sh.append(aw(ch_s[t][r], i_mch[t][r], z2))
        if len(sh) != sharings_per_triple(P):
            raise NetAbort("local", None, ident, "triple assembly mismatch")
        triples.append(sh)
    inputs = [aw(val, i_in[q], z1) for q, val in enumerate(input_value)]
    check_mask = aw(mask_share, i_mask, z1)
    alpha = [pa(x) for x in alpha_share]
    all_pa: List[PA] = list(alpha)
    for w in [w for tr in triples for w in tr] + inputs + [check_mask]:
        all_pa.append(w.v)
        all_pa.extend(w.m)
    tags, keys = await tag_layer("3", [x.x for x in all_pa])
    for u, x in enumerate(all_pa):
        for p in others:
            x.tag[p] = tags[p][u]
            x.key[p] = keys[p][u]

    def disclose(t: int) -> List[SlotDisclosure]:
        def slot(item: int, x: EncShare, z: int) -> SlotDisclosure:
            return SlotDisclosure(list(x.bits), b_s[t], z, {p: kept1.recv[p][item] for p in others}, {p: kept1.rho[p][item] for p in others})

        return [slot(i_c[t], a_e[t], c_s[t])] + [slot(item, ah_e[t][r], ch_s[t][r]) for r, item in enumerate(i_ch[t])]

    return Prep(mode="no-dealer", tagged=True, delta=delta, alpha=alpha, triples=triples, inputs=inputs, my_plain=[int(b) for b in my_bits],
                check_mask=check_mask, forensics=Forensics(gadget=gadget, rows=len(gadget), slots=1 + P, disclose=disclose))
