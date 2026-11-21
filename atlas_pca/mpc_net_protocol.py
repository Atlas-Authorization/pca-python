"""The DISTRIBUTED malicious-with-abort (SPDZ-style) composition protocol (research prototype), port of the reference's net/protocol.ts.

Same circuit and semantics as `compose_secure_malicious` (allow = AND, t = MAX, r = MAX via thermometers; authenticated Beaver
multiplication; batched MAC-check before any output), but each party is its OWN node holding ONLY its own shares, and every opening is a
real message over the mutual-TLS mesh (mpc_mesh). Rounds (n parties, C = 1 + 3 + Q independent chains, k = MAC_KEYS global keys):

  prep     dealer -> party   : [trusted-dealer mode] key shares, sacrificed-triple material, input masks, pairwise tags
                               (no-dealer mode: the OT-based offline phase of mpc_net_offline runs here instead)
  coin1-*  all-to-all        : commit/open of a random seed -> public challenges for the triple sacrifice
  sac-rho  all-to-all        : value shares of rho = e*a - a-hat for every triple and sacrifice partner
  sac-tau  all-to-all        : value shares of tau = e*c - c-hat - rho*b; every tau must be 0
  inputs   all-to-all        : [dealer mode] owner broadcasts x - r (r is the owner's dealer-given mask)
  in-check all-to-all        : [no-dealer mode] opening of a masked random combination of the inputs
  mul0..   all-to-all        : value shares of d = x-a, e = y-b for all C chains at once (n-1 rounds)
  out      all-to-all        : value shares of the C output bits
  <rd>.t   all-to-all        : after every opening, the pairwise tags: each receiver verifies the sender's opened shares at once
  coin-c/o all-to-all        : commit/open of a random seed -> public MAC-check challenges
  sig-c/o  all-to-all        : commit/open of each party's MAC residual shares (one per key); sums must be 0
  digest   all-to-all        : hash of the whole broadcast transcript; any disagreement aborts
  blame    all-to-all        : only after a failed MAC-check: every party opens its combined MAC shares and key shares with their
                               pairwise tags; each verifier checks them and names the party whose data is inconsistent

No output is decoded until the MAC-check and the transcript echo pass. Timeouts, malformed/duplicate/out-of-order frames, disconnects and
aborts are handled by the mesh. HONEST LIMITS: no security proof; the echo-broadcast is a hash exchange, not Byzantine agreement; a trusted
dealer is trusted for privacy; in no-dealer mode a wrong OT operand in the offline triple products is named only for n = 2.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .mpc import ComposedDecision, DecisionVector, Field, FieldRng, SecureFieldRng, Thermometer
from .mpc_mesh import Mesh
from .mpc_net import AW, PA, NetAbort, NetForensics, NetPa, NetWire, PaEnv, js_json, js_utf8
from .mpc_net_forensics import exchange_disclosures
from .mpc_net_prep import Behavior, CrashParty, Prep, SilentParty, T_M, sharings_per_triple  # noqa: F401  (re-exported)
from .mpc_spdz import MAC_KEYS, PRIME, SACRIFICE_PARTNERS, DealerFault, Spdz

fadd, fsub, fmul = Field.fadd, Field.fsub, Field.fmul
hx, unhx_array = NetWire.hx, NetWire.unhx_array
_HEX64 = re.compile(r"[0-9a-f]{64}")

DEFAULT_Q = 100
PREP_CHUNK = 30_000  # hex numbers per `prep` frame


def chain_count(q: int) -> int:
    """Number of independent circuit chains (= output bits = input bits per owner)."""
    return 1 + T_M + q


@dataclass
class RoundStat:
    rd: str
    ms: float
    bytes_out: int
    bytes_in: int


@dataclass
class PartyResult:
    id: int
    n: int
    Q: int
    composed: ComposedDecision
    rounds: List[RoundStat]
    transcript_digest: str
    wall_ms: float
    multiplications: int
    opens: int
    offline_mode: str  # 'trusted-dealer' | 'no-dealer'
    mac_keys: int
    sacrificed_triples: int
    sacrifice_partners: int
    identifiable_abort: bool


@dataclass
class DealerConfig:
    n: int
    mesh: Mesh
    insecure_trusted_dealer: bool = False  # required True
    Q: Optional[int] = None
    seed: Optional[int] = None  # deterministic stream for reproducible tests; None = CSPRNG
    fault: Optional[DealerFault] = None  # TEST ONLY: a lying dealer
    mac_fault_at_input: Optional[int] = None  # TEST ONLY: a wrong MAC share of that input mask for party 0


@dataclass
class PartyConfig:
    id: int
    n: int
    input: DecisionVector
    mesh: Mesh
    session_id: str
    Q: Optional[int] = None
    dealer_id: Optional[int] = None  # default n
    offline: Optional[str] = None  # 'trusted-dealer' | 'no-dealer' (default)
    insecure_trusted_dealer: bool = False
    behavior: Optional[Behavior] = None  # TEST ONLY
    unsafe_test_hooks: bool = False
    forensic_deadline_ms: Optional[int] = None  # default 30 s


def _prep_layout(n: int, C: int, keys: int, partners: int, tagged: bool) -> Dict[str, int]:
    """Canonical numbers per party in a dealer `prep` frame."""
    aw = NetPa.aw_width(n, keys, tagged)
    triples = (n - 1) * C
    inputs = n * C
    nums = (1 if tagged else 0) + keys * NetPa.pa_width(n, tagged) + triples * sharings_per_triple(partners) * aw + inputs * aw + C
    return {"nums": nums, "triples": triples, "inputs": inputs}


# ---------------------------------------------------------------------------------------------------------------------- dealer

async def run_dealer(cfg: DealerConfig) -> None:
    """The TRUSTED DEALER role: samples the MAC keys, the verification keys, sacrifice-certified authenticated triples and authenticated
    input masks, and ships each party only its own slice. It never sees any input bit (inputs are masked by r), but it knows every key and
    share, so it can break privacy/integrity if it colludes with parties. A dealer that deals a wrong triple is caught by the parties' sacrifice."""
    n, mesh = cfg.n, cfg.mesh
    if cfg.insecure_trusted_dealer is not True:
        raise ValueError("run_dealer requires insecure_trusted_dealer=True (a dealer sees every share and MAC key; the default offline phase has no dealer)")
    Q = DEFAULT_Q if cfg.Q is None else cfg.Q
    rng = FieldRng(cfg.seed) if cfg.seed is not None else SecureFieldRng()
    C = chain_count(Q)
    ctx = Spdz.setup_mac(n, rng, MAC_KEYS)
    keys = Spdz.mac_keys(ctx)
    deltas: List[int] = []
    for _ in range(n):
        d = rng.next()
        while d == 0:
            d = rng.next()
        deltas.append(d)

    def deal_pa(x: List[int]) -> List[PA]:
        """The pairwise tags/keys for one sharing x_0..x_{n-1}: T_ij = K_ij + delta_j * x_i."""
        K = [[0 if i == j else rng.next() for j in range(n)] for i in range(n)]
        return [PA(xi, [0 if j == p else fadd(K[p][j], fmul(deltas[j], xi)) for j in range(n)], [0 if j == p else K[j][p] for j in range(n)])
                for p, xi in enumerate(x)]

    def deal_aw(sv) -> List[AW]:
        comps = [deal_pa(c) for c in [sv.value, sv.mac] + list(sv.extra_mac)]
        return [AW(comps[0][p], [c[p] for c in comps[1:]]) for p in range(n)]

    per_party: List[List[int]] = [[deltas[p]] for p in range(n)]
    alpha_pa = [deal_pa(k.alpha_shares) for k in keys]
    for p in range(n):
        for a in alpha_pa:
            per_party[p].extend(NetPa.pa_flat(a[p], p, n, True))
    for _t in range((n - 1) * C):
        tr = Spdz.gen_triple_with_partners(ctx, rng, SACRIFICE_PARTNERS, cfg.fault)
        sharings = [tr.keep.a, tr.keep.b, tr.keep.c]
        for q in tr.partners:
            sharings += [q.a, q.c]
        for sv in sharings:
            aws = deal_aw(sv)
            for p in range(n):
                per_party[p].extend(NetPa.aw_flat(aws[p], p, n, True))
    masks_by_owner: List[List[int]] = [[] for _ in range(n)]
    for q in range(n * C):
        owner = q // C
        r = rng.next()
        masks_by_owner[owner].append(r)
        sv = Spdz.auth_share(r, ctx, rng)
        if cfg.mac_fault_at_input == q:
            sv.mac[0] = fadd(sv.mac[0], 1)
        aws = deal_aw(sv)
        for p in range(n):
            per_party[p].extend(NetPa.aw_flat(aws[p], p, n, True))
    for p in range(n):
        per_party[p].extend(masks_by_owner[p])

    for p in range(n):
        nums = [hx(v) for v in per_party[p]]
        chunks = max(1, -(-len(nums) // PREP_CHUNK))
        mesh.send(p, "prep", {"total": len(nums), "chunks": chunks, "nums": nums[:PREP_CHUNK]})
        for c in range(1, chunks):
            mesh.send(p, "prep.%d" % c, nums[c * PREP_CHUNK:(c + 1) * PREP_CHUNK])
    await mesh.finish()


# ---------------------------------------------------------------------------------------------------------------------- party

def _sha(*parts: Any) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(js_utf8(p) if isinstance(p, str) else bytes(p))
        h.update(b"\x00")
    return h.digest()


def _challenge(seed: bytes, label: str, j: int) -> int:
    """Uniform non-zero field element j of the public challenge stream `label` derived from `seed` (rejection on p)."""
    ctr = 0
    while True:
        h = _sha("chal", seed, "%s:%d:%d" % (label, j, ctr))
        x = int.from_bytes(h[:8], "big") & ((1 << 61) - 1)
        if 0 < x < PRIME:
            return x
        ctr += 1


@dataclass
class _Opened:
    val: int
    mac: List[PA]  # my MAC share (with its pairwise tags/keys) under each key, as used at this opening


def _js_bytes(v: Any) -> bytes:
    return js_utf8(js_json(v))


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


async def run_party(cfg: PartyConfig) -> PartyResult:
    id_, n, mesh, session_id = cfg.id, cfg.n, cfg.mesh, cfg.session_id
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise NetAbort("local", None, id_, "n must be >= 1")
    Q = DEFAULT_Q if cfg.Q is None else cfg.Q
    dealer_id = n if cfg.dealer_id is None else cfg.dealer_id
    offline_mode = cfg.offline or "no-dealer"
    if offline_mode == "trusted-dealer" and cfg.insecure_trusted_dealer is not True:
        raise NetAbort("local", None, id_, "offline 'trusted-dealer' requires insecure_trusted_dealer=True (the dealer sees every share and key); the default is 'no-dealer'")
    if offline_mode not in ("trusted-dealer", "no-dealer"):
        raise NetAbort("local", None, id_, "offline must be 'trusted-dealer' or 'no-dealer'")
    C = chain_count(Q)
    K = MAC_KEYS
    P = SACRIFICE_PARTNERS
    if cfg.behavior is not None and cfg.unsafe_test_hooks is not True:
        raise NetAbort("local", None, id_, "the behavior test hook requires unsafe_test_hooks=True (test-only)")
    beh = cfg.behavior
    t0 = _now_ms()
    rounds: List[RoundStat] = []
    transcript = hashlib.sha256()
    others = [i for i in range(n) if i != id_]

    v = cfg.input
    if (v.allow not in (0, 1) or isinstance(v.allow, bool) or v.t not in (1, 2, 3) or isinstance(v.t, bool)
            or isinstance(v.r_quant, bool) or not isinstance(v.r_quant, int) or v.r_quant < 0 or v.r_quant > Q):
        raise NetAbort("local", None, id_, "invalid decision vector")

    def totals():
        o = i = 0
        for s in mesh.stats():
            o += s["appBytesOut"]
            i += s["appBytesIn"]
        return o, i

    def crash_if(rd: str) -> None:
        if beh is not None and beh.round == rd:
            if beh.kind == "crash":
                raise CrashParty()
            if beh.kind == "silent":
                raise SilentParty()

    def abort(e: NetAbort):
        mesh.fail(e)
        raise e

    def bad(p: int, what: str):
        raise NetAbort("malformed", p, id_, what)

    def arr(p: int, raw: Any, length: int) -> List[int]:
        r = unhx_array(raw, length)
        return r if r is not None else bad(p, "expected %d canonical field elements" % length)

    async def exchange(rd: str, mine: Callable[[int], Any], parse: Callable[[int, Any], Any], common: Any = None, hashed: bool = True,
                       timeout_ms: Optional[float] = None) -> Dict[int, Any]:
        """One all-to-all round among the parties: send mine(peer) to each peer, collect + validate theirs. hashed=False keeps a round
        (the peer-specific pairwise tags) out of the echoed transcript."""
        crash_if(rd)
        a_out, a_in = totals()
        s = _now_ms()
        for p in others:
            mesh.send(p, rd, mine(p))
        raw = await mesh.collect(rd, others, timeout_ms)
        parsed: Dict[int, Any] = {}
        for p in others:
            try:
                parsed[p] = parse(p, raw.get(p))
            except NetAbort as e:
                mesh.fail(e)
                raise
            except Exception as e:  # noqa: BLE001
                ne = NetAbort("malformed", p, id_, "round '%s': %s" % (rd, e))
                mesh.fail(ne)
                raise ne from None
        if hashed:
            # transcript: party order, canonical JSON of what each party broadcast in this round
            transcript.update(js_utf8(rd))
            for p in range(n):
                transcript.update(("|%d:" % p).encode("utf-8"))
                transcript.update(_js_bytes(common if p == id_ else raw.get(p)))
        b_out, b_in = totals()
        rounds.append(RoundStat(rd, _now_ms() - s, b_out - a_out, b_in - a_in))
        return parsed

    async def exchange_plain(rd, mine, parse, timeout_ms=None):
        return await exchange(rd, mine, parse, None, False, timeout_ms)

    # ---- offline phase: prep from the trusted dealer, or the OT-based no-dealer phase ----
    async def receive_dealer_prep() -> Prep:
        lay = _prep_layout(n, C, K, P, True)
        first = await mesh.recv(dealer_id, "prep")
        try:
            if not isinstance(first, dict) or isinstance(first.get("total"), bool) or first.get("total") != lay["nums"]:
                bad(dealer_id, "bad prep size")
            want_chunks = max(1, -(-lay["nums"] // PREP_CHUNK))
            if isinstance(first.get("chunks"), bool) or first.get("chunks") != want_chunks:
                bad(dealer_id, "bad prep chunk count")

            def take(raw: Any, length: int) -> List[int]:
                r = unhx_array(raw, length)
                return r if r is not None else bad(dealer_id, "bad prep numbers")

            nums = take(first.get("nums"), min(PREP_CHUNK, lay["nums"]))
            for c in range(1, want_chunks):
                part = await mesh.recv(dealer_id, "prep.%d" % c)
                nums = nums + take(part, min(PREP_CHUNK, lay["nums"] - c * PREP_CHUNK))
        except NetAbort as e:
            abort(e)
        o = 0
        delta = nums[o]
        o += 1
        if delta == 0:
            abort(NetAbort("dealer", dealer_id, id_, "the dealer gave me a zero verification key"))
        w = NetPa.pa_width(n, True)
        alpha: List[PA] = []
        for _l in range(K):
            alpha.append(NetPa.pa_parse(nums, o, id_, n, True))
            o += w
        aw = NetPa.aw_width(n, K, True)
        triples: List[List[AW]] = []
        for _t in range(lay["triples"]):
            sh = []
            for _s in range(sharings_per_triple(P)):
                sh.append(NetPa.aw_parse(nums, o, id_, n, K, True))
                o += aw
            triples.append(sh)
        inputs: List[AW] = []
        for _q in range(lay["inputs"]):
            inputs.append(NetPa.aw_parse(nums, o, id_, n, K, True))
            o += aw
        return Prep("trusted-dealer", True, delta, alpha, triples, inputs, nums[o:o + C])

    crash_if("prep")
    prep_start = _now_ms()
    before_out, before_in = totals()
    if offline_mode == "trusted-dealer":
        prep = await receive_dealer_prep()
    else:
        from .mpc_net_offline import OfflineNetArgs, run_offline_net
        prep = await run_offline_net(OfflineNetArgs(mesh=mesh, id=id_, n=n, C=C, keys=K, partners=P, session_id=session_id, input=v, Q=Q,
                                                    behavior=beh, exchange=exchange_plain, crash_if=crash_if, bad=bad, arr=arr))
    after_out, after_in = totals()
    rounds.append(RoundStat("prep", _now_ms() - prep_start, after_out - before_out, after_in - before_in))

    env = PaEnv(id_, n, prep.delta, prep.tagged)

    def add_pub(x: AW, c: int) -> AW:
        return NetPa.w_add_public(env, x, c, prep.alpha)

    def not_(x: AW) -> AW:
        return add_pub(NetPa.w_neg(x), 1)

    w_add, w_sub, w_scale, w_neg = NetPa.w_add, NetPa.w_sub, NetPa.w_scale, NetPa.w_neg

    # ---- retained for the MAC-check / blame: every opened value, with my MAC shares at that opening ----
    opened: List[_Opened] = []

    async def open_many(rd: str, ws: List[AW]) -> List[int]:
        """Open authenticated values: broadcast value shares, verify pairwise tags (dealer mode), record for the MAC-check."""
        send_vals = [x.v.x for x in ws]
        macs = [list(x.m) for x in ws]
        if beh is not None and beh.round == rd:
            if beh.kind == "open-lie":
                send_vals = [fadd(x, 1) if i == 0 else x for i, x in enumerate(send_vals)]
            if beh.kind == "mac-lie":
                macs[0] = [PA(fadd(pa.x, 1), pa.tag, pa.key) if l == 0 else pa for l, pa in enumerate(macs[0])]
        common = [hx(x) for x in send_vals]

        def mine_fn(peer: int) -> Any:
            if beh is not None and beh.round == rd:
                if beh.kind == "equivocate" and peer == others[0]:
                    return [hx(fadd(int(s, 16), 1)) if i == 0 else s for i, s in enumerate(common)]
                if beh.kind == "short-array":
                    return common[1:]
                if beh.kind == "noncanonical":
                    return [hx(PRIME) if i == 0 else s for i, s in enumerate(common)]
            return common

        got = await exchange(rd, mine_fn, lambda p, raw: arr(p, raw, len(ws)), common)
        if prep.tagged:
            # pairwise tags: peer-specific, so a separate un-echoed round; each receiver verifies at once
            def tag_msg(peer: int) -> Any:
                return [hx(fadd(x.v.tag[peer], 1) if (beh is not None and beh.kind == "bad-tag" and beh.round == rd and i == 0) else x.v.tag[peer])
                        for i, x in enumerate(ws)]

            tags = await exchange(rd + ".t", tag_msg, lambda p, raw: arr(p, raw, len(ws)), None, False)
            for p in others:
                for i in range(len(ws)):
                    if not NetPa.pa_verify(env, ws[i].v, p, got[p][i], tags[p][i]):
                        abort(NetAbort("mac-check", p, id_, "pairwise MAC on party %d's opened share failed in round '%s' (index %d): the share or its tag is not what the dealer issued" % (p, rd, i)))
        out: List[int] = []
        for i in range(len(ws)):
            sm = send_vals[i]
            for p in others:
                sm = fadd(sm, got[p][i])
            out.append(sm)
            opened.append(_Opened(sm, macs[i]))
        return out

    # ---- coin flip (commit / open of a random seed) -> a joint public seed ----
    async def coin(label: str, tamper_open: bool) -> bytes:
        my_seed = secrets.token_bytes(32)
        seed_commit = _sha("seed", session_id, label, str(id_), my_seed).hex()

        def parse_commit(p: int, raw: Any) -> str:
            return raw if isinstance(raw, str) and _HEX64.fullmatch(raw) else bad(p, "bad commitment")

        seed_commits = await exchange(label + "-c", lambda peer: seed_commit, parse_commit, seed_commit)

        def open_msg(peer: int) -> str:
            return secrets.token_bytes(32).hex() if (tamper_open and beh is not None and beh.kind == "bad-coin-open") else my_seed.hex()

        def parse_open(p: int, raw: Any) -> bytes:
            if not isinstance(raw, str) or _HEX64.fullmatch(raw) is None:
                return bad(p, "bad seed")
            sd = bytes.fromhex(raw)
            if _sha("seed", session_id, label, str(p), sd).hex() != seed_commits[p]:
                raise NetAbort("commitment", p, id_, "party %d opened a coin seed that does not match its commitment" % p)
            return sd

        seeds = await exchange(label + "-o", open_msg, parse_open, my_seed.hex())
        return _sha("joint", session_id, label, *[my_seed if p == id_ else seeds[p] for p in range(n)])

    # ---- sacrifice: certify every triple against its partners before it is used ----
    nT = len(prep.triples)
    if nT > 0:
        joint1 = await coin("coin1", False)
        rho_w: List[AW] = []
        for t in range(nT):
            a = prep.triples[t][0]
            parts = prep.triples[t][3:]
            for r in range(P):
                e = _challenge(joint1, "sac", t * P + r)
                rho_w.append(w_sub(w_scale(a, e), parts[2 * r]))
        rho = await open_many("sac-rho", rho_w)
        tau_w: List[AW] = []
        for t in range(nT):
            b, c = prep.triples[t][1], prep.triples[t][2]
            parts = prep.triples[t][3:]
            for r in range(P):
                e = _challenge(joint1, "sac", t * P + r)
                tau_w.append(w_sub(w_sub(w_scale(c, e), parts[2 * r + 1]), w_scale(b, rho[t * P + r])))
        tau = await open_many("sac-tau", tau_w)
        bad_at = next((i for i, x in enumerate(tau) if x != 0), -1)
        if bad_at >= 0:
            # Dealer-free mode: the triple is discarded, so its OT transcript can be disclosed and audited to name a party that fed a wrong
            # operand into a triple product. Every honest party reaches this point together.
            attributed: Optional[int] = None
            note = ""
            fx = prep.forensics if prep.mode == "no-dealer" else None
            if fx is not None:
                bt = bad_at // P
                mine = fx.disclose(bt)
                # commit first, open only once every commitment is in hand; a late or absent party times out at the shared deadline
                got = await exchange_disclosures(
                    session_id=session_id, id=id_, n=n, triple_index=bt, mine=mine, slots=fx.slots, rows=fx.rows,
                    deadline_ms=cfg.forensic_deadline_ms if cfg.forensic_deadline_ms is not None else NetForensics.DEFAULT_FORENSIC_DEADLINE_MS,
                    exchange=lambda rd, m, parse, t: exchange(rd, m, parse, None, False, t), bad=bad)
                all_ = {id_: mine}
                all_.update(got)
                res = NetForensics.audit_disclosures(all_, fx.gadget)
                attributed = NetForensics.blame_from(id_, res)
                note = (" (OT transcript audit: %d inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)" % len(res.pair_bad)
                        if attributed is None else " (OT transcript audit names party %d)" % attributed)
            # every honest tag already verified, so the opened tau are the true ones: the dealt triple is wrong
            abort(NetAbort(
                "dealer" if prep.mode == "trusted-dealer" else "mac-check",
                dealer_id if prep.mode == "trusted-dealer" else (attributed if attributed is not None else ((1 - id_) if n == 2 else None)),
                id_,
                "triple sacrifice FAILED at triple %d (partner %d): c != a*b in the offline material; aborting with no output%s" % (bad_at // P, bad_at % P, note),
                None, None,
                "the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted against a third party)"))

    # ---- inputs: bit k of owner o is the C-vector [allow, t-therm(3), r-therm(Q)] ----
    my_bits = [v.allow] + Thermometer.thermometer_encode(v.t, T_M) + Thermometer.thermometer_encode(v.r_quant, Q)
    if prep.mode == "trusted-dealer":
        masked = [fsub(b, prep.my_plain[k]) for k, b in enumerate(my_bits)]
        masked_msg = [hx(x) for x in masked]
        got_masked = await exchange("inputs", lambda peer: masked_msg, lambda p, raw: arr(p, raw, C), masked_msg)

        def bit_share(owner: int, k: int) -> AW:
            pub = masked[k] if owner == id_ else got_masked[owner][k]
            return add_pub(prep.inputs[owner * C + k], pub)
    else:
        # No-dealer: the inputs are already authenticated sharings of the bits. Run the input-consistency check: open a random masked
        # combination (the opening joins the batched MAC-check below).
        def bit_share(owner: int, k: int) -> AW:
            return prep.inputs[owner * C + k]

        joint_in = await coin("coin-in", False)
        w = prep.check_mask
        for q in range(n * C):
            w = w_add(w, w_scale(prep.inputs[q], _challenge(joint_in, "in", q)))
        await open_many("in-check", [w])

    # ---- chains: acc_c over owners; allow uses AND, others OR (= NOT AND NOT) ----
    def is_or(c: int) -> bool:
        return c != 0

    acc: List[AW] = []
    for c in range(C):
        b0 = bit_share(0, c)
        acc.append(not_(b0) if is_or(c) else b0)

    mults = 0
    for s in range(1, n):
        trs = [prep.triples[(s - 1) * C + c] for c in range(C)]
        ys = []
        for c in range(C):
            b = bit_share(s, c)
            ys.append(not_(b) if is_or(c) else b)
        ds = [w_sub(x, trs[c][0]) for c, x in enumerate(acc)]
        es = [w_sub(y, trs[c][1]) for c, y in enumerate(ys)]
        pub = await open_many("mul%d" % (s - 1), ds + es)
        new_acc = []
        for c in range(C):
            d, e = pub[c], pub[C + c]
            ta, tb, tc = trs[c][0], trs[c][1], trs[c][2]
            z = w_add(tc, w_add(w_scale(tb, d), w_scale(ta, e)))
            new_acc.append(add_pub(z, fmul(d, e)))
        acc = new_acc
        mults += C

    # ---- outputs: allow as-is; or-chains are NOT of the product ----
    out_shares = [not_(x) if is_or(c) else x for c, x in enumerate(acc)]
    out_vals = await open_many("out", out_shares)

    # ---- MAC-check: coin-flip for the challenges, one independent challenge vector per key ----
    joint = await coin("coin", True)

    def chal(l: int, j: int) -> int:
        return _challenge(joint, "mac%d" % l, j)

    a_pub: List[int] = []
    for l in range(K):
        a = 0
        for j, o in enumerate(opened):
            a = fadd(a, fmul(chal(l, j), o.val))
        a_pub.append(a)

    def combo(l: int, pick: Callable[[_Opened], int]) -> int:
        g = 0
        for j, o in enumerate(opened):
            g = fadd(g, fmul(chal(l, j), pick(o)))
        return g

    Gamma = [combo(l, lambda o, l=l: o.mac[l].x) for l in range(K)]
    sigma = [fsub(g, fmul(prep.alpha[l].x, a_pub[l])) for l, g in enumerate(Gamma)]
    sig_nonce = secrets.token_bytes(32)

    def sig_commit(p: int, s: List[int], nonce: bytes) -> str:
        return _sha("sigma", session_id, str(p), ",".join(hx(x) for x in s), nonce).hex()

    sigma_sent = [fadd(s, 1) if l == 0 else s for l, s in enumerate(sigma)] if (beh is not None and beh.kind == "sigma-lie") else sigma
    my_sig_commit = sig_commit(id_, sigma_sent, sig_nonce)

    def parse_sig_commit(p: int, raw: Any) -> str:
        return raw if isinstance(raw, str) and _HEX64.fullmatch(raw) else bad(p, "bad commitment")

    sig_commits = await exchange("sig-c", lambda peer: my_sig_commit, parse_sig_commit, my_sig_commit)
    my_sig_open = {"s": [hx(x) for x in sigma_sent], "nonce": sig_nonce.hex()}

    def sig_open_msg(peer: int) -> Any:
        if beh is not None and beh.kind == "bad-sigma-open":
            return {"s": [hx(fadd(s, 1) if l == 0 else s) for l, s in enumerate(sigma_sent)], "nonce": my_sig_open["nonce"]}
        return my_sig_open

    def parse_sig_open(p: int, raw: Any) -> List[int]:
        o = raw if isinstance(raw, dict) else {}
        sv = unhx_array(o.get("s"), K)
        nn = o.get("nonce")
        if sv is None or not isinstance(nn, str) or _HEX64.fullmatch(nn) is None:
            return bad(p, "bad sigma opening")
        if sig_commit(p, sv, bytes.fromhex(nn)) != sig_commits[p]:
            raise NetAbort("commitment", p, id_, "party %d opened a MAC residual that does not match its commitment" % p)
        return sv

    sig_opens = await exchange("sig-o", sig_open_msg, parse_sig_open, my_sig_open)
    residual = []
    for l in range(K):
        r = sigma_sent[l]
        for p in others:
            r = fadd(r, sig_opens[p][l])
        residual.append(r)
    mac_failed = any(r != 0 for r in residual)

    # ---- transcript echo: everyone must have seen the same broadcasts (also fixes the sigma data for the blame) ----
    digest = transcript.copy().hexdigest()

    def parse_digest(p: int, raw: Any) -> str:
        return raw if isinstance(raw, str) and _HEX64.fullmatch(raw) else bad(p, "bad digest")

    digests = await exchange("digest", lambda peer: digest, parse_digest, digest)
    for p in others:
        if digests[p] != digest:
            abort(NetAbort("equivocation", p, id_, "transcript digest of party %d differs from mine (a broadcast was inconsistent)" % p))

    if mac_failed:
        msg = "MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output"
        if not prep.tagged:
            abort(NetAbort("mac-check", (1 - id_) if n == 2 else None, id_, msg, None, None,
                           "this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)"))

        def blame_msg(peer: int) -> Any:
            return {"g": [hx(g) for g in Gamma], "gt": [hx(combo(l, lambda o, l=l: o.mac[l].tag[peer])) for l in range(K)],
                    "a": [hx(a.x) for a in prep.alpha], "at": [hx(a.tag[peer]) for a in prep.alpha]}

        def parse_blame(p: int, raw: Any) -> Dict[str, List[int]]:
            o = raw if isinstance(raw, dict) else {}
            return {"g": arr(p, o.get("g"), K), "gt": arr(p, o.get("gt"), K), "a": arr(p, o.get("a"), K), "at": arr(p, o.get("at"), K)}

        # Abort claims arriving during this round are read in link order (see Mesh.set_defer_aborts): the cheater's own abort must not
        # pre-empt an honest party that has not yet received every peer's blame data.
        mesh.set_defer_aborts(True)
        try:
            blames = await exchange("blame", blame_msg, parse_blame, None, False)
        finally:
            mesh.set_defer_aborts(False)
        for p in others:
            b = blames[p]
            for l in range(K):
                key_combo = combo(l, lambda o, l=l: o.mac[l].key[p])
                if fadd(key_combo, fmul(env.delta, b["g"][l])) != b["gt"][l]:
                    abort(NetAbort("mac-check", p, id_, "%s - party %d's MAC share (key %d) does not match its pairwise tag" % (msg, p, l)))
                if fadd(prep.alpha[l].key[p], fmul(env.delta, b["a"][l])) != b["at"][l]:
                    abort(NetAbort("mac-check", p, id_, "%s - party %d's key share (key %d) does not match its pairwise tag" % (msg, p, l)))
                if fsub(b["g"][l], fmul(b["a"][l], a_pub[l])) != sig_opens[p][l]:
                    abort(NetAbort("mac-check", p, id_, "%s - party %d's opened MAC residual (key %d) is not what its authenticated shares give" % (msg, p, l)))
        # Every other party's data is consistent with its pairwise tags; so is mine: the offline material disagrees.
        if prep.mode == "trusted-dealer":
            abort(NetAbort("dealer", dealer_id, id_, "%s - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values" % msg))
        abort(NetAbort("mac-check", (1 - id_) if n == 2 else None, id_,
                       "%s - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable" % msg,
                       None, None, "every party's shares verify under its pairwise tags, so the failure is in the offline OT material and no party can be named"))

    # ---- only now decode ----
    def bit(x: int) -> int:
        return 1 if x == 1 else 0

    allow = bit(out_vals[0])
    t_bits = [bit(x) for x in out_vals[1:1 + T_M]]
    r_bits = [bit(x) for x in out_vals[1 + T_M:]]
    composed = ComposedDecision(allow, min(3, max(1, Thermometer.thermometer_decode(t_bits))), Thermometer.thermometer_decode(r_bits))
    await mesh.finish()
    return PartyResult(id=id_, n=n, Q=Q, composed=composed, rounds=rounds, transcript_digest=digest, wall_ms=_now_ms() - t0,
                       multiplications=mults, opens=len(opened), offline_mode=prep.mode, mac_keys=K, sacrificed_triples=nT,
                       sacrifice_partners=P, identifiable_abort=prep.tagged)
