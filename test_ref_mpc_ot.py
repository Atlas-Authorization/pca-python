"""Replays the TS-reference oracle of the MPC oblivious-transfer stack (test-data/ref-mpc-ot.json.gz). Every random draw in the corpus comes from a
seeded SplitMix64; bigints travel as decimal strings, bytes as {"$bytes"}. Needs libsodium through pysodium and the cryptography package; the
ML-KEM transcripts need OpenSSL >= 3.5 (PCA_LIBCRYPTO may name the library)."""
import os

import pytest

pytest.importorskip("pysodium")
pytest.importorskip("cryptography")

from atlas_pca import mpc as M  # noqa: E402
from atlas_pca import mpc_mascot as MA  # noqa: E402
from atlas_pca import mpc_spdz as S  # noqa: E402
from atlas_pca.mpc_ec import BASE, IDENTITY, L, Q, Ec, Point, SchnorrProof  # noqa: E402
from atlas_pca.mpc_kem_ot import HybridBaseOtTamper, HybridOt, KemMalTamper, KemOt  # noqa: E402
from atlas_pca.mpc_libcrypto import Libcrypto  # noqa: E402
from atlas_pca.mpc_ot import BaseOtBinding, BaseOtTamper, Ot, OtChannel  # noqa: E402
from atlas_pca.mpc_otx import OtTweak, Otx  # noqa: E402
from base_oracle import b64d, covered, load_gen, load_ref, merge_cases, require_gen, run  # noqa: E402

F = M.Field
COUNT, _MAIN = load_ref("mpc-ot")
_GEN = load_gen("mpc-ot")
CASES = merge_cases(_MAIN, _GEN)
ORDER2 = Point(0, Q - 1, 1, 0)


def big(o):
    if not isinstance(o, str):
        raise ValueError("bigint arg")
    return int(o)


def _num(o):
    if isinstance(o, bool) or not isinstance(o, (int, float)):
        raise ValueError("not an integer")
    f = float(o)
    if f != f or f in (float("inf"), float("-inf")) or f != round(f):
        raise ValueError("not an integer")
    return f


def pint(o):
    """A JavaScript integer argument (a non-integer is the reference's Number.isInteger failure)."""
    f = _num(o)
    if abs(f) > 1e9:
        return 2 ** 31 - 1 if o > 0 else -2 ** 31
    return int(o)


def lng(o):
    _num(o)
    return int(o)


def ints(o):
    return [pint(x) for x in o]


def bigs(o):
    return [None if x is None else big(x) for x in o]


def strs(a):
    return [None if x is None else str(x) for x in a]


def pairs(a):
    return [[p[0], p[1]] for p in a]


def orng(seed):
    return Ot.ot_random(Ot.split_mix64(big(seed)))


def flip(b, mask):
    return bytes(x ^ mask for x in b)


def pt(o):
    return Point(*[big(v) for v in o])


def aff(p):
    x, y = Ec.to_affine(p)
    return {"x": str(x), "y": str(y)}


def tamper(name):
    if name == "none":
        return None
    t = BaseOtTamper()
    if name == "S_identity":
        t.tamper_s = lambda _p: IDENTITY
    elif name == "S_order2":
        t.tamper_s = lambda _p: ORDER2
    elif name == "S_other":
        t.tamper_s = lambda p: Ec.add_points(p, BASE)
    elif name == "proof_z":
        t.tamper_proof = lambda p: SchnorrProof(p.u, (p.z + 1) % L)
    elif name == "proof_U":
        t.tamper_proof = lambda p: SchnorrProof(Ec.add_points(p.u, BASE), p.z)
    elif name == "R0_identity":
        t.tamper_r = lambda r: r.__setitem__(0, IDENTITY)
    elif name == "R1_order2":
        t.tamper_r = lambda r: r.__setitem__(1, ORDER2) if len(r) > 1 else None
    elif name == "R_swap":
        def swap(r):
            if len(r) > 1:
                r[0], r[1] = r[1], r[0]
        t.tamper_r = swap
    elif name == "ct_flip":
        t.tamper_ciphertext = lambda ct: ct[0].__setitem__(0, flip(ct[0][0], 1))
    elif name == "ct_flip1":
        t.tamper_ciphertext = lambda ct: ct[-1].__setitem__(1, flip(ct[-1][1], 0x80))
    else:
        raise ValueError(name)
    return t


def bind_in(sess, a, b, rnd):
    return BaseOtBinding(b64d(sess), lng(a), lng(b), rnd)


def random_ot(*a):
    r = Ot.mal_base_random_ot(ints(a[0]), orng(a[1]), tamper(a[2]))
    return {"S": aff(r.s), "U": aff(r.proof.u), "z": str(r.proof.z), "R": [aff(p) for p in r.r], "senderPads": pairs(r.sender_pads),
            "recvPads": list(r.recv_pads)}


def base_ot(*a):
    res = Ot.base_ot(a[0], ints(a[1]), orng(a[2]), tamper(a[3]))
    t = res.transcript
    return {"received": list(res.received), "S": aff(t.s), "U": aff(t.proof.u), "z": str(t.proof.z), "R": [aff(p) for p in t.r],
            "ct": pairs(t.ct), "com": pairs(t.com)}


def channel(*a):
    ch = OtChannel(orng(a[3]))
    kind = a[5]

    def flip00(u, _r):
        u[0] ^= 1

    def flip_last(u, _r):
        u[127] ^= 1 << 5

    def oversize(u, _r):
        u[3] |= 1 << 5000

    def negative(u, _r):
        u[3] = -1

    def round2flip(u, r):
        if r == 1:
            u[10] ^= 2

    ch.tamper_u = {"flip00": flip00, "flipLast": flip_last, "oversize": oversize, "negative": negative, "round2flip": round2flip}.get(kind)
    outs = []
    for _ in range(pint(a[4])):
        e = ch.extend_ot(ints(a[0]), bigs(a[1]), bigs(a[2]))
        outs.append({"received": strs(e.received), "uMatrix": strs(e.u_matrix)})
    bt = ch.base_transcript
    return {"selector": str(ch.selector()), "outs": outs, "base": None if bt is None else {"S": aff(bt.s), "R": len(bt.r)}}


def kos_chi(*a):
    b = b64d(a[0])
    u = bigs(a[2])
    return {"w": Ot.kos_chi_words(b, pint(a[1]), u, pint(a[3])), "chi": strs(Ot.kos_challenges(b, pint(a[1]), u, pint(a[3])))}


def auth_sv(x):
    return {"value": strs(x.value), "mac": strs(x.mac), "extraMac": [strs(r) for r in x.extra_mac]}


def triple(t):
    return {"a": auth_sv(t.a), "b": auth_sv(t.b), "c": auth_sv(t.c)}


def key(k):
    return {"alphaShares": strs(k.alpha_shares), "alpha": str(k.alpha)}


def ctx(c):
    return {"n": c.n, "alphaShares": strs(c.alpha_shares), "alpha": str(c.alpha), "extraKeys": [key(k) for k in c.extra_keys]}


def offline_options(o):
    if o is None:
        return None
    opts = MA.NoDealerOptions()
    if o.get("sacrifice") is not None:
        opts.sacrifice = o["sacrifice"]
    if o.get("partners") is not None:
        opts.sacrifice_partners = pint(o["partners"])
    if o.get("keys") is not None:
        opts.mac_keys = pint(o["keys"])
    if o.get("statSec") is not None:
        opts.stat_sec = pint(o["statSec"])
    opts.unsafe_stat_sec = o.get("unsafe") is True
    if o.get("dev") is not None:
        opts.deviation = MA.OfflineDeviation(pint(o["dev"][0]), big(o["dev"][1]))
    return opts


def _fsum(vs):
    s = 0
    for v in vs:
        s = F.fadd(s, v)
    return s


def offline(*a):
    n = pint(a[0])
    o = a[3]
    off = MA.make_no_dealer_offline(n, big(a[1]), offline_options(o))
    base = {"n": off.n, "statSec": off.stat_sec, "ctx": ctx(off.mac_context)}
    what = a[2]
    if what == "ctx":
        return base
    if what == "triple":
        return {**base, "t": triple(off.gen_auth_triple())}
    if what == "input":
        return {**base, "v": auth_sv(off.auth_input(big(o["value"]), pint(o["owner"])))}
    if what == "multiply":
        x = bigs(o["x"])
        y = bigs(o["y"])
        z = off.ot_share_multiply(x, y)
        return {**base, "z": strs(z), "sum": str(_fsum(z)), "expect": str(F.fmul(_fsum(x), _fsum(y)))}
    if what == "consistency":
        ins = [off.auth_input(big(v), i % n) for i, v in enumerate(o["values"])]
        if o.get("tamper") is True:
            ins[0].value[0] = F.fadd(ins[0].value[0], 1)
        off.check_input_consistency(ins)
        return {**base, "ok": True}
    raise ValueError(what)


def offline_blame(*a):
    opts = MA.NoDealerOptions()
    opts.deviation = MA.OfflineDeviation(pint(a[2]), big(a[3]))
    try:
        MA.make_no_dealer_offline(pint(a[0]), big(a[1]), opts).gen_auth_triple()
        return {"aborted": False}
    except MA.OfflineCheatingAbort as e:
        return {"aborted": True, "name": "OfflineCheatingAbort", "blamed": e.blamed}


def vectors(o):
    if not isinstance(o, list):
        raise ValueError("decision vectors must be an array")
    out = []
    for e in o:
        if not isinstance(e, dict):
            raise ValueError("decision vector must be an object")
        out.append(M.DecisionVector(pint(e.get("allow")), pint(e.get("t")), pint(e.get("rQuant"))))
    return out


def no_dealer_run(*a):
    m = a[1]
    r = S.SpdzRunner.compose_secure_malicious(vectors(a[0]), q=None if m.get("Q") is None else pint(m["Q"]),
                                              seed=None if m.get("seed") is None else big(m["seed"]),
                                              deviations=None if m.get("deviations") is None else [
                                                  S.Deviation(pint(d[0]), pint(d[1]), None if d[2] is None else big(d[2]),
                                                              None if d[3] is None else big(d[3]), None if d[4] is None else pint(d[4]))
                                                  for d in m["deviations"]])
    return {"composed": {"allow": r.composed.allow, "t": r.composed.t, "rQuant": r.composed.r_quant}, "parties": r.parties, "Q": r.q,
            "opens": r.opens, "multiplications": r.multiplications, "offlineMode": r.offline_mode, "triplesVerified": r.triples_verified,
            "macChecked": r.mac_checked}


def kem_tamper(name):
    t = KemMalTamper()
    if name == "badKey":
        def bad_key(pk):
            pk[0][0], pk[0][1] = pk[0][1], pk[0][0]
        t.tamper_opened_keys = bad_key
    elif name == "badSid":
        t.tamper_receiver_sid = lambda s: flip(s, 1)
    else:
        return None
    return t


def kem_ot(*a):
    fn = a[0]
    g = orng(a[3])
    choices = ints(a[2])
    tn = a[4]
    if fn == "kemBaseOT":
        r = KemOt.kem_base_ot(a[1], choices, g)
        t = r.transcript
        return {"received": list(r.received),
                "transcript": {"publicKeys": pairs(t.public_keys), "ciphertexts": pairs(t.ciphertexts), "encrypted": pairs(t.encrypted)}}
    if fn == "kemBaseOtMal":
        r = KemOt.kem_base_ot_mal(a[1], choices, g, kem_tamper(tn))
        t = r.transcript
        return {"received": list(r.received),
                "transcript": {"rn": t.rn, "commitments": list(t.commitments), "sn": t.sn, "publicKeys": pairs(t.public_keys),
                               "ciphertexts": pairs(t.ciphertexts), "encrypted": pairs(t.encrypted)}}
    r = KemOt.kem_base_ot_mal_random(choices, g, kem_tamper(tn))
    t = r.transcript
    return {"senderSecrets": pairs(r.sender_secrets), "recvSecrets": list(r.recv_secrets), "sid": r.sid,
            "transcript": {"rn": t.rn, "commitments": list(t.commitments), "sn": t.sn, "publicKeys": pairs(t.public_keys),
                           "ciphertexts": pairs(t.ciphertexts)}}


def kem_pad(*a):
    if len(a) == 1:
        return KemOt.kem_ot_pad(0, 0, bytes(32), pint(a[0]))
    return KemOt.kem_ot_pad(pint(a[0]), pint(a[1]), bytes(range(32)), pint(a[2]))


def hybrid_ot(*a):
    tn = a[3]
    t = None
    if tn is not None:
        t = HybridBaseOtTamper()
        if tn == "ec":
            t.ec = tamper("ct_flip")
        elif tn == "ecS":
            t.ec = tamper("S_identity")
        elif tn == "enc":
            t.tamper_encrypted = lambda e: e[0].__setitem__(0, flip(e[0][0], 1))
        elif tn == "kem":
            t.kem = kem_tamper("badKey")
    r = HybridOt.hybrid_base_ot(a[0], ints(a[1]), orng(a[2]), t)
    tr = r.transcript
    return {"received": list(r.received), "sid": tr.sid, "ecS": aff(tr.ec_s), "kemSid": tr.kem_sid, "encrypted": pairs(tr.encrypted),
            "commitments": pairs(tr.commitments)}


def ec_op(*a):
    op = a[0]
    if op == "mulBase":
        p = Ec.mul_base(big(a[1]))
        return {"p": aff(p), "enc": Ec.encode_point(p), "comp": Ec.compress_point(p)}
    if op == "mul":
        return aff(Ec.mul(big(a[1]), pt(a[2])))
    if op == "add":
        return aff(Ec.add_points(pt(a[1]), pt(a[2])))
    if op == "sub":
        return aff(Ec.sub(pt(a[1]), pt(a[2])))
    if op == "neg":
        return aff(Ec.neg(pt(a[1])))
    if op == "dbl":
        return aff(Ec.dbl(pt(a[1])))
    if op == "decompress":
        p = Ec.decompress_point(a[1])
        return {"p": aff(p), "onCurve": Ec.on_curve(p), "identity": Ec.identity(p), "prime": Ec.prime_order(p), "inSub": Ec.in_subgroup(p)}
    raise ValueError(op)


def schnorr(*a):
    y = big(a[0])
    nonce = big(a[1])
    cx = b64d(a[2])
    s = Ec.mul_base(y)
    proof = Ec.schnorr_prove(y, s, lambda: nonce, cx)
    forged = SchnorrProof(proof.u, (proof.z + 1) % L)
    oor = SchnorrProof(proof.u, L)
    return {"S": aff(s), "U": aff(proof.u), "z": str(proof.z), "ok": Ec.schnorr_verify(s, proof, cx),
            "badCtx": Ec.schnorr_verify(s, proof, b"other-ctx"), "forged": Ec.schnorr_verify(s, forged, cx),
            "oor": Ec.schnorr_verify(s, oor, cx), "wrongS": Ec.schnorr_verify(Ec.mul_base(y + 1), proof, cx),
            "identityS": Ec.schnorr_verify(IDENTITY, proof, cx)}


def base_ot_kdf(i):
    b0 = Ot.random_binding(orng("4242"), "base-ot")
    r = [Ec.mul_base(5), Ec.mul_base(6)]
    th = Ot.base_ot_transcript_hash(b0, Ec.mul_base(3), r)
    return {"th": th, "k": Ot.base_ot_kdf(th, pint(i), r[0], Ec.mul_base(9))}


def gf_big(w):
    v = Otx.gf_to_big(w)
    return {"big": str(v), "back": Otx.gf_from_big(v)}


MAP = {
    "ecOp": ec_op,
    "ecValidate": lambda o: {"onCurve": Ec.on_curve(pt(o)), "identity": Ec.identity(pt(o)), "prime": Ec.prime_order(pt(o)),
                             "inSubgroup": Ec.in_subgroup(pt(o))},
    "ecAssert": lambda o: Ec.assert_in_subgroup(pt(o), "p"),
    "schnorr": schnorr,
    "prg": lambda seed, blk, n: Otx.prg_column(b64d(seed), lng(blk), pint(n)),
    "maskTail": lambda w, nb: Otx.mask_tail(list(w), pint(nb)),
    "transpose32": lambda w: Otx.transpose32(list(w), 0),
    "transposeCols": lambda w, ww, rows: Otx.transpose_cols(w, pint(ww), pint(rows)),
    "gfMulX": lambda w: Otx.gf_mul_x(list(w)),
    "gfXorInto": lambda w, v: Otx.gf_xor_into(list(w), v, 0),
    "gfBig": gf_big,
    "accumColumn": lambda c, chi: Otx.accum_column(c, 0, len(c), chi, [0, 0, 0, 0]),
    "kosCombine": lambda c, w, chi: Otx.kos_combine(c, pint(w), chi),
    "tmmo": lambda rows, n, off, dom: Otx.tmmo_crh(rows, pint(n), OtTweak(lng(off), dom)),
    "tweakDomain": lambda b: Otx.ot_tweak_domain(b64d(b)),
    "bigBytes": lambda v, ln: Otx.big_to_bytes(big(v), pint(ln)),
    "bytesBig": lambda b: str(Otx.bytes_to_big(b64d(b))),
    "word64": lambda w, j: str(Otx.word64(w, pint(j))),
    "bindingBytes": lambda s, a, b, r: Ot.binding_bytes(bind_in(s, a, b, r)),
    "baseOtKdf": base_ot_kdf,
    "randomOt": random_ot,
    "baseOt": base_ot,
    "channel": channel,
    "kosChi": kos_chi,
    "offline": offline,
    "offlineBlame": offline_blame,
    "noDealerRun": no_dealer_run,
    "kemOt": kem_ot,
    "kemPad": kem_pad,
    "hybridOt": hybrid_ot,
    "hybridKey": lambda ln: HybridOt.hybrid_transfer_key(b"\x01" * 32, 3, 1, b"\x02" * 16, b"\x03" * 32, pint(ln)),
}

# the ML-KEM transcripts need OpenSSL >= 3.5 (the vetted ML-KEM-768) through ctypes
NEEDS_MLKEM = ("kemOt", "hybridOt")


def test_corpus_is_covered():
    assert covered(CASES, _GEN, MAP), "unmapped corpus functions"


def test_secret_corpus_present():
    if _GEN is None:
        require_gen("mpc-ot")


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    if fn in NEEDS_MLKEM and not Libcrypto.mlkem_available():
        if os.environ.get("PCA_MPC_REQUIRE_MLKEM") == "1":  # the mpc workflow runs on an OpenSSL 3.5 image: a skip there is a failure
            pytest.fail("ML-KEM-768 needs OpenSSL >= 3.5")
        pytest.skip("ML-KEM-768 needs OpenSSL >= 3.5")
    if fn not in CASES:
        require_gen("mpc-ot")
    run(CASES[fn], MAP[fn])
