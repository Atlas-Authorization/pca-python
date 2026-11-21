"""Replays the TS-reference oracle of the MPC deterministic layer and the SPDZ online phase (test-data/ref-mpc.json.gz). Every random draw in
the corpus comes from a seeded SplitMix64; bigints travel as decimal strings."""
import pytest

from atlas_pca import mpc as M
from atlas_pca import mpc_spdz as S
from base_oracle import load_ref, run

F = M.Field
COUNT, CASES = load_ref("mpc")


def big(o):
    if not isinstance(o, str):
        raise ValueError("bigint arg")
    return int(o)


def pint(o):
    """A JavaScript integer argument (a non-integer is the reference's Number.isInteger failure)."""
    if isinstance(o, bool) or not isinstance(o, (int, float)):
        raise ValueError("not an integer")
    f = float(o)
    if f != f or f in (float("inf"), float("-inf")) or f != round(f):
        raise ValueError("not an integer")
    if abs(f) > 1e9:
        return 2 ** 31 - 1 if o > 0 else -2 ** 31
    return int(o)


def dbl(o):
    if isinstance(o, bool) or not isinstance(o, (int, float)):
        raise ValueError("not a number")
    return float(o)


def rng(seed):
    return F.FieldRng(big(seed))


def bigs(o):
    return [None if x is None else big(x) for x in o]


def bigss(o):
    return [bigs(x) for x in o]


def strs1(a):
    return [None if x is None else str(x) for x in a]


def strs2(a):
    return [strs1(x) for x in a]


def vectors(o):
    if not isinstance(o, list):
        raise ValueError("decision vectors must be an array")
    out = []
    for e in o:
        if not isinstance(e, dict):
            raise ValueError("decision vector must be an object")
        out.append(M.DecisionVector(pint(e.get("allow")), pint(e.get("t")), pint(e.get("rQuant"))))
    return out


def auth_sv(x):
    return {"value": strs1(x.value), "mac": strs1(x.mac), "extraMac": strs2(x.extra_mac)}


def triple(t):
    return {"a": auth_sv(t.a), "b": auth_sv(t.b), "c": auth_sv(t.c)}


def key(k):
    return {"alphaShares": strs1(k.alpha_shares), "alpha": str(k.alpha)}


def ctx(c):
    return {"n": c.n, "alphaShares": strs1(c.alpha_shares), "alpha": str(c.alpha), "extraKeys": [key(k) for k in c.extra_keys]}


def devs(o):
    return [S.Deviation(pint(d[0]), pint(d[1]), None if d[2] is None else big(d[2]), None if d[3] is None else big(d[3]),
                        None if d[4] is None else pint(d[4])) for d in o]


def fault(o):
    if o is None:
        return None
    pcd = o.get("partnerCDelta")
    return S.DealerFault(None if o.get("keepCDelta") is None else big(o["keepCDelta"]),
                         None if pcd is None else [None if x is None else big(x) for x in pcd])


def opened(lst):
    return [{"label": m.label, "value": str(m.value), "shares": strs1(m.shares)} for m in lst]


def decision(d):
    return {"allow": d.allow, "t": d.t, "rQuant": d.r_quant}


def partnered(t):
    return {"keep": triple(t.keep), "partners": [triple(p) for p in t.partners]}


def sv_op(op, x, y):
    if op == "add":
        return M.Sharing.add_sv(x, y)
    if op == "sub":
        return M.Sharing.sub_sv(x, y)
    raise ValueError(op)


def sv(op, x, y=None):
    xs = bigs(x)
    if op == "neg":
        r = M.Sharing.neg_sv(xs)
    elif op == "scale":
        r = M.Sharing.scale_sv(xs, big(y))
    elif op == "addPublic":
        r = M.Sharing.add_public_sv(xs, big(y))
    elif op == "notBit":
        r = M.Sharing.not_bit_sv(xs)
    else:
        r = sv_op(op, xs, bigs(y))
    return strs1(r)


def gf(*a):
    g = M.Gf128
    x = big(a[1])
    if a[0] == "add":
        r = g.add(x, big(a[2]))
    elif a[0] == "mul":
        r = g.mul(x, big(a[2]))
    elif a[0] == "mulX":
        r = g.mul_x(x)
    elif a[0] == "mulByXi":
        r = g.mul_by_xi(x, pint(a[2]))
    else:
        raise ValueError(a[0])
    return str(r)


def auth_op(*a):
    op = a[0]
    g = rng(a[2])
    c = S.Spdz.setup_mac(pint(a[1]), g)
    x = S.Spdz.auth_share(big(a[3]), c, g)
    y = S.Spdz.auth_share(big(a[4]), c, g)
    k = big(a[5])
    if op == "open":
        return {"val": str(S.Spdz.auth_value(x))}
    Z = S.Spdz
    if op == "add":
        res = Z.add_auth(x, y)
    elif op == "sub":
        res = Z.sub_auth(x, y)
    elif op == "neg":
        res = Z.neg_auth(x)
    elif op == "scale":
        res = Z.scale_auth(x, k)
    elif op == "addPublic":
        res = Z.add_public_auth(x, k, c)
    elif op == "notBit":
        res = Z.not_bit_auth(x, c)
    else:
        raise ValueError(op)
    val = Z.auth_value(res)
    keys = Z.mac_keys(c)
    ok = all(sum(row) % M.PRIME == F.fmul(keys[l].alpha, val) for l, row in enumerate([res.mac] + list(res.extra_mac)))
    return {"res": auth_sv(res), "val": str(val), "okMac": ok}


def engine_run(*a):
    g = rng(a[1])
    c = S.Spdz.setup_mac(pint(a[0]), g, pint(a[4]) if len(a) > 4 else S.MAC_KEYS)
    e = S.SpdzEngine(c, devs(a[3]))
    outs = [str(e.open(S.Spdz.auth_share(big(v), c, g), "v%d" % i)) for i, v in enumerate(a[2])]
    e.mac_check(g)
    return {"outs": outs, "count": e.open_count()}


def beaver_auth(*a):
    g = rng(a[1])
    c = S.Spdz.setup_mac(pint(a[0]), g)
    e = S.SpdzEngine(c, devs(a[4]))
    x = S.Spdz.auth_share(big(a[2]), c, g)
    y = S.Spdz.auth_share(big(a[3]), c, g)
    t = S.Spdz.gen_auth_triple(c, g)
    z = S.Spdz.beaver_mul_auth(x, y, t, c, e, "m")
    val = S.Spdz.auth_value(z)
    out = e.open(z, "out")
    e.mac_check(g)
    return {"z": auth_sv(z), "val": str(val), "out": str(out), "opens": e.open_count()}


def sacrifice(*a):
    g = rng(a[1])
    c = S.Spdz.setup_mac(pint(a[0]), g)
    f = fault(a[4])
    batch = [S.Spdz.gen_triple_with_partners(c, g, pint(a[3]), f if i == 0 else None) for i in range(pint(a[2]))]
    return {"certified": [triple(t) for t in S.Spdz.sacrifice_verify(batch, c, g, devs(a[5]))]}


def compose_secure(*a):
    r = M.Runner.compose_secure(vectors(a[0]), pint(a[1]), big(a[2]))
    return {"composed": decision(r.composed), "parties": r.parties, "Q": r.q, "multiplications": r.multiplications, "opened": opened(r.opened),
            "sharings": [{"label": s.label, "party": s.party, "secret": str(s.secret), "shares": strs1(s.shares)} for s in r.sharings],
            "heldShares0": strs1(r.views[0].held_shares), "viewsLen": len(r.views)}


def malicious(*a):
    m = a[1]
    d = m.get("dealer")
    dealer = None
    if d is not None:
        dealer = S.DealerOptions(d.get("verifyTriples"), None if d.get("partners") is None else pint(d["partners"]), fault(d.get("fault")))
    r = S.SpdzRunner.compose_secure_malicious(
        vectors(a[0]), q=None if m.get("Q") is None else pint(m["Q"]), seed=None if m.get("seed") is None else big(m["seed"]),
        deviations=None if m.get("deviations") is None else devs(m["deviations"]), insecure_trusted_dealer=m.get("insecureTrustedDealer") is True,
        dealer=dealer)
    return {"composed": decision(r.composed), "parties": r.parties, "Q": r.q, "opens": r.opens, "multiplications": r.multiplications,
            "offlineMode": r.offline_mode, "triplesVerified": r.triples_verified, "macChecked": r.mac_checked}


def gen_triple(n, seed):
    t = M.Beaver.gen_triple(pint(n), rng(seed))
    return {"a": strs1(t.a), "b": strs1(t.b), "c": strs1(t.c)}


def beaver_mul(x, y, ta, tb, tc):
    op = []
    z = M.Beaver.beaver_mul(bigs(x), bigs(y), M.Beaver.Triple(bigs(ta), bigs(tb), bigs(tc)), op)
    return {"z": strs1(z), "opened": opened(op)}


def sample_enc(s, seed):
    g = rng(seed)
    gad = M.Enc.make_gadget(pint(s), g, True)
    e = M.Enc.sample_enc(gad, g)
    return {"gadget": strs1(gad), "e": {"value": str(e.value), "bits": e.bits}}


def plain_share(x):
    e = M.Enc.plain_share(big(x))
    return {"value": str(e.value), "bits": e.bits}


def gen_triple_with_partners(*a):
    if len(a) == 2:
        g = rng(a[1])
        return partnered(S.Spdz.gen_triple_with_partners(S.Spdz.setup_mac(pint(a[0]), g), g))
    g = rng(a[0])
    return partnered(S.Spdz.gen_triple_with_partners(S.Spdz.setup_mac(2, g), g, pint(a[1]), fault(a[2])))


def mac_residuals(p, alphas, op, ch):
    ov = [S.OpenedValue(big(o["value"]), bigss(o["macShares"]), "") for o in op]
    return strs2(S.Spdz.mac_residuals(big(p), bigss(alphas), ov, bigss(ch)))


def field_rng(seed, n):
    g = rng(seed)
    return [str(g.next()) for _ in range(pint(n))]


def field_rng_default(n):
    g = F.FieldRng()
    return [str(g.next()) for _ in range(pint(n))]


def auth_share_fn(n, seed, secret):
    g = rng(seed)
    c = S.Spdz.setup_mac(pint(n), g)
    return {"ctx": ctx(c), "sv": auth_sv(S.Spdz.auth_share(big(secret), c, g))}


def gen_auth_triple(n, seed):
    g = rng(seed)
    return triple(S.Spdz.gen_auth_triple(S.Spdz.setup_mac(pint(n), g), g))


MAP = {
    "mod": lambda x: str(F.mod(big(x))),
    "fneg": lambda x: str(F.fneg(big(x))),
    "fadd": lambda x, y: str(F.fadd(big(x), big(y))),
    "fsub": lambda x, y: str(F.fsub(big(x), big(y))),
    "fmul": lambda x, y: str(F.fmul(big(x), big(y))),
    "fieldRng": field_rng,
    "fieldRngDefault": field_rng_default,
    "share": lambda s, n, seed: strs1(M.Sharing.share(big(s), pint(n), rng(seed))),
    "reconstruct": lambda sh: str(M.Sharing.reconstruct(bigs(sh))),
    "shareConstant": lambda c, n: strs1(M.Sharing.share_constant(big(c), pint(n))),
    "sv": sv,
    "gf": gf,
    "encBits": lambda s: M.Enc.enc_bits(pint(s)),
    "makeGadget": lambda s, seed, unsafe: strs1(M.Enc.make_gadget(pint(s), rng(seed), unsafe is True)),
    "plainShare": plain_share,
    "plainGadget": lambda: strs1(M.Enc.plain_gadget()),
    "randomBits": lambda m, seed: M.Enc.random_bits(pint(m), rng(seed)),
    "sampleEnc": sample_enc,
    "encValue": lambda g, bits: str(M.Enc.enc_value(bigs(g), [pint(b) for b in bits])),
    "genTriple": gen_triple,
    "beaverMul": beaver_mul,
    "thermometerEncode": lambda v, m: M.Thermometer.thermometer_encode(dbl(v), pint(m)),
    "thermometerDecode": lambda bits: sum(1 for b in bits if isinstance(b, (int, float)) and not isinstance(b, bool) and b == 1),
    "quantizeR": lambda r, q: M.Party.quantize_r(dbl(r), pint(q)),
    "composeClear": lambda v, q: decision(M.Compose.compose_clear(vectors(v), pint(q))),
    "assertDecisionVectors": lambda v, q: M.Compose.assert_decision_vectors(vectors(v), pint(q)) or True,
    "composeSecure": compose_secure,
    "setupMac": lambda n, seed, keys: ctx(S.Spdz.setup_mac(pint(n), rng(seed), pint(keys))),
    "macSoundnessBits": lambda k, p=None: S.Spdz.mac_soundness_bits(pint(k)) if p is None else S.Spdz.mac_soundness_bits(pint(k), big(p)),
    "authShare": auth_share_fn,
    "authConstant": lambda n, seed, c: auth_sv(S.Spdz.auth_constant(big(c), S.Spdz.setup_mac(pint(n), rng(seed)))),
    "authOp": auth_op,
    "genAuthTriple": gen_auth_triple,
    "genTripleWithPartners": gen_triple_with_partners,
    "sacrifice": sacrifice,
    "engineRun": engine_run,
    "macResiduals": mac_residuals,
    "beaverAuth": beaver_auth,
    "composeSecureMalicious": malicious,
}


def test_corpus_is_covered():
    assert sorted(MAP) == sorted(CASES)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
