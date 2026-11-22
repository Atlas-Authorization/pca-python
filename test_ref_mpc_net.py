"""Replays the TS-reference oracle of the pure parts of the MPC networked runner (test-data/ref-mpc-net.json.gz): the wire codec,
pairwise-authenticated shares, forensic disclosures and the OT message codecs. The point codecs need libsodium through pysodium."""
import pytest

pytest.importorskip("pysodium")

from atlas_pca import mpc_net as N  # noqa: E402
from atlas_pca.mpc_ec import Ec  # noqa: E402
from base_oracle import load_ref, run  # noqa: E402

W, Pa, Fx, C = N.NetWire, N.NetPa, N.NetForensics, N.NetCodec
COUNT, CASES = load_ref("mpc-net")


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


def bigs(o):
    return [None if x is None else big(x) for x in o]


def strs(a):
    return [None if x is None else str(x) for x in a]


# ---- wire ----
def split(*a):
    s = N.FrameSplitter()
    frames = []
    for c in a[0]:
        frames.extend(s.push(c))
    return {"frames": frames}


def net_abort(*a):
    op = a[6]
    e = N.NetAbort(a[0], None if a[1] is None else pint(a[1]), pint(a[2]), a[3], a[4],
                   pint(a[5]) if isinstance(a[5], (int, float)) and not isinstance(a[5], bool) else None,
                   op and op.get("reason"), op and op.get("evidence"), None if op is None or op.get("deadlineMs") is None else pint(op["deadlineMs"]))
    return {"message": str(e), "name": "NetAbort", "kind": e.kind, "blamed": e.blamed, "reporter": e.reporter, "reason": e.reason,
            "claimedKind": e.claimed_kind, "claimedBlame": e.claimed_blame, "evidence": e.evidence, "deadlineMs": e.deadline_ms}


# ---- pairwise-authenticated shares ----
def pa(o):
    return Pa.PA(big(o["x"]), bigs(o["tag"]), bigs(o["key"]))


def aw(o):
    return Pa.AW(pa(o["v"]), [pa(p) for p in o["m"]])


def pa_j(p):
    return {"x": str(p.x), "tag": strs(p.tag), "key": strs(p.key)}


def aw_j(a):
    return {"v": pa_j(a.v), "m": [pa_j(p) for p in a.m]}


def pa_op(*a):
    op = a[0]
    p = pa(a[1])
    n = len(p.tag)
    if op == "add":
        return pa_j(Pa.pa_add(p, pa(a[2])))
    if op == "sub":
        return pa_j(Pa.pa_sub(p, pa(a[2])))
    if op == "neg":
        return pa_j(Pa.pa_neg(p))
    if op == "scale":
        return pa_j(Pa.pa_scale(p, big(a[2])))
    if op == "addPublic0":
        return pa_j(Pa.pa_add_public0(Pa.PaEnv(pint(a[2]), n, big(a[3]), a[4] is True), p, big(a[5])))
    if op == "verify":
        return Pa.pa_verify(Pa.PaEnv(pint(a[2]), n, big(a[3]), True), p, pint(a[4]), big(a[5]), big(a[6]))
    if op == "flat":
        i = pint(a[2])
        tg = a[3] is True
        f = Pa.pa_flat(p, i, n, tg)
        return {"f": strs(f), "w": Pa.pa_width(n, tg), "back": pa_j(Pa.pa_parse(f, 0, i, n, tg))}
    raise ValueError(op)


def aw_op(*a):
    if len(a) == 1:
        return C.sharings_per_triple(pint(a[0]))
    if len(a) == 3:
        x = aw(a[0])
        n = len(x.v.tag)
        keys = len(x.m)
        i = pint(a[1])
        tg = a[2] is True
        f = Pa.aw_flat(x, i, n, tg)
        return {"f": strs(f), "w": Pa.aw_width(n, keys, tg), "back": aw_j(Pa.aw_parse(f, 0, i, n, keys, tg))}
    x = aw(a[0])
    y = aw(a[1])
    n = len(x.v.tag)
    alpha = [pa(p) for p in a[2]]
    tg = a[3] is True
    c = big(a[4])
    return {"add": aw_j(Pa.w_add(x, y)), "sub": aw_j(Pa.w_sub(x, y)), "neg": aw_j(Pa.w_neg(x)), "scale": aw_j(Pa.w_scale(x, c)),
            "addPublic": aw_j(Pa.w_add_public(Pa.PaEnv(1, n, 7, tg), x, c, alpha)),
            "addPublic0": aw_j(Pa.w_add_public(Pa.PaEnv(0, n, 7, tg), x, c, alpha))}


# ---- forensics ----
def side_j(m):
    return [[k, strs(v)] for k, v in m.items()]


def side_in(o):
    return {pint(e[0]): bigs(e[1]) for e in o}


def dis(o):
    return [Fx.SlotDisclosure([pint(b) for b in s["bits"]], big(s["y"]), big(s["z"]), side_in(s["recv"]), side_in(s["rho"])) for s in o]


def forensics(*a):
    n = len(a)
    if n == 1:
        return Fx.slots_for(pint(a[0]))
    if n == 3:
        if isinstance(a[0], dict):
            all_ = {int(k): dis(v) for k, v in a[0].items()}
            if a[2] is not None:
                all_.pop(pint(a[2]), None)
            res = Fx.audit_disclosures(all_, bigs(a[1]))
            return {"selfBad": sorted(res.self_bad), "pairBad": res.pair_bad, "blame": [Fx.blame_from(me, res) for me in range(3)]}
        return Fx.blame_from(pint(a[0]), Fx.AuditResult([pint(x) for x in a[1]], [[pint(x[0]), pint(x[1])] for x in a[2]]))
    if n == 4:
        dd = Fx.parse_disclosure(a[0], pint(a[1]), pint(a[2]), [pint(x) for x in a[3]])
        return {"dd": [{"bits": s.bits, "y": str(s.y), "z": str(s.z), "recv": side_j(s.recv), "rho": side_j(s.rho)} for s in dd],
                "back": Fx.wire_disclosure(dd)}
    if n == 6:
        return Fx.disclosure_commit(a[0], pint(a[1]), pint(a[2]), 0 if a[3] is None else int(a[3]), a[4], a[5])
    raise ValueError("forensics arity")


# ---- codecs ----
def codec(*a):
    op = a[0]
    if op == "unb64":
        return C.unb64(a[1], -1 if a[2] is None else pint(a[2]))
    if op == "b64":
        return C.b64(a[1])
    if op == "hexBig":
        return str(C.hex_big(a[1]))
    if op == "jPt":
        return C.pt_j(C.j_pt(a[1]))
    if op == "ptJ":
        return C.pt_j(Ec.mul_base(big(a[1])))
    if op == "gadgetCommit":
        return C.gadget_commit(a[1], pint(a[2]), a[3])
    if op == "gadgetStatement":
        return C.gadget_statement(a[1], a[2], pint(a[3]), a[4])
    raise ValueError(op)


def unhx(s):
    v = W.unhx(s)
    return None if v is None else str(v)


def unhx_array(a, n):
    v = W.unhx_array(a, pint(n))
    return None if v is None else [str(x) for x in v]


MAP = {
    "encodeFrame": W.encode_frame,
    "split": split,
    "peekVersion": W.peek_version,
    "parseFrame": W.parse_frame,
    "versionMismatch": W.version_mismatch,
    "hx": lambda x: W.hx(big(x)),
    "unhx": unhx,
    "unhxArray": unhx_array,
    "netAbort": net_abort,
    "abortKinds": lambda: sorted(W.ABORT_KINDS),
    "pa": pa_op,
    "aw": aw_op,
    "forensics": forensics,
    "codec": codec,
}


def test_corpus_is_covered():
    assert sorted(CASES) == sorted(MAP), "unmapped corpus functions"


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
