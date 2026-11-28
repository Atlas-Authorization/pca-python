"""Replays the TS-reference oracle of networked FROST signing (testdata/ref-frost-net.json.gz, 634 cases) for the parts that are pure functions and
stores, the signer service and the coordinator: the allow token, the signer proof of possession and its enrollment gate, the equivocation guard, the wire decoders, the nonce store (and the contract
a custom store must pass, checked against stores broken in each way), the group-algorithm registry, the hybrid co-sign and the PQ quorum block. Dealer shares
are rebuilt from their descriptor with the lane's own trusted-dealer keygen; the reference's random draws (``$rng``) are replayed through the ``random_bytes``
seam. A refusal is compared by its class and fields (typed errors) and, unless the case marks the reason open, its text. The guardian signer SERVICE and the NETWORK COORDINATOR run in process over scripted randomness, clock and transports (delays, hostile edits, canned responses). Needs libsodium (the ``ristretto`` extra) and an ML-DSA-65 backend (OpenSSL >= 3.5 or the ``pq`` extra)."""
import copy
import math
import os
import time

import pytest

from atlas_pca import frost as F
from atlas_pca import frost_net as N
from atlas_pca import frost_nonce_store as NS
from atlas_pca import frost_pq as FP
from atlas_pca import pq_threshold as PT
from atlas_pca.agent import generate_pq_keypair
from atlas_pca.pca import b64u, decode_b64u_strict, verify_leaf_suite
from base_oracle import HERE, canon, norm, load, run

COUNT, CASES = load("frost-net", os.path.join(HERE, "testdata", "ref-frost-net.json.gz"))
NUM = {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}


def _rv(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return NUM[v["$num"]]
        if set(v) == {"$share"}:
            s = v["$share"]
            kg = F.trusted_dealer_keygen(s["t"], s["n"], s["secret"], s["coefficients"], s.get("identifiers"))
            return next(p["share"] for p in kg["participantShares"] if p["identifier"] == s["id"])
        return {k: _rv(x) for k, x in v.items()}
    return [_rv(x) for x in v] if isinstance(v, list) else v


def _rng(args):
    """(args without the trailing {"$rng": [...]}, a random_bytes seam replaying the draws in order)."""
    if args and isinstance(args[-1], dict) and set(args[-1]) == {"$rng"}:
        draws = iter(args[-1]["$rng"])
        return args[:-1], lambda n: next(draws)[:n]
    return args, os.urandom


def _prep(f, rng=False):
    def go(*args):
        args = _rv(list(args))
        if rng:
            args, rb = _rng(args)
            return f(*args, random_bytes=rb)
        return f(*args)
    return go


def _err(e):
    out = {"$throws": str(e)}
    if type(e).__name__ in ("PoPError", "EquivocationError", "CoordinatorError", "CoordinatorTimeoutError"):
        out["class"] = type(e).__name__
        for k in ("identifier", "session_id", "round", "previousDigest", "offendingDigest", "refusals", "timeoutMs"):
            if hasattr(e, k):
                out[k] = getattr(e, k)
    return out


def _guard(ops):
    g, out = N.EquivocationGuard(), []
    for op in ops:
        try:
            if op["op"] == "observe":
                g.observe(op["session_id"], op["round"], op["identifier"], op["message"])
            else:
                g.forget(op["session_id"])
            out.append({"ok": True})
        except Exception as e:  # noqa: BLE001
            out.append(_err(e))
    return out


def _enroll(enrollments, expect):
    try:
        return N.enroll_verification_shares(enrollments, expect)
    except N.PoPError as e:
        return _err(e)


def _nonce_store(ops):
    st, out = NS.MemoryNonceStore(), []
    for op in ops:
        try:
            if op["op"] == "create":
                st.create(op["sid"], op["rec"])
                out.append({"ok": True})
            elif op["op"] == "load":
                out.append({"value": st.load(op["sid"])})
            elif op["op"] == "spend":
                st.spend(op["sid"])
                out.append({"ok": True})
            elif op["op"] == "drop":
                st.drop(op["sid"])
                out.append({"ok": True})
            else:
                out.append({"value": st.is_spent(op["sid"])})
        except Exception as e:  # noqa: BLE001
            out.append(_err(e))
    return out


def _broken_store(kind):
    live, spent = {}, set()

    def cp(r):
        return {k: (bytes(v) if isinstance(v, (bytes, bytearray)) else v) for k, v in r.items()}

    class Store:
        def create(self, sid, r):
            if kind != "create-overwrites" and sid in live:
                raise ValueError("exists")
            if kind != "create-over-spent" and sid in spent:
                raise ValueError("spent")
            live[sid] = r if kind == "create-aliases-input" else cp(r)

        def load(self, sid):
            r = live.get(sid)
            return None if r is None else (r if kind == "load-aliases" else cp(r))

        def spend(self, sid):
            if sid not in live:
                if kind == "spend-unknown-ok" or (kind == "spend-twice-ok" and sid in spent):
                    return
                raise ValueError("not live")
            del live[sid]
            spent.add(sid)

        def drop(self, sid):
            live.pop(sid, None)
            if kind == "drop-marks-spent":
                spent.add(sid)

        def is_spent(self, sid):
            return True if kind == "unknown-reports-spent" else sid in spent

    st = Store()

    def reopen(s):
        if kind == "spent-forgotten-on-restart":
            spent.clear()
        if kind == "live-lost-on-restart":
            live.clear()
        return s
    return (lambda: st), reopen


def _contract(a):
    if a["store"] == "memory":
        NS.assert_nonce_store_contract(NS.MemoryNonceStore)
    else:
        make, reopen = _broken_store(a["store"][len("broken:"):])
        NS.assert_nonce_store_contract(make, reopen)
    return None


def _sign_hybrid(gpk, quorum, message, opts):
    o = {k: v for k, v in opts.items() if k not in ("guardianMlDsaSeed", "guardianMlDsa")}
    if "guardianMlDsaSeed" in opts:
        o["guardianMlDsa"] = generate_pq_keypair("ML-DSA-65", opts["guardianMlDsaSeed"])
    art = FP.sign_hybrid_frost_cosign(gpk, quorum, message, o)
    out = {k: v for k, v in art.items() if k != "sig"}
    raw = decode_b64u_strict(art["sig"])
    out["sigLength"] = len(raw)
    out["sigVerifies"] = len(raw) == 64 and verify_leaf_suite({"alg": "ed25519", "sig": art["sig"]}, b64u(bytes(gpk)), bytes(message))
    return out


def _ordered_pool(pks):
    """The pool in input order (the reference returns a Set): each entry normalised alone, first occurrence kept."""
    PT.normalize_pq_quorum_pool(pks)
    out = []
    for p in pks:
        for s in PT.normalize_pq_quorum_pool([p]):
            if s not in out:
                out.append(s)
    return out


def _sign_pq_quorum(message, seeds, pq_t):
    return FP.sign_pq_quorum(message, [generate_pq_keypair("ML-DSA-65", s) for s in seeds], pq_t)


class _FailStore(NS.MemoryNonceStore):
    def __init__(self, method):
        super().__init__()
        self._m = method

    def _chk(self, m):
        if self._m == m:
            raise RuntimeError("store down")

    def create(self, a, b):
        self._chk("create")
        return super().create(a, b)

    def load(self, a):
        self._chk("load")
        return super().load(a)

    def spend(self, a):
        self._chk("spend")
        return super().spend(a)

    def drop(self, a):
        self._chk("drop")
        return super().drop(a)

    def is_spent(self, a):
        self._chk("isSpent")
        return super().is_spent(a)


class _NoSpendStore:
    def create(self, *a):
        pass

    def load(self, *a):
        pass

    def drop(self, *a):
        pass

    def is_spent(self, *a):
        pass


def _mk_store(kind):
    if not kind or kind == "none":
        return None
    if kind == "memory":
        return NS.MemoryNonceStore()
    if kind == "invalid-no-spend":
        return _NoSpendStore()
    if kind.startswith("fail-"):
        return _FailStore(kind[5:])
    raise AssertionError("store " + kind)


def _svc(cfg, store, clock, rb):
    return N.GuardianSignerService(cfg["identifier"], cfg["share"], cfg["groupPublicKey"], cfg["threshold"], cfg["policyAuthorityPublicKey"],
                                   cfg.get("sessionTtlMs"), clock, store, rb)


def _signer_service(cfg, steps, random_bytes=os.urandom):
    clock = [cfg.get("clock") if cfg.get("clock") is not None else 1000000]
    store = _mk_store(cfg.get("store"))
    out = {"ctor": None, "steps": []}
    try:
        svc = _svc(cfg, store, lambda: clock[0], random_bytes)
        out["ctor"] = {"verificationShare": svc.verification_share, "pop": svc.proof_of_possession, "enrollment": svc.enrollment()}
    except Exception as e:  # noqa: BLE001
        return {"ctor": _err(e), "steps": []}
    for st in steps:
        try:
            op = st["op"]
            if op == "round1":
                out["steps"].append(svc.round1(st["req"]))
            elif op == "round2":
                out["steps"].append(svc.round2(st["req"]))
            elif op == "clock":
                clock[0] += st["ms"]
                out["steps"].append({"clock": clock[0]})
            elif op == "restart":
                svc = _svc(cfg, store, lambda: clock[0], random_bytes)
                out["steps"].append({"restarted": True, "pop": svc.proof_of_possession})
            elif op == "storeLoad":
                out["steps"].append({"live": store.load(st["sid"]) is not None})
            elif op == "storeIsSpent":
                out["steps"].append({"spent": store.is_spent(st["sid"])})
            else:
                raise AssertionError("bad step")
        except Exception as e:  # noqa: BLE001
            out["steps"].append(_err(e))
    return out


def _flip(v):
    import base64
    raw = bytearray(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)))
    raw[0] ^= 1
    return b64u(bytes(raw))


def _apply_edits(resp, edits, rnd):
    r = copy.deepcopy(resp)
    for e in edits or []:
        if e["round"] != rnd:
            continue
        parent = r
        for k in e["path"][:-1]:
            parent = parent.get(k) if isinstance(parent, dict) else None
        key = e["path"][-1]
        if not isinstance(parent, dict):
            continue
        if e["op"] == "set":
            parent[key] = e["value"]
        elif e["op"] == "delete":
            parent.pop(key, None)
        elif e["op"] == "flip":
            parent[key] = _flip(parent[key])
    return r


class _Transport:
    def __init__(self, s):
        self.identifier = s["identifier"]
        self._s, self._n = s, {1: 0, 2: 0}
        self._svc = None
        if not s.get("canned"):
            draws = iter(s["rng"])
            self._svc = _svc(s, _mk_store(s.get("store")), lambda: 1000000, lambda n: next(draws)[:n])

    def _respond(self, rnd, req):
        s = self._s
        key = "r%d" % rnd
        n = self._n[rnd]
        self._n[rnd] += 1
        if (s.get("delay") or {}).get(key):
            time.sleep(s["delay"][key] / 1000.0)
        if (s.get("throws") or {}).get(key):
            raise RuntimeError("unreachable")
        if s.get("canned"):
            lst = s["canned"]["round%d" % rnd]
            c = lst[n] if n < len(lst) else "throw"
            if c == "throw":
                raise RuntimeError("unreachable")
            resp = c
        else:
            resp = self._svc.round1(req) if rnd == 1 else self._svc.round2(req)
        return _apply_edits(resp, s.get("edits"), rnd)

    def round1(self, req):
        return self._respond(1, req)

    def round2(self, req):
        return self._respond(2, req)


def _coordinator(cfg):
    out = {"calls": []}
    sids = list(cfg.get("sessionIds") or [])

    def next_sid():
        if not sids:
            raise RuntimeError("no more scripted session ids")
        return sids.pop(0)
    try:
        coord = N.NetworkCoordinator(cfg["groupPublicKey"], cfg["threshold"], [_Transport(s) for s in cfg["signers"]], cfg.get("verificationShares"),
                                     cfg.get("enroll"), cfg.get("timeoutMs"), next_sid)
    except Exception as e:  # noqa: BLE001
        out["ctor"] = _err(e)
        return out
    for c in cfg["calls"]:
        try:
            r = coord.sign(c["message"], c["allow"], c.get("signerIds"), c.get("timeoutMs"))
            out["calls"].append({"signature": r["signature"], "sessionId": r["sessionId"], "signers": r["signers"]})
        except Exception as e:  # noqa: BLE001
            out["calls"].append(_err(e))
    return out


HANDLERS = {
    "signerService": _prep(_signer_service, rng=True),
    "coordinator": _prep(_coordinator),
    "constants": lambda: {"ALLOW_TOKEN_TYP": N.ALLOW_TOKEN_TYP, "SIGNER_POP_DST": N.SIGNER_POP_DST, "MAX_FROST_SIGNING_SET": N.MAX_FROST_SIGNING_SET,
                          "DEFAULT_FROST_GROUP_ALG": FP.DEFAULT_FROST_GROUP_ALG, "PQ_QUORUM_VERSION": FP.PQ_QUORUM_VERSION, "PQ_QUORUM_ALG": FP.PQ_QUORUM_ALG,
                          "MAX_PQ_QUORUM_ENTRIES": FP.MAX_PQ_QUORUM_ENTRIES},
    "frostActionDigest": N.frost_action_digest,
    "issueAllowToken": _prep(N.issue_allow_token, rng=True),
    "verifyAllowToken": _prep(N.verify_allow_token),
    "createSignerPoP": _prep(N.create_signer_pop, rng=True),
    "verifySignerPoP": _prep(N.verify_signer_pop),
    "enrollVerificationShares": _prep(_enroll),
    "equivocationGuard": _guard,
    "decodeCommitment": N.decode_commitment,
    "decodeCommitments": N.decode_commitments,
    "decodeVerificationShares": N.decode_verification_shares,
    "nonceStore": _nonce_store,
    "assertNonceStoreContract": _contract,
    "resolveFrostGroupAlg": FP.resolve_frost_group_alg,
    "frostSignerSetDigest": FP.frost_signer_set_digest,
    "frostCosignRepresentative": FP.frost_cosign_representative,
    "verifyHybridFrostCosign": FP.verify_hybrid_frost_cosign,
    "signHybridFrostCosign": lambda *a: _sign_hybrid(*_rng(_rv(list(a)))[0]),  # the reference's nonce draws are not replayed: the signature is random
    "pqQuorumRepresentative": FP.pq_quorum_representative,
    "signPqQuorum": _sign_pq_quorum,
    "normalizePqQuorumPool": lambda pks: _ordered_pool(pks),
    "verifyPqQuorum": lambda block, msg, pool, pq_t: FP.verify_pq_quorum(block, msg, set(pool), pq_t),
}
TOTALS = {"constants": 1, "frostActionDigest": 7, "issueAllowToken": 25, "verifyAllowToken": 58, "createSignerPoP": 24, "verifySignerPoP": 36,
          "enrollVerificationShares": 23, "equivocationGuard": 27, "decodeCommitment": 22, "decodeCommitments": 10, "decodeVerificationShares": 16,
          "nonceStore": 16, "assertNonceStoreContract": 11, "resolveFrostGroupAlg": 16, "frostSignerSetDigest": 17, "frostCosignRepresentative": 13,
          "verifyHybridFrostCosign": 60, "signHybridFrostCosign": 18, "pqQuorumRepresentative": 4, "signPqQuorum": 7, "normalizePqQuorumPool": 6,
          "verifyPqQuorum": 36, "signerService": 95, "coordinator": 86}


def _err_eq(g, o):
    return isinstance(g, dict) and "$throws" in g and _eq({k: v for k, v in g.items() if k != "$throws"}, {k: v for k, v in o.items() if k != "$throws"})


def _eq(g, o):
    g = norm(g)
    """Recursive equality; a dict marked ``reasonOpen`` (a reason that wraps a library message) must carry a reason (or a refusal text) but not the same one."""
    if isinstance(o, dict):
        if not isinstance(g, dict):
            return False
        open_ = bool(o.get("reasonOpen"))
        ok = {k for k in o if k != "reasonOpen"}
        if set(g) != ok:
            return False
        return all(True if (open_ and k in ("reason", "$throws")) else _eq(g[k], o[k]) for k in ok)
    if isinstance(o, list):
        return isinstance(g, (list, tuple)) and len(g) == len(o) and all(_eq(x, y) for x, y in zip(g, o))
    return canon(g) == canon(o)


def _same(got, out, _case):
    return _eq(got, out)


def _refused(got, case):
    return _err_eq(got, case["out"])


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 634 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_frost_net_replay(fn):
    assert run(CASES[fn], HANDLERS[fn], compare=_same, refused=_refused) == (TOTALS[fn], 0)
