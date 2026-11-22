"""Replays the TS-reference oracle of guardian high availability (testdata/ref-ha.json.gz, 753 cases): liveness, quorum, degrade mode,
signer selection, failover, the guardian-set validator, the fence guard, the lease op scripts (acquire / renew / release / fence /
fenced signer over an in-memory store with a settable clock and injected faults) and the raw compare-and-swap of the key/value store.
Every fn and every lease op has a handler; the totals are asserted."""
import math
import os

import pytest

from atlas_pca import ha as H
from atlas_pca.durable_state import create_memory_durable_kv
from base_oracle import HERE, load

COUNT, CASES = load("ha", os.path.join(HERE, "testdata", "ref-ha.json.gz"))
KEY = "ha/lease"
SEEN_OPS = set()


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _lease(ops):
    kv = create_memory_durable_kv()
    st = {"clock": 0, "fault": "none", "lose": False}
    kvs = H.KvLeaseStore(kv, now=lambda: st["clock"])

    def read():
        if st["fault"] == "read":
            raise RuntimeError("boom")
        return kvs.read()

    def now():
        if st["fault"] == "now":
            raise RuntimeError("boom")
        return kvs.now()

    def cas(e, n):
        if st["fault"] == "cas":
            raise RuntimeError("boom")
        if st["lose"]:
            st["lose"] = False
            return False
        return kvs.cas(e, n)

    store = type("S", (), {"read": staticmethod(read), "now": staticmethod(now), "cas": staticmethod(cas)})
    refs = {}
    res = lambda x: refs.get(x) if isinstance(x, str) else x  # noqa: E731
    out = []
    for op in ops:
        SEEN_OPS.add(op[0])
        k = op[0]
        if k == "clock":
            st["clock"] = op[1]
            out.append(None)
        elif k == "fault":
            if op[1] == "loseCas":
                st["lose"] = True
            else:
                st["fault"] = op[1]
            out.append(None)
        elif k == "raw":
            kv.set(KEY, op[1])
            out.append(None)
        elif k == "read":
            out.append(kv.get(KEY))
        elif k == "acquire":
            r = H.acquire_lease(store, op[2], op[3])
            if r["ok"]:
                refs[op[1]] = r["lease"]
            out.append(r)
        elif k in ("renew", "release"):
            r = H.renew_lease(store, res(op[1]), op[2]) if k == "renew" else H.release_lease(store, res(op[1]))
            if r["ok"] and isinstance(op[1], str):
                refs[op[1]] = r["lease"]
            out.append(r)
        elif k == "fence":
            out.append(H.assert_fence(store, res(op[1]), *([] if op[2] is None else [op[2]])))
        elif k == "signer":
            lease = None if op[1] is None else res(op[1])

            def sign(adv=op[3], boom=op[4]):
                st["clock"] += adv
                if boom:
                    raise RuntimeError("sign")
                return "signed"

            f = H.fenced_signer(store, lambda: lease, sign, *([] if op[2] is None else [op[2]]))
            try:
                r = f()
                out.append({"ok": True, "result": r["result"], "epoch": r["epoch"]})
            except H.FenceError as e:
                out.append({"ok": False, "reason": e.reason})
            except RuntimeError as e:
                out.append({"ok": False, "error": str(e)})
        else:
            out.append({"$err": "bad op"})
    return out


def _opts(o):
    return {} if o is None else o


def _fence_guard(init, epochs):
    g = H.create_fence_guard(init)
    return {"admits": [g.admit(e) for e in epochs], "highest": g.highest()}


def _kv_cas(prev, exp, nxt):
    kv = create_memory_durable_kv()
    if prev is not None:
        kv.set(KEY, prev)
    ok = H.KvLeaseStore(kv, now=lambda: 0).cas(exp, nxt)
    return {"ok": ok, "stored": kv.get(KEY)}


HANDLERS = {
    "liveGuardians": lambda s, n, o: H.live_guardians(s, n, _opts(o)),
    "quorumStatus": lambda s, n, o: H.quorum_status(s, n, _opts(o)),
    "selectSigners": lambda s, n, o: H.select_signers(s, n, _opts(o)),
    "failoverPlan": lambda s, n, o: H.failover_plan(s, n, _opts(o)),
    "degradeMode": lambda st, p: H.degrade_mode(st, _opts(p)),
    "validateGuardianSet": H.validate_guardian_set,
    "fenceGuard": _fence_guard,
    "lease": _lease,
    "constants": lambda: {"MAX_LEASE_TTL_MS": H.MAX_LEASE_TTL_MS, "DEFAULT_LEASE_SKEW_MS": H.DEFAULT_LEASE_SKEW_MS},
    "kvCas": _kv_cas,
}
TOTALS = {"liveGuardians": 144, "quorumStatus": 144, "selectSigners": 144, "failoverPlan": 144, "degradeMode": 70, "lease": 45,
          "validateGuardianSet": 33, "kvCas": 17, "fenceGuard": 11, "constants": 1}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 753 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_ha_replay(fn):
    from base_oracle import run
    ran, skipped = run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))))
    assert (ran, skipped) == (TOTALS[fn], 0)


def test_every_lease_op_was_replayed():
    test_ha_replay("lease")
    assert SEEN_OPS == {"clock", "fault", "raw", "read", "acquire", "renew", "release", "fence", "signer", "bogus"}
