"""Replays the TS-reference oracle of the liveness beacons (testdata/ref-beacons.json.gz, 174 cases): issue under every suite, the signed message, the
reference, verification (reason texts exactly), replay acceptance, the frozen-liveness check and the durable acceptor over one in-memory key/value
store (with an injected store failure and junk written into a sequence slot). Every fn has a handler and the totals are asserted; a reference
refusal needs a native exception. The 1 verification the reference accepts only through the legacy unbound-PQ opt-out is asserted REFUSED (no native
lane offers that option)."""
import json
import math
import os

import pytest

from atlas_pca import beacon as B
from atlas_pca.agent import KeyPair
from atlas_pca.durable_state import create_memory_durable_kv
from atlas_pca.pq_suites import ml_dsa65_keygen
from atlas_pca.intent_v2 import _UNDEF
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("beacons", os.path.join(HERE, "testdata", "ref-beacons.json.gz"))
UNBOUND = []


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _issue(a):
    if "instance" not in a:  # an absent instance has no canonical form in the reference
        raise TypeError("canonicalize: unsupported type undefined")
    s = a.get("suite")
    alg, pq = (None, None) if s is None else (s["alg"], None if s["alg"] == "ed25519" or "pqSeed" not in s else ml_dsa65_keygen(s["pqSeed"]))
    return B.issue_liveness_beacon(KeyPair(a["issuerSecret"], allow_insecure_signer=True), a["instance"], a.get("seq"), a.get("issuedAt"),
                                   B.GLOBAL_SCOPE if a.get("scope") is None else a["scope"], a.get("validityMs"), alg, pq)


def _verify(b, c):
    return B.verify_liveness_beacon(b, c["issuers"], c.get("now", _UNDEF), c.get("instance", _UNDEF), c.get("scope"), c.get("pqPins"))


class _Kv:
    def __init__(self):
        self.kv, self.fail = create_memory_durable_kv(), False

    def update(self, key, fn):
        if self.fail:
            self.fail = False
            raise RuntimeError("kv down")
        return self.kv.update(key, fn)


def _acceptor(ops):
    k = _Kv()
    acc = B.create_beacon_acceptor(k)
    out = []
    for op in ops:
        if op[0] == "accept":
            c = op[2]
            out.append(acc.accept(op[1], c["issuers"], c["now"], c["instance"], c.get("scope"), c.get("pqPins")))
        elif op[0] == "fail":
            k.fail = True
            out.append(None)
        elif op[0] == "raw":
            k.kv.set(B._beacon_key(op[1]), op[2])
            out.append(None)
        else:
            out.append({"$err": "op"})
    return out


def _ctor(kv):
    try:
        if kv == "ok":
            B.create_beacon_acceptor(create_memory_durable_kv())
        elif isinstance(kv, dict):  # a JS object: `update` is its own member, never a dict method
            if kv.get("update") != "fn":
                raise TypeError("a DurableKv is required")
            B.create_beacon_acceptor(type("K", (), {"update": staticmethod(lambda k, f: 0)})())
        else:
            B.create_beacon_acceptor(kv)
        return {"built": True}
    except Exception:  # noqa: BLE001
        return {"built": False}


HANDLERS = {
    "issueLivenessBeacon": _issue, "livenessBeaconMessage": B.liveness_beacon_message, "beaconRef": B.beacon_ref, "verifyLivenessBeacon": _verify,
    "acceptBeacon": B.accept_beacon,
    "isFrozenLiveness": lambda bs, c: B.is_frozen_liveness(bs, c["issuers"], c["now"], c["instance"], c.get("scope"), c.get("pqPins")),
    "acceptor": _acceptor, "ctor": _ctor,
    "constants": lambda: {"GLOBAL_SCOPE": B.GLOBAL_SCOPE, "BEACON_EPOCH_MS": B.BEACON_EPOCH_MS, "BEACON_MAX_VALIDITY_MS": B.BEACON_MAX_VALIDITY_MS,
                          "BEACON_CLOCK_SKEW_MS": B.BEACON_CLOCK_SKEW_MS},
}
TOTALS = {"verifyLivenessBeacon": 67, "issueLivenessBeacon": 36, "acceptor": 19, "acceptBeacon": 18, "livenessBeaconMessage": 12, "beaconRef": 8,
          "isFrozenLiveness": 8, "ctor": 5, "constants": 1}


def _same(got, out, case):
    if case["fn"] == "verifyLivenessBeacon" and "allowUnboundPq" in json.dumps(case["args"]) and isinstance(out, dict) and out.get("ok") is True:
        UNBOUND.append(case["name"])
        return isinstance(got, dict) and got.get("ok") is False
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 174 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 21


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_beacons_replay(fn):
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same) == (TOTALS[fn], 0)
    if fn == "verifyLivenessBeacon":
        assert len(UNBOUND) == 1
