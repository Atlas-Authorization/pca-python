"""Liveness beacons: exact refusal reasons, window / scope / skew boundaries, issuance bounds, monotonic acceptance and the durable acceptor."""
import os

import pytest

from atlas_pca import beacon as B
from atlas_pca.agent import generate_keypair, generate_pq_keypair, sign_artifact
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.pca import supported_suites

T = 120_000_000  # a multiple of the epoch length
MAX = B.BEACON_MAX_VALIDITY_MS
SKEW = B.BEACON_CLOCK_SKEW_MS
DEL = object()


def sbeacon(k, **over):
    """A beacon signed over an arbitrary (possibly malformed) body."""
    body = {"v": 2, "instance": "inst", "scope": "*", "epoch": T // B.BEACON_EPOCH_MS, "seq": 1, "issued_at": T,
            "not_after": T + 5 * B.BEACON_EPOCH_MS, "issuer": k.public}
    body.update(over)
    for key in [x for x, v in body.items() if v is DEL]:
        del body[key]
    return sign_artifact(B.LIVENESS_DOMAIN, body, k)


def verify(b, k, now=T + 1000, instance="inst", scope=None, pins=None, issuers=None):
    return B.verify_liveness_beacon(b, [k.public] if issuers is None else issuers, now, instance, scope, pins)


def refused(reason):
    return {"ok": False, "reason": reason}


def need_suite(alg):
    if alg not in supported_suites():
        if os.environ.get("PCA_REQUIRE_PQ") == "1":
            pytest.fail(alg + ": backend required in CI")
        pytest.skip(alg + " unavailable")


# ---- issue_liveness_beacon ----------------------------------------------------------------------------------------------

def test_issue_defaults_and_fields():
    k = generate_keypair()
    b = B.issue_liveness_beacon(k, "inst", 0, 0)
    assert b["not_after"] - b["issued_at"] == 5 * B.BEACON_EPOCH_MS == 300_000
    assert (b["v"], b["instance"], b["scope"], b["epoch"], b["seq"], b["issued_at"], b["issuer"]) == (2, "inst", "*", 0, 0, 0, k.public)
    assert "alg" not in b and "pq_pk" not in b
    b = B.issue_liveness_beacon(k, "inst", 3, 130_000, "s", validity_ms=60_000)
    assert (b["epoch"], b["scope"], b["not_after"]) == (2, "s", 190_000)
    assert B.issue_liveness_beacon(k, "inst", 1, 5, validity_ms=1)["not_after"] == 6
    assert B.issue_liveness_beacon(k, "inst", 1, 5, validity_ms=MAX)["not_after"] == 5 + MAX


def _raises(**kw):
    args = dict(seq=1, issued_at=5)
    args.update(kw)
    with pytest.raises(ValueError) as e:
        B.issue_liveness_beacon(generate_keypair(), "inst", **args)
    return str(e.value)


def test_issue_bounds_and_messages():
    assert _raises(seq=-1) == "issueLivenessBeacon: seq must be a non-negative integer"
    assert _raises(seq="1") == "issueLivenessBeacon: seq must be a non-negative integer"
    assert _raises(seq=True) == "issueLivenessBeacon: seq must be a non-negative integer"
    assert _raises(issued_at=-1) == "issueLivenessBeacon: issuedAt must be an integer"
    assert _raises(issued_at=1.5) == "issueLivenessBeacon: issuedAt must be an integer"
    assert _raises(issued_at=False) == "issueLivenessBeacon: issuedAt must be an integer"
    msg = "issueLivenessBeacon: validity must be in (0, 3600000] ms"
    for v in (0, -1, MAX + 1, "x", 1.5, True):
        assert _raises(validity_ms=v) == msg, v


def test_issue_with_pq_suite_binds_alg_and_key():
    alg = "hybrid-ed25519-ml-dsa-65"
    need_suite(alg)
    k, pq = generate_keypair(), generate_pq_keypair("ML-DSA-65")
    b = B.issue_liveness_beacon(k, "inst", 1, T, alg=alg, pq=pq)
    assert b["alg"] == alg and b["pq_pk"] == pq.public and "pq_sig" in b
    pins = {k.public: pq.public}
    assert verify(b, k, pins=pins) == {"ok": True}
    assert verify(b, k) == refused("bad signature")
    assert verify(b, k, pins={k.public: generate_pq_keypair("ML-DSA-65").public}) == refused("bad signature")
    # the pins reach the acceptor and the freeze check too
    assert B.is_frozen_liveness([b], [k.public], T + 1000, "inst", None, pins) is False
    assert B.is_frozen_liveness([b], [k.public], T + 1000, "inst") is True
    acc = B.BeaconAcceptor(MemoryAtomicKv())
    assert acc.accept(b, [k.public], T + 1000, "inst", None, pins) == {"ok": True}
    assert acc.accept(b, [k.public], T + 1000, "inst") == refused("bad signature")


# ---- verify_liveness_beacon ---------------------------------------------------------------------------------------------

def test_verify_ok_and_malformed_inputs():
    k = generate_keypair()
    b = sbeacon(k)
    assert verify(b, k) == {"ok": True}
    for bad in (None, "x", [], 3):
        assert verify(bad, k) == refused("malformed beacon")
    assert verify(sbeacon(k, v=3), k) == refused("malformed beacon")
    assert verify(sbeacon(k, v=DEL), k) == refused("malformed beacon")
    for alg in (None, 5, "fn-dsa-512", "nope"):
        t = dict(b)
        t["alg"] = alg
        assert verify(t, k) == refused("malformed beacon"), alg
    # an exception inside the checks is a refusal, never a raise
    assert B.verify_liveness_beacon(b, None, T + 1000, "inst") == refused("malformed beacon")


def test_verify_instance_issuer_signature():
    k = generate_keypair()
    b = sbeacon(k)
    assert verify(b, k, instance="other") == refused("wrong instance")
    assert verify(b, k, issuers=[generate_keypair().public]) == refused("issuer not pinned")
    assert verify(b, k, issuers=[]) == refused("issuer not pinned")
    t = dict(b)
    t["seq"] = 2
    assert verify(t, k) == refused("bad signature")
    assert verify(b, k, issuers=[generate_keypair().public, k.public]) == {"ok": True}


def test_verify_window_each_field_must_be_int():
    k = generate_keypair()
    for field, bad in (("epoch", "2"), ("epoch", True), ("epoch", None) ,
                       ("seq", "1"), ("seq", True), ("seq", None) ,
                       ("issued_at", "x"), ("issued_at", True), ("issued_at", None) ,
                       ("not_after", "x"), ("not_after", True), ("not_after", None) ):
        assert verify(sbeacon(k, **{field: bad}), k) == refused("malformed window"), (field, bad)
    assert verify(sbeacon(k, seq=-1), k) == refused("malformed window")
    assert verify(sbeacon(k, seq=0), k) == {"ok": True}


def test_verify_validity_boundaries():
    k = generate_keypair()
    assert verify(sbeacon(k, not_after=T + MAX), k, now=T) == {"ok": True}
    assert verify(sbeacon(k, not_after=T + 1), k, now=T) == {"ok": True}
    for na in (T + MAX + 1, T, T - 1, T - MAX - 5):
        assert verify(sbeacon(k, not_after=na), k) == refused("validity exceeds the hard maximum"), na


def test_verify_epoch_must_match():
    k = generate_keypair()
    e = T // B.BEACON_EPOCH_MS
    for bad in (e - 1, e + 1, 0):
        assert verify(sbeacon(k, epoch=bad), k) == refused("epoch does not match issued_at")
    # the epoch floor, not the round: one ms before the boundary is still the previous epoch
    assert verify(sbeacon(k, issued_at=T - 1, not_after=T + 1000, epoch=e - 1), k, now=T) == {"ok": True}
    assert verify(sbeacon(k, issued_at=T - 1, not_after=T + 1000, epoch=e), k, now=T) == refused("epoch does not match issued_at")


def test_verify_skew_and_expiry_boundaries():
    k = generate_keypair()
    b = sbeacon(k)
    assert verify(b, k, now=T - SKEW) == {"ok": True}
    assert verify(b, k, now=T - SKEW - 1) == refused("not yet valid")
    assert verify(b, k, now=T + 300_000) == {"ok": True}
    assert verify(b, k, now=T + 300_001) == refused("expired")


def test_verify_scope_cover():
    k = generate_keypair()
    glob, mine = sbeacon(k, scope="*"), sbeacon(k, scope="a")
    assert verify(mine, k, scope="b") == refused("scope not covered")
    assert verify(mine, k, scope="a") == {"ok": True}
    assert verify(mine, k, scope=None) == {"ok": True}
    assert verify(mine, k) == {"ok": True}
    assert verify(glob, k, scope="b") == {"ok": True}
    assert verify(sbeacon(k, scope=None), k, scope="b") == refused("scope not covered")
    assert verify(sbeacon(k, scope=None), k) == {"ok": True}


# ---- is_frozen_liveness -------------------------------------------------------------------------------------------------

def test_is_frozen_each_argument_matters():
    k = generate_keypair()
    b = sbeacon(k, scope="a")
    iss = [k.public]
    now = T + 1000
    assert B.is_frozen_liveness([], iss, now, "inst") is True
    assert B.is_frozen_liveness([b], iss, now, "inst", "a") is False
    assert B.is_frozen_liveness([None, b], iss, now, "inst", "a") is False
    assert B.is_frozen_liveness([None], iss, now, "inst", "a") is True
    assert B.is_frozen_liveness([b], [], now, "inst", "a") is True
    assert B.is_frozen_liveness([b], None, now, "inst", "a") is True
    assert B.is_frozen_liveness([b], iss, T + 400_000, "inst", "a") is True
    assert B.is_frozen_liveness([b], iss, None, "inst", "a") is True
    assert B.is_frozen_liveness([b], iss, now, "other", "a") is True
    assert B.is_frozen_liveness([b], iss, now, None, "a") is True
    assert B.is_frozen_liveness([b], iss, now, "inst", "b") is True
    assert B.is_frozen_liveness([b], iss, now, "inst") is False


# ---- accept_beacon ------------------------------------------------------------------------------------------------------

def test_accept_beacon_shape():
    malformed = refused("malformed beacon")
    for bad in (None, "x", 5, [], [("seq", 1)]):
        assert B.accept_beacon(None, bad) == malformed
    for seq in (None, "1", True, False, 1.0, -1, B._MAX_SAFE + 1, DEL):
        n = {} if seq is DEL else {"seq": seq}
        assert B.accept_beacon(None, n) == malformed, seq
    assert B.accept_beacon(None, {"seq": 0}) == {"ok": True}
    assert B.accept_beacon(None, {"seq": B._MAX_SAFE}) == {"ok": True}
    assert B.accept_beacon({}, {"seq": 0}) == {"ok": True}
    assert B.accept_beacon(7, {"seq": 0}) == {"ok": True}
    assert B.accept_beacon([], {"seq": 0}) == {"ok": True}


def test_accept_beacon_monotonic():
    assert B.accept_beacon({"seq": 5}, {"seq": 6}) == {"ok": True}
    assert B.accept_beacon({"seq": 5}, {"seq": 5}) == refused("replayed beacon: seq 5 <= 5")
    assert B.accept_beacon({"seq": 5}, {"seq": 4}) == refused("replayed beacon: seq 4 <= 5")
    assert B.accept_beacon({"seq": 0}, {"seq": 0}) == refused("replayed beacon: seq 0 <= 0")


# ---- keys and the durable acceptor --------------------------------------------------------------------------------------

def test_beacon_key_exact():
    assert B._beacon_key({"instance": "i", "scope": "s", "issuer": "k"}) == 'beacon-seq/v1/["i","s","k"]'
    assert B._beacon_key({"instance": "ïnst", "scope": "☃", "issuer": "k"}) == 'beacon-seq/v1/["ïnst","☃","k"]'
    assert B._beacon_key({"instance": "i", "scope": "s", "issuer": "k"}) != B._beacon_key({"instance": "i", "scope": "s", "issuer": "j"})
    assert B._beacon_key({"instance": "i", "scope": "s", "issuer": "k"}) != B._beacon_key({"instance": "i", "scope": "t", "issuer": "k"})


class RecKv:
    def __init__(self, inner=None, boom=None):
        self.inner = inner or MemoryAtomicKv()
        self.keys, self.errs, self.boom = [], [], boom

    def update(self, key, fn):
        self.keys.append(key)
        if self.boom:
            raise self.boom

        def wrap(prev):
            try:
                return fn(prev)
            except Exception as e:  # noqa: BLE001
                self.errs.append(e)
                raise
        return self.inner.update(key, wrap)


def test_acceptor_requires_update():
    for bad in (object(), None, type("X", (), {"update": 1})()):
        with pytest.raises(TypeError) as e:
            B.BeaconAcceptor(bad)
        assert str(e.value) == "createBeaconAcceptor: a DurableKv is required"
    kv = MemoryAtomicKv()
    a = B.create_beacon_acceptor(kv)
    assert isinstance(a, B.BeaconAcceptor) and a.kv is kv


def test_acceptor_monotonic_flow_and_stored_value():
    k = generate_keypair()
    kv = RecKv()
    acc = B.BeaconAcceptor(kv)
    iss, now = [k.public], T + 1000
    b5 = sbeacon(k, seq=5)
    key = B._beacon_key(b5)
    assert acc.accept(b5, iss, now, "inst") == {"ok": True}
    assert kv.keys == [key] and kv.inner.get(key) == 5
    assert acc.accept(b5, iss, now, "inst") == refused("replayed beacon: seq 5 <= 5")
    assert acc.accept(sbeacon(k, seq=3), iss, now, "inst") == refused("replayed beacon: seq 3 <= 5")
    assert kv.inner.get(key) == 5
    assert acc.accept(sbeacon(k, seq=6), iss, now, "inst") == {"ok": True}
    assert kv.inner.get(key) == 6
    # another scope has its own counter
    other = sbeacon(k, seq=1, scope="a")
    assert acc.accept(other, iss, now, "inst") == {"ok": True}
    assert kv.inner.get(B._beacon_key(other)) == 1 and kv.inner.get(key) == 6
    assert kv.errs == []


def test_acceptor_seq_zero_then_replay():
    k = generate_keypair()
    kv = RecKv()
    acc = B.BeaconAcceptor(kv)
    b0 = sbeacon(k, seq=0)
    assert acc.accept(b0, [k.public], T + 1000, "inst") == {"ok": True}
    assert kv.inner.get(B._beacon_key(b0)) == 0
    assert acc.accept(b0, [k.public], T + 1000, "inst") == refused("replayed beacon: seq 0 <= 0")
    assert acc.accept(sbeacon(k, seq=1), [k.public], T + 1000, "inst") == {"ok": True}


def test_acceptor_returns_the_verifier_refusal_and_never_stores():
    k = generate_keypair()
    kv = RecKv()
    acc = B.BeaconAcceptor(kv)
    b = sbeacon(k, seq=2, scope="a")
    now = T + 1000
    assert acc.accept(b, [k.public], now, "other") == refused("wrong instance")
    assert acc.accept(b, [k.public], now, "inst", "b") == refused("scope not covered")
    assert acc.accept(b, [k.public], T + 999_999, "inst") == refused("expired")
    assert acc.accept(b, [], now, "inst") == refused("issuer not pinned")
    assert acc.accept(None, [k.public], now, "inst") == refused("malformed beacon")
    assert acc.accept(b, None, now, "inst") == refused("malformed beacon")
    assert acc.accept(b, [k.public], None, "inst") == refused("malformed beacon")
    assert kv.keys == []
    assert acc.accept(b, [k.public], now, "inst", "a") == {"ok": True}
    assert acc.accept(b, [k.public], now, "inst", None) == refused("replayed beacon: seq 2 <= 2")


def test_acceptor_junk_state_fails_closed_with_the_junk_error():
    k = generate_keypair()
    b = sbeacon(k, seq=5)
    key = B._beacon_key(b)
    for junk in (-1, True, False, "7", 1.5, [], {}, B._MAX_SAFE + 1):
        inner = MemoryAtomicKv()
        inner.set(key, junk)
        kv = RecKv(inner)
        r = B.BeaconAcceptor(kv).accept(b, [k.public], T + 1000, "inst")
        assert r == refused("beacon state unavailable"), junk
        assert len(kv.errs) == 1 and type(kv.errs[0]) is TypeError and str(kv.errs[0]) == "junk on disk", junk
        assert inner.get(key) == junk and type(inner.get(key)) is type(junk)


def test_acceptor_valid_stored_bounds():
    k = generate_keypair()
    b = sbeacon(k, seq=5)
    key = B._beacon_key(b)
    for prev, want in ((0, {"ok": True}), (4, {"ok": True}), (B._MAX_SAFE, refused("replayed beacon: seq 5 <= %d" % B._MAX_SAFE))):
        inner = MemoryAtomicKv()
        inner.set(key, prev)
        kv = RecKv(inner)
        assert B.BeaconAcceptor(kv).accept(b, [k.public], T + 1000, "inst") == want, prev
        assert kv.errs == []


def test_acceptor_store_failure_fails_closed():
    k = generate_keypair()
    b = sbeacon(k, seq=5)
    for boom in (RuntimeError("disk"), OSError("io"), ValueError("v")):
        r = B.BeaconAcceptor(RecKv(boom=boom)).accept(b, [k.public], T + 1000, "inst")
        assert r == {"ok": False, "reason": "beacon state unavailable"}


def test_beacon_ref_and_decision():
    k = generate_keypair()
    b = sbeacon(k)
    assert B.beacon_ref(b) == B.beacon_ref(dict(b)) and len(B.beacon_ref(b)) == 43
    for present, ok, replayed, binds, want in ((False, True, True, True, "not-enforced"), (True, False, True, True, "rejected"),
                                               (True, True, True, True, "replayed"), (True, True, False, False, "unbound"),
                                               (True, True, False, True, "pass")):
        assert B.beacon_decision(present, ok, replayed, binds) == want
