"""Kill tests (intent_v2, sigstore_bundle, fastapi, store_conformance, pca): early exits observed through call counts, the
exact revocation-age reason, wallet accumulators, the arguments rule 14 hands to the model rules, and the refusal class."""
import asyncio
import threading
import time

import pytest

import test_mutation_kill_intent_v2 as T
from atlas_pca import intent_v2 as V
from atlas_pca import pca as P
from atlas_pca import store_conformance as SC
from atlas_pca.intent_v2 import session_root_digest


def test_revocation_age_unknown_reason():
    assert V.check_revocation_age(None, 5, 10) == {"ok": False, "reason": "revocation state age is unknown (unverifiable revocation state)"}
    assert V.check_revocation_age(float("inf"), 5, 10, "the epoch") == {"ok": False, "reason": "the epoch age is unknown (unverifiable revocation state)"}


def test_schema_and_receipt_searches_stop_at_the_first_match(monkeypatch):
    seen = {"schema": 0, "receipt": 0}
    real_s, real_r = V.action_schema_digest, V.acc_receipt_digest

    def spy_s(d):
        seen["schema"] += 1
        return real_s(d)

    def spy_r(r):
        seen["receipt"] += 1
        return real_r(r)

    monkeypatch.setattr(V, "action_schema_digest", spy_s)
    monkeypatch.setattr(V, "acc_receipt_digest", spy_r)

    def count(key, ctx, step):
        seen[key] = 0
        step(ctx)
        return seen[key]

    one = T._ctx()
    two = T._ctx(schema={"docs": [T.SCHEMA, T.SCHEMA], "keys": T.KEYS})
    assert count("schema", two, lambda c: V._schema_step(T.P0, c)) == count("schema", one, lambda c: V._schema_step(T.P0, c))
    assert count("schema", two, lambda c: V._acc_step(T.P0, c, T.NOW)) == count("schema", one, lambda c: V._acc_step(T.P0, c, T.NOW))

    rc = T._receipt()
    r1 = T._c_seq([rc], keys=[T.KS])
    r2 = T._c_seq([rc, rc], keys=[T.KS])
    p = T._p_seq(rc)
    assert count("receipt", r2, lambda c: V._acc_step(p, c, T.NOW)) == count("receipt", r1, lambda c: V._acc_step(p, c, T.NOW))
    assert seen["receipt"] >= 1


def test_rule_14_hands_the_model_rules_every_argument(monkeypatch):
    got = []
    monkeypatch.setattr(V, "_model_rules", lambda *a: got.append(a))
    out, p, grant, ctx = {"checks": []}, {}, {"g": 1}, {"policy": {}}
    V._decide_intent_v2(out, p, grant, ctx, 5)
    assert len(got) == 1
    a = got[0]
    assert a[0] is out and a[1] is p and a[2] is grant and a[3] is ctx and callable(a[4])
    assert set(a[5]) == {"verb", "resource", "params"} and a[5]["params"] == {}


# ---- fastapi

def test_pca_refusal_carries_status_detail_headers_and_doc(monkeypatch):
    pytest.importorskip("fastapi")
    from atlas_pca import fastapi as F
    monkeypatch.setattr(F, "_REFUSAL", None)  # the class is cached on first use: build it from the code under test
    R = F._refusal_class()
    e = R(403, {"a": 1}, {"X-H": "v"}, "https://doc.example")
    assert (e.status_code, e.detail, e.headers, e.doc) == (403, {"a": 1}, {"X-H": "v"}, "https://doc.example")
    d = R(400, "x")
    assert (d.status_code, d.detail, d.headers, d.doc) == (400, "x", None, "")


def test_pca_handler_renders_detail_doc_status_and_headers(monkeypatch):
    pytest.importorskip("fastapi")
    from atlas_pca import fastapi as F
    monkeypatch.setattr(F, "_REFUSAL", None)
    R = F._refusal_class()
    reg = {}

    class App:
        def exception_handler(self, cls):
            def deco(f):
                reg["cls"], reg["f"] = cls, f
                return f
            return deco

    F.add_pca_handler(App())
    assert reg["cls"] is R
    resp = asyncio.run(reg["f"](None, R(409, "d", {"X-A": "b"}, "u")))
    assert resp.status_code == 409 and resp.headers["x-a"] == "b"
    assert resp.body == b'{"detail":"d","doc":"u"}'


# ---- strict JSON: whitespace inside empty containers

def test_empty_containers_may_hold_whitespace():
    assert P.strict_parse("{ }") == {} and P.strict_parse("[ ]") == [] and P.strict_parse('{"a": [ \n ]}') == {"a": []}


# ---- store conformance: a store that raises under contention is reported by every race

class _Busy:
    """Wraps a store: a call to one of `raising` made from a worker thread while another worker is inside the store raises
    (the winner holds the store for 50 ms); every other call, and every main-thread call, passes straight through."""

    def __init__(self, inner, raising):
        self._i, self._r, self._l = inner, raising, threading.Lock()

    def _go(self, name, *a):
        if name not in self._r or threading.current_thread() is threading.main_thread():
            return getattr(self._i, name)(*a)
        if not self._l.acquire(blocking=False):
            raise RuntimeError("busy")
        try:
            time.sleep(0.05)
            return getattr(self._i, name)(*a)
        finally:
            self._l.release()

    def claim(self, *a):
        return self._go("claim", *a)

    def create(self, *a):
        return self._go("create", *a)

    def transition(self, *a):
        return self._go("transition", *a)

    def get(self, *a):
        return self._go("get", *a)


def _status(report):
    return {x.test: x for x in report.results}


def _must_fail(s, *names):
    for name in names:
        assert s[name].status == "fail" and "concurrent calls raised" in s[name].note, (name, s[name])


def test_every_race_reports_a_state_store_that_raises_under_contention():
    from atlas_pca import MemoryStateStore
    st = _Busy(MemoryStateStore(), {"claim"})
    r = SC.run_state_store_conformance(lambda: st, durable=False, threads=4, rounds=2, handles=2)
    _must_fail(_status(r), "claim-burst", "claim-concurrent", "retry-after-timeout")


def test_every_race_reports_an_operation_store_that_raises_under_contention():
    from atlas_pca import MemoryOperationStore
    only_create = _Busy(MemoryOperationStore(), {"create"})
    r = SC.run_operation_store_conformance(lambda: only_create, durable=False, threads=4, rounds=2, handles=2)
    _must_fail(_status(r), "create-race", "cross-handle")
    only_transition = _Busy(MemoryOperationStore(), {"transition"})
    r = SC.run_operation_store_conformance(lambda: only_transition, durable=False, threads=4, rounds=2, handles=2)
    s = _status(r)
    _must_fail(s, "transition-race", "cross-handle")
    assert s["create-race"].status == "pass"


# ---- sigstore: an SCT whose log key is not valid at its timestamp does not end the search

def test_sct_search_continues_past_an_entry_outside_its_log_window(monkeypatch):
    pytest.importorskip("cryptography")
    from atlas_pca import sigstore_bundle as S
    from test_k05_kill_stores_sigstore import ISSUER, ROOTS, _lst, _leaf, _sct
    monkeypatch.setattr(S, "_verify", lambda *a: True)
    assert S._verify_sct(_leaf(_lst(_sct(ts=99), _sct())), ISSUER, ROOTS) is None
    assert S._verify_sct(_leaf(_lst(_sct(ts=99))), ISSUER, ROOTS) == "SCT log key not valid at its timestamp"


def test_rule_14_hands_the_model_rules_every_argument_for_a_session(monkeypatch):
    got = []
    monkeypatch.setattr(V, "_model_rules", lambda *a: got.append(a))
    ctx = T._ctx()
    out = {"checks": []}
    V._decide_intent_v2(out, T.P0, T.G0, ctx, T.NOW)
    assert len(got) == 1
    a = got[0]
    assert a[0] is out and a[1] is T.P0 and a[2] is T.G0 and a[3] is ctx and callable(a[4])
    assert set(a[5]) == {"verb", "resource", "params"}


def test_sct_search_continues_past_every_kind_of_skipped_entry(monkeypatch):
    pytest.importorskip("cryptography")
    from atlas_pca import sigstore_bundle as S
    from test_k05_kill_stores_sigstore import ISSUER, OPEN, ROOTS, _lst, _leaf, _sct
    monkeypatch.setattr(S, "_verify", lambda *a: True)
    v = lambda roots, *s: S._verify_sct(_leaf(_lst(*s)), ISSUER, roots)  # noqa: E731
    assert v(ROOTS, _sct(version=1), _sct()) is None            # a non-v1 entry
    assert v(ROOTS, _sct(log_id=b"O" * 32), _sct()) is None     # an unknown log
    assert v(ROOTS, _sct(hash_alg=5), _sct()) is None           # an unsupported algorithm
    assert v(OPEN, _sct(ts=2 ** 53), _sct()) is None            # a timestamp out of range
    assert v(ROOTS, _sct(ts=99), _sct()) is None                # outside the log key's window
