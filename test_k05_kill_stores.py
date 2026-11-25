"""k05 mutation-kill tests, group "stores": store_conformance (driven with deliberately broken fake stores so every
assertion / skip fires with its exact note), lease, break_glass, read_vault, readside, revocation_staleness and
plan_lifecycle. Expectations follow the TypeScript references (pca-grants/src/lease.ts, breakglass.ts,
pca/src/read-vault.ts, readside.ts, revocation.ts, server/plan-lifecycle.ts); store_conformance is the Python-only twin of
pca-store-conformance (its notes are this SDK's API). Deterministic, no network."""
from atlas_pca.atomic_kv import MemoryAtomicKv
import copy
import threading

import pytest

from atlas_pca import break_glass as BG
from atlas_pca import lease as L
from atlas_pca import read_vault as RV
from atlas_pca import readside as RS
from atlas_pca import revocation_staleness as ST
from atlas_pca import store_conformance as SC
from atlas_pca.agent import KeyPair, _sign_body
from atlas_pca.plan_lifecycle import PlanRegistry, plan_root
from test_break_glass_vectors import DOC as BGDOC
from test_k5_read_vault import VA
from test_lease_vectors import DOC as LDOC
from test_revocation_staleness import DOC as SDOC

# ======================================================================================================== store_conformance


def _rows(rep):
    return [(r.test, r.status, r.note) for r in rep.results]


class _Be:
    """A shared backend: one lock, the claims and the operation records, plus an event log."""

    def __init__(self):
        self.lock = threading.Lock()
        self.last = {}
        self.ops = {}
        self.log = []
        self.frozen = False


class _State:
    """A correct claim(key, counter) handle on a backend; subclasses override decide() to break it."""

    def __init__(self, be):
        self.be = be
        be.log.append("open")

    def decide(self, last, counter, key):
        if last is not None and counter <= last:
            return (False, last)
        return (True,)

    def claim(self, key, counter):
        with self.be.lock:
            last = self.be.last.get(key)
            if self.be.frozen:
                return (False, last)
            r = self.decide(last, counter, key)
            if SC._claimed(r):
                self.be.last[key] = counter
            return r

    def close(self):
        self.be.log.append("close")


def _state_run(cls, be=None, per_handle=False, **kw):
    be = be or _Be()
    kw.setdefault("threads", 2)
    kw.setdefault("rounds", 1)
    kw.setdefault("handles", 2)
    return SC.run_state_store_conformance(lambda: cls(_Be() if per_handle else be), **kw), be


def test_state_good_store_with_defaults_every_hook_and_close_count():
    be = _Be()

    def ev(name):
        return lambda: be.log.append(name)
    rep = SC.run_state_store_conformance(lambda: _State(be), crash=ev("crash"), restart=ev("restart"), teardown=ev("teardown"))
    assert rep.name == "state store"
    assert _rows(rep) == [("claim-sequence", "pass", ""), ("claim-burst", "pass", "5 rounds x 16 threads"),
                          ("claim-concurrent", "pass", "5 rounds x 16 threads over 4 handles"),
                          ("claim-durability", "pass", ""), ("crash-after-claim", "pass", ""),
                          ("retry-after-timeout", "pass", "lost answer and in-flight retry")]
    assert rep.ok is True and rep.failures() == []
    assert rep.render() == ("pass claim-sequence\npass claim-burst: 5 rounds x 16 threads\n"
                            "pass claim-concurrent: 5 rounds x 16 threads over 4 handles\npass claim-durability\npass crash-after-claim\n"
                            "pass retry-after-timeout: lost answer and in-flight retry")
    # 13 handles opened; durability closes the 7 opened so far, the finally closes all 13
    assert be.log.count("open") == 13 and be.log.count("close") == 20
    assert [e for e in be.log if e not in ("open", "close")] == ["restart", "crash", "restart", "teardown"]
    assert be.log[-1] == "teardown"


def test_state_process_local_skips_with_exact_notes():
    calls = []
    rep, _ = _state_run(_State, durable=False, shared=False, crash=lambda: calls.append("c"), restart=lambda: calls.append("r"),
                        name="mine")
    assert rep.name == "mine"
    assert _rows(rep) == [("claim-sequence", "pass", ""), ("claim-burst", "pass", "1 rounds x 2 threads"),
                          ("claim-concurrent", "skip", "the adapter declares shared=False (a process-local store)"),
                          ("claim-durability", "skip", "the adapter declares durable=False (state dies with the process)"),
                          ("crash-after-claim", "skip", "the adapter declares durable=False (state dies with the process)"),
                          ("retry-after-timeout", "pass", "lost answer and in-flight retry (one handle: shared=False)")]
    assert calls == [] and rep.ok is True
    assert rep.render().splitlines()[2] == "skip claim-concurrent: the adapter declares shared=False (a process-local store)"


class _AlwaysYes(_State):
    def decide(self, last, counter, key):
        return (True,)


class _AlwaysNo(_State):
    def decide(self, last, counter, key):
        return (False, last)


def test_state_always_admits():
    rep, _ = _state_run(_AlwaysYes, durable=False)
    assert _rows(rep) == [("claim-sequence", "fail", "counter 1 claimed twice"),
                          ("claim-burst", "fail", "round 1: 2 of 2 concurrent claims of counter 1 were admitted (want exactly 1)"),
                          ("claim-concurrent", "fail", "round 1: 2 of 2 claims over 2 handles were admitted (want exactly 1)"),
                          ("claim-durability", "skip", "the adapter declares durable=False (state dies with the process)"),
                          ("crash-after-claim", "skip", "the adapter declares durable=False (state dies with the process)"),
                          ("retry-after-timeout", "fail", "the retry of a claim whose answer was lost was admitted again")]
    assert rep.ok is False
    assert [r.test for r in rep.failures()] == ["claim-sequence", "claim-burst", "claim-concurrent", "retry-after-timeout"]
    assert rep.render().splitlines()[0] == "fail claim-sequence: counter 1 claimed twice"


def test_state_always_refuses():
    rep, _ = _state_run(_AlwaysNo, shared=False)
    assert _rows(rep) == [("claim-sequence", "fail", "first claim of counter 1 refused"),
                          ("claim-burst", "fail", "round 1: 0 of 2 concurrent claims of counter 1 were admitted (want exactly 1)"),
                          ("claim-concurrent", "skip", "the adapter declares shared=False (a process-local store)"),
                          ("claim-durability", "fail", "claim refused"), ("crash-after-claim", "fail", "claim refused"),
                          ("retry-after-timeout", "fail", "claim refused")]


@pytest.mark.parametrize("refusal,shown", [(False, "False"), ((False,), "(False,)"), ((False, 2), "(False, 2)")])
def test_state_refusal_must_report_last_counter(refusal, shown):
    class S(_State):
        def decide(self, last, counter, key):
            return refusal if last is not None and counter <= last else (True,)
    rep, _ = _state_run(S, durable=False, shared=False)
    assert _rows(rep)[0] == ("claim-sequence", "fail", "a refused claim must report last_counter=1, got %s" % shown)


def test_state_sequence_notes_each_rule():
    class Consecutive(_State):  # refuses a gap
        def decide(self, last, counter, key):
            return (True,) if counter == (last or 0) + 1 else (False, last)

    class RepeatsOnly(_State):  # refuses only an exact repeat: an older counter slips in
        def decide(self, last, counter, key):
            seen = self.be.ops.setdefault(key, set())
            if counter in seen:
                return (False, max(seen))
            seen.add(counter)
            return (True,)

    class FiveTwice(_State):  # refuses the repeat of 1, not the repeat of 5
        def decide(self, last, counter, key):
            if last is not None and (counter < last or counter == last == 1):
                return (False, last)
            return (True,)

    class OneCounter(_State):  # ignores the key
        def decide(self, last, counter, key):
            g = self.be.ops.get("g")
            if g is not None and counter <= g:
                return (False, g)
            self.be.ops["g"] = counter
            return (True,)
    notes = {c: _rows(_state_run(c, durable=False, shared=False)[0])[0] for c in (Consecutive, RepeatsOnly, FiveTwice, OneCounter)}
    assert notes == {
        Consecutive: ("claim-sequence", "fail", "a larger counter (a gap) must be admitted"),
        RepeatsOnly: ("claim-sequence", "fail", "an older counter was admitted after 5"),
        FiveTwice: ("claim-sequence", "fail", "counter 5 claimed twice"),
        OneCounter: ("claim-sequence", "fail", "another key must be independent"),
    }


def test_state_forgetful_store_fails_durability_and_crash():
    rep, _ = _state_run(_State, per_handle=True, shared=False)
    assert _rows(rep)[3:] == [
        ("claim-durability", "fail", "counter 7 was admitted again after the handles were closed (the claim was not durable)"),
        ("crash-after-claim", "fail", "the proof admitted before the crash was admitted again"),
        ("retry-after-timeout", "pass", "lost answer and in-flight retry (one handle: shared=False)")]
    rep, _ = _state_run(_State, per_handle=True, shared=True, durable=False)
    assert _rows(rep)[2] == ("claim-concurrent", "fail", "round 1: 2 of 2 claims over 2 handles were admitted (want exactly 1)")


def test_state_next_counter_after_restart_and_after_crash():
    be = _Be()
    rep, _ = _state_run(_State, be=be, shared=False, restart=lambda: setattr(be, "frozen", True))
    assert _rows(rep)[3] == ("claim-durability", "fail", "the next counter must be admitted after a restart")
    be2 = _Be()
    rep, _ = _state_run(_State, be=be2, shared=False, crash=lambda: setattr(be2, "frozen", True))
    assert _rows(rep)[3:] == [("claim-durability", "pass", ""),
                              ("crash-after-claim", "fail", "the next counter must be admitted after the crash"),
                              ("retry-after-timeout", "fail", "claim refused")]


def test_state_retry_after_timeout_rules():
    class ReAdmitsLostAck(_State):  # a retry of the newest counter is taken for an unacknowledged commit and admitted once more
        def decide(self, last, counter, key):
            acked = self.be.ops.setdefault("acked", set())
            if last is not None and counter == last and (key, counter) not in acked:
                acked.add((key, counter))
                return (True,)
            return (False, last) if last is not None and counter <= last else (True,)
    rep, _ = _state_run(ReAdmitsLostAck, durable=False)
    assert ("retry-after-timeout", "fail", "the retry of a claim whose answer was lost was admitted again") in _rows(rep)

    class NoNextAfterRetry(_State):  # refuses everything once a counter has been retried
        def decide(self, last, counter, key):
            if key.startswith("retry:") and last is not None:
                return (False, last)
            return super().decide(last, counter, key)
    rep, _ = _state_run(NoNextAfterRetry, durable=False)
    assert ("retry-after-timeout", "fail", "the next counter must be admitted after the lost answer") in _rows(rep)

    class AdmitsBothInFlight(_State):  # counter 3 of a retry key is never serialised
        def decide(self, last, counter, key):
            return (True,) if key.startswith("retry:") and counter == 3 else super().decide(last, counter, key)
    rep, _ = _state_run(AdmitsBothInFlight, durable=False)
    assert ("retry-after-timeout", "fail", "in-flight retry: 2 of 2 claims were admitted (want exactly 1)") in _rows(rep)


def test_state_raising_store_and_missing_claim():
    class Boom(_State):
        def claim(self, key, counter):
            raise RuntimeError("boom")
    rep, _ = _state_run(Boom, durable=False, shared=False)
    assert _rows(rep)[:2] == [("claim-sequence", "fail", "RuntimeError: boom"),
                              ("claim-burst", "fail", "2 of 2 concurrent calls raised: RuntimeError('boom')")]
    rep = SC.run_state_store_conformance(lambda: object(), threads=2, rounds=1, handles=2)
    assert _rows(rep) == [(t, "fail", "the store has no claim(key, counter)")
                          for t in ("claim-sequence", "claim-burst", "claim-concurrent", "claim-durability", "crash-after-claim", "retry-after-timeout")]
    assert rep.ok is False


def test_state_close_faults_are_swallowed_and_teardown_still_runs():
    class BadClose(_State):
        def close(self):
            raise RuntimeError("close failed")

    class OddClose(_State):
        close = 5  # not callable: ignored
    seen = []
    rep, _ = _state_run(BadClose, durable=False, shared=False, teardown=lambda: seen.append(1))
    assert rep.ok is True and seen == [1]
    rep, _ = _state_run(OddClose)
    assert {r.status for r in rep.results} == {"pass"}


def test_claimed_and_report_and_helpers(monkeypatch):
    assert [SC._claimed(x) for x in (True, (True,), (True, 3), (False, 1), (), 1, [True], "x", None, (1,))] == \
        [True, True, True, False, False, False, False, False, False, False]
    R = SC.TestResult
    assert SC.TestResult.__test__ is False and R("a", "pass").note == ""
    assert SC.ConformanceReport("n").ok is False
    assert SC.ConformanceReport("n", [R("a", "skip")]).ok is False
    assert SC.ConformanceReport("n", [R("a", "pass"), R("b", "skip")]).ok is True
    rep = SC.ConformanceReport("n", [R("a", "pass"), R("b", "fail", "why")])
    assert rep.ok is False and rep.failures() == [R("b", "fail", "why")] and rep.render() == "pass a\nfail b: why"
    SC._check_no_errors([None, 0, "x"])
    with pytest.raises(AssertionError) as e:
        SC._check_no_errors([1, ValueError("x"), KeyError("k")])
    assert str(e.value) == "2 of 3 concurrent calls raised: ValueError('x')"
    assert SC._race(3, lambda i: i * 2) == [0, 2, 4]
    out = SC._race(2, lambda i: 1 // i)
    assert out[1] == 1 and isinstance(out[0], ZeroDivisionError)
    closed = []

    class C:
        def close(self):
            closed.append(1)
    SC._close(C())
    SC._close(object())
    assert closed == [1]
    waits, made = [], []

    class FakeBarrier:
        def __init__(self, n):
            made.append(n)

        def wait(self, timeout=None):
            waits.append(timeout)
    monkeypatch.setattr(SC.threading, "Barrier", FakeBarrier)
    assert SC._race(3, lambda i: i) == [0, 1, 2]
    assert made == [3] and waits == [60, 60, 60]


def test_run_reports_each_outcome():
    rep = SC.ConformanceReport("n")
    SC._run(rep, "a", lambda: None)
    SC._run(rep, "b", lambda: "note")

    def skip():
        raise SC._Skip("why")

    def bad():
        raise AssertionError("nope")  # not an assert statement: pytest would rewrite its message

    def err():
        raise KeyError("k")
    SC._run(rep, "c", skip)
    SC._run(rep, "d", bad)
    SC._run(rep, "e", err)
    assert _rows(rep) == [("a", "pass", ""), ("b", "pass", "note"), ("c", "skip", "why"), ("d", "fail", "nope"),
                          ("e", "fail", "KeyError: 'k'")]


# ---- operation store


class _Op:
    """A correct operation store handle (create-if-absent, copying get, compare-and-set transition)."""

    def __init__(self, be):
        self.be = be
        be.log.append("open")

    def create(self, rec):
        with self.be.lock:
            if rec["id"] in self.be.ops:
                return copy.deepcopy(self.be.ops[rec["id"]])
            self.be.ops[rec["id"]] = copy.deepcopy(rec)
            return None

    def get(self, i):
        with self.be.lock:
            r = self.be.ops.get(i)
            return copy.deepcopy(r) if r is not None else None

    def transition(self, i, frm, nxt):
        with self.be.lock:
            cur = self.be.ops.get(i)
            if cur is None or cur["state"] != frm:
                return False
            self.be.ops[i] = copy.deepcopy(nxt)
            return True

    def close(self):
        self.be.log.append("close")


def _op_run(cls, be=None, per_handle=False, **kw):
    be = be or _Be()
    kw.setdefault("threads", 2)
    kw.setdefault("rounds", 1)
    kw.setdefault("handles", 2)
    return SC.run_operation_store_conformance(lambda: cls(_Be() if per_handle else be), **kw)


def _sem(cls, **kw):
    kw.setdefault("durable", False)
    kw.setdefault("shared", False)
    return _rows(_op_run(cls, **kw))[0]


def test_op_good_store_with_defaults():
    be = _Be()
    rep = SC.run_operation_store_conformance(lambda: _Op(be), restart=lambda: be.log.append("restart"),
                                             teardown=lambda: be.log.append("teardown"))
    assert rep.name == "operation store"
    assert _rows(rep) == [("semantics", "pass", ""), ("copies", "pass", ""), ("create-race", "pass", "5 rounds x 16 threads"),
                          ("transition-race", "pass", "5 rounds x 16 threads"), ("cross-handle", "pass", "over 4 handles"),
                          ("durability", "pass", "")]
    assert [e for e in be.log if e not in ("open", "close")] == ["restart", "teardown"]
    # handles: 1+1+1+1+4+1 opened before the durability close (9), then one more; the finally closes all 10
    assert be.log.count("open") == 10 and be.log.count("close") == 19


def test_op_process_local_skips():
    assert _rows(_op_run(_Op, durable=False, shared=False))[4:] == [
        ("cross-handle", "skip", "the adapter declares shared=False (a process-local store)"),
        ("durability", "skip", "the adapter declares durable=False (state dies with the process)")]


def test_op_missing_methods():
    class NoCreate:
        get = transition = staticmethod(lambda *a: None)

    class NoGet:
        create = transition = staticmethod(lambda *a: None)

    class NoTransition:
        create = get = staticmethod(lambda *a: None)
    for cls, m in ((NoCreate, "create"), (NoGet, "get"), (NoTransition, "transition")):
        rep = SC.run_operation_store_conformance(lambda: cls(), threads=2, rounds=1, handles=2, durable=False, shared=False)
        assert {(r.status, r.note) for r in rep.results if r.status != "skip"} == {("fail", "the store has no %s()" % m)}


def test_op_semantics_each_assertion():
    class GetUnknownEmpty(_Op):
        def get(self, i):
            r = super().get(i)
            return {} if r is None else r

    class CreateEchoes(_Op):
        def create(self, rec):
            super().create(rec)
            return copy.deepcopy(rec)

    class MergeUpsert(_Op):  # PATCH-like: an existing id gets the non-null fields of the new record
        def create(self, rec):
            with self.be.lock:
                cur = self.be.ops.get(rec["id"])
                if cur is None:
                    self.be.ops[rec["id"]] = copy.deepcopy(rec)
                    return None
                cur.update({k: v for k, v in rec.items() if v is not None})
                return copy.deepcopy(cur)

    class UnknownTrue(_Op):
        def transition(self, i, frm, nxt):
            return True if self.be.ops.get(i) is None else super().transition(i, frm, nxt)

    class IgnoresFrom(_Op):  # CAS on "the state changes" instead of on `frm`; refuses an unknown target state
        def transition(self, i, frm, nxt):
            with self.be.lock:
                cur = self.be.ops.get(i)
                if cur is None or nxt["state"] == cur["state"] or nxt["state"] not in ("pending", "executing", "aborted"):
                    return False
                self.be.ops[i] = copy.deepcopy(nxt)
                return True

    class WritesOnRefusal(_Op):
        def transition(self, i, frm, nxt):
            with self.be.lock:
                cur = self.be.ops.get(i)
                if cur is None:
                    return False
                self.be.ops[i] = copy.deepcopy(nxt)
                return cur["state"] == frm

    class NeverMoves(_Op):
        def transition(self, i, frm, nxt):
            return False

    class TrueWithoutWrite(_Op):
        def transition(self, i, frm, nxt):
            cur = self.be.ops.get(i)
            return cur is not None and cur["state"] == frm

    class DropsExtra(_Op):
        def transition(self, i, frm, nxt):
            return super().transition(i, frm, {k: v for k, v in nxt.items() if k != "executingAt"})

    class CasOnFirstState(_Op):  # compares `frm` with the state the record was CREATED with
        def transition(self, i, frm, nxt):
            with self.be.lock:
                cur = self.be.ops.get(i)
                if cur is None or cur.setdefault("_first", cur["state"]) != frm:
                    return False
                self.be.ops[i] = dict(copy.deepcopy(nxt), _first=cur["_first"])
                return True
    S = "semantics"
    assert _sem(GetUnknownEmpty) == (S, "fail", "get of an unknown id must be None")
    assert _sem(CreateEchoes) == (S, "fail", "create of a new id must return None")
    assert _sem(MergeUpsert) == (S, "fail", "create of an existing id must return the existing record unchanged")
    assert _sem(UnknownTrue) == (S, "fail", "transition of an unknown id must be False")
    assert _sem(IgnoresFrom) == (S, "fail", "transition from the wrong state must be False")
    assert _sem(WritesOnRefusal) == (S, "fail", "a refused transition changed the record")
    assert _sem(NeverMoves) == (S, "fail", "")
    assert _sem(TrueWithoutWrite) == (S, "fail", "")
    assert _sem(DropsExtra) == (S, "fail", "")
    assert _sem(CasOnFirstState) == (S, "fail", "the old state must no longer match")
    assert _sem(_Op) == (S, "pass", "")


def test_op_copies():
    class AliasGet(_Op):
        def get(self, i):
            return self.be.ops.get(i)

    class StoresGiven(_Op):
        def create(self, rec):
            if rec["id"] in self.be.ops:
                return copy.deepcopy(self.be.ops[rec["id"]])
            self.be.ops[rec["id"]] = rec
            return None
    assert _rows(_op_run(AliasGet, durable=False, shared=False))[1] == ("copies", "fail", "get must return a copy, not the stored record")
    assert _rows(_op_run(StoresGiven, durable=False, shared=False))[1] == \
        ("copies", "fail", "create must store a copy of the record it was given")


def test_op_races_cross_handle_and_durability():
    class CreateNone(_Op):
        def create(self, rec):
            super().create(rec)
            return None

    class TransitionTrue(_Op):
        def transition(self, i, frm, nxt):
            super().transition(i, frm, nxt)
            return True

    class CreateBoom(_Op):
        def create(self, rec):
            raise RuntimeError("boom")
    r = _rows(_op_run(CreateNone, durable=False, shared=False))
    assert r[2] == ("create-race", "fail", "round 0: 2 of 2 concurrent creates reported 'created' (want exactly 1)")
    r = _rows(_op_run(TransitionTrue, durable=False, shared=True))
    assert r[3] == ("transition-race", "fail", "round 0: 2 of 2 concurrent pending->executing transitions succeeded (want exactly 1)")
    assert r[4] == ("cross-handle", "fail", "transitions over 2 handles: not exactly one success")
    r = _rows(_op_run(_Op, per_handle=True, durable=True, shared=True))
    assert r[4:] == [("cross-handle", "fail", "creates over 2 handles: not exactly one 'created'"),
                     ("durability", "fail", "the record did not survive closing every handle")]
    r = _rows(_op_run(CreateBoom, durable=False, shared=False))
    assert r[0] == ("semantics", "fail", "RuntimeError: boom")
    assert r[2] == ("create-race", "fail", "2 of 2 concurrent calls raised: RuntimeError('boom')")


def test_op_record_shape():
    assert SC._record("x") == {"id": "x", "state": "pending", "verb": "v", "resource": "/r", "params_digest": "d",
                               "reversibility": "reversible", "startedAt": 1}
    assert SC._record("x", "executing")["state"] == "executing"


# ===================================================================================================================== lease

KP = KeyPair(bytes(range(32)))


def _lease(**over):
    base = dict(v=1, lease_id="L9", path="db/x", grant_ref="g9", holder="agent", requester="alice", approvers=["bob"],
                justification_digest="j1", seq=1, issued_at=1000, renewed_at=1000, expires_at=2000, max_ttl=10000, authority=KP.public)
    base.update(over)
    base["sig"] = _sign_body(KP, L.LEASE_DOMAIN, {k: base[k] for k in L._BODY_KEYS})
    return base


def test_sod_error_every_reason():
    l = {"approvers": ["bob"], "requester": "alice", "holder": "agent"}
    assert L.sod_error(l, {"eligibleApprovers": ["carol"]}) == "an approver is not eligible"
    assert L.sod_error(l, {"eligibleApprovers": ["bob"]}) is None
    assert L.sod_error(l, {"eligibleApprovers": []}) == "an approver is not eligible"
    assert L.sod_error(l) is None and L.sod_error(l, None) is None
    assert L.sod_error({"approvers": ["agent"], "requester": "alice", "holder": "agent"}) == "the holder may not approve its own lease"
    assert L.sod_error(l, {}, ["x", "bob"]) == "an approver appears in the holder's delegation chain"
    assert L.sod_error({"approvers": [], "requester": "a", "holder": "b"}) == "0 approver(s), need 1"
    assert L.sod_error(l, {"minApprovals": 2}) == "1 approver(s), need 2"
    assert L.sod_error({"approvers": ["b", "c"], "requester": "a", "holder": "h"}, {"minApprovals": 2}) is None
    assert L.sod_error(l, {"minApprovals": True}) == "minApprovals must be a positive integer"


def test_lease_registry_seq_rules():
    reg = L.LeaseRegistry({"authorities": [KP.public]}, MemoryAtomicKv())
    assert reg.accept(_lease(seq=2, renewed_at=1500, expires_at=2500)) == \
        {"ok": False, "code": "bad_seq", "reason": "a new lease starts at seq 1"}
    assert reg.accept(_lease()) == {"ok": True, "replaced": True, "seq": 1}
    assert reg.accept(_lease(seq=3, renewed_at=1500, expires_at=3000, justification_digest="j3")) == \
        {"ok": False, "code": "bad_seq", "reason": "renewals advance seq by exactly 1"}
    assert reg.accept(_lease(seq=2, renewed_at=1500, expires_at=3000, justification_digest="j2")) == {"ok": True, "replaced": True, "seq": 2}


def test_lease_revoke_store_fault_is_a_refusal():
    rev = next(LDOC["revocations"][st["revocation"]] for s in LDOC["scenarios"] for st in s["steps"]
               if st["op"] == "revoke" and st["expect"].get("ok"))

    class Broken:
        def get(self, key):
            raise RuntimeError("store down")

        def update(self, key, fn):
            raise RuntimeError("store down")
    reg = L.LeaseRegistry({"authorities": [rev["authority"]]}, Broken())
    assert reg.revoke(copy.deepcopy(rev)) == {"ok": False, "code": "store_unreachable"}


# =============================================================================================================== break_glass


def test_break_glass_uses_are_numbered_copies():
    g = BGDOC["grants"][0]
    reg = BG.BreakGlassRegistry({"authorities": [BGDOC["authority"]], "reviewers": [BGDOC["reviewer"]]}, MemoryAtomicKv())
    t = g["issued_at"]
    assert reg.accept(g, t) == {"ok": True, "replaced": True}
    assert reg.use(g["id"], g["holder"], "act-1", t, True)["decision"] == "allow"
    assert reg.use(g["id"], g["holder"], "act-2", t + 5, True)["decision"] == "allow"
    got = reg.uses(g["holder"], g["id"])
    assert got == [{"n": 1, "action_digest": "act-1", "at": t}, {"n": 2, "action_digest": "act-2", "at": t + 5}]
    got[0]["n"] = 99
    assert reg.uses(g["holder"], g["id"])[0]["n"] == 1
    assert reg.uses(5, g["id"]) == [] and reg.uses(g["holder"], "nope") == []


# ================================================================================================================ read_vault

_RULE = {"verb": "v", "resource_prefix": "p/", "purposes": ["a"], "fns": ["count", "sum"], "min_group": 1, "clamp": 0,
         "epsilon_micro": 0, "dp": False}


def test_valid_rule_every_bound():
    ok = RV._valid_rule
    assert ok(_RULE)
    for over, want in (({"resource_prefix": "a" * 512}, True), ({"resource_prefix": "a" * 513}, False), ({"resource_prefix": ""}, False),
                       ({"verb": "v" * 128}, True), ({"verb": "v" * 129}, False),
                       ({"purposes": ["p%02d" % i for i in range(16)]}, True), ({"purposes": ["p%02d" % i for i in range(17)]}, False),
                       ({"purposes": []}, False), ({"purposes": ["b", "a"]}, False),
                       ({"fns": ["count"]}, True), ({"fns": ["sum"]}, True), ({"fns": []}, False), ({"fns": ["sum", "count"]}, False),
                       ({"fns": ["avg"]}, False), ({"min_group": 0}, False), ({"min_group": 2}, True),
                       ({"clamp": 1_000_000}, True), ({"clamp": 1_000_001}, False), ({"clamp": -1}, False),
                       ({"epsilon_micro": 1_073_741_824}, True), ({"epsilon_micro": 1_073_741_825}, False),
                       ({"dp": True}, False), ({"dp": True, "epsilon_micro": 1}, True), ({"dp": 1}, False)):
        assert ok(dict(_RULE, **over)) is want, over
    assert ok(dict(_RULE, extra=1)) is False
    assert ok({k: v for k, v in _RULE.items() if k != "dp"}) is False
    body = {"v": 1, "id": "ag", "principal": VA["keys"]["principal"], "issued_at": 0, "expires_at": 1, "rules": [_RULE],
            "epsilon_budget_micro": 0, "max_queries": 0}
    assert RV.valid_aggregate_grant_body(body) is True
    assert RV.valid_aggregate_grant_body(dict(body, rules=[_RULE] * 16)) is True
    for over in ({"rules": [_RULE] * 17}, {"rules": []}, {"v": True}, {"v": 2}, {"rules": [dict(_RULE, resource_prefix="a" * 513)]}):
        assert RV.valid_aggregate_grant_body(dict(body, **over)) is False, over


def _vault_input():
    c = next(c for c in VA["vault"] if c["name"] == "allowed-class-to-allowed-sink")
    return dict(c["redact"], grant=VA["grants"]["vault"][c["redact_grant"]])


def test_vault_store_failure_hands_out_no_token():
    inp = _vault_input()
    assert RS.redact_read(inp)["decision"] == "allow"  # a token was minted for the field

    class Down:
        def put(self, token, entry):
            raise RuntimeError("vault down")
    r = RV.redact_read_with_vault(inp, Down())
    assert r["decision"] == "deny" and r["view"] == {} and r["fields"] == {} and r["labels"] == []
    good = RV.memory_vault()
    r2 = RV.redact_read_with_vault(inp, good)
    assert r2["decision"] == "allow"
    tok = r2["view"]["cust"]
    assert good.get(tok) == {"cls": "ref", "value": "c_77", "grant": RS.read_grant_digest(inp["grant"]["body"]),
                             "exp": inp["grant"]["body"]["expires_at"]}


# ================================================================================================================== readside


def test_redact_read_schema_needs_both_a_name_and_a_label():
    inp = _vault_input()
    bad = {"decision": "deny", "code": "bad_request", "view": {}, "fields": {}, "labels": [], "counts": {}}
    for fields in ({"cust": "REF", "tax": "ssn"}, {"cust": "ref", "tax": "ssn", "bad key": "ref"}, {"cust": "ref", "tax": 5}):
        assert RS.redact_read(dict(inp, schema={"fields": fields, "required": []})) == bad, fields
    assert RS.redact_read(dict(inp, schema={"fields": {"cust": "ref", "tax": "ssn"}, "required": ["nope"]})) == bad
    assert RS.redact_read(dict(inp, schema={"fields": {"cust": "ref", "tax": "ssn"}}))["code"] == "bad_request"
    assert RS.redact_read(inp)["decision"] == "allow"


_B32 = "A" * 43


def _receipt(**fover):
    f = {"class": "ssn", "action": "shown", "kind": None, "vd": _B32}
    f.update(fover)
    return {"v": 1, "grant": _B32, "verb": "v", "resource": "r", "purpose": "p", "seq": 0, "prev": None,
            "fields": {"x": f}, "labels": ["ssn"], "issued_at": 1, "signer": _B32, "sig": "s"}


def test_valid_read_receipt_field_rules():
    v = RS._valid_read_receipt
    assert v(_receipt()) is True
    for over, want in (({"class": "unclassified"}, True), ({"class": "UPPER"}, False), ({"class": 5}, False),
                       ({"action": "masked", "kind": "token"}, True), ({"action": "dropped"}, True), ({"action": "weird"}, False),
                       ({"kind": 5}, False), ({"vd": "x"}, False),
                       ({"class": "UPPER", "action": "weird"}, False)):
        assert v(_receipt(**over)) is want, over
    r = _receipt()
    r["fields"]["x"]["extra"] = 1
    assert v(r) is False
    r = _receipt()
    r["fields"] = {"bad key": r["fields"]["x"]}
    assert v(r) is False
    r = _receipt()
    r["fields"] = {"f%02d" % i: dict(r["fields"]["x"]) for i in range(64)}
    assert v(r) is True
    r["fields"]["f64"] = dict(r["fields"]["f00"])
    assert v(r) is False
    assert v(dict(_receipt(), seq=0, prev=_B32)) is False
    assert v(dict(_receipt(), seq=1, prev=None)) is False
    assert v(dict(_receipt(), seq=1, prev=_B32)) is True
    assert v(dict(_receipt(), v=True)) is False


# ====================================================================================================== revocation_staleness

GUARD = SDOC["guardian_public"]
ROOT = SDOC["revocation_root"]
NOW = 1_800_000_000_000


def _gate(name):
    return next(g for g in SDOC["gate"] if g["name"] == name)


def test_check_revocation_state_no_epoch_and_no_root():
    no_epoch = {"ok": False, "reason": "no signed revocation epoch"}
    for state in (None, [], {}, {"kind": "x"}, {"kind": "epoch"}, {"kind": "epoch", "epoch": "e"}):
        assert ST.check_revocation_state(None, state, now=NOW, guardian_public=GUARD) == no_epoch, state
    ep = _gate("epoch-reversible-fresh")["epoch"]
    assert ST.check_revocation_state(None, {"kind": "epoch", "epoch": ep}, now=NOW) == no_epoch  # no guardian anywhere
    assert ST.check_revocation_state(None, {"kind": "epoch", "epoch": ep}, now=NOW, guardian_public="") == no_epoch
    no_root = {"ok": False, "reason": "no revocation root"}
    for root in (None, ""):
        assert ST.check_revocation_state(None, {"kind": "root", "root": root}, now=NOW) == no_root
    assert ST.check_revocation_state(None, {"kind": "root", "root": ROOT}, now=NOW) == {"ok": True}


def test_check_revocation_state_signed_epoch():
    ep = _gate("epoch-reversible-fresh")["epoch"]
    pol = ST.RevocationStaleness(max_revocation_age_ms=300000, guardian_public=GUARD)
    st = {"kind": "epoch", "epoch": ep}
    assert ST.check_revocation_state(pol, st, now=NOW, grant_ref="g1", signed_class="reversible", pcactn_epoch=0) == {"ok": True, "epoch": ep}
    assert ST.check_revocation_state(None, st, now=NOW, grant_ref="g1", pcactn_epoch=0, guardian_public=GUARD) == {"ok": True, "epoch": ep}
    assert ST.check_revocation_state(pol, dict(st, root=ROOT), now=NOW, grant_ref="g1", signed_class="reversible", pcactn_epoch=0) == \
        {"ok": True, "epoch": ep}
    assert ST.check_revocation_state(pol, dict(st, root="x"), now=NOW, grant_ref="g1", signed_class="reversible", pcactn_epoch=0) == \
        {"ok": False, "reason": "revocation root does not match the signed epoch"}
    other = _gate("epoch-reversible-fresh")["epoch"]["guardian"][::-1]
    assert ST.check_revocation_state(pol, st, now=NOW, grant_ref="g1", signed_class="reversible", pcactn_epoch=0,
                                     guardian_public=other)["ok"] is False
    assert ST.check_revocation_state(pol, st, now=NOW, grant_ref="g1", signed_class="reversible", pcactn_epoch=0,
                                     ids=["c1"])["reason"] == "no non-membership proof for c1"


def test_check_revocation_state_unsigned_root_under_policy():
    pol = ST.RevocationStaleness()
    root = {"kind": "root", "root": ROOT, "issued_at": NOW}
    assert ST.check_revocation_state(pol, root, now=NOW) == {
        "ok": False, "reason": "unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)"}
    assert ST.check_revocation_state(pol, root, now=NOW, signed_class="costly") == {"ok": True}
    assert ST.check_revocation_state(pol, dict(root, issued_at=NOW - 300000), now=NOW, signed_class="reversible") == {"ok": True}
    assert ST.check_revocation_state(pol, dict(root, issued_at=NOW - 300001), now=NOW, signed_class="reversible") == {
        "ok": False, "reason": "revocation root is 300001 ms old, over the verifier's maximum of 300000 ms (stale revocation state)"}
    assert ST.check_revocation_state(pol, dict(root, issued_at=None), now=NOW, signed_class="reversible") == {
        "ok": False, "reason": "revocation root age is unknown (unverifiable revocation state)"}
    pol2 = ST.RevocationStaleness(allow_unsigned_root_for_irreversible=True)
    assert ST.check_revocation_state(pol2, root, now=NOW) == {"ok": True}
    assert ST.check_revocation_state(pol2, dict(root, issued_at=NOW - 120001), now=NOW)["ok"] is False
    assert ST.check_revocation_state(pol, root, now=NOW, signed_class="reversible", server_class="irreversible")["ok"] is False


def test_check_revocation_state_proofs():
    st = {"kind": "root", "root": ROOT}
    assert ST.check_revocation_state(None, st, now=NOW, ids=["c1"]) == {"ok": False, "reason": "no non-membership proof for c1"}
    assert ST.check_revocation_state(None, st, now=NOW, ids=["c1"], proof_for=lambda rid: None) == \
        {"ok": False, "reason": "no non-membership proof for c1"}
    assert ST.check_revocation_state(None, st, now=NOW, ids=["c1"], proof_for=lambda rid: {"x": 1}) == \
        {"ok": False, "reason": "capability c1 is revoked or proof invalid"}
    assert ST.check_revocation_state(None, st, now=NOW, ids=[], proof_for=lambda rid: None) == {"ok": True}
    for falsy in (0, "", False, 0.0, float("nan")):  # revocation.ts:526 `!proof`
        assert ST.check_revocation_state(None, st, now=NOW, ids=["c1"], proof_for=lambda rid: falsy) == {"ok": False, "reason": "no non-membership proof for c1"}
    for truthy in ({}, [], 1, "x"):
        assert ST.check_revocation_state(None, st, now=NOW, ids=["c1"], proof_for=lambda rid: truthy) == {"ok": False, "reason": "capability c1 is revoked or proof invalid"}

    def boom(rid):
        raise RuntimeError("x")
    assert ST.check_revocation_state(None, st, now=NOW, ids=["c1"], proof_for=boom) == \
        {"ok": False, "reason": "revocation state check error (fail closed)"}


def test_staleness_policy_helpers():
    p = ST.RevocationStaleness()
    assert [ST.revocation_max_age_ms(p, c) for c in ("irreversible", "rate_limited", "costly", "reversible", "other")] == \
        [120000, 300000, 300000, 300000, 300000]
    p = ST.RevocationStaleness(max_revocation_age_ms=100000)
    assert [ST.revocation_max_age_ms(p, c) for c in ("irreversible", "rate_limited", "reversible")] == [100000, 100000, 100000]
    p = ST.RevocationStaleness(staleness={"irreversible": 500000, "rate_limited": 1000, "costly": 2000})
    assert [ST.revocation_max_age_ms(p, c) for c in ("irreversible", "rate_limited", "costly")] == [300000, 1000, 1000]
    p = ST.RevocationStaleness(staleness={"costly": 2000})
    assert [ST.revocation_max_age_ms(p, c) for c in ("rate_limited", "costly", "irreversible")] == [2000, 2000, 120000]
    assert [ST.class_rank(c) for c in ("reversible", "rate_limited", "costly", "irreversible", "x", None, 1)] == [0, 1, 1, 2, 2, 2, 2]
    er = ST.effective_reversibility
    assert [er(None, "reversible"), er("reversible", None), er("costly", "reversible"), er("reversible", "rate_limited"),
            er(None, None), er("reversible", "reversible")] == ["reversible", "irreversible", "rate_limited", "rate_limited",
                                                                "irreversible", "reversible"]
    assert [ST._positive_ms(x) for x in (1, 0.5, 0, -1, float("inf"), float("nan"), True, "1", None)] == \
        [True, True, False, False, False, False, False, False, False]
    with pytest.raises(ValueError) as e:
        ST.RevocationStaleness(staleness=[1])
    assert str(e.value) == "staleness must be a mapping"
    with pytest.raises(ValueError) as e:
        ST.RevocationStaleness(staleness={"rate_limited": 0})
    assert str(e.value) == "staleness.rate_limited must be a positive number of milliseconds"
    with pytest.raises(ValueError) as e:
        ST.RevocationStaleness(max_revocation_age_ms=0)
    assert str(e.value) == "max_revocation_age_ms must be a positive number of milliseconds"
    ST.RevocationStaleness(staleness={"other": 0})  # unknown keys are not validated


# ============================================================================================================ plan_lifecycle

NODES = [{"id": "a", "verb": "v", "resource": "r"}]


def _plans(validator=None):
    clock = {"t": 10}
    reg = PlanRegistry(now=lambda: clock["t"], validator=validator)
    return reg, clock


def _drafted(nodes=NODES, validator=None):
    reg, clock = _plans(validator)
    root = plan_root(nodes)
    assert reg.draft("g", nodes)["ok"] is True
    return reg, clock, root


def _tamper(reg, root, fn):
    k = reg._key("g", root)
    rec = reg._kv.get(k)
    fn(rec)
    reg._kv.set(k, rec)


def test_validate_refuses_nodes_that_no_longer_hash_to_the_root():
    reg, _, root = _drafted()
    _tamper(reg, root, lambda r: r["nodes"][0].update(verb="w"))
    assert reg.validate("g", root) == {"ok": False, "state": "draft",
                                       "reason": "plan %s is invalid: the stored nodes no longer hash to the root" % root}
    reg, _, root = _drafted()
    _tamper(reg, root, lambda r: r["nodes"][0].update(pre=object()))
    assert reg.validate("g", root) == {"ok": False, "state": "draft",
                                       "reason": "plan %s is invalid: the stored nodes no longer hash to the root" % root}


@pytest.mark.parametrize("nodes,problem", [
    ([{"id": "a", "verb": "", "resource": "r"}], "node 'a' needs a verb and a resource"),
    ([{"id": "a", "verb": "v", "resource": ""}], "node 'a' needs a verb and a resource"),
    ([{"id": "", "verb": "v", "resource": "r"}], "every node needs an id"),
    ([{"id": "a", "verb": "v", "resource": "r"}, {"id": "a", "verb": "w", "resource": "r"}], "duplicate node id 'a'"),
    ([{"id": "a", "verb": "v", "resource": "r", "reversibility_class": "weird"}], "node 'a' has an unknown reversibility class 'weird'"),
])
def test_validate_structural_problems(nodes, problem):
    reg, _, root = _drafted(nodes)
    assert reg.validate("g", root) == {"ok": False, "state": "draft", "reason": "plan %s is invalid: %s" % (root, problem)}


def test_validator_outcomes():
    for v, why in ((lambda r: {"ok": False, "reason": "nope"}, "nope"), (lambda r: None, "refused by the validator"),
                   (lambda r: {"ok": "yes"}, "refused by the validator"), (lambda r: {"ok": False, "reason": ""}, ""),
                   (lambda r: {"ok": False}, "undefined"), (lambda r: {"ok": False, "reason": None}, "null"), (lambda r: {"ok": False, "reason": 5}, "5")):  # plan-lifecycle.ts:218
        reg, _, root = _drafted(validator=v)
        assert reg.validate("g", root) == {"ok": False, "state": "draft", "reason": "plan %s is invalid: %s" % (root, why)}

    def boom(r):
        raise ValueError("down")
    reg, _, root = _drafted(validator=boom)
    assert reg.validate("g", root)["reason"] == "plan %s is invalid: validator error (fail closed): down" % root
    seen = []
    reg, clock, root = _drafted(validator=lambda r: seen.append(r) or {"ok": True})
    clock["t"] = 20
    rec = {"grantRef": "g", "root": root, "nodes": NODES, "state": "draft", "createdAt": 10}
    assert reg.validate("g", root) == {"ok": True, "record": dict(rec, state="validated", validatedAt=20)}
    assert seen == [rec]


def test_lifecycle_exact_results():
    reg, clock = _plans()
    root = plan_root(NODES)
    rec = {"grantRef": "g", "root": root, "nodes": NODES, "state": "draft", "createdAt": 10}
    assert reg.draft("", NODES) == {"ok": False, "state": "unknown", "reason": "a plan needs a grant"}
    assert reg.draft(None, NODES)["reason"] == "a plan needs a grant"
    assert reg.draft("g", []) == {"ok": False, "state": "unknown", "reason": "the plan cannot be committed: merkleRoot: empty leaf set"}
    assert reg.draft("g", NODES) == {"ok": True, "record": rec}
    assert reg.draft("g", NODES) == {"ok": False, "state": "draft", "reason": "plan %s already exists (draft)" % root}
    unknown = "plan zz is unknown for this grant"
    assert reg.validate("g", "zz") == {"ok": False, "state": "unknown", "reason": unknown}
    assert reg.commit("g", "zz") == {"ok": False, "state": "unknown", "reason": unknown}
    assert reg.commit("g", root) == {"ok": False, "state": "draft", "reason": "plan %s is draft: cannot commit" % root}
    assert reg.status("g", root) == {"state": "draft", "executable": False, "reason": "plan %s is draft, not authorized" % root, "record": rec}
    clock["t"] = 11
    assert reg.validate("g", root)["ok"] is True
    assert reg.validate("g", root) == {"ok": False, "state": "validated", "reason": "plan %s is validated: cannot validate" % root}
    clock["t"] = 12
    rec = dict(rec, state="committed", validatedAt=11, committedAt=12)
    assert reg.commit("g", root) == {"ok": True, "record": rec}
    assert reg.status("g", root) == {"state": "committed", "executable": False,
                                     "reason": "plan %s is committed but not authorized by the principal" % root, "record": rec}
    who = "an approval names who approved (`by`)"
    for a in (None, {}, {"by": ""}, {"by": 5}):
        assert reg.authorize("g", root, a) == {"ok": False, "state": "committed", "reason": who}
    assert reg.authorize("g", "zz", None) == {"ok": False, "state": "unknown", "reason": who}
    for x in ("1", float("inf"), float("nan"), True, None):
        assert reg.authorize("g", root, {"by": "p", "expiresAt": x}) == \
            {"ok": False, "state": "committed", "reason": "approval.expiresAt must be a time (epoch ms)"}
    clock["t"] = 13
    rec = dict(rec, state="authorized", authorizedAt=13, approval={"by": "p", "expiresAt": 100})
    assert reg.authorize("g", root, {"by": "p", "expiresAt": 100}) == {"ok": True, "record": rec}
    assert reg.status("g", root, 99) == {"state": "authorized", "executable": True, "record": rec}
    assert reg.status("g", root, 100) == {"state": "authorized", "executable": False, "record": rec,
                                          "reason": "plan %s: the principal's approval expired at 100" % root}
    assert reg.is_plan_authorized("g", root) is True
    assert reg.context("g", root, 99) == {"plan": NODES, "planAuthorized": True, "status": reg.status("g", root, 99)}
    assert reg.context("g", "zz") is None
    clock["t"] = 14
    assert reg.revoke("g", root, None) == {"ok": True, "record": dict(rec, state="revoked", revokedAt=14, revokedReason="")}
    assert reg.status("g", root)["reason"] == "plan %s is revoked ()" % root
    assert reg.revoke("g", root, "x") == {"ok": False, "state": "revoked", "reason": "plan %s is revoked: cannot revoke" % root}
    assert reg.is_plan_authorized("g", root) is False


def test_status_reasons_and_check_rules():
    reg, clock, root = _drafted()
    reg.validate("g", root)
    reg.commit("g", root)
    reg.authorize("g", root, {"by": "p", "expiresAt": 1e21})
    s = reg.status("g", root, 1e21)
    assert s["reason"] == "plan %s: the principal's approval expired at 1e+21" % root
    assert reg.check("g", root, now=50)["executable"] is True
    assert reg.check("g", root, node_id="a", now=50)["executable"] is True
    c = reg.check("g", root, node_id="zz", now=50)
    assert (c["executable"], c["reason"]) == (False, "plan %s has no node 'zz'" % root)
    c = reg.check("g", root, operation={"verb": "v", "resource": "r", "params": {"p": float("nan")}}, now=50)
    assert (c["executable"], c["reason"]) == (False, "plan %s: the operation's params cannot be hashed" % root)
    for op in ({"verb": "w", "resource": "r"}, {"verb": "v", "resource": "q"}, {"verb": "v", "resource": "r", "params": {"a": 1}}):
        c = reg.check("g", root, node_id="a", operation=op, now=50)
        assert (c["executable"], c["reason"]) == (False, "plan %s: the operation (%s on %s with these params) is not what the principal approved"
                                                  % (root, op["verb"], op["resource"])), op
    assert reg.check("g", root, operation={"verb": "v", "resource": "r"}, now=50)["executable"] is True
    assert reg.check("g", root, node_id="a", operation={"verb": "v", "resource": "r", "params": {}}, now=50)["executable"] is True
    assert "reason" not in reg.check("g", root, operation={"verb": "v", "resource": "r"}, now=50)
    # the stored nodes drift after authorization: never executable, whatever the per-action rules
    _tamper(reg, root, lambda r: r["nodes"][0].update(verb="w"))
    c = reg.check("g", root, node_id="a", operation={"verb": "w", "resource": "r"}, now=50)
    assert (c["executable"], c["reason"]) == (False, "plan %s: the stored nodes no longer hash to the root" % root)
    _tamper(reg, root, lambda r: r.update(state="revoked"))
    assert reg.status("g", root)["reason"] == "plan %s is revoked (no reason given)" % root
    assert reg.status("g", "zz") == {"state": "unknown", "executable": False, "reason": "plan zz is unknown for this grant"}
