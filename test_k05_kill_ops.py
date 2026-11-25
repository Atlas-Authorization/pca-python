"""k05 mutation-kill tests, group "ops": optimistic (bonded claims, fraud proofs, settlement records), undo (windows, tokens,
receipts), operations (operation records, executor) and stepup (the principal's device client). Expectations follow the
TypeScript references (pca/src/optimistic.ts, bond-settlement.ts, undo.ts, operations.ts). Deterministic, no network."""
import calendar
import io
import json
import os
import sys
import time
import urllib.error
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from atlas_pca import ed25519
from atlas_pca import operations as EO
from atlas_pca import optimistic as OP
from atlas_pca import stepup as SU
from atlas_pca import undo as U
from atlas_pca.agent import KeyPair
from atlas_pca.authorize import AuthorizedOperation, AuthorizeResult
from atlas_pca.pca import EMPTY_PARAMS_DIGEST, b64u, canonical_bytes, hash_canonical, params_digest

K = KeyPair(bytes(range(32)))
OTHER = KeyPair(bytes(range(1, 33)))


class _Duck:
    """A mapping that is not a dict: has get / [] but is rejected by an isinstance(dict) check."""

    def __init__(self, d):
        self._d = d

    def get(self, k, default=None):
        return self._d.get(k, default)

    def __getitem__(self, k):
        return self._d[k]

    def __contains__(self, k):
        return k in self._d

    def __len__(self):
        return len(self._d)


class _Boom(dict):
    """A dict whose .get raises (drives the total functions' catch-all)."""

    def get(self, *a, **k):
        raise RuntimeError("boom")


# ================================================================================================================ optimistic

def _claim(**over):
    body = {"pcactn_digest": "D", "bond_ref": "B", "claimed_r": 0.5, "reversibility_class": "reversible", "issued_at": 1000,
            "challenge_window_ms": 60000}
    body.update(over)
    body = {k: v for k, v in body.items() if v is not None}
    return {**body, "sig": b64u(K.sign(OP._CLAIM_DOMAIN.encode() + canonical_bytes(body)))}


def test_same_strict_equality():
    assert OP._same(True, True) is True
    assert OP._same(True, False) is False
    assert OP._same(True, 1) is False
    assert OP._same(1, True) is False
    assert OP._same(1, 1.0) is True
    assert OP._same(1, 2) is False
    assert OP._same("a", "a") is True
    assert OP._same("a", 1) is False

    class Eq:
        def __eq__(self, o):
            return True
    assert OP._same(1, Eq()) is False
    assert OP._same(Eq(), 1) is False


def test_validate_window_messages():
    P = OP.DEFAULT_WINDOW_POLICY
    assert OP._validate_window(1000, 60000, 1000, P) is None
    assert OP._validate_window(1000 + 6000, 60000, 1000, P) == "issued_at is outside the allowed skew of server time"
    assert OP._validate_window(1000, 999, 1000, P) == "challenge window is below the minimum"
    assert OP._validate_window(1000, 86_400_001, 1000, P) == "challenge window exceeds the maximum"
    assert OP._validate_window(1000, 86_400_000, 1000, P) is None


def test_claim_check_window_policy_and_defaults():
    c = _claim()
    assert OP.claim_check(c, "D", K.public, 1000) == "ok"
    assert OP.claim_check(c, "D", K.public, 1000, None) == "ok"
    # a custom policy replaces the default: a window beyond the default maximum is fine under it
    big = _claim(challenge_window_ms=10 ** 8)
    assert OP.claim_check(big, "D", K.public, 1000) == "window"
    pol = {"minWindowMs": 1, "maxWindowMs": 10 ** 9, "defaultWindowMs": 1, "maxSkewMs": 10 ** 6}
    assert OP.claim_check(big, "D", K.public, 1000, pol) == "ok"


def test_claim_check_digest_missing_vs_null():
    c = _claim()
    del c["pcactn_digest"]
    assert OP.claim_check(c, None, K.public, 1000) == "digest"
    assert OP.claim_check(c, "D", K.public, 1000) == "digest"


def test_claim_check_catch_all():
    assert OP.claim_check(_Boom(_claim()), "D", K.public, 1000) == "malformed"


def _fraud(kind="policy-denied", decision=None, **over):
    claim = {"pcactn_digest": "D", "bond_ref": "B", "claimed_r": 0.5, "reversibility_class": "reversible"}
    proof = {"pcactn_digest": "D", "bond_ref": "B", "claimed_r": 0.5, "kind": kind, "reason": "x",
             "decision": decision or {"releaseGuardianShare": False, "optimisticAllowed": True, "r": 0.9}}
    proof.update(over)
    return claim, proof


def test_fraud_proof_understated_boundary_is_strict():
    d = {"releaseGuardianShare": True, "optimisticAllowed": True, "r": 0.5}
    claim, proof = _fraud("risk-understated", d, r_margin=0)
    assert OP.fraud_proof_wire_check(claim, proof) == "consistency"  # r == claimed_r + margin is not above it
    d2 = dict(d, r=0.5000001)
    claim, proof = _fraud("risk-understated", d2, r_margin=0)
    assert OP.fraud_proof_wire_check(claim, proof) == "ok"


def test_fraud_proof_claimed_r_absent_on_both_sides():
    claim, proof = _fraud()
    del claim["claimed_r"]
    del proof["claimed_r"]
    assert OP.fraud_proof_wire_check(claim, proof) == "ok"
    claim, proof = _fraud()
    del claim["claimed_r"]
    assert OP.fraud_proof_wire_check(claim, proof) == "claimed_r"
    claim, proof = _fraud()
    del proof["claimed_r"]
    assert OP.fraud_proof_wire_check(claim, proof) == "claimed_r"


def test_fraud_proof_digest_and_bond_missing_on_claim():
    claim, proof = _fraud()
    del claim["pcactn_digest"]
    assert OP.fraud_proof_wire_check(claim, proof) == "digest"
    claim, proof = _fraud()
    del claim["bond_ref"]
    assert OP.fraud_proof_wire_check(claim, proof) == "bond"


def test_fraud_proof_non_dict_inputs():
    claim, proof = _fraud()
    assert OP.fraud_proof_wire_check(claim, proof) == "ok"
    assert OP.fraud_proof_wire_check(_Duck(claim), proof) == "malformed"
    assert OP.fraud_proof_wire_check(claim, _Duck(proof)) == "malformed"
    assert OP.fraud_proof_wire_check(None, proof) == "malformed"
    assert OP.fraud_proof_wire_check(claim, None) == "malformed"


def test_fraud_proof_catch_all():
    claim, proof = _fraud()
    assert OP.fraud_proof_wire_check(_Boom(claim), proof) == "malformed"


def _settle(**over):
    r = {"claimId": "c1", "action": "open", "amount": 1, "from": "a", "to": "b", "at": 1, "evidenceDigest": ""}
    r.update(over)
    r = {k: v for k, v in r.items() if v is not None}
    return {**r, "sig": b64u(K.sign(OP._SETTLEMENT_DOMAIN.encode() + canonical_bytes(r)))}


def test_settlement_amount_floor():
    assert OP.settlement_wire_check(_settle(amount=1), K.public) == "ok"
    assert OP.settlement_wire_check(_settle(amount=0.5), K.public) == "ok"
    assert OP.settlement_wire_check(_settle(amount=0), K.public) == "shape"
    assert OP.settlement_wire_check(_settle(amount=-1), K.public) == "shape"


def _slash(split_over=None, amount=10, **over):
    split = {"amount": amount, "challengerReward": 0, "victimCompensation": 0, "treasuryRemainder": amount,
             "victimAccount": "v", "treasuryAccount": "t"}
    split.update(split_over or {})
    split = {k: v for k, v in split.items() if v is not _DEL}
    return _settle(action="slash", amount=amount, to="t", evidenceDigest="e", split=split, **over)


_DEL = object()


def test_settlement_slash_anonymous_split():
    assert OP.settlement_wire_check(_slash({"challengerAccount": None}), K.public) == "ok"
    # an absent challengerAccount is not an anonymous split
    assert OP.settlement_wire_check(_slash(), K.public) == "split"
    # explicit null with a tiny challenger reward: not anonymous, though the float sum still equals the amount
    assert OP.settlement_wire_check(_slash({"challengerAccount": None, "challengerReward": 1e-20}), K.public) == "split"
    assert OP.settlement_wire_check(_slash({"challengerAccount": None, "victimCompensation": 1e-20}), K.public) == "split"
    assert OP.settlement_wire_check(_slash({"challengerAccount": "ch", "challengerReward": 4, "treasuryRemainder": 6}), K.public) == "ok"


def test_settlement_catch_all():
    assert OP.settlement_wire_check(_Boom(_settle()), K.public) == "malformed"


# ======================================================================================================================= undo

def _rbody(**o):
    b = {"v": 1, "kind": U.UNDO_RECEIPT_KIND, "record": "r1", "event": "opened", "state": "open", "at": 5,
         "compensation_digest": "cd", "prev": "", "note": "", "signer": K.public}
    b.update(o)
    return b


def _rsign(body):
    return {**body, "sig": b64u(K.sign(U._domain_bytes(U.UNDO_RECEIPT_DOMAIN, body)))}


@pytest.mark.parametrize("over", [
    {"v": 2}, {"kind": "x"}, {"record": ""}, {"event": "bogus"}, {"state": "bogus"}, {"at": "5"}, {"compensation_digest": 5},
    {"prev": 5}, {"note": 5}, {"signer": "evil"},
])
def test_verify_receipt_refuses_each_bad_field(over):
    # signed correctly over the bad content: only the shape check can refuse it
    assert U.verify_undo_receipt(_rsign(_rbody()), K.public) is True
    assert U.verify_undo_receipt(_rsign(_rbody(**over)), K.public) is False


def test_verify_receipt_non_dict_with_all_members():
    r = _rsign(_rbody())
    assert U.verify_undo_receipt(_Duck(r), K.public) is False
    assert U.verify_undo_receipt([], K.public) is False


def test_token_check_null_record_is_malformed():
    rec = {"id": "r1", "aud": "a", "principal": "p", "compensation_digest": "cd", "window_end": 100}
    tok = U.sign_undo_token(rec, bytes(range(32)))
    assert U.undo_token_check(tok, K.public, rec, 50) == "ok"
    assert U.undo_token_check(tok, K.public, None, 50) == "malformed"


class _SpyStr(str):
    calls = None

    def encode(self, *a, **k):
        self.calls.append((a, k))
        return _SpyBytes(str.encode(self, *a, **k))


class _SpyBytes(bytes):
    calls = None

    def __getitem__(self, i):
        r = bytes.__getitem__(self, i)
        return _SpyBytes(r) if isinstance(i, slice) else r

    def decode(self, *a, **k):
        _SpyBytes.calls.append((a, k))
        return bytes.decode(self, *a, **k)


def test_domain_bytes_uses_utf8():
    calls = []
    s = _SpyStr("dom\x00")
    s.calls = calls
    assert U._domain_bytes(s, {"a": 1}) == b"dom\x00" + b'{"a":1}'
    assert calls == [(("utf-8",), {})]


def test_u16_head_codec_arguments():
    enc, dec = [], []
    s = _SpyStr("a\U0001F600b")
    s.calls = enc
    _SpyBytes.calls = dec
    # str.encode is spied; hand back spied bytes so the decode arguments are observed too
    assert U._u16_head(s, 2) == "a"
    assert enc == [(("utf-16-le", "surrogatepass"), {})]
    assert dec == [(("utf-16-le", "surrogatepass"), {})]


def test_u16_head_lone_surrogates_and_pairs():
    hi, lo = "\ud800", "\udc00"
    assert U._u16_head("a" + hi + "b", 2) == "a" + hi  # a lone surrogate survives the round trip
    assert U._u16_head("\U0001F600", 1) == ""  # never splits a pair (n = 1 included)
    assert U._u16_head("a\U0001F600", 2) == "a"
    assert U._u16_head("a\U0001F600", 3) == "a\U0001F600"
    assert U._u16_head(hi + lo, 1) == ""  # U+10000: lowest pair
    assert U._u16_head("􏿿", 1) == ""  # highest pair
    assert U._u16_head("\udc00\udc00", 1) == "\udc00"  # a low surrogate is not a lead
    assert U._u16_head("􏰀x", 1) == ""
    assert U._u16_head(hi + "", 1) == hi  # U+E000 is not a trail
    assert U._u16_head("a\udc00", 1) == "a"  # a trail alone after a plain unit is no pair
    assert U._u16_head("\udbffa", 1) == "\udbff"
    assert U._u16_head("abc", 0) == ""
    assert U._u16_head("abc", 2) == "ab"


def test_u16_head_n_one_cut_of_pair():
    assert U._u16_head("\U0001F600x", 1) == ""


def test_transition_does_not_alias_the_event_or_record():
    rec = {"state": "open", "window_end": 100, "ver": 1, "meta": {"x": [1]}}
    res = {"a": {"b": 1}}
    out = U.undo_transition(rec, {"kind": "effect", "result": res}, 50)
    assert out["outcome"] == "applied"
    res["a"]["b"] = 2
    assert out["record"]["effect"]["result"] == {"a": {"b": 1}}
    out["record"]["meta"]["x"].append(2)
    assert rec["meta"]["x"] == [1]
    rec2 = {"state": "vetoed", "window_end": 100, "ver": 1}
    res2 = {"a": {"b": 1}}
    out2 = U.undo_transition(rec2, {"kind": "compensated", "result": res2}, 50)
    assert out2["outcome"] == "applied"
    res2["a"]["b"] = 2
    assert out2["record"]["outcome"]["result"] == {"a": {"b": 1}}


def test_decode_token_bounds():
    assert U.decode_undo_token("") is None
    assert U.decode_undo_token(5) is None
    assert U.decode_undo_token(["x"]) is None
    assert U.decode_undo_token(U.encode_undo_token({"a": 1})) == {"a": 1}


# ================================================================================================================ operations

def _az(id="op1", verb="v", resource="/r", pcactn=None, params=None, allow=True):
    return SimpleNamespace(allow=allow, pcactn={"action": {"reversibility_class": "reversible"}} if pcactn is None else pcactn,
                           operation=AuthorizedOperation(verb=verb, resource=resource, params_digest=params_digest(params), id=id))


def _rec(id="op1", state="pending", **o):
    r = {"id": id, "state": state, "verb": "v", "resource": "/r", "params_digest": EMPTY_PARAMS_DIGEST, "reversibility": "reversible",
         "startedAt": 1000}
    r.update(o)
    return r


def test_allowed_each_condition_alone():
    good = _az()
    assert EO._allowed(good) == (good.pcactn, good.operation)
    assert EO._allowed(_az(allow=False)) is None
    assert EO._allowed(_az(allow="yes")) is None
    assert EO._allowed(SimpleNamespace(pcactn=good.pcactn, operation=good.operation)) is None  # no allow attribute
    assert EO._allowed(SimpleNamespace(allow=True, pcactn="x", operation=good.operation)) is None
    assert EO._allowed(SimpleNamespace(allow=True, pcactn=good.pcactn, operation=SimpleNamespace(id=5))) is None
    assert EO._allowed(SimpleNamespace(allow=True, pcactn=good.pcactn, operation=SimpleNamespace(id=""))) is None
    assert EO._allowed(SimpleNamespace(allow=True, pcactn=good.pcactn, operation=SimpleNamespace(id="x"))) is not None


def test_execute_refused_texts():
    out = EO.execute_authorized(_az(allow=False), lambda h: 1, store=EO.MemoryOperationStore())
    assert (out.status, out.reason) == ("refused", "executeAuthorized: the authorization did not allow an operation")
    out = EO.execute_authorized(_az(), lambda h: 1, store=EO.MemoryOperationStore(), operation={"verb": "other", "resource": "/r"})
    assert (out.status, out.reason) == ("refused", "executeAuthorized: the authorization is not for this operation (verb, resource or params differ)")
    assert out.operation_id is None


def test_bound_to_requires_every_member():
    op = AuthorizedOperation(verb="v", resource="/r", params_digest=params_digest({"a": 1}), id="x")
    good = {"verb": "v", "resource": "/r", "params": {"a": 1}}
    assert EO._bound_to(op, good) is True
    assert EO._bound_to(op, dict(good, verb="w")) is False
    assert EO._bound_to(op, dict(good, resource="/s")) is False
    assert EO._bound_to(op, dict(good, params={"a": 2})) is False
    assert EO._bound_to(op, dict(good, verb="w", resource="/s")) is False
    assert EO._bound_to(op, dict(good, verb="w", params={"a": 2})) is False
    assert EO._bound_to(op, dict(good, resource="/s", params={"a": 2})) is False
    assert EO._bound_to(op, dict(good, verb="w", resource="/s", params={"a": 2})) is False
    assert EO._bound_to(op, _Duck(good)) is False


def test_non_dict_action_is_irreversible():
    out = EO.execute_authorized(_az(pcactn={"action": 5}), lambda h: 1, store=EO.MemoryOperationStore(), now=lambda: 1000)
    assert out.status == "refused"
    assert out.reason == ("executeAuthorized: a irreversible operation needs a recheck (revocation, expiry, approval) before it "
                          "runs (fail closed)")


def test_handle_carries_the_operation():
    seen = []
    az = _az()
    EO.execute_authorized(az, lambda h: seen.append(h) or "R", store=EO.MemoryOperationStore(), now=lambda: 1000)
    h = seen[0]
    assert h.idempotency_key == "op1" and h.operation is az.operation and h.pcactn is az.pcactn


_IRR = {"action": {"reversibility_class": "irreversible"}}


@pytest.mark.parametrize("rc, why", [
    ({"ok": False, "reason": "R"}, "R"),
    ({"ok": False}, "refused"),
    ({"ok": False, "reason": ""}, "refused"),
    ({"ok": None, "reason": "x"}, "refused"),
    ({"ok": "no", "reason": "x"}, "refused"),
    ("nope", "refused"),
    (None, "refused"),
    ([], "refused"),
])
def test_recheck_refusal_reasons(rc, why):
    store = EO.MemoryOperationStore()
    ran = []
    out = EO.execute_authorized(_az(pcactn=_IRR), lambda h: ran.append(1), store=store, recheck=lambda h: rc, now=lambda: 1000)
    assert not ran
    assert (out.status, out.reason, out.operation_id) == ("aborted", "recheck: " + why, "op1")
    assert out.replayed is False
    assert store.get("op1")["error"] == "recheck: " + why


def _stale_executing(store, id="op1"):
    store._m[id] = {"id": id, "state": "executing", "startedAt": 0, "executingAt": 0, "verb": "v", "resource": "/r",
                    "params_digest": EMPTY_PARAMS_DIGEST}


def test_recheck_lost_race_answers_from_the_current_record():
    store = EO.MemoryOperationStore()

    def recheck(h):
        _stale_executing(store)
        return {"ok": False, "reason": "no"}
    ran = []
    out = EO.execute_authorized(_az(pcactn=_IRR), lambda h: ran.append(1), store=store, recheck=recheck, now=lambda: 1000,
                                pending_timeout_ms=500)
    assert not ran
    assert (out.status, out.operation_id, out.replayed) == ("uncertain", "op1", True)
    assert out.reason == "no outcome recorded within 500 ms of the start: the side effect may or may not have happened"


class _HookStore(EO.MemoryOperationStore):
    hook = None

    def create(self, record):
        r = super().create(record)
        if r is None and self.hook:
            self.hook(self, record["id"])
        return r


def test_claim_lost_before_executing_answers_from_the_current_record():
    store = _HookStore()
    store.hook = lambda s, i: _stale_executing(s, i)
    ran = []
    out = EO.execute_authorized(_az(), lambda h: ran.append(1), store=store, now=lambda: 1000, pending_timeout_ms=500)
    assert not ran
    assert (out.status, out.operation_id, out.replayed) == ("uncertain", "op1", True)
    assert out.reason == "no outcome recorded within 500 ms of the start: the side effect may or may not have happened"


def test_record_is_executing_while_fn_runs():
    store = EO.MemoryOperationStore()
    seen = []
    EO.execute_authorized(_az(), lambda h: seen.append(store.get("op1")), store=store, now=lambda: 1234)
    assert seen[0]["state"] == "executing" and seen[0]["executingAt"] == 1234
    assert store.get("op1")["state"] == "committed"


def test_failed_and_committed_outcome_fields():
    def boom(h):
        raise RuntimeError("bad")
    out = EO.execute_authorized(_az(), boom, store=EO.MemoryOperationStore(), now=lambda: 1000)
    assert (out.status, out.error, out.replayed) == ("failed", "bad", False)
    out = EO.execute_authorized(_az(), lambda h: 7, store=EO.MemoryOperationStore(), now=lambda: 1000)
    assert (out.status, out.result, out.replayed, out.recorded) == ("committed", 7, False, True)


class _NoCommitStore(EO.MemoryOperationStore):
    mode = "refuse"

    def transition(self, id, from_state, next_record):
        if next_record.get("state") == "committed":
            if self.mode == "raise":
                raise RuntimeError("down")
            return False
        return super().transition(id, from_state, next_record)


def test_commit_not_recorded_is_reported():
    s = _NoCommitStore()
    out = EO.execute_authorized(_az(), lambda h: 7, store=s, now=lambda: 1000)
    assert (out.status, out.result, out.recorded, out.replayed) == ("committed", 7, False, False)
    s = _NoCommitStore()
    s.mode = "raise"
    out = EO.execute_authorized(_az(), lambda h: 7, store=s, now=lambda: 1000)
    assert out.status == "committed" and out.recorded is False


def test_recover_operation_default_timeout():
    store = EO.MemoryOperationStore()
    store.create(_rec(startedAt=0))
    assert EO.recover_operation(store, "op1", now=lambda: EO.OPERATION_PENDING_TIMEOUT_MS)["state"] == "pending"
    r = EO.recover_operation(store, "op1", now=lambda: EO.OPERATION_PENDING_TIMEOUT_MS + 1)
    assert r["state"] == "aborted"
    assert r["error"] == "not started within 300000 ms of the claim: the side effect never ran"
    assert EO.recover_operation(store, "none") is None


def test_settle_stale_age_sources():
    store = EO.MemoryOperationStore()
    # an executing record without executingAt ages from startedAt
    store.create(_rec(state="executing", startedAt=0))
    r = EO._settle_stale(store, store.get("op1"), 1000, 500)
    assert r["state"] == "uncertain"
    # a pending record ages from startedAt, never from executingAt
    store2 = EO.MemoryOperationStore()
    store2.create(_rec(state="pending", startedAt=900, executingAt=0))
    assert EO._settle_stale(store2, store2.get("op1"), 1000, 500)["state"] == "pending"


def test_settle_stale_returns_what_is_stored_now():
    store = EO.MemoryOperationStore()
    store.create(_rec(state="committed", result=1))
    stale = _rec(state="executing", executingAt=0, startedAt=0)
    r = EO._settle_stale(store, stale, 10 ** 6, 1)
    assert r["state"] == "committed"

    class Gone(EO.MemoryOperationStore):
        def transition(self, *a):
            return False

        def get(self, id):
            return None
    r2 = EO._settle_stale(Gone(), stale, 10 ** 6, 1)
    assert r2["state"] == "uncertain" and r2["finishedAt"] == 10 ** 6


def test_from_record_defaults_and_flags():
    s = EO.MemoryOperationStore()
    o = EO._from_record(s, _rec(state="committed", result={"a": 1}), 1000, 500)
    assert (o.status, o.operation_id, o.result, o.replayed, o.recorded) == ("committed", "op1", {"a": 1}, True, True)
    o = EO._from_record(s, _rec(state="failed"), 1000, 500)
    assert (o.status, o.error, o.replayed) == ("failed", "failed", True)
    o = EO._from_record(s, _rec(state="failed", error="E"), 1000, 500)
    assert o.error == "E"
    o = EO._from_record(s, _rec(state="aborted"), 1000, 500)
    assert (o.status, o.reason, o.replayed) == ("aborted", "aborted", True)
    o = EO._from_record(s, _rec(state="uncertain"), 1000, 500)
    assert (o.status, o.reason, o.replayed) == ("uncertain", "outcome unknown", True)
    o = EO._from_record(s, _rec(state="pending", startedAt=999), 1000, 500)
    assert (o.status, o.operation_id, o.replayed) == ("pending", "op1", True)
    o = EO._from_record(s, _rec(state="weird"), 1000, 500)
    assert (o.status, o.operation_id, o.reason, o.replayed) == ("uncertain", "op1", "unknown record state 'weird'", True)


def test_finish_settles_through_uncertain_only_from_executing():
    s = EO.MemoryOperationStore()
    s.create(_rec(state="uncertain"))
    assert EO._finish(s, _rec(state="executing"), {"state": "committed"}) is True
    assert s.get("op1")["state"] == "committed"
    s2 = EO.MemoryOperationStore()
    s2.create(_rec(state="uncertain"))
    assert EO._finish(s2, _rec(state="pending"), {"state": "committed"}) is False
    assert s2.get("op1")["state"] == "uncertain"
    s3 = EO.MemoryOperationStore()
    s3.create(_rec(state="executing"))
    assert EO._finish(s3, _rec(state="executing"), {"state": "failed", "error": "e"}) is True
    s4 = EO.MemoryOperationStore()
    s4.create(_rec(state="committed"))
    assert EO._finish(s4, _rec(state="executing"), {"state": "failed"}) is False


def test_answer_current_settles_a_stale_record_and_reports_a_vanished_one():
    s = EO.MemoryOperationStore()
    s.create(_rec(state="pending", startedAt=0))
    o = EO._answer_current(s, "op1", 1000, 500)
    assert (o.status, o.operation_id, o.replayed) == ("aborted", "op1", True)
    assert o.reason == "not started within 500 ms of the claim: the side effect never ran"
    o = EO._answer_current(s, "nope", 1000, 500)
    assert (o.status, o.operation_id, o.reason, o.replayed) == ("uncertain", "nope", "the operation record disappeared", True)


def test_store_transition_forces_the_id():
    m = EO.MemoryOperationStore()
    m.create(_rec())
    assert m.transition("op1", "pending", {"state": "x", "id": "other"}) is True
    assert m.get("op1")["id"] == "op1"
    kv = EO.KvOperationStore(__import__("atlas_pca").atomic_kv.MemoryAtomicKv())
    kv.create(_rec())
    assert kv.transition("op1", "pending", {"state": "x"}) is True
    assert kv.get("op1") == {"state": "x", "id": "op1"}
    assert kv.transition("op1", "pending", {"state": "y"}) is False


def test_kv_transition_is_false_when_the_kv_never_ran_the_step():
    class Dead:
        def update(self, key, fn):
            return None
    assert EO.KvOperationStore(Dead()).transition("op1", "pending", {"state": "x"}) is False


class _Opts:
    def __init__(self, revoked=False, plans=None, result=None):
        self.plans, self._revoked, self.result, self.calls = plans, revoked, result, []

    def is_revoked(self, p, grant):
        self.calls.append((p, grant))
        if isinstance(self._revoked, Exception):
            raise self._revoked
        return self._revoked

    def run(self, pcactn, **kw):
        return self.result


class _Plans:
    def __init__(self, state):
        self.state, self.got, self.checked = state, [], []

    def get(self, grant_ref, root):
        self.got.append((grant_ref, root))
        return {"root": root}

    def check(self, grant_ref, root, **kw):
        self.checked.append((grant_ref, root, kw))
        return self.state


def _exec(opts, resolve=lambda ref: {"g": ref}, **kw):
    kw.setdefault("operations", EO.MemoryOperationStore())
    kw.setdefault("now", lambda: 777)
    return EO.Executor(options=opts, audience="aud", resolve_grant=resolve, **kw)


def _handle(p):
    return EO.ExecutionHandle(idempotency_key="id", operation=None, pcactn=p)


def test_executor_recheck_resolves_the_grant_by_reference():
    seen = []
    ex = _exec(_Opts(), resolve=lambda ref: seen.append(ref) or {"ok": 1})
    assert ex._recheck(_handle({"grant_ref": "G1"})) == {"ok": True}
    assert seen == ["G1"]
    ex = _exec(_Opts(), resolve=lambda ref: None)
    assert ex._recheck(_handle({"grant_ref": "G1"})) == {"ok": False, "reason": "the grant is no longer known"}


def test_executor_recheck_revocation_inputs_and_reasons():
    grant = {"g": 1}
    p = {"grant_ref": "G"}
    o = _Opts()
    assert _exec(o, resolve=lambda r: grant)._recheck(_handle(p)) == {"ok": True}
    assert o.calls[0][0] is p and o.calls[0][1] is grant
    for revoked, reason in ((True, "the grant has been revoked"), (None, "revocation could not be checked"),
                            ("x", "revocation could not be checked"), (RuntimeError("down"), "revocation could not be checked")):
        r = _exec(_Opts(revoked=revoked), resolve=lambda r: grant)._recheck(_handle(p))
        assert r == {"ok": False, "reason": reason}


def test_executor_recheck_plan_checks():
    plans = _Plans({"executable": True})
    ex = _exec(_Opts(plans=plans))
    p = {"grant_ref": "G", "plan": {"root": "R1", "node_id": "n9"}}
    assert ex._recheck(_handle(p)) == {"ok": True}
    assert plans.got == [("G", "R1")]
    assert plans.checked == [("G", "R1", {"node_id": "n9", "now": 777})]
    # a plan that is not an object registers nothing
    plans2 = _Plans({"executable": False, "state": "revoked"})
    assert _exec(_Opts(plans=plans2))._recheck(_handle({"grant_ref": "G", "plan": "x"})) == {"ok": True}
    assert plans2.checked == []
    bad = _exec(_Opts(plans=_Plans({"executable": False, "state": "revoked"})))
    assert bad._recheck(_handle(p)) == {"ok": False, "reason": "plan is revoked"}
    bad = _exec(_Opts(plans=_Plans({"executable": False, "state": "revoked", "reason": "why"})))
    assert bad._recheck(_handle(p)) == {"ok": False, "reason": "why"}


def test_executor_recheck_extra_hook():
    h = _handle({"grant_ref": "G"})
    seen = []
    ex = _exec(_Opts(), recheck=lambda hh: seen.append(hh) or {"ok": False, "reason": "extra"})
    assert ex._recheck(h) == {"ok": False, "reason": "extra"}
    assert seen == [h]


def test_executor_replay_answer_only_when_replay_is_the_sole_failure():
    p = {"x": 1}
    store = EO.MemoryOperationStore()
    store.create(_rec(id=hash_canonical(p), state="committed", result=9))
    op = {"verb": "v", "resource": "/r"}

    def run(status, checks):
        return AuthorizeResult(allow=False, status=status, checks=checks, reason="why")
    ok = _exec(_Opts(result=run(403, {"replay": "fail", "aud": "pass"})), operations=store)(p, op, lambda h: 1)
    assert (ok.status, ok.result, ok.replayed) == ("committed", 9, True)
    two = _exec(_Opts(result=run(403, {"replay": "fail", "aud": "fail"})), operations=store)(p, op, lambda h: 1)
    assert two.status == "denied" and two.reason == "why"
    s401 = _exec(_Opts(result=run(401, {"replay": "fail"})), operations=store)(p, op, lambda h: 1)
    assert s401.status == "denied" and s401.reason == "why"


def test_create_executor_passes_every_option_through():
    f, g, now = (lambda h: {"ok": True}), (lambda op: "reversible"), (lambda: 5)
    ex = EO.create_executor(operations="ops", options="opts", audience="aud", resolve_grant="res", recheck=f, recheck_for="always",
                            reversibility_class_of=g, pending_timeout_ms=123, now=now)
    assert ex._ops == "ops" and ex._opts == "opts" and ex._aud == "aud" and ex._resolve == "res"
    assert ex._extra is f and ex._recheck_for == "always" and ex._cls_of is g and ex._timeout == 123 and ex._now is now


# ======================================================================================================================= stepup

def _transport(replies):
    calls = []

    def go(method, url, headers, body):
        calls.append((method, url, headers, body))
        r = replies.pop(0) if isinstance(replies, list) else replies
        if isinstance(r, Exception):
            raise r
        return r
    go.calls = calls
    return go


def _client(replies=None, now=lambda: 1000, dash="https://dash.example.com/", inst="https://inst.example.com/", **kw):
    key = SU.PrincipalDeviceKey(SU.MemorySecretStore())
    key.generate()
    t = _transport(replies if replies is not None else (200, "{}"))
    return SU.StepUpClient(dash, inst, "acct/1", "ins tance", key, lambda: "tok", transport=t, now=now, **kw), t


def test_secret_store_file_encoding_and_mode(tmp_path, monkeypatch):
    seen = []
    real_open = open

    def spy(*a, **k):
        seen.append(k)
        return real_open(*a, **k)
    path = str(tmp_path / "k")
    store = SU.FileSecretStore(path)
    assert store.load() is None
    monkeypatch.setattr(SU, "open", spy, raising=False)
    monkeypatch.setattr(SU.os, "chmod", lambda *a, **k: None)  # the creation mode alone must already be 0600
    store.save(b"\x01" * 32)
    if os.name != "nt":  # POSIX file modes do not exist on Windows
        assert stat_mode(path) == 0o600
    assert store.load() == b"\x01" * 32
    assert seen == [{"encoding": "ascii"}]


def stat_mode(path):
    return os.stat(path).st_mode & 0o777


def test_secret_store_writes_ascii(tmp_path, monkeypatch):
    got = []
    real = os.fdopen

    def spy(fd, mode, **k):
        got.append((mode, k))
        return real(fd, mode, **k)
    monkeypatch.setattr(SU.os, "fdopen", spy)
    SU.FileSecretStore(str(tmp_path / "k2")).save(b"\x02" * 32)
    assert got == [("w", {"encoding": "ascii"})]


def test_secret_store_load_rejects_non_ascii(tmp_path):
    p = tmp_path / "k3"
    p.write_bytes("é".encode("utf-8"))
    with pytest.raises(UnicodeDecodeError):
        SU.FileSecretStore(str(p)).load()


def test_sign_falls_back_to_the_pure_signer(monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric.ed25519", None)
    seen = []
    real = ed25519.sign
    monkeypatch.setattr(ed25519, "sign", lambda s, m: seen.append((s, m)) or real(s, m))
    seed = bytes(range(32))
    sig = SU._sign(seed, b"msg")
    assert seen == [(seed, b"msg")]
    assert ed25519.verify(ed25519.public_key(seed), b"msg", sig)


def test_generate_asks_for_32_bytes(monkeypatch):
    asked = []
    monkeypatch.setattr(SU.secrets, "token_bytes", lambda n=None: asked.append(n) or bytes(range(32)))
    store = SU.MemorySecretStore()
    SU.PrincipalDeviceKey(store).generate()
    assert asked == [32] and store.load() == bytes(range(32))


def test_seed_error_messages():
    k = SU.PrincipalDeviceKey(SU.MemorySecretStore())
    with pytest.raises(SU.NoDeviceKey) as e:
        k.export_secret()
    assert str(e.value) == "No principal device key is stored."
    k._store.save(b"\x01" * 5)
    with pytest.raises(SU.InvalidSecret) as e:
        k.export_secret()
    assert str(e.value) == "The stored secret is not a 32-byte seed."


def test_urllib_transport_request_and_decoding(monkeypatch):
    seen = {}

    class Resp:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return _SpyBytes(b"ok\xff")

    class Opener:
        def open(self, req, timeout="unset"):
            seen["req"], seen["timeout"] = req, timeout
            return Resp()
    monkeypatch.setattr(SU, "_OPENER", Opener())
    dec = []
    _SpyBytes.calls = dec
    status, text = SU._urllib_transport(7.5)("POST", "https://h.example/x", {"X-A": "1"}, b"body")
    assert (status, text) == (201, "ok�")
    assert dec == [(("utf-8", "replace"), {})]
    req = seen["req"]
    assert req.full_url == "https://h.example/x" and req.data == b"body" and req.get_method() == "POST"
    assert req.get_header("X-a") == "1"
    assert seen["timeout"] == 7.5


def test_urllib_transport_http_error_and_network_error(monkeypatch):
    class Opener:
        def __init__(self, exc):
            self.exc = exc

        def open(self, req, timeout=None):
            raise self.exc
    dec = []
    _SpyBytes.calls = dec

    class Body(io.BytesIO):
        def read(self, *a):
            return _SpyBytes(b"bad\xff")
    err = urllib.error.HTTPError("https://h/x", 500, "m", {}, Body(b""))
    monkeypatch.setattr(SU, "_OPENER", Opener(err))
    assert SU._urllib_transport(1)("GET", "https://h/x", {}, None) == (500, "bad�")
    assert dec == [(("utf-8", "replace"), {})]
    monkeypatch.setattr(SU, "_OPENER", Opener(urllib.error.URLError("boom")))
    with pytest.raises(SU.TransportError) as e:
        SU._urllib_transport(1)("GET", "https://h/x", {}, None)
    assert str(e.value) == "<urlopen error boom>"
    monkeypatch.setattr(SU, "_OPENER", Opener(OSError("sock")))
    with pytest.raises(SU.TransportError) as e:
        SU._urllib_transport(1)("GET", "https://h/x", {}, None)
    assert str(e.value) == "sock"


def test_parse_iso_epoch_ms():
    base = calendar.timegm((2026, 10, 6, 18, 0, 0))
    assert SU._parse_iso("2026-10-06T18:00:00Z") == base * 1000
    assert SU._parse_iso("2026-10-06T18:00:00.123Z") == base * 1000 + 123
    assert SU._parse_iso("2026-10-06T18:00:00.5Z") == base * 1000 + 500
    assert SU._parse_iso("2026-10-06T18:00:00.12Z") == base * 1000 + 120
    assert SU._parse_iso("2026-10-06T18:00:00.987654Z") == base * 1000 + 987
    assert SU._parse_iso("2026-10-06T18:00:00Z") == int(datetime(2026, 10, 6, 18, tzinfo=timezone.utc).timestamp()) * 1000
    with pytest.raises(ValueError):
        SU._parse_iso("2026-10-06")


def test_base_url_validation():
    assert SU._base("http://host.example/") == "http://host.example"
    assert SU._base("HTTPS://host.example//") == "HTTPS://host.example"
    assert SU._base("https://hostX/") == "https://hostX"
    assert SU._base("https://hostX") == "https://hostX"
    for bad in ("ftp://h", "h.example", "https://", "http:///x"):
        with pytest.raises(ValueError):
            SU._base(bad)


def test_client_defaults(monkeypatch):
    got = []
    monkeypatch.setattr(SU, "_urllib_transport", lambda t: got.append(t) or (lambda *a: (200, "{}")))
    key = SU.PrincipalDeviceKey(SU.MemorySecretStore())
    c = SU.StepUpClient("https://d.example", "https://i.example", "a", "i", key, lambda: "t")
    assert got == [30.0]
    assert abs(c._now() - time.time() * 1000) < 5000
    SU.StepUpClient("https://d.example", "https://i.example", "a", "i", key, lambda: "t", timeout=12.5)
    assert got == [30.0, 12.5]


def _stepup_json(**o):
    e = {"id": "s1", "grant_ref": "g1", "action": {"verb": "pay", "resource": "/r"}, "required_t": 2, "threshold_message": "abc",
         "expires_at": "2026-10-06T18:00:00.123Z"}
    e.update(o)
    return e


def test_pending_request_and_parsing():
    exp = calendar.timegm((2026, 10, 6, 18, 0, 0)) * 1000 + 123
    c, t = _client((200, json.dumps({"stepups": [_stepup_json()]})), now=lambda: exp - 1)
    out = c.pending()
    assert out == [SU.PendingStepUp(id="s1", grant_ref="g1", action_verb="pay", action_resource="/r", required_t=2,
                                    threshold_message="abc", expires_at=exp)]
    method, url, headers, body = t.calls[0]
    assert method == "GET" and body is None
    assert url == "https://dash.example.com/v1/dashboard/accounts/acct%2F1/instances/ins%20tance/pca/stepups?status=pending"
    assert headers == {"Authorization": "Bearer tok", "Accept": "application/json"}
    # an entry that expires exactly now is expired
    c2, _ = _client((200, json.dumps({"stepups": [_stepup_json()]})), now=lambda: exp)
    assert c2.pending() == []


def test_pending_errors():
    c, _ = _client((200, json.dumps({"stepups": "x"})))
    with pytest.raises(SU.TransportError) as e:
        c.pending()
    assert str(e.value) == "Unreadable step-up list."
    c, _ = _client((200, "not json"))
    with pytest.raises(SU.TransportError) as e:
        c.pending()
    assert str(e.value) == "Unreadable step-up list."
    for bad in (_stepup_json(required_t=True), _stepup_json(required_t="2"), _stepup_json(grant_ref=5), _stepup_json(id=None)):
        c, _ = _client((200, json.dumps({"stepups": [bad]})), now=lambda: 0)
        with pytest.raises(SU.TransportError) as e:
            c.pending()
        assert str(e.value) == "Unreadable step-up entry."
    c, _ = _client((200, json.dumps({"stepups": [_stepup_json(required_t=True)]})), now=lambda: 0)
    with pytest.raises(SU.TransportError) as e:
        c.pending()
    assert type(e.value.__cause__) is ValueError and str(e.value.__cause__) == "required_t"


def test_call_status_boundaries():
    c, _ = _client((300, json.dumps({"errors": [{"message": "moved"}]})))
    with pytest.raises(SU.ApiError) as e:
        c._call("GET", "https://x", {})
    assert e.value.status == 300 and str(e.value) == "moved"
    c, _ = _client((299, "{}"))
    assert c._call("GET", "https://x", {}) == (299, "{}")
    c, _ = _client((403, "x"))
    with pytest.raises(SU.PrincipalMismatch) as e:
        c._call("GET", "https://x", {})
    assert str(e.value) == "The request failed."


def test_approve_request_and_answers():
    c, t = _client((200, json.dumps({"status": "anchored", "allow": True})))
    msg = b"threshold bytes"
    r = c.approve(SU.PendingStepUp("s/1", "g", "v", "/r", 1, b64u(msg), 5))
    assert r == SU.ApproveResult(status="anchored", anchored=True, http_status=200)
    method, url, headers, body = t.calls[0]
    assert method == "POST" and url == "https://inst.example.com/v1/pca/stepups/s%2F1/cosign"
    assert headers == {"Content-Type": "application/json", "Accept": "application/json"}
    payload = json.loads(body)
    assert payload["role"] == "principal" and payload["publicKey"] == c.key.public_key()
    assert ed25519.verify(ed25519.public_key(c.key._seed()), msg, SU.decode_b64u_strict(payload["sig"]))
    for text, want in (("[1,2]", ("", False)), ("5", ("", False)), ("not json", ("", False)), ('{"status": 5}', ("", False)),
                       ('{}', ("", False)), ('{"status":"pending","allow":"true"}', ("pending", False))):
        c, _ = _client((202, text))
        r = c.approve(SU.PendingStepUp("s", "g", "v", "/r", 1, b64u(msg), 5))
        assert (r.status, r.anchored, r.http_status) == (want[0], want[1], 202)


def test_approve_rejects_non_canonical_threshold_message():
    c, t = _client()
    with pytest.raises(SU.InvalidThresholdMessage) as e:
        c.approve(SU.PendingStepUp("s", "g", "v", "/r", 1, "a=", 5))
    assert str(e.value) == "The step-up's threshold message is not canonical base64url."
    assert t.calls == []


def test_deny_request():
    c, t = _client((200, "{}"))
    c.deny(SU.PendingStepUp("a/b", "g", "v", "/r", 1, "x", 5), "no")
    method, url, headers, body = t.calls[0]
    assert method == "POST"
    assert url == "https://dash.example.com/v1/dashboard/accounts/acct%2F1/instances/ins%20tance/pca/stepups/a%2Fb/deny"
    assert headers == {"Authorization": "Bearer tok", "Accept": "application/json", "Content-Type": "application/json"}
    assert json.loads(body) == {"reason": "no"}
    c.deny(SU.PendingStepUp("a", "g", "v", "/r", 1, "x", 5))
    assert json.loads(t.calls[1][3]) == {}
