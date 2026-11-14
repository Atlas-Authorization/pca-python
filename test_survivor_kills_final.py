"""Exact-value tests for the last mutation survivors in prohibitions, contracts, the contract enforcer, risk and the authorize forbid
gate: condition and state validation messages, the veto trigger's oversized-subject rule (UTF-16 units, as the reference), the signed
evidence fallbacks, the arguments the enforcer hands to the contract monitor, and the fail-closed paths that need an injected failure."""
import importlib

from atlas_pca import contract_enforcer as CE
from atlas_pca import contracts as C
from atlas_pca import ed25519
from atlas_pca import prohibitions as P
from atlas_pca import risk as R
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.pca import b64u

Z = importlib.import_module("atlas_pca.authorize")

SEED = b"\x41" * 32
NOW = 1_700_000_000_000
NAN = float("nan")


def act(verb, resource="/r"):
    return {"action": {"verb": verb, "resource": resource}}


def _boom(*a, **k):
    raise RuntimeError("injected")


# ---- prohibitions: condition validation ---------------------------------------------------------------------------------------------

def test_a_condition_ref_must_be_a_non_empty_string():
    base = {"field": "f", "op": "eq"}
    assert P.validate_condition(dict(base)) is None
    assert P.validate_condition({**base, "ref": "x"}) is None
    for bad in ("", 5, None, ["x"], True):
        assert P.validate_condition({**base, "ref": bad}) == "bad condition.ref", bad


def test_a_member_of_collection_must_be_a_non_empty_string_but_only_for_member_of():
    base = {"field": "f", "op": "member_of"}
    assert P.validate_condition(dict(base)) is None
    assert P.validate_condition({**base, "collection": "c"}) is None
    for bad in ("", 5, None, ["c"]):
        assert P.validate_condition({**base, "collection": bad}) == "bad condition.collection", bad
    # any other op does not read the collection
    for bad in ("", 5, None):
        assert P.validate_condition({"field": "f", "op": "eq", "collection": bad}) is None, bad


# ---- prohibitions: monitor state ----------------------------------------------------------------------------------------------------

def test_state_problem_names_each_malformed_member_before_it_looks_at_the_sequence():
    good = P.empty_state(NOW)
    assert P.state_problem(good) is None
    for bad_state in (None, [], "x", 5):
        assert P.state_problem(bad_state) == "malformed monitor state", bad_state
    # seq is invalid as well: only the member check can produce the bare message
    for key, bad in (("now", None), ("now", NAN), ("now", "1"), ("ledger", []), ("ledger", None), ("latched", []), ("latched", None), ("latched", "x")):
        assert P.state_problem({**good, "seq": -1, key: bad}) == "malformed monitor state", (key, bad)
    assert P.state_problem({**good, "seq": -1}) == "malformed monitor state: seq"


# ---- prohibitions: the veto trigger ---------------------------------------------------------------------------------------------------

def _veto(resource_pattern, subject):
    return P.when_matches({"verb": "read", "resource": resource_pattern}, act("read", subject))


def test_a_regex_trigger_vetoes_a_subject_longer_than_512_utf16_units():
    # 512 units are evaluated by the matcher (no match = no veto); one more is "could not decide" = the veto applies
    assert _veto("re:zzz", "a" * 512) is False
    assert _veto("re:zzz", "a" * 513) is True
    assert _veto("re:a+", "a" * 512) is True
    # code points are not units: 256 astral characters are 512 units, 257 are 514
    assert _veto("re:zzz", "\U0001F600" * 256) is False
    assert _veto("re:zzz", "\U0001F600" * 257) is True
    assert _veto("re:zzz", "a" * 255 + "\U0001F600" * 129) is True  # 384 code points, 513 units


def test_a_non_regex_trigger_never_takes_the_oversized_shortcut():
    assert P.when_matches({"verb": "read", "resource": "/exact"}, act("read", "a" * 600)) is False
    assert P.when_matches({"verb": "read", "resource": "/exact*"}, act("read", "b" * 600)) is False
    assert P.when_matches({"verb": "read"}, act("read", "a" * 600)) is True


# ---- prohibitions: signed evidence --------------------------------------------------------------------------------------------------

def _signed():
    pub = b64u(ed25519.public_key(SEED))
    c = {"version": 1, "principal": pub, "invariants": [{"id": "n", "kind": "never", "when": {"verb": "delete"}}]}
    s, a = P.empty_state(NOW), act("read")
    signed = P.sign_safety_evidence(P.prove_safety(a, c, s), SEED, pub)
    return signed, {"signer": pub, "action": a, "constitution": c, "state": s}


def test_signed_evidence_that_does_not_reproduce_carries_the_recomputed_reason(monkeypatch):
    signed, exp = _signed()
    assert P.verify_signed_safety_evidence(signed, exp) == {"ok": True}
    monkeypatch.setattr(P, "verify_safety_evidence", lambda *a: {"ok": False, "reason": "custom reason"})
    assert P.verify_signed_safety_evidence(signed, exp) == {"ok": False, "reason": "custom reason"}
    for full in ({"ok": False}, {"ok": False, "reason": ""}, {"ok": False, "reason": None}):
        monkeypatch.setattr(P, "verify_safety_evidence", lambda *a, _f=full: _f)
        assert P.verify_signed_safety_evidence(signed, exp) == {"ok": False, "reason": "evidence does not reproduce"}, full


# ---- contracts ------------------------------------------------------------------------------------------------------------------------

def _contract(clauses):
    return {"version": 1, "principal": "pp", "invariants": [], "clauses": clauses}


def test_a_clause_whose_evaluation_raises_is_a_violated_row_of_its_own_kind(monkeypatch):
    monkeypatch.setattr(C, "validate_contract", lambda c: [])  # the clauses below are not valid contracts: only the handler is under test
    monkeypatch.setattr(C, "_eval_clause", _boom)
    reason = "clause evaluation error (fail closed)"
    got = C.check_contract(act("x"), _contract([{"id": "c1"}, {"id": "c2", "kind": "never"}]), P.empty_state(NOW))
    assert got == {"ok": False, "violated": ["c1", "c2"], "reasons": ["c1: " + reason, "c2: " + reason],
                   "evaluated": [{"id": "c1", "kind": "clause", "result": "violated", "reason": reason},
                                 {"id": "c2", "kind": "never", "result": "violated", "reason": reason}]}


def test_an_invalid_resulting_state_reuses_the_verdict_it_already_computed(monkeypatch):
    c = _contract([{"id": "n", "kind": "never", "p": {"verb": "delete"}}])
    s, a = P.empty_state(NOW), act("read")
    rows = C.check_contract(a, c, s)["evaluated"]
    real_check, real_problem, calls = C.check_contract, C.state_problem, []

    def fake(action, contract, state):
        r = real_check(action, contract, state)
        calls.append(1)
        return r if len(calls) == 1 else {**r, "reasons": r["reasons"] + ["recomputed"]}

    monkeypatch.setattr(C, "check_contract", fake)
    monkeypatch.setattr(C, "state_problem", lambda x: "boom" if isinstance(x, dict) and x.get("seq") == 1 else real_problem(x))
    got = C.advance_contract(s, a, c, {})
    assert got == {"ok": False, "violated": ["<state>"], "reasons": ["<state>: resulting state invalid: boom"], "evaluated": rows,
                   "next": s, "decidedBy": "state"}
    assert len(calls) == 1


def test_a_refused_advance_keeps_the_verdict_ids_and_replaces_a_structural_state_id():
    c = _contract([{"id": "n", "kind": "never", "p": {"verb": "delete"}}])
    s = P.empty_state(NOW)
    # a stale head after a real violation: the violated id stays, "<state>" is appended
    got = C.advance_contract(s, act("delete"), c, {"expectedSeq": 5})
    assert got["violated"] == ["n", "<state>"]
    assert got["reasons"] == ["n: never-invariant violated (forbidden action)", "<state>: stale state head (seq)"]
    assert got["decidedBy"] == "state" and got["next"] == s and got["ok"] is False
    # a malformed state is already reported as "<state>": it is not listed twice
    got = C.advance_contract(None, act("read"), c, {"expectedSeq": 0})
    assert got["violated"] == ["<state>"]
    assert got["reasons"] == ["<state>: malformed monitor state", "<state>: stale state head (seq)"]


# ---- the contract enforcer -----------------------------------------------------------------------------------------------------------

def _sc():
    prec = {"id": "review-first", "kind": "precedes", "p": {"verb": "review"}, "q": {"verb": "deploy"}}
    nodel = {"id": "no-delete", "kind": "never", "p": {"verb": "delete"}}
    pub = b64u(ed25519.public_key(SEED))
    return C.sign_contract({"version": 1, "principal": pub, "clauses": [nodel, prec]}, SEED), pub


def _open(kv, wall):
    sc, pub = _sc()
    return CE.ContractEnforcer.open(kv, sc, pub, now=lambda: wall[0]), sc


def test_the_first_check_stores_a_genesis_state_at_the_clock_or_at_zero():
    kv = MemoryAtomicKv()
    e, sc = _open(kv, [NOW])
    assert e.check(act("delete"))["reason"] == "violated"
    assert kv.get("contract/" + sc["id"]) == {"v": 1, "contract_id": sc["id"], "state": P.empty_state(NOW),
                                              "latched": {"seq": 0, "violated": ["no-delete"]}}
    kv2 = MemoryAtomicKv()
    e2, sc2 = _open(kv2, [NAN])
    assert e2.check(act("delete"))["reason"] == "violated"
    assert kv2.get("contract/" + sc2["id"]) == {"v": 1, "contract_id": sc2["id"], "state": P.empty_state(0),
                                                "latched": {"seq": 0, "violated": ["no-delete"]}}


def test_a_non_finite_clock_on_the_first_check_cannot_advance_the_genesis_state():
    kv = MemoryAtomicKv()
    e, sc = _open(kv, [NAN])
    assert e.check(act("review")) == {"allow": False, "reason": "state-error", "violated": [],
                                      "reasons": ["<state>: advance failed: clock regression"], "seq": 0}
    assert kv.get("contract/" + sc["id"]) is None


def test_check_hands_the_permission_the_state_the_clock_and_the_head_to_the_monitor(monkeypatch):
    seen, real = [], CE.check_and_advance_contract

    def spy(*args):
        seen.append(args)
        return real(*args)

    monkeypatch.setattr(CE, "check_and_advance_contract", spy)
    kv, wall = MemoryAtomicKv(), [NOW]
    e, sc = _open(kv, wall)
    key = "contract/" + sc["id"]
    assert e.check(act("review"))["allow"] is True
    assert seen[0] == (True, P.empty_state(NOW), act("review"), sc, {"now": NOW, "expectedSeq": 0})
    state1 = kv.get(key)["state"]
    assert state1["seq"] == 1
    wall[0] = NOW + 5_000
    assert e.check(act("deploy"), False)["reason"] == "permission"
    assert seen[1] == (False, state1, act("deploy"), sc, {"now": NOW + 5_000, "expectedSeq": 1})
    wall[0] = NOW - 1_000
    e.check(act("deploy"))
    assert seen[2] == (True, state1, act("deploy"), sc, {"now": state1["now"], "expectedSeq": 1})


def test_peek_evaluates_against_the_stored_state_or_a_genesis_state_at_the_clock_or_zero(monkeypatch):
    seen, real = [], CE.check_contract

    def spy(action, contract, state):
        seen.append(state)
        return real(action, contract, state)

    monkeypatch.setattr(CE, "check_contract", spy)
    wall = [NOW]
    e, sc = _open(MemoryAtomicKv(), wall)
    assert e.peek(act("review"))["allow"] is True
    assert seen[-1] == P.empty_state(NOW)
    wall[0] = NAN
    assert e.peek(act("review"))["allow"] is True
    assert seen[-1] == P.empty_state(0)
    wall[0] = NOW + 7
    assert e.check(act("review"))["allow"] is True
    stored = e._kv.get(e._key)["state"]
    assert e.peek(act("deploy"))["allow"] is True
    assert seen[-1] == stored and stored["seq"] == 1


# ---- risk ------------------------------------------------------------------------------------------------------------------------------

def test_age_since_touch_accepts_any_positive_horizon_including_fractions():
    b = {"B": 1, "tau": 0}
    assert R.age_since_touch(b, 0.25, 0.5) == 0.5
    assert R.age_since_touch(b, 0.5, 1) == 0.5
    assert R.age_since_touch(b, 1, 0) == 1
    assert R.age_since_touch(b, 1, -1) == 1
    assert R.age_since_touch(b, 1, NAN) == 1


def test_decide_risk_measures_the_age_over_the_given_or_the_default_horizon(monkeypatch):
    seen = []

    def spy(b, now, horizon_ms=3_600_000):
        seen.append(horizon_ms)
        return 0.5

    monkeypatch.setattr(R, "age_since_touch", spy)
    pol = dict(R.DEFAULT_RISK_POLICY)
    bud = {"B": 1, "tau": 0, "asOf": 0}
    R.decide_risk(pol, {}, bud, 0, True, "reversible")
    R.decide_risk(pol, {}, bud, 0, True, "reversible", age_horizon_ms=777)
    R.decide_risk(pol, {"age": 0.1}, bud, 0, True, "reversible", age_horizon_ms=888)
    assert seen == [3_600_000, 777]


# ---- the authorize forbid gate ---------------------------------------------------------------------------------------------------------

def test_a_refused_certificate_names_the_reason_or_mismatch(monkeypatch):
    import atlas_pca.forbid_certificate as FC

    op = {"verb": "read", "resource": "/r", "params": {}}
    f = {"clauses": lambda o, g: [{"id": "p1", "kind": "permit", "signer": "user", "when": {"verb": "read"}}], "require_certificate": True}
    for verdict, shown in (({"ok": False, "reason": "why not"}, "why not"), ({"ok": False}, "mismatch"), ({"ok": False, "reason": ""}, "mismatch")):
        monkeypatch.setattr(FC, "check_forbid_certificate", lambda *a, _v=verdict, **k: _v)
        r = Z._forbid_refusal("not json", f, op, lambda ref: None, {"any": "certificate"})
        assert (r.allow, r.status, r.checks, r.reason) == (False, 403, {"forbid": "fail"}, "forbid: certificate refused (%s)" % shown), verdict


def test_state_problem_bare_message_is_exact_for_a_non_object_state():
    assert P.state_problem(None) == "malformed monitor state"
    assert P.state_problem({**P.empty_state(NOW), "latched": []}) == "malformed monitor state"
