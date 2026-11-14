"""Exact-value tests for atlas_pca.contracts and atlas_pca.contract_enforcer: clause / contract validation, per-clause transitions, the
whole-contract monitor, advance, check-and-advance, and the durable enforcer (state document, latch, reset, peek, fail-closed paths).
Fail-closed handlers are driven by injected failures; nothing is cached at module level."""
import time

import pytest

from atlas_pca import contract_enforcer as CE
from atlas_pca import contracts as C
from atlas_pca import ed25519
from atlas_pca import prohibitions as P
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.pca import b64u

SEED, OTHER_SEED = b"\x21" * 32, b"\x22" * 32
NOW = 1_700_000_000_000


def _prin(seed=SEED):
    return b64u(ed25519.public_key(seed))


def act(verb, resource="/r"):
    return {"action": {"verb": verb, "resource": resource}}


def _never(id_, verb, **kw):
    return {"id": id_, "kind": "never", "p": {"verb": verb}, **kw}


def _contract(clauses, invariants=None):
    return {"version": 1, "principal": "pp", "invariants": invariants or [], "clauses": clauses}


def _nest(n):
    c = _never("leaf", "x")
    for i in range(n):
        c = {"id": "and%d" % i, "kind": "and", "clauses": [c]}
    return c


def _fail(id_, reason):
    return {"ok": False, "violated": [id_], "reasons": ["%s: %s" % (id_, reason)],
            "evaluated": [{"id": id_, "kind": "structural", "result": "violated", "reason": reason}]}


def _boom(*a, **k):
    raise RuntimeError("injected")


# ---- clause counting -------------------------------------------------------------------------------------------------------------

def test_count_clauses_is_exact_and_bounded():
    assert C._count_clauses([_nest(16)]) == 17
    assert C._count_clauses([_nest(17)]) == 274
    assert C._count_clauses([_nest(30)]) == 274
    leaves = [_never("l%d" % i, "x") for i in range(3)]
    assert C._count_clauses(leaves) == 3
    assert C._count_clauses([{"id": "n", "kind": "and", "clauses": leaves[:2]}, leaves[2]]) == 4
    assert C._count_clauses([{"id": "n", "kind": "never", "clauses": leaves}]) == 1
    assert C._count_clauses([{"id": "n", "kind": "and", "clauses": "x"}]) == 1
    assert C._count_clauses([5, None]) == 2


# ---- validation -----------------------------------------------------------------------------------------------------------------

def _v(clauses, **extra):
    c = {"version": 1, "principal": "pp", "clauses": clauses}
    c.update(extra)
    return C.validate_contract(c)


def test_clause_id_and_kind_problems():
    assert _v([{"id": "", "kind": "never", "p": {"verb": "x"}}]) == ["<no id>: missing clause id"]
    assert _v([{"id": 5, "kind": "never", "p": {"verb": "x"}}]) == ["<no id>: missing clause id"]
    assert _v([_never("x" * 128, "x")]) == []
    assert _v([_never("x" * 129, "x")]) == ["%s: id too long" % ("x" * 129)]
    assert _v([{"id": "u", "p": {"verb": "x"}}]) == ["u: unknown clause kind undefined"]
    assert _v([{"id": "u", "kind": None}]) == ["u: unknown clause kind null"]
    assert _v([{"id": "u", "kind": 5}]) == ["u: unknown clause kind 5"]
    assert _v([_never("a", "x"), _never("a", "y")]) == ["a: duplicate id"]
    assert _v([{"id": "constructor", "kind": "never", "p": {"verb": "x"}}]) == ["constructor: forbidden id"]


@pytest.mark.parametrize("kind", ["always", "never"])
def test_always_and_never_triggers(kind):
    assert _v([{"id": "a", "kind": kind}]) == ["a: p: not an object"]
    assert _v([{"id": "a", "kind": kind, "p": {"verb": ""}}]) == ["a: p: bad verb"]
    assert _v([{"id": "a", "kind": kind, "p": {"verb": "x"}}]) == []


@pytest.mark.parametrize("kind", ["precedes", "requires_prior"])
def test_precedence_triggers(kind):
    ok = {"verb": "x"}
    assert _v([{"id": "a", "kind": kind, "q": ok}]) == ["a: p: not an object"]
    assert _v([{"id": "a", "kind": kind, "p": {"verb": ""}, "q": ok}]) == ["a: p: bad verb"]
    assert _v([{"id": "a", "kind": kind, "p": ok}]) == ["a: q: not an object"]
    assert _v([{"id": "a", "kind": kind, "p": ok, "q": {"verb": []}}]) == ["a: q: bad verb"]
    assert _v([{"id": "a", "kind": kind}]) == ["a: p: not an object"]
    assert _v([{"id": "a", "kind": kind, "p": ok, "q": ok}]) == []


def test_responds_within_triggers_and_window():
    ok = {"verb": "x"}

    def rw(**kw):
        return {"id": "r", "kind": "responds_within", "within": 3, **kw}

    assert _v([rw(q=ok)]) == ["r: p: not an object"]
    assert _v([rw(p={"verb": ""}, q=ok)]) == ["r: p: bad verb"]
    assert _v([rw(p=ok)]) == ["r: q: not an object"]
    assert _v([rw(p=ok, q={"verb": 5})]) == ["r: q: bad verb"]
    assert _v([rw()]) == ["r: p: not an object"]
    window = "r: within must be an integer in [1, MAX_DEADLINE]"
    assert _v([rw(p=ok, q=ok, within=1)]) == []
    assert _v([rw(p=ok, q=ok, within=1_000_000)]) == []
    assert _v([rw(p=ok, q=ok, within=0)]) == [window]
    assert _v([rw(p=ok, q=ok, within=1_000_001)]) == [window]
    assert _v([rw(p=ok, q=ok, within=True)]) == [window]
    assert _v([rw(p=ok, q=ok, within=2.5)]) == [window]


def test_and_clauses_validate_their_members():
    assert _v([{"id": "n", "kind": "and", "clauses": []}]) == ["n: and.clauses must be a non-empty array"]
    assert _v([{"id": "n", "kind": "and"}]) == ["n: and.clauses must be a non-empty array"]
    assert _v([{"id": "n", "kind": "and", "clauses": [5]}]) == ["clause not an object"]
    assert _v([{"id": "n", "kind": "and", "clauses": [_never("a", "x"), _never("a", "y")]}]) == ["a: duplicate id"]


def test_contract_limits_and_invariants():
    inv = lambda i: {"id": "i%d" % i, "kind": "never", "when": {"verb": "x"}}  # noqa: E731
    assert _v([], invariants=[inv(i) for i in range(256)]) == []
    assert _v([], invariants=[inv(i) for i in range(257)]) == ["too many invariants"]
    assert _v([], invariants=[5]) == ["invariant not an object"]
    assert _v([], invariants=[{"id": "i", "kind": "never"}]) == ["i: when: not an object"]
    assert _v([], invariants=[inv(1), inv(1)]) == ["i1: duplicate id"]
    assert _v([_never("i1", "x")], invariants=[inv(1)]) == ["i1: duplicate id"]
    assert _v([_never("c%d" % i, "x") for i in range(256)]) == []
    assert _v([_never("c%d" % i, "x") for i in range(257)]) == ["too many clauses"]
    assert _v([{"id": "g", "kind": "and", "clauses": [_never("l%d" % i, "x") for i in range(255)]}]) == []
    assert _v([{"id": "g", "kind": "and", "clauses": [_never("l%d" % i, "x") for i in range(256)]}]) == ["too many clauses"]
    assert "too many clauses" in _v([_nest(17)])
    assert "too many clauses" not in _v([_nest(16)])


def test_verify_contract_fails_closed_when_the_commitment_cannot_be_computed(monkeypatch):
    sc = C.sign_contract({"version": 1, "principal": _prin(), "clauses": [_never("a", "x")]}, SEED)
    assert C.verify_contract(sc) == {"ok": True}
    monkeypatch.setattr(C, "contract_id", _boom)
    assert C.verify_contract(sc) == {"ok": False, "reason": "verification error (fail closed)"}


def test_constitution_conversions():
    inv = [{"id": "n", "kind": "never", "when": {"verb": "x"}}]
    assert C.contract_from_constitution({"version": 1, "principal": "pp", "invariants": inv}) == {"version": 1, "principal": "pp", "invariants": inv, "clauses": []}
    assert C.embedded_constitution({"version": 1, "principal": "pp", "invariants": inv}) == {"version": 1, "principal": "pp", "invariants": inv}
    assert C.embedded_constitution({"version": 1, "principal": "pp", "invariants": 5}) == {"version": 1, "principal": "pp", "invariants": []}
    assert C.embedded_constitution({"version": 1, "principal": "pp"}) == {"version": 1, "principal": "pp", "invariants": []}


# ---- per-clause transitions --------------------------------------------------------------------------------------------------------

def _row(id_, kind, result="pass", reason=None):
    r = {"id": id_, "kind": kind, "result": result}
    if reason is not None:
        r["reason"] = reason
    return r


def _ev(cl, verb, deadlines=None, latched=None, now=9):
    state = {"latched": latched or {}}
    if deadlines is not None:
        state["deadlines"] = deadlines
    return C._eval_clause(cl, act(verb), state, now)


def _out(ok, rows, latch=None, deadline=None, reason=None):
    d = {"ok": ok, "rows": rows, "latchSet": latch or {}, "deadlineSet": deadline or {}}
    if reason is not None:
        d["reason"] = reason
    return d


def test_always_and_never_transitions():
    al = {"id": "a", "kind": "always", "p": {"verb": "x"}}
    assert _ev(al, "x") == _out(True, [_row("a", "always")])
    r = "always-invariant violated (action does not satisfy p)"
    assert _ev(al, "y") == _out(False, [_row("a", "always", "violated", r)], reason=r)
    assert _ev({**al, "description": "mine"}, "y") == _out(False, [_row("a", "always", "violated", "mine")], reason="mine")
    nv = _never("n", "x")
    assert _ev(nv, "y") == _out(True, [_row("n", "never")])
    r = "never-invariant violated (forbidden action)"
    assert _ev(nv, "x") == _out(False, [_row("n", "never", "violated", r)], reason=r)
    assert _ev({**nv, "description": "no x"}, "x") == _out(False, [_row("n", "never", "violated", "no x")], reason="no x")
    assert _ev({**nv, "description": ""}, "x") == _out(False, [_row("n", "never", "violated")])


@pytest.mark.parametrize("kind", ["precedes", "requires_prior"])
def test_precedence_transitions(kind):
    cl = {"id": "pc", "kind": kind, "p": {"verb": "p"}, "q": {"verb": "q"}}
    r = "precedence violated (prerequisite p not yet admitted before q)"
    assert _ev(cl, "q") == _out(False, [_row("pc", kind, "violated", r)], reason=r)
    assert _ev({**cl, "description": "need p"}, "q") == _out(False, [_row("pc", kind, "violated", "need p")], reason="need p")
    assert _ev(cl, "q", latched={"pc": 3}) == _out(True, [_row("pc", kind)])
    assert _ev(cl, "p") == _out(True, [_row("pc", kind)], latch={"pc": 9})
    assert _ev(cl, "p", latched={"pc": 3}) == _out(True, [_row("pc", kind)])
    assert _ev(cl, "z") == _out(True, [_row("pc", kind)])


def test_responds_within_transitions():
    cl = {"id": "r", "kind": "responds_within", "p": {"verb": "p"}, "q": {"verb": "q"}, "within": 3}
    row = _row("r", "responds_within")
    assert _ev(cl, "p") == _out(True, [row], deadline={"r": 3})
    assert _ev(cl, "z") == _out(True, [row], deadline={"r": None})
    assert _ev(cl, "z", deadlines={"r": 3}) == _out(True, [row], deadline={"r": 2})
    assert _ev(cl, "p", deadlines={"r": 3}) == _out(True, [row], deadline={"r": 2})
    assert _ev(cl, "p", deadlines={"r": 5}) == _out(True, [row], deadline={"r": 3})
    assert _ev(cl, "q", deadlines={"r": 3}) == _out(True, [row], deadline={"r": None})
    assert _ev(cl, "z", deadlines={"r": 2}) == _out(True, [row], deadline={"r": 1})
    late = "bounded-liveness deadline missed (no q within 3 actions of p)"
    expected = {"ok": False, "reason": late, "rows": [_row("r", "responds_within", "violated", late)], "latchSet": {}, "deadlineSet": {}}
    assert _ev(cl, "z", deadlines={"r": 1}) == expected
    assert _ev(cl, "p", deadlines={"r": 1}) == expected
    mine = {"ok": False, "reason": "late", "rows": [_row("r", "responds_within", "violated", "late")], "latchSet": {}, "deadlineSet": {}}
    assert _ev({**cl, "description": "late"}, "z", deadlines={"r": 1}) == mine


def test_and_transitions():
    ok_a = {"id": "x", "kind": "never", "p": {"verb": "z"}}
    rw = {"id": "r", "kind": "responds_within", "p": {"verb": "pp"}, "q": {"verb": "qq"}, "within": 4}
    pc = {"id": "pc", "kind": "precedes", "p": {"verb": "x"}, "q": {"verb": "y"}}
    both = {"id": "g", "kind": "and", "clauses": [ok_a, pc, rw]}
    assert _ev(both, "x", deadlines={"r": 3}) == _out(
        True, [_row("x", "never"), _row("pc", "precedes"), _row("r", "responds_within")], latch={"pc": 9}, deadline={"r": 2})
    bad = {"id": "g", "kind": "and", "clauses": [_never("n1", "x", description="A"), _never("n2", "x", description="B"), rw]}
    assert _ev(bad, "x", deadlines={"r": 3}) == _out(
        False, [_row("n1", "never", "violated", "A"), _row("n2", "never", "violated", "B"), _row("r", "responds_within")],
        deadline={"r": 2}, reason="A")
    assert _ev({"id": "g", "kind": "and", "clauses": [ok_a, _never("n2", "x", description="B")]}, "x") == _out(
        False, [_row("x", "never"), _row("n2", "never", "violated", "B")], reason="B")


def test_unknown_kinds_and_evaluation_errors_fail_closed():
    why = "unknown clause kind (fail closed)"
    assert C._eval_clause({"id": "u", "kind": "eventually"}, act("x"), {"latched": {}}, 1) == _out(False, [_row("u", "eventually", "violated", why)], reason=why)
    boom = "clause evaluation error (fail closed)"
    assert C._eval_clause({"id": "a", "kind": "always"}, act("x"), {"latched": {}}, 1) == _out(False, [_row("a", "always", "violated", boom)], reason=boom)


# ---- the whole-contract monitor -----------------------------------------------------------------------------------------------------

def test_check_contract_structural_refusals():
    c, s = _contract([_never("n", "x")]), P.empty_state(NOW)
    for bad in (None, [], {}, {"action": {"verb": "x"}}, {"action": {"resource": "/r"}}, {"action": {"verb": 1, "resource": "/r"}}, {"action": {"verb": "x", "resource": 1}}):
        assert C.check_contract(bad, c, s) == _fail("<action>", "malformed action"), bad
    assert C.check_contract(act("x"), {}, s) == _fail("<contract>", "unsupported version undefined")
    assert C.check_contract(act("x"), c, {}) == _fail("<state>", "malformed monitor state")


def test_check_contract_monitor_errors_fail_closed(monkeypatch):
    c, s = _contract([_never("n", "x")]), P.empty_state(NOW)
    monkeypatch.setattr(C, "_eval_clause", _boom)
    assert C.check_contract(act("y"), c, s) == {
        "ok": False, "violated": ["n"], "reasons": ["n: clause evaluation error (fail closed)"],
        "evaluated": [_row("n", "never", "violated", "clause evaluation error (fail closed)")]}
    monkeypatch.undo()
    monkeypatch.setattr(C, "validate_contract", _boom)
    assert C.check_contract(act("y"), c, s) == _fail("<monitor>", "monitor error (fail closed)")


def test_check_contract_reasons_print_like_javascript():
    s = P.empty_state(NOW)

    def reasons(desc):
        r = C.check_contract(act("x"), _contract([_never("n", "x", description=desc)]), s)
        return r["reasons"], r["evaluated"]

    assert reasons("") == (["n: violated"], [_row("n", "never", "violated")])
    assert reasons(0) == (["n: violated"], [_row("n", "never", "violated")])
    assert reasons(5) == (["n: 5"], [_row("n", "never", "violated", 5)])
    assert reasons(["a", 1]) == (["n: a,1"], [_row("n", "never", "violated", ["a", 1])])
    assert reasons(True) == (["n: true"], [_row("n", "never", "violated", True)])


def test_check_contract_evaluates_the_constitution_before_the_clauses():
    inv = [{"id": "i", "kind": "never", "when": {"verb": "x"}, "description": "inv"}]
    r = C.check_contract(act("x"), _contract([_never("c", "x", description="cl")], inv), P.empty_state(NOW))
    assert r == {"ok": False, "violated": ["i", "c"], "reasons": ["i: inv", "c: cl"],
                 "evaluated": [_row("i", "never", "violated", "inv"), _row("c", "never", "violated", "cl")]}


# ---- advance ----------------------------------------------------------------------------------------------------------------------

def _case():
    return _contract([_never("d", "delete")]), P.empty_state(NOW), act("read"), [_row("d", "never")]


def test_stale_heads_are_refused_with_the_verdict_attached():
    c, s, a, rows = _case()
    stale = {"ok": False, "violated": ["<state>"], "reasons": ["<state>: stale state head (seq)"], "evaluated": rows, "next": s, "decidedBy": "state"}
    assert C.advance_contract(s, a, c, {"expectedSeq": 1}) == stale
    assert C.advance_contract(s, a, c, {"expectedSeq": False}) == stale
    assert C.advance_contract(s, a, c, {"expectedSeq": None}) == stale
    assert C.advance_contract(s, a, c, {"expectedSeq": "0"}) == stale
    assert C.advance_contract(s, a, c, {"expectedSeq": 0.0})["ok"] is True
    assert C.advance_contract(s, a, c, {"expectedSeq": 0})["ok"] is True
    one = P.advance_state_strict(a, C.embedded_constitution(c), s)["state"]
    assert C.advance_contract(one, a, c, {"expectedSeq": True})["decidedBy"] == "state"
    assert C.advance_contract(one, a, c, {"expectedSeq": 1})["ok"] is True
    digest = {**stale, "reasons": ["<state>: stale state head (digest)"]}
    assert C.advance_contract(s, a, c, {"expectedStateDigest": "bogus"}) == digest
    assert C.advance_contract(s, a, c, {"expectedStateDigest": P.state_digest(s)})["ok"] is True
    assert C.advance_contract({"seq": 1}, a, c, {"expectedStateDigest": P.state_digest(s)})["decidedBy"] == "state"


def test_a_malformed_state_is_named_once_when_the_head_is_stale():
    c, _, a, _ = _case()
    got = C.advance_contract({"seq": 1}, a, c, {"expectedSeq": 2})
    assert got == {"ok": False, "violated": ["<state>"], "reasons": ["<state>: malformed monitor state", "<state>: stale state head (seq)"],
                   "evaluated": [_row("<state>", "structural", "violated", "malformed monitor state")], "next": {"seq": 1}, "decidedBy": "state"}


def test_decided_by_tells_structural_ids_from_clause_ids():
    s = P.empty_state(NOW)
    for cid in ("<a", "b>", "plain"):
        r = C.advance_contract(s, act("x"), _contract([_never(cid, "x")]), {})
        assert (r["ok"], r["decidedBy"], r["violated"], r["next"]) == (False, "contract", [cid], s), cid
    assert C.advance_contract(s, {}, _contract([_never("n", "x")]), {})["decidedBy"] == "state"
    assert C.advance_contract({}, act("x"), _contract([_never("n", "x")]), {})["decidedBy"] == "state"


def test_advance_failures_keep_the_input_state_and_reuse_the_verdict(monkeypatch):
    c, s, a, rows = _case()
    real, calls = C.check_contract, []

    def fake(action, contract, state):
        r = real(action, contract, state)
        calls.append(1)
        return r if len(calls) == 1 else {**r, "reasons": r["reasons"] + ["recomputed"]}

    monkeypatch.setattr(C, "check_contract", fake)
    got = C.advance_contract(s, a, c, {"now": NOW - 1})
    assert got == {"ok": False, "violated": ["<state>"], "reasons": ["<state>: advance failed: clock regression"], "evaluated": rows, "next": s, "decidedBy": "state"}
    assert len(calls) == 1
    monkeypatch.undo()
    monkeypatch.setattr(C, "advance_state_strict", _boom)
    got = C.advance_contract(s, a, c, {})
    assert got == {"ok": False, "violated": ["<state>"], "reasons": ["<state>: advance error (fail closed)"], "evaluated": rows, "next": s, "decidedBy": "state"}


def test_an_invalid_resulting_state_is_refused(monkeypatch):
    c, s, a, rows = _case()
    real = C.state_problem
    monkeypatch.setattr(C, "state_problem", lambda x: "boom" if isinstance(x, dict) and x.get("seq") == 1 else real(x))
    got = C.advance_contract(s, a, c, {})
    assert got == {"ok": False, "violated": ["<state>"], "reasons": ["<state>: resulting state invalid: boom"], "evaluated": rows, "next": s, "decidedBy": "state"}


def test_advance_carries_latches_and_deadlines():
    s = {**P.empty_state(NOW), "deadlines": {"r": 3, "other": 5}}
    rw = {"id": "r", "kind": "responds_within", "p": {"verb": "p"}, "q": {"verb": "q"}, "within": 3}
    pc = {"id": "pc", "kind": "precedes", "p": {"verb": "p"}, "q": {"verb": "q"}}
    c = _contract([rw, pc])
    r = C.advance_contract(s, act("z"), c, {"now": NOW + 7})
    assert (r["ok"], r["decidedBy"]) == (True, "none")
    assert (r["next"]["seq"], r["next"]["now"], r["next"]["deadlines"], r["next"]["latched"]) == (1, NOW + 7, {"r": 2, "other": 5}, {})
    r = C.advance_contract(s, act("p"), c, {"now": NOW + 7})
    assert (r["next"]["deadlines"], r["next"]["latched"]) == ({"r": 2, "other": 5}, {"pc": NOW + 7})
    r = C.advance_contract({**P.empty_state(NOW), "deadlines": {"r": 3}}, act("q"), _contract([rw]), {})
    assert r["ok"] is True and "deadlines" not in r["next"]
    r = C.advance_contract({**P.empty_state(NOW), "deadlines": {"r": 1}}, act("z"), _contract([rw]), {})
    assert (r["ok"], r["decidedBy"], r["violated"]) == (False, "contract", ["r"])


def test_check_and_advance_contract_outcomes():
    c, s, a, rows = _case()
    allowed = C.check_and_advance_contract(True, s, a, c)
    assert (allowed["ok"], allowed["allow"], allowed["permitted"], allowed["decidedBy"], allowed["next"]["seq"]) == (True, True, True, "none", 1)
    assert C.check_and_advance_contract(False, s, a, c) == {
        "ok": False, "violated": [], "reasons": ["<permission>: not permitted"], "evaluated": rows, "next": s,
        "decidedBy": "contract", "allow": False, "permitted": False}
    assert C.check_and_advance_contract(1, s, a, c)["permitted"] is False
    assert C.check_and_advance_contract("yes", s, a, c)["allow"] is False
    denied = C.check_and_advance_contract(True, s, act("delete"), c)
    r = "never-invariant violated (forbidden action)"
    assert denied == {"ok": False, "violated": ["d"], "reasons": ["d: " + r], "evaluated": [_row("d", "never", "violated", r)], "next": s,
                      "decidedBy": "contract", "allow": False, "permitted": True}
    both = C.check_and_advance_contract(False, s, act("delete"), c)
    assert (both["allow"], both["permitted"], both["violated"], both["decidedBy"]) == (False, False, ["d"], "contract")
    stale = C.check_and_advance_contract(True, s, a, c, {"expectedSeq": 9})
    assert stale == {"ok": False, "violated": ["<state>"], "reasons": ["<state>: stale state head (seq)"], "evaluated": rows, "next": s,
                     "decidedBy": "state", "allow": False, "permitted": True}


# ---- the enforcer ----------------------------------------------------------------------------------------------------------------

def _sc():
    prec = {"id": "review-first", "kind": "precedes", "p": {"verb": "review"}, "q": {"verb": "deploy"}}
    return C.sign_contract({"version": 1, "principal": _prin(), "clauses": [_never("no-delete", "delete"), prec]}, SEED)


def _open(kv, sc=None, wall=None, **kw):
    sc = sc or _sc()
    return CE.ContractEnforcer.open(kv, sc, _prin(), now=(lambda: wall[0]) if wall is not None else (lambda: NOW), **kw), sc


DELETE_REASON = "no-delete: never-invariant violated (forbidden action)"


def test_enforcer_error_messages():
    assert str(CE.ContractEnforcerError("x")) == "ContractEnforcer: x"
    sc = _sc()
    with pytest.raises(CE.ContractEnforcerError) as ei:
        CE.ContractEnforcer.open(MemoryAtomicKv(), sc, _prin(OTHER_SEED))
    assert str(ei.value) == "ContractEnforcer: contract refused: principal mismatch"
    with pytest.raises(CE.ContractEnforcerError) as ei:
        CE.ContractEnforcer.open(MemoryAtomicKv(), sc, None)
    assert str(ei.value) == "ContractEnforcer: a pinned principal is required"
    kv = MemoryAtomicKv()
    e, sc = _open(kv)
    kv.set("contract/" + sc["id"], {"v": 1, "contract_id": "other", "state": P.empty_state(NOW)})
    with pytest.raises(CE.ContractEnforcerError) as ei:
        e.state()
    assert str(ei.value) == "ContractEnforcer: stored state is corrupt or belongs to another contract"


def test_enforcer_stores_one_document_under_the_contract_key_or_the_given_key():
    kv = MemoryAtomicKv()
    e, sc = _open(kv)
    assert e.check(act("review")) == {"allow": True, "reason": "ok", "violated": [], "reasons": [], "seq": 1}
    doc = kv.get("contract/" + sc["id"])
    assert set(doc) == {"v", "contract_id", "state"} and doc["v"] == 1 and doc["contract_id"] == sc["id"] and doc["state"]["seq"] == 1
    kv2 = MemoryAtomicKv()
    e2, sc2 = _open(kv2, key="custom/key")
    e2.check(act("review"))
    assert kv2.get("contract/" + sc2["id"]) is None and kv2.get("custom/key")["state"]["seq"] == 1
    assert e2.state()["state"]["seq"] == 1


def test_enforcer_default_clock_is_wall_time_in_milliseconds():
    kv = MemoryAtomicKv()
    sc = _sc()
    e = CE.ContractEnforcer.open(kv, sc, _prin())
    assert e.check(act("review"))["allow"] is True
    assert abs(kv.get("contract/" + sc["id"])["state"]["now"] - time.time() * 1000) < 3_600_000


def test_enforcer_time_follows_the_clock_but_never_goes_back():
    kv, wall = MemoryAtomicKv(), [NOW]
    e, _ = _open(kv, wall=wall)
    assert e.check(act("review"))["allow"] is True
    wall[0] = NOW + 5_000
    assert e.check(act("deploy"))["allow"] is True
    assert e.state()["state"]["now"] == NOW + 5_000
    wall[0] = NOW + 1_000
    assert e.check(act("review"))["allow"] is True
    assert e.state()["state"]["now"] == NOW + 5_000
    wall[0] = NOW + 9_000
    e.check(act("review"))
    assert e.state()["state"]["now"] == NOW + 9_000


def test_enforcer_outcomes_are_exact():
    kv = MemoryAtomicKv()
    e, sc = _open(kv)
    assert e.check(act("review"), False) == {"allow": False, "reason": "permission", "violated": [], "reasons": ["<permission>: not permitted"], "seq": 0}
    assert e.check(act("review")) == {"allow": True, "reason": "ok", "violated": [], "reasons": [], "seq": 1}
    assert e.check(act("delete")) == {"allow": False, "reason": "violated", "violated": ["no-delete"], "reasons": [DELETE_REASON], "seq": 1}
    assert kv.get("contract/" + sc["id"])["latched"] == {"seq": 1, "violated": ["no-delete"]}
    latched = {"allow": False, "reason": "latched", "violated": ["no-delete"], "reasons": ["<latched>: contract violated at seq 1"], "seq": 1}
    assert e.check(act("review")) == latched
    assert e.peek(act("review")) == latched
    assert e.state()["latched"] is True


def test_enforcer_without_latching_keeps_going():
    kv = MemoryAtomicKv()
    e, sc = _open(kv, latch_on_violation=False)
    assert e.check(act("delete")) == {"allow": False, "reason": "violated", "violated": ["no-delete"], "reasons": [DELETE_REASON], "seq": 0}
    assert "latched" not in kv.get("contract/" + sc["id"]) if kv.get("contract/" + sc["id"]) else True
    e2, _ = _open(MemoryAtomicKv(), latch_on_violation=None)
    e2.check(act("delete"))
    assert e2.check(act("review"))["reason"] == "latched"


def test_enforcer_peek_reads_without_writing():
    kv = MemoryAtomicKv()
    e, sc = _open(kv)
    assert e.peek(act("review")) == {"allow": True, "reason": "ok", "violated": [], "reasons": [], "seq": 0}
    assert e.peek(act("delete")) == {"allow": False, "reason": "violated", "violated": ["no-delete"], "reasons": [DELETE_REASON], "seq": 0}
    e.check(act("review"))
    assert e.peek(act("deploy")) == {"allow": True, "reason": "ok", "violated": [], "reasons": [], "seq": 1}
    assert e.peek(act("delete")) == {"allow": False, "reason": "violated", "violated": ["no-delete"], "reasons": [DELETE_REASON], "seq": 1}
    assert kv.get("contract/" + sc["id"])["state"]["seq"] == 1 and "latched" not in kv.get("contract/" + sc["id"])
    # a state that has not seen the prerequisite: the precedence clause itself refuses
    fresh, _ = _open(MemoryAtomicKv())
    got = fresh.peek(act("deploy"))
    assert (got["allow"], got["reason"], got["violated"], got["seq"]) == (False, "violated", ["review-first"], 0)


def test_enforcer_peek_with_a_non_finite_clock_uses_a_genesis_state():
    e, _ = _open(MemoryAtomicKv(), wall=[float("nan")])
    assert e.peek(act("review")) == {"allow": True, "reason": "ok", "violated": [], "reasons": [], "seq": 0}


def test_enforcer_store_errors_deny():
    class Down(MemoryAtomicKv):
        def update(self, key, fn):
            raise RuntimeError("down")

        def get(self, key):
            raise RuntimeError("down")

    down = {"allow": False, "reason": "store-error", "violated": [], "reasons": ["store error (fail closed)"], "seq": 0}
    e, _ = _open(Down())
    assert e.check(act("review")) == down
    assert e.peek(act("review")) == down
    assert e.reset("x") is False

    class Inert(MemoryAtomicKv):
        def update(self, key, fn):
            return None

    e, _ = _open(Inert())
    assert e.check(act("review")) == {"allow": False, "reason": "store-error", "violated": [], "reasons": ["store unavailable"], "seq": 0}


def test_enforcer_a_non_finite_clock_denies_against_a_stored_state():
    kv, wall = MemoryAtomicKv(), [NOW]
    e, _ = _open(kv, wall=wall)
    e.check(act("review"))
    wall[0] = float("inf")
    assert e.check(act("review")) == {"allow": False, "reason": "state-error", "violated": [], "reasons": ["<state>: clock is not finite"], "seq": 1}
    wall[0] = float("nan")
    assert e.check(act("review"))["reasons"] == ["<state>: clock is not finite"]
    first, _ = _open(MemoryAtomicKv(), wall=[float("nan")])
    got = first.check(act("review"))
    assert (got["allow"], got["reason"], got["violated"], got["seq"]) == (False, "state-error", [], 0)


def test_enforcer_structural_refusals_never_latch(monkeypatch):
    kv = MemoryAtomicKv()
    e, sc = _open(kv)
    e.check(act("review"))
    before = kv.get("contract/" + sc["id"])
    monkeypatch.setattr(CE, "check_and_advance_contract", lambda *a, **k: {
        "ok": False, "allow": False, "decidedBy": "state", "violated": ["<state>"], "reasons": ["<state>: injected"], "evaluated": [], "next": {}})
    assert e.check(act("review")) == {"allow": False, "reason": "state-error", "violated": [], "reasons": ["<state>: injected"], "seq": 1}
    assert kv.get("contract/" + sc["id"]) == before
    monkeypatch.setattr(CE, "check_and_advance_contract", lambda *a, **k: {
        "ok": False, "allow": False, "decidedBy": "contract", "violated": [], "reasons": ["<permission>: not permitted"], "evaluated": [], "next": {}})
    assert e.check(act("review")) == {"allow": False, "reason": "permission", "violated": [], "reasons": ["<permission>: not permitted"], "seq": 1}
    assert kv.get("contract/" + sc["id"]) == before


def test_enforcer_reset_needs_a_sound_document_and_the_signature():
    kv = MemoryAtomicKv()
    e, sc = _open(kv)
    key = "contract/" + sc["id"]
    assert e.reset(CE.sign_contract_reset(SEED, sc["id"], 0)) is False
    e.check(act("review"))
    assert e.reset(CE.sign_contract_reset(SEED, sc["id"], 1)) is False
    e.check(act("delete"))
    sig = CE.sign_contract_reset(SEED, sc["id"], 1)
    assert e.reset(CE.sign_contract_reset(OTHER_SEED, sc["id"], 1)) is False
    assert e.reset(CE.sign_contract_reset(SEED, "other-id", 1)) is False
    assert e.reset(5) is False
    assert "latched" in kv.get(key)
    corrupt = {"v": 1, "contract_id": "other", "state": P.empty_state(NOW), "latched": {"seq": 1, "violated": []}}
    kv.set(key, corrupt)
    assert e.reset(sig) is False
    assert kv.get(key) == corrupt
    kv.set(key, {**corrupt, "contract_id": sc["id"]})
    assert e.reset(sig) is True
    assert "latched" not in kv.get(key)


def test_reset_signature_binds_contract_and_sequence():
    a, b = CE.sign_contract_reset(SEED, "c1", 3), CE.sign_contract_reset(SEED, "c1", 4)
    assert a != b and a != CE.sign_contract_reset(SEED, "c2", 3)
    assert CE._msg("c1", 3) != CE._msg("c1", 4) and CE._msg("c1", 3) != CE._msg("c2", 3)
    assert CE._msg("c1", 3).startswith(b"atlas-pca/contract-reset/v1\0") and len(CE._msg("c1", 3)) == 28 + 32  # 27-character domain plus its NUL


def test_stored_documents_must_carry_the_integer_version():
    kv = MemoryAtomicKv()
    e, sc = _open(kv)
    key = "contract/" + sc["id"]
    good = {"v": 1, "contract_id": sc["id"], "state": P.empty_state(NOW)}
    kv.set(key, good)
    assert e.state() == {"state": P.empty_state(NOW), "latched": False}
    for v in (True, 2, "1", None):
        kv.set(key, {**good, "v": v})
        assert e.check(act("review"))["reason"] == "state-error"
    kv.set(key, {**good, "v": 1.0})
    assert e.state() == {"state": P.empty_state(NOW), "latched": False}


def test_enforcer_peek_reads_the_clock_even_without_a_stored_state():
    def broken():
        raise RuntimeError("clock down")

    e = CE.ContractEnforcer.open(MemoryAtomicKv(), _sc(), _prin(), now=broken)
    assert e.peek(act("review")) == {"allow": False, "reason": "store-error", "violated": [], "reasons": ["store error (fail closed)"], "seq": 0}
    assert e.check(act("review")) == {"allow": False, "reason": "store-error", "violated": [], "reasons": ["store error (fail closed)"], "seq": 0}
