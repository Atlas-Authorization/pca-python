"""Behavioural contracts (port of contracts.test.ts, contracts-fail-closed-table.test.ts, contracts-enforcer.test.ts)."""
import random

from atlas_pca import ed25519
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.contract_enforcer import ContractEnforcer, ContractEnforcerError, sign_contract_reset
from atlas_pca.contracts import (
    CONTRACT_VERSION, MAX_CLAUSE_DEPTH, MAX_CLAUSES, advance_contract, check_and_advance_contract, check_contract, contract_from_constitution,
    contract_id, embedded_constitution, sign_contract, validate_contract, verify_contract,
)
from atlas_pca.pca import b64u, hash_canonical
from atlas_pca.prohibitions import advance_state, advance_state_strict, check_prohibitions, empty_state, state_digest

SEED, OTHER_SEED = b"\x11" * 32, b"\x12" * 32
PRIN, OTHER = b64u(ed25519.public_key(SEED)), b64u(ed25519.public_key(OTHER_SEED))
NOW = 1_700_000_000_000


def act(verb, resource="/r", params=None):
    a = {"action": {"verb": verb, "resource": resource}}
    if params is not None:
        a["action"]["params"] = params
    return a


def contract(clauses, invariants=None):
    return {"version": CONTRACT_VERSION, "principal": PRIN, "invariants": invariants or [], "clauses": clauses}


def run(c, actions):
    state, results, first = empty_state(NOW), [], -1
    for i, a in enumerate(actions):
        r = advance_contract(state, a, c, {"now": state["now"]})
        results.append(r)
        if not r["ok"] and first < 0:
            first = i
        state = r["next"]
    return {"state": state, "results": results, "rejected": first >= 0, "first": first}


NEVER = {"id": "a", "kind": "never", "p": {"verb": "x"}}


def nest(n):
    c = {"id": "leaf", "kind": "never", "p": {"verb": "x"}}
    for i in range(n):
        c = {"id": "and%d" % i, "kind": "and", "clauses": [c]}
    return c


def test_validate_exact_problems():
    base = lambda cl: {"version": 1, "principal": PRIN, "clauses": cl}  # noqa: E731
    rw = lambda w: {"id": "r", "kind": "responds_within", "p": {"verb": "x"}, "q": {"verb": "y"}, "within": w}  # noqa: E731
    cases = [
        (None, "contract not an object"), ({"version": 2, "principal": PRIN}, "unsupported version 2"), ({"version": 1}, "principal missing"),
        ({"version": 1, "principal": PRIN, "clauses": {}}, "clauses not an array"), ({"version": 1, "principal": PRIN, "invariants": 3}, "invariants not an array"),
        (base([5]), "clause not an object"), (base([{"kind": "never", "p": {"verb": "x"}}]), "<no id>: missing clause id"),
        (base([{"id": "u", "kind": "eventually", "p": {"verb": "x"}}]), "u: unknown clause kind eventually"),
        (base([{**NEVER, "id": "__proto__"}]), "__proto__: forbidden id"), (base([{**NEVER, "id": "x" * 129}]), "%s: id too long" % ("x" * 129)),
        (base([NEVER, NEVER]), "a: duplicate id"), (base([rw(0)]), "r: within must be an integer in [1, MAX_DEADLINE]"),
        (base([rw(1.5)]), "r: within must be an integer in [1, MAX_DEADLINE]"), (base([rw(1_000_001)]), "r: within must be an integer in [1, MAX_DEADLINE]"),
        (base([{"id": "n", "kind": "and", "clauses": []}]), "n: and.clauses must be a non-empty array"),
        (base([{"id": "p", "kind": "precedes", "p": {"verb": "x"}}]), "p: q: not an object"),
    ]
    for c, problem in cases:
        assert problem in validate_contract(c), (c, validate_contract(c))
    assert "too many clauses" in validate_contract(base([{"id": "c%d" % i, "kind": "never", "p": {"verb": "x"}} for i in range(MAX_CLAUSES + 1)]))
    assert validate_contract(base([nest(MAX_CLAUSE_DEPTH - 2)])) == []
    assert any("too deep" in p for p in validate_contract(base([nest(MAX_CLAUSE_DEPTH + 2)])))
    assert len(validate_contract(base([nest(20_000)]))) > 0
    bad = contract([{"id": "dup", "kind": "never", "p": {"verb": "a"}}], [{"id": "dup", "kind": "never", "when": {"verb": "b"}}])
    assert "dup: duplicate id" in validate_contract(bad)


def test_verify_exact_outcomes():
    sc = sign_contract(contract([NEVER]), SEED)
    assert sc["id"] == contract_id(contract([NEVER]))
    assert verify_contract(sc, PRIN) == {"ok": True} and verify_contract(sc) == {"ok": True}
    assert verify_contract(sc, OTHER) == {"ok": False, "reason": "principal mismatch"}
    assert verify_contract({**sc, "clauses": [{"id": "a", "kind": "never", "p": {"verb": "y"}}]}) == {"ok": False, "reason": "id does not match content"}
    other = sign_contract(contract([NEVER]), OTHER_SEED)
    assert verify_contract({**sc, "sig": other["sig"]}) == {"ok": False, "reason": "bad signature"}
    assert verify_contract({**sc, "sig": None}) == {"ok": False, "reason": "bad signature"}
    assert verify_contract(None)["ok"] is False
    try:
        sign_contract(contract([{"id": "x"}]), SEED)
        raise AssertionError("signed")
    except TypeError:
        pass


def test_always():
    c = contract([{"id": "only-safe", "kind": "always", "p": {"verb": "*", "resource": "/safe/*"}}])
    assert run(c, [act("read", "/safe/a"), act("write", "/safe/b")])["rejected"] is False
    r = run(c, [act("read", "/safe/a"), act("read", "/prod/x")])
    assert (r["first"], r["results"][1]["violated"], r["results"][1]["reasons"]) == (1, ["only-safe"], ["only-safe: always-invariant violated (action does not satisfy p)"])
    cc = contract([{"id": "need", "kind": "always", "p": {"verb": "*", "where": [{"field": "action.params.ok", "op": "eq", "value": True}]}}])
    assert run(cc, [act("read")])["rejected"] is True and run(cc, [act("read", "/r", {"ok": True})])["rejected"] is False


def test_never():
    c = contract([{"id": "no-delete", "kind": "never", "p": {"verb": "delete", "resource": "*"}}])
    assert run(c, [act("read"), act("write")])["rejected"] is False
    assert run(c, [act("read"), act("delete", "/x")])["results"][1]["violated"] == ["no-delete"]
    bad = contract([{"id": "bad-re", "kind": "never", "p": {"verb": "x", "resource": "re:(a+)+"}}])
    assert validate_contract(bad) and run(bad, [act("x", "/anything")])["rejected"] is True


def test_precedes_and_requires_prior():
    pre = contract([{"id": "r", "kind": "precedes", "p": {"verb": "review"}, "q": {"verb": "deploy"}}])
    req = contract([{"id": "r", "kind": "requires_prior", "q": {"verb": "deploy"}, "p": {"verb": "review"}}])
    for c in (pre, req):
        assert run(c, [act("review"), act("deploy")])["rejected"] is False
    r = run(pre, [act("deploy")])
    assert r["results"][0]["violated"] == ["r"] and r["results"][0]["reasons"] == ["r: precedence violated (prerequisite p not yet admitted before q)"]
    trace = [act("deploy"), act("review"), act("deploy")]
    assert [x["ok"] for x in run(pre, trace)["results"]] == [x["ok"] for x in run(req, trace)["results"]] == [False, True, True]
    self_ = contract([{"id": "x", "kind": "precedes", "p": {"verb": "open"}, "q": {"verb": "open"}}])
    assert [x["ok"] for x in run(self_, [act("open"), act("open")])["results"]] == [False, False]
    assert run(contract([{"id": "y", "kind": "precedes", "p": {"verb": "prep"}, "q": {"verb": "open"}}]), [act("prep"), act("open")])["rejected"] is False


def test_responds_within():
    c = contract([{"id": "ack", "kind": "responds_within", "p": {"verb": "request"}, "q": {"verb": "ack"}, "within": 2}])
    assert run(c, [act("request"), act("ack")])["rejected"] is False
    assert run(c, [act("request"), act("noise"), act("ack")])["rejected"] is False
    r = run(c, [act("request"), act("noise"), act("noise"), act("ack")])
    assert (r["first"], r["results"][2]["violated"]) == (2, ["ack"])
    assert r["results"][2]["reasons"] == ["ack: bounded-liveness deadline missed (no q within 2 actions of p)"]
    assert run(c, [act("request")])["rejected"] is False and run(c, [act("request"), act("noise")])["rejected"] is False
    assert run(c, [act("request"), act("request"), act("ack")])["rejected"] is False
    c1 = contract([{"id": "ack", "kind": "responds_within", "p": {"verb": "request"}, "q": {"verb": "ack"}, "within": 1}])
    assert run(c1, [act("request"), act("ack")])["rejected"] is False and run(c1, [act("request"), act("noise")])["rejected"] is True
    assert run(c, [act("ack"), act("request"), act("noise"), act("noise")])["rejected"] is True
    st = advance_contract(empty_state(NOW), act("request"), c)["next"]
    assert st["deadlines"] == {"ack": 2}


def test_and():
    c = contract([{"id": "both", "kind": "and", "clauses": [{"id": "no-delete", "kind": "never", "p": {"verb": "delete"}},
                                                           {"id": "review-first", "kind": "precedes", "p": {"verb": "review"}, "q": {"verb": "deploy"}}]}])
    assert run(c, [act("review"), act("deploy")])["rejected"] is False
    assert run(c, [act("delete")])["results"][0]["violated"] == ["no-delete"]
    assert run(c, [act("deploy")])["results"][0]["violated"] == ["review-first"]


SPEND = {"id": "spend", "kind": "cap", "when": {"verb": "pay"}, "amount": "action.params.usd", "max": 100, "window_secs": 86_400}
LOCK = {"id": "lock", "kind": "never_after", "after": {"verb": "read", "resource": "/s/*"}, "forbid": {"verb": "send"}}


def test_degenerate_contract_is_the_prohibition_monitor():
    cons = {"version": 1, "principal": PRIN, "invariants": [SPEND, LOCK]}
    deg = contract_from_constitution(cons)
    assert embedded_constitution(deg)["invariants"] == [SPEND, LOCK]
    cs = ps = empty_state(NOW)
    for a in [act("pay", "/v", {"usd": 40}), act("read", "/s/x"), act("send", "/y"), act("pay", "/v", {"usd": 80})]:
        pr = check_prohibitions(a, cons, ps)
        cr = advance_contract(cs, a, deg, {"now": cs["now"]})
        assert cr["ok"] is pr["ok"] and cr["violated"] == pr["violated"]
        if pr["ok"]:
            adv = advance_state_strict(a, cons, ps)
            assert cr["next"] == adv["state"] and state_digest(cr["next"]) == state_digest(adv["state"])
            ps, cs = adv["state"], cr["next"]
        else:
            assert cr["next"] == cs
            ps = advance_state(a, cons, ps)
    assert "deadlines" not in advance_contract(empty_state(NOW), act("pay", "/v", {"usd": 10}), deg)["next"]


def test_constitution_and_clauses_both_veto():
    c = contract([{"id": "ack", "kind": "responds_within", "p": {"verb": "open"}, "q": {"verb": "close"}, "within": 2}], [SPEND, LOCK])
    assert run(c, [act("pay", "/v", {"usd": 200})])["results"][0]["violated"] == ["spend"]
    assert run(c, [act("open"), act("x"), act("y")])["results"][2]["violated"] == ["ack"]
    assert [e["id"] for e in check_contract(act("read", "/z"), c, empty_state(NOW))["evaluated"]] == ["spend", "lock", "ack"]


def test_stale_forged_and_replayed_state():
    c = contract([{"id": "order", "kind": "precedes", "p": {"verb": "review"}, "q": {"verb": "deploy"}}])
    s1 = advance_contract(empty_state(NOW), act("review"), c)
    assert s1["ok"] and s1["next"]["seq"] == 1 and s1["next"]["parent"] is not None
    r = advance_contract(empty_state(NOW), act("review"), c, {"expectedSeq": 1})
    assert (r["ok"], r["decidedBy"], r["violated"], r["reasons"]) == (False, "state", ["<state>"], ["<state>: stale state head (seq)"])
    assert r["next"] == empty_state(NOW)
    r = advance_contract(s1["next"], act("deploy"), c, {"expectedStateDigest": state_digest(empty_state(NOW))})
    assert (r["ok"], r["decidedBy"], r["reasons"]) == (False, "state", ["<state>: stale state head (digest)"])
    for patch in ({"seq": -1}, {"seq": 3, "parent": None}, {"seq": 0, "parent": "x"}, {"now": float("inf")}, {"ledger": 5}):
        forged = {**empty_state(NOW), **patch}
        r = advance_contract(forged, act("review"), c)
        assert r["ok"] is False and r["next"] is forged
    r = advance_contract(empty_state(NOW), act("deploy"), c)
    assert (r["decidedBy"], r["violated"]) == ("contract", ["order"])
    assert advance_contract(s1["next"], act("deploy"), c, {"now": NOW - 1})["ok"] is False
    bad = contract([{"id": "u", "kind": "eventually", "p": {"verb": "x"}}])
    assert check_contract(act("read"), bad, empty_state(NOW))["ok"] is False and advance_contract(empty_state(NOW), act("read"), bad)["ok"] is False
    ok = advance_contract(s1["next"], act("deploy"), c, {"expectedSeq": 1, "expectedStateDigest": state_digest(s1["next"])})
    assert ok["ok"] and ok["next"]["seq"] == 2


def test_check_and_advance_contract():
    c = contract([{"id": "no-del", "kind": "never", "p": {"verb": "delete"}}])
    ok = check_and_advance_contract(True, empty_state(NOW), act("read"), c, {"now": NOW})
    assert ok["allow"] is True and ok["next"]["seq"] == 1
    no = check_and_advance_contract(False, empty_state(NOW), act("read"), c, {"now": NOW})
    assert (no["allow"], no["reasons"], no["decidedBy"], no["next"]) == (False, ["<permission>: not permitted"], "contract", empty_state(NOW))
    v = check_and_advance_contract(True, empty_state(NOW), act("delete"), c, {"now": NOW})
    assert v["allow"] is False and "no-del" in v["violated"]


def test_totality():
    c = contract([{"id": "a", "kind": "never", "p": {"verb": "delete"}}])
    assert advance_contract(empty_state(NOW), {"action": {"verb": 1}}, c)["ok"] is False
    assert advance_contract({"now": float("nan")}, act("read"), c)["ok"] is False
    assert advance_contract(empty_state(NOW), act("read"), {"version": 2, "principal": PRIN, "clauses": []})["ok"] is False
    assert check_contract(act("read"), None, empty_state(NOW))["ok"] is False
    r = advance_contract(empty_state(NOW), {"action": {}}, c)
    assert r["next"] == empty_state(NOW) and r["decidedBy"] == "state"


def _rng(seed):
    return random.Random(seed)


_VERBS = ["read", "write", "pay", "deploy", "delete", "review", "ack", "request", "send", "open", "close"]


def test_property_never_rejects_iff_some_action_matches():
    for seed in range(1, 120):
        r = _rng(seed)
        v = r.choice(_VERBS)
        trace = [act(r.choice(_VERBS)) for _ in range(7)]
        assert run(contract([{"id": "n", "kind": "never", "p": {"verb": v}}]), trace)["rejected"] is any(a["action"]["verb"] == v for a in trace)


def test_property_responds_within_matches_oracle():
    def oracle(trace, n):
        for i, a in enumerate(trace):
            if a["action"]["verb"] != "request" or i + n > len(trace) - 1:
                continue
            if not any(trace[j]["action"]["verb"] == "ack" for j in range(i + 1, i + n + 1)):
                return True
        return False

    for seed in range(1, 200):
        r = _rng(seed)
        n = r.randint(1, 3)
        c = contract([{"id": "ack", "kind": "responds_within", "p": {"verb": "request"}, "q": {"verb": "ack"}, "within": n}])
        trace = [act(r.choice(["request", "ack", "noise", "noise"])) for _ in range(r.randint(2, 8))]
        assert run(c, trace)["rejected"] is oracle(trace, n), (seed, trace)


def test_property_chain_is_monotonic_and_history_binding():
    for seed in range(1, 60):
        r = _rng(seed + 10_000)
        c = contract([{"id": "c0", "kind": "responds_within", "p": {"verb": r.choice(_VERBS)}, "q": {"verb": r.choice(_VERBS)}, "within": r.randint(1, 4)},
                      {"id": "c1", "kind": "precedes", "p": {"verb": r.choice(_VERBS)}, "q": {"verb": r.choice(_VERBS)}}])
        prev, digests = empty_state(NOW), {state_digest(empty_state(NOW))}
        for _ in range(8):
            a = act(r.choice(_VERBS))
            res = advance_contract(prev, a, c, {"now": prev["now"]})
            if res["ok"]:
                assert res["next"]["seq"] == prev["seq"] + 1
                assert res["next"]["parent"] == hash_canonical({"d": "atlas-pca/monitor-state-link/v1", "state": state_digest(prev), "action": hash_canonical(a)})
                d = state_digest(res["next"])
                assert d not in digests
                digests.add(d)
                prev = res["next"]
            else:
                assert res["next"] == prev


# ---- the enforcer ---------------------------------------------------------------------------------------------------------------

_CLAUSES = [{"id": "no-delete", "kind": "never", "p": {"verb": "delete"}}, {"id": "review-first", "kind": "precedes", "p": {"verb": "review"}, "q": {"verb": "deploy"}}]
SC = sign_contract({"version": CONTRACT_VERSION, "principal": PRIN, "clauses": _CLAUSES}, SEED)


def _open(kv, **extra):
    return ContractEnforcer.open(kv, SC, PRIN, now=lambda: 1_700_000_000_000, **extra)


def _raises(fn, msg):
    try:
        fn()
    except ContractEnforcerError as e:
        assert msg in str(e)
        return
    raise AssertionError("did not raise")


def test_enforcer_open_pins_the_principal():
    _raises(lambda: ContractEnforcer.open(MemoryAtomicKv(), SC, OTHER), "contract refused: principal mismatch")
    _raises(lambda: ContractEnforcer.open(MemoryAtomicKv(), {**SC, "clauses": []}, PRIN), "contract refused: id does not match content")
    _raises(lambda: ContractEnforcer.open(MemoryAtomicKv(), SC, ""), "a pinned principal is required")
    _raises(lambda: ContractEnforcer.open(MemoryAtomicKv(), SC, None), "ContractEnforcer: a pinned principal is required")


def test_enforcer_check_outcomes():
    e = _open(MemoryAtomicKv())
    assert e.check(act("review")) == {"allow": True, "reason": "ok", "violated": [], "reasons": [], "seq": 1}
    assert e.check(act("deploy"))["seq"] == 2
    e = _open(MemoryAtomicKv())
    r = e.check(act("review"), False)
    assert (r["allow"], r["reason"], r["violated"], r["reasons"], r["seq"]) == (False, "permission", [], ["<permission>: not permitted"], 0)
    assert e.check(act("review"))["seq"] == 1
    e = _open(MemoryAtomicKv())
    assert e.check(act("deploy"))["reason"] == "violated"
    latched = e.check(act("review"))
    assert (latched["reason"], latched["violated"], latched["reasons"]) == ("latched", ["review-first"], ["<latched>: contract violated at seq 0"])
    assert e.state()["latched"] is True
    e = _open(MemoryAtomicKv(), latch_on_violation=False)
    assert e.check(act("delete"))["reason"] == "violated" and e.check(act("review"))["allow"] is True


def test_enforcer_reset_needs_the_principal_signature_at_the_latched_seq():
    e = _open(MemoryAtomicKv())
    e.check(act("review"))
    e.check(act("delete"))
    assert e.reset(sign_contract_reset(OTHER_SEED, SC["id"], 1)) is False
    assert e.reset(sign_contract_reset(SEED, SC["id"], 0)) is False
    assert e.reset(None) is False
    assert e.check(act("review"))["reason"] == "latched"
    assert e.reset(sign_contract_reset(SEED, SC["id"], 1)) is True
    assert e.reset(sign_contract_reset(SEED, SC["id"], 1)) is False
    assert e.check(act("deploy"))["allow"] is True


def test_enforcer_fail_closed():
    kv = MemoryAtomicKv()
    e = _open(kv)
    e.check(act("review"))
    key = "contract/" + SC["id"]
    kv.set(key, {"v": 1, "contract_id": SC["id"], "state": {"now": "x"}})
    r = e.check(act("review"))
    assert (r["allow"], r["reason"], r["seq"]) == (False, "state-error", 0)
    assert e.peek(act("review"))["reason"] == "state-error"
    _raises(e.state, "stored state is corrupt")
    kv.set(key, {"v": 1, "contract_id": "other", "state": {"now": NOW, "seq": 0, "parent": None, "ledger": {}, "latched": {}}})
    assert e.check(act("review"))["reason"] == "state-error"

    class Down(MemoryAtomicKv):
        def update(self, key, fn):
            raise RuntimeError("down")

        def get(self, key):
            raise RuntimeError("down")

    d = _open(Down())
    assert d.check(act("review")) == {"allow": False, "reason": "store-error", "violated": [], "reasons": ["store error (fail closed)"], "seq": 0}
    assert d.peek(act("review"))["reason"] == "store-error"
    assert d.reset("x") is False


def test_enforcer_latched_seq_must_be_an_integer():
    kv = MemoryAtomicKv()
    e = _open(kv)
    e.check(act("review"))
    e.check(act("delete"))
    key = "contract/" + SC["id"]
    doc = kv.get(key)
    kv.set(key, {**doc, "latched": {**doc["latched"], "seq": 0}})
    assert e.state()["latched"] is True
    kv.set(key, {**doc, "latched": {**doc["latched"], "seq": -0.0}})
    _raises(e.state, "corrupt")
    kv.set(key, {**doc, "latched": {**doc["latched"], "seq": 1.5}})
    _raises(e.state, "corrupt")


def test_enforcer_clock_never_goes_back_and_a_bad_clock_denies():
    kv, wall = MemoryAtomicKv(), [1_700_000_005_000]
    e = ContractEnforcer.open(kv, SC, PRIN, now=lambda: wall[0])
    assert e.check(act("review"))["allow"] is True
    wall[0] = 1_700_000_000_000
    assert e.check(act("deploy"))["allow"] is True and e.state()["state"]["now"] == 1_700_000_005_000
    wall[0] = float("nan")
    r = e.check(act("review"))
    assert (r["reason"], r["reasons"], r["seq"]) == ("state-error", ["<state>: clock is not finite"], 2)


def test_enforcer_peek_is_read_only():
    e = _open(MemoryAtomicKv())
    assert e.peek(act("delete"))["reason"] == "violated" and e.state() is None
    assert e.peek(act("review")) == {"allow": True, "reason": "ok", "violated": [], "reasons": [], "seq": 0} and e.state() is None
    e.check(act("delete"))
    assert e.peek(act("review"))["reason"] == "latched"


def test_enforcer_two_enforcers_on_one_store_serialise():
    kv = MemoryAtomicKv()
    a, b = _open(kv), _open(kv)
    seqs = sorted(x.check(act("review"))["seq"] for x in (a, b, a, b))
    assert seqs == [1, 2, 3, 4]


def test_non_ascii_contract_ids_texts_and_digests_match_the_reference():
    # expected values come from running the TypeScript reference on the same inputs
    p = "príncipe-ключ-\U0001f642"
    inv = {"id": "ünï-cap", "kind": "cap", "when": {"verb": "pay"}, "amount": "action.params.usd", "max": 100, "window_secs": 60, "description": "dépense \U0001f642"}
    k = {"version": 1, "principal": p, "invariants": [inv], "clauses": [
        {"id": "précède", "kind": "precedes", "p": {"verb": "rév"}, "q": {"verb": "dép"}, "description": "d\U0001f642"},
        {"id": "rép", "kind": "responds_within", "p": {"verb": "rq"}, "q": {"verb": "ack"}, "within": 1},
        {"id": "tj", "kind": "always", "p": {"verb": "ok"}}, {"id": "ün", "kind": "never", "p": {"verb": "del"}}]}
    assert contract_id(k) == "qVXoMbrwtQgpeUK9-YRTuBiQa4BWu-LQK8fZWk95dC0"
    assert validate_contract({**k, "clauses": k["clauses"] + [{"id": "é" * 129, "kind": "never", "p": {"verb": "x"}}, {"id": "u", "kind": "\U0001f642"}]}) == [
        "%s: id too long" % ("é" * 129), "u: unknown clause kind \U0001f642"]
    s = empty_state(NOW)
    mk = lambda v: act(v, "/é", {})  # noqa: E731
    assert check_contract(mk("dép"), k, s)["reasons"] == ["précède: d\U0001f642", "tj: always-invariant violated (action does not satisfy p)"]
    assert check_contract(mk("del"), k, s)["reasons"] == ["tj: always-invariant violated (action does not satisfy p)", "ün: never-invariant violated (forbidden action)"]
    r = advance_contract(s, mk("zzz"), k)
    assert state_digest(r["next"]) == "-_g0nao5WBkqQu9GGWYpMruHYA0f6inO__C71LsoDXM" and r["violated"] == ["tj"]


def test_enforcer_concurrent_threads_on_one_store_each_get_a_distinct_sequence():
    import threading

    kv = MemoryAtomicKv()
    es = [_open(kv) for _ in range(4)]
    out, errors = [], []

    def worker(e):
        try:
            for _ in range(25):
                out.append(e.check(act("review")))
        except Exception as x:  # noqa: BLE001
            errors.append(x)

    ts = [threading.Thread(target=worker, args=(e,)) for e in es]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert errors == [] and all(r["allow"] for r in out)
    assert sorted(r["seq"] for r in out) == list(range(1, 101))
    assert es[0].state()["state"]["seq"] == 100


def test_enforcer_state_and_latch_survive_a_restart_on_a_sqlite_file():
    import os
    import tempfile

    from atlas_pca.atomic_kv import SqliteAtomicKv

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "contract.sqlite")
        stores = []

        def store():
            stores.append(SqliteAtomicKv(path))
            return stores[-1]

        try:
            e1 = _open(store())
            assert e1.check(act("review"))["seq"] == 1
            assert e1.check(act("delete"))["reason"] == "violated"
            e2 = _open(store())  # a new store object on the same file: a restart
            assert e2.state()["state"]["seq"] == 1 and e2.state()["latched"] is True
            r = e2.check(act("review"))
            assert (r["allow"], r["reason"]) == (False, "latched")
            assert e2.reset(sign_contract_reset(SEED, SC["id"], 1)) is True
            assert _open(store()).check(act("deploy"))["allow"] is True
        finally:
            for st in stores:  # an open handle blocks removing the file on Windows
                st.close()
