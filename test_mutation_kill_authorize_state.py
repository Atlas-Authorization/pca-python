"""State stores (memory and SQLite), the store-capability check and the configuration refusals / option plumbing / claim retries of authorize()."""
import importlib
import sqlite3
import types

import pytest

A = importlib.import_module("atlas_pca.authorize")
CR = A.ClaimResult
NAN = float("nan")


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        yield A.MemoryStateStore()
        return
    s = A.SqliteStateStore(str(tmp_path / "state.db"))
    yield s
    s.close()


# ---- claim_budget -------------------------------------------------------------------------------------------------------------------

def test_claim_budget_replay_conflict_and_success_exact(store):
    assert store.claim_budget("k", 5, None, {"B": 1}) == CR(True, None, None)
    assert store.last("k") == 5
    assert store.budget("k") == {"B": 1}
    # the same counter is a replay (not strictly greater), reported with the stored counter
    assert store.claim_budget("k", 5, {"B": 1}, {"B": 2}) == CR(False, 5, "replay")
    # a replay wins over a budget conflict
    assert store.claim_budget("k", 4, None, None) == CR(False, 5, "replay")
    # a newer counter with a stale budget is a conflict and changes nothing
    assert store.claim_budget("k", 6, {"B": 9}, {"B": 2}) == CR(False, None, "conflict")
    assert store.claim_budget("k", 6, None, {"B": 2}) == CR(False, None, "conflict")
    assert store.last("k") == 5
    assert store.budget("k") == {"B": 1}
    # budget_after None keeps the stored budget
    assert store.claim_budget("k", 6, {"B": 1}, None) == CR(True, None, None)
    assert store.last("k") == 6
    assert store.budget("k") == {"B": 1}
    assert store.claim_budget("k", 7, {"B": 1}, {"B": 0.5, "tau": 3}) == CR(True, None, None)
    assert store.budget("k") == {"B": 0.5, "tau": 3}
    # a key never seen: both absent counts as equal
    assert store.claim_budget("other", 1, None, None) == CR(True, None, None)
    assert store.budget("other") is None


def test_claim_result_fields():
    r = CR(False, 3, "replay")
    assert (r.ok, r.last_counter, r.reason) == (False, 3, "replay")
    assert CR(True) == CR(True, None, None)


@pytest.mark.parametrize("key,counter", [(1, 1), (None, 1), ("k", True), ("k", "1"), ("k", 1.0), ("k", None)])
def test_sqlite_claim_and_claim_budget_refuse_malformed_arguments(tmp_path, key, counter):
    s = A.SqliteStateStore(str(tmp_path / "bad.db"))
    try:
        assert s.claim_budget(key, counter, None, {"B": 1}) == CR(False, None, None)
        assert s.claim(key, counter) == CR(False, None, None)
        assert s.last("k") is None and s.budget("k") is None
        assert s.claim_budget("k", 1, None, {"B": 1}) == CR(True, None, None)  # the connection is left usable
    finally:
        s.close()


def test_sqlite_budget_json_is_compact_and_a_non_finite_budget_is_refused(tmp_path):
    path = str(tmp_path / "json.db")
    s = A.SqliteStateStore(path)
    try:
        s.put_budget("k", {"B": 1, "tau": 0})
        assert s.budget("k") == {"B": 1, "tau": 0}
        with pytest.raises(ValueError):
            s.put_budget("k2", {"B": NAN})
        assert s.budget("k2") is None
        assert s.claim_budget("c", 1, None, {"B": 2, "tau": 1}) == CR(True, None, None)
        with pytest.raises(ValueError):
            s.claim_budget("c", 2, {"B": 2, "tau": 1}, {"B": NAN})
        # the failed claim rolled back: nothing changed and the same connection can claim again
        assert s.last("c") == 1 and s.budget("c") == {"B": 2, "tau": 1}
        assert s.claim_budget("c", 2, {"B": 2, "tau": 1}, None) == CR(True, None, None)
        raw = sqlite3.connect(path)
        try:
            assert raw.execute("SELECT budget FROM pca_budget WHERE key = 'k'").fetchone() == ('{"B":1,"tau":0}',)
            assert raw.execute("SELECT budget FROM pca_budget WHERE key = 'c'").fetchone() == ('{"B":2,"tau":1}',)
        finally:
            raw.close()
    finally:
        s.close()


# ---- pins, claim, last ---------------------------------------------------------------------------------------------------------------

def test_pin_is_monotone_and_validated(store):
    assert store.pin("g") is None
    store.raise_pin("g", 5)
    assert store.pin("g") == 5
    store.raise_pin("g", 3)
    assert store.pin("g") == 5
    store.raise_pin("g", 5)
    assert store.pin("g") == 5
    store.raise_pin("g", 9)
    assert store.pin("g") == 9
    store.raise_pin("neg", -4)
    assert store.pin("neg") == -4
    store.raise_pin("neg", -6)
    assert store.pin("neg") == -4
    for key, value in (("", 1), ("g", True), ("g", "1"), (None, 1)):
        with pytest.raises(ValueError):
            store.raise_pin(key, value)
    assert store.pin("g") == 9


def test_claim_is_strictly_increasing(store):
    assert store.claim("k", 1) == CR(True, None, None)
    assert store.claim("k", 1) == CR(False, 1, None)
    assert store.claim("k", 0) == CR(False, 1, None)
    assert store.claim("k", 2) == CR(True, None, None)
    assert store.last("k") == 2
    assert store.last("none") is None


# ---- missing_authorize_components ---------------------------------------------------------------------------------------------------

def _obj(**names):
    return types.SimpleNamespace(**{k: (lambda *a, **kw: None) for k in names})


_BASE = dict(audience="aud", resolve_grant=lambda g: None, is_revoked=lambda *a: False)
_BUDGET_MSG = "state_store.claim_budget (the trust budget is decided and debited with the replay claim)"


def test_missing_components_needs_both_budget_and_claim_budget():
    assert A.missing_authorize_components(state_store=_obj(claim=1, budget=1, claim_budget=1), **_BASE) == []
    assert A.missing_authorize_components(state_store=_obj(claim=1), **_BASE) == [_BUDGET_MSG]
    assert A.missing_authorize_components(state_store=_obj(claim=1, budget=1), **_BASE) == [_BUDGET_MSG]
    assert A.missing_authorize_components(state_store=_obj(claim=1, claim_budget=1), **_BASE) == [_BUDGET_MSG]
    assert A.missing_authorize_components(state_store=None, **_BASE) == ["state_store"]
    assert A.missing_authorize_components(state_store=_obj(budget=1, claim_budget=1), **_BASE) == ["state_store"]


# ---- authorize(): configuration refusals, option plumbing, claim retries -----------------------------------------------------------

def _ok():
    return A.AuthorizeResult(allow=True, status=200, checks={}, reasons=[], assurance={"x": {"outcome": "pass"}}, decision="allow")


@pytest.fixture
def spy(monkeypatch):
    calls = []

    def fake(*a, **kw):
        calls.append((a, kw))
        return _ok()

    monkeypatch.setattr(A, "_authorize", fake)
    return calls


def call(**kw):
    args = dict(operation={"verb": "v", "resource": "r", "params": {}}, audience="aud", resolve_grant=lambda g: None,
                state_store=_obj(claim=1, budget=1, claim_budget=1, last=1), is_revoked=lambda *a: False)
    args.update(kw)
    return A.authorize(None, **args)


def assert_refused(res, check, reason, missing):
    assert res.allow is False
    assert res.status == 403
    assert res.checks == {check: "fail"}
    assert res.reasons == [reason] and res.reason == reason
    assert res.missing == missing
    assert res.assurance == {check: {"outcome": "fail"}}


def test_multi_instance_refuses_a_process_scoped_store_only(spy):
    res = call(multi_instance=True, state_store=A.MemoryStateStore())
    assert_refused(res, "authorize_config", "authorize_config: " + A.MULTI_INSTANCE_ERROR, ["state_store"])
    assert spy == []
    shared = _obj(claim=1, budget=1, claim_budget=1)
    shared.scope = "shared"
    assert call(multi_instance=True, state_store=shared).allow is True
    assert call(multi_instance=True, state_store=_obj(claim=1, budget=1, claim_budget=1)).allow is True  # no declared scope
    assert call(multi_instance=None, state_store=A.MemoryStateStore()).allow is True
    assert call(multi_instance=False, state_store=A.MemoryStateStore()).allow is True
    assert len(spy) == 4


def test_pin_capabilities_are_required_for_revocation_staleness(spy):
    both = _obj(claim=1, budget=1, claim_budget=1, pin=1, raise_pin=1)
    only_pin = _obj(claim=1, budget=1, claim_budget=1, pin=1)
    only_raise = _obj(claim=1, budget=1, claim_budget=1, raise_pin=1)
    for st in (only_pin, only_raise, _obj(claim=1, budget=1, claim_budget=1)):
        assert_refused(call(revocation_staleness=object(), state_store=st), "authorize_config",
                       "authorize_config: " + A.PIN_STORE_ERROR, ["state_store"])
    assert spy == []
    assert call(revocation_staleness=object(), state_store=both).allow is True
    assert call(revocation_staleness=object(), state_store=None).allow is True  # no store: the guard reports it as missing
    assert len(spy) == 2


def test_beacon_needs_a_store_with_pins(spy):
    both = _obj(claim=1, budget=1, claim_budget=1, pin=1, raise_pin=1)
    only_pin = _obj(claim=1, budget=1, claim_budget=1, pin=1)
    only_raise = _obj(claim=1, budget=1, claim_budget=1, raise_pin=1)
    msg = "authorize_config: beacon needs a state store that implements pins (replay protection)"
    for st in (only_pin, only_raise, _obj(claim=1, budget=1, claim_budget=1)):
        assert_refused(call(beacon=lambda *a: None, state_store=st), "authorize_config", msg, ["state_store"])
    assert spy == []
    assert call(beacon=lambda *a: None, state_store=both).allow is True
    assert call(beacon=lambda *a: None, state_store=None).allow is True
    assert len(spy) == 2


def test_passport_gate_receives_the_clock_and_its_refusal_is_returned(spy, monkeypatch):
    seen = []
    refusal = A._refuse(403, "passport", "passport: nope")

    def fake_gate(pcactn, rp, passport, now):
        seen.append((pcactn, rp, passport, now))
        return refusal if rp.get("deny") else None

    monkeypatch.setattr(A, "_passport_refusal", fake_gate)
    pc = {"cap_chain": [{"holder": "root"}, {"holder": "leaf"}]}
    verified = {"pc": pc}

    def guard(*a, **kw):
        spy.append((a, kw))
        r = _ok()
        r.pcactn = verified["pc"]
        return r

    monkeypatch.setattr(A, "_authorize", guard)
    res = A.authorize(pc, operation={"verb": "v", "resource": "r", "params": {}}, audience="aud", resolve_grant=lambda g: None,
                      state_store=_obj(claim=1, budget=1, claim_budget=1), is_revoked=lambda *a: False,
                      require_passport={"x": 1}, passport="PP", now=123456)
    assert res.allow is True
    assert res.assurance["passport"] == {"outcome": "pass", "level": "software"}
    assert seen == [(pc, {"x": 1}, "PP", 123456)]
    # the guard verified a different leaf than the passport was checked for: refused
    verified["pc"] = {"cap_chain": [{"holder": "root"}, {"holder": "other"}]}
    res = A.authorize(pc, operation={"verb": "v", "resource": "r", "params": {}}, audience="aud", resolve_grant=lambda g: None,
                      state_store=_obj(claim=1, budget=1, claim_budget=1), is_revoked=lambda *a: False,
                      require_passport={"x": 1}, passport="PP", now=1)
    assert res.allow is False and res.reason == "passport: subject_mismatch"
    # no leaf could be read up front: refused even though the guard allowed
    verified["pc"] = pc
    res = A.authorize("P", operation={"verb": "v", "resource": "r", "params": {}}, audience="aud", resolve_grant=lambda g: None,
                      state_store=_obj(claim=1, budget=1, claim_budget=1), is_revoked=lambda *a: False,
                      require_passport={"x": 1}, passport="PP", now=1)
    assert res.allow is False and res.reason == "passport: subject_mismatch"
    spy.clear()
    res = A.authorize("P", operation={"verb": "v", "resource": "r", "params": {}}, audience="aud", resolve_grant=lambda g: None,
                      state_store=_obj(claim=1, budget=1, claim_budget=1), is_revoked=lambda *a: False,
                      require_passport={"deny": 1}, passport="PP", now=None)
    assert res is refusal
    assert seen[-1][3] is None
    assert spy == []  # the gate's refusal is returned before the guard runs


def test_forbid_and_linked_template_configuration_refusals(spy, monkeypatch):
    msg = "authorize_config: missing required component(s): forbid.clauses (fail closed)"
    for f in ({}, {"clauses": None}, {"clauses": "x"}):
        assert_refused(call(forbid=f), "authorize_config", msg, ["forbid.clauses"])
    msg = "authorize_config: missing required component(s): require_linked_template.registry (fail closed)"
    for t in ({}, {"registry": None}):
        assert_refused(call(require_linked_template=t), "authorize_config", msg, ["require_linked_template.registry"])
    assert spy == []
    refusal = A._refuse(403, "forbid", "forbid: x")
    monkeypatch.setattr(A, "_forbid_refusal", lambda *a: refusal)
    assert call(forbid={"clauses": lambda: []}) is refusal
    monkeypatch.setattr(A, "_forbid_refusal", lambda *a: None)
    assert call(forbid={"clauses": lambda: []}).allow is True
    t_refusal = A._refuse(403, "template", "template: x")
    seen = []
    monkeypatch.setattr(A, "_template_refusal", lambda p, reg, rg: seen.append(reg) or t_refusal)
    assert call(require_linked_template={"registry": "REG"}) is t_refusal
    assert seen == ["REG"]
    monkeypatch.setattr(A, "_template_refusal", lambda p, reg, rg: None)
    assert call(require_linked_template={"registry": "REG"}).allow is True


def test_contract_peek_refusal_and_pass_through(spy):
    seen = []

    class C:
        def __init__(self, verdict):
            self.verdict = verdict

        def peek(self, action):
            seen.append(action)
            return self.verdict

    res = call(contracts=C({"allow": False, "reason": "nope", "violated": ["a", "b"]}))
    assert_refused(res, "contract", "contract: nope (a,b)", None)
    assert seen == [{"action": {"verb": "v", "resource": "r", "params": {}}}]
    assert_refused(call(contracts=C({"allow": False, "reason": "nope"})), "contract", "contract: nope", None)
    assert spy == []
    ok = C({"allow": True})
    assert call(contracts=ok).allow is True
    assert spy[0][1]["contracts"] is ok


def test_optional_arguments_reach_the_core_only_when_set(spy):
    f = lambda *a: None  # noqa: E731
    both = _obj(claim=1, budget=1, claim_budget=1, pin=1, raise_pin=1)
    opts = dict(pq_pins={"a": "b"}, resolve_principal=f, require_verified_principal=True, risk=f, require_risk_inputs=["x"],
                threshold=f, enforce_freshness={"a": 1}, enforce_taint={"b": 1}, beacon=f, adaptive_policy=f,
                contracts=_obj(peek=1))
    opts["contracts"].peek = lambda action: {"allow": True}
    assert call(state_store=both, **opts).allow is True
    assert spy[-1][1] == opts
    call()
    assert spy[-1][1] == {}
    call(require_verified_principal=False)
    assert spy[-1][1] == {}
    call(seed_budget={"B": 2})
    assert spy[-1][1] == {"seed_budget": {"B": 2}}
    call(seed_budget=None)
    assert spy[-1][1] == {"seed_budget": None}
    call(seed_budget="default")
    assert spy[-1][1] == {}


def _retry_run(monkeypatch, succeed_after=None, **kw):
    n = [0]

    def fake(*a, **k):
        n[0] += 1
        if succeed_after is not None and n[0] > succeed_after:
            return _ok()
        raise A._BudgetConflict()

    monkeypatch.setattr(A, "_authorize", fake)
    return call(**kw), n[0]


_RETRY_MSG = "replay: concurrent state update for this holder kept conflicting (fail closed, retry the request)"


@pytest.mark.parametrize("kw,calls", [({}, 4), ({"claim_retries": 3}, 4), ({"claim_retries": 0}, 1), ({"claim_retries": 1}, 2),
                                      ({"claim_retries": 2}, 3), ({"claim_retries": -4}, 1)])
def test_claim_retries_bound_the_attempts(monkeypatch, kw, calls):
    res, n = _retry_run(monkeypatch, **kw)
    assert n == calls
    assert_refused(res, "replay", _RETRY_MSG, None)


def test_a_conflict_is_retried_until_the_core_decides(monkeypatch):
    res, n = _retry_run(monkeypatch, succeed_after=3)
    assert n == 4 and res.allow is True
    res, n = _retry_run(monkeypatch, succeed_after=1, claim_retries=1)
    assert n == 2 and res.allow is True
    res, n = _retry_run(monkeypatch, succeed_after=0, claim_retries=0)
    assert n == 1 and res.allow is True
    res, n = _retry_run(monkeypatch, succeed_after=3, claim_retries=2)
    assert n == 3
    assert_refused(res, "replay", _RETRY_MSG, None)


# ---- the passport gate: leaf read before and after the guard, and the assurance label -------------------------------------------------

def _passport_run(monkeypatch, presented, verified, rp=None, passport="PP"):
    monkeypatch.setattr(A, "_passport_refusal", lambda *a: None)

    def guard(*a, **kw):
        r = _ok()
        r.pcactn = verified
        return r

    monkeypatch.setattr(A, "_authorize", guard)
    return A.authorize(presented, operation={"verb": "v", "resource": "r", "params": {}}, audience="aud", resolve_grant=lambda g: None,
                       state_store=_obj(claim=1, budget=1, claim_budget=1), is_revoked=lambda *a: False,
                       require_passport={"x": 1} if rp is None else rp, passport=passport, now=1)


_LEAF_PC = {"cap_chain": [{"holder": "root"}, {"holder": "leaf"}]}


@pytest.mark.parametrize("presented", [
    "P", None, 5, {}, {"cap_chain": None}, {"cap_chain": []}, {"cap_chain": [1]}, {"cap_chain": "ab"}, {"cap_chain": {"0": 1}},
    {"cap_chain": [{"holder": 5}]}, {"cap_chain": [{"holder": None}]}, {"cap_chain": [{}]}, {"cap_chain": [{"holder": ["leaf"]}]},
])
def test_passport_gate_refuses_when_the_presented_leaf_cannot_be_read_as_a_string(monkeypatch, presented):
    verified = {"cap_chain": [{"holder": "leaf"}]}
    res = _passport_run(monkeypatch, presented, verified)
    assert res.allow is False and res.reason == "passport: subject_mismatch"
    # a non-string leaf never matches, even when the guard verified the very same value
    if isinstance(presented, dict) and isinstance(presented.get("cap_chain"), list) and presented["cap_chain"] == [{"holder": 5}]:
        res = _passport_run(monkeypatch, presented, presented)
        assert res.allow is False and res.reason == "passport: subject_mismatch"
    # an empty-string verified leaf must not match an unreadable presented leaf
    res = _passport_run(monkeypatch, presented, {"cap_chain": [{"holder": ""}]})
    assert res.allow is False and res.reason == "passport: subject_mismatch"


def test_passport_gate_reads_the_presented_leaf_from_an_encoded_pcactn(monkeypatch):
    res = _passport_run(monkeypatch, '{"cap_chain":[{"holder":"leaf"}]}', {"cap_chain": [{"holder": "leaf"}]})
    assert res.allow is True
    res = _passport_run(monkeypatch, _LEAF_PC, {"cap_chain": [{"holder": "root"}, {"holder": "leaf"}]})
    assert res.allow is True


@pytest.mark.parametrize("verified", [
    "str", None, 5, [], {}, {"cap_chain": None}, {"cap_chain": []}, {"cap_chain": [1]}, {"cap_chain": "ab"}, {"cap_chain": {"0": 1}},
    {"cap_chain": [{}]}, {"cap_chain": [{"holder": None}]}, {"cap_chain": [{"holder": 5}]}, {"cap_chain": [{"holder": ["leaf"]}]},
    {"cap_chain": [{"holder": "leaf"}, {"holder": "other"}]},
])
def test_passport_gate_refuses_when_the_verified_leaf_cannot_be_read_or_differs(monkeypatch, verified):
    res = _passport_run(monkeypatch, _LEAF_PC, verified)
    assert res.allow is False and res.reason == "passport: subject_mismatch"
    assert res.status == 403 and res.checks == {"passport": "fail"}


def _labelled(level, vendor=None):
    return A.set_assurance_label(lambda *a: None, level, vendor=vendor)


def _rooted(rp):
    return _passport_run(monkeypatch=_rooted.mp, presented=_LEAF_PC, verified=_LEAF_PC, rp=rp,
                         passport={"passport": {"hardware_rooted": True}}).assurance["passport"]


@pytest.mark.parametrize("rp,expected", [
    ({"attest": _labelled("hardware", "amd-sev-snp")}, {"outcome": "pass", "level": "hardware", "vendor": "amd-sev-snp"}),
    ({"default_verifier": _labelled("multi_root", "tpm")}, {"outcome": "pass", "level": "multi_root", "vendor": "tpm"}),
    ({"attest": _labelled("hardware", "amd-sev-snp"), "default_verifier": _labelled("software", "other")},
     {"outcome": "pass", "level": "hardware", "vendor": "amd-sev-snp"}),
    ({"attest": _labelled("hardware"), "default_verifier": _labelled("software", "other")}, {"outcome": "pass", "level": "hardware"}),
    ({"attest": None, "default_verifier": _labelled("software")}, {"outcome": "pass", "level": "software"}),
    ({"attest": lambda *a: None, "default_verifier": _labelled("hardware", "v")}, {"outcome": "pass", "level": "unknown"}),
    ({"attest": _labelled("hardware", "v"), "default_verifier": None}, {"outcome": "pass", "level": "hardware", "vendor": "v"}),
    ({}, {"outcome": "pass", "level": "unknown"}),
    ({"attest": None, "default_verifier": None}, {"outcome": "pass", "level": "unknown"}),
])
def test_hardware_rooted_passport_assurance_label_comes_from_attest_then_default_verifier(monkeypatch, rp, expected):
    _rooted.mp = monkeypatch
    assert _rooted(rp) == expected


def test_passport_assurance_is_software_unless_the_passport_is_hardware_rooted(monkeypatch):
    rp = {"attest": _labelled("hardware", "v")}
    for passport in ("PP", None, {}, {"passport": None}, {"passport": {}}, {"passport": {"hardware_rooted": "yes"}},
                     {"passport": {"hardware_rooted": False}}):
        res = _passport_run(monkeypatch, _LEAF_PC, _LEAF_PC, rp=rp, passport=passport)
        assert res.assurance["passport"] == {"outcome": "pass", "level": "software"}, passport
