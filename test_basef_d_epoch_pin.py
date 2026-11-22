"""The revocation-epoch rollback pin is automatic: with a staleness policy the guard keeps the highest accepted epoch of each grant in its
state store (`<grant id>:epoch`) and refuses an older signed epoch as a rollback even when the host supplied no last-accepted value;
a denied action never raises it; a store that cannot hold pins is refused at construction."""
import sys

import pytest
from prov_harness import prov

from atlas_pca import MemoryStateStore, RevocationStaleness, SqliteStateStore, authorize
from test_revocation_staleness import FIX, GUARD, _case

AZ = sys.modules["atlas_pca.authorize"]  # the module (the package attribute `authorize` is the function)

PIN_TEXT = "revocation staleness needs a state store that implements pins (rollback protection)"


def run(monkeypatch, store, state, verdict, seen=None, counter_bump=0):
    c = _case()
    s = c["steps"][0]
    import json
    pcactn = json.loads(json.dumps(s["pcactn"]))

    def stub(policy, st, **kw):
        if seen is not None:
            seen.append(st)
        return verdict

    monkeypatch.setattr(AZ, "check_revocation_state", stub)
    pol = RevocationStaleness(guardian_public=GUARD, allow_unsigned_root_for_irreversible=True)
    r = authorize(pcactn, operation=s["operation"], audience=FIX["audience"], resolve_grant=lambda ref: c["grant"], state_store=store,
                  is_revoked=lambda p, g: False, now=FIX["now"], plan="single-step", context=lambda p: {"revocation_state": state},
                  revocation_staleness=pol, **prov(s["operation"]))
    return r, c["grant"]["id"]


def epoch_ok(n):
    return {"ok": True, "epoch": {"epoch": n}}


def test_an_allowed_epoch_raises_the_pin_and_the_next_call_sees_it(monkeypatch):
    store = MemoryStateStore()
    seen = []
    r, gid = run(monkeypatch, store, {"kind": "epoch", "epoch": {}}, epoch_ok(5), seen)
    assert r.allow is True and r.checks["freshness"] == "pass"
    assert store.pin("%s:epoch" % gid) == 5
    assert seen[0] == {"kind": "epoch", "epoch": {}}  # nothing stored yet: the host state is untouched
    seen.clear()
    run(monkeypatch, store, {"kind": "epoch", "epoch": {}}, epoch_ok(6), seen)
    assert seen[0]["last_accepted_epoch"] == 5  # the stored pin, though the host supplied none


def test_the_larger_of_the_host_value_and_the_pin_wins(monkeypatch):
    store = MemoryStateStore()
    run(monkeypatch, store, {"kind": "epoch", "epoch": {}}, epoch_ok(5))
    seen = []
    run(monkeypatch, store, {"kind": "epoch", "epoch": {}, "last_accepted_epoch": 7}, epoch_ok(8), seen)
    assert seen[0]["last_accepted_epoch"] == 7
    seen.clear()
    run(monkeypatch, store, {"kind": "epoch", "epoch": {}, "last_accepted_epoch": 3}, epoch_ok(8), seen)
    assert seen[0]["last_accepted_epoch"] == 5
    seen.clear()
    run(monkeypatch, store, {"kind": "epoch", "epoch": {}, "last_accepted_epoch": 5}, epoch_ok(9), seen)
    assert seen[0]["last_accepted_epoch"] == 5


def test_a_root_state_does_not_read_or_write_a_pin(monkeypatch):
    store = MemoryStateStore()
    seen = []
    r, gid = run(monkeypatch, store, {"kind": "root", "root": "r", "issued_at": 0}, {"ok": True}, seen)
    assert r.allow is True and store.pin("%s:epoch" % gid) is None
    assert seen[0] == {"kind": "root", "root": "r", "issued_at": 0}


def test_a_denied_freshness_never_raises_the_pin(monkeypatch):
    store = MemoryStateStore()
    r, gid = run(monkeypatch, store, {"kind": "epoch", "epoch": {}}, {"ok": False, "reason": "no"})
    assert r.allow is False and store.pin("%s:epoch" % gid) is None


def test_the_pin_never_lowers(monkeypatch):
    store = MemoryStateStore()
    _r, gid = run(monkeypatch, store, {"kind": "epoch", "epoch": {}}, epoch_ok(9))
    store._pins["%s:epoch" % gid] = 12  # a later, higher pin
    store.raise_pin("%s:epoch" % gid, 11)
    assert store.pin("%s:epoch" % gid) == 12


def test_memory_and_sqlite_pins_are_monotone(tmp_path):
    for store in (MemoryStateStore(), SqliteStateStore(str(tmp_path / "p.db"))):
        assert store.pin("k") is None
        store.raise_pin("k", 7)
        store.raise_pin("k", 6)
        assert store.pin("k") == 7
        store.raise_pin("k", 7)
        store.raise_pin("k", 9)
        assert store.pin("k") == 9
        for bad in (("", 1), (5, 1), ("k", True), ("k", 1.5), ("k", "1")):
            with pytest.raises(ValueError):
                store.raise_pin(*bad)
        assert store.pin("k") == 9


def test_a_sqlite_pin_survives_a_new_store(tmp_path):
    path = str(tmp_path / "p.db")
    SqliteStateStore(path).raise_pin("g:epoch", 4)
    assert SqliteStateStore(path).pin("g:epoch") == 4


def test_a_store_without_pins_is_refused():
    class NoPins:
        def budget(self, key):
            return None

        def claim_budget(self, key, counter, before, after):  # the 0.5 stores decide the budget with the claim
            return self.claim(key, counter)

        def claim(self, key, counter):
            raise NotImplementedError

    pol = RevocationStaleness(guardian_public=GUARD)
    with pytest.raises(ValueError) as e:
        AZ.AuthorizeOptions(state_store=NoPins(), is_revoked=lambda p, g: False, revocation_staleness=pol)
    assert str(e.value) == "AuthorizeOptions: " + PIN_TEXT
    r = authorize({}, operation={"verb": "v", "resource": "r", "params": {}}, audience="a", resolve_grant=lambda ref: None,
                  state_store=NoPins(), is_revoked=lambda p, g: False, revocation_staleness=pol)
    assert r.allow is False and r.reason == "authorize_config: " + PIN_TEXT


def test_a_pin_store_that_fails_denies_fail_closed(monkeypatch):
    class Broken(MemoryStateStore):
        def pin(self, key):
            raise RuntimeError("down")

    r, _ = run(monkeypatch, Broken(), {"kind": "epoch", "epoch": {}}, epoch_ok(5))
    assert r.allow is False and r.checks["freshness"] == "fail"
    assert any("the revocation epoch pin could not be read (fail closed)" in x for x in r.reasons)

    class BrokenRaise(MemoryStateStore):
        def raise_pin(self, key, value):
            raise RuntimeError("down")

    r, _ = run(monkeypatch, BrokenRaise(), {"kind": "epoch", "epoch": {}}, epoch_ok(5))
    assert r.allow is False and any("the revocation epoch pin could not be stored (fail closed)" in x for x in r.reasons)
