"""Conformance cases for an approval store, plus broker-level cases run over it. Mirrors the TypeScript reference
(@atlasauth/pca-ciba). Run them against YOUR store::

    from atlas_pca.ciba_conformance import run_approval_store_conformance
    report = run_approval_store_conformance(lambda: MyStore(), reopen=lambda previous: MyStore())
    assert report.ok, report.render()

Each case raises ``AssertionError`` when the store breaks the contract: absent means version 0, ``cas`` writes only at the
expected version and bumps it by one, exactly one of many concurrent ``cas`` calls wins, returned values are snapshots, and (with
``reopen``) written records survive a restart. The broker cases check what the contract is for: exactly one concurrent decision
wins and an approval redeems once."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from .ciba_store import create_durable_ciba_broker
from .store_conformance import ConformanceReport, TestResult, _check_no_errors, _race


@dataclass
class ApprovalStoreCase:
    __test__ = False

    name: str
    run: Callable[[], None]


def _eq(actual: Any, expected: Any) -> None:
    if actual != expected or type(actual) is not type(expected):
        raise AssertionError("expected %r, got %r" % (expected, actual))


def approval_store_cases(make: Callable[[], Any], reopen: Optional[Callable[[Any], Any]] = None) -> List[ApprovalStoreCase]:
    """@param make a store over a fresh, empty backing location each call.
    @param reopen for a persistent store: a NEW store object over the same backing location as ``previous``, as after a restart."""
    cases: List[ApprovalStoreCase] = []

    def case(name: str) -> Callable[[Callable[[], None]], Callable[[], None]]:
        def deco(fn: Callable[[], None]) -> Callable[[], None]:
            cases.append(ApprovalStoreCase(name, fn))
            return fn
        return deco

    @case("an absent key reads None")
    def _() -> None:
        _eq(make().get("nope"), None)

    @case("cas at version 0 creates the key at version 1 with the whole value")
    def _() -> None:
        s = make()
        v = {"a": 1, "nested": {"b": ["x", 2, None]}}
        _eq(s.cas("k", 0, v), True)
        _eq(s.get("k"), {"version": 1, "value": v})

    @case("cas at version 0 on an existing key is refused and changes nothing")
    def _() -> None:
        s = make()
        s.cas("k", 0, "first")
        _eq(s.cas("k", 0, "second"), False)
        _eq(s.get("k"), {"version": 1, "value": "first"})

    @case("cas succeeds only at the current version and bumps it by exactly one")
    def _() -> None:
        s = make()
        s.cas("k", 0, 1)
        _eq(s.cas("k", 1, 2), True)
        _eq(s.cas("k", 1, 3), False)  # stale
        _eq(s.cas("k", 5, 4), False)  # from the future
        _eq(s.cas("k", 2, 5), True)
        _eq(s.get("k"), {"version": 3, "value": 5})

    @case("cas on a key that does not exist at a non-zero version is refused and creates nothing")
    def _() -> None:
        s = make()
        _eq(s.cas("k", 1, "x"), False)
        _eq(s.get("k"), None)

    @case("keys are independent")
    def _() -> None:
        s = make()
        s.cas("a", 0, "A")
        s.cas("b", 0, "B")
        s.cas("a", 1, "A2")
        _eq(s.get("a"), {"version": 2, "value": "A2"})
        _eq(s.get("b"), {"version": 1, "value": "B"})

    @case("a read is a snapshot: changing the returned value does not change the store")
    def _() -> None:
        s = make()
        s.cas("k", 0, {"list": [1]})
        got = s.get("k")
        got["value"]["list"].append(2)
        _eq(s.get("k"), {"version": 1, "value": {"list": [1]}})

    @case("a written value is a snapshot: changing it after cas does not change the store")
    def _() -> None:
        s = make()
        v = {"list": [1]}
        s.cas("k", 0, v)
        v["list"].append(2)
        _eq(s.get("k"), {"version": 1, "value": {"list": [1]}})

    @case("exactly one of many concurrent creates wins")
    def _() -> None:
        s = make()
        results = _race(32, lambda i: s.cas("k", 0, i))
        _check_no_errors(results)
        _eq([r for r in results if r is True], [True])
        stored = s.get("k")
        _eq(stored["version"], 1)
        _eq(stored["value"], results.index(True))

    @case("exactly one of many concurrent updates at the same version wins")
    def _() -> None:
        s = make()
        s.cas("k", 0, "base")
        results = _race(32, lambda i: s.cas("k", 1, i))
        _check_no_errors(results)
        _eq(len([r for r in results if r is True]), 1)
        _eq(s.get("k"), {"version": 2, "value": results.index(True)})

    @case("a retry loop over concurrent writers loses no increment")
    def _() -> None:
        s = make()
        s.cas("n", 0, 0)

        def bump(_i: int) -> None:
            while True:
                cur = s.get("n")
                if cur and s.cas("n", cur["version"], cur["value"] + 1):
                    return

        _check_no_errors(_race(24, bump))
        _eq(s.get("n"), {"version": 25, "value": 24})

    if reopen is not None:
        @case("records and their versions survive reopening the store")
        def _() -> None:
            s = make()
            s.cas("k", 0, {"v": 1})
            s.cas("k", 1, {"v": 2})
            again = reopen(s)
            _eq(again.get("k"), {"version": 2, "value": {"v": 2}})
            _eq(again.cas("k", 1, {"v": "stale"}), False)
            _eq(again.cas("k", 2, {"v": 3}), True)

    return cases


def _step_up() -> dict:
    return {"id": "su_" + uuid.uuid4().hex, "verb": "stripe.payout", "resource": "acct:1", "params": {"amount": 80, "currency": "USD", "payee": "bob"},
            "tier": 3, "reason": "conformance", "goalCommit": "A" * 43, "goal": "pay suppliers", "lineage": {}, "r": 0.5, "requestedAt": 1}


def approval_broker_cases(make: Callable[[], Any]) -> List[ApprovalStoreCase]:
    """Broker-level cases over a store: what the compare-and-set contract is for."""
    def brokers(n: int) -> list:
        store = make()
        return [create_durable_ciba_broker(store) for _ in range(n)]

    def concurrent_resolves() -> None:
        bs = brokers(8)
        req = bs[0].start(_step_up())
        settled = _race(8, lambda i: bs[i].resolve(req["auth_req_id"], "approve" if i % 2 == 0 else "deny", "user-%d" % i))
        won = [i for i, r in enumerate(settled) if not isinstance(r, BaseException)]
        _eq(len(won), 1)
        final = bs[0].get(req["auth_req_id"])
        _eq(final["decidedBy"], "user-%d" % won[0])
        _eq(final["status"], "approved" if won[0] % 2 == 0 else "denied")

    def redeems_once() -> None:
        bs = brokers(8)
        req = bs[0].start(_step_up())
        bs[0].resolve(req["auth_req_id"], "approve", "owner")
        outs = _race(8, lambda i: bs[i].token(req["auth_req_id"]))
        _check_no_errors(outs)
        _eq(len([o for o in outs if o["ok"]]), 1)

    def second_broker_sees() -> None:
        a, b = brokers(2)
        req = a.start(_step_up())
        _eq(b.poll(req["auth_req_id"])["status"], "pending")
        a.resolve(req["auth_req_id"], "approve", "owner")
        _eq(b.poll(req["auth_req_id"])["status"], "approved")
        try:
            b.resolve(req["auth_req_id"], "deny", "late")
        except Exception:
            return
        raise AssertionError("expected a refusal")

    return [
        ApprovalStoreCase("concurrent resolves through separate brokers: exactly one wins and its decision stands", concurrent_resolves),
        ApprovalStoreCase("an approval redeems once even when many brokers redeem at the same time", redeems_once),
        ApprovalStoreCase("a second broker over the same store sees the decision of the first", second_broker_sees),
    ]


def run_approval_store_conformance(make: Callable[[], Any], reopen: Optional[Callable[[Any], Any]] = None) -> ConformanceReport:
    """Run the store cases and the broker cases; returns a report (``report.ok``, ``report.render()``)."""
    report = ConformanceReport("approval-store")
    for c in approval_store_cases(make, reopen) + approval_broker_cases(make):
        try:
            c.run()
            report.results.append(TestResult(c.name, "pass"))
        except Exception as e:  # noqa: BLE001
            report.results.append(TestResult(c.name, "fail", "%s: %s" % (type(e).__name__, e)))
    return report
