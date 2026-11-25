"""The risk functional, threshold map and trust budget: every case of the reference's risk.test.ts, translated."""
import math

import pytest

from atlas_pca import risk as R

P = R.DEFAULT_RISK_POLICY
W = P["weights"]
CALM = {"semanticDistance": 0, "reversibility": 1, "blastRadius": 0, "taint": 0, "confidence": 1, "age": 0}
NAN = float("nan")


def approx(a, b, tol=1e-9):
    return abs(a - b) <= tol


def test_risk_score_calm_worst_and_clamp():
    assert R.risk_score(CALM, W) == 0
    worst = {"semanticDistance": 1, "reversibility": 0, "blastRadius": 1, "taint": 1, "confidence": 0, "age": 1}
    assert approx(R.risk_score(worst, W), 1, 1e-10)
    assert R.risk_score(worst, {k: 5 for k in W}) == 1


def test_risk_score_is_monotone_in_every_input():
    for k in ("semanticDistance", "blastRadius", "taint", "age"):
        prev = -1
        for v in (0, 0.2, 0.5, 0.9, 1):
            r = R.risk_score(dict(CALM, **{k: v}), W)
            assert r >= prev
            prev = r
        assert R.risk_score(dict(CALM, **{k: 1}), W) > 0
    for k in ("reversibility", "confidence"):
        prev = 2
        for v in (0, 0.2, 0.5, 0.9, 1):
            r = R.risk_score(dict(CALM, **{k: v}), W)
            assert r <= prev
            prev = r


def test_out_of_range_clamps_nan_fails_closed_negative_weights_are_ignored():
    assert R.risk_score(dict(CALM, taint=7), W) == R.risk_score(dict(CALM, taint=1), W)
    assert R.risk_score(dict(CALM, taint=NAN), W) == R.risk_score(dict(CALM, taint=1), W)
    assert R.risk_score(dict(CALM, confidence=NAN), W) == R.risk_score(dict(CALM, confidence=0), W)
    assert R.risk_score(dict(CALM, taint=1), dict(W, delta=-3)) == 0
    assert R.risk_score(dict(CALM, taint=True), W) == R.risk_score(dict(CALM, taint=1), W)  # a boolean is not a number: the worst case


def test_required_threshold_boundaries_are_inclusive_on_the_lower_tier():
    p = {"theta1": 0.25, "theta2": 0.6}
    assert R.required_threshold(0, p) == {"t": 1, "proof": "claim", "optimisticAllowed": True}
    assert R.required_threshold(0.25, p)["t"] == 1
    assert R.required_threshold(0.2501, p) == {"t": 2, "proof": "standard", "optimisticAllowed": False}
    assert R.required_threshold(0.6, p)["t"] == 2
    assert R.required_threshold(0.6001, p) == {"t": 3, "proof": "strong", "optimisticAllowed": False}
    assert R.required_threshold(NAN, p)["t"] == 3


def test_irreversible_is_never_optimistic_and_t_is_monotone():
    p = {"theta1": 0.25, "theta2": 0.6}
    assert R.required_threshold(0.1, p, irreversible=True)["optimisticAllowed"] is False
    prev = 0
    for i in range(101):
        t = R.required_threshold(i / 100, p)["t"]
        assert t >= prev
        prev = t


def test_escalate_threshold_raises_and_stays_coherent():
    t1 = {"t": 1, "proof": "claim", "optimisticAllowed": True}
    assert R.escalate_threshold(t1, 1) == t1
    assert R.escalate_threshold(t1, 2) == {"t": 2, "proof": "standard", "optimisticAllowed": False}
    assert R.escalate_threshold(t1, 3) == {"t": 3, "proof": "strong", "optimisticAllowed": False}
    t3 = {"t": 3, "proof": "strong", "optimisticAllowed": False}
    assert R.escalate_threshold(t3, 1) == t3 and R.escalate_threshold(t3, 2) == t3  # never lowers
    assert R.escalate_threshold({"t": 1, "proof": "strong", "optimisticAllowed": True}, 2) == {"t": 2, "proof": "strong", "optimisticAllowed": False}
    assert R.escalate_threshold({"t": 2, "proof": "standard", "optimisticAllowed": False}, 1)["proof"] == "standard"


def test_cost_debit_leak():
    b0 = {"B": 1, "tau": 0}
    assert approx(R.cost(0.2, 2), 0.4)
    assert R.cost(NAN, 2) == 2 and R.cost(5, 2) == 2 and R.cost(0.5, -1) == 0
    assert approx(R.debit(b0, 0.3)["B"], 0.7)
    assert R.debit(b0, 5)["B"] == 0
    assert R.debit(b0, -5)["B"] == 1 and R.debit(b0, NAN)["B"] == 1
    lk = R.leak(b0, 1_000_000, 0.0005)  # 1000 s * 0.0005 = 0.5
    assert approx(lk["B"], 0.5)
    assert approx(R.leak(lk, 1_000_000, 0.0005)["B"], 0.5)  # idempotent at the same now
    assert approx(R.leak(lk, 2_000_000, 0.0005)["B"], 0)
    assert R.leak(b0, -5, 1)["B"] == 1  # time going backwards: no change
    assert lk["tau"] == 0  # leak is not a human touch
    assert R.leak(b0, NAN, 1) == {"B": 1, "tau": 0, "asOf": 0}
    assert R.leak({"B": 1, "tau": 0, "asOf": 500}, 1500, 1)["B"] == 0.0 or approx(R.leak({"B": 1, "tau": 0, "asOf": 500}, 1500, 1)["B"], 0)


def test_recharge_caps_at_bmax_and_resets_tau_full_recharge():
    low = {"B": 0.2, "tau": 0}
    assert R.recharge(low, 0.5, 1, 99) == {"B": 0.7, "tau": 99, "asOf": 99}
    assert R.recharge(low, 5, 1, 99)["B"] == 1
    assert R.recharge_full(low, 1, 7) == {"B": 1, "tau": 7, "asOf": 7}


def test_age_since_touch():
    assert approx(R.age_since_touch({"B": 1, "tau": 0}, 1_800_000), 0.5)
    assert R.age_since_touch({"B": 1, "tau": 0}, 9e9) == 1
    assert R.age_since_touch({"B": 1, "tau": 0}, NAN) == 1
    assert R.age_since_touch({"B": 1, "tau": NAN}, 5) == 1
    assert R.age_since_touch({"B": 1, "tau": 0}, 5, 0) == 1


def test_admit_low_r_with_budget_auto_mid_high_step_up_depleted_step_up_t3():
    assert R.admit(0.1, {"B": 1, "tau": 0}, P) == {"admit": True, "needStepUp": False, "t": 1, "metered": True}
    assert R.admit(0.25, {"B": 0.25, "tau": 0}, P)["admit"] is True  # B >= cost edge
    assert R.admit(0.4, {"B": 1, "tau": 0}, P) == {"admit": False, "needStepUp": True, "t": 2, "metered": True}
    assert R.admit(0.4, {"B": 0.3, "tau": 0}, P) == {"admit": False, "needStepUp": True, "t": 3, "metered": False}
    assert R.admit(0.9, {"B": 1, "tau": 0}, P) == {"admit": False, "needStepUp": True, "t": 3, "metered": False}
    assert R.admit(0.1, {"B": 0.05, "tau": 0}, P) == {"admit": False, "needStepUp": True, "t": 3, "metered": False}


def test_the_safety_invariant_machine_only_risk_between_recharges_is_bounded():
    for pol in (P, dict(P, kappa=2, bMax=1.5), dict(P, kappa=0.5, bMax=0.7, **{"lambda": 0})):
        seed = [12345]

        def rnd():
            seed[0] = (seed[0] * 1664525 + 1013904223) % 4294967296
            return seed[0] / 4294967296
        b = {"B": pol["bMax"], "tau": 0}
        total, now, touches = 0.0, 0, 0
        for _ in range(5000):
            now += math.floor(rnd() * 5000)
            b = R.leak(b, now, pol["lambda"])
            r = rnd() * 0.7
            a = R.admit(r, b, pol)
            if a["metered"]:
                total += r
                b = R.debit(b, R.cost(r, pol["kappa"]))
                assert total <= R.safety_bound(pol) + 1e-9
            elif rnd() < 0.05:
                b = R.recharge(b, pol["rho"], pol["bMax"], now)
                touches += 1
                total = 0
        assert touches > 0
    assert R.safety_bound({"bMax": 1, "kappa": 4}) == 0.25
    assert R.safety_bound({"bMax": 1, "kappa": 0}) == 0 and R.safety_bound({"bMax": -1, "kappa": 1}) == 0


def test_a_compromised_agent_hammering_free_actions_halts_at_the_bound():
    pol = dict(P, **{"lambda": 0})
    b = {"B": pol["bMax"], "tau": 0}
    total = 0.0
    for _ in range(10_000):
        r = 0.2
        if not R.admit(r, b, pol)["admit"]:
            break
        total += r
        b = R.debit(b, R.cost(r, pol["kappa"]))
    assert total <= R.safety_bound(pol)
    assert R.admit(0.01, b, dict(pol, kappa=1000))["needStepUp"] is True


def test_depletion_forces_step_up_even_for_low_r():
    b = {"B": 0.3, "tau": 0}
    assert R.admit(0.2, b, P)["admit"] is True
    b = R.debit(b, R.cost(0.2, P["kappa"]))
    got = R.admit(0.2, b, P)
    assert got["admit"] is False and got["needStepUp"] is True


def test_sub_budget_cannot_exceed_the_parent_and_the_debit_is_consolidated():
    parent = {"B": 0.6, "tau": 5}
    assert R.sub_budget(parent, 0.7) == {"ok": False, "reason": "allocation exceeds parent remaining budget"}
    assert R.sub_budget(parent, -1) == {"ok": False, "reason": "allocation must be finite and >= 0"}
    assert R.sub_budget(parent, NAN) == {"ok": False, "reason": "allocation must be finite and >= 0"}
    s1 = R.sub_budget(parent, 0.6)
    assert s1 == {"ok": True, "sub": {"B": 0.6, "tau": 5, "asOf": 5}}
    s2 = R.sub_budget(dict(parent, asOf=9), 0.6)
    assert s2["sub"]["asOf"] == 9
    a = R.debit_consolidated(parent, s1["sub"], 0.4)
    assert a["ok"] is True and approx(a["parent"]["B"], 0.2)
    b = R.debit_consolidated(a["parent"], s2["sub"], 0.4)
    assert b == {"ok": False, "reason": "parent budget insufficient"}
    assert R.debit_consolidated(parent, {"B": 0.1, "tau": 0}, 0.2) == {"ok": False, "reason": "sub-agent budget insufficient"}


def test_debit_consolidated_path_debits_every_level_and_refuses_if_any_cannot_cover():
    path = [{"B": 5, "tau": 0}, {"B": 3, "tau": 0}, {"B": 2, "tau": 0}]
    a = R.debit_consolidated_path(path, 1.5)
    assert a["ok"] is True and [n["B"] for n in a["nodes"]] == [3.5, 1.5, 0.5]
    b = R.debit_consolidated_path(a["nodes"], 1.5)
    assert b == {"ok": False, "reason": "budget node at depth 2 insufficient (need 1.5, have 0.5)"}
    dry = [{"B": 0.2, "tau": 0}, {"B": 9, "tau": 0}]
    assert R.debit_consolidated_path(dry, 1) == {"ok": False, "reason": "budget node at depth 0 insufficient (need 1, have 0.2)"}
    z = R.debit_consolidated_path(path, 0)
    assert z["ok"] is True and [n["B"] for n in z["nodes"]] == [5, 3, 2]
    assert R.debit_consolidated_path([], 1) == {"ok": True, "nodes": []}


def test_validate_risk_policy():
    assert R.validate_risk_policy(P) is None
    assert R.validate_risk_policy(dict(P, theta1=0.9, theta2=0.1)) == "risk_policy requires 0 <= theta1 <= theta2"
    assert R.validate_risk_policy(dict(P, kappa=0)) == "risk_policy.kappa must be > 0"
    assert R.validate_risk_policy(dict(P, weights=dict(W, alpha=-1))) == "risk_policy.weights.alpha must be finite and >= 0"
    assert R.validate_risk_policy(None) == "risk_policy must be an object"
    assert R.validate_risk_policy(dict(P, weights=None)) == "risk_policy.weights missing"
    assert R.validate_risk_policy(dict(P, rho=NAN)) == "risk_policy.rho must be finite"
    assert R.validate_risk_policy(dict(P, bMax=-1)) == "risk_policy lambda/rho/bMax must be >= 0"
    assert R.validate_risk_policy(dict(P, theta1=True)) == "risk_policy.theta1 must be finite"


def node(i, **extra):
    return dict({"id": i, "verb": "v", "resource": "/" + i}, **extra)


def test_plan_geodesic_index_fallback_when_there_are_no_edges():
    plan = [node("a"), node("b"), node("c"), node("d")]
    assert R.plan_geodesic(plan, "a", "a") == 0
    assert R.plan_geodesic(plan, "a", "d") == 1
    assert approx(R.plan_geodesic(plan, "b", "d"), 2 / 3)


def test_plan_geodesic_bfs_over_pre_and_post_references():
    plan = [node("a", post={"before": ["b"]}), node("b"), node("c", pre={"after": "b"}), node("d", pre="c"), node("x")]
    assert approx(R.plan_geodesic(plan, "a", "d"), 3 / 4)
    assert approx(R.plan_geodesic(plan, "d", "a"), 3 / 4)
    assert approx(R.plan_geodesic(plan, "c", "d"), 1 / 4)
    assert R.plan_geodesic(plan, "a", "x") == 1
    assert R.plan_geodesic(plan, "a", "nope") == 1


def test_plan_geodesic_single_node_and_bad_plan():
    assert R.plan_geodesic([node("a")], "a", "a") == 0
    assert R.plan_geodesic(None, "a", "b") == 1
