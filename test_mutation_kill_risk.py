"""Exact-value tests for the risk functional, the threshold map, the budget algebra, the plan geodesic and decide_risk."""
import copy

import pytest

from atlas_pca import risk as R

NAN = float("nan")
INF = float("inf")
CALM = {"semanticDistance": 0, "reversibility": 1, "blastRadius": 0, "taint": 0, "confidence": 1, "age": 0}


def pol(**over):
    p = copy.deepcopy(R.DEFAULT_RISK_POLICY)
    p.update(over)
    return p


def bud(b=1, tau=0, as_of=0):
    return {"B": b, "tau": tau, "asOf": as_of}


def node(i, **extra):
    return dict({"id": i}, **extra)


# ---- validate_risk_policy ----------------------------------------------------------------------------------------------------------

def test_validate_policy_messages_and_boundaries():
    assert R.validate_risk_policy(pol()) is None
    assert R.validate_risk_policy("x") == "risk_policy must be an object"
    assert R.validate_risk_policy({}) == "risk_policy.weights missing"
    assert R.validate_risk_policy(pol(weights=[])) == "risk_policy.weights missing"
    # a zero weight is valid, a negative one is not
    zero = {k: 0 for k in R.DEFAULT_RISK_POLICY["weights"]}
    assert R.validate_risk_policy(pol(weights=zero)) is None
    for k in zero:
        assert R.validate_risk_policy(pol(weights=dict(zero, **{k: -0.1}))) == "risk_policy.weights.%s must be finite and >= 0" % k
        assert R.validate_risk_policy(pol(weights=dict(zero, **{k: NAN}))) == "risk_policy.weights.%s must be finite and >= 0" % k
    assert R.validate_risk_policy(pol(weights={k: v for k, v in zero.items() if k != "zeta"})) == "risk_policy.weights.zeta must be finite and >= 0"
    for k in ("theta1", "theta2", "kappa", "lambda", "rho", "bMax"):
        assert R.validate_risk_policy(pol(**{k: INF})) == "risk_policy.%s must be finite" % k
        assert R.validate_risk_policy({kk: vv for kk, vv in pol().items() if kk != k}) == "risk_policy.%s must be finite" % k
    # theta1 == 0 and theta2 == theta1 are valid; theta1 < 0 and theta2 < theta1 are not
    assert R.validate_risk_policy(pol(theta1=0, theta2=0)) is None
    assert R.validate_risk_policy(pol(theta1=0.3, theta2=0.3)) is None
    assert R.validate_risk_policy(pol(theta1=-0.1, theta2=0.5)) == "risk_policy requires 0 <= theta1 <= theta2"
    assert R.validate_risk_policy(pol(theta1=0.3, theta2=0.29)) == "risk_policy requires 0 <= theta1 <= theta2"
    assert R.validate_risk_policy(pol(kappa=0)) == "risk_policy.kappa must be > 0"
    assert R.validate_risk_policy(pol(kappa=-1)) == "risk_policy.kappa must be > 0"
    assert R.validate_risk_policy(pol(kappa=0.001)) is None
    msg = "risk_policy lambda/rho/bMax must be >= 0"
    assert R.validate_risk_policy(pol(**{"lambda": -1})) == msg
    assert R.validate_risk_policy(pol(rho=-1)) == msg
    assert R.validate_risk_policy(pol(bMax=-1)) == msg
    assert R.validate_risk_policy(pol(**{"lambda": 0, "rho": 0, "bMax": 0})) is None


# ---- risk_score: a missing input is the worst case, one input at a time ------------------------------------------------------------

@pytest.mark.parametrize("weight,key,expected", [
    ("alpha", "semanticDistance", 0.1), ("beta", "reversibility", 0.1), ("gamma", "blastRadius", 0.1),
    ("delta", "taint", 0.1), ("epsilon", "confidence", 0.1), ("zeta", "age", 0.1),
])
def test_risk_score_each_missing_input_counts_as_its_worst_case(weight, key, expected):
    w = {k: 0 for k in R.DEFAULT_RISK_POLICY["weights"]}
    w[weight] = 0.1
    inputs = {k: v for k, v in CALM.items() if k != key}
    assert R.risk_score(inputs, w) == pytest.approx(expected, abs=1e-12)
    assert R.risk_score(dict(inputs, **{key: NAN}), w) == pytest.approx(expected, abs=1e-12)
    assert R.risk_score(dict(CALM), w) == 0


# ---- required_threshold / escalate / cost / leak / age ---------------------------------------------------------------------------

def test_required_threshold_non_finite_r_is_exactly_one():
    p = {"theta1": 1, "theta2": 1.5}
    for bad in (NAN, INF, None, "x"):
        assert R.required_threshold(bad, p) == {"t": 1, "proof": "claim", "optimisticAllowed": True}
    assert R.required_threshold(NAN, {"theta1": 0.5, "theta2": 1.5}) == {"t": 2, "proof": "standard", "optimisticAllowed": False}
    assert R.required_threshold(NAN, {"theta1": 0.5, "theta2": 0.9}) == {"t": 3, "proof": "strong", "optimisticAllowed": False}


def test_escalate_threshold_exact():
    claim = {"t": 1, "proof": "claim", "optimisticAllowed": True}
    assert R.escalate_threshold(claim, 1) == claim
    assert R.escalate_threshold(claim, 2) == {"t": 2, "proof": "standard", "optimisticAllowed": False}
    assert R.escalate_threshold(claim, 3) == {"t": 3, "proof": "strong", "optimisticAllowed": False}
    strong = {"t": 3, "proof": "strong", "optimisticAllowed": False}
    assert R.escalate_threshold(strong, 1) == strong
    # a stronger proof than the floor is kept
    assert R.escalate_threshold({"t": 1, "proof": "strong", "optimisticAllowed": True}, 2) == {"t": 2, "proof": "strong", "optimisticAllowed": False}
    assert R.escalate_threshold({"t": 2, "proof": "standard", "optimisticAllowed": False}, 2) == {"t": 2, "proof": "standard", "optimisticAllowed": False}


def test_cost_exact():
    assert R.cost(0.5, 2) == 1.0
    assert R.cost(NAN, 2) == 2
    assert R.cost(7, 2) == 2
    assert R.cost(-1, 2) == 0
    assert R.cost(0.5, -3) == 0


def test_leak_exact():
    assert R.leak({"B": 1, "tau": 0, "asOf": 0}, 1000, 0.5) == {"B": 0.5, "tau": 0, "asOf": 1000}
    assert R.leak({"B": 1, "tau": 0}, 1000, 0.5) == {"B": 0.5, "tau": 0, "asOf": 1000}
    # leaks from asOf, not tau
    assert R.leak({"B": 1, "tau": 0, "asOf": 500}, 1000, 0.5) == {"B": 0.75, "tau": 0, "asOf": 1000}
    # a clock that went backwards neither leaks nor moves asOf
    assert R.leak({"B": 1, "tau": 0, "asOf": 900}, 100, 0.5) == {"B": 1, "tau": 0, "asOf": 900}
    # a non-finite now leaks nothing and keeps asOf
    assert R.leak({"B": 1, "tau": 0, "asOf": 7}, INF, 0.5) == {"B": 1, "tau": 0, "asOf": 7}
    assert R.leak({"B": 1, "tau": 0, "asOf": 7}, NAN, 0.5) == {"B": 1, "tau": 0, "asOf": 7}
    assert R.leak({"B": 0.2, "tau": 0, "asOf": 0}, 10_000_000, 0.5)["B"] == 0


def test_age_since_touch_exact():
    b = {"B": 1, "tau": 0}
    assert R.age_since_touch(b, 1_800_000) == 0.5
    assert R.age_since_touch({"B": 1, "tau": 900_000}, 1_800_000) == 0.25
    assert R.age_since_touch(b, 3_600_000) == 1
    assert R.age_since_touch(b, 99_000_000) == 1
    assert R.age_since_touch({"B": 1, "tau": 5}, 0) == 0
    assert R.age_since_touch(b, 500, 1000) == 0.5
    assert R.age_since_touch(b, NAN) == 1
    assert R.age_since_touch(b, INF) == 1
    assert R.age_since_touch(b, None) == 1
    assert R.age_since_touch({"B": 1}, 100) == 1
    assert R.age_since_touch({"B": 1, "tau": NAN}, 100) == 1
    assert R.age_since_touch({"B": 1, "tau": INF}, 100) == 1
    assert R.age_since_touch(b, 100, 0) == 1
    assert R.age_since_touch(b, 100, -5) == 1
    assert R.age_since_touch(b, 100, NAN) == 1
    assert R.age_since_touch(b, 100, INF) == 1


# ---- debit_consolidated ----------------------------------------------------------------------------------------------------------

def test_debit_consolidated_exact_and_at_the_boundary():
    parent, sub = {"B": 1, "tau": 0, "asOf": 5}, {"B": 0.5, "tau": 1, "asOf": 6}
    out = R.debit_consolidated(parent, sub, 0.5)
    assert out == {"ok": True, "parent": {"B": 0.5, "tau": 0, "asOf": 5}, "sub": {"B": 0, "tau": 1, "asOf": 6}}
    assert parent == {"B": 1, "tau": 0, "asOf": 5} and sub == {"B": 0.5, "tau": 1, "asOf": 6}
    # parent exactly covers the cost
    out = R.debit_consolidated({"B": 0.5, "tau": 0}, {"B": 1, "tau": 0}, 0.5)
    assert out == {"ok": True, "parent": {"B": 0, "tau": 0}, "sub": {"B": 0.5, "tau": 0}}
    assert R.debit_consolidated({"B": 1, "tau": 0}, {"B": 0.4, "tau": 0}, 0.5) == {"ok": False, "reason": "sub-agent budget insufficient"}
    assert R.debit_consolidated({"B": 0.4, "tau": 0}, {"B": 1, "tau": 0}, 0.5) == {"ok": False, "reason": "parent budget insufficient"}
    assert R.debit_consolidated({"B": 0.1, "tau": 0}, {"B": 0.1, "tau": 0}, 0.5) == {"ok": False, "reason": "sub-agent budget insufficient"}


def test_debit_consolidated_path_messages_print_numbers_like_js():
    path = [{"B": 5, "tau": 0}, {"B": 0.5, "tau": 0}]
    assert R.debit_consolidated_path(path, 2.5) == {"ok": False, "reason": "budget node at depth 1 insufficient (need 2.5, have 0.5)"}
    assert R.debit_consolidated_path([{"B": 0.0}], 3.0) == {"ok": False, "reason": "budget node at depth 0 insufficient (need 3, have 0)"}
    assert R.debit_consolidated_path([{"B": 1}], 3) == {"ok": False, "reason": "budget node at depth 0 insufficient (need 3, have 1)"}
    assert R.debit_consolidated_path([{"B": 0.0}], 1e20) == {"ok": False, "reason": "budget node at depth 0 insufficient (need 100000000000000000000, have 0)"}
    assert R.debit_consolidated_path([{"B": 1e21}], 2e21) == {"ok": False, "reason": "budget node at depth 0 insufficient (need 2e+21, have 1e+21)"}
    assert R.debit_consolidated_path([{"B": 1.0, "tau": 0}, {"B": 0.5, "tau": 0}], 0.5) == {"ok": True, "nodes": [{"B": 0.5, "tau": 0}, {"B": 0, "tau": 0}]}


# ---- plan_geodesic ---------------------------------------------------------------------------------------------------------------

def test_plan_geodesic_a_single_non_chain_edge_is_followed_not_the_index_fallback():
    plan = [node("a"), node("b"), node("c", pre="a")]
    assert R.plan_geodesic(plan, "a", "c") == 0.5
    assert R.plan_geodesic(plan, "c", "a") == 0.5
    assert R.plan_geodesic(plan, "a", "b") == 1
    assert R.plan_geodesic(plan, "b", "c") == 1
    assert R.plan_geodesic(plan, "a", "a") == 0


def test_plan_geodesic_a_post_edge_and_a_self_reference():
    plan = [node("a", post={"then": ["c"]}), node("b"), node("c")]
    assert R.plan_geodesic(plan, "a", "c") == 0.5
    # a node that only references itself is not an edge: the index fallback applies
    own = [node("a", pre="a"), node("b"), node("c")]
    assert R.plan_geodesic(own, "a", "c") == 1
    assert R.plan_geodesic(own, "a", "b") == 0.5


def test_plan_geodesic_unreachable_is_one_and_a_chain_is_normalized():
    plan = [node("a"), node("b", pre=["a"]), node("c"), node("d", pre={"after": "c"})]
    assert R.plan_geodesic(plan, "a", "b") == pytest.approx(1 / 3)
    assert R.plan_geodesic(plan, "a", "d") == 1
    assert R.plan_geodesic(plan, "c", "d") == pytest.approx(1 / 3)
    assert R.plan_geodesic(plan, "a", "zzz") == 1


# ---- riskier ---------------------------------------------------------------------------------------------------------------------

def test_riskier_per_input():
    a = {"taint": 0.2, "reversibility": 0.8, "confidence": 0.5, "age": 0.1, "blastRadius": 0.9}
    b = {"taint": 0.9, "reversibility": 0.3, "confidence": 0.7, "age": 0.05, "semanticDistance": 0.4, "blastRadius": 0.2}
    before = copy.deepcopy(a)
    assert R.riskier(a, b) == {"taint": 0.9, "reversibility": 0.3, "confidence": 0.5, "age": 0.1, "blastRadius": 0.9, "semanticDistance": 0.4}
    assert a == before
    assert R.riskier(b, a) == {"taint": 0.9, "reversibility": 0.3, "confidence": 0.5, "age": 0.1, "blastRadius": 0.9, "semanticDistance": 0.4}


def test_riskier_ignores_a_non_finite_b_value_and_does_not_stop_at_it():
    a = {"taint": 0.2}
    b = {"x": NAN, "y": None, "taint": 0.9, "z": "s", "w": True}
    assert R.riskier(a, b) == {"taint": 0.9}
    assert R.riskier({"taint": 0.2}, {"taint": NAN}) == {"taint": 0.2}
    assert R.riskier({"taint": NAN}, {"taint": 0.4}) == {"taint": 0.4}
    assert R.riskier({"taint": "bad"}, {"taint": 0.4}) == {"taint": 0.4}
    assert R.riskier({"reversibility": NAN}, {"reversibility": 0.4}) == {"reversibility": 0.4}
    assert R.riskier({"confidence": 0.4}, {"confidence": 0.4}) == {"confidence": 0.4}
    assert R.riskier({"taint": 0.9}, {"taint": 0.1}) == {"taint": 0.9}


def test_riskier_empty_and_missing_sides():
    assert R.riskier(None, None) is None
    assert R.riskier(None, {"taint": 1}) == {"taint": 1}
    assert R.riskier({"taint": 1}, None) == {"taint": 1}
    assert R.riskier({}, {"taint": 1}) == {"taint": 1}
    assert R.riskier({"taint": 1}, {}) == {"taint": 1}


# ---- decide_risk -----------------------------------------------------------------------------------------------------------------

def test_decide_risk_calm_reversible_release_is_admitted_and_optimistic():
    out = R.decide_risk(pol(), dict(CALM), bud(), 0, True, "reversible")
    assert out == {"r": 0, "release": True, "threshold": {"t": 1, "proof": "claim", "optimisticAllowed": True},
                   "admit": True, "needStepUp": False, "reasons": [], "budget": {"B": 1, "tau": 0, "asOf": 0}}


@pytest.mark.parametrize("cls", [None, "irreversible", "unknown", 7])
def test_decide_risk_an_unrecognized_class_is_never_optimistic(cls):
    out = R.decide_risk(pol(), dict(CALM), bud(), 0, True, cls)
    assert out["threshold"] == {"t": 1, "proof": "claim", "optimisticAllowed": False}
    assert out["admit"] is True and out["needStepUp"] is False


def test_decide_risk_release_false_never_admits_and_never_debits():
    risk = dict(CALM, blastRadius=0.5)
    out = R.decide_risk(pol(), risk, bud(), 0, False, "reversible")
    assert out["r"] == pytest.approx(0.1)
    assert out["release"] is False and out["admit"] is False and out["needStepUp"] is True
    assert out["budget"] == {"B": 1, "tau": 0, "asOf": 0}
    out = R.decide_risk(pol(), risk, bud(), 0, True, "reversible")
    assert out["admit"] is True and out["needStepUp"] is False
    assert out["budget"]["B"] == pytest.approx(0.9)


def test_decide_risk_mid_band_steps_up_and_debits_when_released():
    risk = dict(CALM, blastRadius=1, taint=1)
    out = R.decide_risk(pol(), risk, bud(), 0, True, "reversible")
    assert out["r"] == pytest.approx(0.4)
    assert out["threshold"] == {"t": 2, "proof": "standard", "optimisticAllowed": False}
    assert out["admit"] is False and out["needStepUp"] is True
    assert out["reasons"] == ["risk 0.400 exceeds auto threshold: step-up to t=2"]
    assert out["budget"]["B"] == pytest.approx(0.6)
    out = R.decide_risk(pol(), risk, bud(), 0, False, "reversible")
    assert out["budget"] == {"B": 1, "tau": 0, "asOf": 0} and out["needStepUp"] is True and out["admit"] is False


def test_decide_risk_worst_case_is_t3_never_debited_even_when_released():
    out = R.decide_risk(pol(), None, bud(), 0, True)
    assert out["r"] == pytest.approx(0.95)
    assert out["threshold"] == {"t": 3, "proof": "strong", "optimisticAllowed": False}
    assert out["admit"] is False and out["needStepUp"] is True
    assert out["reasons"] == [
        "risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence",
        "risk 0.950 exceeds auto threshold: step-up to t=3",
    ]
    assert out["budget"] == {"B": 1, "tau": 0, "asOf": 0}


def test_decide_risk_depleted_budget_forces_a_human_step_up_for_a_low_risk():
    out = R.decide_risk(pol(), dict(CALM, blastRadius=0.5), bud(0.05), 0, True, "reversible")
    assert out["threshold"] == {"t": 3, "proof": "strong", "optimisticAllowed": False}
    assert out["admit"] is False and out["needStepUp"] is True
    assert out["reasons"] == ["trust budget depleted: human recharge required"]
    assert out["budget"] == {"B": 0.05, "tau": 0, "asOf": 0}


def test_decide_risk_leaks_the_budget_up_to_now():
    # 1800 s at 0.0005/s drains 0.9; the age since the last human touch is half the default horizon
    out = R.decide_risk(pol(), {k: v for k, v in CALM.items() if k != "age"}, bud(), 1_800_000, True, "reversible")
    assert out["r"] == pytest.approx(0.025)
    assert out["admit"] is True
    assert out["budget"]["B"] == pytest.approx(0.1 - 0.025)
    assert out["budget"]["tau"] == 0 and out["budget"]["asOf"] == 1_800_000
    # the horizon argument is honoured; the default applies when it is None
    out = R.decide_risk(pol(), {k: v for k, v in CALM.items() if k != "age"}, bud(), 1_800_000, True, "reversible", age_horizon_ms=1_800_000)
    assert out["r"] == pytest.approx(0.05)
    out = R.decide_risk(pol(), {k: v for k, v in CALM.items() if k != "age"}, bud(), 1_800_000, True, "reversible", age_horizon_ms=None)
    assert out["r"] == pytest.approx(0.025)
    # an explicit finite age is used as given
    out = R.decide_risk(pol(), dict(CALM, age=1), bud(), 1_800_000, True, "reversible")
    assert out["r"] == pytest.approx(0.05)


def test_decide_risk_floor_is_clamped_to_one_and_ignored_when_negative_or_non_finite():
    assert R.decide_risk(pol(), dict(CALM), bud(), 0, True, "reversible", r_floor=0.5)["r"] == 0.5
    out = R.decide_risk(pol(), dict(CALM), bud(), 0, True, "reversible", r_floor=1.5)
    assert out["r"] == 1
    assert out["reasons"] == ["risk 1.000 exceeds auto threshold: step-up to t=3"]
    for bad in (-1, NAN, INF, None, True, "x"):
        assert R.decide_risk(pol(), dict(CALM), bud(), 0, True, "reversible", r_floor=bad)["r"] == 0


def test_decide_risk_plan_geodesic_fills_semantic_distance():
    plan = [node("a"), node("b"), node("c", pre="a")]
    calm = {k: v for k, v in CALM.items() if k != "semanticDistance"}
    out = R.decide_risk(pol(), calm, bud(), 0, True, "reversible", plan=plan, node_id="a")
    assert out["r"] == 0.125 and out["reasons"] == []
    out = R.decide_risk(pol(), calm, bud(), 0, True, "reversible", plan=plan, node_id="a", goal_node_id="c")
    assert out["r"] == 0.125 and out["reasons"] == []
    out = R.decide_risk(pol(), calm, bud(), 0, True, "reversible", plan=plan, node_id="a", goal_node_id="b")
    assert out["r"] == 0.25 and out["reasons"] == []
    out = R.decide_risk(pol(), calm, bud(), 0, True, "reversible", plan=plan, node_id="b", goal_node_id="a")
    assert out["r"] == 0.25
    # no node id, an empty plan or a non-list plan: the worst case, and not reported as missing
    for kw in ({"plan": plan}, {"plan": []}, {"plan": {}, "node_id": "a"}):
        out = R.decide_risk(pol(), calm, bud(), 0, True, "reversible", **kw)
        assert out["r"] == 0.25 and out["reasons"] == []
    # a supplied finite semantic distance wins over the plan
    out = R.decide_risk(pol(), dict(calm, semanticDistance=0), bud(), 0, True, "reversible", plan=plan, node_id="a", goal_node_id="b")
    assert out["r"] == 0
    # without a plan the missing distance is reported
    out = R.decide_risk(pol(), calm, bud(), 0, True, "reversible")
    assert out["reasons"][0] == "risk input(s) missing, assumed worst case: semanticDistance"


def test_decide_risk_a_plan_node_without_an_id_is_not_a_wildcard():
    # the goal defaults to the last node's id (None here): no geodesic is computed, the worst case applies
    plan = [node("a"), node("b"), node(None)]
    calm = {k: v for k, v in CALM.items() if k != "semanticDistance"}
    out = R.decide_risk(pol(), calm, bud(), 0, True, "reversible", plan=plan, node_id="b")
    assert out["r"] == 0.25
    plan2 = [node(None), node("b"), node("c")]
    out = R.decide_risk(pol(), calm, bud(), 0, True, "reversible", plan=plan2, goal_node_id="b")
    assert out["r"] == 0.25
