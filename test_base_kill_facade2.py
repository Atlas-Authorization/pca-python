"""The agent facade at its edges, pinned to the TypeScript reference (facade.ts, catalog.ts): UTF-16 limit length, the trim
set, zero and sub-unit caps, catalog aliases and leading dots, the uncatalogued fallback, rate windows, the budget model,
risk-policy merging, Number() coercion, the dry run's caveat context, act options, sub-agent and handle defaults.

Keys and handles are built inside each test: nothing from atlas_pca is called at import time."""
import math
import time

import pytest

from atlas_pca import facade
from atlas_pca.agent import KeyPair, keypair_from_seed
from atlas_pca.facade import (BUILTIN_ACTIONS, _Catalog, _risk_for, _spec_for, _to_number, compile_policy, create_agent,
                              parse_limit)
from atlas_pca.pca import canonicalize
from atlas_pca.risk import DEFAULT_RISK_POLICY

T0 = 1_000_000_000  # a fixed 1970 clock: a dry run that fell back to the real clock would see the grant expired
DAY = 86_400_000

CAT = [
    {"connector": "pay", "action": "send", "verb": "pay.send", "reversibility": "reversible", "blastRadius": 0.3,
     "amountField": "amount", "resource": "acct:*"},
    {"connector": "pay", "action": "void", "verb": "pay.void", "reversibility": "weird", "blastRadius": 0.7,
     "aliases": ["cancel", "undo"]},
    {"connector": "pay", "action": "undo2", "verb": "pay.undo2", "reversibility": "weird", "blastRadius": 0.7, "aliases": ["undo"]},
    {"connector": "c", "action": "a", "verb": "c.a", "reversibility": "rate_limited", "blastRadius": 0.4, "aliases": ["z"]},
    {"connector": "", "action": "a", "verb": ".a", "reversibility": "reversible", "blastRadius": 0.1, "aliases": ["x"]},
    {"connector": "solo", "action": "solo", "verb": "solo", "reversibility": "reversible", "blastRadius": 0.1},
    {"connector": "e", "action": "a", "verb": "e.a", "reversibility": "reversible", "blastRadius": 0.1, "resource": ""},
]


def _key(i):
    return keypair_from_seed(bytes([i]) * 32)


def _message(fn):
    with pytest.raises(ValueError) as e:
        fn()
    return str(e.value)


def _handle(**kw):
    args = dict(holder=_key(8), aud="rs", now=T0, goal_salt="salt")
    args.update(kw)
    return create_agent(_key(7), "reconcile", {"stripe": ["refund"], "github": ["read"]}, {"refund": "$100/day"}, **args)


# ---- parse_limit --------------------------------------------------------------------------------------------------------

def test_limit_length_counts_utf16_units():
    astral, bmp_max = "\U00010000", "￿"
    # 32 astral characters are 64 UTF-16 units: not too long, just unparseable
    s = astral * 32
    assert _message(lambda: parse_limit(s)) == "parseLimit: cannot parse limit '%s'" % s
    # 33 are 66 units: too long, whatever their Python length
    assert _message(lambda: parse_limit(astral * 33)) == "parseLimit: limit is longer than 64 characters"
    # U+FFFF is one unit
    s = bmp_max * 33
    assert _message(lambda: parse_limit(s)) == "parseLimit: cannot parse limit '%s'" % s
    # exactly 64 characters is allowed
    assert parse_limit("$" + "0" * 62 + "1") == {"amount": 1, "unit": "usd"}


def test_limit_trims_the_ecmascript_whitespace_set():
    assert parse_limit("﻿$5") == {"amount": 5, "unit": "usd"}


def test_limit_zero_and_fractions():
    assert parse_limit("0") == {"amount": 0, "unit": "count"}
    assert parse_limit("$0.5") == {"amount": 0.5, "unit": "usd"}


def test_limit_amount_is_an_int_up_to_max_safe():
    assert type(parse_limit("9007199254740991")["amount"]) is int
    assert type(parse_limit("9007199254740993")["amount"]) is float


@pytest.mark.parametrize("bad", [-1, math.inf, math.nan])
def test_limit_bad_amount_guard(monkeypatch, bad):
    # the grammar only yields finite non-negative amounts; the guard is the reference's backstop, observed through a seam
    monkeypatch.setattr(facade, "_js_num", lambda text: bad)
    assert _message(lambda: parse_limit("5")) == "parseLimit: bad amount in '5'"


# ---- catalog ------------------------------------------------------------------------------------------------------------

def _uncatalogued(connector, action, verb):
    return {"connector": connector, "action": action, "verb": verb, "reversibility": "irreversible", "blastRadius": 0.8,
            "description": "(uncatalogued) %s" % verb}


def test_catalog_resolve():
    b, c = _Catalog(BUILTIN_ACTIONS), _Catalog(CAT)
    assert b.resolve("stripe", "charge")["verb"] == "stripe.charge"  # exact, though "charge" is no alias
    assert b.resolve("stripe", "bill")["verb"] == "stripe.charge"  # the one alias hit
    assert b.resolve("gmail", "bill") is None  # an alias of another connector
    assert c.resolve("pay", "cancel")["verb"] == "pay.void"
    assert c.resolve("pay", "undo") is None  # two actions answer to it: never a guess


def test_spec_for():
    b, c = _Catalog(BUILTIN_ACTIONS), _Catalog(CAT)
    assert _spec_for(c, "solo") == CAT[5]  # a verb with no dot is still a catalog hit
    assert _spec_for(b, "stripe.issue_refund")["verb"] == "stripe.refund"
    assert _spec_for(c, "c.z")["verb"] == "c.a"  # a one-character connector
    assert _spec_for(c, ".x") == _uncatalogued("", "x", ".x")  # a leading dot names no connector: no alias lookup
    assert _spec_for(b, "x.y.z") == _uncatalogued("x", "y.z", "x.y.z")
    assert _spec_for(b, "nodot") == _uncatalogued("nodot", "nodot", "nodot")


# ---- compile_policy -----------------------------------------------------------------------------------------------------

def test_compile_without_now_uses_the_clock():
    before = int(time.time() * 1000)
    p = compile_policy({"stripe": ["refund"]}, {"refund": "$5/day"})
    after = int(time.time() * 1000)
    assert p["caveats"][1]["type"] == "expires"
    assert before + DAY <= p["caveats"][1]["at"] <= after + DAY


def test_compile_non_object_limits_are_no_limits():
    p = compile_policy({"stripe": ["refund"]}, [], now=T0)
    assert p["limits"] == {} and p["inputLimits"] == {}


def test_compile_resources_and_unknown_classes():
    p = compile_policy({"e": ["a"], "pay": ["send"]}, catalog=CAT, now=T0)
    # the catalog's resource is kept, even an empty one (the reference's `resource ?? '*'`)
    assert p["predicates"] == [{"verb": "e.a", "resource": ""}, {"verb": "pay.send", "resource": "acct:*"}]
    assert compile_policy({"pay": ["void"]}, catalog=CAT, now=T0)["caveats"] == [{"type": "reversibility_max", "class": "reversible"}]


def test_compile_rate_of_one_second():
    p = compile_policy({"github": ["read"]}, {"read": "5/s"}, now=T0)
    assert p["caveats"] == [{"type": "reversibility_max", "class": "reversible"}, {"type": "expires", "at": T0 + 1000},
                            {"type": "rate", "max": 5, "per_secs": 1}]


def test_compile_forced_dollars_model():
    p = compile_policy({"stripe": ["refund"]}, budget_model="dollars", now=T0)
    assert p["budgetModel"] == "dollars"
    assert p["riskPolicy"] == DEFAULT_RISK_POLICY


def test_compile_reversible_money_auto_approves_within_cap():
    p = compile_policy({"pay": ["send"]}, {"send": "$100"}, catalog=CAT, now=T0)
    assert p["riskPolicy"] == {"weights": {"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0},
                               "theta1": 1, "theta2": 1, "kappa": 100, "lambda": 0, "rho": 0.5, "bMax": 100}


def test_compile_zero_and_sub_unit_caps():
    rp = compile_policy({"stripe": ["refund"]}, {"refund": "$0"}, now=T0)["riskPolicy"]
    assert (rp["kappa"], rp["bMax"], rp["theta1"], rp["theta2"]) == (1, 1, 0.25, 0.6)
    rp = compile_policy({"stripe": ["refund"]}, {"refund": "$0.5"}, now=T0)["riskPolicy"]
    assert (rp["kappa"], rp["bMax"]) == (0.5, 0.5)


def test_compile_default_weights_are_a_copy():
    w = compile_policy({"github": ["read"]}, now=T0)["riskPolicy"]["weights"]
    assert w == DEFAULT_RISK_POLICY["weights"] and w is not DEFAULT_RISK_POLICY["weights"]


def test_compile_merges_partial_weights():
    p = compile_policy({"github": ["read"]}, risk_policy={"weights": {"alpha": 0.5}}, now=T0)
    assert p["riskPolicy"] == dict(DEFAULT_RISK_POLICY, weights=dict(DEFAULT_RISK_POLICY["weights"], alpha=0.5))


# ---- Number() and the risk claim ----------------------------------------------------------------------------------------

def test_to_number_is_ecmascript_number():
    def n(v):
        return _to_number({"a": v}, "a")
    assert (n("0x11"), n("0o17"), n("0b101")) == (17.0, 15.0, 5.0)
    assert n("Infinity") == math.inf and n("-Infinity") == -math.inf
    assert (n(None), n(True), n(False), n("5"), n([7])) == (0.0, 1.0, 0.0, 5.0, 7.0)
    assert math.isnan(n({})) and math.isnan(_to_number({}, "a"))


def test_risk_for_kappa_guard():
    spec = {"amountField": "amount", "blastRadius": 0.3}
    assert _risk_for({"budgetModel": "dollars", "riskPolicy": {"kappa": 0}}, spec, {"amount": 5}) == 0.3
    assert _risk_for({"budgetModel": "dollars", "riskPolicy": {"kappa": 0.5}}, spec, {"amount": 0.25}) == 0.5


# ---- the handle ---------------------------------------------------------------------------------------------------------

def test_handle_fields():
    h = _handle()
    assert h.budget == {"B": 100, "tau": T0, "asOf": T0}
    assert h.autonomy_bound == 100
    assert h.principal_public == _key(7).public and h.holder.public == _key(8).public
    assert h.goal_salt == "salt" and h._aud == "rs" and h._start_now == T0
    assert isinstance(h._catalog, _Catalog) and h.provenance is not None
    assert h.encode_grant() == canonicalize(h.grant)
    assert h.dry_run("stripe.refund", "c", {"amount": 5}, now=T0) == {"allowed": True, "t": 1}


def test_handle_without_now_uses_the_clock():
    before = int(time.time() * 1000)
    h = create_agent(_key(7), "g", {"stripe": ["refund"]}, {"refund": "$100/day"}, holder=_key(8))
    after = int(time.time() * 1000)
    assert before <= h.budget["tau"] == h.budget["asOf"] <= after
    h.policy["caveats"].append({"type": "not_before", "at": before})
    assert h.dry_run("stripe.refund", "c", {"amount": 5}) == {"allowed": True, "t": 1}


def test_create_agent_defaults_and_options():
    g = create_agent(_key(7), "g", {"github": ["read"]}, now=T0)
    assert isinstance(g.holder, KeyPair) and g.grant["holder"] == g.holder.public
    assert g.grant["caveats"][0]["agent_binding"] == {}
    b = create_agent(_key(7), "g", {"github": ["read"]}, holder=_key(8), now=T0, agent_binding={"model_id": "m1"})
    assert b.grant["caveats"][0]["agent_binding"] == {"model_id": "m1"}
    d = create_agent(_key(7), "g", {"stripe": ["refund"]}, holder=_key(8), now=T0, budget_model="dollars")
    assert d.policy["budgetModel"] == "dollars"
    r = create_agent(_key(7), "g", {"github": ["read"]}, holder=_key(8), now=T0, risk_policy={"theta1": 0.1})
    assert r.policy["riskPolicy"]["theta1"] == 0.1 and r.grant["caveats"][0]["risk_policy"]["theta1"] == 0.1


def test_create_agent_uses_the_given_catalog():
    h = create_agent(_key(7), "g", {"pay": ["send"]}, {"send": "$100"}, holder=_key(8), aud="rs", now=T0, catalog=CAT)
    assert h.policy["actions"] == [CAT[0]]
    assert h.dry_run("pay.send", "acct:1", {"amount": 5}, now=T0) == {"allowed": True, "t": 1}
    assert h.act("pay.send", "acct:1", {"amount": 5}, now=T0)["pcactn"]["action"]["reversibility_class"] == "reversible"


def test_act_options():
    h = _handle()
    a = h.act("stripe.refund", "c", {"amount": 5}, now=T0, ttl_ms=5000, caution=0.4, risk=0.3)
    p = a["pcactn"]
    assert (p["iat"], p["exp"]) == (T0, T0 + 5000)
    assert p["caution"] == 0.4
    assert p["risk_claim"] == {"r": 0.3, "inputs": {"blastRadius": 0.3}}
    assert a["dry_run"] == {"allowed": True, "t": 1}


def test_act_without_a_recorder():
    h = _handle()
    h.provenance = None
    a = h.act("github.read", "repo", now=T0)
    assert a["provenance"] is None and set(a["headers"]) == {"PCA-Action"}


def test_sub_agent_inherits_everything_but_the_holder():
    h = _handle()
    s = h.sub_agent()
    assert isinstance(s.holder, KeyPair) and s.holder.public != h.holder.public
    assert s.chain[-1]["holder"] == s.holder.public and len(s.chain) == 2
    assert s.grant is h.grant and s.policy is h.policy and s.goal_salt == h.goal_salt
    assert s.principal_public == h.principal_public and s._catalog is h._catalog and s._aud == h._aud
    assert s._start_now == T0 and s.budget == h.budget and s.provenance is h.provenance


# ---- the dry run --------------------------------------------------------------------------------------------------------

def test_dry_run_caveat_context():
    h = _handle()
    h.policy["caveats"].append({"type": "max_blast_radius", "max": 0.5})
    assert h.dry_run("github.read", "repo", now=T0) == {"allowed": True, "t": 1}
    assert h.dry_run("stripe.refund", "c", {"amount": 5}, now=T0 + 2 * DAY) == {
        "allowed": False, "reason": "caveat(s) failed: expires, max_blast_radius"}


def test_dry_run_delegation_depth():
    h = _handle()
    h.policy["caveats"].append({"type": "delegation_depth", "max": 0})
    assert h.dry_run("github.read", "repo", now=T0) == {"allowed": True, "t": 1}
    assert h.sub_agent(_key(9)).dry_run("github.read", "repo", now=T0) == {
        "allowed": False, "reason": "caveat(s) failed: delegation_depth"}


def test_dry_run_action_context():
    h = _handle()
    # absent params are an empty object (not "unavailable"), and the action carries the catalog's class
    h.policy["predicates"] = [{"verb": "github.read", "resource": "*", "where": [
        {"field": "action.params.note", "op": "exists", "value": False},
        {"field": "action.reversibility_class", "op": "eq", "value": "reversible"}]}]
    assert h.dry_run("github.read", "repo", now=T0) == {"allowed": True, "t": 1}


def test_dry_run_reason_fallback(monkeypatch):
    h = _handle()
    monkeypatch.setattr(facade, "evaluate_predicates", lambda predicates, ctx: {"allowed": False})
    assert h.dry_run("github.read", "repo", now=T0) == {"allowed": False, "reason": "no predicate matched"}
