"""Kill tests for atlas_pca.predicates: structural equality over mixed types, the fail-closed fallbacks, `not` chains that
carry a grouping member, path walking through scalars and the glob tokeniser."""
import itertools

import pytest

from atlas_pca import predicates as P

VALUES = [None, True, False, 0, 1, 1.0, "a", "", [], [1], [[]], {}, {"a": 1}, {"a": [1]}]


def _same(a, b):
    """Reference for canonical equality of two JSON values (type-strict, 1 == 1.0)."""
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) or isinstance(b, (int, float)):
        return isinstance(a, (int, float)) and isinstance(b, (int, float)) and a == b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_same(a[k], b[k]) for k in a)
    return False


def test_jeq_over_every_pair_of_json_types_never_raises():
    for a, b in itertools.product(VALUES, VALUES):
        assert P._jeq(a, b, 0) is _same(a, b), (a, b)
        assert P._deep_eq(a, b) is _same(a, b), (a, b)


def test_jeq_refuses_an_unsupported_type_and_a_non_finite_number():
    for a in ([], {}, [1], {"a": 1}):
        with pytest.raises(P._NotCanonical):
            P._jeq(a, object(), 0)
        with pytest.raises(P._NotCanonical):
            P._jeq(object(), a, 0)
    with pytest.raises(P._NotCanonical):
        P._jeq(1, float("inf"), 0)
    assert P._deep_eq([object()], [object()]) is False
    assert P._deep_eq([float("inf")], [1]) is False and P._deep_eq([1], [float("inf")]) is False


def test_error_fallbacks_are_exact(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("x")

    err = {"allowed": False, "reason": "predicate evaluation error (fail closed)"}
    monkeypatch.setattr(P, "predicate_matches", boom)
    assert P.evaluate_predicates([{"verb": "*"}], {}) == err
    monkeypatch.undo()
    monkeypatch.setattr(P, "with_regex_budget", boom)
    assert P.evaluate_predicates([{"verb": "*"}], {}) == err
    assert P.predicate_matches({"verb": "*"}, {"action": {"verb": "a", "resource": "b"}}) is False
    assert P.evaluate_condition_tri({"field": "action.verb", "op": "exists"}, {}) == "unknown"
    monkeypatch.undo()
    monkeypatch.setattr(P, "_resolve", boom)
    assert P.resolve_path({}, "action") == {"found": False}


def test_a_non_group_array_condition_is_unknown():
    assert P.evaluate_condition_tri([1], {}) == "unknown"
    assert P.evaluate_condition_tri([], {}) == "unknown"


def test_not_chain_stops_at_a_grouping_member():
    t = {"field": "action.verb", "op": "eq", "value": "x"}
    ctx = {"action": {"verb": "x", "resource": "r"}}
    assert P.evaluate_condition_tri(t, ctx) == "true"
    assert P.evaluate_condition_tri({"not": {"all_of": [t], "not": t}}, ctx) == "false"
    assert P.evaluate_condition_tri({"not": {"any_of": [t], "not": t}}, ctx) == "false"
    assert P.evaluate_condition_tri({"not": {"not": {"all_of": [t], "not": t}}}, ctx) == "true"
    assert P.evaluate_condition_tri({"not": {"not": t}}, ctx) == "true"
    assert P.evaluate_condition_tri({"not": {"not": {"not": t}}}, ctx) == "false"


def test_resolve_through_scalars_and_bad_paths():
    ctx = {"action": {"verb": "v", "n": 5, "z": None, "list": [1]}}
    assert P._resolve(ctx, 5) == (False, None)
    assert P._resolve(ctx, None) == (False, None)
    assert P._resolve(ctx, "") == (False, None)
    for p in ("action.verb.x", "action.n.x", "action.z.x", "action.list.x", "action.list.1", "action.list.0.x"):
        assert P._resolve(ctx, p) == (False, None), p
    assert P._resolve(ctx, "action.list.0") == (True, 1)
    assert P._resolve(ctx, "action.n") == (True, 5)
    assert P._resolve(ctx, "action.z") == (True, None)


def test_glob_tokeniser():
    assert P._parse_glob("a*?\\*") == [("lit", "a"), ("star",), ("one",), ("lit", "*")]
    assert P._parse_glob("a**b") == [("lit", "a"), ("star",), ("lit", "b")]
    assert P._parse_glob("\\") is None and P._parse_glob("a\\") is None
    assert P._parse_glob("\\?") == [("lit", "?")]
    assert P._parse_glob("") == []


def test_a_leaf_that_raises_is_unknown(monkeypatch):
    def boom(c, ctx):
        raise RuntimeError("x")

    monkeypatch.setattr(P, "_tri_leaf", boom)
    assert P._evaluate_condition_tri_inner({"field": "action.verb", "op": "exists"}, {}) == "unknown"
    assert P.evaluate_condition_tri({"all_of": [{"field": "action.verb", "op": "exists"}]}, {}) == "unknown"


def test_canonical_equality_distinguishes_keys_that_collapse_to_one_unit_sequence():
    astral = chr(0x10000)
    pair = chr(0xD800) + chr(0xDC00)  # the same UTF-16 units as the astral character
    assert P._jeq({astral: 1, pair: 1}, {astral: 1}, 0) is False
    assert P._jeq({astral: 1}, {astral: 1, pair: 1}, 0) is False
    assert P._jeq({astral: 1}, {pair: 1}, 0) is True
    assert P._deep_eq({astral: 1, pair: 1}, {astral: 1}) is False


def test_jeq_refuses_a_non_finite_number_on_either_side():
    with pytest.raises(P._NotCanonical):
        P._jeq(float("inf"), 1, 0)
    with pytest.raises(P._NotCanonical):
        P._jeq(float("-inf"), "x", 0)
    with pytest.raises(P._NotCanonical):
        P._jeq(10 ** 400, 1, 0)
