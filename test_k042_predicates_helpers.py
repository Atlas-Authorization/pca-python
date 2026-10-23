"""Kill tests for the predicate-DSL helpers: String(x) of JSON values (predicates._js_string), the canonical-equality
walk (_jeq / _deep_eq / _canonicalizable: type pairs, depth cap, key-collision rule), UTF-8 string order with lone
surrogates (_order_utf8 / _ordered) and units_have_lone_surrogate boundaries; wb._js_str spellings."""
import pytest

from atlas_pca.intent_wb import _js_str as wb_js_str, _UNDEF as WB_UNDEF
from atlas_pca.predicates import (
    _NotCanonical, _canonicalizable, _deep_eq, _jeq, _js_string, _order_utf8, _ordered, _UNDEF,
)
from atlas_pca.safe_regex import units_have_lone_surrogate

INF = float("inf")


# ---- _js_string / wb._js_str -------------------------------------------------------------------------------------------

def test_js_string_spellings():
    assert _js_string(True) == "true" and _js_string(False) == "false"
    assert _js_string(None) == "null" and _js_string(_UNDEF) == "undefined"
    assert _js_string({}) == "[object Object]" and _js_string([]) == ""
    assert _js_string([1, None, "a", [True, [False]]]) == "1,,a,true,false"
    assert _js_string([[1, 2], 3]) == "1,2,3"


def _nest(n):
    x = 1
    for _ in range(n):
        x = [x]
    return x


def test_js_string_nesting_cap():
    assert _js_string(_nest(65)) == "1"  # a list at depth 64 is allowed, one at depth 65 is not
    with pytest.raises(ValueError) as e:
        _js_string(_nest(66))
    assert str(e.value) == "String(): nesting too deep"
    assert _js_string([_nest(64)]) == "1"
    with pytest.raises(ValueError):
        _js_string([_nest(65)])


def test_wb_js_str_spellings():
    f = wb_js_str
    assert f(True) == "true" and f(False) == "false" and f(None) == "null" and f(WB_UNDEF) == "undefined"
    assert f({}) == "[object Object]" and f({"a": [1]}) == "[object Object]"
    assert f([]) == "" and f([1, 2]) == "1,2" and f(["a", None, "b"]) == "a,,b"
    assert f([None]) == "" and f([WB_UNDEF, 1]) == ",1"
    assert f([[1, [2]], True]) == "1,2,true"
    assert f([{}]) == "[object Object]"
    assert f(3) == "3" and f(1.5) == "1.5" and f("x") == "x"


# ---- canonical equality -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("a,b,want", [
    (None, None, True), (None, 0, False), (0, None, False), (None, False, False), (None, "", False), (None, [], False),
    (True, True, True), (False, False, True), (True, False, False), (True, 1, False), (1, True, False), (0, False, False),
    (False, 0, False), (1, 1, True), (1, 1.0, True), (1, 2, False), (-0.0, 0, True), (1, "1", False), ("1", 1, False),
    ("a", "a", True), ("a", "b", False), ("a", 1, False), (1, "a", False), ("", "", True), ("\ud800", "\ud800", True),
    ("\U0001F600", chr(0xD83D) + chr(0xDE00), True),
    ([], [], True), ([1], [1], True), ([1], [2], False), ([1], [1, 1], False), ([[1]], [[1]], True), ([1, 2], [2, 1], False),
    ({}, {}, True), ({"a": 1}, {"a": 1}, True), ({"a": 1}, {"a": 2}, False), ({"a": 1}, {"b": 1}, False),
    ({"a": 1, "b": 2}, {"b": 2, "a": 1}, True), ({"a": 1}, {"a": 1, "b": 2}, False), ({"a": 1, "b": 2}, {"a": 1}, False),
    ([], {}, False), ({}, [], False), ([1], {"0": 1}, False), ({"0": 1}, [1], False),
    ({"a": {"b": [1, {"c": None}]}}, {"a": {"b": [1, {"c": None}]}}, True),
    ({"a": {"b": [1, {"c": None}]}}, {"a": {"b": [1, {"c": 0}]}}, False),
    (INF, INF, False), (1, INF, False), (INF, 1, False), (-INF, -INF, False), ([INF], [INF], False), ({"a": INF}, {"a": INF}, False),
    ([1, INF], [1, 2], False), ([1, 2], [1, INF], False),
    ({1: 1}, {1: 1}, False), (object(), object(), False),
])
def test_deep_eq(a, b, want):
    assert _deep_eq(a, b) is want


def test_deep_eq_key_collision_by_utf16_units():
    pair, astral = chr(0xD83D) + chr(0xDE00), "\U0001F600"  # two keys with the same UTF-16 units
    two = {pair: 1, astral: 2}
    assert _deep_eq(two, {astral: 2}) is False
    assert _deep_eq({astral: 2}, two) is False
    assert _deep_eq(two, two) is False
    assert _deep_eq({pair: 1}, {astral: 1}) is True


def test_jeq_raises_for_non_finite_on_either_side_and_unsupported():
    for a, b in [(INF, 1), (1, INF), (-INF, "x"), ("x", INF), (INF, None), (None, INF), (INF, [1]), ([1], INF), (INF, {}), ({}, INF)]:
        with pytest.raises(_NotCanonical):
            _jeq(a, b, 0)
    for a, b in [(object(), 1), (1, object()), (object(), "a"), (("a",), {}), ({}, ("a",))]:
        try:
            _jeq(a, b, 0)
        except _NotCanonical:
            pass


def test_jeq_depth_cap():
    assert _jeq(1, 1, 10_000) is True
    with pytest.raises(_NotCanonical):
        _jeq(1, 1, 10_001)
    assert _jeq([1], [1], 9_998) is True
    assert _jeq([1], [1], 9_999) is True
    with pytest.raises(_NotCanonical):
        _jeq([1], [1], 10_000)
    assert _jeq({"a": 1}, {"a": 1}, 9_999) is True
    with pytest.raises(_NotCanonical):
        _jeq({"a": 1}, {"a": 1}, 10_000)


@pytest.mark.parametrize("v,want", [
    (None, True), (True, True), ("s", True), (1, True), (1.5, True), (INF, False), (-INF, False), (float("nan"), False),
    (10 ** 400, False), ([], True), ({}, True), ({"a": 1}, True), ({1: 1}, False), (object(), False), (b"x", False),
    ([INF, None], False), ([INF, True], False), ([INF, "s"], False), ([INF, 1], False), ([INF, [1]], False),
    ([INF, {"a": 1}], False), ([INF, []], False), ({"a": INF, "b": None}, False), ({"a": INF, "b": "s"}, False),
    ({"a": INF, "b": 1}, False), ({"a": INF, "b": [1]}, False), ({"a": INF, "b": {}}, False), ({"a": INF, "b": True}, False),
    ({1: 1, "b": None}, False), ({"b": None, 1: 1}, False), ([object(), None], False), ([None, object()], False),
    ([[1, [2, {"a": [3]}]]], True), ({"a": [{"b": {"c": [None, True, "x", 1]}}]}, True),
])
def test_canonicalizable(v, want):
    assert _canonicalizable(v) is want


def test_canonicalizable_depth_cap():
    assert _canonicalizable(_nest(10_000)) is True
    assert _canonicalizable(_nest(10_001)) is False
    d = {"a": 1}
    for _ in range(10_000):
        d = {"a": d}
    assert _canonicalizable(d) is False
    d = {"a": 1}
    for _ in range(9_998):
        d = {"a": d}
    assert _canonicalizable(d) is True


# ---- string order ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("a,b,want", [
    ("a", "a", 0), ("", "", 0), ("a", "b", -1), ("b", "a", 1), ("a", "ab", -1), ("ab", "a", 1), ("Z", "a", -1),
    ("\U0001F600", "￿", 1), ("￿", "\U0001F600", -1), ("é", "z", 1),
    ("\ud800", "a", None), ("a", "\ud800", None), ("\ud800", "\ud800", None), ("\udc00", "x", None), ("x", "\udc00", None),
    ("😀", "\U0001F600", 0),
])
def test_order_utf8(a, b, want):
    assert _order_utf8(a, b) == want


def test_ordered():
    assert _ordered(1, 2) == -1 and _ordered(2, 1) == 1 and _ordered(2, 2.0) == 0
    assert _ordered("a", "b") == -1 and _ordered("b", "a") == 1
    assert _ordered(1, "a") is None and _ordered("a", 1) is None and _ordered(True, 1) is None
    assert _ordered(INF, 1) is None and _ordered(1, INF) is None and _ordered(None, None) is None


@pytest.mark.parametrize("u,want", [
    ("", False), ("a", False), ("퟿", False), ("\ud800", True), ("\udbff", True), ("\udc00", True), ("\udfff", True),
    ("", False), ("😀", False), ("𐀀", False), ("􏿿", False),
    ("\ud83d\ud83d", True), ("\ud83d😀", True), ("a\ud83d", True), ("\ud83da", True), ("\ude00\ud83d", True),
    ("😀\ud83d", True), ("😀\ude00", True), ("😀😀", False), ("\ud83d퟿", True),
    ("\ud83d", True), ("\ude00", True), ("a\ude00", True),
])
def test_units_have_lone_surrogate(u, want):
    assert units_have_lone_surrogate(u) is want
