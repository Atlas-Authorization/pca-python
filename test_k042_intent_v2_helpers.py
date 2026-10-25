"""Unit tests (every branch) of the JS-semantics helpers of atlas_pca.intent_v2: `_js_string` (`String(x)` of a JSON value or
undefined: exact, it feeds the verb / resource / aud decisions), `_js_str` (the reason-text spelling, which must agree with it)
and `_action_member` (`p.action?.<k>`)."""
import math

import pytest

from atlas_pca.intent_v2 import _UNDEF, _action_member, _js_str, _js_string


@pytest.mark.parametrize("x,want", [
    (_UNDEF, "undefined"),                      # absent
    (None, "null"),
    (True, "true"),
    (False, "false"),
    ("", ""),
    ("abc", "abc"),
    (0, "0"),
    (-0.0, "0"),
    (7, "7"),
    (-3, "-3"),
    (1.5, "1.5"),
    (1e21, "1e+21"),
    (float("nan"), "NaN"),                      # NaN
    (float("inf"), "Infinity"),                 # +Infinity
    (float("-inf"), "-Infinity"),               # -Infinity
    ({}, "[object Object]"),                    # dict
    ({"a": 1}, "[object Object]"),
    ([], ""),                                   # list
    ([1], "1"),
    ([1, 2], "1,2"),
    (["a", "b"], "a,b"),
    ([None], ""),                               # null / undefined elements are empty
    ([_UNDEF], ""),
    ([None, 1, None], ",1,"),
    ([[1, 2], 3], "1,2,3"),                     # nested lists flatten like Array.prototype.join
    ([[]], ""),
    ([float("nan"), float("inf"), float("-inf")], "NaN,Infinity,-Infinity"),
    ([{}, True, False], "[object Object],true,false"),
    ([1, [None, "x"]], "1,,x"),
])
def test_js_string(x, want):
    assert _js_string(x) == want


@pytest.mark.parametrize("x", [
    _UNDEF, None, True, False, "s", 0, 7, 1.5, float("nan"), float("inf"), float("-inf"), {}, {"a": 1}, [], [1, 2],
    [None, "x"], ["a", ["b", float("nan")]],
])
def test_js_str_agrees_with_js_string(x):
    assert _js_str(x) == _js_string(x)


def test_js_string_distinguishes_the_boolean_from_the_number():
    assert _js_string(True) == "true" and _js_string(1) == "1"
    assert _js_string(False) == "false" and _js_string(0) == "0"


def test_action_member_present():
    p = {"action": {"verb": "v", "resource": None, "params_digest": 0}}
    assert _action_member(p, "verb") == "v"
    assert _action_member(p, "resource") is None  # a present null is null, not undefined
    assert _action_member(p, "params_digest") == 0
    assert _action_member(p, "absent") is _UNDEF


@pytest.mark.parametrize("p", [
    {}, {"action": None}, {"action": 5}, {"action": "x"}, {"action": []}, {"action": [1]}, {"action": True},
    None, 5, "x", [], [{"verb": "v"}], _UNDEF,
])
def test_action_member_without_an_action_object_is_undefined(p):
    assert _action_member(p, "verb") is _UNDEF


def test_action_member_reads_only_own_members_of_the_action():
    assert _action_member({"verb": "top"}, "verb") is _UNDEF  # `verb` is not read from the PCActn itself
    assert _action_member({"action": {"verb": "v"}}, "resource") is _UNDEF
