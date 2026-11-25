"""The action diff compares JSON members with object keys sorted recursively (as the reference does): key order never matters, list order does."""
from atlas_pca import actions_diff as D


def test_reversed_keys_compare_equal_and_list_order_does_not():
    a = {"unit": {"b": 1, "a": {"y": [1, 2], "x": None}}, "id": {"q": "1", "p": "2"}}
    b = {"unit": {"a": {"x": None, "y": [1, 2]}, "b": 1}, "id": {"p": "2", "q": "1"}}
    assert D._sj(a, "unit") == D._sj(b, "unit") and D._js(a["id"]) == D._js(b["id"])
    assert D._js({"l": [1, 2]}) != D._js({"l": [2, 1]})
    assert D._js({"l": [{"b": 1, "a": 2}]}) == D._js({"l": [{"a": 2, "b": 1}]})
    assert D._sj({}, "unit") == "undefined"
