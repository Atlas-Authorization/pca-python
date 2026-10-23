"""Kill tests for atlas_pca.intent_wb helpers: String() of JSON values, Object.keys order at the index limit, strict scalar
equality, safe-integer bounds, ranks, UTF-8 key order, nested sets, subjects, and the fail-closed provenance fallback."""
import itertools

import pytest

import atlas_pca.intent_wb as W
import test_mutation_kill_intent_wb as T

U = W._UNDEF


def u(*parts):
    return "".join(chr(p) if isinstance(p, int) else p for p in parts)


def test_js_str_of_json_values():
    assert W._js_str(True) == "true" and W._js_str(False) == "false"
    assert W._js_str(None) == "null" and W._js_str(U) == "undefined"
    assert W._js_str([]) == "" and W._js_str([1]) == "1" and W._js_str([1, 2]) == "1,2"
    assert W._js_str([None, 1, U, "a", True, False, [2, [3]]]) == ",1,,a,true,false,2,3"
    assert W._js_str([None]) == "" and W._js_str([None, None]) == ","
    assert W._js_str({}) == "[object Object]" and W._js_str([{}]) == "[object Object]"
    assert W._js_str({"a": 1}) == "[object Object]"
    assert W._js_str(1.5) == "1.5" and W._js_str(-0.0) == "0" and W._js_str(10 ** 21) == "1e+21"


def test_js_keys_order():
    assert W._js_keys({"b": 1, "10": 2, "9": 3, "a": 4}) == ["9", "10", "b", "a"]
    assert W._js_keys({"x": 0, "4294967295": 1, "4294967294": 2, "01": 3, "0": 4}) == ["0", "4294967294", "x", "4294967295", "01"]


VALUES = [None, True, False, 0, 1, 1.0, "a", "", "1", [], {}, U]


def test_scalar_eq_over_every_pair():
    for a, b in itertools.product(VALUES, VALUES):
        if a is U or b is U:
            want = a is b
        elif a is None or b is None:
            want = a is None and b is None
        elif isinstance(a, bool) or isinstance(b, bool):
            want = isinstance(a, bool) and isinstance(b, bool) and a == b
        elif isinstance(a, (int, float)) or isinstance(b, (int, float)):
            want = isinstance(a, (int, float)) and isinstance(b, (int, float)) and a == b
        elif isinstance(a, str) or isinstance(b, str):
            want = isinstance(a, str) and isinstance(b, str) and a == b
        else:
            want = a is b
        assert W.scalar_eq(a, b) is want, (a, b)
    x = {}
    assert W.scalar_eq(x, x) is True and W.scalar_eq({}, {}) is False


def test_defaults_and_small_helpers():
    assert W._dflt(None, 5) == 5 and W._dflt(U, 5) == 5 and W._dflt(0, 5) == 0 and W._dflt(False, 5) is False
    assert W._utf16_len("ab") == 2 and type(W._utf16_len("ab")) is int and W._utf16_len(u(0x10000)) == 2
    assert W._is_safe_int(2 ** 53 - 1) is True and W._is_safe_int(2 ** 53) is False and W._is_safe_int(-(2 ** 53 - 1)) is True
    assert W._is_safe_int(-0.0) is False and W._is_safe_int(0.0) is True and W._is_safe_int(1.5) is False
    assert W._is_safe_int(True) is False and W._is_safe_int(float("inf")) is False
    assert W._is_safe_int(float(2 ** 53 - 1)) is True and W._is_safe_int(float(2 ** 53)) is False
    assert W._is_safe_int(-float(2 ** 53 - 1)) is True and W._is_safe_int(-float(2 ** 53)) is False
    assert W._rank("agent") == 4 and W._rank("trusted") == 0 and W._rank("web") == 3
    for bad in ("nope", None, 3, [], U):
        assert W._rank(bad) == 4, bad


def test_sorted_utf8_orders_lone_surrogates_by_their_replacement():
    lone, bmp = u(0xD800), u(0xE000)
    assert W._sorted_utf8([lone, bmp]) == [bmp, lone]  # a lone surrogate encodes as U+FFFD (EF BF BD) > U+E000 (EE 80 80)
    assert W._sorted_utf8(["b", "a", "B"]) == ["B", "a", "b"]
    assert W._sorted_utf8([u(0xFFFF), u(0x10000)]) == [u(0xFFFF), u(0x10000)]


def test_set_nested():
    root = {"a": {"b": 1}}
    assert W._set_nested(root, "a.b", 2) is False and root == {"a": {"b": 1}}
    assert W._set_nested(root, "a.c", 2) is True and root == {"a": {"b": 1, "c": 2}}
    assert W._set_nested(root, "a.b.d", 2) is False
    assert W._set_nested(root, "x.y.z", 3) is True and root["x"] == {"y": {"z": 3}}
    assert W._set_nested(root, "a", 5) is False


def test_subject_of_requires_a_string():
    assert W._subject_of({"resource": "r", "verb": "v"}, {}, "action.resource") == "r"
    assert W._subject_of({"resource": "r", "verb": "v"}, {}, "action.verb") == "v"
    for bad in (5, None, ["x"], {"a": 1}, True):
        assert W._subject_of({"resource": bad, "verb": bad}, {}, "action.resource") is None, bad
        assert W._subject_of({"resource": bad, "verb": bad}, {}, "action.verb") is None, bad
    assert W._subject_of({}, {}, "action.verb") is None
    assert W._subject_of({}, {"p": "x"}, "action.params.p") == "x"
    assert W._subject_of({}, {"p": 5}, "action.params.p") is None


def test_an_invalid_supplied_fact_does_not_stop_the_scan():
    pol = {"worlds": [T.fare_world()]}
    good = T.three()
    for bad in (5, "x", None, {"v": 1}, []):
        r = W.decide_intent_world(T.W(good, pol, facts=[bad] + good))
        assert T.ok_world(r) == {"fare": 39_800}, bad


def test_provenance_internal_error_is_a_denial(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")

    assert W.decide_param_provenance(T.P())["outcome"] == "pass"
    monkeypatch.setattr(W, "resolve_param_path", boom)
    r = W.decide_param_provenance(T.P())
    assert r["outcome"] == "deny" and r["reason"] == "provenance: evaluation error (fail closed): boom"
    assert r["env"] == {} and set(r) == {"outcome", "reason", "labels", "classes", "env"}
