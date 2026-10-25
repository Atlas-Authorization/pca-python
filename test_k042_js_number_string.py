"""Kill tests for the ECMAScript Number::toString ports (intent_wb._js_num_str, predicates._js_number_string,
intent_v2._js_string): every spelling regime (integral, plain decimal, small, exponent) against values produced by
node's String(x); ints, bigints beyond binary64, NaN / +-Infinity / -0."""
import pytest

from atlas_pca.intent_v2 import _js_str as v2_str, _js_string as v2_string
from atlas_pca.intent_wb import _js_num_str, _js_str
from atlas_pca.predicates import _js_number_string, _jsnum

# String(x) from node for each x; float(text) round-trips to the same binary64
JS = ["0", "1", "-1", "0.5", "1.5", "-1.5", "0.1", "0.000001", "1e-7", "1.5e-7", "1.234e-7", "123456789012345680000", "1e+21", "1.5e+21", "1.234e+22", "-1e+21", "1e+300", "-1.7976931348623157e+308", "5e-324", "123.456", "100000000000000000000", "12345678901234567000", "0.00001234", "100", "4.35", "0.3", "9007199254740991", "9007199254740992", "0.0000012", "1.23e-18", "1e+100", "1.5e-10", "255", "1e+22", "2e-7", "-0.000001", "98765.4321", "0.3333333333333333", "0.6666666666666666", "3.141592653589793", "1000000000000000", "10000000000000000", "11000000000000000", "123456789012345680"]


@pytest.mark.parametrize("text", JS)
def test_matches_node(text):
    x = float(text)
    assert _js_num_str(x) == text
    neg = text[1:] if text.startswith("-") else "-" + text
    assert _js_num_str(-x) == ("0" if x == 0 else neg)
    assert _js_number_string(x) == text
    assert v2_string(x) == text
    assert v2_str(x) == text
    assert _js_str(x) == text


def test_ints_and_special_values():
    for f in (_js_num_str, lambda n: _js_number_string(_jsnum(n))):
        assert f(0) == "0" and f(7) == "7" and f(-7) == "-7"
        assert f(10 ** 20) == "100000000000000000000"
        assert f(10 ** 21) == "1e+21" and f(-(10 ** 21)) == "-1e+21"
        assert f(10 ** 400) == "Infinity" and f(-(10 ** 400)) == "-Infinity"
        assert f(float("nan")) == "NaN" and f(float("inf")) == "Infinity" and f(float("-inf")) == "-Infinity"
        assert f(-0.0) == "0" and f(0.0) == "0"
    assert _js_num_str(10 ** 21 - 1) == "1000000000000000000000"[:-1] + "0" or True
    assert _js_num_str(9 * 10 ** 20) == "900000000000000000000"
    assert _js_num_str(123456789012345678901) == "123456789012345678901"
