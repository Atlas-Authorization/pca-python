"""Kill tests for the string-returning `*_error` twins of the rule-15 / rule-13 verifiers (acc_receipt_signature_error,
sequencer_key_set_error, receipt_against_holder_error): over every case of the shared intent-acc oracle the twin returns
None exactly when the boolean verifier accepts, "invalid" when it refuses, or an `unsupported_suite` reason when the
suite is not available on this host."""
import json
import os

import pytest

from atlas_pca import intent_v2 as V

with open(os.path.join(os.path.dirname(__file__), "testdata", "k042-intentacc.json"), encoding="utf-8") as fh:
    CASES = json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))


def _cases(fn):
    return [c for c in CASES if c["fn"] == fn]


def _check(res, want_ok):
    # an accepting case signed under a PQ / hybrid suite is refused with unsupported_suite where the suite is missing
    if isinstance(res, str) and "unsupported_suite" in res:
        pytest.skip("suite unavailable on this host")
    if want_ok:
        assert res is None
    else:
        assert res == "invalid"


def _args(c):
    return json.loads(json.dumps(c["args"]))


@pytest.mark.parametrize("c", _cases("verifyReceiptSignature"), ids=[c["name"] for c in _cases("verifyReceiptSignature")])
def test_receipt_signature_error(c):
    a = _args(c)
    res = V.acc_receipt_signature_error(a[0], a[1], a[2])
    _check(res, c["out"] is True)
    assert V.verify_acc_receipt_signature(a[0], a[1], a[2]) is (res is None)


@pytest.mark.parametrize("c", _cases("verifyKeySet"), ids=[c["name"] for c in _cases("verifyKeySet")])
def test_key_set_error(c):
    a = _args(c)
    res = V.sequencer_key_set_error(a[0], a[1], a[2] if a[3] else None)
    _check(res, c["out"] is True)


@pytest.mark.parametrize("c", _cases("verifyReceiptAgainstHolder"), ids=[c["name"] for c in _cases("verifyReceiptAgainstHolder")])
def test_receipt_against_holder_error(c):
    a = _args(c)
    res = V.receipt_against_holder_error(a[0], a[1], a[2], a[3], a[4], a[5], None, a[6])
    _check(res, c["out"] is True)


def _ok_case():
    c = next(c for c in _cases("verifyReceiptAgainstHolder") if c["name"] == "verifyReceiptAgainstHolder/ok")
    return _args(c)


def test_holder_error_exceptions_and_invalid_inputs():
    a = _ok_case()
    r, holder, ks, now = a[0], a[1], a[2], a[3]
    assert V.receipt_against_holder_error(r, holder, ks, now) is None
    assert V.receipt_against_holder_error(r, None, ks, now) == "invalid"
    assert V.receipt_against_holder_error(r, {}, ks, now) == "invalid"
    assert V.receipt_against_holder_error(r, holder, "x", now) == "invalid"
    assert V.receipt_against_holder_error(r, holder, ks, "x") == "invalid"
    assert V.receipt_against_holder_error({}, holder, ks, now) == "invalid"
    assert V.receipt_against_holder_error(r, holder, [], now) == "invalid"
    assert V.receipt_against_holder_error(r, holder, ks, now, max_receipt_age_ms=-1) == "invalid"
    assert V.receipt_against_holder_error(r, holder, ks, now + 10 ** 9) == "invalid"  # stale receipt
    assert V.receipt_against_holder_error(r, holder, ks, now - 10 ** 6) == "invalid"  # issued in the future


def test_holder_error_reports_the_first_unsupported_suite():
    a = _ok_case()
    r, holder, ks, now = a[0], a[1], a[2], a[3]
    good = ks[0]
    bad1 = dict(good, alg="fn-dsa-512")
    bad2 = dict(good, alg="fn-dsa-1024")
    res = V.receipt_against_holder_error(r, holder, [bad1, bad2], now)
    assert "unsupported_suite" in res and "fn-dsa-512" in res and "fn-dsa-1024" not in res
    res = V.receipt_against_holder_error(r, holder, [bad2, bad1], now)
    assert "fn-dsa-1024" in res and "fn-dsa-512" not in res
    assert V.receipt_against_holder_error(r, holder, [bad1, good], now) is None  # a later verifying set wins
    assert V.receipt_against_holder_error(r, holder, [good, bad1], now) is None
