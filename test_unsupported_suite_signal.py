"""0.4.2 audit: the "unsupported suite" classification is a STRUCTURED signal, not a substring test.

A shape error that merely echoes an attacker-chosen member name (``unsupported_suite``) must collapse to "invalid", not
be reported as an unsupported-suite refusal; a genuinely unimplemented ``alg`` still surfaces ``unsupported_suite``.
"""
from atlas_pca import intent_v2 as iv

ROOT = "A" * 43  # canonical base64url of 32 zero-ish bytes is not needed: the shape check fails first


def test_member_named_unsupported_suite_is_invalid_for_key_set():
    k = {"unsupported_suite": 1}
    assert iv.sequencer_key_set_shape_error(k) == "key set: unknown member 'unsupported_suite'"
    assert iv.sequencer_key_set_error(k, ROOT) == "invalid"


def test_member_named_unsupported_suite_is_invalid_for_receipt():
    r = {"unsupported_suite": 1}
    assert iv.acc_receipt_shape_error(r) == "receipt: unknown member 'unsupported_suite'"
    assert iv.acc_receipt_signature_error(r, ROOT) == "invalid"


def test_plain_string_containing_marker_is_not_a_signal():
    assert iv._unsupported("key set: unknown member 'unsupported_suite'") is False
    assert iv._unsupported(None) is False


def test_real_unsupported_suite_keeps_the_signal_through_context():
    se = iv.suite_capability_error("no-such-suite")
    assert se == "unsupported_suite: 'no-such-suite'"
    assert iv._unsupported(se)
    assert iv._unsupported(iv._ctx("receipt.alg: ", se))
    assert not iv._unsupported(iv.suite_capability_error(7))  # malformed alg: not a suite-capability refusal
    assert iv._ctx("x: ", se) == "x: unsupported_suite: 'no-such-suite'"
