"""A lone surrogate in a failure message must never kill the xdist session (execnet cannot encode it): conftest escapes it in the report."""
import pytest


@pytest.mark.xfail(strict=True, reason="deliberate: the assertion text holds a lone surrogate; the session must survive and report it")
def test_a_failure_message_with_a_lone_surrogate_is_reported_not_fatal():
    got = "x\udc00"
    assert got == "y\udc00", "mismatch: %s" % got
