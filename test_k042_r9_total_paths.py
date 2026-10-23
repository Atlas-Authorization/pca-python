"""Kill tests (0.4.2 r9): the `except Exception` totality arms and one guard of the Python verifier, hit by fault injection
(a dict subclass whose accessors raise) and by a nesting depth past CPython's recursion limit. Each verdict is the closed one."""
import pytest

from atlas_pca import intent_v2 as V
from atlas_pca.predicates import _deep_eq, _predicate_matches_inner, is_safe_regex_source


class Boom(dict):
    """A JSON object (isinstance dict) whose every read raises: a verifier that is `total` must answer closed."""

    def get(self, *a, **k):
        raise RuntimeError("boom")

    def __contains__(self, k):
        raise RuntimeError("boom")

    def __getitem__(self, k):
        raise RuntimeError("boom")

    def __iter__(self):
        raise RuntimeError("boom")


def test_is_safe_regex_source_refuses_every_non_string():
    for v in (None, 5, 1.5, True, b"a", ["a"], {"a": 1}):
        assert is_safe_regex_source(v) is False
    assert is_safe_regex_source("a") is True


def test_verify_non_membership_total_on_a_raising_proof():
    assert V.verify_non_membership("root", Boom(size=0), "x") is False
    assert V.verify_non_membership(None, Boom(), "x") is False


def test_deep_eq_past_the_recursion_limit_is_false():
    def nest(n):
        x = []
        for _ in range(n):
            x = [x]
        return x

    assert _deep_eq(nest(20), nest(20)) is True
    assert _deep_eq(nest(5000), nest(5000)) is False  # RecursionError in the comparison: the closed answer


def test_predicate_matches_inner_total_on_a_raising_context():
    p = {"verb": "read", "resource": "/r"}
    assert _predicate_matches_inner(p, {"action": {"verb": "read", "resource": "/r"}}) is True
    assert _predicate_matches_inner(p, {"action": Boom(verb="read", resource="/r")}) is False
    assert _predicate_matches_inner(Boom(verb="read"), {"action": {"verb": "read", "resource": "/r"}}) is False


def test_pinned_suite_error_total_when_the_suite_dispatch_raises(monkeypatch):
    """verify_leaf_suite is itself total, so the arm is reached by injecting a fault into it: the verdict is still closed."""
    U = V._UNDEF
    assert V._pinned_suite_error("ed25519", "id", U, b"m", "AAAA", U, None) == "invalid"

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(V, "verify_leaf_suite", boom)
    assert V._pinned_suite_error("ed25519", "id", U, b"m", "AAAA", U, None) == "invalid"


def test_is_safe_regex_source_total_when_the_engine_raises(monkeypatch):
    """The `except Exception` arm of is_safe_regex_source (never raises, answers False), reached by injecting a fault."""
    import atlas_pca.predicates as PR

    assert PR.is_safe_regex_source("a") is True

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(PR, "_is_safe_regex_source", boom)
    assert PR.is_safe_regex_source("a") is False
