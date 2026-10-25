"""Kill tests for atlas_pca.pca: Object.keys order at the array-index boundary, caveat predicates failing closed without
raising, an exception in a caveat counting as a failed one, and the variable-length LESS signature on the wire."""
import pytest

from atlas_pca import pca as P
from atlas_pca import pq_backends
from atlas_pca.pca import b64u


def test_js_keys_orders_array_indexes_numerically_and_stops_at_the_index_limit():
    assert P._js_keys({"b": 1, "10": 2, "9": 3, "a": 4}) == ["9", "10", "b", "a"]
    assert P._js_keys({"x": 0, "4294967295": 1, "4294967294": 2, "01": 3, "0": 4}) == ["0", "4294967294", "x", "4294967295", "01"]


def test_a_raising_caveat_is_a_failed_caveat(monkeypatch):
    def boom(cv, ctx):
        raise RuntimeError("x")

    monkeypatch.setattr(P, "_caveat_satisfied", boom)
    assert P.evaluate_caveats([{"type": "expires", "at": 1}], {"now": 0}) == (False, ["expires"])
    assert P.evaluate_caveats([5], {}) == (False, ["<malformed>"])


def test_caveat_predicates_fail_closed_without_raising():
    cs = P._caveat_satisfied
    ctx = {"now": 1000}
    assert cs(5, {}) is False and cs({}, 5) is False and cs(5, 5) is False
    assert cs({"type": "rate", "per_secs": 60}, dict(ctx, recent_action_times=[])) is False  # max absent
    assert cs({"type": "rate", "max": 3}, dict(ctx, recent_action_times=[])) is False  # per_secs absent
    assert cs({"type": "rate", "max": 3, "per_secs": 60}, dict(ctx, recent_action_times=[])) is True
    assert cs({"type": "reversibility_max", "class": "reversible"}, dict(ctx, reversibility_class="bogus")) is False
    assert cs({"type": "reversibility_max", "class": "bogus"}, dict(ctx, reversibility_class="reversible")) is False
    assert cs({"type": "reversibility_max", "class": 5}, dict(ctx, reversibility_class="reversible")) is False
    assert cs({"type": "reversibility_max", "class": "reversible"}, dict(ctx, reversibility_class=None)) is False
    assert cs({"type": "reversibility_max", "class": "irreversible"}, dict(ctx, reversibility_class="reversible")) is True


def test_max_spend_fails_closed_without_raising():
    ms = P._max_spend_satisfied
    act = lambda **p: {"action": {"params": p}}
    assert ms({}, act(amount=1)) is False  # no usd limit
    assert ms({"usd": -1}, act(amount=0)) is False
    assert ms({"usd": 5}, {"action": {"params": None}}) is False
    assert ms({"usd": 5}, {"action": {"params": []}}) is False
    assert ms({"usd": 5}, act()) is False  # no amount
    assert ms({"usd": 5}, act(amount=5)) is True and ms({"usd": 5}, act(amount=6)) is False


def test_less_signature_lengths_on_the_wire(monkeypatch):
    monkeypatch.setattr(pq_backends, "available", lambda key_type: True)
    pk = b64u(bytes(97484))
    for n, ok in ((1329, True), (1313, True), (1153, True), (1152, False), (1330, False), (1321, False)):
        p = {"alg": "less-cat1", "sig": b64u(bytes(n)), "pq_pk": pk}
        assert (P.validate_signature_wire(p) is None) is ok, n
        s = {"alg": "less-cat1", "sig": b64u(bytes(n)), "pq_pk": pk}
        assert (P.validate_share_signature_wire(s) is None) is ok, n


def test_pq_verify_refuses_a_public_key_of_the_wrong_length():
    sig = b64u(bytes(3309))
    for n in (0, 10, 1951, 1953, 2592):
        assert P._pq_verify_b64u("ML-DSA-65", b64u(bytes(n)), b"m", sig) is False, n
    assert P._pq_verify_b64u("ML-DSA-65", 5, b"m", sig) is False
    ok_pk = b64u(bytes(1952))
    for bad_sig in ("!!", 5, None, "", b64u(bytes(3308))):
        assert P._pq_verify_b64u("ML-DSA-65", ok_pk, b"m", bad_sig) is False, bad_sig
