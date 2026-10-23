"""Kill tests for atlas_pca.pca helpers: caveat evaluation boundaries, artifact size boundary, strict numbers, base64url
strictness, suite manifest, the pinned-key choke point and the ML-DSA-65 wrappers (real signatures when dilithium-py is
installed)."""
import math

import pytest

from atlas_pca import pca
from atlas_pca.pca import (
    MAX_ARTIFACT_BYTES, _is_safe_int, _resolve_pq_key, artifact_too_large, b64u, decode_b64u_strict, evaluate_caveats,
    strict_number_error, suite_available, supported_suites,
)

INF = float("inf")


def ok(cv, ctx):
    return evaluate_caveats([cv], ctx)[0]


def test_caveat_boundaries():
    now = {"now": 1000}
    assert ok({"type": "expires", "at": 1001}, now) is True and ok({"type": "expires", "at": 1000}, now) is False
    assert ok({"type": "not_before", "at": 1000}, now) is True and ok({"type": "not_before", "at": 1001}, now) is False
    assert ok({"type": "max_blast_radius", "max": 3}, {"now": 1, "blast_radius": 3}) is True
    assert ok({"type": "max_blast_radius", "max": 3}, {"now": 1, "blast_radius": 4}) is False
    assert ok({"type": "delegation_depth", "max": 2}, {"now": 1, "delegation_depth": 2}) is True
    assert ok({"type": "delegation_depth", "max": 2}, {"now": 1, "delegation_depth": 3}) is False
    assert ok({"type": "budget_alloc", "limit": 0}, now) is True and ok({"type": "budget_alloc", "limit": -1}, now) is False
    assert ok({"type": "budget_alloc", "limit": 1}, now) is True and ok({"type": "budget_alloc"}, now) is False
    for t in ("expires", "not_before", "budget_alloc", "rate"):
        assert ok({"type": t, "at": 1, "limit": 1, "max": 1, "per_secs": 1}, {}) is False  # no clock: every type but max_spend
    assert ok("x", now) is False and ok({"type": "expires", "at": 2000}, "x") is False and ok({"type": "unknown"}, now) is False


def test_rate_window_is_half_open():
    cv = {"type": "rate", "max": 2, "per_secs": 10}
    t = lambda *xs: {"now": 100000, "recent_action_times": list(xs)}  # noqa: E731
    assert ok(cv, t()) is True
    assert ok(cv, t(90000)) is True  # exactly now - window is outside the window
    assert ok(cv, t(90001)) is True
    assert ok(cv, t(90001, 95000)) is False  # two in the window already: n < max fails
    assert ok(cv, t(90000, 90000, 100000)) is True  # 90000 is outside; only 100000 counts
    assert ok(cv, t(90001, 100000)) is False and ok(cv, t(90001, 100001)) is True  # a future time is not counted
    assert ok(cv, {"now": 100000}) is False and ok(cv, {"now": 100000, "recent_action_times": "x"}) is False
    assert ok(dict(cv, per_secs=0), t()) is False and ok(dict(cv, per_secs=-1), t()) is False
    assert ok({"type": "rate", "per_secs": 10}, t()) is False and ok({"type": "rate", "max": 2}, t()) is False
    assert ok(cv, t("x", None, True, 95000)) is True  # non-numbers are skipped


def test_reversibility_order():
    cv = lambda c: {"type": "reversibility_max", "class": c}  # noqa: E731
    ctx = lambda c: {"now": 1, "reversibility_class": c}  # noqa: E731
    order = list(pca.REVERSIBILITY_ORDER)
    for i, lim in enumerate(order):
        for j, cur in enumerate(order):
            assert ok(cv(lim), ctx(cur)) is (j <= i), (lim, cur)
    assert ok(cv("bogus"), ctx(order[0])) is False and ok(cv(order[0]), ctx("bogus")) is False
    assert ok(cv(5), ctx(order[0])) is False and ok(cv(order[0]), ctx(None)) is False
    assert ok(cv("bogus"), ctx("bogus")) is False


def test_max_spend():
    cv = {"type": "max_spend", "usd": 10}
    c = lambda **p: {"action": {"params": p}}  # noqa: E731
    assert ok(cv, c(amount=10)) is True and ok(cv, c(amount=10.5)) is False and ok(cv, c(amount=0)) is True
    assert ok(cv, c(amount=-1)) is False and ok(cv, c(amount="5")) is False and ok(cv, c(amount=True)) is False
    assert ok(cv, c(amount=5, currency="usd")) is True and ok(cv, c(amount=5, currency="USD")) is True
    assert ok(cv, c(amount=5, currency="eur")) is False and ok(cv, c(amount=5, currency=None)) is False
    assert ok(dict(cv, usd=0), c(amount=0)) is True and ok(dict(cv, usd=-1), c(amount=0)) is False
    assert ok(dict(cv, usd=None), c(amount=0)) is False and ok(dict(cv, usd="1"), c(amount=0)) is False
    assert ok({"type": "max_spend"}, c(amount=0)) is False
    assert ok(cv, {"action": {"params": {}}}) is False and ok(cv, {"action": {"params": []}}) is False
    assert ok(cv, {"action": {"params": "x"}}) is False and ok(cv, {"action": {}}) is False and ok(cv, {"action": 5}) is False
    assert ok(cv, {}) is False and ok(cv, {"action": {"params": None}}) is False
    assert ok(cv, c(amount=INF)) is False and ok(dict(cv, usd=INF), c(amount=1)) is False


def test_evaluate_caveats_results():
    assert evaluate_caveats([], {}) == (True, [])
    assert evaluate_caveats("x", {}) == (False, ["<malformed caveats>"])
    assert evaluate_caveats([{"type": "expires", "at": 1}, 5, {"type": 7}, {"type": "nope"}], {"now": 2}) == (
        False, ["expires", "<malformed>", "<malformed>", "nope"])
    assert evaluate_caveats([{"type": "expires", "at": 5}], {"now": 2}) == (True, [])


def test_artifact_size_boundary():
    m = MAX_ARTIFACT_BYTES
    assert artifact_too_large(b"a" * m) is False and artifact_too_large(b"a" * (m + 1)) is True
    assert artifact_too_large(bytearray(m + 1)) is True and artifact_too_large(bytearray(m)) is False
    assert artifact_too_large("a" * m) is False and artifact_too_large("a" * (m + 1)) is True
    assert artifact_too_large("a" * (m // 4)) is False and artifact_too_large("a" * (m // 4 + 1)) is False
    assert artifact_too_large("é" * (m // 2)) is False and artifact_too_large("é" * (m // 2 + 1)) is True
    assert artifact_too_large("€" * (m // 3)) is False and artifact_too_large("€" * (m // 3 + 1)) is True
    assert artifact_too_large("\ud800" * (m // 3 + 1)) is True  # a lone surrogate counts 3 bytes
    assert artifact_too_large("\U0001F600" * (m // 4)) is False and artifact_too_large("\U0001F600" * (m // 4 + 1)) is True
    assert artifact_too_large("a" * (m // 4) + "\U0001F600") is False
    assert artifact_too_large("") is False


@pytest.mark.parametrize("v,want", [
    (0, None), (1, None), (2 ** 53 - 1, None), (2 ** 53, "integer outside the safe range (|n| > 2^53-1)"),
    (-(2 ** 53), "integer outside the safe range (|n| > 2^53-1)"), (1.5, None), (-1.5, None), (0.1, None),
    (1e-6, None), (9e-7, "non-integer magnitude below 1e-6"), (-9e-7, "non-integer magnitude below 1e-6"),
    (-0.0, "negative zero"), (0.0, None), (INF, "non-finite number"), (-INF, "non-finite number"),
    (float("nan"), "non-finite number"), (True, "not a number"), (None, "not a number"), ("1", "not a number"),
    (1.0, None), (1e20, "integer outside the safe range (|n| > 2^53-1)"),
    (1.5e-5, None), (123456789.123456, None), (0.123456789012345, None),
    (123456789.1234567, "non-integer number has more than 15 significant digits"),
    (0.1234567890123456, "non-integer number has more than 15 significant digits"),
])
def test_strict_number_error(v, want):
    assert strict_number_error(v) == want


def test_strict_number_digits_and_exponent_text():
    many = float("1." + "1" * 20)
    got = strict_number_error(many)
    assert got is None or got.startswith("non-integer number has more than")
    assert strict_number_error(0.000001234) is None
    assert pca._plain(1e-7) == "0.0000001" and pca._plain(1.5) == "1.5" and pca._plain(1e21) == "1000000000000000000000"
    assert pca._plain(float("1E-07")) == "0.0000001"
    assert pca._num(1e21, False) == "1000000000000000000000" and pca._num(1e20, False) == "100000000000000000000"
    assert pca._num(2.0 ** 70, False) == "1180591620717411300000"  # JS Number::toString pads the shortest digits


def test_safe_int_negative_zero():
    assert _is_safe_int(-0.0) is False and _is_safe_int(0.0) is True and _is_safe_int(0) is True
    assert _is_safe_int(2 ** 53 - 1) is True and _is_safe_int(2 ** 53) is False and _is_safe_int(1.5) is False
    assert _is_safe_int(True) is False and _is_safe_int(INF) is False and _is_safe_int("1") is False and _is_safe_int(-1) is True


@pytest.mark.parametrize("s,n,want", [
    ("", None, b""), ("AA", None, b"\x00"), ("AAA", None, b"\x00\x00"), ("AAAA", None, b"\x00\x00\x00"), ("A", None, None),
    ("AB", None, None), ("AAB", None, None), ("A=", None, None), ("A A", None, None), ("A\n", None, None), ("A+", None, None),
    ("A/", None, None), ("-_", None, None), ("éé", None, None), (None, None, None), (b"AA", None, None),
    ("AAAA", 3, b"\x00\x00\x00"), ("AAAA", 2, None), ("AAAA", 4, None), ("AA", 1, b"\x00"), ("AA", 2, None), ("AAA", 2, b"\x00\x00"),
    ("AAA", 1, None), ("AAAAA", 3, None), ("AAAAAAAA", 6, b"\x00" * 6), ("AAAAAAAA", 5, None),
])
def test_decode_b64u_strict(s, n, want):
    got = decode_b64u_strict(s) if n is None else decode_b64u_strict(s, n)
    assert got == want


def test_b64u_roundtrip_and_ascii():
    for raw in (b"", b"\xff", b"\xfb\xff", b"\xfb\xff\xfe", bytes(range(256))):
        s = b64u(raw)
        assert "=" not in s and isinstance(s, str) and decode_b64u_strict(s) == raw
    assert b64u(b"\xfb\xff") == "-_8"


def test_suite_manifest():
    assert supported_suites() == [a for a in pca.REGISTERED_SUITES if suite_available(a)]
    assert suite_available("ed25519") is True and "ed25519" in supported_suites()
    for bad in (None, 5, "nope", "", ["ed25519"], b"ed25519"):
        assert suite_available(bad) is False
    assert suite_available("ED25519") is False


def test_pq_choke_point():
    p = _resolve_pq_key("id", "ART", trusted_pk="TRUSTED")
    assert p.key == "TRUSTED" and p.source == "trusted"
    assert _resolve_pq_key("id", "ART", trusted_pk="") is None
    assert _resolve_pq_key("id", "ART", pq_pins={"id": "ART"}).source == "pin"
    assert _resolve_pq_key("id", "ART", pq_pins={"id": "OTHER"}) is None
    assert _resolve_pq_key("id", "ART", pq_pins={"other": "ART"}) is None
    assert _resolve_pq_key("id", "ART", pq_pins={"id": "OTHER"}, holder_pq=pca.holder_pq_commitment("ART")) is None
    assert _resolve_pq_key("id", "ART", holder_pq=pca.holder_pq_commitment("ART")).source == "holder-commitment"
    assert _resolve_pq_key("id", "ART", holder_pq="x") is None and _resolve_pq_key("id", "", holder_pq="x") is None
    assert _resolve_pq_key("id", None, trusted_pk=None) is None and _resolve_pq_key("id", 5) is None
    assert pca.holder_pq_commitment("é") == b64u(pca.sha256(pca.HOLDER_PQ_DOMAIN + "é".encode("utf-8")))
    with pytest.raises(TypeError):
        pca._PinnedPq("k", "s")
    with pytest.raises(AttributeError):
        p.key = "x"


def test_ml_dsa65_wrappers_with_real_signatures():
    dil = pytest.importorskip("dilithium_py.ml_dsa")
    from atlas_pca import pq_backends

    if not pq_backends.available("ML-DSA-65"):
        pytest.skip("no ML-DSA-65 backend")
    pk, sk = dil.ML_DSA_65.keygen()
    msg = b"pinned message"
    sig = dil.ML_DSA_65.sign(sk, msg)
    pkb, sgb = b64u(pk), b64u(sig)
    assert pca._ml_dsa65_verify_b64u(pkb, msg, sgb) is True
    assert pca._pq_verify_b64u("ML-DSA-65", pkb, msg, sgb) is True
    assert pca._ml_dsa65_verify_b64u(pkb, b"other", sgb) is False
    assert pca._ml_dsa65_verify_b64u(b64u(pk[:-1]), msg, sgb) is False
    assert pca._ml_dsa65_verify_b64u(None, msg, sgb) is False and pca._ml_dsa65_verify_b64u(pkb, msg, None) is False
    assert pca._ml_dsa65_verify_b64u(pkb, msg, b64u(sig[:-1])) is False
    assert pca._ml_dsa65_verify_b64u(pkb, msg, b64u(sig + b"\x00")) is False
    pinned = _resolve_pq_key("id", pkb, pq_pins={"id": pkb})
    assert pca._ml_dsa65_verify_pinned(pinned, msg, sgb) is True
    assert pca._ml_dsa65_verify_pinned(pinned, b"other", sgb) is False and pca._ml_dsa65_verify_pinned(pinned, msg, None) is False
    assert pca._ml_dsa65_verify_pinned(None, msg, sgb) is False and pca._ml_dsa65_verify_pinned(pkb, msg, sgb) is False
    assert pca.pq_backends.sig_len_ok("ML-DSA-65", len(sig))
    assert pca._pq_lens("ml-dsa-65") == (1952, 3309) and pca._pq_lens("ed25519") == (0, 0)
