"""Reference contract round 14: exactly reproducible immune decay and bond power curve, unrepresentable clocks, non-number adaptations."""
import hashlib
import math

import pytest

from atlas_pca import immune as I
from atlas_pca._fin import pow_eighths


def _ref_decay(count, dt, hl):
    """The reference's definition, written out independently of the implementation."""
    u = math.floor(dt * 1024 / hl)
    f = 1.0
    for _ in range(u // 1024):
        f *= 0.5
    for _ in range(u % 1024):
        f *= 0.9993233275026507
    return count * f


def test_immune_decay_is_the_reference_quantised_product(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("pow / exp / log must not be called")
    monkeypatch.setattr(math, "pow", boom)
    monkeypatch.setattr(math, "exp", boom)
    monkeypatch.setattr(math, "log", boom)
    hl = 3_686_400  # a multiple of 1024: one step is exactly hl / 1024 ms
    assert I._decay(1.0, hl, hl) == 0.5 and I._decay(1.0, 2 * hl, hl) == 0.25
    assert I._decay(1.0, hl // 1024, hl) == 0.9993233275026507  # one step
    for dt in (1, 3_000, 1_800_000, 5_400_001, 36_000_000, 123_456_789):
        assert I._decay(3.0, dt, hl) == _ref_decay(3.0, dt, hl), dt
    assert I._decay(5.0, 0, hl) == 5.0 and I._decay(5.0, -1, hl) == 5.0 and I._decay(0, 10, hl) == 0
    assert math.isnan(I._decay(1.0, math.nan, hl))
    assert I._decay(1.0, 1e15 * hl, hl) == 0.0  # 0.5^1100 underflows
    assert I._decay(1.0, 10, 0) == 0.0  # a zero half-life: the quotient is +Infinity


def test_no_widen_violation_refuses_a_non_number_kappa_or_theta():
    base = {"kappa": 2.0, "theta1": 0.3, "theta2": 0.6, "lambda": 1, "rho": 1, "bMax": 1, "weights": {}}
    ok = dict(base)
    assert I.no_widen_violation(base, ok) is None
    for k in ("kappa", "theta1", "theta2"):
        for bad in (None, True, False, "2", [], {}):
            assert I.no_widen_violation(base, dict(ok, **{k: bad})) == "kappa and theta must be numbers", (k, bad)


def test_bond_power_curve_uses_exact_operations_and_refuses_other_gammas():
    assert pow_eighths(2, 3) == 8.0 and pow_eighths(9, 1) == 9.0 and pow_eighths(4, 1.5) == 8.0
    e = 7.3
    s1 = math.sqrt(e); s2 = math.sqrt(s1); s3 = math.sqrt(s2)
    r = 1.0
    r *= e; r *= e
    r *= s1; r *= s2; r *= s3
    assert pow_eighths(e, 2.875) == r
    assert pow_eighths(e, 64) == _loop(e, 64)
    for bad in (1.1, 1.0625, 64.125, 65, math.nan, math.inf):
        with pytest.raises(ValueError, match="multiple of 1/8 and at most 64"):
            pow_eighths(2.0, bad)


def _loop(e, n):
    r = 1.0
    for _ in range(n):
        r *= e
    return r


def test_bond_amount_power_curve_goes_through_it():
    from atlas_pca import bond_settlement as B
    assert B._curve_component({"kind": "power", "gamma": 2}, 3.0, 5.0) == 3.0 * 25.0
    for bad in (1.1, 70):
        with pytest.raises(ValueError):
            B._curve_component({"kind": "power", "gamma": bad}, 1.0, 2.0)
    with pytest.raises(ValueError, match="finite gamma >= 1"):
        B._curve_component({"kind": "power", "gamma": 0.5}, 1.0, 2.0)


def test_sdjwt_refuses_an_unrepresentable_now():
    from atlas_pca.sdjwt import verify_pca_sd_jwt
    for now in (1e300, -1e300, 8.64e15 + 2e3):
        r = verify_pca_sd_jwt("x", {"issuer_key": {}, "now": now})
        assert r["ok"] is False and r["reason"] == "now is not a representable time", now
    assert verify_pca_sd_jwt("x", {"issuer_key": {}, "now": math.nan})["reason"].startswith("now, clockToleranceSec")


def test_receive_set_refuses_an_unrepresentable_now_sec():
    import test_ref_signals as T
    from atlas_pca import signals as S
    st = S.create_revocation_state()
    store = S.create_in_memory_set_replay_store()
    tok = S.build_set({T.ET["grantRevoked"]: {"grant_ref": "g", "reason": "r", "event_timestamp": 1}}, "iss", "aud", T.K1_SEED)
    for bad in (math.nan, math.inf, -math.inf, 1e300, -1e300, "5"):
        o = {"issuer": "iss", "audience": "aud", "replayStore": store, "state": st, "maxAgeSec": 300, "nowSec": bad}
        r = S.receive_set(tok, T.K1_PUB, o)
        assert r["ok"] is False and r["code"] == "verify_failed" and "representable" in r["reason"], bad
