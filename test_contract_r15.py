"""Reference contract round 15: exact entropy cutoff and the deterministic math (atlas_pca.detmath) of every float that gates a decision."""
import math

import pytest

from atlas_pca import detmath as D
from atlas_pca import entropy as E


def test_proportion_cutoff_is_exact_and_never_disabled():
    assert E.proportion_cutoff(1, 2000) == 1107  # the old float recurrence underflowed and returned 2001 (test off)
    assert E.proportion_cutoff(8, 512) == 13
    assert E.proportion_cutoff(0.5, 512) == 410
    assert E.proportion_cutoff(1, 2) == 3
    for h in (0, 0.0625, 0.126, 64.125, 65, math.nan, math.inf, -1, True, "8", None):
        with pytest.raises(ValueError):
            E.proportion_cutoff(h, 512)
    for w in (1, 2.5, 65537, 0, -3, math.nan, math.inf, True, "512", None):
        with pytest.raises(ValueError):
            E.proportion_cutoff(8, w)
    assert E.proportion_cutoff(64, 65536) == 1  # (1 - 2^-64)^65536 already exceeds 1 - 2^-20: k = 0


def test_health_test_bytes_domain():
    ok = bytes(range(256)) * 4
    assert E.health_test_bytes(ok, 8, 512).ok is True
    for h in (0.9, 8.5, 1.1, 2.0625, math.nan, True):
        v = E.health_test_bytes(ok, h, 512)
        assert v.ok is False and v.test == "repetition-count", h
    assert E.health_test_bytes(ok, 8, 1).ok is False and E.health_test_bytes(ok, 8, 2.5).ok is False
    assert E.health_test_bytes(b"\x01", 8, 512).ok is True  # a one-byte window: the proportion test is skipped
    assert E.health_test_bytes(bytes([7]) * 600, 8, 99999).test in ("repetition-count", "adaptive-proportion")  # the window clamps to 65536


def test_det_functions_are_exact_where_the_rule_says():
    assert D.det_log2(8) == 3.0 and D.det_log2(0.5) == -1.0 and D.det_log2(1) == 0.0 and D.det_ln(1) == 0.0
    assert D.det_ln(0.0) == -math.inf and D.det_ln(-0.0) == -math.inf and D.det_log2(0.0) == -math.inf and D.det_log2(-0.0) == -math.inf
    assert math.isnan(D.det_ln(-1)) and math.isnan(D.det_log2(-1)) and math.isnan(D.det_ln(math.nan)) and math.isnan(D.det_log2(math.nan))
    assert D.det_exp(-math.inf) == 0.0 and D.det_exp(math.inf) == math.inf
    assert D.det_ln(math.inf) == math.inf and D.det_log2(math.inf) == math.inf
    assert D.det_exp(0) == 1.0 and D.det_exp(800) == math.inf and D.det_exp(-800) == 0.0 and math.isnan(D.det_exp(math.nan))
    assert D.det_pow_int(2.0, 10) == 1024.0 and D.det_pow_int(3.0, 0) == 1.0 and D.det_pow_int(3.0, -2) == 1.0
    assert D.det_pow_int(2.0, 2.5) == 8.0  # a fractional exponent runs ceil(n) multiplications, as the reference's loop


@pytest.mark.parametrize("x", [1e-300, 5e-324, 0.3, 0.5000000000000001, 1.5, 2.718281828459045, 100.0, 12345.678, 1e300])
def test_det_log_is_within_an_ulp_of_libm(x):
    assert math.isclose(D.det_ln(x), math.log(x), rel_tol=4e-16, abs_tol=0)
    if x != 1:
        assert math.isclose(D.det_log2(x), math.log2(x), rel_tol=4e-16, abs_tol=0)


@pytest.mark.parametrize("x", [-745.0, -100.5, -1.0, -1e-9, 1e-9, 0.5, 1.0, 10.25, 700.0])
def test_det_exp_is_within_an_ulp_of_libm(x):
    assert math.isclose(D.det_exp(x), math.exp(x), rel_tol=4e-16, abs_tol=5e-324)


def test_truncating_division_of_negatives():
    assert D._tdiv(-7, 2) == -3 and D._tdiv(7, -2) == -3 and D._tdiv(-7, -2) == 3 and D._tdiv(7, 2) == 3
    # a negative fixed-point log (x < 1) must truncate toward zero: log2(0.75) is not off by a unit in the last place of the 96-bit value
    assert D.det_log2(0.75) == pytest.approx(-0.4150374992788438, rel=1e-15)


def test_wallet_noise_bounds_are_the_exact_clopper_pearson_inversion():
    from atlas_pca import wallet as W
    from atlas_pca.wallet_omega import clopper_pearson_upper
    assert W.beta_upper_exact(0.05, 3, 9) == clopper_pearson_upper(2, 11, 0.05)
    assert W.estimate_noise({"falseYes": 1, "correctNo": 9, "falseNo": 0, "correctYes": 4})["etaPosUpper"] == W.beta_upper_exact(0.05, W.NOISE_PRIOR["a"] + 1, W.NOISE_PRIOR["b"] + 9)
    for a, b in ((0, 3), (3, 0), (1.5, 2), (math.nan, 2), (True, 2)):
        with pytest.raises(ValueError):
            W.beta_upper_exact(0.05, a, b)


def test_binary_entropy_is_memoized_and_deterministic():
    from atlas_pca import intent_learner as L
    L._BIN_ENT_MEMO.clear()
    a = L._bin_ent(0.3)
    assert a == -(0.3 * D.det_log2(0.3) + 0.7 * D.det_log2(0.7)) and 0.3 in L._BIN_ENT_MEMO and L._bin_ent(0.3) == a
    assert L._bin_ent(0) == 0 and L._bin_ent(1) == 0


def test_a_prior_mix_cell_with_q_zero_or_one_has_weight_zero_not_nan():
    from atlas_pca import intent_mapkit as M
    for q in (0, 1):
        pm = M._prior_mix_of({"beta": 0.5, "cells": [{"verb": "v", "cell": 0, "q": q}]})
        w_in, w_out = pm["weight"]({"verb": "v"}, lambda c: True), pm["weight"]({"verb": "v"}, lambda c: False)
        assert not math.isnan(w_in) and not math.isnan(w_out) and 0.0 in (w_in, w_out), q
