"""atlas_pca._fdlibm.pow: exact points, the special values of the reference runtime's Math.pow, and agreement with the platform pow
within two units in the last place over a fixed (seeded) sample. The cutoff cases of the entropy corpus pin it bit for bit."""
import math
import random

from atlas_pca._fdlibm import pow as fpow


def test_exact_points():
    assert fpow(2, 10) == 1024 and fpow(2, -20) == 9.5367431640625e-07 and fpow(2, -1074) == 5e-324
    assert fpow(2, 1023) == 8.98846567431158e307 and fpow(2, 1024) == math.inf
    assert fpow(0.5, 3) == 0.125 and fpow(10, 2) == 100 and fpow(4, 0.5) == 2 and fpow(3, 1) == 3 and fpow(4, -1) == 0.25
    assert fpow(-2, 3) == -8 and fpow(-2, 4) == 16 and fpow(1e200, 2) == math.inf


def test_special_values():
    assert fpow(7, 0) == 1 and fpow(math.nan, 0) == 1 and fpow(math.inf, -0.0) == 1
    for x, y in ((-8, 1.0 / 3.0), (1, math.inf), (-1, -math.inf), (2, math.nan), (math.nan, 1), (-1, 0.5), (-4, 0.5)):
        assert math.isnan(fpow(x, y)), (x, y)
    assert fpow(0.5, math.inf) == 0 and fpow(0.5, -math.inf) == math.inf and fpow(2, math.inf) == math.inf and fpow(2, -math.inf) == 0
    assert fpow(0, -1) == math.inf and fpow(-0.0, -1) == -math.inf and fpow(0, 16) == 0 and fpow(0.0, -3.5) == math.inf
    assert math.copysign(1, fpow(-0.0, 3)) == -1 and math.copysign(1, fpow(-0.0, 2.0)) == 1 and math.copysign(1, fpow(-0.0, 4.0)) == 1
    assert fpow(-math.inf, 3) == -math.inf and fpow(-math.inf, -3) == 0 and fpow(-math.inf, 0.5) == math.inf and fpow(-1, 3) == -1
    assert fpow(1e-320, 0.5) == math.sqrt(1e-320) and fpow(2, -1080) == 0 and fpow(-2, 1025) == -math.inf


def test_agrees_with_the_platform_pow_within_two_ulp():
    rnd = random.Random(0x0E170)
    for _ in range(20000):
        x, y = rnd.uniform(0.001, 50), rnd.uniform(-40, 40)
        a, b = fpow(x, y), math.pow(x, y)
        assert abs(a - b) <= 2 * math.ulp(b), (x, y, a, b)
