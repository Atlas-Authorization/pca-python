"""Finite-number check shared by the clock, budget, amount and limit comparisons: NaN, +/-Infinity and an int beyond the double range (a JSON integer such as 10**400 is Infinity to the reference) never pass for a clock, age, spend, remaining or amount."""
import math
from typing import Any


def fin(*xs: Any) -> bool:
    try:
        return all(math.isfinite(x) for x in xs)
    except (OverflowError, TypeError, ValueError):  # math.isfinite overflows on a huge int
        return False


def to_float(x: Any) -> float:
    """float(x), with an int beyond the double range read as +/-Infinity (what a JSON parse of it gives the reference)."""
    try:
        return float(x)
    except OverflowError:
        return math.inf if x > 0 else -math.inf


#: The largest exponent of a bond power curve (the integer part is a loop of multiplications).
POWER_CURVE_MAX_GAMMA = 64


def pow_eighths(e: Any, gamma: Any) -> float:
    """e ** gamma for gamma a multiple of 1/8 in [1, 64], from operations every platform computes identically (pow is not correctly rounded and
    differs in the last digit between libm implementations; a bond amount is money). With gamma = n / 8: multiply by e floor(n / 8) times, one
    multiplication at a time, then by sqrt(e) if bit 4 of (n mod 8) is set, by sqrt(sqrt(e)) if bit 2 is set, by sqrt(sqrt(sqrt(e))) if bit 1 is
    set, in that order. A gamma that is not a multiple of 1/8, or above 64, is refused, never rounded."""
    n = float(gamma) * 8
    if not (math.isfinite(n) and n == math.floor(n) and float(gamma) <= POWER_CURVE_MAX_GAMMA):
        raise ValueError("bondAmount: power curve gamma must be a multiple of 1/8 and at most 64")
    n = int(n)
    e = float(e)
    r = 1.0
    for _ in range(n // 8):
        r *= e
    f = n % 8
    s1 = math.sqrt(e)
    s2 = math.sqrt(s1)
    s3 = math.sqrt(s2)
    if f & 4:
        r *= s1
    if f & 2:
        r *= s2
    if f & 1:
        r *= s3
    return r
