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
