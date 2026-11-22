"""DETERMINISTIC MATH (the rule every language follows). libm's log, exp, log2 and pow are not correctly rounded and differ in the last digit
between implementations, which moves a decision that sits on a boundary (the drift threshold, the next question, a map weight, an integer cut
point). The functions here use only integer arithmetic: fixed point with 96 fractional bits (a value is an integer scaled by 2^96), TRUNCATING
division (toward zero; Python's ``//`` floors, so ``_tdiv`` is used wherever an operand can be negative), and one final conversion of the integer
to a double with round-to-nearest-even followed by an exact power-of-two scaling.

  det_ln(x)    ln x for x > 0 (0 and -0 give -Infinity, x < 0 and NaN give NaN): x = m * 2^E, m = M / 2^52 in [1, 2) (M the 53-bit significand); ln x = E * LN2 + 2 * atanh((M - 2^52) / (M + 2^52)),
               atanh summed as z + z^3/3 + z^5/5 + ... (z fixed point, z2 = (z*z)/2^96 truncated) until a term is 0; LN2 = 2 * atanh(1/3).
  det_log2(x)  log2 x: the same fixed value divided by LN2 in fixed point ((fixed * 2^96) / LN2, truncating): an exact power of two gives its
               integer exponent exactly.
  det_exp(x)   e^x: X = trunc(x * 2^96) (exact shift of the double's integer significand); k = floor((X + LN2/2) / LN2) (floor division);
               r = X - k * LN2; e^r = sum of r^n / n! with term_0 = 2^96, term_n = trunc(trunc(term_{n-1} * r / 2^96) / n), until a term is 0;
               result = float(sum) * 2^(k - 96) (the scaling split into two exact powers of two so that no intermediate overflows). x > 709.78
               gives +Infinity, x < -745.2 gives 0, NaN gives NaN.
  det_pow_int(b, n) b^n for an integer n >= 0: 1 multiplied by b, n times, in sequence (IEEE multiplication is exactly rounded).
"""
from __future__ import annotations

import math
import struct

_FRAC = 96
_ONE = 1 << _FRAC
_MASK52 = (1 << 52) - 1


def _tdiv(a: int, b: int) -> int:
    """Integer division truncating toward zero (BigInt `/`)."""
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _atanh2(num: int, den: int) -> int:
    """2 * atanh(z) for z = num / den, in fixed point (num, den > 0 here)."""
    z = (num << _FRAC) // den
    z2 = (z * z) >> _FRAC
    term = z
    total = 0
    i = 1
    while term != 0:
        total += term // i
        term = (term * z2) >> _FRAC
        i += 2
    return 2 * total


_LN2 = _atanh2(1, 3)  # ln 2 = 2 atanh(1/3)


def _bits(y: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", y))[0]


def _ln_fixed(x: float):
    """Fixed-point ln(x) (an integer scaled by 2^96) of a positive finite double, or None when x is not positive and finite."""
    if not (x > 0) or x == math.inf:
        return None
    scale = 0
    y = x
    if y < 2.0 ** -1022:
        y *= 2.0 ** 64
        scale = 64
    bits = _bits(y)
    e = ((bits >> 52) & 0x7FF) - 1023 - scale
    m = (bits & _MASK52) | (1 << 52)
    return e * _LN2 + _atanh2(m - (1 << 52), m + (1 << 52))


def _number(v: int) -> float:
    """Number(BigInt): the nearest double, ties to even (Python's int -> float conversion rounds exactly so)."""
    return float(v)


def det_ln(x: float) -> float:
    if x == 0:  # +0 and -0: -Infinity, as Math.log
        return -math.inf
    if not (x > 0):
        return math.nan
    if x == math.inf:
        return x
    if x == 1:
        return 0.0
    return _number(_ln_fixed(x)) / _number(_ONE)


def det_log2(x: float) -> float:
    if x == 0:  # +0 and -0: -Infinity, as Math.log2
        return -math.inf
    if not (x > 0):
        return math.nan
    if x == math.inf:
        return x
    if x == 1:
        return 0.0
    l = _ln_fixed(x)
    return _number(_tdiv(l << _FRAC, _LN2)) / _number(_ONE)


def det_exp(x: float) -> float:
    if x != x:
        return x
    if x > 709.782712893384:
        return math.inf
    if x < -745.2:
        return 0.0
    if x == 0:
        return 1.0
    bits = _bits(abs(x))
    be = (bits >> 52) & 0x7FF
    frac = bits & _MASK52
    m = frac if be == 0 else frac | (1 << 52)
    sh = (1 if be == 0 else be) - 1075 + _FRAC  # |x| * 2^96 = m * 2^sh
    big_x = m << sh if sh >= 0 else m >> -sh
    if x < 0:
        big_x = -big_x
    k = (big_x + _LN2 // 2) // _LN2  # floor division (the reference's explicit floorDiv)
    r = big_x - k * _LN2
    term = _ONE
    total = _ONE
    n = 1
    while term != 0:
        term = _tdiv(_tdiv(term * r, _ONE), n)
        total += term
        n += 1
    e = k - _FRAC
    half = int(e / 2)  # Math.trunc(e / 2)
    return _number(total) * (2.0 ** half) * (2.0 ** (e - half))


def det_pow_int(b: float, n: int) -> float:
    """b^n for an integer n >= 0 by sequential multiplication (b * b * ..., n times, starting from 1)."""
    r = 1.0
    i = 0
    while i < n:  # as the reference's `for (i = 0; i < n; i++)`: a fractional n runs ceil(n) times, a negative one never
        r *= b
        i += 1
    return r
