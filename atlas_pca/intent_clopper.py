"""Exact Clopper-Pearson upper bounds, computed in integer arithmetic at dyadic points q = a / 2^52 exactly as the
formal definition is stated; a floating-point bisection only supplies the starting guess. Native port of the
TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from ._fin import fin
import math
from typing import Any, Callable, Dict, List, Optional, Tuple

CP_GRID_BITS = 52
CP_TOLERANCE = 2.0 ** -44

_A = 1 << CP_GRID_BITS
_TOL_UNITS = 1 << (CP_GRID_BITS - 44)


def _log_factorials(n: int) -> List[float]:
    lf = [0.0] * (n + 1)
    for i in range(1, n + 1):
        lf[i] = lf[i - 1] + math.log(i)
    return lf


def binomial_cdf(k: float, n: float, p: float, lf: Optional[List[float]] = None) -> float:
    """P(X <= k) for X ~ Binomial(n, p) in floating point (guesses and diagnostics, never decisions)."""
    if k >= n:
        return 1
    if k < 0:
        return 0
    if p <= 0:
        return 1
    if p >= 1:
        return 0
    if lf is None:
        lf = _log_factorials(int(n))
    lp = math.log(p)
    lq = math.log1p(-p)
    s = 0.0
    for i in range(0, int(math.floor(k)) + 1):
        s += math.exp(lf[int(n)] - lf[i] - lf[int(n) - i] + i * lp + (n - i) * lq)
    return min(1, s)


def double_to_dyadic(x: float) -> Dict[str, Any]:
    """The exact binary fraction of a finite double x in (0, 1): x = num / 2^exp."""
    if not (isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x) and 0 < x < 1):
        raise ValueError("doubleToDyadic: need 0 < x < 1")
    e = 0
    y = float(x)
    while not y.is_integer():
        y *= 2
        e += 1
        if e > 1100:
            raise ValueError("doubleToDyadic: not reached")
    return {"num": int(y), "exp": e}


def cdf_rec_numerator(n: int, k: int, a: int) -> int:
    """The numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52 n)."""
    if a < 0 or a > _A:
        raise ValueError("cdfRecNumerator: a must be in [0, 2^52]")
    b = _A - a
    K = min(k, n)
    row = [1] * (K + 1)
    pw = 1
    for m in range(n):
        nxt = [0] * (K + 1)
        pw_next = pw * _A
        for j in range(K + 1):
            if j >= m + 1:
                nxt[j] = pw_next
            else:
                left = 0 if j == 0 else row[j - 1]
                nxt[j] = a * left + b * row[j]
        row = nxt
        pw = pw_next
    return row[K]


def cdf_exceeds(n: int, k: int, a: int, alpha: Dict[str, Any]) -> bool:
    """Exactly decides alpha < cdfRec(a / 2^52, n, k)."""
    N = cdf_rec_numerator(n, k, a)
    return N * (1 << alpha["exp"]) > alpha["num"] * _A ** n


def _float_guess(k: int, n: int, alpha: float) -> float:
    lf = _log_factorials(n)
    lo = k / n
    hi = 1.0
    it = 0
    while it < 200 and hi - lo > 1e-13:
        mid = (lo + hi) / 2
        if binomial_cdf(k, n, mid, lf) > alpha:
            lo = mid
        else:
            hi = mid
        it += 1
    return hi


def _clamp(a: int) -> int:
    return 0 if a < 0 else _A if a > _A else a


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) or isinstance(x, float) and fin(x) and x.is_integer()


def certify_bracket(start: int, exceeds: Callable[[int], bool]) -> Dict[str, int]:
    """A bracket [lo, hi] of at most the tolerance around the point where `exceeds` (antitone) flips, from any start."""
    hi = start
    step = _TOL_UNITS
    while exceeds(hi):
        hi = _clamp(hi + step)
        step *= 2
    lo = _clamp(hi - _TOL_UNITS)
    step = _TOL_UNITS
    while lo > 0 and not exceeds(lo):
        hi = lo
        lo = _clamp(lo - step)
        step *= 2
    if lo == 0 and not exceeds(0):
        raise ValueError("clopperPearsonUpper: unreachable (cdfRec(0) = 1)")
    while hi - lo > _TOL_UNITS:
        mid = (lo + hi) // 2
        if exceeds(mid):
            lo = mid
        else:
            hi = mid
    return {"hi": hi, "lo": lo}


def clopper_pearson_certified(k: Any, n: Any, alpha: Any) -> Dict[str, Any]:
    """Exact one-sided upper bound with its certificate: {upper, upperUnits, lowerUnits}."""
    if not (_is_int(k) and _is_int(n) and k >= 0 and n >= 0 and k <= n):
        raise ValueError("clopperPearsonUpper: need integers 0 <= k <= n")
    if not (isinstance(alpha, (int, float)) and not isinstance(alpha, bool) and 0 < alpha < 1):
        raise ValueError("clopperPearsonUpper: alpha must be in (0, 1)")
    k, n = int(k), int(n)
    if n == 0 or k == n:
        return {"upper": 1, "upperUnits": _A, "lowerUnits": _A}
    al = double_to_dyadic(alpha)
    start = _clamp(math.ceil(_float_guess(k, n, alpha) * 2.0 ** CP_GRID_BITS) + _TOL_UNITS)
    br = certify_bracket(start, lambda a: cdf_exceeds(n, k, a, al))
    return {"upper": float(br["hi"]) / 2.0 ** CP_GRID_BITS, "upperUnits": br["hi"], "lowerUnits": br["lo"]}


def clopper_pearson_upper(k: Any, n: Any, alpha: Any) -> float:
    return clopper_pearson_certified(k, n, alpha)["upper"]
