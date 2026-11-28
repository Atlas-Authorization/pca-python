"""The outcome space the wallet resolves question cells against (the Omega of the intent layer), the separable harm model
and the exact Clopper-Pearson bound, as the wallet needs them. Mirrors the TypeScript reference (@atlasauth/pca-intent) for the
members the wallet uses; it is private to the wallet port. Floats follow the reference operation by operation (IEEE-754 doubles)."""
from ._fin import fin
from .detmath import det_ln
import math
import re
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "OTHER", "EXACT_SPAN", "HarmModel", "DEFAULT_HARM", "num_cells", "cell_count", "verb_cell_count", "decode_cell",
    "cat_cell_of", "cell_of_value", "cell_of", "cat_rep", "num_rep", "rep_value", "cell_rep", "interval_weight", "dim_cell_stats",
    "cell_stats", "label_of", "clopper_pearson_upper", "u16len", "u16slice", "is_number", "is_int", "is_safe_int",
]

OTHER = "⊥"  # ⊥, "any value not named"
EXACT_SPAN = 4096
_EULER_GAMMA = 0.5772156649015329
_MAX_SAFE = 2 ** 53 - 1


# ---- JavaScript value helpers shared by the wallet modules ------------------------------------------------------------------

def is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def is_finite_number(v: Any) -> bool:
    return is_number(v) and fin(v)


def is_safe_int(v: Any) -> bool:
    """Number.isSafeInteger (accepts -0)."""
    if not is_number(v):
        return False
    if isinstance(v, int):
        return abs(v) <= _MAX_SAFE
    return v == v and v not in (math.inf, -math.inf) and v.is_integer() and abs(v) <= _MAX_SAFE


def is_int(v: Any) -> bool:
    """A safe integer that is not -0 (the wire `isInt`)."""
    if not is_safe_int(v):
        return False
    return not (isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0)


def u16len(s: str) -> int:
    """JavaScript String.length (UTF-16 code units)."""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def u16slice(s: str, start: int, end: Optional[int] = None) -> str:
    b = s.encode("utf-16-le", "surrogatepass")
    n = len(b) // 2
    if end is None:
        end = n
    if start < 0:
        start = max(0, n + start)
    return b[2 * start:2 * min(end, n)].decode("utf-16-le", "surrogatepass")


def _f(x: Any) -> float:
    return float(x)


# ---- cells ----------------------------------------------------------------------------------------------------------------------

def num_cells(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    cur = d["lo"]
    for c in d["cuts"]:
        if c < d["lo"] or c > d["hi"]:
            continue
        if cur <= c - 1:
            out.append({"lo": cur, "hi": c - 1})
        out.append({"lo": c, "hi": c})
        cur = c + 1
    if cur <= d["hi"]:
        out.append({"lo": cur, "hi": d["hi"]})
    return out


def cell_count(d: Dict[str, Any]) -> int:
    return len(num_cells(d)) if d["kind"] == "num" else len(d["values"])


def verb_cell_count(vs: Dict[str, Any]) -> int:
    n = 1
    for d in vs["dims"]:
        n *= cell_count(d)
    return n


def decode_cell(vs: Dict[str, Any], flat: int) -> List[int]:
    dims = vs["dims"]
    idx = [0] * len(dims)
    for i in range(len(dims) - 1, -1, -1):
        n = cell_count(dims[i])
        idx[i] = flat % n
        flat = flat // n
    return idx


def cat_cell_of(d: Dict[str, Any], s: str) -> int:
    best, best_len = -1, -1
    for i, v in enumerate(d["values"]):
        if v["kind"] == "exact" and v["value"] == s:
            return i
        if v["kind"] == "prefix" and s.startswith(v["value"]) and u16len(v["value"]) > best_len:
            best, best_len = i, u16len(v["value"])
    if best >= 0:
        return best
    for i, v in enumerate(d["values"]):
        if v["kind"] == "other":
            return i
    return -1


def cell_of_value(d: Dict[str, Any], x: Any) -> int:
    """The cell a concrete value falls in, or -1 outside the dimension's domain or type."""
    if d["kind"] == "num":
        if not is_finite_number(x):
            return -1
        for i, c in enumerate(num_cells(d)):
            if x >= c["lo"] and x <= c["hi"]:
                return i
        return -1
    if not isinstance(x, str):
        return -1
    return cat_cell_of(d, x)


def cell_of(vs: Dict[str, Any], o: Dict[str, Any]) -> Optional[List[int]]:
    idx: List[int] = []
    values = o["values"]
    for d in vs["dims"]:
        i = cell_of_value(d, values.get(d["path"]) if isinstance(values, dict) else None)
        if i < 0:
            return None
        idx.append(i)
    return idx


def cat_rep(d: Dict[str, Any], i: int) -> str:
    v = d["values"][i]
    if v["kind"] == "exact":
        return v["value"]
    base = v["value"] + "x" if v["kind"] == "prefix" else "other"
    for k in range(64):
        s = base + ("" if k == 0 else str(k))
        if cat_cell_of(d, s) == i:
            return s
    return base


def num_rep(d: Dict[str, Any], i: int) -> int:
    c = num_cells(d)[i]
    return c["lo"] if i > 0 else c["hi"]


def rep_value(d: Dict[str, Any], i: int) -> Any:
    return num_rep(d, i) if d["kind"] == "num" else cat_rep(d, i)


def cell_rep(vs: Dict[str, Any], idx) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for i, d in enumerate(vs["dims"]):
        values[d["path"]] = rep_value(d, idx[i])
    return {"verb": vs["verb"], "values": values}


def label_of(path: str) -> str:
    if path == "action.resource":
        return "resource"
    return path.split(".")[-1].replace("_", " ")


# ---- workload and harm ----------------------------------------------------------------------------------------------------------

def _harmonic(n: Any) -> float:
    if n <= 0:
        return 0
    if n <= EXACT_SPAN:
        s = 0.0
        for k in range(int(n), 0, -1):
            s += 1 / k
        return s
    n = _f(n)
    n2 = n * n
    return det_ln(n) + _EULER_GAMMA + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2)


def interval_weight(d: Dict[str, Any], a: int, b: int) -> float:
    if b < a:
        return 0
    if not (d.get("dist") == "loguniform" and d["lo"] >= 0):
        return b - a + 1
    if b - a + 1 <= EXACT_SPAN:
        s = 0.0
        for x in range(b, a - 1, -1):
            s += 1 / (x + 1)
        return s
    return _harmonic(b + 1) - _harmonic(a)


def _first_moment(d: Dict[str, Any], a: int, b: int) -> float:
    if b < a:
        return 0
    if not (d.get("dist") == "loguniform" and d["lo"] >= 0):
        return (_f(a + b) * _f(b - a + 1)) / 2
    return (b - a + 1) - interval_weight(d, a, b)


def _interval_mean_x(d: Dict[str, Any], a: int, b: int, cell_lo: int) -> float:
    whole = interval_weight(d, cell_lo, b)
    return _first_moment(d, a, b) / whole if whole > 0 else 0


_LINEAR_AMOUNT = re.compile(r"(^|\.)amount$")


def _linear_amount(d: Dict[str, Any]) -> bool:
    return d["kind"] == "num" and _LINEAR_AMOUNT.search(d["path"]) is not None


class HarmModel:
    """h_v (verb factor), g_d (dimension factor at a concrete value) and the optional closed-form mean over an interval."""

    def __init__(self, verb, dim, dim_mean=None):
        self.verb = verb
        self.dim = dim
        self.dim_mean = dim_mean


def _default_verb(vs: Dict[str, Any]) -> float:
    r = vs.get("reversibility")
    return 10 if r == "irreversible" else 3 if r == "rate_limited" else 1


def _default_dim(d: Dict[str, Any], x: Any) -> float:
    return 1 + max(0, x) / 100 if _linear_amount(d) and is_number(x) else 1


def _default_dim_mean(d: Dict[str, Any], lo: int, hi: int) -> float:
    return 1 + max(0, _interval_mean_x(d, max(lo, 0), hi, lo)) / 100 if _linear_amount(d) else 1


DEFAULT_HARM = HarmModel(_default_verb, _default_dim, _default_dim_mean)


def _point_weight(d: Dict[str, Any], x: int) -> float:
    if d.get("dist") == "loguniform" and d["lo"] >= 0:
        return 1 / (x + 1)
    return 1


def _interval_harm(d: Dict[str, Any], a: int, b: int, harm: HarmModel) -> float:
    if harm.dim_mean is not None:
        return harm.dim_mean(d, a, b)
    n = b - a + 1
    w_tot = interval_weight(d, a, b)
    if not (w_tot > 0):
        return harm.dim(d, a)
    if n <= EXACT_SPAN:
        s = 0.0
        for x in range(a, b + 1):
            s += _point_weight(d, x) * harm.dim(d, x)
        return s / w_tot
    s = 0.0
    for i in range(1024):
        pa = a + (i * n) // 1024
        pb = a + ((i + 1) * n) // 1024 - 1
        if pb < pa:
            continue
        w = interval_weight(d, pa, pb)
        s += w * harm.dim(d, math.floor((pa + pb) / 2 + 0.5))
    return s / w_tot


def dim_cell_stats(d: Dict[str, Any], i: int, harm: HarmModel = DEFAULT_HARM) -> Dict[str, Any]:
    if d["kind"] == "cat":
        return {"mass": 1 / len(d["values"]), "harm": harm.dim(d, cat_rep(d, i))}
    c = num_cells(d)[i]
    wm = interval_weight(d, c["lo"], c["hi"])
    total = interval_weight(d, d["lo"], d["hi"])
    return {"mass": wm / total, "harm": _interval_harm(d, c["lo"], c["hi"], harm) if wm > 0 else harm.dim(d, c["lo"])}


def cell_stats(vs: Dict[str, Any], idx, harm: Optional[HarmModel] = None) -> Dict[str, Any]:
    """Exact mu(cell) and E[h | cell] for a whole cell (product measure, separable harm)."""
    harm = harm or DEFAULT_HARM
    mass = vs["weight"]
    h = harm.verb(vs)
    for k, d in enumerate(vs["dims"]):
        s = dim_cell_stats(d, idx[k], harm)
        mass *= s["mass"]
        h *= s["harm"]
    return {"mass": mass, "harm": h}


# ---- exact Clopper-Pearson upper bound ------------------------------------------------------------------------------------------

_GRID_BITS = 52
_A = 1 << _GRID_BITS
_TOL_UNITS = 1 << (_GRID_BITS - 44)


def _log_factorials(n: int) -> List[float]:
    lf = [0.0] * (n + 1)
    for i in range(1, n + 1):
        lf[i] = lf[i - 1] + math.log(i)
    return lf


def _binomial_cdf(k: int, n: int, p: float, lf: List[float]) -> float:
    if k >= n:
        return 1
    if k < 0:
        return 0
    if p <= 0:
        return 1
    if p >= 1:
        return 0
    lp = math.log(p)
    lq = math.log1p(-p)
    s = 0.0
    for i in range(0, k + 1):
        s += math.exp(lf[n] - lf[i] - lf[n - i] + i * lp + (n - i) * lq)
    return min(1, s)


def _cdf_rec_numerator(n: int, k: int, a: int) -> int:
    b = _A - a
    kk = min(k, n)
    row = [1] * (kk + 1)
    pw = 1
    for m in range(n):
        nxt = [0] * (kk + 1)
        pw_next = pw * _A
        for j in range(kk + 1):
            if j >= m + 1:
                nxt[j] = pw_next
            else:
                left = 0 if j == 0 else row[j - 1]
                nxt[j] = a * left + b * row[j]
        row = nxt
        pw = pw_next
    return row[kk]


def _cdf_exceeds(n: int, k: int, a: int, alpha: Tuple[int, int]) -> bool:
    num, exp = alpha
    return _cdf_rec_numerator(n, k, a) * (1 << exp) > num * _A ** n


def _float_guess(k: int, n: int, alpha: float) -> float:
    lf = _log_factorials(n)
    lo = k / n
    hi = 1.0
    it = 0
    while it < 200 and hi - lo > 1e-13:
        mid = (lo + hi) / 2
        if _binomial_cdf(k, n, mid, lf) > alpha:
            lo = mid
        else:
            hi = mid
        it += 1
    return hi


def _clamp(a: int) -> int:
    return 0 if a < 0 else _A if a > _A else a


def _certify_bracket(start: int, exceeds) -> Tuple[int, int]:
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
    return hi, lo


def clopper_pearson_upper(k: Any, n: Any, alpha: Any) -> float:
    """One-sided Clopper-Pearson upper bound after k successes in n, rounded outward on the 2^-52 grid (exact integer arithmetic)."""
    if not (is_number(k) and is_number(n) and float(k).is_integer() and float(n).is_integer() and k >= 0 and n >= 0 and k <= n):
        raise ValueError("clopperPearsonUpper: need integers 0 <= k <= n")
    if not (is_number(alpha) and alpha > 0 and alpha < 1):
        raise ValueError("clopperPearsonUpper: alpha must be in (0, 1)")
    k, n = int(k), int(n)
    if n == 0 or k == n:
        return 1
    num, den = float(alpha).as_integer_ratio()
    al = (num, den.bit_length() - 1)
    start = _clamp(math.ceil(_float_guess(k, n, float(alpha)) * 2 ** _GRID_BITS) + _TOL_UNITS)
    hi, _lo = _certify_bracket(start, lambda a: _cdf_exceeds(n, k, a, al))
    return hi / 2 ** _GRID_BITS
