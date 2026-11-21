"""The intent outcome space (omega): typed dimensions derived from the grant vocabulary, cells, representatives, the
workload and harm measures, a seeded generator and the derivation from policies + slots. Native port of the TypeScript
reference (@atlasauth/pca-intent). Dimensions, verb spaces and omegas are plain JSON dicts, as in the reference."""
from __future__ import annotations

from ._fin import fin
import math
import re
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Tuple

OTHER = "⊥"

DEFAULT_DOMAINS = {
    "action.params.amount": {"lo": 0, "hi": 100000, "dist": "loguniform"},
    "env.hour": {"lo": 0, "hi": 23, "dist": "uniform"},
    "action.params.count": {"lo": 0, "hi": 1000, "dist": "loguniform"},
}

EXACT_SPAN = 4096
HARM_QUADRATURE_PIECES = 1024
EULER_GAMMA = 0.5772156649015329


def is_number(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def is_finite_number(x: Any) -> bool:
    return is_number(x) and fin(x)


def u16key(s: str) -> bytes:
    """JS default string order is by UTF-16 code unit."""
    return s.encode("utf-16-be", "surrogatepass")


def js_round(x: float) -> float:
    return math.floor(x + 0.5)


# ---- cells -------------------------------------------------------------------------------------------------------

@lru_cache(maxsize=4096)
def _num_cells_cached(lo: Any, hi: Any, cuts: tuple) -> tuple:
    out = []
    cur = lo
    for c in cuts:
        if c < lo or c > hi:
            continue
        if cur <= c - 1:
            out.append((cur, c - 1))
        out.append((c, c))
        cur = c + 1
    if cur <= hi:
        out.append((cur, hi))
    return tuple(out)


def num_cells(d: dict) -> List[dict]:
    """The ordered cells of a numeric dimension (inclusive integer ranges; empty cells dropped)."""
    return [{"lo": a, "hi": b} for a, b in _num_cells_cached(d["lo"], d["hi"], tuple(d["cuts"]))]


def _cells(d: dict) -> tuple:
    return _num_cells_cached(d["lo"], d["hi"], tuple(d["cuts"]))


def _at(seq: Any, i: int) -> Any:
    """seq[i] with the reference's out-of-range failure (a negative index must not wrap around)."""
    if i < 0 or i >= len(seq):
        raise IndexError("cell index %r out of range" % (i,))
    return seq[i]


def cell_count(d: dict) -> int:
    return len(_cells(d)) if d["kind"] == "num" else len(d["values"])


def verb_cell_count(vs: dict) -> int:
    n = 1
    for d in vs["dims"]:
        n *= cell_count(d)
    return n


def decode_cell(vs: dict, flat: Any) -> List[int]:
    dims = vs["dims"]
    idx = [0] * len(dims)
    for i in range(len(dims) - 1, -1, -1):
        n = cell_count(dims[i])
        idx[i] = int(flat % n)
        flat = math.floor(flat / n)
    return idx


def encode_cell(vs: dict, idx: List[int]) -> int:
    flat = 0
    for i, d in enumerate(vs["dims"]):
        flat = flat * cell_count(d) + idx[i]
    return flat


def cat_cell_of(d: dict, s: str) -> int:
    """Which cell of a categorical dimension a concrete string falls in (exact > longest prefix > OTHER)."""
    best = -1
    best_len = -1
    for i, v in enumerate(d["values"]):
        if v["kind"] == "exact" and v["value"] == s:
            return i
        if v["kind"] == "prefix" and s.startswith(v["value"]) and _u16len(v["value"]) > best_len:
            best = i
            best_len = _u16len(v["value"])
    if best >= 0:
        return best
    for i, v in enumerate(d["values"]):
        if v["kind"] == "other":
            return i
    return -1


def _u16len(s: str) -> int:
    return sum(2 if ord(c) > 0xFFFF else 1 for c in s)


def cell_of_value(d: dict, x: Any) -> int:
    """Which cell a concrete value falls in, or -1 when it is outside the dimension's domain/type."""
    if d["kind"] == "num":
        if not is_finite_number(x):
            return -1
        for i, (lo, hi) in enumerate(_cells(d)):
            if x >= lo and x <= hi:
                return i
        return -1
    if not isinstance(x, str):
        return -1
    return cat_cell_of(d, x)


def cell_of(vs: dict, o: dict) -> Optional[List[int]]:
    idx: List[int] = []
    values = o.get("values") or {}
    for d in vs["dims"]:
        i = cell_of_value(d, values.get(d["path"]))
        if i < 0:
            return None
        idx.append(i)
    return idx


def cat_rep(d: dict, i: int) -> str:
    v = _at(d["values"], i)
    if v["kind"] == "exact":
        return v["value"]
    base = v["value"] + "x" if v["kind"] == "prefix" else "other"
    for k in range(64):
        s = base + ("" if k == 0 else str(k))
        if cat_cell_of(d, s) == i:
            return s
    return base


def num_rep(d: dict, i: int) -> Any:
    lo, hi = _at(_cells(d), i)
    return lo if i > 0 else hi


def rep_value(d: dict, i: int) -> Any:
    return num_rep(d, i) if d["kind"] == "num" else cat_rep(d, i)


def cell_rep(vs: dict, idx: List[int]) -> dict:
    values: Dict[str, Any] = {}
    for i, d in enumerate(vs["dims"]):
        values[d["path"]] = rep_value(d, idx[i])
    return {"verb": vs["verb"], "values": values}


# ---- workload and harm -------------------------------------------------------------------------------------------

def _point_weight(d: dict, x: Any) -> float:
    if d.get("dist") == "loguniform" and d["lo"] >= 0:
        return 1 / (x + 1)
    return 1


_AMOUNT_RE = re.compile(r"(^|\.)amount$")


def _linear_amount(d: dict) -> bool:
    return d["kind"] == "num" and _AMOUNT_RE.search(d["path"]) is not None


class HarmModel:
    """verb(vs) -> float; dim(d, x) -> float; dim_mean(d, lo, hi) -> float (optional closed form of the mean over an interval)."""

    def __init__(self, verb: Callable, dim: Callable, dim_mean: Optional[Callable] = None):
        self.verb = verb
        self.dim = dim
        self.dim_mean = dim_mean


def _default_verb(vs: dict) -> float:
    r = vs.get("reversibility")
    return 10 if r == "irreversible" else 3 if r == "rate_limited" else 1


def _default_dim(d: dict, x: Any) -> float:
    return 1 + max(0, x) / 100 if _linear_amount(d) and is_number(x) else 1


def _default_dim_mean(d: dict, lo: Any, hi: Any) -> float:
    if not _linear_amount(d):
        return 1
    return 1 + max(0, _interval_mean_x(d, max(lo, 0), hi, lo)) / 100


DEFAULT_HARM = HarmModel(_default_verb, _default_dim, _default_dim_mean)


def harm_max(omega: dict, harm: HarmModel = DEFAULT_HARM) -> float:
    m = 0
    for vs in omega["verbs"]:
        f = harm.verb(vs)
        for d in vs["dims"]:
            if d["kind"] == "num":
                f *= max(harm.dim(d, d["lo"]), harm.dim(d, d["hi"]))
            else:
                f *= max([harm.dim(d, cat_rep(d, i)) for i in range(len(d["values"]))])
        m = max(m, f)
    return m


def _harmonic(n: Any) -> float:
    if n <= 0:
        return 0
    if n <= EXACT_SPAN:
        s = 0.0
        for k in range(int(n), 0, -1):
            s += 1 / k
        return s
    n = float(n)
    n2 = n * n
    return math.log(n) + EULER_GAMMA + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2)


def interval_weight(d: dict, a: Any, b: Any) -> float:
    """Sum of the dimension's law over the integers a..b (0 for an empty interval)."""
    if b < a:
        return 0
    if not (d.get("dist") == "loguniform" and d["lo"] >= 0):
        return b - a + 1
    if b - a + 1 <= EXACT_SPAN:
        s = 0.0
        x = int(b)
        while x >= a:
            s += 1 / (x + 1)
            x -= 1
        return s
    return _harmonic(float(b) + 1) - _harmonic(a)


def _interval_first_moment(d: dict, a: Any, b: Any) -> float:
    if b < a:
        return 0
    a, b = float(a), float(b)
    if not (d.get("dist") == "loguniform" and d["lo"] >= 0):
        return ((a + b) * (b - a + 1)) / 2
    return b - a + 1 - interval_weight(d, a, b)


def _interval_mean_x(d: dict, a: Any, b: Any, cell_lo: Any) -> float:
    whole = interval_weight(d, cell_lo, b)
    return _interval_first_moment(d, a, b) / whole if whole > 0 else 0


def _interval_harm(d: dict, a: Any, b: Any, harm: HarmModel) -> float:
    if harm.dim_mean is not None:
        return harm.dim_mean(d, a, b)
    n = float(b) - float(a) + 1
    w_tot = interval_weight(d, a, b)
    if not (w_tot > 0):
        return harm.dim(d, a)
    if n <= EXACT_SPAN:
        s = 0.0
        x = a
        while x <= b:
            s += _point_weight(d, x) * harm.dim(d, x)
            x += 1
        return s / w_tot
    s = 0.0
    fa = float(a)
    for i in range(HARM_QUADRATURE_PIECES):
        pa = fa + math.floor(float(i) * n / HARM_QUADRATURE_PIECES)
        pb = fa + math.floor(float(i + 1) * n / HARM_QUADRATURE_PIECES) - 1
        if pb < pa:
            continue
        w = interval_weight(d, pa, pb)
        s += w * harm.dim(d, js_round((pa + pb) / 2))
    return s / w_tot


@lru_cache(maxsize=4096)
def _dim_total_cached(lo: Any, hi: Any, dist: Any) -> float:
    return interval_weight({"lo": lo, "dist": dist}, lo, hi)


def _dim_total(d: dict) -> float:
    return _dim_total_cached(d["lo"], d["hi"], d.get("dist"))


def dim_cell_stats(d: dict, i: int, harm: HarmModel = DEFAULT_HARM) -> dict:
    """mu_d(cell) and E[g_d | cell] for one dimension cell. Categorical values are uniform."""
    if d["kind"] == "cat":
        return {"mass": 1 / len(d["values"]), "harm": harm.dim(d, cat_rep(d, i))}
    lo, hi = _at(_cells(d), i)
    wm = interval_weight(d, lo, hi)
    return {"mass": wm / _dim_total(d), "harm": _interval_harm(d, lo, hi, harm) if wm > 0 else harm.dim(d, lo)}


def _quantile_value(d: dict, target: float) -> Any:
    acc = 0.0
    cells = _cells(d)
    for ci, (lo, hi) in enumerate(cells):
        w = interval_weight(d, lo, hi)
        if target < acc + w or ci == len(cells) - 1:
            r = target - acc
            if hi - lo + 1 <= EXACT_SPAN:
                x = lo
                while x < hi:
                    r -= _point_weight(d, x)
                    if r < 0:
                        return x
                    x += 1
                return hi
            if not (d.get("dist") == "loguniform" and d["lo"] >= 0):
                return min(hi, lo + math.floor(r))
            x = math.floor((float(lo) + 1) * math.exp(r) - 1)
            return max(lo, min(hi, x))
        acc += w
    return d["hi"]


def cell_stats(vs: dict, idx: List[int], harm: HarmModel = DEFAULT_HARM) -> dict:
    mass = vs["weight"]
    h = harm.verb(vs)
    for k, d in enumerate(vs["dims"]):
        s = dim_cell_stats(d, idx[k], harm)
        mass *= s["mass"]
        h *= s["harm"]
    return {"mass": mass, "harm": h}


def harm_of(vs: dict, o: dict, harm: HarmModel = DEFAULT_HARM) -> float:
    h = harm.verb(vs)
    values = o.get("values") or {}
    for d in vs["dims"]:
        h *= harm.dim(d, values.get(d["path"]))
    return h


def rng(seed: Any) -> Callable[[], float]:
    """A small seeded PRNG (mulberry32), bit-identical to the reference."""
    state = [int(seed) & 0xFFFFFFFF]
    M = 0xFFFFFFFF

    def nxt() -> float:
        state[0] = (state[0] + 0x6D2B79F5) & M
        t = state[0]
        t = ((t ^ (t >> 15)) * (t | 1)) & M
        t ^= (t + (((t ^ (t >> 7)) * (t | 61)) & M)) & M
        return ((t ^ (t >> 14)) & M) / 4294967296

    return nxt


def sample_outcome(omega: dict, rand: Callable[[], float], _harm: HarmModel = DEFAULT_HARM) -> Tuple[dict, dict]:
    """Draw an outcome from the workload: (verb space, outcome)."""
    u = rand()
    vs = omega["verbs"][-1]
    for v in omega["verbs"]:
        if u < v["weight"]:
            vs = v
            break
        u -= v["weight"]
    values: Dict[str, Any] = {}
    for d in vs["dims"]:
        if d["kind"] == "cat":
            values[d["path"]] = cat_rep(d, min(len(d["values"]) - 1, math.floor(rand() * len(d["values"]))))
            continue
        values[d["path"]] = _quantile_value(d, rand() * _dim_total(d))
    return vs, {"verb": vs["verb"], "values": values}


# ---- derivation from policies + slots ----------------------------------------------------------------------------

class _FieldLits:
    def __init__(self) -> None:
        self.nums: Dict[Any, None] = {}
        self.exacts: Dict[str, None] = {}
        self.prefixes: Dict[str, None] = {}


def _lits(m: Dict[str, _FieldLits], path: str) -> _FieldLits:
    f = m.get(path)
    if f is None:
        f = m[path] = _FieldLits()
    return f


def _int_if_integral(x: Any) -> Any:
    return int(x) if isinstance(x, float) and x.is_integer() and abs(x) < 2 ** 63 else x


def _add_num(f: _FieldLits, x: Any) -> None:
    if not is_finite_number(x):
        return
    f.nums[_int_if_integral(math.floor(x))] = None
    f.nums[_int_if_integral(math.ceil(x))] = None


def _collect_cond(c: Any, m: Dict[str, _FieldLits], approx: set) -> None:
    from .predicates import is_group_condition, is_leaf_condition
    if c is None or not isinstance(c, dict):
        return
    if is_group_condition(c):
        if "all_of" in c and isinstance(c["all_of"], list):
            for x in c["all_of"]:
                _collect_cond(x, m, approx)
        elif "any_of" in c and isinstance(c["any_of"], list):
            for x in c["any_of"]:
                _collect_cond(x, m, approx)
        elif "not" in c:
            _collect_cond(c["not"], m, approx)
        return
    if not is_leaf_condition(c):
        return
    field = c["field"]
    op = c.get("op")
    if c.get("ref") is not None:
        approx.add("cross-field ref on " + field)
    if op in ("like", "matches", "is_a", "member_of"):
        approx.add("%s on %s" % (op, field))
    if op == "exists":
        _lits(m, field)
        return
    f = _lits(m, field)
    value = c.get("value")
    vals = value if isinstance(value, list) else [value]
    for v in vals:
        if is_number(v):
            _add_num(f, v)
        elif isinstance(v, str):
            (f.prefixes if op == "prefix" else f.exacts)[v] = None


def _add_resource(r: Any, m: Dict[str, _FieldLits], approx: set) -> None:
    if not isinstance(r, str) or r == "*":
        return
    if r.startswith("re:"):
        approx.add("re: resource matcher")
        return
    f = _lits(m, "action.resource")
    if r.endswith("*"):
        f.prefixes[r[:-1]] = None
    else:
        f.exacts[r] = None


def _verbs_of(p: Any) -> Any:
    v = p.get("verb") if isinstance(p, dict) else None
    if isinstance(v, str):
        return "*" if v == "*" else [v]
    if isinstance(v, list):
        return "*" if "*" in v else [x for x in v if isinstance(x, str)]
    return []


def _catalog_all(catalog: Any) -> List[dict]:
    if catalog is None:
        from .facade import BUILTIN_ACTIONS
        catalog = BUILTIN_ACTIONS
    if isinstance(catalog, dict):
        return list(catalog.values())
    by: Dict[str, dict] = {}
    for s in catalog:
        by[s["verb"]] = s
    return list(by.values())


def derive_omega(opts: dict) -> dict:
    """Derive the outcome space from the vocabulary of the policies and the intent slots. Wildcard verbs expand to the
    catalog verbs of every connector that appears anywhere (or the whole catalog when none does)."""
    from .intent_policy import normalize_policy
    pool_all = _catalog_all(opts.get("catalog"))
    cat_by_verb = {s["verb"]: s for s in pool_all}
    approx: set = set()
    preds: List[Any] = []
    for p in opts["policies"]:
        preds.extend(normalize_policy(p)["predicates"])
    slots = opts.get("slots")
    explicit: Dict[str, None] = {}
    for v in opts.get("extraVerbs") or []:
        explicit[v] = None
    wildcard = False
    for p in preds:
        vs = _verbs_of(p)
        if vs == "*":
            wildcard = True
        else:
            for v in vs:
                explicit[v] = None
    for v in (slots.get("verbs") if isinstance(slots, dict) else None) or []:
        explicit[v] = None
    if wildcard:
        connectors = {v.split(".")[0] for v in explicit}
        pool = [s for s in pool_all if s["connector"] in connectors] if connectors else pool_all
        for s in pool:
            explicit[s["verb"]] = None
    domains = opts.get("domains") or {}
    out: List[dict] = []
    for verb in sorted(explicit, key=u16key):
        m: Dict[str, _FieldLits] = {}
        for p in preds:
            pv = _verbs_of(p)
            if pv != "*" and verb not in pv:
                continue
            _add_resource(p.get("resource") if isinstance(p.get("resource"), str) else None, m, approx)
            if isinstance(p.get("where"), list):
                for c in p["where"]:
                    _collect_cond(c, m, approx)
        for sc in (slots.get("constraints") if isinstance(slots, dict) else None) or []:
            if sc.get("verb") is not None and sc.get("verb") != verb:
                continue
            f = _lits(m, sc["path"])
            if sc.get("max") is not None:
                _add_num(f, sc["max"])
            if sc.get("min") is not None:
                _add_num(f, sc["min"])
            for x in sc.get("oneOf") or []:
                f.exacts[x] = None
            for x in sc.get("noneOf") or []:
                f.exacts[x] = None
            for x in sc.get("prefixOneOf") or []:
                f.prefixes[x] = None
        dims: List[dict] = []
        for path in sorted(m, key=u16key):
            f = m[path]
            if len(f.nums) > 0 or (not f.exacts and not f.prefixes and path in DEFAULT_DOMAINS):
                cuts = sorted(f.nums)
                dom = domains.get(path) or DEFAULT_DOMAINS.get(path)
                max_cut = cuts[-1] if cuts else 0
                min_cut = cuts[0] if cuts else 0
                lo = dom["lo"] if dom and dom.get("lo") is not None else min(0, min_cut - 1)
                hi = dom["hi"] if dom and dom.get("hi") is not None else max(10, 2 * max_cut, max_cut + 10)
                dist = dom.get("dist") if dom and dom.get("dist") is not None else ("loguniform" if lo >= 0 else "uniform")
                dims.append({"kind": "num", "path": path, "lo": lo, "hi": hi, "cuts": [c for c in cuts if lo <= c <= hi], "dist": dist})
            else:
                values = [{"kind": "exact", "value": v} for v in sorted(f.exacts, key=u16key)]
                values += [{"kind": "prefix", "value": v} for v in sorted(f.prefixes, key=u16key)]
                values.append({"kind": "other", "value": OTHER})
                dims.append({"kind": "cat", "path": path, "values": values})
        spec = cat_by_verb.get(verb)
        out.append({"verb": verb, "reversibility": (spec or {}).get("reversibility", "irreversible"), "weight": 0, "dims": dims})
    for v in out:
        v["weight"] = 1 / len(out)
    return {"v": 1, "verbs": out, "approximate": sorted(approx, key=u16key)}


def verb_space(omega: dict, verb: str) -> Optional[dict]:
    for v in omega["verbs"]:
        if v["verb"] == verb:
            return v
    return None


# ---- IEEE-754 behaviour of the JS Math functions (Python raises where JS returns NaN / Infinity) -----------------------

def js_div(a: float, b: float) -> float:
    try:
        return a / b
    except ZeroDivisionError:
        if a != a or a == 0:
            return math.nan
        neg = (a < 0) != (math.copysign(1.0, b) < 0)
        return -math.inf if neg else math.inf


def js_sqrt(x: float) -> float:
    return math.nan if x != x or x < 0 else math.sqrt(x)


def js_log(x: float) -> float:
    if x != x or x < 0:
        return math.nan
    if x == 0:
        return -math.inf
    return math.log(x)


def js_max(a: float, b: float) -> float:
    return math.nan if a != a or b != b else max(a, b)


def js_min(a: float, b: float) -> float:
    return math.nan if a != a or b != b else min(a, b)
