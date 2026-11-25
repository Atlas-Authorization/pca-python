"""JavaScript-semantics helpers for the analyzer port (the TypeScript reference is @atlasauth/pca-analyzer).

Inputs are JSON trees as `json.loads` yields them. A missing member is `UNDEF` (JavaScript `undefined`), `None` is `null`;
`UNDEF` never appears in a result (`uobj` drops it)."""
import json
import math
import re
from typing import Any, Dict, Iterable, List

from .predicates import _UNDEF as UNDEF
from .predicates import _is_arr, _is_num, _is_obj, _js_number_string, _js_string, _jsnum

__all__ = [
    "UNDEF", "jget", "oget", "to_fixed", "u16key", "has", "is_fin", "fin", "truthy", "strict_eq", "includes", "js_str", "num_str", "to_number", "js_json", "uobj",
    "spread", "req_list", "nn", "own", "js_gt", "js_lt", "js_min", "js_max", "key_order", "is_arr", "is_obj", "is_num", "jsnum",
]

is_arr = _is_arr
is_obj = _is_obj
is_num = _is_num
jsnum = _jsnum
js_str = _js_string
num_str = _js_number_string


def jget(o: Any, k: str) -> Any:
    """`o[k]`: undefined for an absent member or a non-object; reading a member of null / undefined throws, as in JavaScript."""
    if o is None or o is UNDEF:
        raise TypeError("cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    if isinstance(o, dict) and k in o:
        return o[k]
    return UNDEF


def oget(o: Any, k: str) -> Any:
    """`o?.k`: undefined when `o` is null / undefined."""
    return UNDEF if o is None or o is UNDEF else jget(o, k)


def to_fixed(x: float, digits: int = 2) -> str:
    """`x.toFixed(digits)`: exact decimal expansion of the double, ties away from zero."""
    from decimal import ROUND_HALF_UP, Decimal
    if x != x:
        return "NaN"
    if math.isinf(x):
        return "Infinity" if x > 0 else "-Infinity"
    return str(Decimal(x).quantize(Decimal(1).scaleb(-digits), rounding=ROUND_HALF_UP))


def u16key(s: str) -> bytes:
    """Sort key giving JavaScript's default string order (UTF-16 code units)."""
    return s.encode("utf-16-be", "surrogatepass")


def has(o: Any, k: str) -> bool:
    return isinstance(o, dict) and k in o


def own(o: Any, k: str, default: Any = UNDEF) -> Any:
    """An own member of a plain object, else `default` (never throws)."""
    return o[k] if isinstance(o, dict) and k in o else default


def nn(v: Any, default: Any) -> Any:
    """`v ?? default`."""
    return default if v is None or v is UNDEF else v


def fin(v: Any) -> Any:
    """`typeof v === 'number' && Number.isFinite(v)`: the binary64 value, else None."""
    if _is_num(v):
        f = _jsnum(v)
        if math.isfinite(f):
            return f
    return None


def is_fin(v: Any) -> bool:
    return fin(v) is not None


def truthy(v: Any) -> bool:
    if v is None or v is UNDEF or v is False:
        return False
    if v is True:
        return True
    if isinstance(v, str):
        return len(v) > 0
    if _is_num(v):
        f = _jsnum(v)
        return f != 0 and f == f
    return True


def strict_eq(a: Any, b: Any) -> bool:
    """`a === b` over JSON values (objects by identity)."""
    if a is UNDEF or b is UNDEF:
        return a is b
    if a is None or b is None:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_num(a) or _is_num(b):
        return _is_num(a) and _is_num(b) and _jsnum(a) == _jsnum(b)
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b


def includes(xs: Any, x: Any) -> bool:
    """`xs.includes(x)`; a non-array has no `includes` and throws."""
    req_list(xs)
    return any(strict_eq(e, x) for e in xs)


def req_list(x: Any) -> list:
    if not isinstance(x, (list, tuple)):
        raise TypeError("not an array")
    return x  # type: ignore[return-value]


_NUMLIT = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|[+-]?Infinity")


def to_number(v: Any) -> float:
    """`Number(v)` for a JSON value."""
    if v is None:
        return 0.0
    if v is UNDEF:
        return math.nan
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if _is_num(v):
        return _jsnum(v)
    if isinstance(v, str):
        t = v.strip(" \t\n\r\f\v   ﻿")
        if not t:
            return 0.0
        return float(t.replace("Infinity", "inf")) if _NUMLIT.fullmatch(t) else math.nan
    if isinstance(v, list):
        return 0.0 if not v else (to_number(v[0]) if len(v) == 1 else math.nan)
    return math.nan


def js_gt(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a > b
    return to_number(a) > to_number(b)


def js_lt(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a < b
    return to_number(a) < to_number(b)


def js_min(*xs: float) -> float:
    return min(xs)


def js_max(*xs: float) -> float:
    return max(xs)


_LONE = re.compile("[\ud800-\udfff]")


def _quote(s: str) -> str:
    """A JSON string literal as the well-formed JSON.stringify writes it (a lone surrogate becomes a \\uXXXX escape)."""
    return _LONE.sub(lambda m: "\\u%04x" % ord(m.group(0)), json.dumps(s, ensure_ascii=False))


def js_json(v: Any) -> str:
    """`JSON.stringify(v)` of a JSON tree (undefined members dropped, -0 as 0, own-key order)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _quote(v)
    if _is_num(v):
        f = _jsnum(v)
        return "null" if not math.isfinite(f) else _js_number_string(f)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join("null" if x is UNDEF else js_json(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(_quote(k) + ":" + js_json(v[k]) for k in key_order(v) if v[k] is not UNDEF) + "}"
    return "null"


def key_order(m: Dict[str, Any]) -> List[str]:
    """JavaScript own-key order: array-index keys ascending, then insertion order."""
    idx = [k for k in m if k.isdigit() and (k == "0" or k[0] != "0") and len(k) <= 10 and int(k) < 4294967295]
    idx.sort(key=int)
    s = set(idx)
    return idx + [k for k in m if k not in s]


def uobj(d: Dict[str, Any]) -> Dict[str, Any]:
    """An object literal: members whose value is undefined are absent."""
    return {k: v for k, v in d.items() if v is not UNDEF}


def spread(o: Any) -> Dict[str, Any]:
    """`{...o}` (nullish spreads nothing; a string or array spreads its indices)."""
    if isinstance(o, dict):
        return dict(o)
    if isinstance(o, (list, tuple)):
        return {str(i): x for i, x in enumerate(o)}
    if isinstance(o, str):
        u = o.encode("utf-16-le")
        return {str(i): u[2 * i:2 * i + 2].decode("utf-16-le", "surrogatepass") for i in range(len(u) // 2)}
    return {}
