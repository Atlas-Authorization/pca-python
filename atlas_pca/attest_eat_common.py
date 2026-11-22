"""Shared helpers for the EAT attestation modules: JavaScript-faithful property access, string and number coercion, the
constant-time compare and the clock, so the port refuses and words its reasons exactly as the TypeScript reference
(@atlasauth/pca-attest-eat) does on hostile JSON input."""
from ._fin import fin
import hmac
import time
from typing import Any

from .attest_common import _utf8, js_number, js_str
from .oauth import _js_json

__all__ = ["U", "G", "has", "is_number", "is_finite", "js_string", "ct_eq", "now_ms", "js_json", "utf8", "to_number", "js_includes",
           "js_strict_eq", "msg_of"]


class _Undefined:
    """JavaScript `undefined`, kept apart from JSON null (which is `None`)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False


U = _Undefined()
utf8 = _utf8
js_json = _js_json


def G(o: Any, k: str) -> Any:
    """`o.k`: the member, `U` when absent or when `o` is a value without members; a TypeError on null/undefined (as JS)."""
    if o is None or o is U:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    if isinstance(o, dict):
        return o.get(k, U)
    return U


def has(o: Any, k: str) -> bool:
    """`o.k !== undefined` (an explicit null counts as defined)."""
    return G(o, k) is not U


def is_number(v: Any) -> bool:
    """typeof v === 'number'."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def is_finite(v: Any) -> bool:
    """typeof v === 'number' && Number.isFinite(v)."""
    return is_number(v) and fin(v)


def js_string(v: Any) -> str:
    """String(v)."""
    if v is U:
        return "undefined"
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if v != v:
            return "NaN"
        if v in (float("inf"), float("-inf")):
            return "Infinity" if v > 0 else "-Infinity"
        return js_str(v) if v.is_integer() else repr(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return ",".join("" if x is None or x is U else js_string(x) for x in v)
    return "[object Object]"


def to_number(v: Any) -> float:
    """Number(v) for the JSON value shapes (NaN where JavaScript yields NaN)."""
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if is_number(v):
        return float(v)
    if isinstance(v, str):
        return js_number(v)
    if isinstance(v, list):
        return js_number(js_string(v))
    return float("nan")


def ct_eq(a: Any, b: Any) -> bool:
    """Length-checked constant-time equality over UTF-8 (a non-string throws, as Buffer.from(undefined) does)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("the first argument must be of type string")
    x, y = utf8(a), utf8(b)
    return len(x) == len(y) and hmac.compare_digest(x, y)


def now_ms() -> int:
    return int(time.time() * 1000)


def js_strict_eq(a: Any, b: Any) -> bool:
    """a === b for JSON values (no bool/number mixing; containers by identity)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if is_number(a) and is_number(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if a is None or b is None or a is U or b is U:
        return a is b
    return a is b


def js_includes(seq: Any, v: Any) -> bool:
    """Array.prototype.includes (SameValueZero) over a list."""
    return any(js_strict_eq(x, v) for x in seq)


def msg_of(e: BaseException) -> str:
    return str(e) or "unknown"

