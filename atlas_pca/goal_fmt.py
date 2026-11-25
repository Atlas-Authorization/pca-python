"""Rendering helpers for quantities, values and actions (the TypeScript reference is @atlasauth/pca-goal `fmt`)."""
from typing import Any

from .analyzer_js import UNDEF, jget, js_str, req_list
from .goal_normalize import jq
from .goal_codec import okeys, oget
from .analyzer_js import u16key

__all__ = ["CCY_EXPONENT", "fmt_money", "fmt_quantity", "fmt_value", "fmt_act"]

# An unknown currency is shown in raw minor units, never guessed.
CCY_EXPONENT = {"USD": 2, "EUR": 2, "GBP": 2, "CAD": 2, "AUD": 2, "CHF": 2, "JPY": 0, "KRW": 0}


def fmt_money(ccy: Any, minor: Any) -> str:
    e = CCY_EXPONENT.get(ccy) if isinstance(ccy, str) else None
    if e is None:
        return "%s %s (minor units)" % (js_str(ccy), js_str(minor))
    if e == 0:
        return "%s %s" % (js_str(ccy), js_str(minor))
    s = js_str(minor).rjust(e + 1, "0")
    return "%s %s.%s" % (js_str(ccy), s[:-e], s[-e:])


def fmt_quantity(q: Any) -> Any:
    """The rendered text; UNDEF (JavaScript undefined) for an unknown unit tag."""
    u = jget(q, "u")
    k = jget(u, "k")
    n = jget(q, "n")
    if k == "money":
        return fmt_money(jget(u, "ccy"), n)
    if k == "count":
        return js_str(n)
    if k == "duration":
        return js_str(n) + "ms"
    if k == "instant":
        return "@" + js_str(n)
    if k == "bytes":
        return js_str(n) + "B"
    if k == "ratio":
        return js_str(n) + "ppm"
    return UNDEF  # the reference switch has no default: undefined


def fmt_value(v: Any) -> Any:
    k = jget(v, "k")
    if k == "q":
        return fmt_quantity(jget(v, "q"))
    if k == "s":
        return jq(jget(v, "s")) if jget(v, "s") is not UNDEF else UNDEF
    return "{" + ", ".join("" if x is UNDEF else x for x in (fmt_value(i) for i in req_list(jget(v, "items")))) + "}"


def fmt_act(a: Any) -> str:
    params = jget(a, "params")
    ps = ", ".join("%s=%s" % (k, js_str(fmt_value(oget(params, k)))) for k in sorted(okeys(params), key=u16key))
    return "%s on %s%s" % (js_str(jget(a, "verb")), js_str(jget(a, "res")), " (%s)" % ps if ps else "")
