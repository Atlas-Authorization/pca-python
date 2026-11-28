"""Stable JSON and canonical Goal order (the TypeScript reference is @atlasauth/pca-goal `normalize`)."""
import json
import re
from functools import cmp_to_key
from typing import Any

from .analyzer_js import UNDEF, js_json, js_str, u16key

__all__ = ["stable", "canonicalize_goal", "jq"]

_LONE = re.compile("[\ud800-\udfff]")


def jq(v: Any) -> str:
    """JSON.stringify of a value; a string's lone surrogates are escaped (well-formed JSON.stringify)."""
    if isinstance(v, str):
        return _LONE.sub(lambda m: "\\u%04x" % ord(m.group()), json.dumps(v, ensure_ascii=False))
    return js_json(v)


def stable(v: Any) -> str:
    """Sorted-key JSON, undefined members dropped: an in-memory key for maps and sets, NOT a signed encoding."""
    if v is None or not isinstance(v, (dict, list, tuple)):
        return jq(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join("" if x is UNDEF else stable(x) for x in v) + "]"
    keys = sorted((k for k in v if v[k] is not UNDEF), key=u16key)
    return "{" + ",".join(jq(k) + ":" + stable(v[k]) for k in keys) + "}"


def _by_id(f):
    def cmp(a: Any, b: Any) -> int:
        x, y = f(a), f(b)
        if isinstance(x, str) and isinstance(y, str):
            ka, kb = u16key(x), u16key(y)
            return -1 if ka < kb else (1 if ka > kb else 0)
        return 0
    return cmp_to_key(cmp)


def _sorted_unique(xs: Any) -> list:
    if not isinstance(xs, (list, tuple)):
        raise TypeError("not iterable")
    return sorted(dict.fromkeys(xs), key=lambda x: u16key(js_str(x)))


def canonicalize_goal(g: Any) -> dict:
    """Grants, prohibits, bounds and holes strictly increasing by id (code-unit order), wildcardAck / mayTouch sorted and
    de-duplicated. Duplicated ids are NOT merged: they stay and the typechecker refuses them."""
    out = dict(g)
    out["grants"] = sorted(list(g["grants"]), key=_by_id(lambda x: x["gid"]))
    out["prohibits"] = sorted(list(g["prohibits"]), key=_by_id(lambda x: x["pid"]))
    out["bounds"] = sorted(list(g["bounds"]), key=_by_id(lambda x: x["bid"]))
    out["holes"] = sorted(list(g["holes"]), key=_by_id(lambda x: x["hid"]))
    out["wildcardAck"] = _sorted_unique(g["wildcardAck"])
    d = dict(g["deleg"])
    d["mayTouch"] = _sorted_unique(g["deleg"]["mayTouch"])
    out["deleg"] = d
    return out
