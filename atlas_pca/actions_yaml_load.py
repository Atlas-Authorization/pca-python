"""YAML text for the authoring-file loader (loadActionsText). The syntax layer is ruamel.yaml's YAML 1.2 scanner and parser (the
optional `yaml` extra); only its EVENT stream is used. Everything the reference decides about meaning is done here, so the result does
not depend on ruamel's own resolver, merge-key or alias handling: the tree is built from events, plain scalars are resolved with the
YAML 1.2 core schema (null, bool, int, 0o / 0x, float, .inf, .nan; everything else a string), mapping keys are stringified the way
JavaScript does, aliases are refused, `<<` is an ordinary key, and positions are the 1-based start of each action and each param key.

Where this differs from the reference it is STRICTER (it refuses): an explicit tag other than !!str / !!map / !!seq, a complex
(non-scalar) mapping key, two keys that are equal once stringified (the reference keeps the last of 1 and "1"), a bare carriage return
used as a line break, more than one document. Syntax error wording and line/column of a syntax error are the parser's own."""
from __future__ import annotations

import math
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .predicates import _js_number_string

_STR = "tag:yaml.org,2002:str"
_OK_TAGS = {_STR, "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq"}
_INT = re.compile(r"[-+]?[0-9]+")
_OCT = re.compile(r"0o[0-7]+")
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_FLOAT = re.compile(r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?")
_INF = re.compile(r"[-+]?\.(?:inf|Inf|INF)")
_NAN = re.compile(r"\.(?:nan|NaN|NAN)")
_SAFE = 2 ** 53


class YamlError(Exception):
    def __init__(self, message: str, line: int = 1, column: int = 1):
        super().__init__(message)
        self.message, self.line, self.column = message, line, column


class _N:
    """A parsed node: kind 'scalar' | 'map' | 'seq', its resolved value, children and 1-based start position."""
    __slots__ = ("kind", "value", "items", "line", "col", "plain_key")

    def __init__(self, kind: str, line: int, col: int):
        self.kind, self.line, self.col = kind, line, col
        self.value: Any = None
        self.items: List[Any] = []  # seq: nodes; map: (key node, value node)


def _js_int(text: str, radix: int = 10) -> Any:
    neg = text.startswith("-")
    n = int(text[1:] if text[:1] in "+-" else text, radix) if radix == 10 else int(text, radix)
    if neg and n == 0:
        return -0.0
    n = -n if neg else n
    return n if abs(n) <= _SAFE else float(n)


def resolve_core_plain(text: str) -> Any:
    """The YAML 1.2 core schema value of a plain scalar, as a JavaScript number / boolean / null / string."""
    if text in ("", "~", "null", "Null", "NULL"):
        return None
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if _INT.fullmatch(text):
        return _js_int(text)
    if _OCT.fullmatch(text):
        return _js_int(text[2:], 8)
    if _HEX.fullmatch(text):
        return _js_int(text[2:], 16)
    if _INF.fullmatch(text):
        return -math.inf if text[0] == "-" else math.inf
    if _NAN.fullmatch(text):
        return math.nan
    if _FLOAT.fullmatch(text):
        f = float(text)
        return int(f) if f.is_integer() and abs(f) <= _SAFE and not (f == 0 and text.lstrip("+").startswith("-")) else f
    return text


def _js_key(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return _js_number_string(float(v))
    return v


def _event_source(text: str) -> Any:
    """The parser event stream (ruamel.yaml). Tests may substitute another event source."""
    try:
        from ruamel.yaml import YAML
    except ImportError as e:
        raise RuntimeError("YAML needs ruamel.yaml (pip install 'atlas-pca[yaml]')") from e
    y = YAML(typ="rt")
    y.version = (1, 2)
    return y.parse(text)


def _kind(ev: Any) -> str:
    return type(ev).__name__


def _mark(ev: Any) -> Tuple[int, int]:
    m = ev.start_mark
    return m.line + 1, m.column + 1


def parse_document(text: str, strict: bool = True) -> Optional[_N]:
    """The one document of `text` as a node tree (None for an empty stream). `strict` (YAML files) refuses duplicate keys; JSON text is
    parsed leniently because only its positions are used."""
    if re.search(r"\r(?!\n)", text):
        raise YamlError("bare carriage return is not accepted as a line break")
    try:
        events = list(_event_source(text))
    except YamlError:
        raise
    except Exception as e:  # noqa: BLE001
        mk = getattr(e, "problem_mark", None)
        msg = getattr(e, "problem", None) or (str(e).splitlines() or ["syntax error"])[0]
        raise YamlError(msg, *((mk.line + 1, mk.column + 1) if mk is not None else (1, 1))) from None
    pos = [0]
    docs = 0

    def node() -> _N:
        ev = events[pos[0]]
        pos[0] += 1
        k = _kind(ev)
        line, col = _mark(ev)
        if k == "AliasEvent":
            raise YamlError("Alias resolution is disabled", line, col)
        tag = getattr(ev, "tag", None)
        if tag is not None and tag not in _OK_TAGS and not (k == "ScalarEvent" and tag in _OK_TAGS):
            raise YamlError("Unresolved or unsupported tag: %s" % tag, line, col)
        if k == "ScalarEvent":
            n = _N("scalar", line, col)
            plain = ev.style in (None, "") and tag is None
            val = ev.value
            if ev.style == ">" and isinstance(val, str):
                val = val.replace("\a", "")  # the round-trip scanner marks each fold of a folded scalar with a bell character
            n.value = resolve_core_plain(val) if plain else val
            return n
        if k == "SequenceStartEvent":
            n = _N("seq", line, col)
            while _kind(events[pos[0]]) != "SequenceEndEvent":
                n.items.append(node())
            pos[0] += 1
            return n
        if k == "MappingStartEvent":
            n = _N("map", line, col)
            seen = set()
            while _kind(events[pos[0]]) != "MappingEndEvent":
                key = node()
                val = node()
                if strict:
                    if key.kind != "scalar":
                        raise YamlError("complex mapping keys are not accepted", key.line, key.col)
                    s = _js_key(key.value)
                    if s in seen:
                        raise YamlError("Map keys must be unique", key.line, key.col)
                    seen.add(s)
                n.items.append((key, val))
            pos[0] += 1
            return n
        raise YamlError("unexpected parser event %s" % k, line, col)

    root: Optional[_N] = None
    while pos[0] < len(events):
        k = _kind(events[pos[0]])
        if k == "DocumentStartEvent":
            docs += 1
            if docs > 1:
                raise YamlError("Source contains multiple documents; please use YAML.parseAllDocuments()")
            pos[0] += 1
            if _kind(events[pos[0]]) != "DocumentEndEvent":
                root = node()
        else:
            pos[0] += 1
    return root


def to_value(n: Optional[_N]) -> Any:
    if n is None:
        return None
    if n.kind == "scalar":
        return n.value
    if n.kind == "seq":
        return [to_value(x) for x in n.items]
    out: Dict[str, Any] = {}
    for k, v in n.items:
        if k.kind != "scalar":
            raise YamlError("complex mapping keys are not accepted", k.line, k.col)
        out[_js_key(k.value)] = to_value(v)
    return out


def positions_of(root: Optional[_N]) -> Optional[List[dict]]:
    """Per-entry positions of an authoring document (`actions` items and their `params` keys), by entry index; None when not a mapping."""
    if root is None or root.kind != "map":
        return None
    actions = None
    for k, v in root.items:
        if k.kind == "scalar" and k.value == "actions":
            actions = v
    items = actions.items if actions is not None and actions.kind == "seq" else [root]
    out = []
    for it in items:
        params: Dict[str, dict] = {}
        if it.kind == "map":
            pm = None
            for k, v in it.items:
                if k.kind == "scalar" and k.value == "params":
                    pm = v
            if pm is not None and pm.kind == "map":
                for k, _ in pm.items:
                    if k.kind == "scalar":
                        params[_js_key(k.value) if k.value is not None else ""] = {"line": k.line, "column": k.col}
        out.append({"item": {"line": it.line, "column": it.col}, "params": params})
    return out


def attach_positions(res: dict, pos: List[dict]) -> None:
    failed = {e["index"] for e in res["errors"] if e.get("index") is not None}
    order = [i for i in range(len(pos)) if i not in failed]
    for k, d in enumerate(res["defs"]):
        p = pos[order[k]] if k < len(order) else None
        if p:
            res["locs"][d["verb"]] = {**p["item"], "params": p["params"]}
    for e in res["errors"]:
        p = pos[e["index"]] if e.get("index") is not None and 0 <= e["index"] < len(pos) else None
        if p:
            e["line"], e["column"] = p["item"]["line"], p["item"]["column"]
        elif e.get("index") is None:
            e["line"], e["column"] = 1, 1
