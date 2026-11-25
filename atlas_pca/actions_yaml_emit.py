"""The YAML text the reference writes for an action pack (defsToYaml): a line-for-line port of the default stringifier of the `yaml`
package (v2, core schema, 80 columns): plain, quoted and block scalars, folding, escapes, anchors and aliases for repeated containers.

Strings are processed as UTF-16 code units (an astral character is two surrogate characters) because the reference measures and
folds in code units; the result is recombined at the end. Comments, tags, flow collections and custom schemas are not produced by
the reference for plain data and are not ported."""
from __future__ import annotations

from ._fin import fin, to_float
import math
import re
from typing import Any, Dict, List, Optional

from .predicates import _js_number_string

__all__ = ["defs_to_yaml", "stringify"]

LINE_WIDTH = 80
MIN_CONTENT_WIDTH = 20
DQ_MIN_MULTILINE = 40
_LT = "\n\r\u2028\u2029"


# ---- UTF-16 code unit domain --------------------------------------------------------------------------------------------

def _units(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if o > 0xFFFF:
            o -= 0x10000
            out.append(chr(0xD800 + (o >> 10)))
            out.append(chr(0xDC00 + (o & 0x3FF)))
        else:
            out.append(ch)
    return "".join(out)


def _from_units(s: str) -> str:
    return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _json_string(s: str) -> str:
    """JSON.stringify of a string in the code unit domain (well-formed: lone surrogates are escaped)."""
    out = ['"']
    n = len(s)
    for i, c in enumerate(s):
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c in "\b\f\n\r\t":
            out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[c])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDBFF and i + 1 < n and 0xDC00 <= ord(s[i + 1]) <= 0xDFFF:
            out.append(c)
        elif 0xDC00 <= o <= 0xDFFF and i > 0 and 0xD800 <= ord(s[i - 1]) <= 0xDBFF:
            out.append(c)
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _at(s: str, i: int) -> str:
    return s[i] if 0 <= i < len(s) else ""


# ---- folding ------------------------------------------------------------------------------------------------------------

def _consume_more_indented(text: str, i: int, indent: int) -> int:
    end = i
    start = i + 1
    ch = _at(text, start)
    while ch == " " or ch == "\t":
        if i < start + indent:
            i += 1
            ch = _at(text, i)
        else:
            while True:
                i += 1
                ch = _at(text, i)
                if not ch or ch == "\n":
                    break
            end = i
            start = i + 1
            ch = _at(text, start)
    return end


def _fold(text: str, indent: str, mode: str, indent_at_start: Optional[int], on_overflow: Any = None) -> str:
    line_width, min_content = LINE_WIDTH, MIN_CONTENT_WIDTH
    if min_content > line_width:
        min_content = 0
    end_step = max(1 + min_content, 1 + line_width - len(indent))
    if len(text) <= end_step:
        return text
    folds: List[int] = []
    escaped: Dict[int, bool] = {}
    end = line_width - len(indent)
    if indent_at_start is not None:
        if indent_at_start > line_width - max(2, min_content):
            folds.append(0)
        else:
            end = line_width - indent_at_start
    split: Optional[int] = None
    prev = ""
    overflow = False
    i = -1
    esc_start = esc_end = -1
    if mode == "block":
        i = _consume_more_indented(text, i, len(indent))
        if i != -1:
            end = i + end_step
    while True:
        i += 1
        ch = _at(text, i)
        if not ch:
            break
        if mode == "quoted" and ch == "\\":
            esc_start = i
            nxt = _at(text, i + 1)
            i += 3 if nxt == "x" else 5 if nxt == "u" else 9 if nxt == "U" else 1
            esc_end = i
        if ch == "\n":
            if mode == "block":
                i = _consume_more_indented(text, i, len(indent))
            end = i + len(indent) + end_step
            split = None
        else:
            if ch == " " and prev and prev not in " \n\t":
                nxt = _at(text, i + 1)
                if nxt and nxt not in " \n\t":
                    split = i
            if i >= end:
                if split is not None:
                    folds.append(split)
                    end = split + end_step
                    split = None
                elif mode == "quoted":
                    while prev == " " or prev == "\t":
                        prev = ch
                        i += 1
                        ch = _at(text, i)
                        overflow = True
                    j = i - 2 if i > esc_end + 1 else esc_start - 1
                    if escaped.get(j):
                        return text
                    folds.append(j)
                    escaped[j] = True
                    end = j + end_step
                    split = None
                else:
                    overflow = True
        prev = ch
    if overflow and on_overflow is not None:
        on_overflow()
    if not folds:
        return text
    res = text[:folds[0]]
    for k, fold in enumerate(folds):
        nxt_fold = folds[k + 1] if k + 1 < len(folds) else 0
        stop = nxt_fold if nxt_fold else len(text)
        if fold == 0:
            res = "\n" + indent + text[:stop]
        else:
            if mode == "quoted" and escaped.get(fold):
                res += (text[fold] if 0 <= fold < len(text) else "") + "\\"
            res += "\n" + indent + text[fold + 1:stop]
    return res


# ---- context ------------------------------------------------------------------------------------------------------------

class _Ctx:
    __slots__ = ("indent", "indent_at_start", "implicit_key", "actual_string", "force_block_indent", "anchors")

    def __init__(self) -> None:
        self.indent = ""
        self.indent_at_start: Optional[int] = None
        self.implicit_key = False
        self.actual_string = False
        self.force_block_indent = False
        self.anchors: set = set()

    def copy(self) -> "_Ctx":
        c = _Ctx.__new__(_Ctx)
        for k in _Ctx.__slots__:
            setattr(c, k, getattr(self, k))
        return c


_INDENT_STEP = "  "


def _contains_doc_marker(s: str) -> bool:
    return re.search(r"(?:\A|(?<=[\n\r\u2028\u2029]))(%|---|\.\.\.)", s) is not None


def _fold_opts(ctx: _Ctx, is_block: bool) -> Optional[int]:
    return len(ctx.indent) if is_block else ctx.indent_at_start


def _line_len_over(s: str, line_width: int, indent_len: int) -> bool:
    if not line_width or line_width < 0:
        return False
    limit = line_width - indent_len
    n = len(s)
    if n <= limit:
        return False
    start = 0
    for i in range(n):
        if s[i] == "\n":
            if i - start > limit:
                return True
            start = i + 1
            if n - start <= limit:
                return False
    return True


# ---- strings ------------------------------------------------------------------------------------------------------------

def _double_quoted(value: str, ctx: _Ctx) -> str:
    js = _json_string(value)
    implicit = ctx.implicit_key
    indent = ctx.indent or ("  " if _contains_doc_marker(value) else "")
    out = ""
    start = 0
    i = 0
    n = len(js)
    while i < n:
        ch = js[i]
        if ch == " " and _at(js, i + 1) == "\\" and _at(js, i + 2) == "n":
            out += js[start:i] + "\\ "
            i += 1
            start = i
            ch = "\\"
        if ch == "\\":
            nx = _at(js, i + 1)
            if nx == "u":
                out += js[start:i]
                code = js[i + 2:i + 6]
                m = {"0000": "\\0", "0007": "\\a", "000b": "\\v", "001b": "\\e", "0085": "\\N", "00a0": "\\_", "2028": "\\L", "2029": "\\P"}
                if code in m:
                    out += m[code]
                elif code[:2] == "00":
                    out += "\\x" + code[2:]
                else:
                    out += js[i:i + 6]
                i += 5
                start = i + 1
            elif nx == "n":
                if implicit or _at(js, i + 2) == '"' or len(js) < DQ_MIN_MULTILINE:
                    i += 1
                else:
                    out += js[start:i] + "\n\n"
                    while _at(js, i + 2) == "\\" and _at(js, i + 3) == "n" and _at(js, i + 4) != '"':
                        out += "\n"
                        i += 2
                    out += indent
                    if _at(js, i + 2) == " ":
                        out += "\\"
                    i += 1
                    start = i + 1
            else:
                i += 1
        i += 1
    out = out + js[start:] if start else js
    return out if implicit else _fold(out, indent, "quoted", _fold_opts(ctx, False))


def _single_quoted(value: str, ctx: _Ctx) -> str:
    if (ctx.implicit_key and "\n" in value) or re.search(r"[ \t]\n|\n[ \t]", value):
        return _double_quoted(value, ctx)
    indent = ctx.indent or ("  " if _contains_doc_marker(value) else "")
    res = "'" + re.sub(r"\n+", lambda m: m.group(0) + "\n" + indent, value.replace("'", "''")) + "'"
    return res if ctx.implicit_key else _fold(res, indent, "flow", _fold_opts(ctx, False))


def _quoted(value: str, ctx: _Ctx) -> str:
    has_d, has_s = '"' in value, "'" in value
    if has_d and not has_s:
        return _single_quoted(value, ctx)
    return _double_quoted(value, ctx)  # a lone single quote, both or neither: double (the default)


_END_NL = re.compile(r"(\A|(?<!\n))\n+(?!\n|\Z)")


def _block_string(value: str, ctx: _Ctx) -> str:
    if re.search(r"\n[\t ]+\Z", value):
        return _quoted(value, ctx)
    indent = ctx.indent or ("  " if (ctx.force_block_indent or _contains_doc_marker(value)) else "")
    literal = not _line_len_over(value, LINE_WIDTH, len(indent))
    if not value:
        return "|\n" if literal else ">\n"
    end_start = len(value)
    while end_start > 0 and value[end_start - 1] in "\n\t ":
        end_start -= 1
    end = value[end_start:]
    nl = end.find("\n")
    if nl == -1:
        chomp = "-"
    elif value == end or nl != len(end) - 1:
        chomp = "+"
    else:
        chomp = ""
    if end:
        value = value[:-len(end)]
        if end[-1] == "\n":
            end = end[:-1]
        end = _END_NL.sub(lambda m: m.group(0) + indent, end)
    start_with_space = False
    start_end = 0
    start_nl = -1
    while start_end < len(value):
        ch = value[start_end]
        if ch == " ":
            start_with_space = True
        elif ch == "\n":
            start_nl = start_end
        else:
            break
        start_end += 1
    start = value[:start_nl + 1 if start_nl < start_end else start_end]
    if start:
        value = value[len(start):]
        start = re.sub(r"\n+", lambda m: m.group(0) + indent, start)
    header = ("2" if indent else "1") if start_with_space else ""
    header += chomp
    if not literal:
        folded = re.sub(r"\n+", lambda m: "\n" + m.group(0), value)
        folded = re.sub(r"(?:\A|\n)([\t ][^\n\r\u2028\u2029]*)(?:([\n\t ]*)\n(?![\n\t ]))?", lambda m: m.group(1) + (m.group(2) or ""), folded)
        folded = re.sub(r"\n+", lambda m: m.group(0) + indent, folded)
        fell = [False]

        def over() -> None:
            fell[0] = True
        body = _fold(start + folded + end, indent, "block", len(ctx.indent), over)
        if not fell[0]:
            return ">" + header + "\n" + indent + body
    value = re.sub(r"\n+", lambda m: m.group(0) + indent, value)
    return "|" + header + "\n" + indent + start + value + end


def _plain_tag_tests() -> List[Any]:
    return [re.compile(p) for p in (
        r"(?:~|[Nn]ull|NULL)?", r"(?:[Tt]rue|TRUE|[Ff]alse|FALSE)", r"0o[0-7]+", r"[-+]?[0-9]+", r"0x[0-9a-fA-F]+",
        r"(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)", r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+",
        r"[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)")]


_TAG_TESTS = _plain_tag_tests()
_PLAIN_BAD = re.compile("\\A[\n\t ,\\[\\]{}#&*!|>'\"%@`]|\\A[?-]\\Z|\\A[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]\\Z")


def _plain(value: str, ctx: _Ctx) -> str:
    if ctx.implicit_key and "\n" in value:
        return _quoted(value, ctx)
    if _PLAIN_BAD.search(value):
        return _quoted(value, ctx) if (ctx.implicit_key or "\n" not in value) else _block_string(value, ctx)
    if not ctx.implicit_key and "\n" in value:
        return _block_string(value, ctx)
    if _contains_doc_marker(value):
        if ctx.indent == "":
            ctx.force_block_indent = True
            return _block_string(value, ctx)
        if ctx.implicit_key and ctx.indent == _INDENT_STEP:
            return _quoted(value, ctx)
    s = re.sub(r"\n+", lambda m: m.group(0) + "\n" + ctx.indent, value)
    if ctx.actual_string and any(t.fullmatch(s) for t in _TAG_TESTS):
        return _quoted(value, ctx)
    return s if ctx.implicit_key else _fold(s, ctx.indent, "flow", _fold_opts(ctx, False))


_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _string(raw: str, ctx: _Ctx) -> str:
    lone = any(0xD800 <= ord(c) <= 0xDFFF for c in raw)  # a surrogate in a Python string is never half of a pair
    value = _units(raw)
    if lone or _CONTROL.search(value):
        return _double_quoted(value, ctx)
    return _plain(value, ctx)


def _number(v: Any) -> str:
    f = to_float(v)
    if not fin(f):
        return ".nan" if math.isnan(f) else "-.inf" if f < 0 else ".inf"
    if f == 0 and math.copysign(1.0, f) < 0:
        return "-0"
    return _js_number_string(f)


# ---- nodes --------------------------------------------------------------------------------------------------------------

class _Node:
    __slots__ = ("anchor",)

    def __init__(self) -> None:
        self.anchor: Optional[str] = None


class _Scalar(_Node):
    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        super().__init__()
        self.value = value


class _Seq(_Node):
    __slots__ = ("items",)

    def __init__(self) -> None:
        super().__init__()
        self.items: List[Any] = []


class _Map(_Node):
    __slots__ = ("pairs",)

    def __init__(self) -> None:
        super().__init__()
        self.pairs: List[Any] = []


class _Alias:
    __slots__ = ("source",)

    def __init__(self, source: str) -> None:
        self.source = source


class _Builder:
    """createNode with aliasDuplicateObjects: a container met twice becomes an anchor (named a1, a2, ... in the order the repeats are
    met) on its first occurrence and an alias on every later one; cycles are allowed."""

    def __init__(self) -> None:
        self.seen: Dict[int, List[Any]] = {}
        self.keep: List[Any] = []
        self.n = 0
        self.alias_sources: List[Any] = []

    def node(self, v: Any) -> Any:
        if isinstance(v, (dict, list, tuple)):
            ref = self.seen.get(id(v))
            if ref is not None:
                if ref[0] is None:
                    self.n += 1
                    ref[0] = "a%d" % self.n
                return _Alias(ref[0])
            ref = [None, None]
            self.seen[id(v)] = ref
            self.keep.append(v)
            if isinstance(v, dict):
                m = _Map()
                ref[1] = m
                for k, x in v.items():
                    if not isinstance(k, str):
                        raise TypeError("a mapping key must be a string")
                    m.pairs.append((_Scalar(k), self.node(x)))
                self.alias_sources.append(ref)
                return m
            s = _Seq()
            ref[1] = s
            for x in v:
                s.items.append(self.node(x))
            self.alias_sources.append(ref)
            return s
        if v is None or isinstance(v, (str, bool, int, float)):
            return _Scalar(v)
        raise TypeError("cannot write a %s as YAML" % type(v).__name__)

    def finish(self) -> None:
        for ref in self.alias_sources:
            if ref[0] is not None:
                ref[1].anchor = ref[0]


def _is_coll(n: Any) -> bool:
    return isinstance(n, (_Seq, _Map))


def _stringify(item: Any, ctx: _Ctx) -> str:
    if isinstance(item, _Alias):
        if item.source not in ctx.anchors:
            raise ValueError("Unresolved alias (the anchor must be set before the alias): %s" % item.source)
        return "*%s " % item.source if ctx.implicit_key else "*%s" % item.source
    props = ""
    if item.anchor:
        ctx.anchors.add(item.anchor)
        props = "&" + item.anchor
        ctx.indent_at_start = (ctx.indent_at_start or 0) + len(props) + 1
    if isinstance(item, _Scalar):
        v = item.value
        if isinstance(v, str):
            c = ctx.copy()
            c.actual_string = True
            s = _string(v, c)
        elif v is None:
            s = "null"
        elif isinstance(v, bool):
            s = "true" if v else "false"
        else:
            s = _number(v)
    elif isinstance(item, _Seq):
        ictx = _item_ctx(ctx, ctx.indent + "  ")  # one context for every item, as the reference shares it
        s = _block(ctx, ["- " + _stringify(x, ictx) for x in item.items], "[", "]")
    else:
        ictx = _item_ctx(ctx, ctx.indent or "")
        s = _block(ctx, [_pair(k, v, ictx) for k, v in item.pairs], "{", "}")
    if not props:
        return s
    return props + " " + s if isinstance(item, _Scalar) or s[0] in "{[" else props + "\n" + ctx.indent + s


def _item_ctx(ctx: _Ctx, indent: str) -> _Ctx:
    c = ctx.copy()
    c.indent = indent
    return c


def _block(ctx: _Ctx, lines: List[str], start: str, end: str) -> str:
    if not lines:
        return start + end
    out = lines[0]
    for line in lines[1:]:
        out += "\n" + ctx.indent + line if line else "\n"
    return out


def _pair(key: Any, value: Any, ctx: _Ctx) -> str:
    indent = ctx.indent
    ctx = ctx.copy()
    ctx.implicit_key = True
    ctx.indent = indent + _INDENT_STEP
    s = _stringify(key, ctx)
    explicit = len(s) > 1024
    s = "? %s\n%s:" % (s, indent) if explicit else s + ":"
    ctx.implicit_key = False
    if not explicit and isinstance(value, _Scalar):
        ctx.indent_at_start = len(s) + 1
    vs = _stringify(value, ctx)
    ws = " "
    if not explicit and _is_coll(value):
        nl0 = vs.find("\n")
        has_nl = nl0 != -1
        flow = (len(value.items) if isinstance(value, _Seq) else len(value.pairs)) == 0
        if has_nl or not flow:
            props_line = False
            if has_nl and vs[0] in "&!":
                sp0 = vs.find(" ")
                if vs[0] == "&" and sp0 != -1 and sp0 < nl0 and _at(vs, sp0 + 1) == "!":
                    sp0 = vs.find(" ", sp0 + 1)
                if sp0 == -1 or nl0 < sp0:
                    props_line = True
            if not props_line:
                ws = "\n" + ctx.indent
    elif vs == "" or vs[0] == "\n":
        ws = ""
    return s + ws + vs


def stringify(value: Any) -> str:
    """The YAML text of plain data (dict / list / str / bool / int / float / None); repeated containers become anchors and aliases."""
    b = _Builder()
    root = b.node(value)
    b.finish()
    ctx = _Ctx()
    body = _stringify(root, ctx)
    return _from_units(body) + "\n"


def defs_to_yaml(ns: str, defs: List[dict], rules: Optional[dict] = None) -> str:
    """`ns: <ns>` and `actions: [...]` as YAML; a def whose verb has an own entry in `rules` gets it re-attached as its `rules` member."""
    rules = rules if rules is not None else {}
    return stringify({"ns": ns, "actions": [({**d, "rules": rules[d["verb"]]} if d["verb"] in rules else d) for d in defs]})
