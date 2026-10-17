"""Deterministic, non-code predicate DSL evaluator (spec s5.1 "semantic action-predicates"). Port of the evaluator part of
packages/pca/src/predicates.ts (the TypeScript is authoritative; the DEFAULT code path, not the PCA_VERIFIED_CORE opt-in).

Predicates are PURE DATA. Every function here is total and never raises; anything malformed, unknown or missing FAILS
CLOSED (condition false, predicate not matched).

JS semantics reproduced (inputs are JSON values as `json.loads` / `strict_parse` yields them):
  - `typeof x === 'number'` excludes Python bool; int and float are one JS number (compared as binary64);
  - `typeof x === 'object'` is dict or list (arrays are objects; `Array.isArray` is list/tuple);
  - string `.length`, prefix tests, globs and regexes work over UTF-16 code units (see `safe_regex.to_units`);
  - lt/lte/gt/gte order strings by their UTF-8 bytes (Unicode code point order); a lone surrogate has no order;
  - `eq` / `in` is canonical-JSON equality: same JSON type and value (2 == 2.0, 0 == -0, 2 != "2", true != 1); any
    non-finite number makes the comparison false (the canonicalizer refuses it).
"""
import math
import re
from typing import Any, Optional, Tuple

from .safe_regex import (
    charge_regex,
    compile_safe_regex_cached,
    safe_regex_full_match,
    to_units,
    units_have_lone_surrogate,
    utf16_len,
    with_regex_budget,
)

__all__ = [
    "MAX_PATTERN_SUBJECT_LEN", "MAX_LIKE_PATTERN_LEN", "MAX_MATCHES_PATTERN_LEN", "MAX_MEMBER_CLOSURE_NODES",
    "MAX_RE_RESOURCE_LEN", "MAX_REGEX_COST_BITS", "UNBOUNDED_QUANTIFIER_BITS", "MAX_BOUNDED_REPEAT",
    "resolve_path", "is_group_condition", "is_leaf_condition", "evaluate_condition_tri", "evaluate_condition",
    "is_safe_regex_source", "predicate_matches", "evaluate_predicates",
]

MAX_PATTERN_SUBJECT_LEN = 512
"""Longest field value a `like`/`matches` leaf is tested against (UTF-16 units)."""
MAX_LIKE_PATTERN_LEN = 512
MAX_MATCHES_PATTERN_LEN = 200
MAX_MEMBER_CLOSURE_NODES = 10_000
MAX_RE_RESOURCE_LEN = 512
"""Longest resource string a `re:` pattern is evaluated against (UTF-16 units)."""
MAX_BOUNDED_REPEAT = 64
MAX_REGEX_COST_BITS = 22
UNBOUNDED_QUANTIFIER_BITS = 8

_ROOTS = frozenset(("action", "subject", "env"))
_FORBIDDEN = frozenset(("__proto__", "constructor", "prototype"))
_UNDEF = object()
_INDEX_RE = re.compile(r"0|[1-9][0-9]*")
_BRACE_RE = re.compile(r"\{([0-9]+)(?:(,)([0-9]*))?\}")


# ---- JS type helpers ------------------------------------------------------------------------------------------------

def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _is_arr(x: Any) -> bool:
    return isinstance(x, (list, tuple))


def _is_obj(x: Any) -> bool:
    """`x !== null && typeof x === 'object'` (arrays included)."""
    return isinstance(x, (dict, list, tuple))


def _jsnum(x: Any) -> float:
    """The binary64 value JS would hold for this JSON number (huge ints round; beyond range -> +/-Infinity)."""
    try:
        return float(x)
    except OverflowError:
        return math.inf if x > 0 else -math.inf


def _get(o: Any, k: str) -> Any:
    """Own-property read `o[k]` (undefined -> _UNDEF). Only plain objects (dicts) carry named properties."""
    if isinstance(o, dict) and k in o:
        return o[k]
    return _UNDEF


def _action(ctx: Any) -> Any:
    return _get(ctx, "action")


def _params_unavailable(ctx: Any) -> bool:
    p = _get(_action(ctx), "params")
    return p is _UNDEF or p is None or not _is_obj(p)


def _js_number_string(v: float) -> str:
    """ECMAScript Number::toString(v)."""
    if math.isnan(v):
        return "NaN"
    if math.isinf(v):
        return "Infinity" if v > 0 else "-Infinity"
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    r = repr(abs(v))
    mant, _, exp = r.partition("e")
    e = int(exp) if exp else 0
    ip, _, fp = mant.partition(".")
    if fp == "0":
        fp = ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + e - lead_zeros  # value = 0.digits x 10^n
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        ex = n - 1
        es = ("+" if ex >= 0 else "-") + str(abs(ex))
        s = (digits + "e" + es) if k == 1 else (digits[0] + "." + digits[1:] + "e" + es)
    return sign + s


def _js_string(v: Any, depth: int = 0) -> str:
    """ECMAScript String(v) for a JSON value (`_UNDEF` is undefined)."""
    if v is _UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    if _is_num(v):
        return _js_number_string(_jsnum(v))
    if _is_arr(v):
        if depth > 64:
            raise ValueError("String(): nesting too deep")
        return ",".join("" if x is None else _js_string(x, depth + 1) for x in v)
    return "[object Object]"


# ---- resolvePath ----------------------------------------------------------------------------------------------------

def _resolve(ctx: Any, path: Any) -> Tuple[bool, Any]:
    if not isinstance(path, str) or len(path) == 0:
        return (False, None)
    segs = path.split(".")
    if segs[0] not in _ROOTS:
        return (False, None)
    cur = _get(ctx, segs[0])
    if cur is _UNDEF:
        return (False, None)
    for s in segs[1:]:
        if s in _FORBIDDEN or cur is None or not _is_obj(cur):
            return (False, None)
        if _is_arr(cur):
            if not _INDEX_RE.fullmatch(s):
                return (False, None)
            idx = int(s)
            if idx >= len(cur):
                return (False, None)
            cur = cur[idx]
        else:
            if s not in cur:
                return (False, None)
            cur = cur[s]
    return (True, cur)


def resolve_path(ctx: Any, path: Any) -> dict:
    """Resolve a dotted path into the context. Own properties only; unknown root => not found. Never raises."""
    try:
        found, value = _resolve(ctx, path)
    except Exception:
        return {"found": False}
    return {"found": True, "value": value} if found else {"found": False}


# ---- deepEq / ordering ----------------------------------------------------------------------------------------------

class _NotCanonical(Exception):
    pass


def _jeq(a: Any, b: Any, depth: int) -> bool:
    """canonicalize(a) === canonicalize(b), structurally: raises _NotCanonical where the canonicalizer would throw."""
    if depth > 10_000:
        raise _NotCanonical()
    if _is_num(a) and not math.isfinite(_jsnum(a)):
        raise _NotCanonical()
    if _is_num(b) and not math.isfinite(_jsnum(b)):
        raise _NotCanonical()
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_num(a) or _is_num(b):
        return _is_num(a) and _is_num(b) and _jsnum(a) == _jsnum(b)
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and to_units(a) == to_units(b)
    if _is_arr(a) and _is_arr(b):
        if len(a) != len(b):
            return False
        return all(_jeq(x, y, depth + 1) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        for k in list(a) + list(b):
            if not isinstance(k, str):
                raise _NotCanonical()
        ka = {to_units(k): k for k in a}
        kb = {to_units(k): k for k in b}
        if set(ka) != set(kb) or len(ka) != len(a) or len(kb) != len(b):
            return False
        return all(_jeq(a[ka[u]], b[kb[u]], depth + 1) for u in ka)
    if _is_obj(a) and _is_obj(b):
        return False  # array vs object
    raise _NotCanonical()  # unsupported type


def _canonicalizable(v: Any) -> bool:
    """Would the lenient canonicalizer accept `v` (whole structure)? False on a non-finite number (incl. an int beyond
    binary64, i.e. `1e400` -> Infinity), a non-string key, an unsupported type or absurd nesting."""
    stack = [(v, 0)]
    while stack:
        x, d = stack.pop()
        if d > 10_000:
            return False
        if x is None or isinstance(x, (bool, str)):
            continue
        if _is_num(x):
            if not math.isfinite(_jsnum(x)):
                return False
            continue
        if _is_arr(x):
            stack.extend((y, d + 1) for y in x)
            continue
        if isinstance(x, dict):
            for k, y in x.items():
                if not isinstance(k, str):
                    return False
                stack.append((y, d + 1))
            continue
        return False
    return True


def _deep_eq(a: Any, b: Any) -> bool:
    """`canonicalize(a) === canonicalize(b)` (false when EITHER side cannot be canonicalized). Both operands are scanned in
    full BEFORE any comparison, so a non-finite number anywhere makes the result false regardless of where they differ."""
    try:
        if not _canonicalizable(a) or not _canonicalizable(b):
            return False
        return _jeq(a, b, 0)
    except Exception:
        return False


def _order_utf8(a: str, b: str) -> Optional[int]:
    ua, ub = to_units(a), to_units(b)
    if units_have_lone_surrogate(ua) or units_have_lone_surrogate(ub):
        return None
    if ua == ub:
        return 0
    x = ua.encode("utf-16-le", "surrogatepass").decode("utf-16-le").encode("utf-8")
    y = ub.encode("utf-16-le", "surrogatepass").decode("utf-16-le").encode("utf-8")
    return -1 if x < y else (1 if x > y else 0)


def _ordered(a: Any, b: Any) -> Optional[int]:
    if _is_num(a) and _is_num(b):
        x, y = _jsnum(a), _jsnum(b)
        if math.isfinite(x) and math.isfinite(y):
            return -1 if x < y else (1 if x > y else 0)
    if isinstance(a, str) and isinstance(b, str):
        return _order_utf8(a, b)
    return None


# ---- glob / type tags / member closure -----------------------------------------------------------------------------

def _parse_glob(glob: str):
    """Tokens over UTF-16 units: ('lit', ch) | ('one',) | ('star',). None on a dangling trailing backslash."""
    out = []
    i = 0
    n = len(glob)
    while i < n:
        ch = glob[i]
        if ch == "\\":
            if i + 1 >= n:
                return None
            out.append(("lit", glob[i + 1]))
            i += 1
        elif ch == "*":
            if not out or out[-1][0] != "star":
                out.append(("star",))
        elif ch == "?":
            out.append(("one",))
        else:
            out.append(("lit", ch))
        i += 1
    return out


def _glob_match(glob: str, s: str) -> Optional[bool]:
    toks = _parse_glob(to_units(glob))
    if toks is None:
        return None
    s = to_units(s)
    ti = si = 0
    star_ti, star_si = -1, 0
    nt = len(toks)
    while si < len(s):
        t = toks[ti] if ti < nt else None
        if t is not None and t[0] == "star":
            ti += 1
            star_ti = ti
            star_si = si
        elif t is not None and (t[0] == "one" or s[si] == t[1]):
            ti += 1
            si += 1
        elif star_ti >= 0:
            ti = star_ti
            star_si += 1
            si = star_si
        else:
            return False
    while ti < nt and toks[ti][0] == "star":
        ti += 1
    return ti == nt


def _starts_with(s: str, prefix: str) -> bool:
    return to_units(s).startswith(to_units(prefix))


def _type_tag_match(v: Any, t: str) -> Optional[bool]:
    if isinstance(v, str):
        return to_units(v) == to_units(t) or _starts_with(v, t + "::")
    if isinstance(v, dict):
        decidable = False
        matched = False
        if "type" in v:
            ty = v["type"]
            if isinstance(ty, str):
                decidable = True
                if to_units(ty) == to_units(t) or _starts_with(ty, t + "::"):
                    matched = True
        if "tags" in v:
            tags = v["tags"]
            if _is_arr(tags):
                decidable = True
                if any(isinstance(x, str) and to_units(x) == to_units(t) for x in tags):
                    matched = True
        return matched if decidable else None
    return None


def _neighbours_of(adj: dict, node: str):
    if node in _FORBIDDEN or node not in adj:
        return []
    raw = adj[node]
    if isinstance(raw, str):
        return [raw]
    if _is_arr(raw):
        return [x for x in raw if isinstance(x, str)]
    return []


def _member_closure(start: str, adj: dict) -> set:
    seen = {start}
    queue = [start]
    qi = 0
    visited = 0
    while qi < len(queue) and visited < MAX_MEMBER_CLOSURE_NODES:
        visited += 1
        node = queue[qi]
        qi += 1
        for n in _neighbours_of(adj, node):
            if n not in seen:
                seen.add(n)
                queue.append(n)
    return seen


# ---- conditions -----------------------------------------------------------------------------------------------------

def is_group_condition(c: Any) -> bool:
    return isinstance(c, dict) and ("all_of" in c or "any_of" in c or "not" in c)


def is_leaf_condition(c: Any) -> bool:
    return isinstance(c, dict) and not is_group_condition(c) and isinstance(c.get("field"), str)


def _tri_leaf(c: dict, ctx: Any) -> str:
    field = c.get("field", _UNDEF)
    if not isinstance(field, str) or len(field) == 0:
        return "unknown"
    op = c.get("op", _UNDEF)
    if not isinstance(op, str):
        return "unknown"
    # "params unavailable" is NOT "field absent": a params-rooted condition fails closed.
    if field == "action.params" or field.startswith("action.params."):
        if _params_unavailable(ctx):
            return "unknown"
    ref = c.get("ref", _UNDEF)
    if isinstance(ref, str) and (ref == "action.params" or ref.startswith("action.params.")):
        if _params_unavailable(ctx):
            return "unknown"
    f_found, v = _resolve(ctx, field)
    if op == "exists":
        must_be_absent = "value" in c and c["value"] is False
        return "true" if ((not f_found) if must_be_absent else f_found) else "false"
    if not f_found:
        return "unknown"

    if op == "member_of":
        if not isinstance(v, str):
            return "unknown"
        coll_path = c.get("collection", _UNDEF)
        if not isinstance(coll_path, str) or len(coll_path) == 0:
            return "unknown"
        c_found, coll = _resolve(ctx, coll_path)
        if not c_found or not isinstance(coll, dict):
            return "unknown"
        if ref is not _UNDEF:
            r_found, target = _resolve(ctx, ref)
            if not r_found:
                return "unknown"
        else:
            if "value" not in c:
                return "unknown"
            target = c["value"]
        if _is_arr(target):
            targets = [x for x in target if isinstance(x, str)]
        elif isinstance(target, str):
            targets = [target]
        else:
            targets = []
        if not targets:
            return "unknown"
        reach = _member_closure(v, coll)
        return "true" if any(t in reach for t in targets) else "false"

    if ref is not _UNDEF:
        r_found, operand = _resolve(ctx, ref)
        if not r_found:
            return "unknown"
    else:
        if "value" not in c:
            return "unknown"
        operand = c["value"]

    if op == "eq":
        return "true" if _deep_eq(v, operand) else "false"
    if op == "ne":
        return "false" if _deep_eq(v, operand) else "true"
    if op == "in":
        if not _is_arr(operand):
            return "unknown"
        return "true" if any(_deep_eq(v, x) for x in operand) else "false"
    if op == "nin":
        if not _is_arr(operand):
            return "unknown"
        return "false" if any(_deep_eq(v, x) for x in operand) else "true"
    if op in ("lt", "lte", "gt", "gte"):
        o = _ordered(v, operand)
        if o is None:
            return "unknown"
        ok = o < 0 if op == "lt" else o <= 0 if op == "lte" else o > 0 if op == "gt" else o >= 0
        return "true" if ok else "false"
    if op == "prefix":
        if not isinstance(v, str) or not isinstance(operand, str):
            return "unknown"
        return "true" if _starts_with(v, operand) else "false"
    if op == "like":
        if not isinstance(v, str) or not isinstance(operand, str):
            return "unknown"
        if utf16_len(operand) > MAX_LIKE_PATTERN_LEN or utf16_len(v) > MAX_PATTERN_SUBJECT_LEN:
            return "unknown"
        m = _glob_match(operand, v)
        if m is None:
            return "unknown"
        return "true" if m else "false"
    if op == "matches":
        if not isinstance(v, str) or not isinstance(operand, str):
            return "unknown"
        vlen = utf16_len(v)
        if utf16_len(operand) > MAX_MATCHES_PATTERN_LEN or vlen > MAX_PATTERN_SUBJECT_LEN:
            return "unknown"
        if not is_safe_regex_source(operand):
            return "unknown"
        if not charge_regex(operand, vlen):
            return "unknown"  # per-document regex work budget (fail closed)
        r = safe_regex_full_match(operand, v)
        return "unknown" if r is None else ("true" if r else "false")
    if op == "is_a":
        if not isinstance(operand, str) or len(operand) == 0:
            return "unknown"
        t = _type_tag_match(v, operand)
        return "unknown" if t is None else ("true" if t else "false")
    return "unknown"


def evaluate_condition_tri(c: Any, ctx: Any) -> str:
    """Tri-valued evaluation ('true' | 'false' | 'unknown') of any condition (leaf or grouping). Never raises."""
    try:
        return with_regex_budget(lambda: _evaluate_condition_tri_inner(c, ctx))
    except Exception:
        return "unknown"


def _evaluate_condition_tri_inner(c: Any, ctx: Any) -> str:
    try:
        if not _is_obj(c):
            return "unknown"
        if is_group_condition(c):
            if "all_of" in c:
                xs = c["all_of"]
                if not _is_arr(xs) or len(xs) == 0:
                    return "unknown"
                saw_unknown = False
                for x in xs:
                    t = evaluate_condition_tri(x, ctx)
                    if t == "false":
                        return "false"
                    if t == "unknown":
                        saw_unknown = True
                return "unknown" if saw_unknown else "true"
            if "any_of" in c:
                xs = c["any_of"]
                if not _is_arr(xs) or len(xs) == 0:
                    return "unknown"
                saw_unknown = False
                for x in xs:
                    t = evaluate_condition_tri(x, ctx)
                    if t == "true":
                        return "true"
                    if t == "unknown":
                        saw_unknown = True
                return "unknown" if saw_unknown else "false"
            inner = evaluate_condition_tri(c["not"], ctx)
            return "false" if inner == "true" else ("true" if inner == "false" else "unknown")
        if not isinstance(c, dict):
            return "unknown"  # an array: `c.field` is undefined
        return _tri_leaf(c, ctx)
    except Exception:
        return "unknown"


def evaluate_condition(c: Any, ctx: Any) -> bool:
    """Evaluate one condition: True iff it is cleanly decided true (groupings fail closed)."""
    return evaluate_condition_tri(c, ctx) == "true"


# ---- the linear-time-safe regex subset guard -------------------------------------------------------------------------

def is_safe_regex_source(src: Any) -> bool:
    """Validate that a `re:` / `matches` pattern is in the linear-time-safe subset (nesting, alternation and cost-bit rules)
    AND compiles in the linear-time engine. Never raises."""
    try:
        if not isinstance(src, str):
            return False
        return _is_safe_regex_source(to_units(src), src)
    except Exception:
        return False


def _is_safe_regex_source(s: str, orig: str) -> bool:
    stack = [[False, False]]  # frames: [has_quant, has_alt]
    prev: Any = "none"  # 'none' | 'atom' | frame
    bits = 0
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\":
            if i + 1 >= n:
                return False
            nx = s[i + 1]
            if ("1" <= nx <= "9") or nx == "k":
                return False  # backreference
            i += 2
            prev = "atom"
            continue
        if ch == "[":
            # JavaScript class semantics: the class ends at the FIRST unescaped `]` after `[` and an optional `^`.
            j = i + 1
            if j < n and s[j] == "^":
                j += 1
            while j < n and s[j] != "]":
                if s[j] == "\\":
                    j += 1
                j += 1
            if j >= n:
                return False
            i = j + 1
            prev = "atom"
            continue
        if ch == "(":
            if i + 1 < n and s[i + 1] == "?":
                if not (i + 2 < n and s[i + 2] == ":"):
                    return False  # lookahead/lookbehind/named group
                i += 3
            else:
                i += 1
            stack.append([False, False])
            prev = "none"
            continue
        if ch == ")":
            if len(stack) < 2:
                return False
            f = stack.pop()
            parent = stack[-1]
            parent[0] = parent[0] or f[0]
            parent[1] = parent[1] or f[1]
            prev = f
            i += 1
            continue
        if ch == "|":
            bits += 1
            if bits > MAX_REGEX_COST_BITS:
                return False
            stack[-1][1] = True
            prev = "none"
            i += 1
            continue
        q = None  # (len, unbounded, max, options)
        if ch == "*" or ch == "+":
            q = (1, True, math.inf, math.inf)
        elif ch == "?":
            q = (1, False, 1, 2)
        elif ch == "{":
            m = _BRACE_RE.match(s, i)
            if not m:
                return False
            lo = int(m.group(1))
            has_comma = m.group(2) is not None
            hi = lo if not has_comma else (math.inf if m.group(3) == "" else int(m.group(3)))
            if _jsnum(hi) < _jsnum(lo):
                return False
            q = (len(m.group(0)), hi == math.inf, hi, math.inf if hi == math.inf else hi - lo + 1)
        if q is not None:
            if prev == "none":
                return False  # nothing to repeat
            if isinstance(prev, list) and (prev[0] or prev[1]):
                return False  # nested quantifier
            qlen, unbounded, qmax, options = q
            if not unbounded and qmax != math.inf and qmax > MAX_BOUNDED_REPEAT:
                return False
            if unbounded:
                bits += UNBOUNDED_QUANTIFIER_BITS
            elif options > 1:
                bits += (int(options) - 1).bit_length()  # == ceil(log2(options)) for an integer options >= 2
            if bits > MAX_REGEX_COST_BITS:
                return False
            stack[-1][0] = True
            i += qlen
            if i < n and s[i] == "?":
                i += 1  # lazy modifier
            prev = "none"
            continue
        i += 1
        prev = "atom"
    # The source must ALSO compile in the linear-time engine that actually runs it.
    return len(stack) == 1 and compile_safe_regex_cached(orig) is not None


# ---- predicates -----------------------------------------------------------------------------------------------------

def _verb_matches(p: Any, verb: str) -> bool:
    if isinstance(p, str):
        return p == "*" or to_units(p) == to_units(verb)
    if _is_arr(p):
        return any(isinstance(x, str) and (x == "*" or to_units(x) == to_units(verb)) for x in p)
    return False


def _resource_matches(pattern: Any, resource: str) -> bool:
    if pattern is _UNDEF:
        return True
    if not isinstance(pattern, str):
        return False
    if pattern == "*":
        return True
    if pattern.startswith("re:"):
        src = pattern[3:]
        if utf16_len(src) > 200:
            return False
        rlen = utf16_len(resource)
        if rlen > MAX_RE_RESOURCE_LEN:
            return False
        if not is_safe_regex_source(src):
            return False
        if not charge_regex(src, rlen):
            return False  # per-document regex work budget (fail closed)
        return safe_regex_full_match(src, resource) is True
    if pattern.endswith("*"):
        return _starts_with(resource, pattern[:-1])
    return to_units(pattern) == to_units(resource)


def predicate_matches(p: Any, ctx: Any) -> bool:
    """Does a single predicate permit the action (verb AND resource AND every `where`)? Never raises."""
    try:
        return with_regex_budget(lambda: _predicate_matches_inner(p, ctx))
    except Exception:
        return False


def _predicate_matches_inner(p: Any, ctx: Any) -> bool:
    try:
        if not _is_obj(p):
            return False
        a = _action(ctx)
        if not _is_obj(a):
            return False
        verb = _get(a, "verb")
        resource = _get(a, "resource")
        if not isinstance(verb, str) or not isinstance(resource, str):
            return False
        if not _verb_matches(_get(p, "verb"), verb):
            return False
        if not _resource_matches(_get(p, "resource"), resource):
            return False
        where = _get(p, "where")
        if where is not _UNDEF:
            if not _is_arr(where):
                return False
            for c in where:
                if not evaluate_condition(c, ctx):
                    return False
        return True
    except Exception:
        return False


def evaluate_predicates(predicates: Any, ctx: Any) -> dict:
    """An action is allowed iff it matches AT LEAST ONE predicate. Default-deny: an empty list allows nothing.
    Returns {"allowed": True, "matched": p} or {"allowed": False, "reason": str}. Never raises."""
    try:
        return with_regex_budget(lambda: _evaluate_predicates_inner(predicates, ctx))
    except Exception:
        return {"allowed": False, "reason": "predicate evaluation error (fail closed)"}


def _evaluate_predicates_inner(predicates: Any, ctx: Any) -> dict:
    try:
        if not _is_arr(predicates) or len(predicates) == 0:
            return {"allowed": False, "reason": "envelope grants no predicates"}
        for p in predicates:
            if predicate_matches(p, ctx):
                return {"allowed": True, "matched": p}
        a = _action(ctx)
        verb = _get(a, "verb") if a is not _UNDEF and a is not None else _UNDEF
        resource = _get(a, "resource") if a is not _UNDEF and a is not None else _UNDEF
        return {"allowed": False, "reason": "no predicate permits %s on %s" % (_js_string(verb), _js_string(resource))}
    except Exception:
        return {"allowed": False, "reason": "predicate evaluation error (fail closed)"}
