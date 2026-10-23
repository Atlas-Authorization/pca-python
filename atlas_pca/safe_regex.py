"""A linear-time, budgeted regular-expression matcher for untrusted `re:` / `matches` patterns, plus the per-document regex
work budget. Port of packages/pca/src/safe-regex.ts and packages/pca/src/regex-budget.ts (the TypeScript is authoritative).

The pattern is parsed ONCE, by this parser, into a Thompson NFA and run by a Pike-style simulation whose cost is
O(|subject| x |NFA|) by construction. Python's `re` module is never run on an untrusted pattern.

SUBSET (anything else is REFUSED at compile time, fail closed): literals; `.` (not a line terminator); classes `[...]` /
`[^...]` incl. `[]` (matches nothing) and `[^]` (any char), ranges and `\\d \\D \\w \\W \\s \\S` inside them; escapes
`\\d \\D \\w \\W \\s \\S \\t \\n \\v \\f \\r \\0 \\xHH \\uHHHH \\cX` and escaped punctuation; groups `( )` and `(?: )`; alternation
`|`; quantifiers `* + ? {n} {n,} {n,m}` with an optional lazy `?`; anchors `^` `$`.

JS SEMANTICS: patterns and subjects are processed as sequences of UTF-16 CODE UNITS, exactly like a flagless JS RegExp (an
astral character is two units; `.` matches one unit). Python strings are code-point sequences, so every input is first
expanded with `to_units` (a str whose every char is one UTF-16 code unit, surrogates as separate chars).
"""
import contextvars
import re
import threading
from collections import OrderedDict
from typing import Any, Callable, List, Optional, Tuple

# ---- UTF-16 helpers (shared with predicates.py) -----------------------------------------------------------------------


def to_units(s: str) -> str:
    """The UTF-16 code-unit view of `s`: one char per code unit (astral code points split into their surrogate pair).
    Two strings are equal in JS iff their unit views are equal; `.length` is `len(to_units(s))`."""
    if not any(ord(c) > 0xFFFF for c in s):
        return s
    out = []
    for c in s:
        o = ord(c)
        if o > 0xFFFF:
            o -= 0x10000
            out.append(chr(0xD800 + (o >> 10)))
            out.append(chr(0xDC00 + (o & 0x3FF)))
        else:
            out.append(c)
    return "".join(out)


def utf16_len(s: str) -> int:
    """JS `s.length` (UTF-16 code units)."""
    return len(s) + sum(1 for c in s if ord(c) > 0xFFFF)


def units_have_lone_surrogate(u: str) -> bool:
    """`hasLoneSurrogate` over a unit view: a high surrogate not followed by a low one, or a low not preceded by a high."""
    n = len(u)
    i = 0
    while i < n:
        o = ord(u[i])
        if 0xD800 <= o <= 0xDBFF:
            if i + 1 < n and 0xDC00 <= ord(u[i + 1]) <= 0xDFFF:
                i += 2
                continue
            return True
        if 0xDC00 <= o <= 0xDFFF:
            return True
        i += 1
    return False


# ---- limits ----------------------------------------------------------------------------------------------------------

MAX_NFA_INSTRUCTIONS = 4096
"""Largest NFA (instruction count) a pattern may compile to."""
MAX_REPEAT = 64
"""Largest `{n,m}` bound."""
MAX_MATCH_STEPS = 2_000_000
"""Hard cap on (NFA size x (subject length + 1)): the matcher refuses rather than run longer."""

INF = float("inf")

# Op codes
OP_SET, OP_SPLIT, OP_JMP, OP_BOL, OP_EOL, OP_MATCH = 0, 1, 2, 3, 4, 5


class CharSet:
    """A set of UTF-16 code units: sorted, merged ranges, optionally negated (negation applied at test time)."""

    __slots__ = ("ranges", "negated")

    def __init__(self, ranges, negated: bool):
        self.ranges = tuple((int(a), int(b)) for a, b in ranges)
        self.negated = negated

    def has(self, c: int) -> bool:
        lo, hi = 0, len(self.ranges) - 1
        inside = False
        while lo <= hi:
            mid = (lo + hi) >> 1
            r = self.ranges[mid]
            if c < r[0]:
                hi = mid - 1
            elif c > r[1]:
                lo = mid + 1
            else:
                inside = True
                break
        return inside != self.negated


DIGIT = ((0x30, 0x39),)
WORD = ((0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A))
SPACE = (
    (0x09, 0x0D), (0x20, 0x20), (0xA0, 0xA0), (0x1680, 0x1680), (0x2000, 0x200A), (0x2028, 0x2029),
    (0x202F, 0x202F), (0x205F, 0x205F), (0x3000, 0x3000), (0xFEFF, 0xFEFF),
)
LINE_TERMINATORS = ((0x0A, 0x0A), (0x0D, 0x0D), (0x2028, 0x2029))


def _normalize(ranges) -> List[List[int]]:
    s = sorted(([a, b] for a, b in ranges), key=lambda r: r[0])
    out: List[List[int]] = []
    for r in s:
        if out and r[0] <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], r[1])
        else:
            out.append([r[0], r[1]])
    return out


def _complement(r) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    nxt = 0
    for a, b in _normalize(r):
        if a > nxt:
            out.append((nxt, a - 1))
        nxt = b + 1
    if nxt <= 0xFFFF:
        out.append((nxt, 0xFFFF))
    return out


# ---- parser (AST nodes are tuples: ('set', CharSet) | ('bol',) | ('eol',) | ('cat', [..]) | ('alt', [..]) |
#      ('rep', node, min, max)) -------------------------------------------------------------------------------------------


class _Refuse(Exception):
    pass


def _refuse(m: str):
    raise _Refuse(m)


_QUANT_RE = re.compile(r"\{([0-9]{1,4})(?:(,)([0-9]{0,4}))?\}")
_HEX2 = re.compile(r"[0-9a-fA-F]{2}")
_HEX4 = re.compile(r"[0-9a-fA-F]{4}")
_ALNUM = re.compile(r"[A-Za-z0-9]")
_ALPHA = re.compile(r"[A-Za-z]")


class _Parser:
    def __init__(self, s: str):
        self.s = s  # unit view
        self.i = 0

    def _at(self, i: int) -> Optional[str]:
        return self.s[i] if 0 <= i < len(self.s) else None

    def parse(self):
        n = self.alt()
        if self.i < len(self.s):
            _refuse("unbalanced )")
        return n

    def alt(self):
        items = [self.cat()]
        while self._at(self.i) == "|":
            self.i += 1
            items.append(self.cat())
        return items[0] if len(items) == 1 else ("alt", items)

    def cat(self):
        items = []
        while self.i < len(self.s) and self.s[self.i] != "|" and self.s[self.i] != ")":
            items.append(self.quantified())
        return ("cat", items)

    def quantified(self):
        atom = self.atom()
        c = self._at(self.i)
        if c == "*":
            mn, mx = 0, INF
            self.i += 1
        elif c == "+":
            mn, mx = 1, INF
            self.i += 1
        elif c == "?":
            mn, mx = 0, 1
            self.i += 1
        elif c == "{":
            m = _QUANT_RE.match(self.s[self.i:self.i + 16])
            if not m:
                _refuse("{ is not a well-formed quantifier")
            mn = int(m.group(1))
            mx = mn if m.group(2) is None else (INF if m.group(3) == "" else int(m.group(3)))
            if mx < mn:
                _refuse("quantifier range out of order")
            self.i += len(m.group(0))
        else:
            return atom
        if atom[0] == "bol" or atom[0] == "eol":
            _refuse("nothing to repeat (assertion)")
        if (mx != INF and mx > MAX_REPEAT) or mn > MAX_REPEAT:
            _refuse("repeat bound too large")
        if self._at(self.i) == "?":
            self.i += 1  # lazy: no effect on a full-match boolean
        return ("rep", atom, mn, mx)

    def atom(self):
        c = self.s[self.i]
        if c == "(":
            self.i += 1
            if self._at(self.i) == "?":
                if self._at(self.i + 1) != ":":
                    _refuse("lookaround / named groups are not supported")
                self.i += 2
            n = self.alt()
            if self._at(self.i) != ")":
                _refuse("unterminated group")
            self.i += 1
            return n
        if c == "[":
            return self.cls()
        if c == ".":
            self.i += 1
            return ("set", CharSet(LINE_TERMINATORS, True))
        if c == "^":
            self.i += 1
            return ("bol",)
        if c == "$":
            self.i += 1
            return ("eol",)
        if c == "\\":
            return ("set", self.escape_inner(False)[0])
        if c in ("*", "+", "?"):
            _refuse("nothing to repeat")
        if c == "{":
            _refuse("{ is not a well-formed quantifier")
        self.i += 1
        o = ord(c)
        return ("set", CharSet(((o, o),), False))

    def escape_inner(self, in_class: bool):
        """After `\\`: returns (set, is_class_escape, ch or None)."""
        self.i += 1  # backslash
        c = self._at(self.i)
        if c is None:
            _refuse("trailing backslash")
        self.i += 1

        def single(code: int):
            return (CharSet(((code, code),), False), False, code)

        if c == "d":
            return (CharSet(DIGIT, False), True, None)
        if c == "D":
            return (CharSet(DIGIT, True), True, None)
        if c == "w":
            return (CharSet(WORD, False), True, None)
        if c == "W":
            return (CharSet(WORD, True), True, None)
        if c == "s":
            return (CharSet(SPACE, False), True, None)
        if c == "S":
            return (CharSet(SPACE, True), True, None)
        if c == "t":
            return single(9)
        if c == "n":
            return single(10)
        if c == "v":
            return single(11)
        if c == "f":
            return single(12)
        if c == "r":
            return single(13)
        if c == "0":
            nx = self._at(self.i)
            if nx is not None and "0" <= nx <= "9":
                _refuse("octal escape")
            return single(0)
        if c == "x":
            h = self.s[self.i:self.i + 2]
            if not _HEX2.fullmatch(h):
                _refuse("bad \\x escape")
            self.i += 2
            return single(int(h, 16))
        if c == "u":
            h = self.s[self.i:self.i + 4]
            if not _HEX4.fullmatch(h):
                _refuse("bad \\u escape")
            self.i += 4
            return single(int(h, 16))
        if c == "c":
            l = self._at(self.i)
            if l is None or not _ALPHA.fullmatch(l):
                _refuse("bad \\c escape")
            self.i += 1
            return single(ord(l) % 32)
        if c == "b":
            if in_class:
                return single(8)  # [\b] is backspace
            _refuse("word-boundary assertions are not supported")
        if _ALNUM.fullmatch(c) or c == "_":
            _refuse("escape \\%s is not supported" % c)
        return single(ord(c))

    def cls(self):
        self.i += 1  # [
        negated = False
        if self._at(self.i) == "^":
            negated = True
            self.i += 1
        ranges: List[Tuple[int, int]] = []

        def read_atom():
            c = self.s[self.i]
            if c == "\\":
                st, is_cls, ch = self.escape_inner(True)
                rs = _complement(st.ranges) if st.negated else list(st.ranges)
                return (rs, ch, is_cls)
            self.i += 1
            o = ord(c)
            return ([(o, o)], o, False)

        while True:
            c = self._at(self.i)
            if c is None:
                _refuse("unterminated class")
            if c == "]":
                self.i += 1
                break
            a = read_atom()
            nx = self._at(self.i + 1)
            if self._at(self.i) == "-" and nx is not None and nx != "]":
                self.i += 1
                b = read_atom()
                if a[2] or b[2]:
                    # Annex B: a class escape as a range endpoint makes the '-' a literal
                    ranges.extend(a[0])
                    ranges.append((0x2D, 0x2D))
                    ranges.extend(b[0])
                else:
                    if a[1] > b[1]:
                        _refuse("class range out of order")
                    ranges.append((a[1], b[1]))
            else:
                ranges.extend(a[0])
        return ("set", CharSet(_normalize(ranges), negated))


# ---- compile ---------------------------------------------------------------------------------------------------------


class CompiledRegex:
    """A compiled NFA program: a list of [op, x, y, set] instructions."""

    __slots__ = ("program",)

    def __init__(self, program):
        self.program = program


def _emit(node, prog: list) -> None:
    if len(prog) > MAX_NFA_INSTRUCTIONS:
        _refuse("pattern too large")
    k = node[0]
    if k == "set":
        prog.append([OP_SET, 0, 0, node[1]])
    elif k == "bol":
        prog.append([OP_BOL, 0, 0, None])
    elif k == "eol":
        prog.append([OP_EOL, 0, 0, None])
    elif k == "cat":
        for it in node[1]:
            _emit(it, prog)
    elif k == "alt":
        items = node[1]
        jmps = []
        for i, it in enumerate(items):
            if i < len(items) - 1:
                split = len(prog)
                prog.append([OP_SPLIT, split + 1, -1, None])
                _emit(it, prog)
                jmps.append(len(prog))
                prog.append([OP_JMP, -1, 0, None])
                prog[split][2] = len(prog)
            else:
                _emit(it, prog)
        for j in jmps:
            prog[j][1] = len(prog)
    else:  # rep
        _, body, mn, mx = node
        for _i in range(mn):
            _emit(body, prog)
        if mx == INF:
            split = len(prog)
            prog.append([OP_SPLIT, split + 1, -1, None])
            _emit(body, prog)
            prog.append([OP_JMP, split, 0, None])
            prog[split][2] = len(prog)
        else:
            splits = []
            for _i in range(mn, int(mx)):
                splits.append(len(prog))
                prog.append([OP_SPLIT, len(prog) + 1, -1, None])
                _emit(body, prog)
            for sp in splits:
                prog[sp][2] = len(prog)
        if len(prog) > MAX_NFA_INSTRUCTIONS:
            _refuse("pattern too large")


def compile_safe_regex(src: Any) -> Optional[CompiledRegex]:
    """Compile `src` into an NFA, or None when it is outside the supported subset or too large. Never raises."""
    try:
        if not isinstance(src, str):
            return None
        ast = _Parser(to_units(src)).parse()
        prog: list = []
        _emit(ast, prog)
        prog.append([OP_MATCH, 0, 0, None])
        if len(prog) > MAX_NFA_INSTRUCTIONS:
            return None
        return CompiledRegex(prog)
    except Exception:  # _Refuse, RecursionError (absurd nesting), anything else: refuse
        return None


def run_safe_regex(rx: CompiledRegex, subject: str) -> Optional[bool]:
    """Full-match `subject` against a compiled program: True / False, or None when the work budget would be exceeded.
    O(|subject| x |program|), no backtracking."""
    prog = rx.program
    u = to_units(subject)
    n = len(u)
    plen = len(prog)
    if plen * (n + 1) > MAX_MATCH_STEPS:
        return None
    mark = [-1] * plen
    state = {"gen": 0, "matched": False}

    def add(lst: list, pc0: int, pos: int) -> None:
        gen = state["gen"]
        stack = [pc0]
        while stack:
            pc = stack.pop()
            if mark[pc] == gen:
                continue
            mark[pc] = gen
            ins = prog[pc]
            op = ins[0]
            if op == OP_JMP:
                stack.append(ins[1])
            elif op == OP_SPLIT:
                stack.append(ins[2])
                stack.append(ins[1])
            elif op == OP_BOL:
                if pos == 0:
                    stack.append(pc + 1)
            elif op == OP_EOL:
                if pos == n:
                    stack.append(pc + 1)
            elif op == OP_MATCH:
                if pos == n:
                    state["matched"] = True
            else:  # OP_SET
                lst.append(pc)

    state["gen"] += 1
    clist: list = []
    add(clist, 0, 0)
    for pos in range(n):
        c = ord(u[pos])
        state["gen"] += 1
        nlist: list = []
        for pc in clist:
            if prog[pc][3].has(c):
                add(nlist, pc + 1, pos + 1)
        clist = nlist
        if not clist and not state["matched"]:
            return False
    return state["matched"]


# ---- the bounded compiled-program cache (regex-cache.ts: an LRU; the verdict never depends on it) ----------------------

REGEX_CACHE_MAX_ENTRIES = 512
_cache: "OrderedDict[str, Optional[CompiledRegex]]" = OrderedDict()
_cache_lock = threading.Lock()


def compile_safe_regex_cached(src: Any) -> Optional[CompiledRegex]:
    """`compile_safe_regex` through a bounded LRU (evicts one entry at a time). Caches refusals too."""
    if not isinstance(src, str):
        return None
    with _cache_lock:
        if src in _cache:
            _cache.move_to_end(src)
            return _cache[src]
    rx = compile_safe_regex(src)
    with _cache_lock:
        _cache[src] = rx
        _cache.move_to_end(src)
        while len(_cache) > REGEX_CACHE_MAX_ENTRIES:
            _cache.popitem(last=False)
    return rx


def safe_regex_full_match(src: Any, subject: Any) -> Optional[bool]:
    """`new RegExp('^(?:' + src + ')$').test(subject)` over the supported subset, in linear time. None when `src` is
    outside the subset (or too large) or the work budget is exceeded; the caller fails closed. Never raises."""
    try:
        if not isinstance(subject, str):
            return None
        rx = compile_safe_regex_cached(src)
        if rx is None:
            return None
        return run_safe_regex(rx, subject)
    except Exception:
        return None


# ---- per-document regex work budget (regex-budget.ts, R4-05 / R5-API-01) ---------------------------------------------

MAX_REGEX_EVALUATIONS_PER_DOCUMENT = 64
MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT = 8192
MAX_REGEX_STEPS_PER_DOCUMENT = 5_000_000
REGEX_REQUEST_SCALE = 4


def _prog_len(src: str) -> Optional[int]:
    c = compile_safe_regex_cached(src)
    return None if c is None else len(c.program)


class RegexBudget:
    """A regex work budget. A DOCUMENT budget (scale 1) is opened by every library entry point; an optional REQUEST budget
    (`RegexBudget.request()`, scale REGEX_REQUEST_SCALE) is charged as well by every document budget opened inside it."""

    def __init__(self, scale: int = 1, parent: "Optional[RegexBudget]" = None, is_document: bool = True,
                 source: Optional[str] = None):
        self.evaluations = 0
        self.chars = 0
        self.steps = 0
        self.refusals = 0
        self._scale = scale
        self._parent = parent
        self.is_document = is_document
        self.source = source

    @property
    def parent_budget(self) -> "Optional[RegexBudget]":
        return self._parent

    @staticmethod
    def request(source: Optional[str] = None) -> "RegexBudget":
        return RegexBudget(REGEX_REQUEST_SCALE, None, False, source)

    def charge(self, src: str, subject_len: int) -> bool:
        """Charge one evaluation of `src` against a subject of `subject_len` UTF-16 units; False = refused."""
        ln = _prog_len(src)
        if ln is None:
            self.refusals += 1
            return False
        ev = self.evaluations + 1
        chars = self.chars + utf16_len(src)
        steps = self.steps + ln * (subject_len + 1)
        k = self._scale
        if (ev > MAX_REGEX_EVALUATIONS_PER_DOCUMENT * k
                or chars > MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT * k
                or steps > MAX_REGEX_STEPS_PER_DOCUMENT * k
                or (self._parent is not None and not self._parent.charge(src, subject_len))):
            # Poison the budget so a later, cheaper pattern cannot sneak in after an over-budget one.
            self.evaluations = MAX_REGEX_EVALUATIONS_PER_DOCUMENT * k + 1
            self.refusals += 1
            return False
        self.evaluations = ev
        self.chars = chars
        self.steps = steps
        return True

    def run(self, fn: Callable[[], Any]) -> Any:
        """Make this the open scope for the synchronous `fn` (restores the previous scope afterwards)."""
        tok = _current.set(self)
        try:
            return fn()
        finally:
            _current.reset(tok)


_current: "contextvars.ContextVar[Optional[RegexBudget]]" = contextvars.ContextVar("atlas_pca_regex_budget", default=None)
_provider: Optional[Callable[[], Optional[RegexBudget]]] = None


def set_regex_budget_provider(fn: Optional[Callable[[], Optional[RegexBudget]]]) -> None:
    """Install an AMBIENT request-budget provider; every document budget opened with no enclosing scope chains to it."""
    global _provider
    _provider = fn


def _ambient() -> Optional[RegexBudget]:
    cur = _current.get()
    if cur is not None:
        return cur
    try:
        return None if _provider is None else _provider()
    except Exception:
        return None


def with_regex_budget(fn: Callable[[], Any], budget: Optional[RegexBudget] = None) -> Any:
    """Run `fn` as ONE document: inside `budget` if given; else join an open document scope; else open a fresh document
    budget chained to the enclosing request budget, if any."""
    if budget is not None:
        return budget.run(fn)
    cur = _current.get()
    if cur is not None and cur.is_document:
        return fn()
    return RegexBudget(1, _ambient(), True).run(fn)


def regex_refusals() -> int:
    """The open scope's refusal count (0 outside a scope)."""
    cur = _current.get()
    return 0 if cur is None else cur.refusals


def charge_regex(src: str, subject_len: int) -> bool:
    """Charge one regex evaluation to the open scope; False = over budget (the caller must NOT match). Outside any scope
    the evaluation is charged to a fresh single-use budget."""
    cur = _current.get()
    return (cur if cur is not None else RegexBudget(1, _ambient(), True)).charge(src, subject_len)
