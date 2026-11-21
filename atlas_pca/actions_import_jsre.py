"""A translator from the JavaScript regular expression dialect (ECMAScript, no flags, Annex B leniency) used by `path_re` of the suggestion
rules to a Python `re` pattern with the same meaning on UTF-16 code units. It exists so a rule set is accepted or refused exactly as the
reference's `new RegExp(...)` does and matches the same locations. Syntax the reference rejects raises ValueError. Supported: literals,
`.`, anchors, `\\b \\B`, classes with ranges and class escapes, groups `(...)` and `(?:...)`, alternation, greedy and lazy quantifiers.
Lookaround, named groups and back-references are refused (the rule validator refuses them before a pattern is compiled)."""
import re
from typing import List, Optional, Tuple

_WS = [(9, 13), (32, 32), (0xA0, 0xA0), (0x1680, 0x1680), (0x2000, 0x200A), (0x2028, 0x2029), (0x202F, 0x202F), (0x205F, 0x205F), (0x3000, 0x3000), (0xFEFF, 0xFEFF)]
_DIGIT = [(48, 57)]
_WORD = [(48, 57), (65, 90), (95, 95), (97, 122)]
_MAX = 0xFFFF


def _norm(iv: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _neg(iv: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    out, cur = [], 0
    for lo, hi in _norm(iv):
        if lo > cur:
            out.append((cur, lo - 1))
        cur = hi + 1
    if cur <= _MAX:
        out.append((cur, _MAX))
    return out


def to_utf16(s: str) -> str:
    """The string as UTF-16 code units: an astral character becomes its two surrogate characters."""
    return "".join(c if ord(c) <= 0xFFFF else chr(0xD800 + ((ord(c) - 0x10000) >> 10)) + chr(0xDC00 + ((ord(c) - 0x10000) & 0x3FF)) for c in s)


def _cls(iv: List[Tuple[int, int]]) -> str:
    iv = _norm(iv)
    if not iv:
        return "(?!)"
    return "[" + "".join("\\u%04x" % lo if lo == hi else "\\u%04x-\\u%04x" % (lo, hi) for lo, hi in iv) + "]"


_CLASS_ESC = {"d": _DIGIT, "w": _WORD, "s": _WS}
_CTRL = {"f": 12, "n": 10, "r": 13, "t": 9, "v": 11}
_HEX = "0123456789abcdefABCDEF"


class _P:
    def __init__(self, src: str):
        self.s = to_utf16(src)
        self.i = 0

    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.s[j] if j < len(self.s) else ""

    def err(self, msg: str):
        raise ValueError("Invalid regular expression: %s" % msg)

    def disjunction(self, depth: int) -> str:
        alts = [self.alternative(depth)]
        while self.peek() == "|":
            self.i += 1
            alts.append(self.alternative(depth))
        return "|".join(alts)

    def alternative(self, depth: int) -> str:
        out: List[str] = []
        while self.i < len(self.s) and self.peek() not in ("|", ")"):
            out.append(self.term(depth))
        return "".join(out)

    def braced(self) -> Optional[Tuple[int, Optional[int], int]]:
        """{n}, {n,} or {n,m} at the cursor: (min, max or None, length), or None when the brace is not a quantifier."""
        m = re.compile(r"\{([0-9]+)(?:(,)([0-9]*))?\}").match(self.s, self.i)
        if m is None:
            return None
        lo = int(m.group(1))
        hi = lo if m.group(2) is None else (int(m.group(3)) if m.group(3) != "" else None)
        if hi is not None and hi < lo:
            self.err("numbers out of order in {} quantifier")
        return lo, hi, m.end() - self.i

    def quantifier(self, atom: str) -> str:
        c = self.peek()
        if c in ("*", "+", "?"):
            self.i += 1
            q = c
        else:
            b = self.braced() if c == "{" else None
            if b is None:
                return atom
            self.i += b[2]
            q = "{%d,%s}" % (b[0], "" if b[1] is None else b[1])
        if self.peek() == "?":
            self.i += 1
            q += "?"
        return atom + q

    def term(self, depth: int) -> str:
        c = self.peek()
        if c == "^":
            self.i += 1
            return "\\A"
        if c == "$":
            self.i += 1
            return "\\Z"
        if c == "\\" and self.peek(1) in ("b", "B"):
            self.i += 2
            return "\\" + self.s[self.i - 1]
        if c in ("*", "+", "?"):
            self.err("nothing to repeat")
        if c == "{" and self.braced() is not None:
            self.err("nothing to repeat")
        return self.quantifier(self.atom(depth))

    def atom(self, depth: int) -> str:
        c = self.peek()
        if depth > 200:
            self.err("too deeply nested")
        if c == "(":
            self.i += 1
            if self.peek() == "?":
                if self.peek(1) != ":":
                    self.err("invalid group")
                self.i += 2
                head = "(?:"
            else:
                head = "("
            body = self.disjunction(depth + 1)
            if self.peek() != ")":
                self.err("unterminated group")
            self.i += 1
            return head + body + ")"
        if c == ".":
            self.i += 1
            return "[^\\n\\r\\u2028\\u2029]"
        if c == "[":
            return self.char_class()
        if c == "\\":
            return self.atom_escape()
        self.i += 1
        return re.escape(c) if c not in ("{", "}", "]") else "\\" + c

    def _hex(self, n: int) -> Optional[int]:
        h = self.s[self.i:self.i + n]
        if len(h) == n and all(x in _HEX for x in h):
            self.i += n
            return int(h, 16)
        return None

    def escape_char(self, in_class: bool) -> Optional[int]:
        """The code unit a character escape at `\\` denotes (cursor past the escape), or None when the escape is a class escape (cursor unmoved)."""
        self.i += 1  # the backslash
        if self.i >= len(self.s):
            self.err("\\ at end of pattern")
        c = self.s[self.i]
        if c in _CTRL:
            self.i += 1
            return _CTRL[c]
        if c == "c":
            nxt = self.peek(1)
            if re.fullmatch("[A-Za-z]", nxt or "-"):
                self.i += 2
                return ord(nxt) % 32
            if in_class and re.fullmatch("[0-9_]", nxt or "-"):
                self.i += 2
                return ord(nxt) % 32
            return ord("\\")  # a lone backslash; the `c` is read next
        if c == "0":
            self.i += 1
            if self.peek() and self.peek() in "01234567":
                v = 0
                n = 0
                while n < 3 and self.peek() and self.peek() in "01234567" and v * 8 + int(self.peek()) <= 0o377:
                    v = v * 8 + int(self.peek())
                    self.i += 1
                    n += 1
                return v
            return 0
        if c == "x":
            self.i += 1
            v = self._hex(2)
            return v if v is not None else ord("x")
        if c == "u":
            self.i += 1
            v = self._hex(4)
            return v if v is not None else ord("u")
        if c == "b" and in_class:
            self.i += 1
            return 8
        if c in "123456789":
            self.err("back-references are not supported")
        if c == "k":
            self.i += 1
            return ord("k")
        self.i += 1
        return ord(c)

    def atom_escape(self) -> str:
        c = self.peek(1)
        if c in _CLASS_ESC or c in ("D", "W", "S"):
            self.i += 2
            iv = _CLASS_ESC[c.lower()]
            return _cls(iv if c.islower() else _neg(iv))
        return _lit(self.escape_char(False))

    def class_atom(self):
        """(code unit or None, interval set or None)."""
        c = self.peek()
        if c == "\\":
            n = self.peek(1)
            if n in _CLASS_ESC or n in ("D", "W", "S"):
                self.i += 2
                iv = _CLASS_ESC[n.lower()]
                return None, (iv if n.islower() else _neg(iv))
            return self.escape_char(True), None
        self.i += 1
        return ord(c), None

    def char_class(self) -> str:
        self.i += 1
        negate = False
        if self.peek() == "^":
            negate = True
            self.i += 1
        iv: List[Tuple[int, int]] = []
        while True:
            if self.i >= len(self.s):
                self.err("unterminated character class")
            if self.peek() == "]":
                self.i += 1
                break
            a, aset = self.class_atom()
            if self.peek() == "-" and self.peek(1) not in ("]", ""):
                self.i += 1
                b, bset = self.class_atom()
                if aset is not None or bset is not None:  # Annex B: a class escape on either side makes the dash a literal
                    iv += (aset if aset is not None else [(a, a)]) + [(45, 45)] + (bset if bset is not None else [(b, b)])
                    continue
                if a > b:
                    self.err("range out of order in character class")
                iv.append((a, b))
                continue
            iv += aset if aset is not None else [(a, a)]
        return _cls(_neg(iv) if negate else iv)


def _lit(u: int) -> str:
    return re.escape(chr(u)) if 0x20 < u < 0x7F else "\\u%04x" % u


def translate(pattern: str) -> str:
    """The Python pattern text for a JavaScript pattern, or ValueError."""
    p = _P(pattern)
    out = p.disjunction(0)
    if p.i < len(p.s):
        p.err("unmatched ')'")
    return out


def compile_js(pattern: str) -> "re.Pattern":
    try:
        return re.compile(translate(pattern), re.ASCII)
    except re.error as e:
        raise ValueError("Invalid regular expression: %s" % e)


def js_test(rx: "re.Pattern", s: str) -> bool:
    """RegExp.prototype.test: a match anywhere in the string (as UTF-16 code units)."""
    return rx.search(to_utf16(s)) is not None
