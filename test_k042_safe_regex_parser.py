"""Kill tests for the linear-time regex parser and compiler (atlas_pca.safe_regex): the exact refusal text of every parse
refusal, the escape table, the parsed shape, the emitted NFA program of each construct, and the program-size boundaries."""
import pytest

from atlas_pca import safe_regex as sr
from atlas_pca.safe_regex import (
    DIGIT, MAX_NFA_INSTRUCTIONS, MAX_REPEAT, OP_BOL, OP_EOL, OP_JMP, OP_MATCH, OP_SET, OP_SPLIT, WORD, SPACE, _emit, _Parser,
    _Refuse, compile_safe_regex, to_units,
)


def refusal(src):
    with pytest.raises(_Refuse) as e:
        _Parser(to_units(src)).parse()
    return str(e.value)


@pytest.mark.parametrize("src,msg", [
    ("a\\", "trailing backslash"), ("\\", "trailing backslash"),
    ("\\00", "octal escape"), ("\\09", "octal escape"), ("\\01", "octal escape"),
    ("\\x", "bad \\x escape"), ("\\x4", "bad \\x escape"), ("\\xg0", "bad \\x escape"), ("\\x0g", "bad \\x escape"),
    ("\\u", "bad \\u escape"), ("\\u123", "bad \\u escape"), ("\\u12g4", "bad \\u escape"), ("\\u123g", "bad \\u escape"),
    ("\\c", "bad \\c escape"), ("\\c1", "bad \\c escape"), ("\\c-", "bad \\c escape"),
    ("\\b", "word-boundary assertions are not supported"), ("a\\b", "word-boundary assertions are not supported"),
    ("\\1", "escape \\1 is not supported"), ("\\k", "escape \\k is not supported"), ("\\_", "escape \\_ is not supported"),
    ("\\B", "escape \\B is not supported"), ("\\a", "escape \\a is not supported"), ("\\Z", "escape \\Z is not supported"),
    ("\\9", "escape \\9 is not supported"),
    ("(?=a)", "lookaround / named groups are not supported"), ("(?!a)", "lookaround / named groups are not supported"),
    ("(?<n>a)", "lookaround / named groups are not supported"), ("(?", "lookaround / named groups are not supported"),
    ("(a", "unterminated group"), ("(?:a", "unterminated group"), ("(", "unterminated group"), ("((a)", "unterminated group"),
    ("a)", "unbalanced )"), (")", "unbalanced )"), ("(a))", "unbalanced )"),
    ("*", "nothing to repeat"), ("+", "nothing to repeat"), ("?", "nothing to repeat"), ("a|*", "nothing to repeat"),
    ("(*)", "nothing to repeat"),
    ("{", "{ is not a well-formed quantifier"), ("a{", "{ is not a well-formed quantifier"),
    ("a{x}", "{ is not a well-formed quantifier"), ("a{1", "{ is not a well-formed quantifier"),
    ("a{,2}", "{ is not a well-formed quantifier"), ("a{12345}", "{ is not a well-formed quantifier"),
    ("a{1,12345}", "{ is not a well-formed quantifier"), ("{1}", "{ is not a well-formed quantifier"),
    ("a{2,1}", "quantifier range out of order"), ("a{64,63}", "quantifier range out of order"),
    ("^*", "nothing to repeat (assertion)"), ("$+", "nothing to repeat (assertion)"), ("^?", "nothing to repeat (assertion)"),
    ("^{2}", "nothing to repeat (assertion)"), ("$*", "nothing to repeat (assertion)"), ("$?", "nothing to repeat (assertion)"),
    ("a{65}", "repeat bound too large"), ("a{0,65}", "repeat bound too large"), ("a{65,}", "repeat bound too large"),
    ("a{65,70}", "repeat bound too large"), ("a{0,1000}", "repeat bound too large"),
    ("[a", "unterminated class"), ("[", "unterminated class"), ("[^", "unterminated class"), ("[a-", "unterminated class"),
    ("[b-a]", "class range out of order"), ("[z-a]", "class range out of order"),
])
def test_parse_refusals(src, msg):
    assert refusal(src) == msg


def test_repeat_bounds_accepted():
    for src in ("a{64}", "a{0,64}", "a{64,}", "a{0}", "a{0,0}", "a{64,64}", "(a{64}){2}"):
        assert compile_safe_regex(src) is not None, src
    assert str(MAX_REPEAT) == "64"


def ast_of(src):
    return _Parser(to_units(src)).parse()


def test_ast_shapes():
    assert ast_of("a")[0] == "cat" and ast_of("a")[1][0][0] == "set"
    assert ast_of("a|b")[0] == "alt" and len(ast_of("a|b")[1]) == 2 and ast_of("a|b|c")[1][2][0] == "cat"
    assert ast_of("^$")[1] == [("bol",), ("eol",)]
    r = ast_of("a{2,3}")[1][0]
    assert r[0] == "rep" and (r[2], r[3]) == (2, 3)
    r = ast_of("a{2}")[1][0]
    assert (r[2], r[3]) == (2, 2)
    r = ast_of("a{2,}")[1][0]
    assert (r[2], r[3]) == (2, float("inf"))
    for src, mn, mx in (("a*", 0, float("inf")), ("a+", 1, float("inf")), ("a?", 0, 1), ("a*?", 0, float("inf")), ("a{1,2}?", 1, 2)):
        r = ast_of(src)[1][0]
        assert r[0] == "rep" and (r[2], r[3]) == (mn, mx), src
    assert ast_of("(?:ab)")[0] == "cat" and ast_of("(ab)c")[1][0][0] == "cat"
    assert ast_of("")[1] == []
    assert ast_of("a|")[1][1] == ("cat", [])


def ranges(src):
    node = ast_of(src)[1][0]
    assert node[0] == "set"
    return node[1].ranges, node[1].negated


@pytest.mark.parametrize("src,ranges_,neg", [
    ("a", ((97, 97),), False), (".", sr.LINE_TERMINATORS, True),
    ("\\d", DIGIT, False), ("\\D", DIGIT, True), ("\\w", WORD, False), ("\\W", WORD, True),
    ("\\s", SPACE, False), ("\\S", SPACE, True),
    ("\\t", ((9, 9),), False), ("\\n", ((10, 10),), False), ("\\v", ((11, 11),), False), ("\\f", ((12, 12),), False),
    ("\\r", ((13, 13),), False), ("\\0", ((0, 0),), False), ("\\x41", ((65, 65),), False), ("\\u0041", ((65, 65),), False),
    ("\\uffff", ((0xFFFF, 0xFFFF),), False), ("\\cA", ((1, 1),), False), ("\\cz", ((26, 26),), False),
    ("\\.", ((46, 46),), False), ("\\\\", ((92, 92),), False), ("\\-", ((45, 45),), False), ("\\/", ((47, 47),), False),
    ("\\x00", ((0, 0),), False), ("\\xFF", ((255, 255),), False), ("\\xff", ((255, 255),), False),
])
def test_atom_sets(src, ranges_, neg):
    got, n = ranges(src)
    assert tuple(got) == tuple(ranges_) and n is neg


def test_escape_inner_tuple():
    for src, cls in (("\\d", True), ("\\D", True), ("\\w", True), ("\\W", True), ("\\s", True), ("\\S", True)):
        s, is_cls, ch = _Parser(src).escape_inner(False)
        assert is_cls is cls and ch is None
    for src, code in (("\\t", 9), ("\\n", 10), ("\\0", 0), ("\\x41", 65), ("\\u0041", 65), ("\\cA", 1), ("\\.", 46)):
        s, is_cls, ch = _Parser(src).escape_inner(False)
        assert is_cls is False and ch == code
    assert _Parser("\\b").escape_inner(True)[2] == 8  # [\b] is a backspace
    with pytest.raises(_Refuse):
        _Parser("\\b").escape_inner(False)


@pytest.mark.parametrize("src,want", [
    ("[abc]", [(97, 99)]), ("[a-c]", [(97, 99)]), ("[^a]", [(97, 97)]), ("[a-cx-z]", [(97, 99), (120, 122)]),
    ("[\\d]", [(48, 57)]), ("[a\\-z]", [(45, 45), (97, 97), (122, 122)]), ("[a-]", [(45, 45), (97, 97)]),
    ("[-a]", [(45, 45), (97, 97)]), ("[]", []), ("[\\d-z]", [(45, 45), (48, 57), (122, 122)]),
    ("[a-\\d]", [(45, 45), (48, 57), (97, 97)]), ("[\\b]", [(8, 8)]), ("[a-a]", [(97, 97)]),
])
def test_class_ranges(src, want):
    got, neg = ranges(src)
    assert list(got) == want and neg is src.startswith("[^")


# ---- emitted programs -------------------------------------------------------------------------------------------------------

def prog_of(src):
    prog = []
    _emit(ast_of(src), prog)
    prog.append([OP_MATCH, 0, 0, None])
    return [[op, x, y, "S" if s is not None else None] for op, x, y, s in prog]


S = lambda: [OP_SET, 0, 0, "S"]  # noqa: E731


@pytest.mark.parametrize("src,want", [
    ("a", [[OP_SET, 0, 0, "S"], [OP_MATCH, 0, 0, None]]),
    ("^a$", [[OP_BOL, 0, 0, None], [OP_SET, 0, 0, "S"], [OP_EOL, 0, 0, None], [OP_MATCH, 0, 0, None]]),
    ("a*", [[OP_SPLIT, 1, 3, None], [OP_SET, 0, 0, "S"], [OP_JMP, 0, 0, None], [OP_MATCH, 0, 0, None]]),
    ("a+", [[OP_SET, 0, 0, "S"], [OP_SPLIT, 2, 4, None], [OP_SET, 0, 0, "S"], [OP_JMP, 1, 0, None], [OP_MATCH, 0, 0, None]]),
    ("a?", [[OP_SPLIT, 1, 2, None], [OP_SET, 0, 0, "S"], [OP_MATCH, 0, 0, None]]),
    ("a{2,3}", [[OP_SET, 0, 0, "S"], [OP_SET, 0, 0, "S"], [OP_SPLIT, 3, 4, None], [OP_SET, 0, 0, "S"], [OP_MATCH, 0, 0, None]]),
    ("a|b", [[OP_SPLIT, 1, 3, None], [OP_SET, 0, 0, "S"], [OP_JMP, 4, 0, None], [OP_SET, 0, 0, "S"], [OP_MATCH, 0, 0, None]]),
    ("a|b|c", [[OP_SPLIT, 1, 3, None], [OP_SET, 0, 0, "S"], [OP_JMP, 7, 0, None], [OP_SPLIT, 4, 6, None], [OP_SET, 0, 0, "S"],
               [OP_JMP, 7, 0, None], [OP_SET, 0, 0, "S"], [OP_MATCH, 0, 0, None]]),
    ("a{0}", [[OP_MATCH, 0, 0, None]]),
    ("a{2,}", [[OP_SET, 0, 0, "S"], [OP_SET, 0, 0, "S"], [OP_SPLIT, 3, 5, None], [OP_SET, 0, 0, "S"], [OP_JMP, 2, 0, None],
               [OP_MATCH, 0, 0, None]]),
    ("a{0,2}", [[OP_SPLIT, 1, 4, None], [OP_SET, 0, 0, "S"], [OP_SPLIT, 3, 4, None], [OP_SET, 0, 0, "S"], [OP_MATCH, 0, 0, None]]),
    ("(ab)*c", [[OP_SPLIT, 1, 4, None], [OP_SET, 0, 0, "S"], [OP_SET, 0, 0, "S"], [OP_JMP, 0, 0, None], [OP_SET, 0, 0, "S"],
                [OP_MATCH, 0, 0, None]]),
    ("", [[OP_MATCH, 0, 0, None]]),
])
def test_program(src, want):
    assert prog_of(src) == want


def test_set_is_the_parsed_set():
    prog = []
    node = ast_of("[a-c]")[1][0]
    _emit(node, prog)
    assert prog[0][0] == OP_SET and prog[0][3] is node[1]


# ---- size boundaries ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("src,ok", [
    ("a" * 4095, True), ("a" * 4096, False), ("a" * 4097, False),
    ("(a{64}){63}" + "a" * 63, True), ("(a{64}){63}" + "a" * 64, False), ("(a{64}){63}a{63}", True), ("(a{64}){63}a{64}", False),
    ("(a{64}){64}", False), ("(a{64}){65}", False),
])
def test_program_size_boundary(src, ok):
    assert (compile_safe_regex(src) is not None) is ok
    assert MAX_NFA_INSTRUCTIONS == 4096


def test_too_large_refusal_text():
    for src in ("a" * 4096, "(a{64}){64}", "(a{64}){63}a{64}"):
        prog = []
        with pytest.raises(_Refuse) as e:
            _emit(ast_of(src), prog)
            if len(prog) + 1 > MAX_NFA_INSTRUCTIONS:
                raise _Refuse("pattern too large")
        assert str(e.value) == "pattern too large"
    prog = [[OP_SET, 0, 0, None]] * (MAX_NFA_INSTRUCTIONS + 1)
    with pytest.raises(_Refuse) as e:
        _emit(("bol",), prog)
    assert str(e.value) == "pattern too large"
    prog = [[OP_SET, 0, 0, None]] * MAX_NFA_INSTRUCTIONS
    _emit(("bol",), prog)  # exactly at the limit is still emitted
    assert len(prog) == MAX_NFA_INSTRUCTIONS + 1
    prog = [[OP_SET, 0, 0, None]] * MAX_NFA_INSTRUCTIONS
    with pytest.raises(_Refuse) as e:
        _emit(("rep", ("bol",), 0, 1), prog)
    assert str(e.value) == "pattern too large"
