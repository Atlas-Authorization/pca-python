"""Mutation kills (predicates): the predicate evaluator (atlas_pca/predicates.py), the linear-time safe-regex engine and the
per-document regex budget (atlas_pca/safe_regex.py) and the Intent Layer v2 `layers` check (atlas_pca/intent_layers.py),
ported from packages/pca/src/{predicates,safe-regex,regex-budget,intent-layers}.ts. Every op is pinned on its
true / false / unknown sides, every cap at max and max+1 (UTF-16 code units, not code points), the JS-semantics traps
(bool is not a number, 2 == 2.0, binary64 rounding, UTF-8 string order, lone surrogates) and the check order."""
from atlas_pca.intent_layers import LAYER_CEILINGS, decide_layer_ceilings, decide_layers, is_layer_policy
from atlas_pca.predicates import (
    MAX_LIKE_PATTERN_LEN, MAX_MATCHES_PATTERN_LEN, MAX_MEMBER_CLOSURE_NODES, MAX_PATTERN_SUBJECT_LEN,
    MAX_RE_RESOURCE_LEN, MAX_REGEX_COST_BITS, UNBOUNDED_QUANTIFIER_BITS, evaluate_condition, evaluate_condition_tri,
    evaluate_predicates, is_group_condition, is_leaf_condition, is_safe_regex_source, predicate_matches, resolve_path,
)
from atlas_pca.safe_regex import (
    MAX_MATCH_STEPS, MAX_NFA_INSTRUCTIONS, MAX_REGEX_EVALUATIONS_PER_DOCUMENT, MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT,
    MAX_REGEX_STEPS_PER_DOCUMENT, MAX_REPEAT, REGEX_REQUEST_SCALE, RegexBudget, charge_regex, compile_safe_regex,
    regex_refusals, safe_regex_full_match, to_units, utf16_len, with_regex_budget,
)

ASTRAL = "\U0001F600"  # one code point, two UTF-16 units
HI = "\ud83d"  # its lone high surrogate


def _ctx(params=None, env=None, verb="read", resource="/r", subject=None, with_params=True):
    a = {"verb": verb, "resource": resource}
    if with_params:
        a["params"] = {} if params is None else params
    c = {"action": a, "env": {} if env is None else env}
    if subject is not None:
        c["subject"] = subject
    return c


def _leaf(op, value=None, field="action.params.x", **kw):
    c = {"field": field, "op": op, **kw}
    if value is not None:
        c["value"] = value
    return c


def tri(cond, ctx):
    return evaluate_condition_tri(cond, ctx)


def x(v, op, value, **kw):
    """Tri of `action.params.x <op> value`."""
    c = {"field": "action.params.x", "op": op, "value": value, **kw}
    return tri(c, _ctx({"x": v}))


T, F, U = "true", "false", "unknown"


# ---- constants ------------------------------------------------------------------------------------------------------

def test_constants_pinned():
    assert (MAX_PATTERN_SUBJECT_LEN, MAX_LIKE_PATTERN_LEN, MAX_MATCHES_PATTERN_LEN) == (512, 512, 200)
    assert (MAX_MEMBER_CLOSURE_NODES, MAX_RE_RESOURCE_LEN) == (10_000, 512)
    assert (MAX_REGEX_COST_BITS, UNBOUNDED_QUANTIFIER_BITS) == (22, 8)
    assert (MAX_NFA_INSTRUCTIONS, MAX_REPEAT, MAX_MATCH_STEPS) == (4096, 64, 2_000_000)
    assert (MAX_REGEX_EVALUATIONS_PER_DOCUMENT, MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT, MAX_REGEX_STEPS_PER_DOCUMENT) == (
        64, 8192, 5_000_000)
    assert REGEX_REQUEST_SCALE == 4
    assert LAYER_CEILINGS == ("org", "site", "std")


def test_utf16_helpers():
    assert utf16_len(ASTRAL) == 2 and utf16_len("ab") == 2 and utf16_len("") == 0
    assert to_units(ASTRAL) == "\ud83d\ude00"  # the surrogate pair, one char per UTF-16 unit
    assert to_units("abc") == "abc"


# ---- resolvePath ----------------------------------------------------------------------------------------------------

def test_resolve_path():
    ctx = _ctx({"list": [10, 20], "o": {"toString": 1, "constructor": 2}, "n": None})
    assert resolve_path(ctx, "action.params.list.1") == {"found": True, "value": 20}
    assert resolve_path(ctx, "action.params.list.0") == {"found": True, "value": 10}
    assert resolve_path(ctx, "action.params.list.01") == {"found": False}
    assert resolve_path(ctx, "action.params.list.2") == {"found": False}
    assert resolve_path(ctx, "action.params.list.-1") == {"found": False}
    assert resolve_path(ctx, "action.params.list.1\n") == {"found": False}  # anchored index regex
    assert resolve_path(ctx, "action.params.o.toString") == {"found": True, "value": 1}
    assert resolve_path(ctx, "action.params.o.constructor") == {"found": False}  # FORBIDDEN segment
    assert resolve_path(ctx, "action.params.n") == {"found": True, "value": None}
    assert resolve_path(ctx, "action.params.n.x") == {"found": False}
    assert resolve_path(ctx, "action.verb.length") == {"found": False}  # strings have no own properties here
    assert resolve_path(ctx, "env") == {"found": True, "value": {}}
    assert resolve_path(ctx, "subject") == {"found": False}
    assert resolve_path(ctx, "params.x") == {"found": False}  # unknown root
    assert resolve_path(ctx, "") == {"found": False}
    assert resolve_path(ctx, 5) == {"found": False}
    assert resolve_path("not-a-ctx", "action") == {"found": False}
    assert resolve_path({"env": None}, "env") == {"found": True, "value": None}


# ---- eq / ne / in / nin ---------------------------------------------------------------------------------------------

def test_eq_json_type_and_value():
    assert x(2, "eq", 2.0) == T
    assert x(0, "eq", -0.0) == T
    assert x(True, "eq", 1) == F and x(1, "eq", True) == F
    assert x(False, "eq", 0) == F
    assert x("2", "eq", 2) == F
    assert x({"a": 1, "b": [1, 2]}, "eq", {"b": [1, 2.0], "a": 1}) == T
    assert x({"a": 1}, "eq", {"a": 1, "b": 2}) == F
    assert x([1], "eq", {"0": 1}) == F
    assert x([1, 2], "eq", [2, 1]) == F
    assert x(9007199254740993, "eq", 9007199254740992) == T  # binary64 rounding, as JSON.parse
    assert x(float("inf"), "eq", float("inf")) == F  # the canonicalizer refuses a non-finite number
    assert x([1, float("nan")], "ne", [1, float("nan")]) == T
    assert x(ASTRAL, "eq", "😀") == T  # same UTF-16 code units
    c = {"field": "action.params.x", "op": "eq", "value": None}
    assert tri(c, _ctx({"x": None})) == T
    assert tri(c, _ctx({"x": 0})) == F
    assert x(2, "ne", 2.0) == F and x(2, "ne", 3) == T


def test_eq_non_finite_anywhere_is_false():
    inf, big = float("inf"), 10 ** 400  # `1e400` parses to Infinity; a Python int beyond binary64 is the same JS number
    # differs EARLY, non-finite LATER: the canonicalizer still throws -> eq false, ne true
    assert x([1, inf], "eq", [2, 0]) == F and x([1, inf], "ne", [2, 0]) == T
    assert x([2, 0], "eq", [1, inf]) == F and x([2, 0], "ne", [1, inf]) == T
    assert x({"a": 1, "z": inf}, "ne", {"a": 2, "z": 0}) == T
    assert x({"a": 1}, "eq", {"a": 1, "b": [big]}) == F  # different key sets AND non-finite
    assert x("s", "eq", [inf]) == F and x([inf], "ne", "s") == T  # type mismatch at the root
    assert x([inf], "eq", [inf]) == F and x([-inf], "ne", [-inf]) == T
    assert x([big], "eq", [big]) == F
    assert x(big, "eq", big) == F
    assert x({"k": [1, {"d": float("nan")}]}, "eq", {"k": [1, {"d": float("nan")}]}) == F
    # in / nin: the field value itself non-finite -> no element is ever equal
    assert x([inf], "in", [[inf], 1]) == F and x([inf], "nin", [[inf], 1]) == T
    assert x(1, "in", [[inf], 1]) == T  # a non-finite ELEMENT only spoils its own comparison
    assert x(1, "nin", [[inf], 1]) == F
    assert x(1, "in", [[1, inf]]) == F
    # a finite neighbour that is large but representable stays comparable
    assert x([1e308], "eq", [1e308]) == T


def test_in_nin():
    assert x(2, "in", [1, 2.0]) == T
    assert x(2, "in", ["2", True]) == F
    assert x(2, "in", []) == F
    assert x(2, "in", 2) == U and x(2, "in", {"a": 2}) == U
    assert x(2, "nin", [1, 2.0]) == F
    assert x(2, "nin", []) == T
    assert x(2, "nin", "2") == U


# ---- ordering -------------------------------------------------------------------------------------------------------

def test_order_numbers():
    for op, lt, eq, gt in (("lt", T, F, F), ("lte", T, T, F), ("gt", F, F, T), ("gte", F, T, T)):
        assert x(1, op, 2) == lt, op
        assert x(2, op, 2.0) == eq, op
        assert x(3, op, 2) == gt, op
    assert x(9007199254740993, "lt", 9007199254740992) == F
    assert x(9007199254740993, "lte", 9007199254740992) == T
    assert x(-0.0, "lt", 0) == F and x(-0.0, "gte", 0) == T


def test_order_types_fail_unknown():
    assert x(True, "lt", 2) == U and x(1, "lt", True) == U  # bool is not a number
    assert x(1, "lt", "2") == U and x("1", "lt", 2) == U
    assert x(None, "lt", 1) == U and x([1], "lt", [2]) == U
    assert x(float("inf"), "gt", 1) == U
    assert x(10 ** 400, "gt", 1) == U  # beyond binary64 -> Infinity -> not finite


def test_order_strings_utf8():
    assert x("a", "lt", "b") == T and x("b", "lt", "a") == F
    assert x("abc", "lte", "abc") == T and x("abc", "lt", "abc") == F
    assert x("", "lt", "a") == T
    assert x("ab", "lt", "abc") == T
    assert x("Z", "lt", "a") == T
    # UTF-8 / code point order: U+FFFF < U+1F600 (JS `<` over UTF-16 units would say the opposite)
    assert x("￿", "lt", ASTRAL) == T
    assert x(ASTRAL, "gt", "￿") == T
    assert x("", "lt", ASTRAL) == T
    # a lone surrogate has no UTF-8 encoding: no order
    assert x(HI, "lt", "a") == U and x("a", "gt", "\udc00") == U


# ---- prefix / like --------------------------------------------------------------------------------------------------

def test_prefix():
    assert x("abc", "prefix", "ab") == T
    assert x("abc", "prefix", "") == T
    assert x("abc", "prefix", "b") == F
    assert x("ab", "prefix", "abc") == F
    assert x(1, "prefix", "1") == U and x("1", "prefix", 1) == U
    assert x(ASTRAL + "x", "prefix", HI) == T  # UTF-16 startsWith


def test_like_semantics():
    assert x("abc", "like", "a*c") == T
    assert x("abc", "like", "a*") == T
    assert x("abc", "like", "*") == T
    assert x("", "like", "*") == T
    assert x("", "like", "?") == F
    assert x("abc", "like", "a?c") == T
    assert x("abbc", "like", "a?c") == F
    assert x("a" + ASTRAL + "c", "like", "a?c") == F  # `?` is ONE UTF-16 unit
    assert x("a" + ASTRAL + "c", "like", "a??c") == T
    assert x("a*", "like", "a\\*") == T and x("ab", "like", "a\\*") == F
    assert x("a?", "like", "a\\?") == T and x("ab", "like", "a\\?") == F
    assert x("a\\", "like", "a\\\\") == T
    assert x("ab", "like", "ab\\") == U  # dangling backslash
    assert x("a\nb", "like", "a*b") == T and x("a\nb", "like", "a?b") == T
    assert x("aXbYc", "like", "*b*c") == T and x("aXbYd", "like", "*b*c") == F
    assert x("abc", "like", "abc*") == T and x("abc", "like", "abcd") == F
    assert x(1, "like", "*") == U and x("1", "like", 1) == U
    # the old exponential case is linear
    assert x("a" * 500, "like", "*a*a*a*a*a*a*b") == F


def test_like_caps():
    assert x("a" * 512, "like", "*") == T
    assert x("a" * 513, "like", "*") == U
    assert x(ASTRAL * 256, "like", "*") == T  # 512 units
    assert x(ASTRAL * 256 + "a", "like", "*") == U  # 513 units (257 code points)
    assert x("a", "like", "*" * 512) == T
    assert x("a", "like", "*" * 513) == U
    assert x("a", "like", "*" * 510 + ASTRAL) == F  # 512 units: evaluated
    assert x("a", "like", "*" * 511 + ASTRAL) == U  # 513 units: refused


# ---- matches --------------------------------------------------------------------------------------------------------

def test_matches_semantics_and_caps():
    assert x("abc", "matches", "a.c") == T
    assert x("abcd", "matches", "a.c") == F  # anchored full match
    assert x("a\n", "matches", "a$") == F  # no trailing-newline leniency
    assert x("a" * 200, "matches", "a" * 200) == T
    assert x("a" * 201, "matches", "a" * 201) == U  # pattern 201 > 200
    assert x("a" * 512, "matches", "a*") == T
    assert x("a" * 513, "matches", "a*") == U
    assert x(ASTRAL * 256, "matches", "[^]*") == T
    assert x(ASTRAL * 256 + "a", "matches", "[^]*") == U
    assert x("a", "matches", ASTRAL * 100) == F  # 200 units: evaluated
    assert x("a", "matches", ASTRAL * 100 + "a") == U  # 201 units
    assert x("aa", "matches", "(a+)+") == U  # unsafe source
    assert x("a", "matches", "\\b") == U  # outside the subset
    assert x(1, "matches", ".") == U and x("1", "matches", 1) == U


# ---- exists / params availability -----------------------------------------------------------------------------------

def test_exists():
    ctx = _ctx({"x": 0, "n": None})
    assert tri({"field": "action.params.x", "op": "exists"}, ctx) == T
    assert tri({"field": "action.params.n", "op": "exists"}, ctx) == T
    assert tri({"field": "action.params.y", "op": "exists"}, ctx) == F
    assert tri({"field": "action.params.y", "op": "exists", "value": False}, ctx) == T
    assert tri({"field": "action.params.x", "op": "exists", "value": False}, ctx) == F
    assert tri({"field": "action.params.x", "op": "exists", "value": 0}, ctx) == T  # only `false` means absent
    assert tri({"field": "action.params.y", "op": "exists", "value": None}, ctx) == F
    assert tri({"field": "env.y", "op": "exists", "value": False}, ctx) == T
    assert tri({"field": "nope.y", "op": "exists"}, ctx) == F


def test_params_unavailable_is_not_absent():
    for ctx in (_ctx(with_params=False), _ctx(params=None, with_params=False),
                {"action": {"verb": "r", "resource": "/", "params": None}},
                {"action": {"verb": "r", "resource": "/", "params": "str"}},
                {"action": "not-an-object"}, {}):
        assert tri({"field": "action.params.y", "op": "exists", "value": False}, ctx) == U
        assert tri({"field": "action.params", "op": "exists", "value": False}, ctx) == U
        assert tri({"field": "env.x", "op": "nin", "ref": "action.params.y"}, dict(ctx, env={"x": 1})) == U
    # an array is an object: params available
    ctx = {"action": {"verb": "r", "resource": "/", "params": []}}
    assert tri({"field": "action.params.y", "op": "exists", "value": False}, ctx) == T
    # not params-rooted: `action.paramsX` is a plain path
    assert tri({"field": "action.paramsX", "op": "exists", "value": False}, _ctx(with_params=False)) == T


# ---- operand resolution ---------------------------------------------------------------------------------------------

def test_ref_and_value():
    ctx = _ctx({"x": 5}, env={"five": 5, "six": 6})
    assert tri({"field": "action.params.x", "op": "eq", "ref": "env.five"}, ctx) == T
    assert tri({"field": "action.params.x", "op": "eq", "ref": "env.six"}, ctx) == F
    assert tri({"field": "action.params.x", "op": "eq", "ref": "env.none"}, ctx) == U
    assert tri({"field": "action.params.x", "op": "eq", "ref": None, "value": 5}, ctx) == U  # ref present wins
    assert tri({"field": "action.params.x", "op": "eq", "ref": "env.five", "value": 6}, ctx) == T
    assert tri({"field": "action.params.x", "op": "eq"}, ctx) == U  # no operand
    assert tri({"field": "action.params.missing", "op": "ne", "value": 1}, ctx) == U  # unresolved field


def test_leaf_shape():
    ctx = _ctx({"x": 1})
    assert tri({"field": "", "op": "eq", "value": 1}, ctx) == U
    assert tri({"field": 5, "op": "eq", "value": 1}, ctx) == U
    assert tri({"field": "action.params.x", "op": 5, "value": 1}, ctx) == U
    assert tri({"field": "action.params.x", "op": "regex", "value": 1}, ctx) == U
    assert tri({"field": "action.params.x", "value": 1}, ctx) == U
    assert tri([{"field": "action.params.x", "op": "eq", "value": 1}], ctx) == U
    assert tri("x", ctx) == U and tri(None, ctx) == U
    assert is_leaf_condition({"field": "a", "op": "eq"}) and not is_leaf_condition({"field": 1})
    assert is_group_condition({"not": None}) and not is_group_condition([{"not": 1}])
    assert not is_leaf_condition({"field": "a", "all_of": []})


# ---- is_a / member_of -----------------------------------------------------------------------------------------------

def test_is_a():
    assert x("User::alice", "is_a", "User") == T
    assert x("User", "is_a", "User") == T
    assert x("Username", "is_a", "User") == F
    assert x("User:alice", "is_a", "User") == F
    assert x({"type": "Doc::pdf"}, "is_a", "Doc") == T
    assert x({"type": "Docs"}, "is_a", "Doc") == F
    assert x({"tags": ["a", "Doc"]}, "is_a", "Doc") == T
    assert x({"tags": ["a", 5]}, "is_a", "Doc") == F
    assert x({"type": 5}, "is_a", "Doc") == U
    assert x({"type": 5, "tags": []}, "is_a", "Doc") == F
    assert x({"type": "X", "tags": ["Doc"]}, "is_a", "Doc") == T
    assert x({}, "is_a", "Doc") == U
    assert x(5, "is_a", "Doc") == U and x(["Doc"], "is_a", "Doc") == U
    assert x("Doc", "is_a", "") == U and x("Doc", "is_a", 5) == U


def _mem(user, target, groups, **kw):
    c = {"field": "env.user", "op": "member_of", "collection": "env.groups", **kw}
    if target is not None:
        c["value"] = target
    return tri(c, _ctx(env={"user": user, "groups": groups, "tgt": "all"}))


def test_member_of():
    g = {"alice": ["eng", 5], "eng": "staff", "staff": ["all"]}
    assert _mem("alice", "all", g) == T
    assert _mem("alice", "alice", g) == T  # reflexive
    assert _mem("alice", "ops", g) == F
    assert _mem("alice", ["ops", "staff"], g) == T
    assert _mem("alice", [5, "ops"], g) == F
    assert _mem("alice", [5], g) == U and _mem("alice", 5, g) == U and _mem("alice", None, g) == U
    assert _mem("alice", None, g, ref="env.tgt") == T
    assert _mem("alice", None, g, ref="env.none") == U
    assert _mem(5, "all", g) == U
    assert _mem("alice", "all", ["alice"]) == U  # collection must be an object
    assert tri({"field": "env.user", "op": "member_of", "value": "all"}, _ctx(env={"user": "a"})) == U
    assert tri({"field": "env.user", "op": "member_of", "collection": "", "value": "a"}, _ctx(env={"user": "a"})) == U
    assert tri({"field": "env.user", "op": "member_of", "collection": "env.no", "value": "a"},
               _ctx(env={"user": "a"})) == U
    assert _mem("a", "c", {"a": "b", "b": "a"}) == F  # cycle terminates
    assert _mem("__proto__", "x", {"__proto__": "x"}) == F  # forbidden node has no neighbours
    assert _mem("constructor", "constructor", {}) == T  # reflexive still holds


def test_member_closure_cap():
    n = MAX_MEMBER_CLOSURE_NODES
    chain = {"n%d" % i: "n%d" % (i + 1) for i in range(n + 2)}
    assert _mem("n0", "n%d" % n, chain) == T  # added by the 10_000th visited node
    assert _mem("n0", "n%d" % (n + 1), chain) == F  # beyond the bound


# ---- boolean groupings ----------------------------------------------------------------------------------------------

CT = {"field": "env.t", "op": "eq", "value": 1}
CF = {"field": "env.t", "op": "eq", "value": 2}
CU = {"field": "env.missing", "op": "eq", "value": 1}
GCTX = _ctx(env={"t": 1})


def test_groups_tri_logic():
    assert tri({"all_of": [CT, CT]}, GCTX) == T
    assert tri({"all_of": [CT, CU]}, GCTX) == U
    assert tri({"all_of": [CU, CF]}, GCTX) == F
    assert tri({"all_of": []}, GCTX) == U and tri({"all_of": CT}, GCTX) == U
    assert tri({"any_of": [CU, CT]}, GCTX) == T
    assert tri({"any_of": [CF, CU]}, GCTX) == U
    assert tri({"any_of": [CF, CF]}, GCTX) == F
    assert tri({"any_of": []}, GCTX) == U and tri({"any_of": "x"}, GCTX) == U
    assert tri({"not": CT}, GCTX) == F and tri({"not": CF}, GCTX) == T and tri({"not": CU}, GCTX) == U
    assert tri({"not": None}, GCTX) == U
    assert tri({"not": {"not": CT}}, GCTX) == T
    assert tri({"all_of": [CT], "any_of": [CF]}, GCTX) == T  # all_of is checked first
    assert tri({"any_of": [CT], "not": CT}, GCTX) == T  # then any_of
    assert tri({"all_of": [CT], "field": "env.t", "op": "eq", "value": 2}, GCTX) == T  # a group is never a leaf
    assert evaluate_condition({"not": CU}, GCTX) is False
    assert evaluate_condition({"not": CF}, GCTX) is True


# ---- safe regex: engine ---------------------------------------------------------------------------------------------

def test_safe_regex_full_match_semantics():
    m = safe_regex_full_match
    assert m("a|b", "a") is True and m("a|b", "ab") is False and m("a|", "") is True
    assert m(".", "x") is True
    for lt in ("\n", "\r", " ", " "):
        assert m(".", lt) is False, repr(lt)
    assert m(".", ASTRAL) is False and m("..", ASTRAL) is True  # UTF-16 units
    assert m("[^]", "\n") is True and m("[]", "") is False and m("[]*", "") is True and m("[]", "a") is False
    assert m("a$", "a\n") is False and m("^a$", "a") is True and m("a^", "a") is False
    assert m("\\d+", "123") is True and m("\\d", "٣") is False  # ASCII digits only
    assert m("\\D", "a") is True and m("\\D", "1") is False
    assert m("\\w", "_") is True and m("\\w", "é") is False and m("\\W", "-") is True
    assert m("\\s", " ") is True and m("\\s", "﻿") is True and m("\\s", "\u0085") is False
    assert m("\\S", "a") is True and m("\\S", " ") is False
    assert m("[\\b]", "\x08") is True
    assert m("\\cJ", "\n") is True and m("\\cj", "\n") is True
    assert m("\\x41", "A") is True and m("\\u00e9", "é") is True and m("\\0", "\x00") is True
    assert m("\\t\\n\\v\\f\\r", "\t\n\x0b\x0c\r") is True
    assert m("[a-c]", "b") is True and m("[a-c]", "d") is False and m("[^a-c]", "d") is True
    assert m("[\\d-z]", "-") is True and m("[\\d-z]", "5") is True and m("[\\d-z]", "z") is True
    assert m("[\\d-z]", "m") is False  # Annex B: the '-' is literal
    assert m("[a-]", "-") is True and m("[-a]", "-") is True
    assert m("[\\D]", "a") is True and m("[\\D]", "1") is False and m("[^\\D]", "1") is True
    assert m("[\\]]", "]") is True and m("]", "]") is True and m("}", "}") is True
    assert m("a{2,3}", "a") is False and m("a{2,3}", "aa") is True and m("a{2,3}", "aaa") is True
    assert m("a{2,3}", "aaaa") is False
    assert m("a{2}", "aa") is True and m("a{2,}", "aaaaa") is True and m("a{2,}", "a") is False
    assert m("a*?", "aaa") is True and m("a+?", "") is False and m("a??", "a") is True
    assert m("(?:ab)+", "abab") is True and m("(a|b)*c", "abbac") is True
    assert m("\\uD83D\\uDE00", ASTRAL) is True
    assert m(ASTRAL, ASTRAL) is True
    assert m("[" + ASTRAL + "]", ASTRAL) is False  # a class holds two separate units
    assert m("[" + ASTRAL + "]", HI) is True
    assert m("\\.", ".") is True and m("\\.", "a") is False and m("\\/", "/") is True
    assert m("a", 5) is None and m(5, "a") is None


def test_compile_refusals():
    for src in ("\\b", "\\B", "\\1", "\\k<a>", "(?=a)", "(?!a)", "(?<=a)", "(?<n>a)", "\\p{L}", "a**", "*", "+a", "?",
                "{", "a{", "a{x}", "a{2,1}", "a{65}", "a{1,65}", "a{65,}", "\\", "[a", "[", "(a", "a)", ")", "\\00",
                "\\01", "\\xG0", "\\x4", "\\u12", "\\uZZZZ", "\\c1", "\\c", "\\_", "\\q", "\\e", "^*", "$+", "[b-a]",
                "a{1}{2}", "a{12345}"):
        assert compile_safe_regex(src) is None, src
        assert safe_regex_full_match(src, "a") is None, src
    for src in ("", "\\.", "\\-", "a{0,64}", "a{64}", "a{64,}", "\\0", "[\\]]", "]", "}", "a{2}?", "[\\d-z]", "(?:)"):
        assert compile_safe_regex(src) is not None, src
    assert compile_safe_regex(5) is None


def test_nfa_size_cap():
    # 64 x 64 sets = 4096 + Match = 4097 > 4096 instructions
    assert compile_safe_regex("(?:a{64}){64}") is None
    assert compile_safe_regex("(?:a{63}){64}") is not None  # 4032 + 1
    rx = compile_safe_regex("(?:a{63}){64}")
    assert len(rx.program) == 4033


P40 = "".join("%s{64}" % ch for ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")  # 200 chars, 2561 instructions


def test_match_steps_cap():
    assert len(P40) == 200 and len(compile_safe_regex(P40).program) == 2561
    assert safe_regex_full_match(P40, "a" * 779) is False  # 2561 x 780 = 1_997_580 <= 2M
    assert safe_regex_full_match(P40, "a" * 780) is None  # 2561 x 781 > 2M: refused, never run


# ---- safe regex: the source guard -----------------------------------------------------------------------------------

def test_is_safe_regex_source_nesting():
    for src in ("(a+)+", "(a*)*", "(a|aa)+", "(.*a){10}", "(?:a|b)*", "((a)+)?", "[^](a+)+]", "(a?){2}"):
        assert is_safe_regex_source(src) is False, src
    for src in ("/acct/[^/]+/items/\\d+", "(?:GET|POST) /x", "(ab)+", "(?:a)*", "[(a+)+]", "\\(a+\\)+"):
        assert is_safe_regex_source(src) is True, src
    for src in ("\\1", "\\k", "(?=a)", "(?<n>a)", "*a", "a|*", "(*)", "a{2,1}", "a{65}", "a{", "(a", "a)", "[a",
                "\\", "\\b"):
        assert is_safe_regex_source(src) is False, src
    assert is_safe_regex_source(5) is False and is_safe_regex_source(None) is False


def test_is_safe_regex_source_cost_bits():
    assert is_safe_regex_source("a*b*") is True  # 16 bits
    assert is_safe_regex_source("a*b*c*") is False  # 24 bits
    assert is_safe_regex_source("a*b*c?d?e?f?g?h?") is True  # 22
    assert is_safe_regex_source("a*b*c?d?e?f?g?h?i?") is False  # 23
    assert is_safe_regex_source("a*b*a{0,63}") is True  # 16 + ceil(log2 64) = 22
    assert is_safe_regex_source("a*b*a{0,64}") is False  # 16 + ceil(log2 65) = 23
    assert is_safe_regex_source("a*b*c{0,3}d{0,3}d{0,1}") is True  # 16 + 2 + 2 + 1 = 21
    assert is_safe_regex_source("a*b*c{0,4}d{0,3}d{0,1}") is True  # 16 + ceil(log2 5)=3 + 2 + 1 = 22
    assert is_safe_regex_source("a*b*c{0,4}d{0,3}d{0,2}") is False  # 16 + 3 + 2 + ceil(log2 3)=2 = 23
    assert is_safe_regex_source("a*b*a{5}a{5}a{5}") is True  # `{n}` costs nothing
    assert is_safe_regex_source("a*b*a{2,}") is False  # an unbounded `{n,}` costs 8
    assert is_safe_regex_source("|".join("a" * 23)) is True  # 22 alternations
    assert is_safe_regex_source("|".join("a" * 24)) is False  # 23
    assert is_safe_regex_source("a*?b*?") is True  # lazy markers cost nothing


def test_is_safe_regex_source_needs_compile():
    # passes the scanner but not the engine's parser (one parser decides what runs)
    assert is_safe_regex_source("\\q") is False
    assert is_safe_regex_source("a{12345,}") is False
    assert is_safe_regex_source("\\c1") is False


# ---- regex budget ---------------------------------------------------------------------------------------------------

def _where_pred(where, verb="r"):
    return [{"verb": "*", "where": where}], {"action": {"verb": verb, "resource": "/", "params": {}}, "env": {}}


MR = {"field": "action.verb", "op": "matches", "value": "r"}


def test_budget_evaluation_cap():
    preds, ctx = _where_pred([MR] * 64)
    assert evaluate_predicates(preds, ctx)["allowed"] is True
    preds, ctx = _where_pred([MR] * 65)
    assert evaluate_predicates(preds, ctx) == {"allowed": False, "reason": "no predicate permits r on /"}
    # a fresh document per call: the same 64 pass again
    preds, ctx = _where_pred([MR] * 64)
    assert evaluate_predicates(preds, ctx)["allowed"] is True
    # predicates of ONE document share the budget
    p1, ctx = _where_pred([MR] * 40)
    p2, _ = _where_pred([MR] * 30)
    assert evaluate_predicates([{"verb": "x"}] + p1 + p2, ctx)["allowed"] is True  # p1 (40) admits first
    p1, ctx = _where_pred([MR] * 40 + [CF])
    assert evaluate_predicates(p1 + p2, ctx)["allowed"] is False  # 40 + 25th of p2 = 65th refused


def test_budget_steps_cap_and_poison():
    nb = {"not": {"field": "action.params.s", "op": "matches", "value": P40}}
    ctx = {"action": {"verb": "r", "resource": "/", "params": {"s": "z" * 512}}, "env": {}}
    # 2561 x 513 = 1_313_793 steps per evaluation: 3 fit in 5M, the 4th does not
    assert evaluate_predicates([{"verb": "*", "where": [nb] * 3}], ctx)["allowed"] is True
    assert evaluate_predicates([{"verb": "*", "where": [nb] * 4}], ctx)["allowed"] is False
    tail = {"any_of": [nb["not"], MR]}
    assert evaluate_predicates([{"verb": "*", "where": [nb] * 3 + [MR]}], ctx)["allowed"] is True
    # after the 4th is refused the budget is poisoned: the cheap `r` that would fit is refused too
    assert evaluate_predicates([{"verb": "*", "where": [nb] * 3 + [tail]}], ctx)["allowed"] is False


def test_budget_object():
    b = RegexBudget()
    assert b.charge("\\b", 1) is False and b.refusals == 1 and b.evaluations == 0
    for _ in range(40):
        assert b.charge("a" * 200, 0) is True
    assert b.chars == 8000
    assert b.charge("a" * 200, 0) is False  # 8200 > 8192
    assert b.evaluations == MAX_REGEX_EVALUATIONS_PER_DOCUMENT + 1 and b.refusals == 2
    assert b.charge("a", 0) is False  # poisoned
    c = RegexBudget()
    for _ in range(40):
        c.charge("a" * 200, 0)
    assert c.charge("a" * 192, 0) is True  # exactly 8192
    assert c.chars == 8192
    assert c.steps == 40 * 201 + 193
    # astral source chars count as two
    d = RegexBudget()
    assert d.charge(ASTRAL, 0) is True and d.chars == 2


def test_budget_request_chain_and_scopes():
    req = RegexBudget.request("client")
    assert req.is_document is False and req.source == "client"
    for _ in range(4):
        doc = RegexBudget(1, req, True)
        for _ in range(64):
            assert doc.charge("r", 1) is True
    doc = RegexBudget(1, req, True)
    assert doc.charge("r", 1) is False  # the request's 4 x 64 is spent
    assert req.evaluations == 4 * 64 + 1
    # outside any scope every charge is a fresh single-use budget
    assert all(charge_regex("r", 1) for _ in range(100))
    assert regex_refusals() == 0

    def inner():
        oks = [charge_regex("r", 1) for _ in range(65)]
        return oks, regex_refusals()

    oks, refusals = with_regex_budget(inner)
    assert oks == [True] * 64 + [False] and refusals == 1
    # nested document scopes join the open one
    def nested():
        for _ in range(64):
            charge_regex("r", 1)
        return with_regex_budget(lambda: charge_regex("r", 1))

    assert with_regex_budget(nested) is False
    # an explicit budget is used as given
    mine = RegexBudget()
    with_regex_budget(lambda: charge_regex("r", 4), mine)
    assert (mine.evaluations, mine.steps, mine.chars) == (1, 10, 1)


# ---- predicates -----------------------------------------------------------------------------------------------------

def test_verb_matching():
    ctx = _ctx(verb="read")
    assert predicate_matches({"verb": "read"}, ctx) is True
    assert predicate_matches({"verb": "*"}, ctx) is True
    assert predicate_matches({"verb": "write"}, ctx) is False
    assert predicate_matches({"verb": ["write", "read"]}, ctx) is True
    assert predicate_matches({"verb": ["write", "*"]}, ctx) is True
    assert predicate_matches({"verb": [5, "write"]}, ctx) is False
    assert predicate_matches({"verb": []}, ctx) is False
    assert predicate_matches({"verb": 5}, ctx) is False
    assert predicate_matches({}, ctx) is False
    assert predicate_matches(None, ctx) is False and predicate_matches([{"verb": "*"}], ctx) is False


def test_resource_matching():
    def rm(pattern, resource):
        p = {"verb": "*", "resource": pattern} if pattern is not ... else {"verb": "*"}
        return predicate_matches(p, _ctx(resource=resource))

    assert rm(..., "/anything") is True
    assert rm("*", "/x") is True
    assert rm(None, "/x") is False and rm(5, "/x") is False
    assert rm("/acct/*", "/acct/1") is True and rm("/acct/*", "/acct/") is True and rm("/acct/*", "/acc") is False
    assert rm(HI + "*", ASTRAL) is True  # UTF-16 startsWith
    assert rm("/x", "/x") is True and rm("/x", "/x/") is False
    assert rm("re:/acct/[^/]+", "/acct/7") is True and rm("re:/acct/[^/]+", "/acct/7/x") is False
    assert rm("re:/x", "/x\n") is False
    assert rm("re:" + "a" * 200, "a" * 200) is True
    assert rm("re:" + "a" * 201, "a" * 201) is False  # source > 200
    assert rm("re:" + ASTRAL * 100, ASTRAL * 100) is True  # 200 units
    assert rm("re:" + ASTRAL * 100 + "a", ASTRAL * 100 + "a") is False  # 201 units
    assert rm("re:a*", "a" * 512) is True
    assert rm("re:a*", "a" * 513) is False
    assert rm("re:a*", ASTRAL * 256 + "a") is False  # 513 units
    assert rm("re:(a+)+", "aa") is False and rm("re:\\b", "") is False
    assert rm("re:", "") is True and rm("re:", "a") is False


def test_predicate_shape_and_order():
    ctx = _ctx({"x": 1})
    assert predicate_matches({"verb": "*", "where": []}, ctx) is True
    assert predicate_matches({"verb": "*", "where": {"field": "action.params.x"}}, ctx) is False
    assert predicate_matches({"verb": "*", "where": [_leaf("eq", 1)]}, ctx) is True
    assert predicate_matches({"verb": "*", "where": [_leaf("eq", 1), _leaf("eq", 2)]}, ctx) is False
    for bad in ({}, {"action": None}, {"action": {"verb": 1, "resource": "/"}}, {"action": {"verb": "r"}},
                {"action": {"verb": "r", "resource": 5}}, "ctx", None):
        assert predicate_matches({"verb": "*"}, bad) is False, repr(bad)


def test_evaluate_predicates_reasons():
    ctx = _ctx(verb="read", resource="/x")
    assert evaluate_predicates([], ctx) == {"allowed": False, "reason": "envelope grants no predicates"}
    assert evaluate_predicates("p", ctx) == {"allowed": False, "reason": "envelope grants no predicates"}
    assert evaluate_predicates(None, ctx) == {"allowed": False, "reason": "envelope grants no predicates"}
    p = {"verb": "read"}
    assert evaluate_predicates([{"verb": "w"}, p, {"verb": "*"}], ctx) == {"allowed": True, "matched": p}
    assert evaluate_predicates([{"verb": "w"}], ctx) == {"allowed": False, "reason": "no predicate permits read on /x"}
    star = [{"verb": "*", "where": [CF]}]
    assert evaluate_predicates(star, {})["reason"] == "no predicate permits undefined on undefined"
    assert evaluate_predicates(star, {"action": None})["reason"] == "no predicate permits undefined on undefined"
    assert evaluate_predicates(star, {"action": {"verb": 5}})["reason"] == "no predicate permits 5 on undefined"
    assert evaluate_predicates(star, {"action": {"verb": 1.5e-7, "resource": None}})["reason"] == (
        "no predicate permits 1.5e-7 on null")
    assert evaluate_predicates(star, {"action": {"verb": 1e21, "resource": True}})["reason"] == (
        "no predicate permits 1e+21 on true")
    assert evaluate_predicates(star, {"action": {"verb": 2.0, "resource": 0.001}})["reason"] == (
        "no predicate permits 2 on 0.001")
    assert evaluate_predicates(star, {"action": {"verb": [1, [2, None]], "resource": {"a": 1}}})["reason"] == (
        "no predicate permits 1,2, on [object Object]")


# ---- layers ---------------------------------------------------------------------------------------------------------

ALLOW = {"predicates": [{"verb": "*"}]}
DENY = {"predicates": [{"verb": "write"}]}
LCTX = {"action": {"verb": "read", "resource": "/doc", "params": {}}, "env": {}}
NOT_OBJECT = {"status": "fail", "layer": "org", "reason": "layers: the layers member is malformed (not an object)"}


def _fail(k):
    return {"status": "fail", "layer": k,
            "reason": "layers: the action is outside the %s ceiling (a ceiling is never a question)" % k}


def _malformed(k):
    return {"status": "fail", "layer": k,
            "reason": "layers: the %s ceiling is malformed (null or not {predicates: [...]})" % k}


def test_is_layer_policy():
    assert is_layer_policy(ALLOW) and is_layer_policy({"predicates": []})
    assert is_layer_policy({"predicates": [], "x": 1}) is False  # exactly {predicates}
    assert is_layer_policy({"predicates": [{"verb": "*"}], "note": None}) is False
    for bad in (None, {}, {"predicates": None}, {"predicates": "x"}, {"predicates": {"verb": "*"}}, [ALLOW], False, 0,
                "", "org"):
        assert is_layer_policy(bad) is False, repr(bad)


def test_layer_ceilings_order():
    assert decide_layer_ceilings({}, LCTX) == {"status": "pass"}
    assert decide_layer_ceilings({"org": ALLOW, "site": ALLOW, "std": ALLOW}, LCTX) == {"status": "pass"}
    assert decide_layer_ceilings({"org": DENY, "site": DENY, "std": DENY}, LCTX) == _fail("org")
    assert decide_layer_ceilings({"org": ALLOW, "site": DENY, "std": DENY}, LCTX) == _fail("site")
    assert decide_layer_ceilings({"site": ALLOW, "std": DENY}, LCTX) == _fail("std")
    assert decide_layer_ceilings({"std": DENY, "site": ALLOW}, LCTX) == _fail("std")
    assert decide_layer_ceilings({"site": DENY, "org": DENY}, LCTX) == _fail("org")  # order is fixed, not key order
    assert decide_layer_ceilings({"org": None}, LCTX) == _malformed("org")
    # an empty predicate list is well-formed but admits nothing
    assert decide_layer_ceilings({"org": {"predicates": []}}, LCTX) == _fail("org")


def test_layer_present_null_or_non_layer_is_malformed():
    for bad in (None, {}, {"predicates": None}, {"predicates": "x"}, {"predicates": {"verb": "*"}}, [ALLOW], False, 0,
                "", "org"):
        assert decide_layer_ceilings({"org": bad}, LCTX) == _malformed("org"), repr(bad)
        assert decide_layer_ceilings({"org": ALLOW, "site": bad}, LCTX) == _malformed("site"), repr(bad)
        assert decide_layer_ceilings({"org": ALLOW, "site": ALLOW, "std": bad}, LCTX) == _malformed("std"), repr(bad)
    # null is NOT "no constraint" (absent is)
    assert decide_layer_ceilings({"org": None, "site": None, "std": None}, LCTX) == _malformed("org")
    assert decide_layer_ceilings({"site": None}, LCTX) == _malformed("site")
    # first failure wins in ceiling order: a denying org beats a malformed site, a malformed org beats a denying site
    assert decide_layer_ceilings({"org": DENY, "site": None}, LCTX) == _fail("org")
    assert decide_layer_ceilings({"org": None, "site": DENY}, LCTX) == _malformed("org")
    assert decide_layer_ceilings({"org": ALLOW, "site": DENY, "std": None}, LCTX) == _fail("site")


UNKNOWN = {"status": "fail", "layer": "org", "reason": "layers: unknown member (the layers object is {org?, site?, std?})"}


def test_layers_object_closed():
    assert decide_layer_ceilings({"task": [ALLOW]}, LCTX) == UNKNOWN
    assert decide_layer_ceilings({"other": None}, LCTX) == UNKNOWN
    assert decide_layer_ceilings({"Org": ALLOW}, LCTX) == UNKNOWN
    # checked before any ceiling: beats a denying / malformed site, reported as org even with a passing org
    assert decide_layer_ceilings({"org": ALLOW, "site": DENY, "x": 1}, LCTX) == UNKNOWN
    assert decide_layer_ceilings({"site": None, "x": 1}, LCTX) == UNKNOWN
    assert decide_layer_ceilings({"org": ALLOW, "site": ALLOW, "std": ALLOW}, LCTX) == {"status": "pass"}


def test_layer_extra_member_is_malformed():
    extra = {"predicates": [{"verb": "*"}], "x": 1}
    assert decide_layer_ceilings({"org": extra}, LCTX) == _malformed("org")
    assert decide_layer_ceilings({"org": ALLOW, "site": extra}, LCTX) == _malformed("site")
    assert decide_layer_ceilings({"org": ALLOW, "std": extra}, LCTX) == _malformed("std")
    assert decide_layers({"task": [extra]}, LCTX) == {"decision": "intent_denied"}
    assert decide_layers({"denied": [extra], "task": [ALLOW]}, LCTX) == {"decision": "intent_denied"}
    assert decide_layers({"site": extra, "task": [ALLOW]}, LCTX) == {"decision": "ceiling", "layer": "site"}


def test_layered_grant_closed():
    D = {"decision": "intent_denied"}
    assert decide_layers({"task": [ALLOW], "x": 1}, LCTX) == D
    assert decide_layers({"task": [ALLOW], "layers": {}}, LCTX) == D
    # checked FIRST: beats a denying ceiling (which would otherwise be `ceiling`)
    assert decide_layers({"org": DENY, "task": [ALLOW], "x": None}, LCTX) == D
    assert decide_layers({"org": ALLOW, "site": ALLOW, "std": ALLOW, "task": [ALLOW], "denied": []}, LCTX) == {
        "decision": "admit", "by": 0}


def test_layers_member_not_an_object():
    for layers in (None, "x", [], [ALLOW], 5, True):
        assert decide_layer_ceilings(layers, LCTX) == NOT_OBJECT, repr(layers)


def test_layer_uses_full_predicate_evaluator():
    org = {"predicates": [{"verb": "read", "resource": "re:/d[a-z]+", "where": [
        {"field": "env.canon.k", "op": "eq", "value": 1}]}]}
    assert decide_layer_ceilings({"org": org}, dict(LCTX, env={"canon": {"k": 1}})) == {"status": "pass"}
    assert decide_layer_ceilings({"org": org}, dict(LCTX, env={"canon": {"k": 2}})) == _fail("org")
    assert decide_layer_ceilings({"org": org}, dict(LCTX, env={})) == _fail("org")


def test_decide_layers_order():
    assert decide_layers({"task": [DENY, ALLOW]}, LCTX) == {"decision": "admit", "by": 1}
    assert decide_layers({"task": [ALLOW]}, LCTX) == {"decision": "admit", "by": 0}
    assert decide_layers({"task": [DENY]}, LCTX) == {"decision": "intent_required"}
    assert decide_layers({"task": []}, LCTX) == {"decision": "intent_required"}
    assert decide_layers({"task": [{"predicates": []}]}, LCTX) == {"decision": "intent_required"}
    assert decide_layers({"denied": [ALLOW], "task": [ALLOW]}, LCTX) == {"decision": "intent_denied"}
    assert decide_layers({"denied": [DENY], "task": [ALLOW]}, LCTX) == {"decision": "admit", "by": 0}
    assert decide_layers({"denied": [], "task": [ALLOW]}, LCTX) == {"decision": "admit", "by": 0}
    assert decide_layers({"org": DENY, "denied": [ALLOW], "task": [ALLOW]}, LCTX) == {"decision": "ceiling",
                                                                                       "layer": "org"}
    assert decide_layers({"std": DENY, "task": [ALLOW]}, LCTX) == {"decision": "ceiling", "layer": "std"}
    assert decide_layers({"org": ALLOW, "site": ALLOW, "std": ALLOW, "task": [ALLOW]}, LCTX) == {
        "decision": "admit", "by": 0}


def test_decide_layers_malformed():
    D = {"decision": "intent_denied"}
    # malformed ceilings are step 1 (ceiling), checked before denied / task
    assert decide_layers({"site": None, "task": "x"}, LCTX) == {"decision": "ceiling", "layer": "site"}
    assert decide_layers(None, LCTX) == {"decision": "ceiling", "layer": "org"}
    assert decide_layers([ALLOW], LCTX) == {"decision": "ceiling", "layer": "org"}
    assert decide_layers("g", LCTX) == {"decision": "ceiling", "layer": "org"}
    # task is required and must be an array of layers
    assert decide_layers({}, LCTX) == D
    for bad in (None, "x", ALLOW, 5):
        assert decide_layers({"task": bad}, LCTX) == D, repr(bad)
    assert decide_layers({"task": [ALLOW, None]}, LCTX) == D  # a malformed entry anywhere, even after an admitter
    assert decide_layers({"task": [ALLOW, {}]}, LCTX) == D
    # denied: absent = []; present must be an array of layers (null is malformed, a string is never iterated)
    for bad in (None, "ab", 5, ALLOW, {"predicates": []}):
        assert decide_layers({"denied": bad, "task": [ALLOW]}, LCTX) == D, repr(bad)
    assert decide_layers({"denied": [DENY, None], "task": [ALLOW]}, LCTX) == D
    assert decide_layers({"denied": [DENY, {"predicates": "x"}], "task": [ALLOW]}, LCTX) == D
