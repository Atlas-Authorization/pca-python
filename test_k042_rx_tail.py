"""Kill tests for atlas_pca.safe_regex: UTF-16 helpers at their code point boundaries, range normalisation and complement,
octal-escape detection, the compiled-program cache and the per-document / per-request regex work budgets."""
from atlas_pca import safe_regex as R


def u(*parts):
    """A string from code points (ints) and literal characters, without relying on how escapes pair up."""
    return "".join(chr(p) if isinstance(p, int) else p for p in parts)


def test_utf16_helpers_at_the_astral_boundary():
    assert R.to_units(u(0xFFFF)) == u(0xFFFF) and R.utf16_len(u(0xFFFF)) == 1
    assert R.to_units(u("a", 0xFFFF, "b")) == u("a", 0xFFFF, "b")
    assert R.to_units(u(0x10000)) == u(0xD800, 0xDC00) and R.utf16_len(u(0x10000)) == 2
    assert R.to_units(u(0x10FFFF)) == u(0xDBFF, 0xDFFF) and R.utf16_len(u(0x10FFFF)) == 2
    assert R.to_units(u("x", 0x10000, 0xFFFF)) == u("x", 0xD800, 0xDC00, 0xFFFF) and R.utf16_len(u("x", 0x10000, 0xFFFF)) == 4
    assert R.to_units("") == "" and R.utf16_len("") == 0


H, L = 0xD800, 0xDC00  # the lowest high / low surrogate
CASES = [
    ((), False), (("a",), False), ((0xD7FF,), False), ((0xE000,), False),
    ((H,), True), ((0xDBFF,), True), ((L,), True), ((0xDFFF,), True),
    ((H, L), False), ((0xDBFF, 0xDFFF), False), ((H, 0xDFFF), False), ((0xDBFF, L), False),
    ((H, 0xDBFF), True), ((H, H), True), ((H, 0xE000), True), ((H, 0xDBFF, L), True),
    ((L, H), True), ((L, L), True), ((H, "a"), True), (("a", H), True), (("a", L), True),
    ((H, L, H), True), ((H, L, L), True), ((H, L, "a"), False), (("a", H, L), False),
    ((H, L, H, L), False), ((H, L, "a", H, L), False), ((H, L, 0xDBFF), True),
]


def test_lone_surrogate_detection():
    for parts, expected in CASES:
        assert R.units_have_lone_surrogate(u(*parts)) is expected, parts


def test_normalize_and_complement():
    assert R._normalize([(5, 9), (1, 3), (4, 4)]) == [[1, 9]]
    assert R._normalize([(1, 3), (5, 6)]) == [[1, 3], [5, 6]]
    assert R._normalize([(1, 2), (3, 4)]) == [[1, 4]]
    assert R._normalize([(1, 3), (2, 10)]) == [[1, 10]]
    assert R._normalize([(1, 10), (2, 3)]) == [[1, 10]]
    assert R._complement([]) == [(0, 0xFFFF)]
    assert R._complement([(0, 0xFFFF)]) == []
    assert R._complement([(0, 5)]) == [(6, 0xFFFF)]
    assert R._complement([(5, 0xFFFF)]) == [(0, 4)]
    assert R._complement([(1, 2)]) == [(0, 0), (3, 0xFFFF)]
    assert R._complement([(0, 0xFFFE)]) == [(0xFFFF, 0xFFFF)]
    assert R._complement([(0, 3), (4, 8)]) == [(9, 0xFFFF)]
    assert R._complement([(2, 3), (7, 8)]) == [(0, 1), (4, 6), (9, 0xFFFF)]


def test_zero_escape_is_octal_only_before_a_digit():
    assert R.compile_safe_regex("\\0A") is not None
    assert R.safe_regex_full_match("\\0A", "\x00A") is True
    assert R.safe_regex_full_match("\\0W", "\x00W") is True
    for d in "0129":
        assert R.compile_safe_regex("\\0" + d) is None, d
    assert R.safe_regex_full_match("\\0", "\x00") is True


def test_compiled_program_cache_is_a_bounded_fifo(monkeypatch):
    monkeypatch.setattr(R, "REGEX_CACHE_MAX_ENTRIES", 3)
    monkeypatch.setattr(R, "_cache", R.OrderedDict())
    for i in range(3):
        R.compile_safe_regex_cached("a%d" % i)
    assert list(R._cache) == ["a0", "a1", "a2"]
    R.compile_safe_regex_cached("a3")
    assert list(R._cache) == ["a1", "a2", "a3"]
    R.compile_safe_regex_cached("a1")  # a hit moves it to the end
    R.compile_safe_regex_cached("a4")
    assert list(R._cache) == ["a3", "a1", "a4"]


def test_default_budget_is_a_document_budget():
    assert R.RegexBudget().is_document is True
    assert R.RegexBudget.request().is_document is False


def test_budget_limits_scale_with_the_budget():
    b = R.RegexBudget(4, None, False)
    assert b.charge("a" * 3000, 0) is True  # 3000 > 8192 / 4 but within 8192 * 4
    assert R.RegexBudget(4, None, False).charge("a", 3_000_000) is True  # 6 M steps: over 5 M, within 20 M
    assert R.RegexBudget(1, None, True).charge("a", 3_000_000) is False
    assert R.RegexBudget(1, None, True).charge("a" * 8193, 0) is False
    c = R.RegexBudget(2, None, True)
    assert all(c.charge("a", 0) for _ in range(128)) and c.charge("a", 0) is False


def test_charge_regex_outside_any_scope_uses_a_fresh_single_document_budget():
    assert R.charge_regex("a", 3_000_000) is False  # 6 M steps > 5 M for ONE document
    assert R.charge_regex("a", 1000) is True


def test_scopes_join_and_chain():
    seen = {}

    def inner():
        seen["inner"] = R._current.get()
        R.charge_regex("a", 0)

    def outer():
        seen["outer"] = R._current.get()
        R.with_regex_budget(inner)

    R.with_regex_budget(outer)
    assert seen["inner"] is seen["outer"] and seen["outer"].is_document is True and seen["outer"].evaluations == 1
    assert seen["outer"].parent_budget is None
    assert R._current.get() is None

    req = R.RegexBudget.request()
    holder = {}

    def under_request():
        holder["doc"] = R._current.get()
        R.charge_regex("a", 0)

    req.run(lambda: R.with_regex_budget(under_request))
    d = holder["doc"]
    assert d is not req and d.is_document is True and d.parent_budget is req
    assert d.evaluations == 1 and req.evaluations == 1


def test_charge_regex_charges_the_open_scope_and_its_parent():
    req = R.RegexBudget.request()
    holder = {}

    def f():
        holder["doc"] = R._current.get()
        assert R.charge_regex("ab", 5) is True

    req.run(lambda: R.with_regex_budget(f))
    assert holder["doc"].evaluations == 1 and holder["doc"].steps == 3 * 6
    assert req.evaluations == 1 and req.steps == 3 * 6 and req.chars == 2


def test_ambient_provider(monkeypatch):
    req = R.RegexBudget.request()
    monkeypatch.setattr(R, "_provider", None)
    assert R._ambient() is None
    R.set_regex_budget_provider(lambda: req)
    try:
        assert R._provider is not None and R._ambient() is req
        holder = {}

        def f():
            holder["doc"] = R._current.get()
            holder["ok"] = R.charge_regex("a", 0)

        R.with_regex_budget(f)
        assert holder["doc"].parent_budget is req and holder["doc"].is_document is True and holder["ok"] is True
        assert req.evaluations == 1
        # an open scope wins over the provider
        other = R.RegexBudget.request()
        other.run(lambda: holder.__setitem__("amb", R._ambient()))
        assert holder["amb"] is other
        R.set_regex_budget_provider(lambda: 1 / 0)
        assert R._ambient() is None
    finally:
        R.set_regex_budget_provider(None)
    assert R._ambient() is None


def test_a_refused_pattern_is_counted_on_the_open_scope():
    holder = {}

    def f():
        holder["scope"] = R._current.get()
        holder["ok"] = R.charge_regex("(", 0)  # outside the subset
        holder["n"] = R.regex_refusals()

    R.with_regex_budget(f)
    assert holder["ok"] is False and holder["n"] == 1 and holder["scope"].refusals == 1
    assert R.regex_refusals() == 0


def test_charge_regex_outside_a_scope_chains_to_the_ambient_provider(monkeypatch):
    req = R.RegexBudget.request()
    monkeypatch.setattr(R, "_provider", None)
    R.set_regex_budget_provider(lambda: req)
    try:
        assert R.charge_regex("ab", 1) is True
        assert req.evaluations == 1 and req.steps == 3 * 2 and req.chars == 2
    finally:
        R.set_regex_budget_provider(None)
