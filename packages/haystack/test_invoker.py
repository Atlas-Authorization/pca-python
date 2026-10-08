"""Tests for the invoker-level guard: ``guard_tools`` / ``guard_tool_invoker``.

A single ``guard_tool_invoker`` call wraps every tool a Haystack ``ToolInvoker`` (and thus the whole
pipeline) can dispatch; each guarded tool then rejects a missing proof and runs a valid one. A
duck-typed fake stands in for the ``ToolInvoker`` (same ``tools`` / ``_tools_with_names`` / name
dispatch calling ``tool.invoke(**arguments)``), so no haystack install is needed.
"""
import pytest

from atlas_pca_haystack import (
    GuardedTool,
    PcaToolDenied,
    guard_tool_invoker,
    guard_tools,
    pca_context,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, VERB, resolver


class _Tool:
    """A haystack-Tool-like object: name/description/parameters + a ``function``, invoked by name."""

    def __init__(self, name):
        self.name = name
        self.description = name
        self.parameters = {"type": "object", "properties": {}}
        self.ran = 0
        self.function = self._work

    def _work(self, *args, **kwargs):
        self.ran += 1
        return "%s-ok" % self.name

    def invoke(self, **kwargs):  # a real haystack Tool.invoke calls self.function(**kwargs)
        return self.function(**kwargs)


class _ToolInvoker:
    """A stand-in for ``haystack.components.tools.ToolInvoker``.

    Holds a tool list and a by-name lookup; ``run(tool_calls)`` dispatches each call to
    ``tool.invoke(**arguments)`` exactly as the real invoker does (arguments come from the LLM, so the
    proof is never among them — it rides the context var).
    """

    def __init__(self, tools):
        self.tools = list(tools)
        self._tools_with_names = {t.name: t for t in self.tools}

    def run(self, tool_calls):
        results = []
        for name, arguments in tool_calls:
            tool = self._tools_with_names[name]
            results.append(tool.invoke(**arguments))
        return {"tool_results": results}


REQUIRE_MAP = {"reader": "%s:%s" % (VERB, RESOURCE), "writer": "%s:%s" % (VERB, RESOURCE)}


def _kw():
    return dict(audience=AUD, resolve_grant=resolver, now=NOW)


# ---- guard_tools ---------------------------------------------------------------------

def test_guard_tools_wraps_mapped_and_passes_through_unmapped():
    mapped = _Tool("reader")
    unmapped = _Tool("mystery")
    out = guard_tools([mapped, unmapped], require={"reader": REQUIRE}, **_kw())
    assert isinstance(out[0], GuardedTool)       # mapped -> guarded
    assert out[1] is unmapped                    # unmapped -> untouched
    # the guarded one is gated
    with pytest.raises(PcaToolDenied):
        out[0].invoke()
    with pca_context(PCACTN):
        assert out[0].invoke() == "reader-ok"


def test_guard_tools_callable_require():
    a, b = _Tool("a"), _Tool("b")
    spec = lambda tool: REQUIRE if tool.name == "a" else None
    out = guard_tools([a, b], require=spec, **_kw())
    assert isinstance(out[0], GuardedTool)
    assert out[1] is b


# ---- guard_tool_invoker (gates every tool a pipeline invokes) ------------------------

def test_guard_tool_invoker_wraps_every_tool_and_rebuilds_lookup():
    invoker = _ToolInvoker([_Tool("reader"), _Tool("writer")])
    returned = guard_tool_invoker(invoker, require=REQUIRE_MAP, **_kw())
    assert returned is invoker

    # every tool is now guarded, in both the list and the name lookup the invoker dispatches through
    assert all(isinstance(t, GuardedTool) for t in invoker.tools)
    assert set(invoker._tools_with_names) == {"reader", "writer"}
    assert all(isinstance(t, GuardedTool) for t in invoker._tools_with_names.values())


def test_guarded_invoker_fails_closed_without_proof():
    originals = [_Tool("reader"), _Tool("writer")]
    invoker = _ToolInvoker(originals)
    guard_tool_invoker(invoker, require=REQUIRE_MAP, **_kw())
    # dispatching any tool through the invoker denies, and the underlying tools never run
    with pytest.raises(PcaToolDenied):
        invoker.run([("reader", {})])
    with pytest.raises(PcaToolDenied):
        invoker.run([("writer", {})])
    assert all(t.ran == 0 for t in originals)  # the underlying work never fired


def test_guarded_invoker_runs_every_tool_with_a_valid_proof():
    invoker = _ToolInvoker([_Tool("reader"), _Tool("writer")])
    guard_tool_invoker(invoker, require=REQUIRE_MAP, **_kw())
    with pca_context(PCACTN):
        out = invoker.run([("reader", {}), ("writer", {})])
    assert out["tool_results"] == ["reader-ok", "writer-ok"]


def test_guard_tool_invoker_single_string_require_applies_to_all():
    invoker = _ToolInvoker([_Tool("x"), _Tool("y")])
    guard_tool_invoker(invoker, require=REQUIRE, **_kw())
    assert all(isinstance(t, GuardedTool) for t in invoker.tools)
    with pca_context(PCACTN):
        assert invoker.run([("x", {}), ("y", {})])["tool_results"] == ["x-ok", "y-ok"]


def test_guard_tool_invoker_leaves_unmapped_tools_ungated():
    invoker = _ToolInvoker([_Tool("reader"), _Tool("mystery")])
    guard_tool_invoker(invoker, require={"reader": REQUIRE}, **_kw())
    guarded = invoker._tools_with_names["reader"]
    passthrough = invoker._tools_with_names["mystery"]
    assert isinstance(guarded, GuardedTool)
    assert not isinstance(passthrough, GuardedTool)
    # the ungated tool still runs with no proof; the gated one does not
    assert invoker.run([("mystery", {})])["tool_results"] == ["mystery-ok"]
    with pytest.raises(PcaToolDenied):
        invoker.run([("reader", {})])


def test_guard_tool_invoker_with_no_tools_is_a_noop():
    invoker = _ToolInvoker([])
    returned = guard_tool_invoker(invoker, require=REQUIRE, **_kw())
    assert returned is invoker
    assert invoker.tools == []
