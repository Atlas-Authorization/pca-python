"""Tests for the crew-wide guard: ``guard_tools`` / ``guard_crew`` / ``PcaToolGuard``.

A single call wraps every tool a crew can reach; each guarded tool then rejects a missing proof and
runs a valid one. Duck-typed fakes stand in for crewai agents/tasks/tools, so no install is needed.
"""
import pytest

from atlas_pca_crewai import (
    GuardedTool,
    PcaToolDenied,
    PcaToolGuard,
    guard_crew,
    guard_tools,
    pca_context,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, VERB, resolver


class _Tool:
    def __init__(self, name):
        self.name = name
        self.description = name
        self.args_schema = None
        self.ran = 0

    def _run(self, *args, **kwargs):
        self.ran += 1
        return "%s-ok" % self.name


class _Agent:
    def __init__(self, tools):
        self.tools = tools


class _Task:
    def __init__(self, tools):
        self.tools = tools


class _Crew:
    def __init__(self, agents=None, tasks=None, tools=None):
        self.agents = agents or []
        self.tasks = tasks or []
        self.tools = tools or []


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
        out[0].run()
    with pca_context(PCACTN):
        assert out[0].run() == "reader-ok"


def test_guard_tools_callable_require():
    a, b = _Tool("a"), _Tool("b")
    spec = lambda tool: REQUIRE if tool.name == "a" else None
    out = guard_tools([a, b], require=spec, **_kw())
    assert isinstance(out[0], GuardedTool)
    assert out[1] is b


# ---- guard_crew (the before_kickoff-style guard) -------------------------------------

def test_guard_crew_wraps_every_reachable_tool():
    agent_tools = [_Tool("reader"), _Tool("writer")]
    task_tool = _Tool("reader")
    crew_tool = _Tool("writer")
    crew = _Crew(agents=[_Agent(agent_tools)], tasks=[_Task([task_tool])], tools=[crew_tool])

    returned = guard_crew(crew, require=REQUIRE_MAP, **_kw())
    assert returned is crew

    guarded_everywhere = crew.agents[0].tools + crew.tasks[0].tools + crew.tools
    assert len(guarded_everywhere) == 4
    assert all(isinstance(t, GuardedTool) for t in guarded_everywhere)

    # every guarded tool fails closed without a proof...
    for t in guarded_everywhere:
        with pytest.raises(PcaToolDenied):
            t.run()
    # ...and runs with a valid one
    with pca_context(PCACTN):
        results = [t.run() for t in guarded_everywhere]
    assert results == ["reader-ok", "writer-ok", "reader-ok", "writer-ok"]


def test_guard_crew_single_string_require_applies_to_all():
    crew = _Crew(agents=[_Agent([_Tool("x"), _Tool("y")])])
    guard_crew(crew, require=REQUIRE, **_kw())
    tools = crew.agents[0].tools
    assert all(isinstance(t, GuardedTool) for t in tools)
    with pca_context(PCACTN):
        assert [t.run() for t in tools] == ["x-ok", "y-ok"]


# ---- PcaToolGuard mixin --------------------------------------------------------------

def test_pca_tool_guard_mixin_guards_the_crew():
    class MyCrew(PcaToolGuard, _Crew):
        pca_audience = AUD
        pca_require = REQUIRE
        pca_resolve_grant = staticmethod(resolver)
        pca_now = NOW

    crew = MyCrew(agents=[_Agent([_Tool("reader")])])
    inputs = {"topic": "orders"}
    returned = crew.pca_guard_tools(inputs)
    assert returned is inputs  # hook passes inputs through

    tool = crew.agents[0].tools[0]
    assert isinstance(tool, GuardedTool)
    with pytest.raises(PcaToolDenied):
        tool.run()
    with pca_context(PCACTN):
        assert tool.run() == "reader-ok"


def test_pca_tool_guard_requires_audience():
    class BadCrew(PcaToolGuard, _Crew):
        pca_require = REQUIRE
        pca_resolve_grant = staticmethod(resolver)

    crew = BadCrew(agents=[_Agent([_Tool("reader")])])
    with pytest.raises(ValueError):
        crew.pca_guard_tools({})
